package certificatepublish

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Certificate redelivery. A certificate's key material
// reaches the nodes a binding (or renewal) publication targeted at that
// moment, through a one-time secret rollout. A node that joins a site's line
// group later, a node reinstalled under the same ID (a new host with an empty
// certificate store) and a node offline or refused then never get it: the
// site's configuration names the version and the node refuses its handshakes
// ("certificate files missing").
//
// Every sweep, per tenant scope: the sites' current bindings (latest binding
// fact, bind, default, naming the asset's active version, servable now, no
// publication of the site in flight); the nodes serving each site (the
// renewal's selection, edgeautopublish.SitesTargetNodeIDsTx); minus the nodes
// whose current host (edgedeployment.CurrentHostDeployment: deployments since
// its latest initial enrollment, so a reinstall starts empty) holds a healthy
// certificate bundle with the site at that binding revision or later. A node
// missing sites, ready (online, active, not isolated, capable) and with no
// deployment of the scope in flight gets one system secret rollout of them
// (bounded batch); a rollout in flight is waited for, a failed round backs
// off (in memory, per scope and node; the in-flight proof is durable). Once a
// node holds everything, the scope is republished to it once (node_sync), so
// its site activation copies the versions into its TLS pool.
//
// Nothing per node is stored: "already delivered" is the deployment history.

const (
	// redeliveryIdempotencyPrefix names the rollouts this worker creates.
	redeliveryIdempotencyPrefix = "certificate-redelivery."
	redeliveryReason            = "certificate_redelivery"
	auditRedeliveryDeliver      = "certificate.redelivery.deliver"

	// redeliveryBatchSites bounds one rollout's sites (the artifact is at most
	// maxArtifactWireBytes; a site's certificate chain and key are a few KiB).
	redeliveryBatchSites = 100
	// redeliverySyncWindow: a delivery confirmed longer ago than this is not
	// followed by a republication any more (the node synced since, or never will).
	redeliverySyncWindow = 24 * time.Hour
)

// RedeliverySiteNodes names the nodes that serve each site
// (edgeautopublish.SitesTargetNodeIDsTx in production).
type RedeliverySiteNodes func(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, siteIDs []uuid.UUID,
) (map[uuid.UUID][]uuid.UUID, error)

// RedeliveryNodeReady reports whether a node can take a certificate bundle
// now (RedeliveryNodeReadyTx in production).
type RedeliveryNodeReady func(ctx context.Context, tx pgx.Tx, nodeID uuid.UUID, now time.Time) (bool, error)

// RedeliveryNodeSync republishes a scope to a node unless a node_sync
// republication of it was queued after notBefore
// (edgeautopublish.NodeSyncRetrier.RetryNodeSync in production).
type RedeliveryNodeSync func(ctx context.Context, nodeID, scopeID uuid.UUID, notBefore time.Time) (bool, error)

type redeliveryRolloutStore interface {
	CreateSystemSecretRolloutTx(context.Context, pgx.Tx, edgedeployment.SystemSecretRolloutRequest,
		edgedeployment.SecretArtifactBuilder) (edgedeployment.CreateRolloutResult, error)
}

type redeliveryAssetStore interface {
	UseRedeliveryMaterialsInTx(context.Context, pgx.Tx, uuid.UUID, []certificateasset.RedeliverySite,
		certificateasset.OpaquePublicationResolver, certificateasset.PublicationConsumer) ([]uuid.UUID, error)
}

type RedelivererConfig struct {
	HealthCheck edgedeployment.HealthCheckPolicy
	// SweepInterval bounds how often the scopes are rescanned.
	SweepInterval time.Duration
	// RoundTimeout is a rollout's deadline.
	RoundTimeout time.Duration
	// RetryBase doubles per failed round of a node up to RetryMaximum.
	RetryBase    time.Duration
	RetryMaximum time.Duration
}

func DefaultRedelivererConfig() RedelivererConfig {
	return RedelivererConfig{
		HealthCheck: edgedeployment.HealthCheckPolicy{ActivationTimeout: time.Minute,
			ObservationWindow: 10 * time.Second, RequiredConsecutiveSuccesses: 1},
		SweepInterval: time.Minute, RoundTimeout: 15 * time.Minute,
		RetryBase: time.Minute, RetryMaximum: time.Hour,
	}
}

type redeliveryKey struct{ scopeID, nodeID uuid.UUID }

// redeliveryBackoff is a node's failed rounds: missing is what it lacked when
// the last round started (fewer since is progress and resets the count);
// enrolled is the node's latest initial enrollment then (a newer one is a
// reinstalled host under the same ID, D-d: it starts over).
type redeliveryBackoff struct {
	attempts int
	next     time.Time
	missing  int
	enrolled time.Time
}

// Redeliverer runs on the automatic edge publication loop
// (edgeautopublish.RuntimeWorker); one instance per process.
type Redeliverer struct {
	pool      *pgxpool.Pool
	assets    redeliveryAssetStore
	rollouts  redeliveryRolloutStore
	producer  *Producer
	siteNodes RedeliverySiteNodes
	ready     RedeliveryNodeReady
	sync      RedeliveryNodeSync
	opaque    certificateasset.OpaquePublicationResolver
	config    RedelivererConfig
	now       func() time.Time

	lastSweep time.Time
	backoff   map[redeliveryKey]redeliveryBackoff
}

func NewRedeliverer(pool *pgxpool.Pool, assets redeliveryAssetStore, rollouts redeliveryRolloutStore, producer *Producer,
	siteNodes RedeliverySiteNodes, ready RedeliveryNodeReady, sync RedeliveryNodeSync,
	opaque certificateasset.OpaquePublicationResolver, config RedelivererConfig, now func() time.Time,
) (*Redeliverer, error) {
	if pool == nil || nilPublicationDependency(assets) || nilPublicationDependency(rollouts) || producer == nil ||
		siteNodes == nil || ready == nil || sync == nil || now == nil ||
		config.SweepInterval <= 0 || config.SweepInterval > time.Hour || config.RoundTimeout < time.Minute ||
		config.RetryBase <= 0 || config.RetryMaximum < config.RetryBase ||
		config.HealthCheck.ActivationTimeout <= 0 || config.HealthCheck.ObservationWindow <= 0 ||
		config.HealthCheck.RequiredConsecutiveSuccesses == 0 {
		return nil, ErrInvalidInput
	}
	return &Redeliverer{pool: pool, assets: assets, rollouts: rollouts, producer: producer, siteNodes: siteNodes,
		ready: ready, sync: sync, opaque: opaque, config: config, now: now,
		backoff: map[redeliveryKey]redeliveryBackoff{}}, nil
}

// RedeliverySweep is what one sweep did.
type RedeliverySweep struct {
	Rollouts []uuid.UUID // created, in scope then node order
	Synced   int         // node_sync republications queued
}

// RunOnce sweeps at most once per SweepInterval. It never reports work: the
// loop's poll interval paces it.
func (redeliverer *Redeliverer) RunOnce(ctx context.Context) (bool, error) {
	if redeliverer == nil || ctx == nil {
		return false, ErrInvalidInput
	}
	now := redeliverer.now()
	if !redeliverer.lastSweep.IsZero() && now.Sub(redeliverer.lastSweep) < redeliverer.config.SweepInterval {
		return false, nil
	}
	redeliverer.lastSweep = now
	_, err := redeliverer.SweepOnce(ctx)
	return false, err
}

// SweepOnce scans every scope with a certificate bound to a site. A scope's
// failure does not stop the others; the failures are returned joined.
func (redeliverer *Redeliverer) SweepOnce(ctx context.Context) (RedeliverySweep, error) {
	if redeliverer == nil || ctx == nil {
		return RedeliverySweep{}, ErrInvalidInput
	}
	rows, err := redeliverer.pool.Query(ctx, `SELECT DISTINCT tenant_scope_id FROM certificate_site_binding_facts
		WHERE action='bind' ORDER BY 1`)
	if err != nil {
		return RedeliverySweep{}, fmt.Errorf("list certificate redelivery scopes: %w", err)
	}
	scopes, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return RedeliverySweep{}, fmt.Errorf("list certificate redelivery scopes: %w", err)
	}
	var result RedeliverySweep
	var failures []error
	seen := map[redeliveryKey]bool{}
	for _, scopeID := range scopes {
		if err := redeliverer.sweepScope(ctx, scopeID, seen, &result); err != nil {
			failures = append(failures, fmt.Errorf("certificate redelivery scope %s: %w", scopeID, err))
		}
	}
	for key := range redeliverer.backoff {
		if !seen[key] {
			delete(redeliverer.backoff, key) // nothing missing any more
		}
	}
	return result, errors.Join(failures...)
}

type redeliveryNode struct {
	id       uuid.UUID
	missing  []certificateasset.RedeliverySite // in site order
	busy     bool                              // a deployment of the scope is in flight on it
	enrolled time.Time                         // its latest initial enrollment (zero: none recorded)
}

type redeliverySync struct {
	nodeID    uuid.UUID
	notBefore time.Time // its latest confirmed redelivery
}

type redeliveryPlan struct {
	nodes []redeliveryNode // missing something, in node order
	sync  []redeliverySync // hold everything, the last redelivery not yet followed by a republication
	// held: bound sites every serving node holds at their binding revision
	// (a failed publication of that binding is settled by redelivery)
	held []certificateasset.RedeliverySite
}

type redeliveryOutcome int

const (
	redeliveryRefused  redeliveryOutcome = iota // nothing created: a failed round
	redeliveryCreated                           // a rollout is on its way
	redeliveryBusy                              // in flight: wait, not a failure
	redeliveryNotReady                          // offline, isolated, incapable: wait, not a failure
)

// errRedeliveryRefused rolls a node's transaction back when nothing could
// be created for it.
var errRedeliveryRefused = errors.New("certificate redelivery refused")

func (redeliverer *Redeliverer) sweepScope(ctx context.Context, scopeID uuid.UUID, seen map[redeliveryKey]bool,
	result *RedeliverySweep) error {
	now := redeliverer.now().UTC()
	var plan redeliveryPlan
	if err := pgx.BeginFunc(ctx, redeliverer.pool, func(tx pgx.Tx) error {
		var err error
		plan, err = redeliverer.planScopeTx(ctx, tx, scopeID, now)
		return err
	}); err != nil {
		return err
	}
	var failures []error
	if len(plan.held) > 0 {
		if err := pgx.BeginFunc(ctx, redeliverer.pool, func(tx pgx.Tx) error {
			return recordRedeliveryRecoveriesTx(ctx, tx, scopeID, plan.held)
		}); err != nil {
			failures = append(failures, fmt.Errorf("record recovered publications: %w", err))
		}
	}
	for _, node := range plan.nodes {
		key := redeliveryKey{scopeID: scopeID, nodeID: node.id}
		seen[key] = true
		if node.busy {
			continue
		}
		state, found := redeliverer.backoff[key]
		if found && (len(node.missing) < state.missing || !node.enrolled.Equal(state.enrolled)) {
			// the last round delivered something, or a new host took the node over
			state, found = redeliveryBackoff{}, false
		}
		if found && now.Before(state.next) {
			continue
		}
		outcome, rolloutID, err := redeliverer.deliver(ctx, scopeID, node)
		if err != nil {
			failures = append(failures, fmt.Errorf("node %s: %w", node.id, err))
		}
		if outcome == redeliveryBusy || outcome == redeliveryNotReady {
			continue
		}
		state.attempts++
		state.missing, state.enrolled = len(node.missing), node.enrolled
		state.next = now.Add(redeliverer.retryDelay(state.attempts))
		redeliverer.backoff[key] = state
		if outcome == redeliveryCreated {
			result.Rollouts = append(result.Rollouts, rolloutID)
		}
	}
	for _, item := range plan.sync {
		queued, err := redeliverer.sync(ctx, item.nodeID, scopeID, item.notBefore)
		if err != nil {
			failures = append(failures, fmt.Errorf("republish to node %s: %w", item.nodeID, err))
		} else if queued {
			result.Synced++
		}
	}
	return errors.Join(failures...)
}

// recordRedeliveryRecoveriesTx settles, as succeeded, the permanently failed
// publication of each held site's binding (after the
// certificates reached the reinstalled nodes the console kept showing the publications
// failed). The result names the newest healthy redelivery rollout that
// carried the site at that binding revision (migration 650 checks it); a
// binding no redelivery carried (its own publication reached every node) is
// left as it is.
func recordRedeliveryRecoveriesTx(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, sites []certificateasset.RedeliverySite) error {
	for _, site := range sites {
		if _, err := tx.Exec(ctx, `INSERT INTO certificate_publication_intent_state_facts(tenant_scope_id,site_id,
				binding_revision,sequence,state,attempt,idempotency_key,lease_owner,lease_token,lease_expires_at,
				occurred_at,recovered_by_rollout_id)
			SELECT latest.tenant_scope_id,latest.site_id,latest.binding_revision,latest.sequence+1,'succeeded',
				latest.attempt,latest.idempotency_key,'certificate-redelivery',$4,transaction_timestamp(),
				transaction_timestamp(),carrier.id
			FROM certificate_publication_intents intent
			JOIN LATERAL (SELECT * FROM certificate_publication_intent_state_facts state
			  WHERE state.tenant_scope_id=intent.tenant_scope_id AND state.site_id=intent.site_id
			    AND state.binding_revision=intent.binding_revision ORDER BY sequence DESC LIMIT 1) latest ON true
			JOIN LATERAL (SELECT rollout.id FROM rollouts rollout
			  JOIN config_versions version ON version.id=rollout.config_version_id
			   AND version.configuration_scope_id=rollout.configuration_scope_id AND version.generator_name=$5
			  JOIN node_deployments deployment ON deployment.rollout_id=rollout.id AND deployment.state='healthy'
			  CROSS JOIN LATERAL jsonb_array_elements(convert_from(version.canonical_snapshot,'UTF8')::jsonb->'certificates') certificate
			  WHERE rollout.configuration_scope_id=intent.tenant_scope_id AND starts_with(rollout.idempotency_key,$6)
			    AND (certificate->>'site_id')::uuid=intent.site_id
			    AND (certificate->>'binding_revision')::bigint>=intent.binding_revision
			  ORDER BY deployment.updated_at DESC LIMIT 1) carrier ON true
			WHERE intent.tenant_scope_id=$1 AND intent.site_id=$2 AND intent.binding_revision=$3
			  AND intent.operation='publish' AND latest.state='permanent_failed'`,
			scopeID, site.SiteID, site.BindingRevision, uuid.New(), defaultGeneratorName, redeliveryIdempotencyPrefix); err != nil {
			return err
		}
	}
	return nil
}

func (redeliverer *Redeliverer) retryDelay(attempt int) time.Duration {
	delay := redeliverer.config.RetryBase
	for step := 1; step < attempt && delay < redeliverer.config.RetryMaximum; step++ {
		delay *= 2
	}
	return min(delay, redeliverer.config.RetryMaximum)
}

// planScopeTx reads what the scope's nodes miss (no lock is taken; deliver
// re-checks under its own).
func (redeliverer *Redeliverer) planScopeTx(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, now time.Time,
) (redeliveryPlan, error) {
	// The current bindings: what the site configuration names (site runtime
	// v2 loadSiteRuntimeV2TLSBindings: the latest fact, bind, default, the
	// asset's active version), servable now, with no publication of the site
	// in flight (that publication delivers it, or settles first).
	rows, err := tx.Query(ctx, `SELECT site.id,binding.asset_id,binding.version_id,binding.sequence
		FROM sites site
		CROSS JOIN LATERAL (SELECT sequence,action,asset_id,version_id,is_default FROM certificate_site_binding_facts
		  WHERE tenant_scope_id=site.scope_id AND site_id=site.id ORDER BY sequence DESC LIMIT 1) binding
		JOIN certificate_assets asset ON asset.tenant_scope_id=site.scope_id AND asset.id=binding.asset_id
		 AND asset.deleted_at IS NULL
		JOIN certificate_asset_versions version ON version.tenant_scope_id=site.scope_id
		 AND version.asset_id=binding.asset_id AND version.id=binding.version_id
		 AND version.not_before<=$2 AND version.not_after>$2
		WHERE site.scope_id=$1 AND site.deleted_at IS NULL AND binding.action='bind' AND binding.is_default
		  AND binding.version_id=(SELECT version_id FROM certificate_asset_activation_facts
		    WHERE tenant_scope_id=site.scope_id AND asset_id=binding.asset_id ORDER BY sequence DESC LIMIT 1)
		  AND NOT EXISTS(SELECT 1 FROM certificate_asset_revocation_facts revoked
		    WHERE revoked.tenant_scope_id=site.scope_id AND revoked.asset_id=binding.asset_id
		      AND revoked.version_id=binding.version_id)
		  AND NOT EXISTS(SELECT 1 FROM certificate_publication_intents intent
		    JOIN LATERAL (SELECT state FROM certificate_publication_intent_state_facts state
		      WHERE state.tenant_scope_id=intent.tenant_scope_id AND state.site_id=intent.site_id
		        AND state.binding_revision=intent.binding_revision ORDER BY sequence DESC LIMIT 1) latest ON true
		    WHERE intent.tenant_scope_id=site.scope_id AND intent.site_id=site.id
		      AND latest.state NOT IN ('succeeded','permanent_failed'))
		ORDER BY site.id`, scopeID, now)
	if err != nil {
		return redeliveryPlan{}, err
	}
	bound, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (certificateasset.RedeliverySite, error) {
		var site certificateasset.RedeliverySite
		return site, row.Scan(&site.SiteID, &site.AssetID, &site.VersionID, &site.BindingRevision)
	})
	if err != nil || len(bound) == 0 {
		return redeliveryPlan{}, err
	}
	siteIDs := make([]uuid.UUID, len(bound))
	for index, site := range bound {
		siteIDs[index] = site.SiteID
	}
	serving, err := redeliverer.siteNodes(ctx, tx, scopeID, siteIDs)
	if err != nil {
		return redeliveryPlan{}, err
	}
	var nodeIDs []uuid.UUID
	for _, nodes := range serving {
		nodeIDs = append(nodeIDs, nodes...)
	}
	slices.SortFunc(nodeIDs, compareRenewalUUID)
	nodeIDs = slices.Compact(nodeIDs)
	if len(nodeIDs) == 0 {
		return redeliveryPlan{}, nil
	}
	// What each node's current host holds: the highest binding revision of
	// each site in a healthy certificate bundle of the scope.
	rows, err = tx.Query(ctx, `SELECT deployment.node_id,(certificate->>'site_id')::uuid,
			max((certificate->>'binding_revision')::bigint)
		FROM rollouts rollout
		JOIN config_versions version ON version.id=rollout.config_version_id
		 AND version.configuration_scope_id=rollout.configuration_scope_id AND version.generator_name=$3
		JOIN node_deployments deployment ON deployment.rollout_id=rollout.id AND deployment.state='healthy'
		CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN version.generator_name=$3
		  THEN convert_from(version.canonical_snapshot,'UTF8')::jsonb->'certificates' ELSE '[]'::jsonb END) certificate
		WHERE rollout.configuration_scope_id=$1 AND deployment.node_id=ANY($2::uuid[])
		  AND `+edgedeployment.CurrentHostDeployment("deployment")+`
		GROUP BY 1,2`, scopeID, nodeIDs, defaultGeneratorName)
	if err != nil {
		return redeliveryPlan{}, err
	}
	type siteNode struct{ siteID, nodeID uuid.UUID }
	held := map[siteNode]int64{} // binding revision
	var nodeID, siteID uuid.UUID
	var revision int64
	if _, err := pgx.ForEachRow(rows, []any{&nodeID, &siteID, &revision}, func() error {
		held[siteNode{siteID: siteID, nodeID: nodeID}] = revision
		return nil
	}); err != nil {
		return redeliveryPlan{}, err
	}
	busy, err := redeliveryBusyNodesTx(ctx, tx, scopeID, nodeIDs)
	if err != nil {
		return redeliveryPlan{}, err
	}
	enrolled := map[uuid.UUID]time.Time{}
	rows, err = tx.Query(ctx, `SELECT node_id,max(issued_at) FROM node_certificates
		WHERE node_id=ANY($1::uuid[]) AND issuance_kind='initial' GROUP BY 1`, nodeIDs)
	if err != nil {
		return redeliveryPlan{}, err
	}
	var enrolledAt time.Time
	if _, err := pgx.ForEachRow(rows, []any{&nodeID, &enrolledAt}, func() error {
		enrolled[nodeID] = enrolledAt
		return nil
	}); err != nil {
		return redeliveryPlan{}, err
	}
	var plan redeliveryPlan
	for _, site := range bound {
		nodes := serving[site.SiteID]
		all := len(nodes) > 0
		for _, nodeID := range nodes {
			all = all && held[siteNode{siteID: site.SiteID, nodeID: nodeID}] >= site.BindingRevision
		}
		if all {
			plan.held = append(plan.held, site)
		}
	}
	var complete []uuid.UUID // hold every site they serve, nothing in flight
	for _, nodeID := range nodeIDs {
		node := redeliveryNode{id: nodeID, busy: busy[nodeID], enrolled: enrolled[nodeID]}
		for _, site := range bound {
			if slices.Contains(serving[site.SiteID], nodeID) &&
				held[siteNode{siteID: site.SiteID, nodeID: nodeID}] < site.BindingRevision {
				node.missing = append(node.missing, site)
			}
		}
		switch {
		case len(node.missing) > 0:
			plan.nodes = append(plan.nodes, node)
		case !node.busy:
			complete = append(complete, nodeID)
		}
	}
	if len(complete) == 0 {
		return plan, nil
	}
	// A node that took a redelivery republishes once: its site activation
	// copies the versions into its TLS pool (the agent reads the store only
	// then). Not when a node_sync republication of the scope was queued
	// since, or a release of the scope reached the node since.
	rows, err = tx.Query(ctx, `SELECT delivered.node_id,delivered.at FROM (
			SELECT deployment.node_id,max(deployment.updated_at) AS at
			FROM rollouts rollout
			JOIN node_deployments deployment ON deployment.rollout_id=rollout.id AND deployment.state='healthy'
			WHERE rollout.configuration_scope_id=$1 AND starts_with(rollout.idempotency_key,$3)
			  AND deployment.node_id=ANY($2::uuid[]) AND deployment.updated_at>$4
			  AND `+edgedeployment.CurrentHostDeployment("deployment")+`
			GROUP BY 1) delivered
		WHERE NOT EXISTS(SELECT 1 FROM edge_automatic_publication_requests request_row
		    WHERE request_row.target_scope_id=$1 AND request_row.source_kind='node_sync'
		      AND request_row.source_resource_id=delivered.node_id AND request_row.created_at>delivered.at)
		  AND NOT EXISTS(SELECT 1 FROM edge_system_revision_segments segment
		    WHERE segment.scope_id=$1 AND segment.source='node_sync' AND segment.recorded_at>delivered.at)
		  AND NOT EXISTS(SELECT 1 FROM edge_config_publications publication
		    JOIN node_deployments released ON released.rollout_id=publication.rollout_id
		     AND released.node_id=delivered.node_id AND released.state='healthy' AND released.updated_at>delivered.at
		    WHERE publication.configuration_scope_id=$1)
		ORDER BY 1`, scopeID, complete, redeliveryIdempotencyPrefix, now.Add(-redeliverySyncWindow))
	if err != nil {
		return redeliveryPlan{}, err
	}
	var at time.Time
	if _, err := pgx.ForEachRow(rows, []any{&nodeID, &at}, func() error {
		plan.sync = append(plan.sync, redeliverySync{nodeID: nodeID, notBefore: at})
		return nil
	}); err != nil {
		return redeliveryPlan{}, err
	}
	return plan, nil
}

// redeliveryBusyNodesTx: nodes with a deployment of the scope still running
// (one per node and scope, migration 288).
func redeliveryBusyNodesTx(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, nodeIDs []uuid.UUID,
) (map[uuid.UUID]bool, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT node_id FROM node_deployments
		WHERE configuration_scope_id=$1 AND node_id=ANY($2::uuid[])
		  AND state <> ALL (ARRAY['healthy','failed','reverted','rollback_failed','cancelled'])`, scopeID, nodeIDs)
	if err != nil {
		return nil, err
	}
	busy, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return nil, err
	}
	result := make(map[uuid.UUID]bool, len(busy))
	for _, nodeID := range busy {
		result[nodeID] = true
	}
	return result, nil
}

// deliver creates, in its own transaction, the rollout of a node's first
// batch of missing sites. Another process (or this one's earlier round) may
// have started one since the plan: the per (scope, node) advisory lock and
// the in-flight re-check make it a wait.
func (redeliverer *Redeliverer) deliver(ctx context.Context, scopeID uuid.UUID, node redeliveryNode,
) (redeliveryOutcome, uuid.UUID, error) {
	outcome, rolloutID := redeliveryRefused, uuid.Nil
	err := pgx.BeginFunc(ctx, redeliverer.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, redeliveryLockKey(scopeID, node.id)); err != nil {
			return err
		}
		busy, err := redeliveryBusyNodesTx(ctx, tx, scopeID, []uuid.UUID{node.id})
		if err != nil {
			return err
		}
		if busy[node.id] {
			outcome = redeliveryBusy
			return nil
		}
		now := redeliverer.now().UTC()
		ready, err := redeliverer.ready(ctx, tx, node.id, now)
		if err != nil {
			return err
		}
		if !ready {
			outcome = redeliveryNotReady
			return nil
		}
		batch := node.missing[:min(len(node.missing), redeliveryBatchSites)]
		rolloutID, err = redeliverer.createRolloutTx(ctx, tx, scopeID, node.id, batch, now)
		switch {
		case errors.Is(err, edgedeployment.ErrNodeDeploymentActive):
			outcome = redeliveryBusy
			return errRedeliveryRefused
		case errors.Is(err, errRedeliveryRefused) || errors.Is(err, edgedeployment.ErrNodeRecipientKeyUnavailable) ||
			errors.Is(err, edgedeployment.ErrNodeNotFound) || errors.Is(err, edgedeployment.ErrConfigurationScopeConflict) ||
			errors.Is(err, edgedeployment.ErrNodeReconciliationRequired):
			return errRedeliveryRefused
		case err != nil:
			return err
		}
		outcome = redeliveryCreated
		return nil
	})
	if errors.Is(err, errRedeliveryRefused) {
		return outcome, uuid.Nil, nil
	}
	if err != nil {
		return redeliveryRefused, uuid.Nil, err
	}
	return outcome, rolloutID, nil
}

// createRolloutTx persists the system secret rollout of the batch's current
// bindings to the node (errRedeliveryRefused: none can be served).
func (redeliverer *Redeliverer) createRolloutTx(ctx context.Context, tx pgx.Tx, scopeID, nodeID uuid.UUID,
	batch []certificateasset.RedeliverySite, now time.Time) (uuid.UUID, error) {
	var rolloutID uuid.UUID
	var delivered, versions []string
	skipped, err := redeliverer.assets.UseRedeliveryMaterialsInTx(ctx, tx, scopeID, batch, redeliverer.opaque,
		func(materials []certificateasset.PublicationMaterial) error {
			snapshot, err := buildPublicationSnapshot(scopeID, materials)
			if err != nil {
				return err
			}
			defer zeroPublicationBytes(snapshot)
			// The rollout's accountable principal: who made the first site's
			// binding (the system redelivers their publication).
			var accountable uuid.UUID
			if err := tx.QueryRow(ctx, `SELECT changed_by_user_id FROM certificate_site_binding_facts
				WHERE tenant_scope_id=$1 AND site_id=$2 AND sequence=$3`, scopeID, materials[0].SiteID,
				materials[0].BindingRevision).Scan(&accountable); err != nil {
				return err
			}
			attemptID, err := uuid.NewV7()
			if err != nil {
				return err
			}
			key := redeliveryIdempotencyPrefix + attemptID.String()
			builder := func(ctx context.Context, binding edgedeployment.SecretArtifactBinding) (edgedeployment.ArtifactInput, error) {
				return redeliverer.producer.Build(ctx, BuildRequest{
					EventID: binding.EventID, DeploymentID: binding.DeploymentID, Attempt: binding.Attempt,
					ConfigVersionID: binding.ConfigVersionID, ArtifactID: binding.ArtifactID,
					RecipientKeyID: binding.RecipientKeyID, RecipientPublicKey: binding.RecipientPublicKey,
					Materials: materials,
				})
			}
			created, err := redeliverer.rollouts.CreateSystemSecretRolloutTx(ctx, tx, edgedeployment.SystemSecretRolloutRequest{
				ConfigurationScopeID: scopeID, AccountableUserID: accountable, NodeIDs: []uuid.UUID{nodeID},
				CanonicalSnapshot: snapshot, GeneratorName: defaultGeneratorName, GeneratorVersion: defaultGeneratorVersion,
				PayloadDigest: sha256.Sum256(snapshot), RequiredCapabilities: edgeautopublish.CertificatePublicationCapabilities(),
				HealthCheck: redeliverer.config.HealthCheck, Deadline: now.Add(redeliverer.config.RoundTimeout),
				IdempotencyKey: key, RequestID: uuid.NewSHA1(uuid.NameSpaceOID, []byte(key)).String(),
				CorrelationID: attemptID.String(), Reason: redeliveryReason,
			}, builder)
			if err != nil {
				return err
			}
			rolloutID = created.Rollout.ID
			for _, material := range materials {
				delivered = append(delivered, material.SiteID.String())
				versions = append(versions, material.CertificateVersionID.String())
			}
			return nil
		})
	if err != nil {
		return uuid.Nil, err
	}
	if rolloutID == uuid.Nil {
		return uuid.Nil, errRedeliveryRefused
	}
	payload := map[string]any{
		"node_id": nodeID.String(), "rollout_id": rolloutID.String(), "sites": len(delivered),
		"site_ids": delivered, "version_ids": versions, "skipped_site_ids": lifecycleUUIDStrings(skipped),
		"target_scope_id": scopeID.String(), "operation": auditRedeliveryDeliver,
	}
	if err := audit.New(redeliverer.pool).Append(ctx, tx, audit.Event{ScopeID: scopeID, ActorKind: "system",
		ActorRef: "job:" + redeliveryReason, Action: auditRedeliveryDeliver, ResourceType: "node",
		ResourceID: nodeID.String(), RequestID: "certificate-redelivery:" + rolloutID.String(), Result: "success",
		Payload: payload}); err != nil {
		return uuid.Nil, fmt.Errorf("audit certificate redelivery: %w", err)
	}
	return rolloutID, nil
}

func redeliveryLockKey(scopeID, nodeID uuid.UUID) int64 {
	digest := sha256.Sum256([]byte("cdnca-certificate-redelivery-v1\x00" + scopeID.String() + "\x00" + nodeID.String()))
	return int64(binary.BigEndian.Uint64(digest[:8]))
}

// RedeliveryNodeReadyTx is the production RedeliveryNodeReady: the node is
// active, online, not isolated, and its enrollment advertises the
// certificate publication capabilities (as RenewalTargetNodes keeps nodes).
func RedeliveryNodeReadyTx(ctx context.Context, tx pgx.Tx, nodeID uuid.UUID, now time.Time) (bool, error) {
	var online bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM nodes node
		JOIN node_presence presence ON presence.node_id=node.id AND presence.status='online'
		WHERE node.id=$1 AND node.admin_state='active' AND NOT EXISTS(SELECT 1 FROM node_isolation_states isolation
		  WHERE isolation.node_id=node.id AND isolation.status='isolated'))`, nodeID).Scan(&online); err != nil || !online {
		return false, err
	}
	capabilities, err := edgepublish.LoadNodePublicationCapabilities(ctx, tx, []uuid.UUID{nodeID}, now)
	if errors.Is(err, edgepublish.ErrTargetIneligible) {
		return false, nil // identity not usable now (e.g. mid-rotation)
	}
	if err != nil {
		return false, err
	}
	return renewalNodeCapable(capabilities[nodeID], edgeautopublish.CertificatePublicationCapabilities()), nil
}
