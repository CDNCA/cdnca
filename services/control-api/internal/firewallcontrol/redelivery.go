package firewallcontrol

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
)

// Global firewall redelivery. A policy reaches the nodes
// its scope owned when it was published or recovered (one projection, one
// command per enabled site and owned node). A node the scope owns later, a
// node reinstalled under the same ID (a new host with an empty firewall
// state) and a node whose command never landed never get it.
//
// Every sweep, per policy whose active revision is settled (deployment
// active, failed or rolled_back: no newer revision in flight or split
// across nodes): the active revision's publication; the sites it was
// projected to that are still enabled; the scope's active, online, not
// isolated nodes; minus the (site, node) pairs whose current host
// (currentHostReceipt: receipts since the latest initial enrollment) applied
// that revision or later, and the pairs with a command still in flight. Each
// remaining pair gets one command of the publication (delivery>0, migration
// 628), signed like the projection's, applying its document. Attempts are the
// pair's redelivery rows on the current host: a failed one backs off
// (doubling), at most redeliveryMaxAttempts. Nothing else is stored.
const (
	// redeliveryCommandTTL is a redelivery command's deadline. The node was
	// online when it was created; past the deadline the sweep fails it.
	redeliveryCommandTTL  = 5 * time.Minute
	redeliveryMaxAttempts = 8

	auditRedeliveryDeliver = "firewall.policy.redeliver"
	redeliveryActorRef     = "job:global_firewall_redelivery"
)

type RedelivererConfig struct {
	// SweepInterval paces the sweeps.
	SweepInterval time.Duration
	// BatchSize bounds the commands of one policy per sweep.
	BatchSize int
	// RetryBase doubles per failed attempt of a pair up to RetryMaximum.
	RetryBase, RetryMaximum time.Duration
	Now                     func() time.Time
}

// Redeliverer runs beside the Projector (one instance per process; sweeps
// of several processes serialize on the policy row).
type Redeliverer struct {
	pool      *pgxpool.Pool
	projector *Projector
	auditor   auditAppender
	config    RedelivererConfig
	logger    *slog.Logger
}

func NewRedeliverer(pool *pgxpool.Pool, projector *Projector, config RedelivererConfig, logger *slog.Logger) (*Redeliverer, error) {
	if config.SweepInterval == 0 {
		config.SweepInterval = time.Minute
	}
	if config.BatchSize == 0 {
		config.BatchSize = 64
	}
	if config.RetryBase == 0 {
		config.RetryBase = time.Minute
	}
	if config.RetryMaximum == 0 {
		config.RetryMaximum = time.Hour
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if logger == nil {
		logger = slog.Default()
	}
	if pool == nil || projector == nil || config.SweepInterval < 0 || config.SweepInterval > time.Hour ||
		config.BatchSize < 1 || config.BatchSize > 1024 || config.RetryBase < 0 || config.RetryMaximum < config.RetryBase {
		return nil, ErrUnavailable
	}
	return &Redeliverer{pool: pool, projector: projector, auditor: audit.NewWithClock(pool, config.Now),
		config: config, logger: logger}, nil
}

// Run sweeps every SweepInterval until ctx ends. A failed sweep is logged
// and retried on the next one (the facts it reads are durable).
func (redeliverer *Redeliverer) Run(ctx context.Context) error {
	for {
		if _, err := redeliverer.SweepOnce(ctx); err != nil && ctx.Err() == nil {
			redeliverer.logger.Warn("global firewall redelivery sweep failed", "error", err)
		}
		timer := time.NewTimer(redeliverer.config.SweepInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// RedeliverySweep is what one sweep did.
type RedeliverySweep struct {
	Expired  int // redelivery commands past their deadline, failed
	Commands int // redelivery commands created
}

// SweepOnce fails expired redeliveries, then sweeps every policy with a
// settled active revision. A policy's failure does not stop the others.
func (redeliverer *Redeliverer) SweepOnce(ctx context.Context) (RedeliverySweep, error) {
	if redeliverer == nil || ctx == nil {
		return RedeliverySweep{}, ErrUnavailable
	}
	now := redeliverer.config.Now().UTC().Truncate(time.Microsecond)
	var result RedeliverySweep
	// The gateway and the agent refuse a command past its deadline: nothing
	// will acknowledge it, and in flight it would hold the pair (and the
	// policy's next projection) back.
	expired, err := redeliverer.pool.Exec(ctx, `UPDATE firewall_command_outbox SET state='failed',available_at=$2,
		last_error='redelivery_expired',updated_at=$2
		WHERE delivery>0 AND state IN ('pending','retryable','published') AND created_at<=$1`, now.Add(-redeliveryCommandTTL), now)
	if err != nil {
		return result, fmt.Errorf("expire global firewall redeliveries: %w", err)
	}
	result.Expired = int(expired.RowsAffected())
	rows, err := redeliverer.pool.Query(ctx, `SELECT tenant_scope_id FROM global_firewall_policies
		WHERE active_revision>0 AND deployment_state IN ('active','failed','rolled_back') ORDER BY 1`)
	if err != nil {
		return result, fmt.Errorf("list global firewall redelivery scopes: %w", err)
	}
	scopes, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return result, fmt.Errorf("list global firewall redelivery scopes: %w", err)
	}
	var failures []error
	for _, scopeID := range scopes {
		created, err := redeliverer.sweepScope(ctx, scopeID, now)
		if err != nil {
			failures = append(failures, fmt.Errorf("global firewall redelivery scope %s: %w", scopeID, err))
			continue
		}
		result.Commands += created
	}
	return result, errors.Join(failures...)
}

type redeliveryPair struct{ nodeID, siteID uuid.UUID }

// heldOnCurrentHost: the command of alias (scope $2, policy $3) was applied
// on the node's current host (an apply that moved the active version, or a
// recover that rolled back to its document).
func heldOnCurrentHost(alias string) string {
	return alias + `.tenant_scope_id=$2 AND ` + alias + `.policy_id=$3 AND ` + alias + `.policy_kind='global' AND ` +
		alias + `.node_id=node.id AND ` + alias + `.site_id=projected.site_id AND ` + alias + `.state='acked' AND ` +
		alias + `.terminal_state IN ('applied','rolled_back') AND ` + alias + `.active_policy_version=` + alias + `.policy_version AND ` +
		currentHostReceipt(alias)
}

// sweepScope creates, in one transaction holding the policy row (Put,
// Recover and the projection's settlement take it too), the commands of the
// scope's missing pairs.
func (redeliverer *Redeliverer) sweepScope(ctx context.Context, scopeID uuid.UUID, now time.Time) (int, error) {
	created := 0
	err := pgx.BeginFunc(ctx, redeliverer.pool, func(tx pgx.Tx) error {
		var publication globalPublication
		var document, digest []byte
		err := tx.QueryRow(ctx, `SELECT outbox.id,outbox.tenant_scope_id,outbox.policy_id,outbox.revision,outbox.operation,
				COALESCE(outbox.recovery_reason,''),outbox.document,outbox.document_sha256
			FROM global_firewall_policies policy
			JOIN global_firewall_publication_outbox outbox ON outbox.tenant_scope_id=policy.tenant_scope_id
			 AND outbox.policy_id=policy.id AND outbox.revision=policy.active_revision AND outbox.state IN ('active','rolled_back')
			WHERE policy.tenant_scope_id=$1 AND policy.active_revision>0
			  AND policy.deployment_state IN ('active','failed','rolled_back')
			FOR UPDATE OF policy`, scopeID).Scan(&publication.ID, &publication.TenantScopeID, &publication.PolicyID,
			&publication.Revision, &publication.Operation, &publication.RecoveryReason, &document, &digest)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil // a revision in flight since the listing, or none settled with commands
		}
		if err != nil || len(digest) != sha256.Size {
			return err
		}
		copy(publication.DocumentSHA256[:], digest)
		if err := strictJSON(document, &publication.Document); err != nil {
			return err
		}
		pairs, err := redeliverer.missingPairsTx(ctx, tx, publication, now)
		if err != nil || len(pairs) == 0 {
			return err
		}
		var installationID string
		if err := tx.QueryRow(ctx, `SELECT installation_id FROM control_installation_entitlement WHERE singleton=true FOR SHARE`).
			Scan(&installationID); err != nil {
			return err
		}
		var sites []uuid.UUID
		for _, pair := range pairs {
			sites = append(sites, pair.siteID)
		}
		serving, err := siteServingNodes(ctx, tx, scopeID, sites)
		if err != nil {
			return err
		}
		delivered := map[uuid.UUID][]string{} // node -> sites
		commands := map[uuid.UUID][]string{}  // node -> command ids
		var nodes []uuid.UUID
		for _, pair := range pairs {
			commandID, err := redeliverer.insertTx(ctx, tx, publication, installationID, pair,
				servesSite(serving, pair.siteID, pair.nodeID), now)
			if err != nil {
				return err
			}
			if delivered[pair.nodeID] == nil {
				nodes = append(nodes, pair.nodeID)
			}
			delivered[pair.nodeID] = append(delivered[pair.nodeID], pair.siteID.String())
			commands[pair.nodeID] = append(commands[pair.nodeID], commandID.String())
			created++
		}
		for _, nodeID := range nodes {
			if err := redeliverer.auditor.Append(ctx, tx, audit.Event{ScopeID: scopeID, ActorKind: "system",
				ActorRef: redeliveryActorRef, Action: auditRedeliveryDeliver, ResourceType: "node",
				ResourceID: nodeID.String(), RequestID: "global-firewall-redelivery:" + commands[nodeID][0], Result: "success",
				Payload: map[string]any{"node_id": nodeID.String(), "policy_id": publication.PolicyID.String(),
					"publication_id": publication.ID.String(), "revision": publication.Revision,
					"sites": len(delivered[nodeID]), "site_ids": delivered[nodeID], "command_ids": commands[nodeID]}}); err != nil {
				return fmt.Errorf("audit global firewall redelivery: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return created, nil
}

// missingPairsTx lists the (node, site) pairs that need a command of
// publication now, at most BatchSize, in node then site order. The sites are
// the publication's projected sites still enabled (a site created since
// waits for the next publication, as before); the nodes are the scope's
// ready nodes now. A disabled document clears what a node holds, so it only
// goes to a node holding an older revision of the policy.
func (redeliverer *Redeliverer) missingPairsTx(ctx context.Context, tx pgx.Tx, publication globalPublication, now time.Time,
) ([]redeliveryPair, error) {
	rows, err := tx.Query(ctx, `SELECT node.id,projected.site_id
		FROM (SELECT DISTINCT site_id FROM firewall_command_outbox WHERE publication_id=$1 AND delivery=0) projected
		JOIN sites site ON site.id=projected.site_id AND site.scope_id=$2 AND site.deleted_at IS NULL AND site.enabled
		JOIN nodes node ON node.scope_id=$2 AND node.admin_state='active'
		JOIN node_presence presence ON presence.node_id=node.id AND presence.status='online'
		CROSS JOIN LATERAL (SELECT count(*)::int AS count,max(attempt.created_at) AS last FROM firewall_command_outbox attempt
		  WHERE attempt.publication_id=$1 AND attempt.node_id=node.id AND attempt.site_id=projected.site_id
		    AND attempt.delivery>0 AND attempt.created_at>=`+currentHostSince("node.id")+`) attempt
		WHERE NOT EXISTS(SELECT 1 FROM node_isolation_states isolation WHERE isolation.node_id=node.id AND isolation.status='isolated')
		  AND NOT EXISTS(SELECT 1 FROM firewall_command_outbox held WHERE `+heldOnCurrentHost("held")+` AND held.global_revision>=$4)
		  AND ($5 OR EXISTS(SELECT 1 FROM firewall_command_outbox held WHERE `+heldOnCurrentHost("held")+` AND held.global_revision<$4))
		  AND NOT EXISTS(SELECT 1 FROM firewall_command_outbox flight WHERE flight.tenant_scope_id=$2 AND flight.policy_id=$3
		    AND flight.policy_kind='global' AND flight.node_id=node.id AND flight.site_id=projected.site_id
		    AND flight.state IN ('pending','retryable','published')
		    AND flight.created_at>CASE WHEN flight.delivery>0 THEN $6::timestamptz ELSE $7::timestamptz END)
		  AND attempt.count<$8 AND (attempt.count=0 OR attempt.last+make_interval(secs=>LEAST($9::float8*power(2,attempt.count-1),$10::float8))<=$11)
		ORDER BY node.id,projected.site_id LIMIT $12`,
		publication.ID, publication.TenantScopeID, publication.PolicyID, publication.Revision, publication.Document.Enabled,
		now.Add(-redeliveryCommandTTL), now.Add(-redeliverer.projector.config.CommandTTL), redeliveryMaxAttempts,
		redeliverer.config.RetryBase.Seconds(), redeliverer.config.RetryMaximum.Seconds(), now, redeliverer.config.BatchSize)
	if err != nil {
		return nil, fmt.Errorf("list global firewall redelivery pairs: %w", err)
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (redeliveryPair, error) {
		var pair redeliveryPair
		return pair, row.Scan(&pair.nodeID, &pair.siteID)
	})
}

// insertTx queues one redelivery command of publication for pair: the
// projection's command row with its own identity and the pair's next
// delivery number (the policy row lock serializes the numbering).
func (redeliverer *Redeliverer) insertTx(ctx context.Context, tx pgx.Tx, publication globalPublication, installationID string,
	pair redeliveryPair, serves bool, now time.Time) (uuid.UUID, error) {
	var delivery int
	if err := tx.QueryRow(ctx, `SELECT COALESCE(max(delivery),0)+1 FROM firewall_command_outbox
		WHERE publication_id=$1 AND node_id=$2 AND site_id=$3`, publication.ID, pair.nodeID, pair.siteID).Scan(&delivery); err != nil {
		return uuid.Nil, err
	}
	commandID, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, err
	}
	command, digest, err := redeliverer.projector.command(ctx, tx, publication, pair.siteID, pair.nodeID, serves, now, commandID)
	if err != nil {
		return uuid.Nil, err
	}
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(command)
	if err != nil {
		return uuid.Nil, ErrUnavailable
	}
	_, err = tx.Exec(ctx, `INSERT INTO firewall_command_outbox(
		id,installation_id,tenant_scope_id,site_id,policy_id,policy_kind,binding_id,publication_id,node_id,
		policy_version,expected_active_policy_version,idempotency_key,command_bytes,command_sha256,
		publication_bundle_sha256,canonical_payload_sha256,runtime_snapshot_sha256,signing_key_id,
		signature_algorithm,state,attempts,available_at,created_at,updated_at,global_revision,delivery)
		VALUES($1,$2,$3,$4,$5,'global',NULL,$6,$7,$8,$9,$10,$11,$12,$13,$13,$13,$14,'ed25519','pending',0,$15,$15,$15,$16,$17)`,
		commandID, installationID, publication.TenantScopeID, pair.siteID, publication.PolicyID, publication.ID, pair.nodeID,
		int64(command.PolicyVersion), int64(command.ExpectedActivePolicyVersion), command.IdempotencyKey,
		encoded, digest[:], publication.DocumentSHA256[:], redeliverer.projector.signer.KeyID(), now, publication.Revision, delivery)
	if err != nil {
		return uuid.Nil, fmt.Errorf("queue global firewall redelivery: %w", err)
	}
	return commandID, nil
}
