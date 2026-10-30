package edgepublish

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// System republication: the control plane republishes a tenant
// scope by itself when something outside the tenant's configuration changes
// what its nodes should run: a node's capabilities, a traffic suspension, a
// line group's node set, a failed sync. It never publishes a tenant edit.
//
// The scope's published facts are its latest edge_config_publications row
// (config_versions.canonical_snapshot is that publication's immutable copy)
// or, when newer, the publication it last asked for and was refused because a
// node lacked a gated capability (edge_capability_publication_holds).
// Publication compiles the current rows, so the worker first proves they are
// still those facts: every source revision advance since that baseline must
// be a system segment (edge_system_revision_segments). Any other advance is an
// unpublished tenant edit, and the republication is blocked.
const (
	SystemTriggerNodeCapability     = "node_capability"
	SystemTriggerTrafficEnforcement = "traffic_enforcement"
	SystemTriggerLineGroup          = "line_group"
	SystemTriggerNodeSync           = "node_sync"
	// SystemTriggerDomainOwnership: a verified claim disabled another
	// scope's site (g6-domain), or a claim suspension was released.
	SystemTriggerDomainOwnership = "domain_ownership"
	// SystemTriggerSecondaryVerification: an overdue secondary identity
	// verification stopped a user's sites, or its completion restored them (FX57).
	SystemTriggerSecondaryVerification = "secondary_verification"
	// SystemTriggerAccountSuspension: a disabled user, suspended membership
	// or suspended tenant stopped its sites, or its reactivation restored
	// them.
	SystemTriggerAccountSuspension = "account_suspension"
	// SystemTriggerRuleCatalog: the synced security rule catalog changed the
	// OWASP CRS rule text the scope's published release embeds.
	SystemTriggerRuleCatalog = "rule_catalog"
	// SystemTriggerChallengeDelivery: a node that joined the scope's targets or
	// recovered confirmed (healthy receipt) the redelivered JS challenge policy
	// a site of the scope is bound to.
	SystemTriggerChallengeDelivery = "challenge_delivery"
	// SystemTriggerModuleEntitlement: the lease grants again a module the
	// scope's latest publication uses; the scope was
	// pending republication since the module was revoked.
	SystemTriggerModuleEntitlement = "module_entitlement"
	// SystemTriggerNodeNetworks: the platform's node addresses changed (a node
	// added, retired or deleted, its IPv4/IPv6 or secondary IPs edited) and
	// the scope's latest publication carries the DDoS node network exemption
	// (system.ddos.node_networks) without them.
	SystemTriggerNodeNetworks = "node_networks"
	// SystemTriggerErrorPagePublished / SystemTriggerOriginAuthPublished: the
	// scope published its error pages or origin authentication.
	// A site object (site_runtime 9) carries both, built at publication
	// time, so the scope's site objects go out again.
	SystemTriggerErrorPagePublished  = "error_page_published"
	SystemTriggerOriginAuthPublished = "origin_auth_published"
	// SystemTriggerOriginFailover: the origin probe (or the user's switch
	// back) moved a site's active origin level.
	SystemTriggerOriginFailover = "origin_failover"
	// SystemTriggerMarketLimits: a market supply's per node share or hold
	// changed (grant limits, serving node count, supply.hold; ML-08,
	// market_supply_limits).
	SystemTriggerMarketLimits = "market_limits"
	// SystemTriggerIPList: a named IP list a bound ACL / WAF policy
	// references changed or was deleted; the rules carry
	// the list's contents, so the scope's sites go out again.
	SystemTriggerIPList = "ip_list"
	// SystemTriggerAttackEscalation: attack escalation (migration 460) put a
	// site on a high defense / unlimited line group: that group's nodes must
	// hold the site before DNS moves to them.
	SystemTriggerAttackEscalation = "attack_escalation"
	// SystemTriggerPackageExpiry: a package's term ended (its sites go out
	// marked package_expired, the node answers the expiry page) or a renewal
	// extended it (the mark goes away); errpage-4 S3, migration 511.
	SystemTriggerPackageExpiry = "package_expiry"
	// SystemTriggerNodeStorage: a node's cache directory, cache limit or log
	// directory (节点设置) changed; every scope goes out again so the node's
	// key documents carry them (fix-nodesettings, NODE_STORAGE, migration 538).
	SystemTriggerNodeStorage = "node_storage"
	// SystemTriggerPackageSuspension: a package subscription was suspended
	// (its sites and forwards stop serving, configuration kept) or unsuspended
	// (they go out again); bb03, ADR 0019 §5, migration 555.
	SystemTriggerPackageSuspension = "package_suspension"
	// SystemTriggerCertificateRenewal: an automatic renewal's new version
	// reached its nodes and the sites were switched to it (fix-dnscert3,
	// migration 570); the sites go out referencing it without waiting for the
	// tenant's publication.
	SystemTriggerCertificateRenewal = "certificate_renewal"

	SystemOutcomePublished       = "published"
	SystemOutcomeUnchanged       = "unchanged"
	SystemOutcomeBlocked         = "blocked_unpublished_changes"
	SystemOutcomeNoBaseline      = "no_baseline"
	SystemOutcomeNoCapableTarget = "no_capable_target"
	SystemOutcomeAutomaticScope  = "automatic_scope"
	SystemOutcomeRetry           = "retry"
	SystemOutcomeFailed          = "failed"

	// SystemRepublicationDebounce merges the triggers one scope receives
	// within it into one publication.
	SystemRepublicationDebounce    = 5 * time.Second
	SystemRepublicationMaxAttempts = 8
	systemRepublicationDeadline    = 15 * time.Minute
	systemRepublicationMaxBackoff  = 10 * time.Minute
)

var ErrSystemRepublicationStale = errors.New("system republication claim is stale")

// systemActorFacts marks an Actor as the control plane itself. The actor's
// user and scope are the publication's accountable principal (the one whose
// publication is being redelivered); audit records no actor user.
type systemActorFacts struct {
	attemptID uuid.UUID
	triggers  []string
}

func auditActorUserID(actor Actor) *uuid.UUID {
	if actor.system != nil || actor.UserID == uuid.Nil {
		return nil
	}
	id := actor.UserID
	return &id
}

func validSystemTrigger(value string) bool {
	switch value {
	case SystemTriggerNodeCapability, SystemTriggerTrafficEnforcement, SystemTriggerLineGroup, SystemTriggerNodeSync,
		SystemTriggerDomainOwnership, SystemTriggerSecondaryVerification, SystemTriggerRuleCatalog,
		SystemTriggerChallengeDelivery, SystemTriggerModuleEntitlement, SystemTriggerThemeActivation,
		SystemTriggerAccountSuspension, SystemTriggerNodeNetworks, SystemTriggerErrorPagePublished,
		SystemTriggerOriginAuthPublished, SystemTriggerOriginFailover, SystemTriggerMarketLimits, SystemTriggerIPList,
		SystemTriggerAttackEscalation, SystemTriggerPackageExpiry, SystemTriggerNodeStorage,
		SystemTriggerPackageSuspension, SystemTriggerCertificateRenewal:
		return true
	}
	return false
}

// RecordSystemRevisionSegmentTx attributes the scope's source revision
// advances from fromRevision to its current revision to a system writer. The
// caller holds the scope's edge_configuration_scopes row lock and made every
// advance since fromRevision itself.
func RecordSystemRevisionSegmentTx(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, fromRevision int64, source string) error {
	if ctx == nil || tx == nil || scopeID == uuid.Nil || fromRevision < 1 || !validSystemTrigger(source) {
		return ErrInvalidInput
	}
	_, err := tx.Exec(ctx, `INSERT INTO edge_system_revision_segments(scope_id,from_revision,to_revision,source,recorded_at)
		SELECT scope_id,$2,source_revision,$3,clock_timestamp() FROM edge_configuration_scopes
		WHERE scope_id=$1 AND source_revision>$2
		ON CONFLICT (scope_id,from_revision) DO NOTHING`, scopeID, fromRevision, source)
	return err
}

// SystemTriggerImmediate: a site stop or restore (traffic over limit, domain
// claim, overdue secondary verification) is queued due now, never debounced, and pulls a debounced pending
// republication of the scope forward. So is a node address change: until the
// nodes get the new exemption, DDoS protection may ban node to node traffic.
func SystemTriggerImmediate(trigger string) bool {
	return trigger == SystemTriggerTrafficEnforcement || trigger == SystemTriggerDomainOwnership ||
		trigger == SystemTriggerSecondaryVerification || trigger == SystemTriggerAccountSuspension ||
		trigger == SystemTriggerNodeNetworks || trigger == SystemTriggerOriginFailover || trigger == SystemTriggerMarketLimits ||
		trigger == SystemTriggerAttackEscalation || trigger == SystemTriggerPackageExpiry || trigger == SystemTriggerNodeStorage ||
		trigger == SystemTriggerPackageSuspension || trigger == SystemTriggerCertificateRenewal
}

type SystemRepublicationRequest struct {
	ScopeID  uuid.UUID
	Trigger  string
	Debounce time.Duration
}

// RequestSystemRepublicationTx queues the scope's system republication or
// merges the trigger into the queued one, which keeps its due time. A trigger
// arriving while it runs queues one more run (generation > claimed).
func RequestSystemRepublicationTx(ctx context.Context, tx pgx.Tx, request SystemRepublicationRequest) error {
	if ctx == nil || tx == nil || request.ScopeID == uuid.Nil || !validSystemTrigger(request.Trigger) ||
		request.Debounce < 0 || request.Debounce > time.Hour {
		return ErrInvalidInput
	}
	if SystemTriggerImmediate(request.Trigger) {
		request.Debounce = 0
	}
	_, err := tx.Exec(ctx, `INSERT INTO edge_system_republication_heads(
		scope_id,generation,state,triggers,due_at,attempt,created_at,updated_at)
		VALUES($1,1,'pending',ARRAY[$2::text],clock_timestamp()+$3::bigint*interval '1 millisecond',0,
		  clock_timestamp(),clock_timestamp())
		ON CONFLICT (scope_id) DO UPDATE SET
		  generation=edge_system_republication_heads.generation+1,
		  state=CASE WHEN edge_system_republication_heads.state='leased' THEN 'leased' ELSE 'pending' END,
		  triggers=CASE WHEN edge_system_republication_heads.state='idle' THEN EXCLUDED.triggers
		    ELSE ARRAY(SELECT DISTINCT value FROM unnest(edge_system_republication_heads.triggers||EXCLUDED.triggers) value
		      ORDER BY 1) END,
		  due_at=CASE WHEN edge_system_republication_heads.state='pending'
		    THEN LEAST(edge_system_republication_heads.due_at,EXCLUDED.due_at) ELSE EXCLUDED.due_at END,
		  attempt=CASE WHEN edge_system_republication_heads.state='leased'
		    THEN edge_system_republication_heads.attempt ELSE 0 END,
		  updated_at=EXCLUDED.updated_at`, request.ScopeID, request.Trigger, request.Debounce.Milliseconds())
	return err
}

type SystemRepublisherConfig struct {
	WorkerID      string
	LeaseDuration time.Duration
	RetryDelay    time.Duration
}

// SystemRepublisher runs due system republications with the edge publication
// service's compile, sign, persist and rollout path.
type SystemRepublisher struct {
	service *Service
	config  SystemRepublisherConfig
	// errorPages delivers trigger theme_activation (WithErrorPagePublisher).
	errorPages *ErrorPagePublisher
}

func NewSystemRepublisher(service *Service, config SystemRepublisherConfig) (*SystemRepublisher, error) {
	if service == nil || service.pool == nil || !labelPattern.MatchString(config.WorkerID) ||
		config.LeaseDuration < time.Second || config.LeaseDuration > time.Hour ||
		config.RetryDelay < 0 || config.RetryDelay > time.Hour {
		return nil, ErrInvalidInput
	}
	return &SystemRepublisher{service: service, config: config}, nil
}

type systemClaim struct {
	scopeID    uuid.UUID
	generation int64
	attempt    int
	triggers   []string
	excluded   []uuid.UUID
	leaseToken uuid.UUID
}

type systemRefusal struct {
	NodeID       uuid.UUID `json:"node_id"`
	AgentVersion string    `json:"agent_version,omitempty"`
	Feature      string    `json:"feature"`
	Capability   string    `json:"capability,omitempty"`
	Required     uint32    `json:"required,omitempty"`
	Advertised   uint32    `json:"advertised,omitempty"`
	// Challenge: the node lacks a site's JS challenge policy
	// (ChallengePolicyUnavailableError), not a capability.
	Challenge *systemChallengeRefusal `json:"challenge,omitempty"`
	// RulePacks: the node lacks these rule packs (RulePackUnavailableError).
	RulePacks []string `json:"rule_packs,omitempty"`
	// RulePackIDs name RulePacks for the audit (pack_id@version, or the CRS
	// profile artifact_id@version), sorted; a digest no row names is absent.
	RulePackIDs []string `json:"rule_pack_ids,omitempty"`
}

type systemChallengeRefusal struct {
	SiteID        string `json:"site_id"`
	Domain        string `json:"domain"`
	PolicyID      string `json:"policy_id"`
	PolicyVersion uint64 `json:"policy_version"`
}

type systemAttempt struct {
	outcome          string
	baselineRevision int64
	sourceRevision   int64
	publication      *PublishResult
	nodeIDs          []uuid.UUID
	refused          []systemRefusal
	excluded         []uuid.UUID
	errorClass       string
	overlay          *publicationOverlay
	// errorPageRolloutID: a theme_activation attempt published the scope's
	// error page snapshot (no edge_config_publications row).
	errorPageRolloutID *uuid.UUID
}

// RunOnce claims one due scope and republishes it. The publication, the
// attempt record and the head update commit together.
func (republisher *SystemRepublisher) RunOnce(ctx context.Context) (bool, error) {
	if republisher == nil || ctx == nil {
		return false, ErrInvalidInput
	}
	claim, found, err := republisher.claim(ctx)
	if err != nil || !found {
		return false, err
	}
	err = pgx.BeginFunc(ctx, republisher.service.pool, func(tx pgx.Tx) error {
		return republisher.republishTx(ctx, tx, claim)
	})
	if err == nil || errors.Is(err, ErrSystemRepublicationStale) {
		return true, nil
	}
	return true, republisher.fail(ctx, claim, err)
}

func (republisher *SystemRepublisher) claim(ctx context.Context) (systemClaim, bool, error) {
	var claim systemClaim
	found := false
	err := pgx.BeginFunc(ctx, republisher.service.pool, func(tx pgx.Tx) error {
		token, err := uuid.NewV7()
		if err != nil {
			return err
		}
		err = tx.QueryRow(ctx, `WITH due AS (
				SELECT scope_id FROM edge_system_republication_heads
				WHERE state='pending' AND due_at<=clock_timestamp()
				   OR state='leased' AND lease_expires_at<=clock_timestamp()
				ORDER BY due_at,scope_id LIMIT 1 FOR UPDATE SKIP LOCKED)
			UPDATE edge_system_republication_heads head SET state='leased',lease_owner=$1,lease_token=$2,
			  lease_expires_at=clock_timestamp()+$3::bigint*interval '1 millisecond',claimed_generation=head.generation,
			  attempt=LEAST(head.attempt+1,$4),updated_at=clock_timestamp()
			FROM due WHERE head.scope_id=due.scope_id
			RETURNING head.scope_id,head.generation,head.attempt,head.triggers,head.excluded_node_ids`,
			republisher.config.WorkerID, token, republisher.config.LeaseDuration.Milliseconds(),
			SystemRepublicationMaxAttempts).Scan(&claim.scopeID, &claim.generation, &claim.attempt,
			&claim.triggers, &claim.excluded)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		claim.leaseToken, found = token, true
		return nil
	})
	return claim, found, err
}

// republishTx locks in publication order (HTTP policy facts, configuration
// scope, then the head), decides from the published facts and publishes.
func (republisher *SystemRepublisher) republishTx(ctx context.Context, tx pgx.Tx, claim systemClaim) error {
	service := republisher.service
	if err := lockHTTPPolicyPublicationFacts(ctx, tx, claim.scopeID); err != nil {
		return err
	}
	var current int64
	if err := tx.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1 FOR UPDATE`,
		claim.scopeID).Scan(&current); err != nil {
		return err
	}
	if err := lockSystemClaim(ctx, tx, claim); err != nil {
		return err
	}
	now, err := databaseNow(ctx, tx)
	if err != nil {
		return err
	}
	attemptID, err := uuid.NewV7()
	if err != nil {
		return err
	}
	others := slices.DeleteFunc(slices.Clone(claim.triggers), func(trigger string) bool {
		return trigger == SystemTriggerThemeActivation
	})
	if len(others) == len(claim.triggers) {
		attempt, err := republisher.decideTx(ctx, tx, claim, attemptID, current, now)
		if err != nil {
			return err
		}
		return finishSystemAttemptTx(ctx, tx, service.auditor, claim, attemptID, attempt)
	}
	if len(others) == 0 {
		theme, err := republisher.republishThemeTx(ctx, tx, claim, attemptID, now)
		if err != nil {
			return err
		}
		attempt := systemAttempt{outcome: theme.outcome, nodeIDs: theme.nodeIDs, refused: theme.refused,
			excluded: refusedNodeIDs(theme.refused)}
		if theme.outcome == SystemOutcomePublished {
			attempt.errorPageRolloutID = &theme.rolloutID
		}
		return finishSystemAttemptTx(ctx, tx, service.auditor, claim, attemptID, attempt)
	}
	// The configuration republication goes first; the error page one waits
	// for its own claim (its rollout would find the nodes' deployments still
	// running), queued again as theme_activation alone.
	configuration := claim
	configuration.triggers = others
	attempt, err := republisher.decideTx(ctx, tx, configuration, attemptID, current, now)
	if err != nil {
		return err
	}
	if err := finishSystemAttemptTx(ctx, tx, service.auditor, configuration, attemptID, attempt); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE edge_system_republication_heads SET state='pending',
		triggers=CASE WHEN state='pending' THEN ARRAY(SELECT DISTINCT value FROM unnest(triggers||ARRAY[$2::text]) value ORDER BY 1)
		  ELSE ARRAY[$2::text] END,
		due_at=CASE WHEN state='pending' THEN LEAST(due_at,clock_timestamp()+$3::bigint*interval '1 millisecond')
		  ELSE clock_timestamp()+$3::bigint*interval '1 millisecond' END,
		updated_at=clock_timestamp() WHERE scope_id=$1`, claim.scopeID, SystemTriggerThemeActivation,
		ThemeErrorPageRepublicationDebounce.Milliseconds())
	return err
}

type systemBaseline struct {
	revision   int64
	actor      Actor
	rolloutID  uuid.UUID
	holdNodes  []uuid.UUID
	holdRefuse []uuid.UUID
	fromHold   bool
	lastNodes  []uuid.UUID
	hasRollout bool
}

func (republisher *SystemRepublisher) decideTx(
	ctx context.Context, tx pgx.Tx, claim systemClaim, attemptID uuid.UUID, current int64, now time.Time,
) (systemAttempt, error) {
	var automatic bool
	if err := tx.QueryRow(ctx, `SELECT COALESCE((SELECT mode='automatic' FROM edge_automatic_publication_policy_facts
		WHERE target_scope_id=$1 ORDER BY revision DESC LIMIT 1),false)`, claim.scopeID).Scan(&automatic); err != nil {
		return systemAttempt{}, err
	}
	if automatic {
		// Its policy republishes it (edgeautopublish source node_capability).
		return systemAttempt{outcome: SystemOutcomeAutomaticScope, excluded: claim.excluded}, nil
	}
	baseline, found, err := loadSystemBaseline(ctx, tx, claim.scopeID)
	if err != nil {
		return systemAttempt{}, err
	}
	clean := false
	if found {
		if clean, err = systemChainClean(ctx, tx, claim.scopeID, baseline.revision, current); err != nil {
			return systemAttempt{}, err
		}
	}
	// Unpublished tenant edits: redeliver the latest publication with only the
	// system stops applied (stop overlay), never the scope's current rows.
	var overlay *publicationOverlay
	if !clean {
		var ok bool
		if overlay, ok, err = loadPublicationOverlay(ctx, tx, claim.scopeID); err != nil {
			return systemAttempt{}, err
		}
		if !ok && !found {
			return systemAttempt{outcome: SystemOutcomeNoBaseline}, nil
		}
		if !ok {
			return systemAttempt{outcome: SystemOutcomeBlocked, baselineRevision: baseline.revision,
				sourceRevision: current, excluded: claim.excluded}, nil
		}
		baseline = systemBaseline{revision: overlay.base.sourceRevision, actor: overlay.actor, lastNodes: overlay.lastNodes}
	}
	seeds := slices.Concat(baseline.lastNodes, baseline.holdNodes, claim.excluded)
	// The overlay keeps the published node set: a line group change the
	// tenant has not published is not followed.
	candidates, refused, err := systemTargetNodes(ctx, tx, claim.scopeID, seeds, overlay == nil)
	if err != nil {
		return systemAttempt{}, err
	}
	if len(candidates) == 0 {
		return systemAttempt{outcome: SystemOutcomeNoCapableTarget, baselineRevision: baseline.revision,
			sourceRevision: current, refused: refused, excluded: refusedNodeIDs(refused)}, nil
	}
	// Advance the revision this publication takes (one publication per
	// revision) and attribute it; the savepoint drops both when nothing changes.
	outer, err := tx.Begin(ctx)
	if err != nil {
		return systemAttempt{}, err
	}
	defer func() { _ = outer.Rollback(context.Background()) }()
	if _, err := outer.Exec(ctx, `SELECT advance_edge_configuration_scope_revision($1)`, claim.scopeID); err != nil {
		return systemAttempt{}, err
	}
	if err := RecordSystemRevisionSegmentTx(ctx, outer, claim.scopeID, current, claim.triggers[0]); err != nil {
		return systemAttempt{}, err
	}
	revision := current + 1
	schema := DefaultSiteRuntimeSchema
	result, published, refusals, err := republisher.service.publishExcludingIncapableTx(ctx, outer, candidates,
		func(nodes []uuid.UUID) (normalizedPublishRequest, error) {
			normalized, err := normalizeAutomaticPublishRequest(
				republisher.systemPublishRequest(claim, attemptID, baseline.actor, revision, schema, nodes, now), now)
			normalized.overlay = overlay
			return normalized, err
		}, now)
	if err != nil {
		return systemAttempt{}, err
	}
	refused = append(refused, refusals...)
	if len(published) == 0 {
		return systemAttempt{outcome: SystemOutcomeNoCapableTarget, baselineRevision: baseline.revision,
			sourceRevision: current, refused: refused, excluded: refusedNodeIDs(refused)}, nil
	}
	candidates = published
	excluded := refusedNodeIDs(refused)
	unchanged := slices.Equal(candidates, baseline.lastNodes)
	if baseline.fromHold {
		// A refused publication goes out once a node it was refused for can
		// take it, never on a trigger that changed none of them.
		unchanged = !slices.ContainsFunc(candidates, func(nodeID uuid.UUID) bool {
			return slices.Contains(baseline.holdRefuse, nodeID)
		})
	}
	contentChange := systemContentTrigger(claim.triggers)
	if overlay != nil {
		// The overlay attaches the current CRS rule text (overlay.build).
		contentChange = overlay.changesSites() || slices.Contains(claim.triggers, SystemTriggerNodeSync) ||
			slices.Contains(claim.triggers, SystemTriggerRuleCatalog) ||
			slices.Contains(claim.triggers, SystemTriggerChallengeDelivery) ||
			slices.Contains(claim.triggers, SystemTriggerModuleEntitlement) ||
			slices.Contains(claim.triggers, SystemTriggerErrorPagePublished) ||
			slices.Contains(claim.triggers, SystemTriggerOriginAuthPublished) ||
			// the overlay re-marks expired sites from the current rows
			slices.Contains(claim.triggers, SystemTriggerPackageExpiry) ||
			// the node storage rides in the key documents, never in the sites
			slices.Contains(claim.triggers, SystemTriggerNodeStorage) ||
			// the overlay swaps in the renewed certificate versions
			slices.Contains(claim.triggers, SystemTriggerCertificateRenewal)
	}
	if unchanged && !contentChange {
		// The scope's nodes already run exactly this.
		return systemAttempt{outcome: SystemOutcomeUnchanged, baselineRevision: baseline.revision,
			sourceRevision: current, nodeIDs: candidates, refused: refused, excluded: excluded}, nil
	}
	if err := outer.Commit(ctx); err != nil {
		return systemAttempt{}, err
	}
	if overlay != nil {
		// The overlay did not publish the tenant's rows: give them a revision
		// of their own again (unattributed), so the tenant can publish them.
		if _, err := tx.Exec(ctx, `SELECT advance_edge_configuration_scope_revision($1)`, claim.scopeID); err != nil {
			return systemAttempt{}, err
		}
	}
	return systemAttempt{outcome: SystemOutcomePublished, baselineRevision: baseline.revision,
		sourceRevision: revision, publication: &result, nodeIDs: candidates, refused: refused, excluded: excluded,
		overlay: overlay}, nil
}

// loadSystemBaseline returns the scope's published facts: its latest
// publication (with the nodes a hold of its own revision left out), or a
// capability hold for a later revision.
func loadSystemBaseline(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) (systemBaseline, bool, error) {
	var baseline systemBaseline
	var userID, actorScopeID uuid.UUID
	// A stop overlay publication is not the scope's facts: rows edited before
	// it were not published by it.
	err := tx.QueryRow(ctx, `SELECT publication.source_revision,publication.actor_user_id,publication.actor_scope_id,
		publication.rollout_id FROM edge_config_publications publication
		WHERE publication.configuration_scope_id=$1 AND publication.contract_version=1
		  AND NOT EXISTS(SELECT 1 FROM edge_publication_compile_inputs inputs
		    WHERE inputs.config_version_id=publication.config_version_id AND inputs.overlay)
		ORDER BY publication.source_revision DESC LIMIT 1`, scopeID).Scan(&baseline.revision, &userID, &actorScopeID, &baseline.rolloutID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return systemBaseline{}, false, err
	}
	baseline.hasRollout = err == nil
	if baseline.hasRollout {
		rows, err := tx.Query(ctx, `SELECT DISTINCT node_id FROM node_deployments WHERE rollout_id=$1 ORDER BY node_id`,
			baseline.rolloutID)
		if err != nil {
			return systemBaseline{}, false, err
		}
		if baseline.lastNodes, err = pgx.CollectRows(rows, pgx.RowTo[uuid.UUID]); err != nil {
			return systemBaseline{}, false, err
		}
	}
	var holdRevision int64
	var holdUser, holdScope uuid.UUID
	var holdNodes, holdRefused []uuid.UUID
	err = tx.QueryRow(ctx, `SELECT source_revision,actor_user_id,actor_scope_id,requested_node_ids,refused_node_ids
		FROM edge_capability_publication_holds WHERE scope_id=$1 AND (source_revision>$2 OR
		  source_revision=$2 AND published AND $3)
		ORDER BY source_revision DESC LIMIT 1`, scopeID, baseline.revision, baseline.hasRollout).Scan(&holdRevision, &holdUser, &holdScope,
		&holdNodes, &holdRefused)
	switch {
	case err == nil && baseline.hasRollout && holdRevision == baseline.revision:
		// The publication of this revision left nodes out (a deferred JS
		// challenge promotion, an automatic publication excluding incapable
		// nodes; published, 352): they stay targets; the publication is still
		// the baseline. A refused publication of the same revision (the
		// tenant then published it to fewer nodes) is not taken.
		baseline.holdNodes = holdNodes
	case err == nil:
		baseline.revision, userID, actorScopeID = holdRevision, holdUser, holdScope
		baseline.holdNodes, baseline.holdRefuse, baseline.fromHold = holdNodes, holdRefused, true
	case !errors.Is(err, pgx.ErrNoRows):
		return systemBaseline{}, false, err
	case !baseline.hasRollout:
		return systemBaseline{}, false, nil
	}
	var kind string
	if err := tx.QueryRow(ctx, `SELECT kind FROM access_scopes WHERE id=$1`, actorScopeID).Scan(&kind); err != nil {
		return systemBaseline{}, false, err
	}
	baseline.actor = Actor{UserID: userID, ScopeID: actorScopeID, ScopeKind: kind}
	return baseline, true, nil
}

// systemChainClean reports whether system segments cover every source
// revision advance from baseline to current.
func systemChainClean(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, baseline, current int64) (bool, error) {
	if current < baseline {
		return false, nil
	}
	rows, err := tx.Query(ctx, `SELECT from_revision,to_revision FROM edge_system_revision_segments
		WHERE scope_id=$1 AND to_revision>$2 AND from_revision<$3 ORDER BY from_revision`, scopeID, baseline, current)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	cursor := baseline
	for rows.Next() {
		var from, to int64
		if err := rows.Scan(&from, &to); err != nil {
			return false, err
		}
		if from > cursor {
			break
		}
		cursor = max(cursor, to)
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	return cursor >= current, nil
}

// systemTargetNodes is the scope's intended node set: the nodes the published
// facts went (or were asked) to, nodes refused before, and every node serving
// a current line group the scope's live sites and streams use; restricted to active nodes
// the scope may publish to and that hold no reconciliation. A node shared
// with another scope without the multi-scope capability is refused here.
func systemTargetNodes(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, seeds []uuid.UUID, lineGroups bool,
) ([]uuid.UUID, []systemRefusal, error) {
	rows, err := tx.Query(ctx, `WITH candidate AS (
			SELECT unnest($2::uuid[]) AS node_id
			UNION
			SELECT endpoint.node_id FROM sites site
			LEFT JOIN package_subscriptions subscription ON subscription.tenant_scope_id=site.scope_id
			 AND subscription.id=site.package_subscription_id AND subscription.deleted_at IS NULL
			LEFT JOIN escalate_site_routes route ON route.tenant_scope_id=site.scope_id AND route.site_id=site.id
			JOIN node_line_groups line_group ON line_group.deleted_at IS NULL AND line_group.id IN (
			     site.node_group_id,
			     (subscription.product_snapshot->'spec'->>'node_group_id')::uuid,
			     (subscription.product_snapshot->'spec'->>'backup_node_group_id')::uuid,
			     route.line_group_id, route.next_group_id,
			     -- community edition: no package, no own group -> the platform default
			     (SELECT platform_default.id FROM node_line_groups platform_default WHERE platform_default.is_platform_default AND platform_default.deleted_at IS NULL AND site.node_group_id IS NULL AND site.package_subscription_id IS NULL))
			JOIN node_line_endpoints endpoint ON endpoint.tenant_scope_id=line_group.tenant_scope_id
			 AND endpoint.line_group_id=line_group.id AND endpoint.config_revision=line_group.current_revision
			 AND endpoint.enabled AND endpoint.node_id IS NOT NULL
			WHERE $3 AND site.scope_id=$1 AND site.deleted_at IS NULL
			  AND line_group.tenant_scope_id IN (site.scope_id,(SELECT scope_id FROM nodes WHERE id=endpoint.node_id))
			UNION
			-- A stream's line group / backup group: its own (migration 499), else its package's.
			SELECT endpoint.node_id FROM l4_forwards forward
			LEFT JOIN package_subscriptions subscription ON subscription.tenant_scope_id=forward.scope_id
			 AND subscription.id=forward.package_subscription_id AND subscription.deleted_at IS NULL
			JOIN node_line_groups line_group ON line_group.deleted_at IS NULL AND line_group.id IN (
			     COALESCE(forward.node_group_id, (subscription.product_snapshot->'spec'->>'node_group_id')::uuid),
			     COALESCE(forward.backup_node_group_id, (subscription.product_snapshot->'spec'->>'backup_node_group_id')::uuid),
			     (SELECT platform_default.id FROM node_line_groups platform_default WHERE platform_default.is_platform_default AND platform_default.deleted_at IS NULL AND forward.node_group_id IS NULL AND subscription.id IS NULL))
			JOIN node_line_endpoints endpoint ON endpoint.tenant_scope_id=line_group.tenant_scope_id
			 AND endpoint.line_group_id=line_group.id AND endpoint.config_revision=line_group.current_revision
			 AND endpoint.enabled AND endpoint.node_id IS NOT NULL
			WHERE $3 AND forward.scope_id=$1 AND forward.deleted_at IS NULL
			  AND line_group.tenant_scope_id IN (forward.scope_id,(SELECT scope_id FROM nodes WHERE id=endpoint.node_id)))
		SELECT node.id,EXISTS(SELECT 1 FROM node_config_state other WHERE other.node_id=node.id
		         AND other.configuration_scope_id<>$1)
		FROM candidate JOIN nodes node ON node.id=candidate.node_id AND node.admin_state='active'
		JOIN access_scopes node_scope ON node_scope.id=node.scope_id
		WHERE (node.scope_id=$1 OR node_scope.kind='platform')
		  AND NOT EXISTS(SELECT 1 FROM node_config_state state WHERE state.node_id=node.id
		    AND state.configuration_scope_id=$1 AND state.reconciliation_required)
		ORDER BY node.id`, scopeID, seeds, lineGroups)
	if err != nil {
		return nil, nil, err
	}
	type row struct {
		id     uuid.UUID
		shared bool
	}
	items, err := pgx.CollectRows(rows, func(item pgx.CollectableRow) (row, error) {
		var value row
		return value, item.Scan(&value.id, &value.shared)
	})
	if err != nil {
		return nil, nil, err
	}
	nodes := make([]uuid.UUID, 0, len(items))
	var refused []systemRefusal
	for _, item := range items {
		if item.shared {
			several, err := edgedeployment.NodeServesSeveralScopes(ctx, tx, item.id)
			if err != nil {
				return nil, nil, err
			}
			if !several {
				refused = append(refused, systemRefusal{NodeID: item.id, Feature: "serving several tenant scopes"})
				continue
			}
		}
		nodes = append(nodes, item.id)
	}
	if len(nodes) > maxPublicationTargets {
		return nil, nil, ErrInvalidInput
	}
	return nodes, refused, nil
}

// publishExcludingIncapableTx publishes to nodes, dropping one node per
// round that lacks a gated capability (TargetCapabilityError) until the rest
// can take the release. Each round runs in a savepoint of tx. It returns the
// nodes published to (none when every node was refused) and the refusals.
func (s *Service) publishExcludingIncapableTx(
	ctx context.Context, tx pgx.Tx, nodes []uuid.UUID,
	build func([]uuid.UUID) (normalizedPublishRequest, error), now time.Time,
) (PublishResult, []uuid.UUID, []systemRefusal, error) {
	candidates := slices.Clone(nodes)
	var refused []systemRefusal
	for len(candidates) > 0 {
		normalized, err := build(candidates)
		if err != nil {
			return PublishResult{}, nil, nil, err
		}
		round, err := tx.Begin(ctx)
		if err != nil {
			return PublishResult{}, nil, nil, err
		}
		result, err := s.publishAuthorizedTx(ctx, round, normalized, now)
		if err == nil {
			if err := round.Commit(ctx); err != nil {
				return PublishResult{}, nil, nil, err
			}
			return result, normalized.NodeIDs, refused, nil
		}
		if errors.Is(err, ErrEntitlementDenied) {
			// Only the denial audit was written: keep it, as Publish does.
			if commitErr := round.Commit(ctx); commitErr != nil {
				return PublishResult{}, nil, nil, commitErr
			}
			return PublishResult{}, nil, nil, err
		}
		_ = round.Rollback(ctx)
		item, ok := systemRefusalOf(err)
		if !ok || !slices.Contains(candidates, item.NodeID) {
			return PublishResult{}, nil, nil, err
		}
		if len(item.RulePacks) > 0 {
			if item.RulePackIDs, err = rulePackIDsTx(ctx, tx, item.RulePacks); err != nil {
				return PublishResult{}, nil, nil, err
			}
		}
		candidates = slices.DeleteFunc(candidates, func(nodeID uuid.UUID) bool { return nodeID == item.NodeID })
		refused = append(refused, item)
	}
	return PublishResult{}, nil, refused, nil
}

// systemRefusalOf is the one target node a publication refused: it lacks a
// gated capability, or a JS challenge policy the release loads.
func systemRefusalOf(err error) (systemRefusal, bool) {
	var capability *TargetCapabilityError
	if errors.As(err, &capability) {
		return systemRefusal{NodeID: capability.NodeID, AgentVersion: capability.AgentVersion,
			Feature: capability.Feature, Capability: capability.Capability.String(), Required: capability.Required,
			Advertised: capability.Advertised}, true
	}
	var challenge *ChallengePolicyUnavailableError
	if errors.As(err, &challenge) {
		return systemRefusal{NodeID: challenge.NodeID, Feature: "JS challenge policy not installed (JS 挑战策略未安装)",
			Challenge: &systemChallengeRefusal{SiteID: challenge.SiteID, Domain: challenge.Domain,
				PolicyID: challenge.PolicyID, PolicyVersion: challenge.PolicyVersion}}, true
	}
	var packs *RulePackUnavailableError
	if errors.As(err, &packs) {
		return systemRefusal{NodeID: packs.NodeID, Feature: "rule packs not installed (规则包未安装)",
			RulePacks: slices.Clone(packs.SHA256)}, true
	}
	return systemRefusal{}, false
}

// rulePackIDsTx names rule pack digests for the audit (N15): a mounted or
// system pack version (rule_pack_artifacts) or a CRS profile pack the node
// artifact set carries (local_artifacts).
func rulePackIDsTx(ctx context.Context, tx pgx.Tx, digests []string) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT name FROM (
			SELECT pack_id||'@'||version AS name FROM rule_pack_artifacts WHERE sha256=ANY($1::text[])
			UNION ALL
			SELECT artifact_id||COALESCE('@'||current_version,'') FROM local_artifacts WHERE current_sha256=ANY($1::text[])) named
		ORDER BY name`, digests)
	if err != nil {
		return nil, fmt.Errorf("%w: name refused rule packs", ErrPersistence)
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("%w: name refused rule packs", ErrPersistence)
	}
	return names, nil
}

// capabilityHoldFacts are the audit facts of a publication that left nodes
// out: per node what it lacks (feature, capability and versions, rule packs).
func capabilityHoldFacts(refused []systemRefusal) map[string]any {
	return map[string]any{"refused_nodes": nonNilRefusals(refused)}
}

func (republisher *SystemRepublisher) systemPublishRequest(
	claim systemClaim, attemptID uuid.UUID, accountable Actor, revision int64, schema string,
	nodes []uuid.UUID, now time.Time,
) PublishRequest {
	actor := accountable
	actor.system = &systemActorFacts{attemptID: attemptID, triggers: slices.Clone(claim.triggers)}
	request := PublishRequest{
		Actor: actor, ConfigurationScopeID: claim.scopeID, ExpectedSourceRevision: revision,
		SiteRuntimeSchema: schema, NodeIDs: slices.Clone(nodes), MaxAttempts: 3,
		Deadline: now.Add(systemRepublicationDeadline), IdempotencyKey: "syspub." + attemptID.String(),
		RequestID: attemptID.String(), CorrelationID: attemptID.String(),
	}
	request.HealthCheck.ActivationTimeout = 30 * time.Second
	request.HealthCheck.ObservationWindow = 5 * time.Second
	request.HealthCheck.RequiredConsecutiveSuccesses = 2
	return request
}

// systemContentTrigger: the trigger changes what the nodes run (a site was
// suspended or restored, by traffic, a domain claim or a secondary
// verification; the CRS rule text changed) or must redeliver it
// (a failed sync; a node now holds the redelivered JS challenge policy and
// must load it), so the
// publication goes out even to an unchanged node set.
func systemContentTrigger(triggers []string) bool {
	return slices.Contains(triggers, SystemTriggerTrafficEnforcement) || slices.Contains(triggers, SystemTriggerNodeSync) ||
		slices.Contains(triggers, SystemTriggerDomainOwnership) || slices.Contains(triggers, SystemTriggerSecondaryVerification) ||
		slices.Contains(triggers, SystemTriggerRuleCatalog) || slices.Contains(triggers, SystemTriggerChallengeDelivery) ||
		slices.Contains(triggers, SystemTriggerModuleEntitlement) || slices.Contains(triggers, SystemTriggerAccountSuspension) ||
		slices.Contains(triggers, SystemTriggerNodeNetworks) || slices.Contains(triggers, SystemTriggerErrorPagePublished) ||
		slices.Contains(triggers, SystemTriggerOriginAuthPublished) || slices.Contains(triggers, SystemTriggerOriginFailover) ||
		slices.Contains(triggers, SystemTriggerMarketLimits) || slices.Contains(triggers, SystemTriggerIPList) ||
		slices.Contains(triggers, SystemTriggerPackageExpiry) || slices.Contains(triggers, SystemTriggerNodeStorage) ||
		slices.Contains(triggers, SystemTriggerPackageSuspension) || slices.Contains(triggers, SystemTriggerCertificateRenewal)
}

// SiteFactsRepublicationDebounce merges a burst of error page / origin auth
// publications of one scope into one site object republication.
const SiteFactsRepublicationDebounce = 5 * time.Second

// RequestSiteFactsRepublicationTx queues the system republication a
// published error page snapshot or origin auth publication needs: only when
// the scope's latest publication is a dynamic routing release (v2 site root;
// a v8/v7 release embeds neither, its nodes read them from their own channels).
func RequestSiteFactsRepublicationTx(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, trigger string) error {
	if trigger != SystemTriggerErrorPagePublished && trigger != SystemTriggerOriginAuthPublished {
		return ErrInvalidInput
	}
	var siteObjects bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM configuration_artifacts artifact
		WHERE artifact.media_type=$2 AND artifact.config_version_id=(SELECT publication.config_version_id
		  FROM edge_config_publications publication
		  WHERE publication.configuration_scope_id=$1 AND publication.contract_version=1
		  ORDER BY publication.source_revision DESC LIMIT 1))`, scopeID, siteobject.RootMediaTypeV2).Scan(&siteObjects); err != nil {
		return fmt.Errorf("%w: read scope site object publication", ErrPersistence)
	}
	if !siteObjects {
		return nil
	}
	return RequestSystemRepublicationTx(ctx, tx, SystemRepublicationRequest{ScopeID: scopeID, Trigger: trigger,
		Debounce: SiteFactsRepublicationDebounce})
}

func refusedNodeIDs(refused []systemRefusal) []uuid.UUID {
	nodes := make([]uuid.UUID, 0, len(refused))
	for _, item := range refused {
		nodes = append(nodes, item.NodeID)
	}
	slices.SortFunc(nodes, func(left, right uuid.UUID) int { return compareUUID(left, right) })
	return slices.Compact(nodes)
}

func compareUUID(left, right uuid.UUID) int {
	for index := range left {
		if left[index] != right[index] {
			return int(left[index]) - int(right[index])
		}
	}
	return 0
}

func databaseNow(ctx context.Context, tx pgx.Tx) (time.Time, error) {
	var now time.Time
	err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now)
	return now.UTC().Truncate(time.Microsecond), err
}
func lockSystemClaim(ctx context.Context, tx pgx.Tx, claim systemClaim) error {
	var state string
	var token *uuid.UUID
	err := tx.QueryRow(ctx, `SELECT state,lease_token FROM edge_system_republication_heads WHERE scope_id=$1 FOR UPDATE`,
		claim.scopeID).Scan(&state, &token)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrSystemRepublicationStale
	}
	if err != nil {
		return err
	}
	if state != "leased" || token == nil || *token != claim.leaseToken {
		return ErrSystemRepublicationStale
	}
	return nil
}

// finishSystemAttemptTx records the attempt, releases the head (pending again
// when a trigger arrived meanwhile) and audits as the system.
func finishSystemAttemptTx(
	ctx context.Context, tx pgx.Tx, auditor AuditAppender, claim systemClaim, attemptID uuid.UUID, attempt systemAttempt,
) error {
	refused, err := json.Marshal(nonNilRefusals(attempt.refused))
	if err != nil {
		return err
	}
	var publicationID *uuid.UUID
	if attempt.publication != nil {
		publicationID = &attempt.publication.PublicationID
	}
	if _, err := tx.Exec(ctx, `INSERT INTO edge_system_republication_attempts(
		id,scope_id,generation,attempt,triggers,outcome,baseline_source_revision,source_revision,publication_id,
		node_ids,refused_nodes,error_class,occurred_at,error_page_rollout_id)
		VALUES($1,$2,$3,$4,$5,$6,NULLIF($7,0),NULLIF($8,0),$9,$10,$11,NULLIF($12,''),clock_timestamp(),$13)`,
		attemptID, claim.scopeID, claim.generation, claim.attempt, claim.triggers, attempt.outcome,
		attempt.baselineRevision, attempt.sourceRevision, publicationID, nonNilNodes(attempt.nodeIDs), refused,
		attempt.errorClass, attempt.errorPageRolloutID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE edge_system_republication_heads SET
		state=CASE WHEN generation>claimed_generation THEN 'pending' ELSE 'idle' END,
		attempt=0,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,claimed_generation=NULL,
		excluded_node_ids=$2,last_outcome=$3,updated_at=clock_timestamp()
		WHERE scope_id=$1`, claim.scopeID, nonNilNodes(attempt.excluded), attempt.outcome); err != nil {
		return err
	}
	return appendSystemRepublicationAudit(ctx, tx, auditor, claim, attemptID, attempt.outcome, attempt.baselineRevision,
		attempt.sourceRevision, attempt.publication, attempt.nodeIDs, attempt.refused, attempt.errorClass, attempt.overlay,
		attempt.errorPageRolloutID)
}

func appendSystemRepublicationAudit(
	ctx context.Context, tx pgx.Tx, auditor AuditAppender, claim systemClaim, attemptID uuid.UUID, outcome string,
	baseline, revision int64, publication *PublishResult, nodes []uuid.UUID, refused []systemRefusal, errorClass string,
	overlay *publicationOverlay, errorPageRolloutID *uuid.UUID,
) error {
	result := "success"
	switch outcome {
	case SystemOutcomeBlocked, SystemOutcomeNoCapableTarget:
		result = "denied"
	case SystemOutcomeRetry, SystemOutcomeFailed:
		result = "failure"
	}
	payload := map[string]any{
		"actor_kind": "system", "outcome": outcome, "triggers": claim.triggers, "generation": claim.generation,
		"attempt": claim.attempt, "baseline_source_revision": baseline, "source_revision": revision,
		"node_ids": nonNilNodes(nodes), "refused_nodes": nonNilRefusals(refused),
	}
	if publication != nil {
		payload["publication_id"] = publication.PublicationID.String()
		payload["rollout_id"] = publication.RolloutID.String()
	}
	if errorClass != "" {
		payload["error_class"] = errorClass
	}
	if errorPageRolloutID != nil {
		payload["error_page_rollout_id"] = errorPageRolloutID.String()
	}
	if overlay != nil {
		payload["stop_overlay"] = true
		payload["dropped_site_ids"] = nonNilNodes(overlay.drop)
		payload["restored_site_ids"] = nonNilNodes(overlay.restoreID)
	}
	return auditor.Append(ctx, tx, audit.Event{
		ScopeID: claim.scopeID, Action: "edge_system_republication." + outcome,
		ResourceType: "edge_configuration_scope", ResourceID: claim.scopeID.String(),
		RequestID: attemptID.String(), Result: result, Payload: payload,
	})
}

// fail records a failed attempt and retries with backoff, or gives up after
// SystemRepublicationMaxAttempts until the next trigger.
func (republisher *SystemRepublisher) fail(ctx context.Context, claim systemClaim, cause error) error {
	return pgx.BeginFunc(ctx, republisher.service.pool, func(tx pgx.Tx) error {
		if err := lockSystemClaim(ctx, tx, claim); err != nil {
			if errors.Is(err, ErrSystemRepublicationStale) {
				return nil
			}
			return err
		}
		attemptID, err := uuid.NewV7()
		if err != nil {
			return err
		}
		outcome := SystemOutcomeRetry
		if claim.attempt >= SystemRepublicationMaxAttempts {
			outcome = SystemOutcomeFailed
		}
		class := cause.Error()
		if len(class) > 256 {
			class = class[:256]
		}
		backoff := republisher.config.RetryDelay << max(claim.attempt-1, 0)
		if backoff > systemRepublicationMaxBackoff || backoff < 0 {
			backoff = systemRepublicationMaxBackoff
		}
		if _, err := tx.Exec(ctx, `INSERT INTO edge_system_republication_attempts(
			id,scope_id,generation,attempt,triggers,outcome,error_class,occurred_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,clock_timestamp())`, attemptID, claim.scopeID, claim.generation,
			claim.attempt, claim.triggers, outcome, class); err != nil {
			return err
		}
		if outcome == SystemOutcomeFailed && slices.Contains(claim.triggers, SystemTriggerThemeActivation) {
			if err := failThemeTx(ctx, tx, claim.scopeID, class); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE edge_system_republication_heads SET
			state=CASE WHEN $2 AND generation<=claimed_generation THEN 'idle' ELSE 'pending' END,
			attempt=CASE WHEN $2 OR generation>claimed_generation THEN 0 ELSE attempt END,
			due_at=clock_timestamp()+$3::bigint*interval '1 millisecond',
			lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,claimed_generation=NULL,
			last_outcome=$4,updated_at=clock_timestamp()
			WHERE scope_id=$1`, claim.scopeID, outcome == SystemOutcomeFailed, backoff.Milliseconds(), outcome); err != nil {
			return err
		}
		return appendSystemRepublicationAudit(ctx, tx, republisher.service.auditor, claim, attemptID, outcome,
			0, 0, nil, nil, nil, class, nil, nil)
	})
}

func nonNilNodes(nodes []uuid.UUID) []uuid.UUID {
	if nodes == nil {
		return []uuid.UUID{}
	}
	return nodes
}

func nonNilRefusals(refused []systemRefusal) []systemRefusal {
	if refused == nil {
		return []systemRefusal{}
	}
	return refused
}

// heldRefusal is what a refused publication holds: the nodes that lack a
// gated capability or a JS challenge policy of the release (the
// redeliverer gives a held node the policy, the
// capability watcher or its confirmed delivery republishes), and the audit
// facts of the refusal.
func heldRefusal(err error) ([]uuid.UUID, map[string]any, bool) {
	var capability *TargetCapabilityError
	if errors.As(err, &capability) {
		return append([]uuid.UUID{capability.NodeID}, capability.OtherNodeIDs...), map[string]any{
			"feature": capability.Feature, "capability": capability.Capability.String(), "required": capability.Required,
		}, true
	}
	var challenge *ChallengePolicyUnavailableError
	if errors.As(err, &challenge) {
		return append([]uuid.UUID{challenge.NodeID}, challenge.OtherNodeIDs...), map[string]any{
			"feature": "JS challenge policy not installed", "challenge": map[string]any{
				"site_id": challenge.SiteID, "domain": challenge.Domain, "policy_id": challenge.PolicyID,
				"policy_version": challenge.PolicyVersion,
			},
		}, true
	}
	var packs *RulePackUnavailableError
	if errors.As(err, &packs) {
		return append([]uuid.UUID{packs.NodeID}, packs.OtherNodeIDs...), map[string]any{
			"feature": "rule packs not installed", "rule_packs": slices.Clone(packs.SHA256),
		}, true
	}
	return nil, nil, false
}

// recordCapabilityHold remembers, after the refused publication rolled back,
// that the scope asked to publish this revision and which nodes lacked a
// gated capability or a JS challenge policy (heldRefusal). A system
// republication delivers it once they have it (and while the scope has no
// newer edit).
func (s *Service) recordCapabilityHold(ctx context.Context, request PublishRequest, nodeIDs []uuid.UUID, publishErr error) {
	refused, facts, held := heldRefusal(publishErr)
	if s == nil || ctx == nil || !held || request.Actor.system != nil ||
		request.Actor.UserID == uuid.Nil || request.Actor.ScopeID == uuid.Nil || request.ExpectedSourceRevision < 1 {
		return
	}
	requested := slices.Clone(nodeIDs)
	if len(requested) == 0 {
		requested = slices.Clone(refused)
	}
	_ = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if packs, ok := facts["rule_packs"].([]string); ok {
			names, err := rulePackIDsTx(ctx, tx, packs)
			if err != nil {
				return err
			}
			facts["rule_pack_ids"] = names
		}
		return s.insertCapabilityHoldTx(ctx, tx, request, requested, refused, facts, false)
	})
}

// insertCapabilityHoldTx records that the scope asked to publish this
// revision to requested and refused (the nodes lacking a gated capability or
// a challenge policy); facts are the refusal's audit facts. published: the
// hold is written with this revision's publication to the other nodes
// (migration 352), not for a refused one.
func (s *Service) insertCapabilityHoldTx(ctx context.Context, tx pgx.Tx, request PublishRequest,
	requested, refused []uuid.UUID, facts map[string]any, published bool) error {
	requested, refused = slices.Clone(requested), slices.Clone(refused)
	slices.SortFunc(requested, compareUUID)
	slices.SortFunc(refused, compareUUID)
	requested, refused = slices.Compact(requested), slices.Compact(refused)
	command, err := tx.Exec(ctx, `INSERT INTO edge_capability_publication_holds(
		scope_id,source_revision,actor_user_id,actor_scope_id,requested_node_ids,refused_node_ids,refused_at,published)
		SELECT scope_id,$2,$3,$4,$5,$6,clock_timestamp(),$7 FROM edge_configuration_scopes
		WHERE scope_id=$1 AND source_revision=$2
		ON CONFLICT (scope_id,source_revision) DO UPDATE SET actor_user_id=EXCLUDED.actor_user_id,
		  actor_scope_id=EXCLUDED.actor_scope_id,requested_node_ids=EXCLUDED.requested_node_ids,
		  refused_node_ids=EXCLUDED.refused_node_ids,refused_at=EXCLUDED.refused_at,published=EXCLUDED.published`,
		request.ConfigurationScopeID, request.ExpectedSourceRevision, request.Actor.UserID, request.Actor.ScopeID,
		requested, refused, published)
	if err != nil || command.RowsAffected() == 0 {
		return err
	}
	payload := map[string]any{"source_revision": request.ExpectedSourceRevision, "refused_node_ids": refused}
	for key, value := range facts {
		payload[key] = value
	}
	return s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: request.ConfigurationScopeID, ActorUserID: auditActorUserID(request.Actor),
		Action: "edge_publication.capability_hold", ResourceType: "edge_configuration_scope",
		ResourceID: request.ConfigurationScopeID.String(), RequestID: request.RequestID, Result: "denied",
		Payload: payload,
	})
}

// refusedAllError is the refusal of a release no target node can take: the
// first refused node, the others listed.
func refusedAllError(refused []systemRefusal) error {
	if len(refused) == 0 {
		return ErrTargetIneligible
	}
	first := refused[0]
	if first.Challenge != nil {
		challenge := &ChallengePolicyUnavailableError{NodeID: first.NodeID, SiteID: first.Challenge.SiteID,
			Domain: first.Challenge.Domain, PolicyID: first.Challenge.PolicyID, PolicyVersion: first.Challenge.PolicyVersion}
		for _, item := range refused[1:] {
			challenge.OtherNodeIDs = append(challenge.OtherNodeIDs, item.NodeID)
		}
		return challenge
	}
	if first.RulePacks != nil {
		packs := &RulePackUnavailableError{NodeID: first.NodeID, SHA256: slices.Clone(first.RulePacks)}
		for _, item := range refused[1:] {
			packs.OtherNodeIDs = append(packs.OtherNodeIDs, item.NodeID)
		}
		return packs
	}
	refusal := &TargetCapabilityError{NodeID: first.NodeID, AgentVersion: first.AgentVersion, Feature: first.Feature,
		Capability: agentv1.CapabilityName(agentv1.CapabilityName_value[first.Capability]), Required: first.Required,
		Advertised: first.Advertised}
	for _, item := range refused[1:] {
		refusal.OtherNodeIDs = append(refusal.OtherNodeIDs, item.NodeID)
	}
	return refusal
}
