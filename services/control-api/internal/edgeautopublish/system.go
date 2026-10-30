package edgeautopublish

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// maxPolicyTargets mirrors the 1..10000 node bound of an automatic policy.
const maxPolicyTargets = 10000

// SystemEnqueueInput is a publication the control plane starts itself, on
// behalf of whoever configured the scope's automatic policy.
type SystemEnqueueInput struct {
	TargetScopeID    uuid.UUID
	SourceKind       string
	SourceResourceID uuid.UUID
	SourceRequestID  string
}

// EnqueueSystemTx enqueues a line-group, sync-retry or node-capability
// publication for an automatic scope. The caller has already advanced the
// scope's source revision in this transaction. A scope without an automatic
// policy is left to RequestRepublicationTx (Enqueued=false). The request runs
// as the policy's actor, so the worker re-checks that actor's sites.manage.
func EnqueueSystemTx(ctx context.Context, tx pgx.Tx, input SystemEnqueueInput) (EnqueueResult, error) {
	if tx == nil || input.TargetScopeID == uuid.Nil || input.SourceResourceID == uuid.Nil ||
		(input.SourceKind != SourceLineGroup && input.SourceKind != SourceNodeSync && input.SourceKind != SourceNodeCapability &&
			input.SourceKind != SourceRuleCatalog && input.SourceKind != SourceChallengeDelivery &&
			input.SourceKind != SourceModuleEntitlement && input.SourceKind != SourceNodeNetworks) {
		return EnqueueResult{}, ErrInvalidInput
	}
	actor, automatic, err := automaticPolicyActor(ctx, tx, input.TargetScopeID)
	if err != nil || !automatic {
		return EnqueueResult{}, err
	}
	operation := OperationLineGroupNodesChanged
	switch input.SourceKind {
	case SourceNodeSync:
		operation = OperationNodeSyncRetry
	case SourceNodeCapability:
		operation = OperationNodeCapabilitiesChange
	case SourceRuleCatalog:
		operation = OperationRuleCatalogUpdated
	case SourceChallengeDelivery:
		operation = OperationNodeChallengeDelivered
	case SourceModuleEntitlement:
		operation = OperationModulesGranted
	case SourceNodeNetworks:
		operation = OperationNodeNetworksChanged
	}
	return EnqueueTx(ctx, tx, EnqueueInput{
		Actor: actor, TargetScopeID: input.TargetScopeID, SourceKind: input.SourceKind,
		SourceResourceID: input.SourceResourceID, Operation: operation, Reason: sourceReason(input.SourceKind),
		Permission: PermissionSitesManage, SourceRequestID: input.SourceRequestID,
	})
}

func automaticPolicyActor(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) (Actor, bool, error) {
	var actor Actor
	err := tx.QueryRow(ctx, `SELECT fact.actor_user_id,fact.actor_scope_id,scope.kind
		FROM edge_automatic_publication_policy_facts fact
		JOIN access_scopes scope ON scope.id=fact.actor_scope_id
		WHERE fact.target_scope_id=$1 AND fact.mode='automatic'
		  AND fact.revision=(SELECT max(revision) FROM edge_automatic_publication_policy_facts WHERE target_scope_id=$1)`,
		scopeID).Scan(&actor.UserID, &actor.ScopeID, &actor.ScopeKind)
	if errors.Is(err, pgx.ErrNoRows) {
		return Actor{}, false, nil
	}
	return actor, err == nil, err
}

// RepublishRequest is one system trigger for one tenant scope.
// FromRevision is the scope's source revision before the caller's own
// advances in this transaction (its caller made every advance since); 0 when
// the caller advanced nothing.
type RepublishRequest struct {
	ScopeID          uuid.UUID
	Trigger          string
	SourceResourceID uuid.UUID
	// Operation is site.batch.enable/disable for traffic enforcement and
	// domain ownership claims (the automatic channel's site operation).
	Operation       string
	SourceRequestID string
	FromRevision    int64
	Debounce        time.Duration
	// Immediate makes a manual scope's system republication due now instead
	// of after the default debounce (a stop or restore must not wait).
	Immediate bool
}

type RepublishResult struct {
	Mode   string
	Queued bool
}

// RequestRepublicationTx is the one entry point of system republication for
// every tenant scope. An automatic scope republishes through its policy (an
// automatic request); any other scope through the system channel, which only
// redelivers what the scope last published. The scope's configuration row is
// locked first (publication lock order).
func RequestRepublicationTx(ctx context.Context, tx pgx.Tx, request RepublishRequest) (RepublishResult, error) {
	if ctx == nil || tx == nil || request.ScopeID == uuid.Nil || request.FromRevision < 0 ||
		strings.TrimSpace(request.SourceRequestID) == "" {
		return RepublishResult{}, ErrInvalidInput
	}
	var current int64
	err := tx.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1 FOR UPDATE`,
		request.ScopeID).Scan(&current)
	if errors.Is(err, pgx.ErrNoRows) {
		return RepublishResult{Mode: ModeManual}, nil
	}
	if err != nil {
		return RepublishResult{}, err
	}
	actor, automatic, err := automaticPolicyActor(ctx, tx, request.ScopeID)
	if err != nil {
		return RepublishResult{}, err
	}
	sourceRequestID := request.SourceRequestID
	if len(sourceRequestID) > 128 {
		sourceRequestID = sourceRequestID[:128]
	}
	if automatic {
		var result EnqueueResult
		switch request.Trigger {
		case edgepublish.SystemTriggerTrafficEnforcement, edgepublish.SystemTriggerDomainOwnership,
			edgepublish.SystemTriggerSecondaryVerification, edgepublish.SystemTriggerAccountSuspension,
			edgepublish.SystemTriggerPackageExpiry, edgepublish.SystemTriggerPackageSuspension:
			result, err = EnqueueTx(ctx, tx, EnqueueInput{
				Actor: actor, TargetScopeID: request.ScopeID, SourceKind: SourceSite, Operation: request.Operation,
				Reason: ReasonResourceMutation, Permission: PermissionSitesManage, SourceRequestID: sourceRequestID,
			})
		case edgepublish.SystemTriggerOriginFailover, edgepublish.SystemTriggerMarketLimits,
			// A renewed certificate switched the site's binding (fix-dnscert3).
			edgepublish.SystemTriggerCertificateRenewal:
			// The site's active origin level moved: published as the policy
			// actor's site.update, as EnqueueSiteSettingTx does.
			result, err = EnqueueTx(ctx, tx, EnqueueInput{
				Actor: actor, TargetScopeID: request.ScopeID, SourceKind: SourceSite, SourceResourceID: request.SourceResourceID,
				Operation: "site.update", Reason: ReasonResourceMutation, Permission: PermissionSitesManage,
				SourceRequestID: sourceRequestID,
			})
		case edgepublish.SystemTriggerLineGroup, edgepublish.SystemTriggerNodeSync, edgepublish.SystemTriggerNodeCapability,
			edgepublish.SystemTriggerRuleCatalog, edgepublish.SystemTriggerChallengeDelivery,
			edgepublish.SystemTriggerModuleEntitlement, edgepublish.SystemTriggerNodeNetworks,
			edgepublish.SystemTriggerAttackEscalation, edgepublish.SystemTriggerNodeStorage:
			if request.FromRevision == 0 || current <= request.FromRevision {
				// One publication per revision: the republication takes its own.
				if _, err := tx.Exec(ctx, `SELECT advance_edge_configuration_scope_revision($1)`, request.ScopeID); err != nil {
					return RepublishResult{}, err
				}
			}
			kind := map[string]string{
				edgepublish.SystemTriggerLineGroup: SourceLineGroup, edgepublish.SystemTriggerNodeSync: SourceNodeSync,
				edgepublish.SystemTriggerNodeCapability:    SourceNodeCapability,
				edgepublish.SystemTriggerRuleCatalog:       SourceRuleCatalog,
				edgepublish.SystemTriggerChallengeDelivery: SourceChallengeDelivery,
				edgepublish.SystemTriggerModuleEntitlement: SourceModuleEntitlement,
				edgepublish.SystemTriggerNodeNetworks:      SourceNodeNetworks,
				// A node storage change is a node fact like its addresses and
				// region (same source kind; the trigger names it).
				edgepublish.SystemTriggerNodeStorage: SourceNodeNetworks,
				// The scope's sites go to a new line group's nodes: published
				// as a line group change of the scope.
				edgepublish.SystemTriggerAttackEscalation: SourceLineGroup,
			}[request.Trigger]
			result, err = EnqueueSystemTx(ctx, tx, SystemEnqueueInput{TargetScopeID: request.ScopeID, SourceKind: kind,
				SourceResourceID: request.SourceResourceID, SourceRequestID: sourceRequestID})
		default:
			return RepublishResult{}, ErrInvalidInput
		}
		return RepublishResult{Mode: ModeAutomatic, Queued: result.Enqueued && !result.Replayed}, err
	}
	if request.FromRevision > 0 && current > request.FromRevision {
		if err := edgepublish.RecordSystemRevisionSegmentTx(ctx, tx, request.ScopeID, request.FromRevision, request.Trigger); err != nil {
			return RepublishResult{}, err
		}
	}
	debounce := request.Debounce
	if debounce == 0 && !request.Immediate {
		debounce = edgepublish.SystemRepublicationDebounce
	}
	if edgepublish.SystemTriggerImmediate(request.Trigger) {
		debounce = 0 // stops and restores go out at once
	}
	if err := edgepublish.RequestSystemRepublicationTx(ctx, tx, edgepublish.SystemRepublicationRequest{
		ScopeID: request.ScopeID, Trigger: request.Trigger, Debounce: debounce,
	}); err != nil {
		return RepublishResult{}, err
	}
	return RepublishResult{Mode: ModeManual, Queued: true}, nil
}

// EnqueueSiteSettingTx is the automatic publication of a site setting
// written under a permission other than sites.manage (a site's quick block
// override, security_policies.manage): an automatic scope publishes the
// site's change as its policy's actor (site.update), as system triggers do;
// any other scope leaves it pending (the site's write advanced the source
// revision). The caller locked the site first.
func EnqueueSiteSettingTx(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID, requestID string) (bool, error) {
	actor, automatic, err := automaticPolicyActor(ctx, tx, scopeID)
	if err != nil || !automatic {
		return false, err
	}
	if len(requestID) > 128 {
		requestID = requestID[:128]
	}
	result, err := EnqueueTx(ctx, tx, EnqueueInput{
		Actor: actor, TargetScopeID: scopeID, SourceKind: SourceSite, SourceResourceID: siteID, Operation: "site.update",
		Reason: ReasonResourceMutation, Permission: PermissionSitesManage, SourceRequestID: requestID,
	})
	return result.Enqueued && !result.Replayed, err
}

// EnqueueUnrequestedSiteRevisionTx publishes a site row write that advanced
// the scope's source revision outside any request (the CNAME projection,
// 335 trigger): an automatic scope whose current revision no request covers
// gets the site's site.update as its policy's actor. Without it the write
// stayed unpublished once the scope's last request had published (fix-autopub).
// A covered revision (the caller's transaction already enqueued, or a newer
// request exists) and a manual scope are left alone.
func EnqueueUnrequestedSiteRevisionTx(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID, requestID string) (bool, error) {
	if tx == nil || scopeID == uuid.Nil || siteID == uuid.Nil || strings.TrimSpace(requestID) == "" {
		return false, ErrInvalidInput
	}
	return enqueueUncoveredRevisionTx(ctx, tx, scopeID, func(savepoint pgx.Tx) (bool, error) {
		return EnqueueSiteSettingTx(ctx, savepoint, scopeID, siteID, requestID)
	})
}

// EnqueueUnrequestedScopeRevisionTx is EnqueueUnrequestedSiteRevisionTx for a
// scope write that names no site: an L2 topology configuration, condition or
// member (504 triggers advance the scope's revision; the sites using it read
// it at publication). Published as the policy actor's line group node set
// change of resourceID (the L2 resource), as attack escalation is.
func EnqueueUnrequestedScopeRevisionTx(ctx context.Context, tx pgx.Tx, scopeID, resourceID uuid.UUID, requestID string) (bool, error) {
	if tx == nil || scopeID == uuid.Nil || resourceID == uuid.Nil || strings.TrimSpace(requestID) == "" {
		return false, ErrInvalidInput
	}
	if len(requestID) > 128 {
		requestID = requestID[:128]
	}
	return enqueueUncoveredRevisionTx(ctx, tx, scopeID, func(savepoint pgx.Tx) (bool, error) {
		result, err := EnqueueSystemTx(ctx, savepoint, SystemEnqueueInput{TargetScopeID: scopeID, SourceKind: SourceLineGroup,
			SourceResourceID: resourceID, SourceRequestID: requestID})
		return result.Enqueued && !result.Replayed, err
	})
}

// UnrequestedRevisionPublisher is EnqueueUnrequestedSiteRevisionTx for
// packages this package imports (firewallactioncontrol, httppolicycontrol),
// which cannot import it.
type UnrequestedRevisionPublisher struct{}

func (UnrequestedRevisionPublisher) EnqueueUnrequestedSiteRevisionTx(
	ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID, requestID string,
) (bool, error) {
	return EnqueueUnrequestedSiteRevisionTx(ctx, tx, scopeID, siteID, requestID)
}

// enqueueUncoveredRevisionTx runs enqueue when an automatic scope's current
// revision is covered by no request; a manual scope and a covered revision
// are left alone.
func enqueueUncoveredRevisionTx(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, enqueue func(pgx.Tx) (bool, error)) (bool, error) {
	var uncovered bool
	err := tx.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM edge_automatic_publication_requests request_row
		WHERE request_row.target_scope_id=scope.scope_id AND request_row.source_revision>=scope.source_revision)
		FROM edge_configuration_scopes scope WHERE scope.scope_id=$1 FOR UPDATE OF scope`, scopeID).Scan(&uncovered)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !uncovered {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	// A savepoint: a policy actor the request table refuses (P8602, e.g. a
	// suspended account) leaves the write unpublished instead of failing the
	// caller's write (a CNAME settlement) for good.
	savepoint, err := tx.Begin(ctx)
	if err != nil {
		return false, err
	}
	enqueued, err := enqueue(savepoint)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "P8602" {
		return false, savepoint.Rollback(ctx)
	}
	if err != nil {
		_ = savepoint.Rollback(ctx)
		return false, err
	}
	return enqueued, savepoint.Commit(ctx)
}

// SiteSettingPublisher is EnqueueSiteSettingTx for packages edgepublish's
// tests import (cachecontrol), which cannot import this package.
type SiteSettingPublisher struct{}

func (SiteSettingPublisher) EnqueueSiteSettingTx(
	ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID, requestID string,
) (bool, error) {
	return EnqueueSiteSettingTx(ctx, tx, scopeID, siteID, requestID)
}

// LineGroupPublisher queues the republication nodescheduler asks for when a
// line group's node set changes (FX02), for every scope using the group. The
// scheduler has locked the scope and advanced its revision once.
type LineGroupPublisher struct{}

func (LineGroupPublisher) EnqueueLineGroupChangeTx(
	ctx context.Context, tx pgx.Tx, scopeID, groupID uuid.UUID, requestID string,
) (bool, error) {
	var current int64
	if err := tx.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1 FOR UPDATE`,
		scopeID).Scan(&current); err != nil {
		return false, err
	}
	result, err := RequestRepublicationTx(ctx, tx, RepublishRequest{
		ScopeID: scopeID, Trigger: edgepublish.SystemTriggerLineGroup, SourceResourceID: groupID,
		SourceRequestID: requestID, FromRevision: max(current-1, 1),
	})
	return result.Queued, err
}

// EnqueueUnrequestedScopeRevisionTx publishes nodescheduler's L2 topology
// writes (nodescheduler.ScopeRevisionPublisher).
func (LineGroupPublisher) EnqueueUnrequestedScopeRevisionTx(
	ctx context.Context, tx pgx.Tx, scopeID, resourceID uuid.UUID, requestID string,
) (bool, error) {
	return EnqueueUnrequestedScopeRevisionTx(ctx, tx, scopeID, resourceID, requestID)
}

// publicationNodeIDs is the policy's explicit nodes plus every node serving a
// current line group the scope's live sites use (their own or their package's
// primary/backup group) and the members of their L2 configurations
// (fix-autol2b), restricted to nodes this scope may publish to: active and
// either owned by the scope or a platform node.
func publicationNodeIDs(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, policyNodes []uuid.UUID) ([]uuid.UUID, error) {
	return lineGroupNodeIDs(ctx, tx, scopeID, nil, policyNodes)
}

// ScopeTargetNodeIDsTx is the line-group nodes of every live site and stream
// of scopeID (publicationNodeIDs without policy nodes): the nodes an
// automatic publication of the scope reaches.
func ScopeTargetNodeIDsTx(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) ([]uuid.UUID, error) {
	if ctx == nil || tx == nil || scopeID == uuid.Nil {
		return nil, ErrInvalidInput
	}
	return lineGroupNodeIDs(ctx, tx, scopeID, nil, nil)
}

// SiteTargetNodeIDsTx is the nodes one live site of scopeID is served by: the
// nodes of its own line group and of its package's primary/backup group (and
// an escalation route), restricted as publicationNodeIDs restricts them. A
// security activation a tenant starts without naming nodes targets these
// (the tenant cannot see node IDs; 10-22 自动下发).
func SiteTargetNodeIDsTx(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID) ([]uuid.UUID, error) {
	if ctx == nil || tx == nil || scopeID == uuid.Nil || siteID == uuid.Nil {
		return nil, ErrInvalidInput
	}
	return lineGroupNodeIDs(ctx, tx, scopeID, &siteID, nil)
}

// lineGroupNodeIDs is policyNodes plus the line-group nodes of the scope's
// live sites and streams, or of the one site siteID when it is set (a stream
// belongs to no site, migration 506).
func lineGroupNodeIDs(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, siteID *uuid.UUID, policyNodes []uuid.UUID) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT endpoint.node_id
		FROM sites site
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
		JOIN nodes node ON node.id=endpoint.node_id AND node.admin_state='active'
		JOIN access_scopes node_scope ON node_scope.id=node.scope_id
		WHERE site.scope_id=$1 AND site.deleted_at IS NULL AND ($2::uuid IS NULL OR site.id=$2)
		  AND line_group.tenant_scope_id IN (site.scope_id, node.scope_id)
		  AND (node.scope_id=$1 OR node_scope.kind='platform')
		UNION
		-- fix-autol2b (L2_ROUTING v2): the enabled members of each site's L2
		-- configuration (its line group's -- own, else its package's primary
		-- group -- or its custom one) receive the site too: the L2 serves it.
		SELECT member.node_id
		FROM sites site
		JOIN site_origin_pools pool ON pool.site_id=site.id AND pool.l2_mode<>'off'
		LEFT JOIN package_subscriptions subscription ON subscription.tenant_scope_id=site.scope_id
		 AND subscription.id=site.package_subscription_id AND subscription.deleted_at IS NULL
		LEFT JOIN node_line_groups line_group ON pool.l2_mode='package' AND line_group.deleted_at IS NULL
		 AND line_group.id=COALESCE(site.node_group_id, (subscription.product_snapshot->'spec'->>'node_group_id')::uuid)
		JOIN l2_topology_configs config ON config.deleted_at IS NULL AND (
		     pool.l2_mode='custom' AND config.tenant_scope_id=site.scope_id AND config.id=pool.l2_config_id OR
		     pool.l2_mode='package' AND config.tenant_scope_id=line_group.tenant_scope_id AND config.id=line_group.l2_config_id)
		JOIN l2_topology_nodes member ON member.tenant_scope_id=config.tenant_scope_id AND member.config_id=config.id
		 AND member.enabled AND member.deleted_at IS NULL
		JOIN nodes node ON node.id=member.node_id AND node.admin_state='active'
		JOIN access_scopes node_scope ON node_scope.id=node.scope_id
		WHERE site.scope_id=$1 AND site.deleted_at IS NULL AND ($2::uuid IS NULL OR site.id=$2)
		  AND (node.scope_id=$1 OR node_scope.kind='platform')
		UNION
		-- A stream's line group / backup group: its own (migration 499, 修改线路分组), else its package's.
		SELECT endpoint.node_id
		FROM l4_forwards forward
		LEFT JOIN package_subscriptions subscription ON subscription.tenant_scope_id=forward.scope_id
		 AND subscription.id=forward.package_subscription_id AND subscription.deleted_at IS NULL
		JOIN node_line_groups line_group ON line_group.deleted_at IS NULL AND line_group.id IN (
		     COALESCE(forward.node_group_id, (subscription.product_snapshot->'spec'->>'node_group_id')::uuid),
		     COALESCE(forward.backup_node_group_id, (subscription.product_snapshot->'spec'->>'backup_node_group_id')::uuid),
		     (SELECT platform_default.id FROM node_line_groups platform_default WHERE platform_default.is_platform_default AND platform_default.deleted_at IS NULL AND forward.node_group_id IS NULL AND subscription.id IS NULL))
		JOIN node_line_endpoints endpoint ON endpoint.tenant_scope_id=line_group.tenant_scope_id
		 AND endpoint.line_group_id=line_group.id AND endpoint.config_revision=line_group.current_revision
		 AND endpoint.enabled AND endpoint.node_id IS NOT NULL
		JOIN nodes node ON node.id=endpoint.node_id AND node.admin_state='active'
		JOIN access_scopes node_scope ON node_scope.id=node.scope_id
		WHERE forward.scope_id=$1 AND forward.deleted_at IS NULL AND $2::uuid IS NULL
		  AND line_group.tenant_scope_id IN (forward.scope_id, node.scope_id)
		  AND (node.scope_id=$1 OR node_scope.kind='platform')`, scopeID, siteID)
	if err != nil {
		return nil, err
	}
	resolved, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return nil, err
	}
	nodes := append(slices.Clone(policyNodes), resolved...)
	slices.SortFunc(nodes, func(left, right uuid.UUID) int { return bytes.Compare(left[:], right[:]) })
	nodes = slices.Compact(nodes)
	if len(nodes) > maxPolicyTargets {
		return nil, ErrInvalidInput
	}
	return nodes, nil
}

// FrozenRepublisher redelivers a scope to a node that refused it while frozen
// (fix-stoppolicy2), through the same node_sync channel as a failed-sync
// retry: the scope's last publication goes out again, automatic or not.
type FrozenRepublisher struct{}

// RepublishFrozenTx queues one republication of scopeID inside tx; the
// caller's frozen refusal marks make it happen once per refusal.
func (FrozenRepublisher) RepublishFrozenTx(ctx context.Context, tx pgx.Tx, nodeID, scopeID uuid.UUID) error {
	if ctx == nil || tx == nil || nodeID == uuid.Nil || scopeID == uuid.Nil {
		return ErrInvalidInput
	}
	var current int64
	err := tx.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1 FOR UPDATE`,
		scopeID).Scan(&current)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `SELECT advance_edge_configuration_scope_revision($1)`, scopeID); err != nil {
		return err
	}
	_, err = RequestRepublicationTx(ctx, tx, RepublishRequest{
		ScopeID: scopeID, Trigger: edgepublish.SystemTriggerNodeSync, SourceResourceID: nodeID,
		SourceRequestID: "frozen-redeliver/" + nodeID.String() + "/" + uuid.NewString(), FromRevision: current,
		Immediate: true,
	})
	return err
}

// NodeSyncRetrier republishes a scope to a node held for failed sync (NF04).
type NodeSyncRetrier struct {
	pool *pgxpool.Pool
}

func NewNodeSyncRetrier(pool *pgxpool.Pool) *NodeSyncRetrier { return &NodeSyncRetrier{pool: pool} }

// RetryNodeSync queues one republication of scopeID (automatic or not)
// unless a retry for this node and scope was queued after notBefore.
func (retrier *NodeSyncRetrier) RetryNodeSync(ctx context.Context, nodeID, scopeID uuid.UUID, notBefore time.Time) (bool, error) {
	if retrier == nil || retrier.pool == nil || nodeID == uuid.Nil || scopeID == uuid.Nil {
		return false, ErrInvalidInput
	}
	queued := false
	err := pgx.BeginFunc(ctx, retrier.pool, func(tx pgx.Tx) error {
		var current int64
		var due bool
		err := tx.QueryRow(ctx, `SELECT edge_scope.source_revision,
				NOT EXISTS (SELECT 1 FROM edge_automatic_publication_requests request_row
					WHERE request_row.target_scope_id=edge_scope.scope_id AND request_row.source_kind='node_sync'
					  AND request_row.source_resource_id=$2 AND request_row.created_at>$3)
				AND NOT EXISTS (SELECT 1 FROM edge_system_revision_segments segment
					WHERE segment.scope_id=edge_scope.scope_id AND segment.source='node_sync' AND segment.recorded_at>$3)
			FROM edge_configuration_scopes edge_scope WHERE edge_scope.scope_id=$1 FOR UPDATE`,
			scopeID, nodeID, notBefore).Scan(&current, &due)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && !due {
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT advance_edge_configuration_scope_revision($1)`, scopeID); err != nil {
			return err
		}
		result, err := RequestRepublicationTx(ctx, tx, RepublishRequest{
			ScopeID: scopeID, Trigger: edgepublish.SystemTriggerNodeSync, SourceResourceID: nodeID,
			SourceRequestID: "node-sync-retry/" + nodeID.String(), FromRevision: current,
		})
		queued = result.Queued
		return err
	})
	return queued, err
}
