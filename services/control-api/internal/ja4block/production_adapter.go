package ja4block

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type productionDatabase interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

type PostgresPublicationTargetResolver struct {
	database  productionDatabase
	now       func() time.Time
	freshness time.Duration
}

func NewPostgresPublicationTargetResolver(pool *pgxpool.Pool, now func() time.Time,
	freshness time.Duration,
) (*PostgresPublicationTargetResolver, error) {
	if pool == nil {
		return nil, ErrInvalidConfiguration
	}
	return newPostgresPublicationTargetResolver(pool, now, freshness)
}

func newPostgresPublicationTargetResolver(database productionDatabase, now func() time.Time,
	freshness time.Duration,
) (*PostgresPublicationTargetResolver, error) {
	if database == nil || now == nil || freshness <= 0 || freshness > 10*time.Minute {
		return nil, ErrInvalidConfiguration
	}
	return &PostgresPublicationTargetResolver{database: database, now: now, freshness: freshness}, nil
}

func (resolver *PostgresPublicationTargetResolver) LoadPublicationTarget(ctx context.Context,
	tenantScopeID, siteID uuid.UUID,
) (PublicationTarget, error) {
	if resolver == nil || ctx == nil || tenantScopeID == uuid.Nil || siteID == uuid.Nil {
		return PublicationTarget{}, ErrInvalidInput
	}
	var encoded []byte
	err := resolver.database.QueryRow(ctx, `WITH authority AS (
		SELECT site.scope_id AS tenant_scope_id,site.id AS site_id,site.enabled,site.status,site_sync_status_503(site.scope_id,site.id) AS sync_status,
			line_group.current_revision,snapshot.tenant_scope_id AS snapshot_scope_id,snapshot.id AS snapshot_id,snapshot.revision AS snapshot_revision,
			snapshot.node_set_digest,snapshot.node_count,
			binding.id AS binding_id,binding.revision AS binding_revision,
			COALESCE(binding.active_policy_version,0) AS active_policy_version,
			binding.last_claimed_policy_version,version.document AS current_policy
		FROM sites site
		-- a site following its package (node_group_id NULL) is served by the
		-- package's primary line group (sec-followup; was: no target at all)
		LEFT JOIN package_subscriptions subscription ON subscription.tenant_scope_id=site.scope_id
			AND subscription.id=site.package_subscription_id AND subscription.deleted_at IS NULL
		-- (a package's group may be the platform's)
		JOIN node_line_groups line_group ON line_group.deleted_at IS NULL
			AND line_group.id=COALESCE(site.node_group_id,(subscription.product_snapshot->'spec'->>'node_group_id')::uuid)
			AND (line_group.tenant_scope_id=site.scope_id OR site.node_group_id IS NULL AND line_group.tenant_scope_id=
				(SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL))
		JOIN edge_target_snapshots snapshot ON snapshot.tenant_scope_id=line_group.tenant_scope_id
			AND snapshot.source_line_group_id=line_group.id
			AND snapshot.source_revision=line_group.current_revision
		LEFT JOIN security_policy_site_bindings binding ON binding.tenant_scope_id=site.scope_id
			AND binding.site_id=site.id AND binding.policy_kind='waf'
		LEFT JOIN security_policy_versions version ON version.policy_id=binding.policy_id
			AND version.revision=binding.active_policy_version
		WHERE site.scope_id=$1 AND site.id=$2 AND site.deleted_at IS NULL
		ORDER BY snapshot.revision DESC LIMIT 1
	), targets AS (
		SELECT authority.*,
			COALESCE(array_agg(target.node_id ORDER BY target.node_id)
				FILTER (WHERE target.node_id IS NOT NULL),'{}'::uuid[]) AS node_ids,
			count(target.node_id) AS actual_node_count,
			COALESCE(bool_and(node.admin_state='active' AND presence.status='online'
				AND presence.last_seen_at>$3 AND presence.openresty_state='running'
				AND presence.firewall_state='running' AND presence.active_deployments='[]'::jsonb
				AND NOT config.reconciliation_required
				AND NOT EXISTS (SELECT 1 FROM node_deployments deployment
					WHERE deployment.node_id=target.node_id
					AND deployment.state NOT IN ('healthy','failed','reverted','rollback_failed'))),false) AS nodes_ready
		FROM authority
		LEFT JOIN edge_target_snapshot_nodes target ON target.tenant_scope_id=authority.snapshot_scope_id
			AND target.snapshot_id=authority.snapshot_id AND target.snapshot_revision=authority.snapshot_revision
		LEFT JOIN nodes node ON node.id=target.node_id
		LEFT JOIN node_presence presence ON presence.node_id=target.node_id
		LEFT JOIN node_config_state config ON config.node_id=target.node_id
			AND config.configuration_scope_id=authority.tenant_scope_id
		GROUP BY authority.tenant_scope_id,authority.site_id,authority.enabled,authority.status,
			authority.sync_status,authority.current_revision,authority.snapshot_scope_id,authority.snapshot_id,
			authority.snapshot_revision,authority.node_set_digest,authority.node_count,
			authority.binding_id,authority.binding_revision,authority.active_policy_version,
			authority.last_claimed_policy_version,authority.current_policy
	)
	SELECT jsonb_build_object(
		'tenant_scope_id',tenant_scope_id,'site_id',site_id,
		'authority_ready',enabled AND status='active' AND sync_status='synced' AND nodes_ready
			AND actual_node_count=node_count AND actual_node_count>0
			AND (binding_id IS NULL OR COALESCE(last_claimed_policy_version,0)=active_policy_version)
			AND (active_policy_version=0 OR current_policy IS NOT NULL),
		'target_snapshot_id',snapshot_id,'target_snapshot_revision',snapshot_revision,
		'target_snapshot_sha256',encode(node_set_digest,'hex'),'target_nodes',to_jsonb(node_ids),
		'binding_revision',COALESCE(binding_revision,0),'active_policy_version',active_policy_version,
		'current_policy',current_policy)
	FROM targets`, tenantScopeID, siteID, resolver.now().UTC().Add(-resolver.freshness)).Scan(&encoded)
	if errors.Is(err, pgx.ErrNoRows) {
		return PublicationTarget{}, ErrDependencyUnavailable
	}
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return PublicationTarget{}, err
		}
		return PublicationTarget{}, fmt.Errorf("%w: load publication target", ErrDependencyUnavailable)
	}
	var document struct {
		TenantScopeID          uuid.UUID       `json:"tenant_scope_id"`
		SiteID                 uuid.UUID       `json:"site_id"`
		AuthorityReady         bool            `json:"authority_ready"`
		TargetSnapshotID       uuid.UUID       `json:"target_snapshot_id"`
		TargetSnapshotRevision int64           `json:"target_snapshot_revision"`
		TargetSnapshotSHA256   json.RawMessage `json:"target_snapshot_sha256"`
		TargetNodes            []uuid.UUID     `json:"target_nodes"`
		BindingRevision        int64           `json:"binding_revision"`
		ActivePolicyVersion    int64           `json:"active_policy_version"`
		CurrentPolicy          json.RawMessage `json:"current_policy"`
	}
	if json.Unmarshal(encoded, &document) != nil || !document.AuthorityReady ||
		document.TenantScopeID != tenantScopeID || document.SiteID != siteID {
		return PublicationTarget{}, ErrDependencyUnavailable
	}
	digest, err := decodeTargetDigest(document.TargetSnapshotSHA256)
	if err != nil {
		return PublicationTarget{}, ErrDependencyUnavailable
	}
	var current *securitypolicy.Policy
	if len(document.CurrentPolicy) > 0 && string(document.CurrentPolicy) != "null" {
		current = &securitypolicy.Policy{}
		if json.Unmarshal(document.CurrentPolicy, current) != nil {
			return PublicationTarget{}, ErrDependencyUnavailable
		}
	}
	target := PublicationTarget{
		TenantScopeID: document.TenantScopeID, SiteID: document.SiteID, CurrentPolicy: current,
		ExpectedBindingRevision: document.BindingRevision, ExpectedActiveVersion: document.ActivePolicyVersion,
		TargetSnapshotID: document.TargetSnapshotID, TargetSnapshotRevision: document.TargetSnapshotRevision,
		TargetSnapshotSHA256: digest, TargetNodeIDs: canonicalNodes(document.TargetNodes),
	}
	probe := AuthoritySnapshot{TenantScopeID: target.TenantScopeID, SiteID: target.SiteID,
		CurrentPolicy: target.CurrentPolicy, ExpectedBindingRevision: target.ExpectedBindingRevision,
		ExpectedActiveVersion: target.ExpectedActiveVersion, TargetSnapshotID: target.TargetSnapshotID,
		TargetSnapshotRevision: target.TargetSnapshotRevision, TargetSnapshotSHA256: target.TargetSnapshotSHA256,
		TargetNodeIDs: target.TargetNodeIDs, RolloutID: uuid.New()}
	if !validPublicationTarget(probe) {
		return PublicationTarget{}, ErrDependencyUnavailable
	}
	return target, nil
}

func decodeTargetDigest(encoded json.RawMessage) ([32]byte, error) {
	var digest [32]byte
	if json.Unmarshal(encoded, &digest) == nil && digest != ([32]byte{}) {
		return digest, nil
	}
	var text string
	if json.Unmarshal(encoded, &text) != nil {
		return digest, ErrDependencyUnavailable
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(text, `\x`))
	if err != nil || len(decoded) != len(digest) {
		return digest, ErrDependencyUnavailable
	}
	copy(digest[:], decoded)
	return digest, nil
}

type PostgresEdgeReceiptQueue struct{ database productionDatabase }

func NewPostgresEdgeReceiptQueue(pool *pgxpool.Pool) (*PostgresEdgeReceiptQueue, error) {
	if pool == nil {
		return nil, ErrInvalidConfiguration
	}
	return newPostgresEdgeReceiptQueue(pool)
}

func newPostgresEdgeReceiptQueue(database productionDatabase) (*PostgresEdgeReceiptQueue, error) {
	if database == nil {
		return nil, ErrInvalidConfiguration
	}
	return &PostgresEdgeReceiptQueue{database: database}, nil
}

func (queue *PostgresEdgeReceiptQueue) Claim(ctx context.Context, workerID string, now time.Time,
	lease time.Duration,
) (EdgeReceiptClaim, bool, error) {
	if queue == nil || ctx == nil || !keyPattern.MatchString(workerID) || now.IsZero() || lease <= 0 {
		return EdgeReceiptClaim{}, false, ErrInvalidInput
	}
	token := uuid.New()
	var claim EdgeReceiptClaim
	var configDigest, receiptDigest []byte
	err := queue.database.QueryRow(ctx, `WITH candidate AS (
		SELECT receipt_id FROM ja4_block_edge_receipt_queue_158
		WHERE available_at<=$1 AND (state='pending' OR (state='claimed' AND claim_expires_at<=$1))
		ORDER BY available_at,receipt_id FOR UPDATE SKIP LOCKED LIMIT 1
	), claimed AS (
		UPDATE ja4_block_edge_receipt_queue_158 receipt SET state='claimed',claimed_by=$2,
			claim_token=$3,claim_expires_at=$1+$4::interval,updated_at=$1
		FROM candidate WHERE receipt.receipt_id=candidate.receipt_id
		RETURNING receipt.*
	)
	SELECT claim_token,receipt_id,tenant_scope_id,site_id,workflow_id,policy_id,policy_revision,
		binding_id,binding_revision,publication_id,rollout_id,node_id,config_sha256,receipt_sha256,
		expected_revision,active_policy_revision,terminal_state,reason_code,observed_at,
		actor_user_id,actor_scope_id,actor_scope_kind,session_id FROM claimed`, now.UTC(), workerID, token,
		fmt.Sprintf("%f seconds", lease.Seconds())).Scan(&claim.Token, &claim.Receipt.ReceiptID,
		&claim.Receipt.TenantScopeID, &claim.Receipt.SiteID, &claim.Receipt.WorkflowID,
		&claim.Receipt.PolicyID, &claim.Receipt.PolicyRevision, &claim.Receipt.BindingID,
		&claim.Receipt.BindingRevision, &claim.Receipt.PublicationID, &claim.Receipt.RolloutID,
		&claim.Receipt.NodeID, &configDigest, &receiptDigest, &claim.Receipt.ExpectedRevision,
		&claim.Receipt.ActivePolicyRevision, &claim.Receipt.State, &claim.Receipt.ReasonCode,
		&claim.Receipt.ObservedAt, &claim.Actor.UserID, &claim.Actor.ScopeID, &claim.Actor.ScopeKind,
		&claim.Actor.SessionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return EdgeReceiptClaim{}, false, nil
	}
	if err != nil {
		return EdgeReceiptClaim{}, false, adapterStoreError(err)
	}
	if copyExactDigest(&claim.Receipt.ConfigSHA256, configDigest) != nil ||
		copyExactDigest(&claim.Receipt.ReceiptSHA256, receiptDigest) != nil || !validActor(claim.Actor) {
		return EdgeReceiptClaim{}, false, ErrStoreUnavailable
	}
	return claim, true, nil
}

func (queue *PostgresEdgeReceiptQueue) Complete(ctx context.Context, claim EdgeReceiptClaim) error {
	return queue.settle(ctx, claim, `UPDATE ja4_block_edge_receipt_queue_158
		SET state='completed',completed_at=now(),claimed_by=NULL,claim_token=NULL,claim_expires_at=NULL,updated_at=now()
		WHERE receipt_id=$1 AND state='claimed' AND claim_token=$2 AND recorded_at IS NOT NULL`)
}

func (queue *PostgresEdgeReceiptQueue) Retry(ctx context.Context, claim EdgeReceiptClaim, code string,
	availableAt time.Time,
) error {
	if !reasonPattern.MatchString(code) || availableAt.IsZero() {
		return ErrInvalidInput
	}
	return queue.settleWithArgs(ctx, claim, `UPDATE ja4_block_edge_receipt_queue_158
		SET state='pending',attempt_count=attempt_count+1,available_at=$3,last_error_code=$4,
			claimed_by=NULL,claim_token=NULL,claim_expires_at=NULL,updated_at=now()
		WHERE receipt_id=$1 AND state='claimed' AND claim_token=$2`, availableAt.UTC(), code)
}

func (queue *PostgresEdgeReceiptQueue) Reject(ctx context.Context, claim EdgeReceiptClaim, code string) error {
	if !reasonPattern.MatchString(code) {
		return ErrInvalidInput
	}
	return queue.settleWithArgs(ctx, claim, `UPDATE ja4_block_edge_receipt_queue_158
		SET state='rejected',rejected_at=now(),last_error_code=$3,
			claimed_by=NULL,claim_token=NULL,claim_expires_at=NULL,updated_at=now()
		WHERE receipt_id=$1 AND state='claimed' AND claim_token=$2`, code)
}

func (queue *PostgresEdgeReceiptQueue) settle(ctx context.Context, claim EdgeReceiptClaim, statement string) error {
	return queue.settleWithArgs(ctx, claim, statement)
}

func (queue *PostgresEdgeReceiptQueue) settleWithArgs(ctx context.Context, claim EdgeReceiptClaim,
	statement string, args ...any,
) error {
	if queue == nil || ctx == nil || claim.Token == uuid.Nil || claim.Receipt.ReceiptID == uuid.Nil {
		return ErrInvalidInput
	}
	values := []any{claim.Receipt.ReceiptID, claim.Token}
	values = append(values, args...)
	command, err := queue.database.Exec(ctx, statement, values...)
	if err != nil {
		return adapterStoreError(err)
	}
	if command.RowsAffected() != 1 {
		return ErrClaimLost
	}
	return nil
}

func copyExactDigest(target *[32]byte, source []byte) error {
	if len(source) != len(target) {
		return ErrStoreUnavailable
	}
	copy(target[:], source)
	return nil
}

func adapterStoreError(err error) error {
	if err == nil || errors.Is(err, ErrClaimLost) {
		return err
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return fmt.Errorf("%w: %v", ErrStoreUnavailable, err)
}

var _ PublicationTargetResolver = (*PostgresPublicationTargetResolver)(nil)
var _ EdgeReceiptQueue = (*PostgresEdgeReceiptQueue)(nil)
