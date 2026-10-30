package analyticslog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/securityactivation"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresBlockStateStore struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

type currentBindingRow struct {
	scopeID, tenantID, siteID, policyID, lastBundleID uuid.UUID
	siteDisplayID                                     int64
	siteDomain, siteRegion                            string
	activeVersion, bindingRevision, latestVersion     int64
	document                                          []byte
	blockedAt                                         time.Time
	candidateID                                       *uuid.UUID
	candidateStatus                                   *string
	canaryNodes, expandNodes                          []uuid.UUID
	readyNodes, failedNodes, supersededNodes          int
	recoveryPayload                                   []byte
}

type recoveryPayload struct {
	SiteID     string   `json:"site_id"`
	PolicyID   string   `json:"policy_id"`
	ReasonCode string   `json:"reason_code"`
	ResultCode string   `json:"result_reason_code"`
	CIDRs      []string `json:"cidrs"`
}

// blockEdgeProgressSQL counts the unlock candidate's nodes by their latest
// deployment: an ignored old release (edgedeployment.SupersededDeploymentSQL)
// is counted apart, not as failed (fix-cfgflow3).
const blockEdgeProgressSQL = `
		  SELECT count(*) FILTER (WHERE deployment.state='healthy')::int AS ready_nodes,
		         count(*) FILTER (WHERE deployment.state IN ('failed','rollback_failed')
		           AND NOT ` + edgedeployment.SupersededDeploymentSQL + `)::int AS failed_nodes,
		         count(*) FILTER (WHERE ` + edgedeployment.SupersededDeploymentSQL + `)::int AS superseded_nodes
		  FROM security_policy_activation_rollouts rollout
		  JOIN node_deployments deployment ON deployment.rollout_id=rollout.rollout_id
		  WHERE rollout.candidate_id=candidate.id AND NOT EXISTS (
		    SELECT 1 FROM node_deployments newer WHERE newer.id=deployment.id AND newer.attempt>deployment.attempt)
		`

const blockHistoryQuery = `SELECT audit.id,audit.scope_id,scope.tenant_id,audit.occurred_at,audit.payload,candidate.id,candidate.site_id,binding.policy_id,
		candidate.promoted_at,
		candidate.candidate_status,
		candidate.canary_node_ids,candidate.expand_node_ids,
		COALESCE(progress.ready_nodes,0),COALESCE(progress.failed_nodes,0),COALESCE(progress.superseded_nodes,0),
		site.display_id,site.domain,COALESCE(site.region_name,'')
			FROM audit_events audit
			JOIN access_scopes scope ON scope.id=audit.scope_id AND scope.kind='tenant'
		JOIN security_policy_activation_candidates candidate
		  ON candidate.tenant_scope_id=audit.scope_id AND candidate.id::text=audit.resource_id
		JOIN security_policy_site_bindings binding
		  ON binding.tenant_scope_id=candidate.tenant_scope_id AND binding.id=candidate.binding_id
		  AND binding.site_id=candidate.site_id
		LEFT JOIN sites site ON site.id=candidate.site_id AND site.scope_id=candidate.tenant_scope_id
		LEFT JOIN LATERAL (` + blockEdgeProgressSQL + `) progress ON true
			WHERE ($1::uuid IS NULL OR audit.scope_id=$1) AND audit.action='security_policy.activation.start'
		  AND audit.payload->>'operation'='cidr_unlock'
		  AND ($2::uuid IS NULL OR candidate.site_id=$2)
		  AND ($3::uuid IS NULL OR binding.policy_id=$3)
		  AND ($4='' OR audit.payload->'cidrs' ? $4)
		  AND ($5::timestamptz IS NULL OR audit.occurred_at >= $5)
		  AND ($6::timestamptz IS NULL OR audit.occurred_at <= $6)
		ORDER BY audit.occurred_at DESC,audit.id DESC`

const blockHistoryCountQuery = `SELECT COALESCE(SUM(
		CASE
		  WHEN $4<>'' THEN 1
		  WHEN jsonb_typeof(audit.payload->'cidrs')='array' THEN jsonb_array_length(audit.payload->'cidrs')
		  ELSE 0
		END
	),0)::bigint
		FROM audit_events audit
		JOIN access_scopes scope ON scope.id=audit.scope_id AND scope.kind='tenant'
		JOIN security_policy_activation_candidates candidate
		  ON candidate.tenant_scope_id=audit.scope_id AND candidate.id::text=audit.resource_id
		JOIN security_policy_site_bindings binding
		  ON binding.tenant_scope_id=candidate.tenant_scope_id AND binding.id=candidate.binding_id
		  AND binding.site_id=candidate.site_id
			WHERE ($1::uuid IS NULL OR audit.scope_id=$1) AND audit.action='security_policy.activation.start'
		  AND audit.payload->>'operation'='cidr_unlock'
		  AND ($2::uuid IS NULL OR candidate.site_id=$2)
		  AND ($3::uuid IS NULL OR binding.policy_id=$3)
		  AND ($4='' OR audit.payload->'cidrs' ? $4)
		  AND ($5::timestamptz IS NULL OR audit.occurred_at >= $5)
		  AND ($6::timestamptz IS NULL OR audit.occurred_at <= $6)`

func NewPostgresBlockStateStore(pool *pgxpool.Pool, now func() time.Time) (*PostgresBlockStateStore, error) {
	if !configuredPGXPool(pool) || now == nil {
		return nil, ErrInvalidConfiguration
	}
	return &PostgresBlockStateStore{pool: pool, now: now}, nil
}

func (store *PostgresBlockStateStore) ListCurrent(ctx context.Context, scopeID uuid.UUID,
	request BlockListRequest,
) (CurrentBlockPage, error) {
	rows, err := store.loadCurrentBindings(ctx, scopeID, request.SiteID)
	if err != nil {
		return CurrentBlockPage{}, blockStoreError(ctx, err)
	}
	items := make([]CurrentBlock, 0, request.Limit)
	var totalCount uint64
	for _, row := range rows {
		if request.PolicyID != nil && row.policyID != *request.PolicyID {
			continue
		}
		var policy securitypolicy.Policy
		if err := json.Unmarshal(row.document, &policy); err != nil || policy.ID != row.policyID ||
			policy.ScopeID != row.scopeID || policy.Revision != row.activeVersion || policy.Kind != securitypolicy.KindACL {
			return CurrentBlockPage{}, ErrStorageUnavailable
		}
		for _, rule := range policy.Rules {
			if !rule.Enabled || rule.Action != securitypolicy.ActionBlock {
				continue
			}
			for _, condition := range rule.Conditions {
				if condition.Field != "client_ip" || condition.Operator != "ip_in_cidr" {
					continue
				}
				for _, cidr := range condition.Values {
					if !validBlockCIDR(cidr) {
						return CurrentBlockPage{}, ErrStorageUnavailable
					}
					if request.CIDR != "" && request.CIDR != cidr {
						continue
					}
					item := CurrentBlock{
						ID: blockIdentity(row.siteID, row.policyID, cidr), TenantID: row.tenantID, SiteID: row.siteID,
						SiteDisplayID: row.siteDisplayID, Domain: row.siteDomain, Position: row.siteRegion,
						PolicyID: row.policyID, PolicyVersion: row.activeVersion, CIDR: cidr,
						ReasonCode: "acl_policy_block", BlockedAt: row.blockedAt,
						Unlockable: blockBindingUnlockable(row),
					}
					var payload recoveryPayload
					if row.candidateID != nil && json.Unmarshal(row.recoveryPayload, &payload) == nil &&
						slices.Contains(payload.CIDRs, cidr) {
						item.EdgeProgress = &EdgeProgress{
							CandidateID: *row.candidateID, State: valueOrEmpty(row.candidateStatus),
							TotalNodes: len(row.canaryNodes) + len(row.expandNodes),
							ReadyNodes: row.readyNodes, FailedNodes: row.failedNodes, SupersededNodes: row.supersededNodes,
						}
					}
					totalCount++
					if totalCount > uint64(request.Offset) && len(items) < int(request.Limit) {
						items = append(items, item)
					}
				}
			}
		}
	}
	return CurrentBlockPage{Items: items, TotalCount: totalCount, SnapshotAt: store.now().UTC()}, nil
}

func (store *PostgresBlockStateStore) ListHistory(ctx context.Context, scopeID uuid.UUID,
	request BlockListRequest,
) (BlockHistoryPage, error) {
	var policyID any
	if request.PolicyID != nil {
		policyID = *request.PolicyID
	}
	var scopeFilter any
	if scopeID != uuid.Nil {
		scopeFilter = scopeID
	}
	var totalCount int64
	if err := store.pool.QueryRow(ctx, blockHistoryCountQuery, scopeFilter, request.SiteID, policyID, request.CIDR,
		request.OccurredFrom, request.OccurredTo).Scan(&totalCount); err != nil {
		return BlockHistoryPage{}, blockStoreError(ctx, err)
	}
	if totalCount < 0 {
		return BlockHistoryPage{}, ErrStorageUnavailable
	}
	rows, err := store.pool.Query(ctx, blockHistoryQuery, scopeFilter, request.SiteID, policyID, request.CIDR,
		request.OccurredFrom, request.OccurredTo)
	if err != nil {
		return BlockHistoryPage{}, blockStoreError(ctx, err)
	}
	defer rows.Close()
	items := make([]BlockHistory, 0, request.Limit)
	var historyIndex uint32
	for rows.Next() {
		var tenantScopeID, tenantID, auditID, candidateID, candidateSiteID, candidatePolicyID uuid.UUID
		var occurredAt time.Time
		var promotedAt *time.Time
		var encoded []byte
		var state string
		var canary, expand []uuid.UUID
		var ready, failed, superseded, siteDisplayID int
		var siteDomain, siteRegion string
		if err := rows.Scan(&auditID, &tenantScopeID, &tenantID, &occurredAt, &encoded, &candidateID, &candidateSiteID, &candidatePolicyID,
			&promotedAt, &state, &canary, &expand, &ready, &failed, &superseded,
			&siteDisplayID, &siteDomain, &siteRegion); err != nil {
			return BlockHistoryPage{}, blockStoreError(ctx, err)
		}
		var payload recoveryPayload
		if err := json.Unmarshal(encoded, &payload); err != nil {
			return BlockHistoryPage{}, ErrStorageUnavailable
		}
		siteID, siteErr := uuid.Parse(payload.SiteID)
		policyID, policyErr := uuid.Parse(payload.PolicyID)
		if tenantScopeID == uuid.Nil || tenantID == uuid.Nil || siteErr != nil || policyErr != nil || siteID == uuid.Nil || policyID == uuid.Nil ||
			siteID != candidateSiteID || policyID != candidatePolicyID || len(payload.CIDRs) == 0 {
			return BlockHistoryPage{}, ErrStorageUnavailable
		}
		for _, cidr := range payload.CIDRs {
			if !validBlockCIDR(cidr) {
				return BlockHistoryPage{}, ErrStorageUnavailable
			}
			if request.CIDR != "" && request.CIDR != cidr {
				continue
			}
			if historyIndex < request.Offset {
				historyIndex++
				continue
			}
			historyIndex++
			if len(items) >= int(request.Limit) {
				continue
			}
			items = append(items, BlockHistory{
				ID: uuid.NewSHA1(auditID, []byte(cidr)), BlockID: blockIdentity(siteID, policyID, cidr), TenantID: tenantID,
				SiteID: siteID, SiteDisplayID: int64(siteDisplayID), Domain: siteDomain, Position: siteRegion,
				PolicyID: policyID, CIDR: cidr, ReasonCode: payload.ReasonCode,
				ResultCode: payload.ResultCode, AutoUnlock: promotedAt == nil,
				RequestedAt: occurredAt.UTC(), UnlockedAt: utcTimePointer(promotedAt), EdgeProgress: EdgeProgress{
					CandidateID: candidateID, State: state, TotalNodes: len(canary) + len(expand),
					ReadyNodes: ready, FailedNodes: failed, SupersededNodes: superseded,
				},
			})
		}
	}
	if err := rows.Err(); err != nil {
		return BlockHistoryPage{}, blockStoreError(ctx, err)
	}
	return BlockHistoryPage{Items: items, TotalCount: uint64(totalCount), SnapshotAt: store.now().UTC()}, nil
}

func (store *PostgresBlockStateStore) CountCurrent(ctx context.Context, scopeID uuid.UUID,
) (SiteBlacklistCountPage, error) {
	rows, err := store.loadCurrentBindings(ctx, scopeID, nil)
	if err != nil {
		return SiteBlacklistCountPage{}, blockStoreError(ctx, err)
	}
	items := make([]SiteBlacklistCount, 0, len(rows))
	for _, row := range rows {
		var policy securitypolicy.Policy
		if err := json.Unmarshal(row.document, &policy); err != nil || policy.ID != row.policyID ||
			policy.ScopeID != row.scopeID || policy.Revision != row.activeVersion || policy.Kind != securitypolicy.KindACL {
			return SiteBlacklistCountPage{}, ErrStorageUnavailable
		}
		var count uint64
		for _, rule := range policy.Rules {
			if !rule.Enabled || rule.Action != securitypolicy.ActionBlock {
				continue
			}
			for _, condition := range rule.Conditions {
				if condition.Field != "client_ip" || condition.Operator != "ip_in_cidr" {
					continue
				}
				for _, cidr := range condition.Values {
					if !validBlockCIDR(cidr) {
						return SiteBlacklistCountPage{}, ErrStorageUnavailable
					}
					count++
				}
			}
		}
		if count == 0 {
			continue
		}
		items = append(items, SiteBlacklistCount{
			TenantID: row.tenantID, SiteID: row.siteID, SiteDisplayID: row.siteDisplayID, Domain: row.siteDomain, Count: count,
		})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count != items[j].Count {
			return items[i].Count > items[j].Count
		}
		return items[i].SiteDisplayID < items[j].SiteDisplayID
	})
	return SiteBlacklistCountPage{Items: items, TotalCount: uint64(len(items)), SnapshotAt: store.now().UTC()}, nil
}

func utcTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	result := value.UTC()
	return &result
}

func (store *PostgresBlockStateStore) PrepareUnlock(ctx context.Context, scopeID,
	blockID uuid.UUID,
) (BlockUnlockPreparation, error) {
	rows, err := store.loadCurrentBindings(ctx, scopeID, nil)
	if err != nil {
		return BlockUnlockPreparation{}, blockStoreError(ctx, err)
	}
	for _, row := range rows {
		var policy securitypolicy.Policy
		if err := json.Unmarshal(row.document, &policy); err != nil || policy.ID != row.policyID ||
			policy.ScopeID != scopeID || policy.Revision != row.activeVersion {
			return BlockUnlockPreparation{}, ErrStorageUnavailable
		}
		for _, rule := range policy.Rules {
			if !rule.Enabled || rule.Action != securitypolicy.ActionBlock {
				continue
			}
			for _, condition := range rule.Conditions {
				if condition.Field != "client_ip" || condition.Operator != "ip_in_cidr" {
					continue
				}
				for _, cidr := range condition.Values {
					if !validBlockCIDR(cidr) {
						return BlockUnlockPreparation{}, ErrStorageUnavailable
					}
					if blockIdentity(row.siteID, row.policyID, cidr) != blockID {
						continue
					}
					nodes, loadErr := store.loadPublicationNodes(ctx, scopeID, row.lastBundleID)
					if loadErr != nil {
						return BlockUnlockPreparation{}, blockStoreError(ctx, loadErr)
					}
					prepared := BlockUnlockPreparation{
						Block: CurrentBlock{ID: blockID, TenantID: row.tenantID, SiteID: row.siteID, PolicyID: row.policyID,
							PolicyVersion: row.activeVersion, CIDR: cidr, ReasonCode: "acl_policy_block",
							BlockedAt: row.blockedAt},
						Policy: policy, BindingRevision: row.bindingRevision,
						ActivePolicyVersion: row.activeVersion, LatestPolicyVersion: row.latestVersion,
						TargetNodeIDs: nodes,
					}
					if row.candidateID != nil && isOpenActivation(valueOrEmpty(row.candidateStatus)) {
						prepared.OpenCandidateID = *row.candidateID
					}
					return prepared, nil
				}
			}
		}
	}
	return BlockUnlockPreparation{}, ErrBlockStateNotFound
}

const currentBindingsQuery = `SELECT binding.tenant_scope_id,scope.tenant_id,binding.site_id,binding.policy_id,binding.active_policy_version,binding.revision,
		binding.last_bundle_id,version.document,policy.revision,publication.created_at,
		candidate.id,candidate.candidate_status,candidate.canary_node_ids,candidate.expand_node_ids,
		COALESCE(progress.ready_nodes,0),COALESCE(progress.failed_nodes,0),COALESCE(progress.superseded_nodes,0),candidate_audit.payload,
		site.display_id,site.domain,COALESCE(site.region_name,'')
		FROM security_policy_site_bindings binding
		JOIN access_scopes scope ON scope.id=binding.tenant_scope_id AND scope.kind='tenant'
		JOIN sites site ON site.id=binding.site_id AND site.scope_id=binding.tenant_scope_id
		JOIN security_policy_versions version
		  ON version.policy_id=binding.policy_id AND version.revision=binding.active_policy_version
		JOIN security_policies policy ON policy.scope_id=binding.tenant_scope_id AND policy.id=binding.policy_id
		JOIN security_policy_publications publication
		  ON publication.tenant_scope_id=binding.tenant_scope_id AND publication.id=binding.last_bundle_id
		LEFT JOIN LATERAL (
		  SELECT value.* FROM security_policy_activation_candidates value
		  JOIN audit_events event ON event.scope_id=value.tenant_scope_id AND event.resource_id=value.id::text
		    AND event.action='security_policy.activation.start' AND event.payload->>'operation'='cidr_unlock'
		  WHERE value.tenant_scope_id=binding.tenant_scope_id AND value.binding_id=binding.id
		  ORDER BY value.created_at DESC,value.id DESC LIMIT 1
		) candidate ON true
		LEFT JOIN audit_events candidate_audit ON candidate_audit.scope_id=binding.tenant_scope_id
		  AND candidate_audit.resource_id=candidate.id::text AND candidate_audit.action='security_policy.activation.start'
		LEFT JOIN LATERAL (` + blockEdgeProgressSQL + `) progress ON true
		WHERE ($1::uuid IS NULL OR binding.tenant_scope_id=$1) AND binding.policy_kind='acl'
		  AND binding.active_policy_version IS NOT NULL AND ($2::uuid IS NULL OR binding.site_id=$2)
		ORDER BY binding.site_id,binding.policy_id`

func (store *PostgresBlockStateStore) loadCurrentBindings(ctx context.Context, scopeID uuid.UUID,
	siteID *uuid.UUID,
) ([]currentBindingRow, error) {
	query := currentBindingsQuery
	var scopeFilter any
	if scopeID != uuid.Nil {
		scopeFilter = scopeID
	}
	rows, err := store.pool.Query(ctx, query, scopeFilter, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]currentBindingRow, 0)
	for rows.Next() {
		var row currentBindingRow
		if err := rows.Scan(&row.scopeID, &row.tenantID, &row.siteID, &row.policyID, &row.activeVersion, &row.bindingRevision,
			&row.lastBundleID, &row.document, &row.latestVersion, &row.blockedAt,
			&row.candidateID, &row.candidateStatus, &row.canaryNodes, &row.expandNodes,
			&row.readyNodes, &row.failedNodes, &row.supersededNodes, &row.recoveryPayload,
			&row.siteDisplayID, &row.siteDomain, &row.siteRegion); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func (store *PostgresBlockStateStore) loadPublicationNodes(ctx context.Context, scopeID,
	publicationID uuid.UUID,
) ([]uuid.UUID, error) {
	rows, err := store.pool.Query(ctx, `SELECT node_id FROM security_policy_publication_targets
		WHERE tenant_scope_id=$1 AND publication_id=$2 ORDER BY node_id`, scopeID, publicationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]uuid.UUID, 0)
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		result = append(result, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(result) == 0 {
		return nil, ErrBlockStateConflict
	}
	return result, nil
}

func isOpenActivation(state string) bool {
	return state == string(securityactivation.StatusClaimed) || state == string(securityactivation.StatusCanary) ||
		state == string(securityactivation.StatusExpanding) || state == string(securityactivation.StatusHealthy)
}

func blockBindingUnlockable(row currentBindingRow) bool {
	return row.latestVersion == row.activeVersion &&
		(row.candidateID == nil || !isOpenActivation(valueOrEmpty(row.candidateStatus)))
}

func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func blockStoreError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, ErrBlockStateNotFound) {
		return ErrBlockStateNotFound
	}
	if errors.Is(err, ErrBlockStateConflict) {
		return err
	}
	return fmt.Errorf("%w: block state postgres", ErrStorageUnavailable)
}
