//go:build integration

package nodescheduler

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock/protocol"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type nodeSchedulingLoadProviderFunc func(context.Context, uuid.UUID, []Endpoint) (map[uuid.UUID]LoadSample, error)

func (provider nodeSchedulingLoadProviderFunc) Loads(
	ctx context.Context,
	tenantScopeID uuid.UUID,
	endpoints []Endpoint,
) (map[uuid.UUID]LoadSample, error) {
	return provider(ctx, tenantScopeID, endpoints)
}

func TestRollbackCopiesHistoryForwardAndAudits(t *testing.T) {
	fixture := newIntegrationFixture(t)
	groupID := uuid.New()
	first := fixture.putRequest(groupID, 0, "rollback-first", "rollback-first")
	first.Region, first.ResolvedValue, first.Note, first.SortOrder = "华东", "rollback-first", "首版", 17
	if _, err := fixture.service.PutGroup(t.Context(), fixture.actor, first); err != nil {
		t.Fatal(err)
	}
	second := fixture.putRequest(groupID, 1, "rollback-second", "rollback-second")
	second.Region, second.ResolvedValue, second.Note, second.SortOrder = "华北", "rollback-second", "二版", 3
	second.Endpoints[0].Weight = 9
	if _, err := fixture.service.PutGroup(t.Context(), fixture.actor, second); err != nil {
		t.Fatal(err)
	}
	rolled, err := fixture.service.Rollback(t.Context(), fixture.actor, groupID, 1, 2, "rollback-copy", "rollback-copy-request")
	if err != nil || rolled.Group.Revision != 3 || rolled.Group.Name != first.Name ||
		rolled.Group.Region != first.Region || rolled.Group.ResolvedValue != first.ResolvedValue ||
		rolled.Group.Note != first.Note || rolled.Group.SortOrder != first.SortOrder ||
		rolled.Group.Endpoints[0].Weight != first.Endpoints[0].Weight {
		t.Fatalf("rollback=%#v err=%v", rolled, err)
	}
	replay, err := fixture.service.Rollback(t.Context(), fixture.actor, groupID, 1, 2, "rollback-copy", "rollback-copy-request")
	if err != nil || !replay.Replayed || replay.Group.Revision != 3 {
		t.Fatalf("rollback replay=%#v err=%v", replay, err)
	}
	var auditCount int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events
		WHERE scope_id=$1 AND action='node_scheduling.group.rollback' AND resource_id=$2
		AND payload->>'rollback_source_revision'='1'`, fixture.actor.ScopeID, groupID.String()).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("rollback audit count=%d", auditCount)
	}

	identicalGroupID := uuid.New()
	identical := fixture.putRequest(identicalGroupID, 0, "rollback-identical", "rollback-identical-create")
	if _, err := fixture.service.PutGroup(t.Context(), fixture.actor, identical); err != nil {
		t.Fatal(err)
	}
	identical.ExpectedRevision = 1
	identical.IdempotencyKey = "rollback-identical-update"
	identical.RequestID = "rollback-identical-update-request"
	if _, err := fixture.service.PutGroup(t.Context(), fixture.actor, identical); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.Rollback(t.Context(), fixture.actor, identicalGroupID, 1, 2,
		"rollback-source-bound", "rollback-source-one"); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.Rollback(t.Context(), fixture.actor, identicalGroupID, 2, 2,
		"rollback-source-bound", "rollback-source-two"); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("rollback source revision drift error=%v", err)
	}
}

func TestLineGroupMetadataEmptyCreateUpdateListAndReplay(t *testing.T) {
	fixture := newIntegrationFixture(t)
	create := PutGroupRequest{
		Name: "空线路组", Region: " 华东 ", Note: " 待配置节点 ", SortOrder: 20,
		IdempotencyKey: "empty-metadata-create", RequestID: "empty-metadata-request",
	}
	created, err := fixture.service.PutGroup(t.Context(), fixture.actor, create)
	if err != nil {
		t.Fatal(err)
	}
	groupID := created.Group.GroupID
	wantResolvedValue := "lg-" + strings.ReplaceAll(groupID.String(), "-", "")
	if groupID == uuid.Nil || created.Group.Region != "华东" || created.Group.Note != "待配置节点" ||
		created.Group.ResolvedValue != wantResolvedValue || created.Group.SortOrder != 20 ||
		len(created.Group.Endpoints) != 0 {
		t.Fatalf("created empty group = %#v", created.Group)
	}
	replay, err := fixture.service.PutGroup(t.Context(), fixture.actor, create)
	if err != nil || !replay.Replayed || replay.Group.GroupID != groupID ||
		replay.Group.ResolvedValue != wantResolvedValue {
		t.Fatalf("empty group replay = %#v, err = %v", replay, err)
	}
	plan, err := fixture.service.PlanCurrent(t.Context(), fixture.actor, groupID, Selector{})
	if !errors.Is(err, ErrNoHealthyEndpoint) || plan.TierReason != ReasonNoHealthyEndpoint ||
		plan.Digest == ([32]byte{}) {
		t.Fatalf("empty group plan = %#v, err = %v", plan, err)
	}

	beforeID := uuid.New()
	before := fixture.putRequest(beforeID, 0, "优先线路组", "sorted-metadata-create")
	before.SortOrder = 5
	if _, err := fixture.service.PutGroup(t.Context(), fixture.actor, before); err != nil {
		t.Fatal(err)
	}
	listed, err := fixture.service.List(t.Context(), fixture.actor)
	if err != nil || len(listed) != 2 || listed[0].GroupID != beforeID || listed[1].GroupID != groupID {
		t.Fatalf("sorted groups = %#v, err = %v", listed, err)
	}

	update := fixture.putRequest(groupID, 1, "已配置线路组", "empty-metadata-update")
	update.Region, update.ResolvedValue, update.Note, update.SortOrder = "华北", "edge-custom", "已配置", 2
	updated, err := fixture.service.PutGroup(t.Context(), fixture.actor, update)
	if err != nil || updated.Group.Revision != 2 || updated.Group.Region != update.Region ||
		updated.Group.ResolvedValue != update.ResolvedValue || updated.Group.Note != update.Note ||
		updated.Group.SortOrder != update.SortOrder || len(updated.Group.Endpoints) != 2 {
		t.Fatalf("updated group = %#v, err = %v", updated.Group, err)
	}
	historical, err := fixture.service.GetRevision(t.Context(), fixture.actor, groupID, 1)
	if err != nil || historical.ResolvedValue != wantResolvedValue || len(historical.Endpoints) != 0 {
		t.Fatalf("historical empty revision = %#v, err = %v", historical, err)
	}
	rolled, err := fixture.service.Rollback(t.Context(), fixture.actor, groupID, 1, 2,
		"empty-metadata-rollback", "empty-metadata-rollback-request")
	if err != nil || rolled.Group.Revision != 3 || rolled.Group.Region != "华东" ||
		rolled.Group.ResolvedValue != wantResolvedValue || rolled.Group.Note != "待配置节点" ||
		rolled.Group.SortOrder != 20 || len(rolled.Group.Endpoints) != 0 {
		t.Fatalf("rolled empty revision = %#v, err = %v", rolled.Group, err)
	}
	if _, err := fixture.service.PlanCurrent(t.Context(), fixture.actor, groupID, Selector{}); !errors.Is(err, ErrNoHealthyEndpoint) {
		t.Fatalf("rolled empty group plan error = %v", err)
	}

	var metadataAuditCount int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events
		WHERE scope_id=$1 AND resource_id=$2 AND action='node_scheduling.group.create'
		  AND payload->>'region'='华东' AND payload->>'resolved_value'=$3
		  AND payload->>'note'='待配置节点' AND (payload->>'sort_order')::integer=20
		  AND (payload->>'endpoint_count')::integer=0`, fixture.actor.ScopeID, groupID.String(), wantResolvedValue).
		Scan(&metadataAuditCount); err != nil {
		t.Fatal(err)
	}
	if metadataAuditCount != 1 {
		t.Fatalf("metadata audit count = %d", metadataAuditCount)
	}
}

func TestOperationScopedReceiptsDoNotConflict(t *testing.T) {
	fixture := newIntegrationFixture(t)
	groupID := uuid.New()
	l1NodeID, l2NodeID := uuid.New(), uuid.New()
	for index, nodeID := range []uuid.UUID{l1NodeID, l2NodeID} {
		seedSchedulerActiveNode(t, fixture, nodeID, "operation-node-"+string(rune('a'+index)))
	}
	const key = "same-public-key"
	create := fixture.putRequest(groupID, 0, "operation-create", key)
	create.Endpoints[0].NodeID, create.Endpoints[1].NodeID = l2NodeID, l2NodeID
	create.Endpoints[1].Address = "192.0.2.11"
	ownEndpointAddresses(t, fixture, create.Endpoints)
	if _, err := fixture.service.PutGroup(t.Context(), fixture.actor, create); err != nil {
		t.Fatalf("create with shared key: %v", err)
	}
	update := fixture.putRequest(groupID, 1, "operation-update", key)
	update.Endpoints[0].NodeID, update.Endpoints[1].NodeID = l2NodeID, l2NodeID
	update.Endpoints[1].Address = "192.0.2.11"
	if _, err := fixture.service.PutGroup(t.Context(), fixture.actor, update); err != nil {
		t.Fatalf("update with shared key: %v", err)
	}
	if _, err := fixture.service.Rollback(t.Context(), fixture.actor, groupID, 1, 2, key, key+"-rollback"); err != nil {
		t.Fatalf("rollback with shared key: %v", err)
	}
	if _, err := fixture.service.CreateTargetSnapshotForNodes(t.Context(), fixture.actor, groupID, 3,
		[]uuid.UUID{l1NodeID}, key, key+"-snapshot"); err != nil {
		t.Fatalf("snapshot with shared key: %v", err)
	}
	rows, err := fixture.pool.Query(t.Context(), `SELECT operation FROM node_scheduling_write_requests
		WHERE tenant_scope_id=$1 AND actor_user_id=$2 AND idempotency_key=$3 ORDER BY operation`,
		fixture.actor.ScopeID, fixture.actor.UserID, key)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var operations []string
	for rows.Next() {
		var operation string
		if err := rows.Scan(&operation); err != nil {
			t.Fatal(err)
		}
		operations = append(operations, operation)
	}
	want := []string{
		"node_scheduling.group.create",
		"node_scheduling.group.rollback",
		"node_scheduling.group.update",
		"node_scheduling.target_snapshot.create",
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(operations, ",") != strings.Join(want, ",") {
		t.Fatalf("operation receipts=%v want=%v", operations, want)
	}
}

func TestDecisionTelemetryErrorFallsBackAndAudits(t *testing.T) {
	fixture := newIntegrationFixture(t)
	groupID := uuid.New()
	request := fixture.putRequest(groupID, 0, "decision-audit", "decision-audit-create")
	request.Endpoints[1].Priority = 0
	created, err := fixture.service.PutGroup(t.Context(), fixture.actor, request)
	if err != nil {
		t.Fatal(err)
	}
	for sequence := int64(1); sequence <= 3; sequence++ {
		fixture.clock.Set(integrationBaseTime.Add(time.Duration(sequence) * 10 * time.Second))
		for _, endpoint := range created.Group.Endpoints {
			if _, err := fixture.service.RecordProbe(t.Context(), ProbeRequest{
				TenantScopeID: fixture.actor.ScopeID, GroupID: groupID, Revision: 1,
				EndpointID: endpoint.ID, Sequence: sequence,
				ObservedAt: fixture.clock.Now(), Healthy: true,
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	fixture.service.loads = nodeSchedulingLoadProviderFunc(func(
		_ context.Context,
		tenantScopeID uuid.UUID,
		endpoints []Endpoint,
	) (map[uuid.UUID]LoadSample, error) {
		if tenantScopeID != fixture.actor.ScopeID {
			return nil, errors.New("wrong tenant scope")
		}
		loads := make(map[uuid.UUID]LoadSample, len(endpoints))
		for _, endpoint := range endpoints {
			loads[endpoint.ID] = LoadSample{ObservedAt: fixture.clock.Now()}
		}
		return loads, errors.New("telemetry unavailable")
	})
	decision, err := fixture.service.DecideCurrent(t.Context(), fixture.actor, groupID, DecisionRequest{
		Strategy: StrategyP2CLeastLoaded, StableKey: "  private-stable-key  ", RequestID: "decision-audit-request",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Fallback || decision.Reason != "telemetry_unavailable_fallback" {
		t.Fatalf("decision=%#v", decision)
	}
	stableKeyDigest := sha256.Sum256([]byte("private-stable-key"))
	var auditCount int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events
		WHERE scope_id=$1 AND action='node_scheduling.decision.evaluate' AND resource_id=$2
		  AND request_id='decision-audit-request'
		  AND (SELECT count(*) FROM jsonb_object_keys(payload))=14
		  AND payload->>'requested_strategy'='p2c_least_loaded'
		  AND payload->>'effective_strategy'='weighted_baseline'
		  AND payload->>'reason'='telemetry_unavailable_fallback'
		  AND (payload->>'fallback')::boolean
		  AND payload->>'group_id'=$2
		  AND (payload->>'revision')::bigint=1
		  AND payload->>'endpoint_id'=$3
		  AND payload->>'plan_digest'=$4
		  AND payload->'selector'='{"region":"","carrier":""}'::jsonb
		  AND (payload->>'priority')::integer=0
		  AND (payload->>'candidate_count')::integer=2
		  AND (payload->>'standby_count')::integer=0
		  AND payload->>'stable_key_sha256'=$5
		  AND payload->'snapshot'->>'tier_reason'='primary_priority_selected'
		  AND jsonb_array_length(payload->'snapshot'->'endpoint_evaluations')=2
		  AND payload->'snapshot'->>'plan_digest'=payload->>'plan_digest'
		  AND NOT (payload ? 'stable_key') AND NOT (payload ? 'stable_key_digest')
		  AND payload::text NOT LIKE '%private-stable-key%'`,
		fixture.actor.ScopeID, groupID.String(), decision.Endpoint.ID.String(),
		hex.EncodeToString(decision.Plan.Digest[:]), hex.EncodeToString(stableKeyDigest[:])).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("decision audit count=%d", auditCount)
	}
}

func TestTopologySnapshotL1L2ReplayConflictAndCycle(t *testing.T) {
	fixture := newIntegrationFixture(t)
	l1a, l1b, l2a, l2b := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for index, nodeID := range []uuid.UUID{l1a, l1b, l2a, l2b} {
		seedSchedulerActiveNode(t, fixture, nodeID, "topology-"+string(rune('a'+index)))
	}
	groupID := uuid.New()
	request := fixture.putRequest(groupID, 0, "topology-primary", "topology-primary")
	request.Endpoints[0].NodeID, request.Endpoints[1].NodeID = l2a, l2b
	// A node-bound endpoint must use one of its node's addresses.
	for nodeID, address := range map[uuid.UUID]string{l2a: request.Endpoints[0].Address, l2b: request.Endpoints[1].Address} {
		if _, err := fixture.pool.Exec(t.Context(), `UPDATE nodes SET ipv4=CASE WHEN family($2::inet)=4 THEN $2::inet END,
			ipv6=CASE WHEN family($2::inet)=6 THEN $2::inet END WHERE id=$1`, nodeID, address); err != nil {
			t.Fatal(err)
		}
	}
	// l1b carries the IPv4 endpoint as a secondary IP (节点管理 > 副IP).
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE nodes SET management_settings=jsonb_set(management_settings,
		'{secondary_ips}',jsonb_build_array($2::text)) WHERE id=$1`, l1b, request.Endpoints[0].Address); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.PutGroup(t.Context(), fixture.actor, request); err != nil {
		t.Fatal(err)
	}
	created, err := fixture.service.CreateTargetSnapshotForNodes(t.Context(), fixture.actor, groupID, 1,
		[]uuid.UUID{l1a}, "topology-snapshot", "topology-snapshot-request")
	if err != nil || created.Replayed || len(created.NodeIDs) != 1 || created.NodeIDs[0] != l1a {
		t.Fatalf("topology snapshot=%#v err=%v", created, err)
	}
	replay, err := fixture.service.CreateTargetSnapshotForNodes(t.Context(), fixture.actor, groupID, 1,
		[]uuid.UUID{l1a}, "topology-snapshot-replay", "topology-snapshot-replay-request")
	if err != nil || !replay.Replayed || replay.Reference != created.Reference {
		t.Fatalf("topology replay=%#v err=%v", replay, err)
	}
	if _, err := fixture.service.CreateTargetSnapshotForNodes(t.Context(), fixture.actor, groupID, 1,
		[]uuid.UUID{l1b}, "topology-conflict", "topology-conflict-request"); !errors.Is(err, ErrTargetSnapshotConflict) {
		t.Fatalf("different target set error=%v", err)
	}

	chainGroupID := uuid.New()
	chain := fixture.putRequest(chainGroupID, 0, "topology-chain", "topology-chain")
	chain.Endpoints[0].NodeID, chain.Endpoints[1].NodeID = l1b, l2b
	if _, err := fixture.service.PutGroup(t.Context(), fixture.actor, chain); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.CreateTargetSnapshotForNodes(t.Context(), fixture.actor, chainGroupID, 1,
		[]uuid.UUID{l2a}, "topology-chain-snapshot", "topology-chain-request"); !errors.Is(err, ErrTopologyCycle) {
		t.Fatalf("L2-to-L2 error=%v", err)
	}
	selfGroupID := uuid.New()
	self := fixture.putRequest(selfGroupID, 0, "topology-self", "topology-self")
	self.Endpoints[0].NodeID, self.Endpoints[1].NodeID = l1b, l2b
	if _, err := fixture.service.PutGroup(t.Context(), fixture.actor, self); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.CreateTargetSnapshotForNodes(t.Context(), fixture.actor, selfGroupID, 1,
		[]uuid.UUID{l1b}, "topology-self-snapshot", "topology-self-request"); !errors.Is(err, ErrTopologyCycle) {
		t.Fatalf("self edge error=%v", err)
	}
}

func TestGetTargetSnapshotTenantRevocationPlatformAndMissing(t *testing.T) {
	fixture := newIntegrationFixture(t)
	l1NodeID, l2NodeID := uuid.New(), uuid.New()
	for index, nodeID := range []uuid.UUID{l1NodeID, l2NodeID} {
		seedSchedulerActiveNode(t, fixture, nodeID, "snapshot-read-node-"+string(rune('a'+index)))
	}
	groupID := uuid.New()
	request := fixture.putRequest(groupID, 0, "snapshot-read", "snapshot-read-group")
	request.Endpoints[0].NodeID, request.Endpoints[1].NodeID = l2NodeID, l2NodeID
	ownEndpointAddresses(t, fixture, request.Endpoints)
	if _, err := fixture.service.PutGroup(t.Context(), fixture.actor, request); err != nil {
		t.Fatal(err)
	}
	created, err := fixture.service.CreateTargetSnapshotForNodes(t.Context(), fixture.actor, groupID, 1,
		[]uuid.UUID{l1NodeID}, "snapshot-read-create", "snapshot-read-create-request")
	if err != nil {
		t.Fatal(err)
	}

	viewer := seedTenantViewer(t, fixture.pool, fixture.actor.ScopeID, "snapshot-custom-reader")
	loaded, err := fixture.service.GetTargetSnapshot(t.Context(), viewer, groupID, 1)
	if err != nil || loaded.Reference != created.Reference {
		t.Fatalf("tenant custom read=%#v err=%v", loaded, err)
	}
	var grantID, tenantID, roleID, revokerID uuid.UUID
	var roleRevision int64
	if err := fixture.pool.QueryRow(t.Context(), `SELECT grant_row.id,grant_row.tenant_id,grant_row.role_id,
		grant_row.role_revision,grant_row.granted_by_user_id
		FROM custom_role_grants grant_row
		WHERE grant_row.tenant_scope_id=$1 AND grant_row.subject_user_id=$2
		  AND NOT EXISTS (SELECT 1 FROM custom_role_grant_revocations revoked WHERE revoked.grant_id=grant_row.id)`,
		fixture.actor.ScopeID, viewer.UserID).Scan(&grantID, &tenantID, &roleID, &roleRevision, &revokerID); err != nil {
		t.Fatal(err)
	}
	if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		if _, err := protocol.BeginAuthorityMutation(t.Context(), tx, protocol.OperationCustomRoleRevoke,
			[]uuid.UUID{fixture.actor.ScopeID}); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO custom_role_grant_revocations(
			id,grant_id,tenant_id,tenant_scope_id,role_id,role_revision,subject_user_id,
			revoked_by_user_id,revoked_by_scope_id,revoked_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$4,$9)`, uuid.New(), grantID, tenantID,
			fixture.actor.ScopeID, roleID, roleRevision, viewer.UserID, revokerID, integrationBaseTime)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.GetTargetSnapshot(t.Context(), viewer, groupID, 1); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("revoked custom reader error=%v", err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	tokens, err := identity.NewTokenManager(strings.Repeat("r", 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := sessioncredential.NewVerifier(tokens, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x31}, 32), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewIAMService(fixture.pool, func() time.Time { return now }, authorizer, nil)
	if err != nil {
		t.Fatal(err)
	}
	platformActor := seedPlatformIAMSession(t, fixture, tokens, now)
	loaded, err = service.GetTargetSnapshot(t.Context(), platformActor, groupID, 1)
	if err != nil || loaded.TenantScopeID != fixture.actor.ScopeID || loaded.Reference != created.Reference {
		t.Fatalf("platform scoped read=%#v err=%v", loaded, err)
	}
	if _, err := service.GetTargetSnapshot(t.Context(), platformActor, groupID, 99); !errors.Is(err, ErrNotFound) {
		t.Fatalf("platform missing snapshot error=%v", err)
	}
}

func TestIAMCredentialsRevocationRBACAndPlatformBoundary(t *testing.T) {
	fixture := newIntegrationFixture(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	tokens, err := identity.NewTokenManager(strings.Repeat("n", 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pepper := bytes.Repeat([]byte{0x42}, 32)
	sessions, _ := sessioncredential.NewVerifier(tokens, func() time.Time { return now })
	apiKeys, _ := apikeycredential.NewVerifier(pepper, func() time.Time { return now })
	authorizer, err := iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewIAMService(fixture.pool, func() time.Time { return now }, authorizer, nil)
	if err != nil {
		t.Fatal(err)
	}
	var tenantID, roleID, grantID, grantManagerID uuid.UUID
	var roleRevision int64
	if err := fixture.pool.QueryRow(t.Context(), `
		SELECT scope.tenant_id,role.id,role.current_revision,grant_row.id,grant_row.granted_by_user_id
		FROM access_scopes scope
		JOIN custom_role_grants grant_row
		  ON grant_row.tenant_scope_id=scope.id AND grant_row.subject_user_id=$2
		JOIN custom_roles role
		  ON role.id=grant_row.role_id AND role.tenant_scope_id=scope.id AND role.deactivated_at IS NULL
		JOIN custom_role_revisions revision
		  ON revision.role_id=role.id AND revision.revision=role.current_revision
		WHERE scope.id=$1 AND $3=ANY(revision.permissions) AND $4=ANY(revision.permissions)
		  AND NOT EXISTS (
			SELECT 1 FROM custom_role_grant_revocations revoked WHERE revoked.grant_id=grant_row.id
		  )`, fixture.actor.ScopeID, fixture.actor.UserID, permissionManage, permissionRead).Scan(
		&tenantID, &roleID, &roleRevision, &grantID, &grantManagerID); err != nil {
		t.Fatal(err)
	}
	sessionID := uuid.New()
	rawSession := seedIAMSession(t, fixture, tokens, sessionID, now)
	rawAPIKey, apiKeyID := seedIAMAPIKey(t, fixture, pepper, now)
	sessionActor := Actor{UserID: fixture.actor.UserID, ScopeID: fixture.actor.ScopeID, ScopeKind: "tenant",
		TargetScopeID: fixture.actor.ScopeID, Credential: Credential{Kind: CredentialSession, Raw: rawSession}}
	apiKeyActor := Actor{UserID: fixture.actor.UserID, ScopeID: fixture.actor.ScopeID, ScopeKind: "tenant",
		TargetScopeID: fixture.actor.ScopeID, Credential: Credential{Kind: CredentialAPIKey, Raw: rawAPIKey}}
	tenantSessionGroupID := uuid.New()
	if _, err := service.PutGroup(t.Context(), sessionActor,
		fixture.putRequest(tenantSessionGroupID, 0, "iam-session", "iam-session")); err != nil {
		t.Fatalf("session write=%v", err)
	}
	if _, err := service.PutGroup(t.Context(), apiKeyActor,
		fixture.putRequest(uuid.New(), 0, "iam-api-key", "iam-api-key")); err != nil {
		t.Fatalf("API key write=%v", err)
	}

	revokeTx, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := protocol.BeginAuthorityMutation(t.Context(), revokeTx, protocol.OperationSessionRevoke,
		[]uuid.UUID{fixture.actor.ScopeID}); err != nil {
		t.Fatal(err)
	}
	if _, err := revokeTx.Exec(t.Context(), `UPDATE auth_sessions SET revoked_at=$2,revocation_reason='test'
		WHERE id=$1`, sessionID, now); err != nil {
		t.Fatal(err)
	}
	blocked := make(chan error, 1)
	blockedGroupID := uuid.New()
	go func() {
		_, err := service.PutGroup(context.Background(), sessionActor,
			fixture.putRequest(blockedGroupID, 0, "iam-linearized", "iam-linearized"))
		blocked <- err
	}()
	select {
	case err := <-blocked:
		t.Fatalf("write did not serialize behind revocation: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := revokeTx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-blocked; !errors.Is(err, ErrCredentialInvalid) {
		t.Fatalf("revoked session write=%v", err)
	}
	var blockedFacts int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM node_line_groups WHERE id=$1`, blockedGroupID).Scan(&blockedFacts); err != nil || blockedFacts != 0 {
		t.Fatalf("blocked facts=%d err=%v", blockedFacts, err)
	}

	if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		if _, err := protocol.BeginAuthorityMutation(t.Context(), tx, protocol.OperationAPIKeySelfRevoke,
			[]uuid.UUID{fixture.actor.ScopeID}); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `UPDATE api_keys SET status='revoked',revoked_at=$2,
			revoked_by_user_id=$3,revision=revision+1,updated_at=$2 WHERE id=$1`, apiKeyID, now, fixture.actor.UserID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.PutGroup(t.Context(), apiKeyActor,
		fixture.putRequest(uuid.New(), 0, "iam-api-revoked", "iam-api-revoked")); !errors.Is(err, ErrCredentialInvalid) {
		t.Fatalf("revoked API key write=%v", err)
	}

	freshSessionID := uuid.New()
	freshSession := seedIAMSession(t, fixture, tokens, freshSessionID, now)
	freshActor := sessionActor
	freshActor.Credential.Raw = freshSession
	if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		if _, err := protocol.BeginAuthorityMutation(t.Context(), tx, protocol.OperationCustomRoleRevoke,
			[]uuid.UUID{fixture.actor.ScopeID}); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO custom_role_grant_revocations (
			id,grant_id,tenant_id,tenant_scope_id,role_id,role_revision,subject_user_id,
			revoked_by_user_id,revoked_by_scope_id,revoked_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$4,$9)`, uuid.New(), grantID, tenantID,
			fixture.actor.ScopeID, roleID, roleRevision, fixture.actor.UserID, grantManagerID, now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var revocationFacts, projectedAssignments int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM custom_role_grant_revocations WHERE grant_id=$1),
		(SELECT count(*) FROM role_assignments WHERE scope_id=$2 AND user_id=$3 AND role_id=$4)`,
		grantID, fixture.actor.ScopeID, fixture.actor.UserID, roleID).Scan(
		&revocationFacts, &projectedAssignments); err != nil {
		t.Fatal(err)
	}
	if revocationFacts != 1 || projectedAssignments != 0 {
		t.Fatalf("custom RBAC revocation facts=%d projected assignments=%d", revocationFacts, projectedAssignments)
	}
	if _, err := service.List(t.Context(), freshActor); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("RBAC-revoked read=%v", err)
	}

	platformTenantActor := seedPlatformIAMSession(t, fixture, tokens, now)
	tenantGroups, err := service.List(t.Context(), platformTenantActor)
	if err != nil || len(tenantGroups) < 2 {
		t.Fatalf("platform tenant-target read groups=%d err=%v", len(tenantGroups), err)
	}
	if tenantGroup, err := service.GetCurrent(t.Context(), platformTenantActor, tenantSessionGroupID); err != nil || tenantGroup.TenantScopeID != fixture.actor.ScopeID || tenantGroup.GroupID != tenantSessionGroupID {
		t.Fatalf("platform tenant-target current=%#v err=%v", tenantGroup, err)
	}
	if _, err := service.PutGroup(t.Context(), platformTenantActor,
		fixture.putRequest(uuid.New(), 0, "platform-tenant-write", "platform-tenant-write")); !errors.Is(err, ErrPlatformWriteDenied) {
		t.Fatalf("platform tenant-target write=%v", err)
	}
	if _, err := service.DeleteGroup(t.Context(), platformTenantActor, tenantSessionGroupID, 1,
		"platform-tenant-delete", "platform-tenant-delete-request"); !errors.Is(err, ErrPlatformWriteDenied) {
		t.Fatalf("platform tenant-target delete=%v", err)
	}

	platformActor := platformTenantActor
	platformActor.TargetScopeID = platformActor.ScopeID
	platformGroupID := uuid.New()
	created, err := service.PutGroup(t.Context(), platformActor,
		fixture.putRequest(platformGroupID, 0, "platform-own", "platform-own-create"))
	if err != nil || created.Group.TenantScopeID != platformActor.ScopeID || created.Group.Revision != 1 {
		t.Fatalf("platform own create=%#v err=%v", created, err)
	}
	ownGroups, err := service.List(t.Context(), platformActor)
	if err != nil || len(ownGroups) != 1 || ownGroups[0].GroupID != platformGroupID {
		t.Fatalf("platform own list=%#v err=%v", ownGroups, err)
	}
	if current, err := service.GetCurrent(t.Context(), platformActor, platformGroupID); err != nil || current.Revision != 1 || current.TenantScopeID != platformActor.ScopeID {
		t.Fatalf("platform own current=%#v err=%v", current, err)
	}
	if revision, err := service.GetRevision(t.Context(), platformActor, platformGroupID, 1); err != nil || revision.Revision != 1 || revision.GroupID != platformGroupID {
		t.Fatalf("platform own revision=%#v err=%v", revision, err)
	}
	update := fixture.putRequest(platformGroupID, 1, "platform-own-updated", "platform-own-update")
	updated, err := service.PutGroup(t.Context(), platformActor, update)
	if err != nil || updated.Group.Revision != 2 || updated.Group.Name != update.Name {
		t.Fatalf("platform own update=%#v err=%v", updated, err)
	}
	rolled, err := service.Rollback(t.Context(), platformActor, platformGroupID, 1, 2,
		"platform-own-rollback", "platform-own-rollback-request")
	if err != nil || rolled.Group.Revision != 3 || rolled.Group.Name != created.Group.Name {
		t.Fatalf("platform own rollback=%#v err=%v", rolled, err)
	}
	deleted, err := service.DeleteGroup(t.Context(), platformActor, platformGroupID, 3,
		"platform-own-delete", "platform-own-delete-request")
	if err != nil || deleted.Replayed || deleted.ScopeID != platformActor.ScopeID || deleted.Revision != 3 {
		t.Fatalf("platform own delete=%#v err=%v", deleted, err)
	}
	replayedDelete, err := service.DeleteGroup(t.Context(), platformActor, platformGroupID, 3,
		"platform-own-delete", "platform-own-delete-request")
	if err != nil || !replayedDelete.Replayed || replayedDelete.DeletedAt != deleted.DeletedAt {
		t.Fatalf("platform own delete replay=%#v err=%v", replayedDelete, err)
	}
	if _, err := service.DeleteGroup(t.Context(), platformActor, platformGroupID, 3,
		"platform-own-delete-new-key", "platform-own-delete-new-request"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("platform own repeated delete with new key=%v", err)
	}
	if groups, err := service.List(t.Context(), platformActor); err != nil || len(groups) != 0 {
		t.Fatalf("platform own list after delete=%#v err=%v", groups, err)
	}
	if _, err := service.GetCurrent(t.Context(), platformActor, platformGroupID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("platform own current after delete=%v", err)
	}
	if _, err := service.GetRevision(t.Context(), platformActor, platformGroupID, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("platform own history after delete=%v", err)
	}
	if _, err := service.RecordProbe(t.Context(), ProbeRequest{
		TenantScopeID: platformActor.ScopeID, GroupID: platformGroupID, Revision: 3,
		EndpointID: rolled.Group.Endpoints[0].ID, Sequence: 1, ObservedAt: now, Healthy: true,
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("platform own probe after delete=%v", err)
	}
	if _, err := service.CreateTargetSnapshotForNodes(t.Context(), platformActor, platformGroupID, 3,
		[]uuid.UUID{uuid.New()}, "platform-own-snapshot-after-delete", "platform-own-snapshot-after-delete-request"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("platform own topology snapshot after delete=%v", err)
	}
	var deletedBy uuid.UUID
	var deletedAt time.Time
	var currentRevision int64
	var revisionCount, deleteReceiptCount, deleteAuditCount int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT deleted_by_user_id,deleted_at,current_revision,
		(SELECT count(*) FROM node_line_group_revisions WHERE tenant_scope_id=$1 AND line_group_id=$2),
		(SELECT count(*) FROM node_scheduling_write_requests
		 WHERE tenant_scope_id=$1 AND actor_user_id=$3 AND operation='node_scheduling.group.delete'
		   AND target_group_id=$2 AND completed_at IS NOT NULL),
		(SELECT count(*) FROM audit_events
		 WHERE scope_id=$1 AND actor_user_id=$3 AND action='node_scheduling.group.delete' AND resource_id=$2::text)
		FROM node_line_groups WHERE tenant_scope_id=$1 AND id=$2`,
		platformActor.ScopeID, platformGroupID, platformActor.UserID).Scan(
		&deletedBy, &deletedAt, &currentRevision, &revisionCount, &deleteReceiptCount, &deleteAuditCount); err != nil {
		t.Fatal(err)
	}
	if deletedBy != platformActor.UserID || !deletedAt.Equal(deleted.DeletedAt) || currentRevision != 3 ||
		revisionCount != 3 || deleteReceiptCount != 1 || deleteAuditCount != 1 {
		t.Fatalf("platform delete facts actor=%s at=%s current=%d revisions=%d receipts=%d audits=%d",
			deletedBy, deletedAt, currentRevision, revisionCount, deleteReceiptCount, deleteAuditCount)
	}

	platformKey := platformActor
	platformKey.Credential = Credential{Kind: CredentialAPIKey, Raw: rawAPIKey}
	if _, err := service.List(t.Context(), platformKey); !errors.Is(err, ErrCredentialInvalid) {
		t.Fatalf("platform API key read=%v", err)
	}
}

func seedIAMSession(t *testing.T, fixture *integrationFixture, tokens *identity.TokenManager, sessionID uuid.UUID, now time.Time) string {
	t.Helper()
	refresh := sha256.Sum256([]byte(sessionID.String()))
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO auth_sessions(
		id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7)`, sessionID, uuid.New(), fixture.actor.UserID,
		fixture.actor.ScopeID, refresh[:], now.Add(-time.Hour), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	raw, _, err := tokens.Mint(fixture.actor.UserID, fixture.actor.ScopeID, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func seedIAMAPIKey(t *testing.T, fixture *integrationFixture, pepper []byte, now time.Time) (string, uuid.UUID) {
	t.Helper()
	keyIDBytes := uuid.New()
	keyID := "cfk_" + base64.RawURLEncoding.EncodeToString(keyIDBytes[:])
	secretBytes := sha256.Sum256([]byte("node-scheduling-" + keyID))
	secret := base64.RawURLEncoding.EncodeToString(secretBytes[:])
	mac := hmac.New(sha256.New, pepper)
	_, _ = mac.Write([]byte("cdnca-control-api/api-key/digest/v1\x00"))
	_, _ = mac.Write([]byte(keyID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(secret))
	var tenantID uuid.UUID
	if err := fixture.pool.QueryRow(t.Context(), `SELECT tenant_id FROM access_scopes WHERE id=$1`, fixture.actor.ScopeID).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO api_keys(
		id,key_id,key_prefix,scope_id,tenant_id,user_id,name,scopes,secret_digest,pepper_version,status,
		expires_at,activated_at,created_by_user_id,revision,created_at,updated_at)
		VALUES($1,$2,$2||'.',$3,$4,$5,'node scheduling IAM key',$6,$7,'legacy-v1','active',$8,$9,$5,1,$9,$9)`,
		id, keyID, fixture.actor.ScopeID, tenantID, fixture.actor.UserID,
		[]string{permissionManage, permissionRead}, mac.Sum(nil), now.Add(time.Hour), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	return keyID + "." + secret, id
}

func seedPlatformIAMSession(t *testing.T, fixture *integrationFixture, tokens *identity.TokenManager, now time.Time) Actor {
	t.Helper()
	scopeID, userID, roleID, sessionID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	refresh := sha256.Sum256([]byte(sessionID.String()))
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind) VALUES($1,'platform');
		INSERT INTO users(id,username,display_name,password_hash,created_at,updated_at)
		VALUES($2,$3,'Node scheduling platform','unused',$6,$6);
		INSERT INTO memberships(scope_id,user_id,created_at) VALUES($1,$2,$6);
		INSERT INTO roles(id,scope_id,name,description,system_role,created_at)
		VALUES($4,$1,'platform_owner','Node scheduling platform role',true,$6);
		INSERT INTO role_permissions(role_id,permission_name) VALUES($4,'platform.admin') ON CONFLICT DO NOTHING;
		INSERT INTO role_assignments(scope_id,user_id,role_id,assigned_at) VALUES($1,$2,$4,$6);
		INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
		VALUES($5,$7,$2,$1,$8,$6,$9)`, pgx.QueryExecModeSimpleProtocol,
		scopeID, userID, "node-platform-"+userID.String(), roleID, sessionID, now.Add(-time.Hour),
		uuid.New(), refresh[:], now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	raw, _, err := tokens.Mint(userID, scopeID, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	return Actor{UserID: userID, ScopeID: scopeID, ScopeKind: "platform", TargetScopeID: fixture.actor.ScopeID,
		Credential: Credential{Kind: CredentialSession, Raw: raw}}
}

// seedSchedulerNodeSQL inserts an active node ($1 id, $2 scope, $3 name, $4
// creator) with a display ID from the per-scope sequence, as node.Store
// allocates it (NOT NULL since migration 211).
const seedSchedulerNodeSQL = `WITH display AS (
		INSERT INTO node_display_id_sequences(scope_id,next_value,updated_at) VALUES($2,2,now())
		ON CONFLICT(scope_id) DO UPDATE SET next_value=node_display_id_sequences.next_value+1,
			updated_at=EXCLUDED.updated_at
		RETURNING next_value-1 AS display_id
	)
	INSERT INTO nodes(id,display_id,scope_id,name,admin_state,created_by_user_id)
	SELECT $1,display.display_id,$2,$3,'active',$4 FROM display`

// ownEndpointAddresses gives each node-bound endpoint's node that address
// (primary IPv4/IPv6, else 副IP): fd67f0fad 起端点地址必须属于所绑节点。
func ownEndpointAddresses(t *testing.T, fixture *integrationFixture, endpoints []Endpoint) {
	t.Helper()
	for _, endpoint := range endpoints {
		if endpoint.NodeID == uuid.Nil {
			continue
		}
		if _, err := fixture.pool.Exec(t.Context(), `UPDATE nodes SET
			ipv4=CASE WHEN family($2::inet)=4 AND ipv4 IS NULL THEN $2::inet ELSE ipv4 END,
			ipv6=CASE WHEN family($2::inet)=6 AND ipv6 IS NULL THEN $2::inet ELSE ipv6 END,
			management_settings=CASE WHEN (family($2::inet)=4 AND ipv4 IS NOT NULL AND ipv4<>$2::inet)
				OR (family($2::inet)=6 AND ipv6 IS NOT NULL AND ipv6<>$2::inet)
				THEN jsonb_set(management_settings,'{secondary_ips}',
					COALESCE(management_settings->'secondary_ips','[]'::jsonb)||jsonb_build_array(host($2::inet)))
				ELSE management_settings END
			WHERE id=$1`, endpoint.NodeID, endpoint.Address); err != nil {
			t.Fatal(err)
		}
	}
}

// seedSchedulerActiveNode writes an active node with a per-scope display ID
// and an active mTLS certificate: a target snapshot binds each L1/L2 node to
// its current certificate digest.
func seedSchedulerActiveNode(t *testing.T, fixture *integrationFixture, nodeID uuid.UUID, name string) {
	t.Helper()
	if _, err := fixture.pool.Exec(t.Context(), seedSchedulerNodeSQL, nodeID, fixture.actor.ScopeID,
		name, fixture.actor.UserID); err != nil {
		t.Fatal(err)
	}
	now := fixture.clock.Now()
	tokenID, authorizationID, certificateID := uuid.New(), uuid.New(), uuid.New()
	digest := sha256.Sum256([]byte(nodeID.String()))
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO node_enrollment_tokens(id,node_id,purpose,token_hash,created_by_user_id,created_at,expires_at)
		 VALUES($1,$2,'initial_enrollment',$3,$4,$5,$6)`, []any{tokenID, nodeID, digest[:], fixture.actor.UserID, now.Add(-time.Minute), now.Add(time.Hour)}},
		{`INSERT INTO node_enrollment_authorizations(id,token_id,node_id,purpose,request_id,request_digest,authorized_at)
		 VALUES($1,$2,$3,'initial_enrollment',$4,$5,$6)`, []any{authorizationID, tokenID, nodeID, authorizationID.String(), digest[:], now.Add(-time.Minute)}},
		{`INSERT INTO node_identity_authorizations(id,token_id,node_id,purpose,request_id,request_digest,token_hash,
		 csr_der,csr_sha256,machine_fingerprint_sha256,protocol_min_major,protocol_min_minor,protocol_max_major,
		 protocol_max_minor,selected_protocol_major,selected_protocol_minor,capabilities_snapshot,capabilities_sha256,
		 gateway_workload_identity,gateway_instance_id,artifact_key_id,artifact_public_key,status,authorized_at,expires_at)
		 VALUES($1,$2,$3,'initial_enrollment',$1,$4,$4,'test',$4,$4,1,0,1,0,1,0,'{}',$4,
		 'spiffe://cdn-platform/gateway/test','test','test-key',$4,'authorized',$5,$6)`,
			[]any{authorizationID, tokenID, nodeID, digest[:], now.Add(-time.Minute), now.Add(time.Hour)}},
		{`INSERT INTO node_certificates(id,node_id,issuance_kind,enrollment_authorization_id,serial_number,
		 csr_sha256,certificate_public_key_sha256,uri_san,not_before,not_after,renewal_at,leaf_certificate_pem,
		 issuing_chain_pem,leaf_certificate_sha256,status,issued_at)
		 VALUES($1,$2,'initial',$3,$4,$5,$5,$6,$7,$8,$9,'test',ARRAY['test'::bytea],$5,'active',$7)`,
			[]any{certificateID, nodeID, authorizationID, strings.ReplaceAll(certificateID.String(), "-", ""), digest[:],
				"spiffe://cdn-platform/node/" + nodeID.String(), now.Add(-time.Minute), now.Add(time.Hour), now.Add(30 * time.Minute)}},
	} {
		if _, err := fixture.pool.Exec(t.Context(), statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
}
