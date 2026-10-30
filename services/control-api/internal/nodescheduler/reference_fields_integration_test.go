//go:build integration

package nodescheduler

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestLineGroupReferenceFieldsCRUDRollbackAndConflicts(t *testing.T) {
	fixture := newIntegrationFixture(t)
	ctx := t.Context()

	// 迁移 504 起线路组的 L2 配置指向 L2 拓扑配置（l2_topology_configs），不再是另一条线路组。
	putL2 := func(actor Actor, name, region, key string) L2Config {
		t.Helper()
		written, err := fixture.service.PutL2Config(ctx, actor, L2ConfigWriteRequest{
			Name: name, Region: region, Mode: L2ModeCache, LoadMethod: L2LoadRoundRobin,
			IdempotencyKey: key, RequestID: key + "-request",
		})
		if err != nil {
			t.Fatalf("create L2 config %s: %v", name, err)
		}
		return written.Config
	}
	l2 := putL2(fixture.actor, "华东 L2", "华东", "reference-l2-create")
	l2GroupID := l2.ID

	primaryID := uuid.New()
	primaryRequest := fixture.putRequest(primaryID, 0, "华东主线路", "reference-primary-create")
	primaryRequest.Region = "华东"
	primaryRequest.IPv4ResolvedValue = "v4-east-primary"
	primaryRequest.L2ConfigID = &l2GroupID
	primaryRequest.FailoverMode = FailoverOnlineLessThanBackupCount
	created, err := fixture.service.PutGroup(ctx, fixture.actor, primaryRequest)
	if err != nil || created.Group.IPv4ResolvedValue != "v4-east-primary" ||
		created.Group.L2ConfigID == nil || *created.Group.L2ConfigID != l2GroupID ||
		created.Group.FailoverMode != FailoverOnlineLessThanBackupCount {
		t.Fatalf("create reference fields=%#v err=%v", created, err)
	}

	update := fixture.putRequest(primaryID, 1, "华东主线路更新", "reference-primary-update")
	update.Region = "华东"
	update.IPv4ResolvedValue = "v4-east-primary-updated"
	update.L2ConfigID = &l2GroupID
	update.FailoverMode = FailoverOnlineLessThanBackupCount
	updated, err := fixture.service.PutGroup(ctx, fixture.actor, update)
	if err != nil || updated.Group.Revision != 2 ||
		updated.Group.IPv4ResolvedValue != update.IPv4ResolvedValue ||
		updated.Group.FailoverMode != FailoverOnlineLessThanBackupCount {
		t.Fatalf("update reference fields=%#v err=%v", updated, err)
	}

	historical, err := fixture.service.GetRevision(ctx, fixture.actor, primaryID, 1)
	if err != nil || historical.IPv4ResolvedValue != primaryRequest.IPv4ResolvedValue ||
		historical.L2ConfigID == nil || *historical.L2ConfigID != l2GroupID ||
		historical.FailoverMode != FailoverOnlineLessThanBackupCount {
		t.Fatalf("historical reference fields=%#v err=%v", historical, err)
	}
	rolled, err := fixture.service.Rollback(ctx, fixture.actor, primaryID, 1, 2,
		"reference-primary-rollback", "reference-primary-rollback-request")
	if err != nil || rolled.Group.Revision != 3 ||
		rolled.Group.IPv4ResolvedValue != primaryRequest.IPv4ResolvedValue ||
		rolled.Group.L2ConfigID == nil || *rolled.Group.L2ConfigID != l2GroupID ||
		rolled.Group.FailoverMode != FailoverOnlineLessThanBackupCount {
		t.Fatalf("rollback reference fields=%#v err=%v", rolled, err)
	}
	groups, err := fixture.service.List(ctx, fixture.actor)
	if err != nil {
		t.Fatal(err)
	}
	var listed *LineGroupRevision
	for index := range groups {
		if groups[index].GroupID == primaryID {
			listed = &groups[index]
			break
		}
	}
	if listed == nil || listed.Revision != 3 || listed.L2ConfigID == nil || *listed.L2ConfigID != l2GroupID ||
		listed.IPv4ResolvedValue != primaryRequest.IPv4ResolvedValue || listed.FailoverMode != FailoverOnlineLessThanBackupCount {
		t.Fatalf("listed reference fields=%#v", listed)
	}

	moveTarget := L2ConfigWriteRequest{ConfigID: l2.ID, ExpectedRevision: l2.Revision, Name: l2.Name,
		Region: "华北", Mode: L2ModeCache, LoadMethod: L2LoadRoundRobin,
		IdempotencyKey: "reference-l2-move", RequestID: "reference-l2-move-request"}
	if _, err := fixture.service.PutL2Config(ctx, fixture.actor, moveTarget); !errors.Is(err, ErrReferenceConflict) {
		t.Fatalf("move referenced target error=%v", err)
	}
	if _, err := fixture.service.DeleteL2Config(ctx, fixture.actor, l2.ID, l2.Revision,
		"reference-l2-delete", "reference-l2-delete-request"); !errors.Is(err, ErrReferenceConflict) {
		t.Fatalf("delete referenced target error=%v", err)
	}
	leafID := putL2(fixture.actor, "华南 L2", "华南", "reference-leaf-create").ID

	invalidReference := func(name, key, region string, target uuid.UUID) error {
		request := fixture.putRequest(uuid.New(), 0, name, key)
		request.Region = region
		request.L2ConfigID = &target
		_, err := fixture.service.PutGroup(ctx, fixture.actor, request)
		return err
	}
	if err := invalidReference("缺失 L2", "reference-missing", "华东", uuid.New()); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("missing reference error=%v", err)
	}
	if err := invalidReference("区域不一致 L2", "reference-region-mismatch", "华北", leafID); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("region mismatch error=%v", err)
	}

	otherActor := seedTenantActor(t, fixture.pool, "reference-other-tenant")
	otherTargetID := putL2(otherActor, "其他租户 L2", "华东", "reference-other-target").ID
	if err := invalidReference("跨租户 L2", "reference-cross-scope", "华东", otherTargetID); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("cross-scope reference error=%v", err)
	}

	deletedTarget := putL2(fixture.actor, "已删除 L2", "华东", "reference-deleted-target")
	deletedTargetID := deletedTarget.ID
	if _, err := fixture.service.DeleteL2Config(ctx, fixture.actor, deletedTargetID, deletedTarget.Revision,
		"reference-deleted-target-delete", "reference-deleted-target-delete-request"); err != nil {
		t.Fatal(err)
	}
	if err := invalidReference("引用已删除 L2", "reference-deleted", "华东", deletedTargetID); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("deleted reference error=%v", err)
	}

	// 另一条线路组不是 L2 配置（504 前的旧语义），按缺失引用拒绝。
	if err := invalidReference("引用线路组", "reference-line-group", "华东", primaryID); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("line group as L2 reference error=%v", err)
	}
	selfID := uuid.New()
	selfRequest := fixture.putRequest(selfID, 0, "自引用 L2", "reference-self")
	selfRequest.Region = "华东"
	selfRequest.L2ConfigID = &selfID
	if _, err := fixture.service.PutGroup(ctx, fixture.actor, selfRequest); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("self reference error=%v", err)
	}

	duplicateIPv4 := fixture.putRequest(uuid.New(), 0, "重复 IPv4 解析值", "reference-duplicate-ipv4")
	duplicateIPv4.IPv4ResolvedValue = primaryRequest.IPv4ResolvedValue
	if _, err := fixture.service.PutGroup(ctx, fixture.actor, duplicateIPv4); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("duplicate IPv4 resolved value error=%v", err)
	}

	var auditCount int
	if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FROM audit_events
		WHERE scope_id=$1 AND action='node_scheduling.group.create' AND resource_id=$2
		  AND payload->>'ipv4_resolved_value'='v4-east-primary'
		  AND payload->>'l2_config_id'=$3 AND payload->>'failover_mode'='online_less_than_backup_count'`,
		fixture.actor.ScopeID, primaryID.String(), l2GroupID.String()).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("reference-field create audit count=%d", auditCount)
	}
}

func TestLineGroupReferenceFieldsReplayLegacy233Receipt(t *testing.T) {
	pool := openNodeSchedulingDatabase(t, false)
	// Build the historical fixture forward: later migrations intentionally refuse
	// rollback. Record a verified ledger row only after each real script succeeds.
	if _, err := pool.Exec(t.Context(), `CREATE TABLE schema_migrations (
		version bigint PRIMARY KEY, migration_id text, checksum_sha256 text,
		down_checksum_sha256 text, integrity_state text, metadata_recorded_at timestamptz,
		applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	names, err := fs.Glob(migrations.FS, "*.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		version, err := strconv.Atoi(name[:3])
		if err != nil {
			t.Fatal(err)
		}
		if version > 233 {
			break
		}
		identifier := strings.TrimSuffix(name, ".up.sql")
		up, err := migrations.FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		down, err := migrations.FS.ReadFile(identifier + ".down.sql")
		if err != nil {
			t.Fatal(err)
		}
		if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(t.Context(), string(up)); err != nil {
				return err
			}
			_, err := tx.Exec(t.Context(), `INSERT INTO schema_migrations
				(version,migration_id,checksum_sha256,down_checksum_sha256,integrity_state,metadata_recorded_at)
				VALUES($1,$2,$3,$4,'verified',now())`, version, identifier,
				fmt.Sprintf("%x", sha256.Sum256(up)), fmt.Sprintf("%x", sha256.Sum256(down)))
			return err
		}); err != nil {
			t.Fatalf("apply historical fixture migration %d: %v", version, err)
		}
	}
	actor := seedTenantActor(t, pool, "reference-legacy-replay")
	clock := &integrationClock{value: integrationBaseTime}
	groupID := uuid.New()
	request := PutGroupRequest{
		GroupID: groupID, Name: "旧版幂等线路", IdempotencyKey: "reference-legacy-replay",
		RequestID: "reference-legacy-replay-request",
	}
	normalized, err := normalizePutRequest(request)
	if err != nil || !normalized.v233ReplayEligible {
		t.Fatalf("normalize legacy request=%#v err=%v", normalized, err)
	}
	seedLineGroup233Receipt(t, pool, actor, normalized)

	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatalf("reapply migration 234: %v", err)
	}
	result, err := NewService(pool, clock.Now).PutGroup(t.Context(), actor, request)
	if err != nil || !result.Replayed || result.Group.GroupID != groupID || result.Group.Revision != 1 ||
		result.Group.IPv4ResolvedValue != defaultIPv4ResolvedValue(groupID) || result.Group.L2ConfigID != nil ||
		result.Group.FailoverMode != FailoverPrimaryOffline {
		t.Fatalf("legacy 233 replay=%#v err=%v", result, err)
	}
	var receipts, groups, revisions int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM node_scheduling_write_requests
		 WHERE tenant_scope_id=$1 AND actor_user_id=$2 AND operation='node_scheduling.group.create'
		   AND idempotency_key='reference-legacy-replay'),
		(SELECT count(*) FROM node_line_groups WHERE tenant_scope_id=$1 AND id=$3),
		(SELECT count(*) FROM node_line_group_revisions WHERE tenant_scope_id=$1 AND line_group_id=$3)`,
		actor.ScopeID, actor.UserID, groupID).Scan(&receipts, &groups, &revisions); err != nil {
		t.Fatal(err)
	}
	if receipts != 1 || groups != 1 || revisions != 1 {
		t.Fatalf("legacy replay facts receipts=%d groups=%d revisions=%d", receipts, groups, revisions)
	}
}

func seedLineGroup233Receipt(t *testing.T, pool *pgxpool.Pool, actor Actor, input normalizedPut) {
	t.Helper()
	resolvedValue := input.resolvedValue
	if resolvedValue == "" {
		resolvedValue = defaultResolvedValue(input.groupID)
	}
	encodedConfiguration, err := json.Marshal(v233CanonicalConfiguration{
		Name: input.name, Region: input.region, ResolvedValue: resolvedValue, Note: input.note,
		SortOrder: input.sortOrder, Policy: canonicalizePolicy(input.policy),
		Endpoints: canonicalizeLegacyEndpoints(input.endpoints),
	})
	if err != nil {
		t.Fatal(err)
	}
	configurationDigest := sha256.Sum256(encodedConfiguration)
	now := integrationBaseTime
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO node_line_groups(
			id,tenant_scope_id,name,region,resolved_value,note,sort_order,current_revision,
			created_by_user_id,updated_by_user_id,created_at,updated_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,1,$8,$8,$9,$9)`,
			input.groupID, actor.ScopeID, input.name, input.region, resolvedValue, input.note,
			input.sortOrder, actor.UserID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO node_line_group_revisions(
			line_group_id,tenant_scope_id,revision,name,region,resolved_value,note,sort_order,
			probe_interval_ms,probe_timeout_ms,failure_threshold,recovery_threshold,
			failure_debounce_ms,recovery_debounce_ms,endpoint_count,configuration_digest,
			created_by_user_id,created_at)
			VALUES($1,$2,1,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,0,$14,$15,$16)`,
			input.groupID, actor.ScopeID, input.name, input.region, resolvedValue, input.note,
			input.sortOrder, input.policy.ProbeInterval.Milliseconds(), input.policy.ProbeTimeout.Milliseconds(),
			input.policy.FailureThreshold, input.policy.RecoveryThreshold,
			input.policy.FailureDebounce.Milliseconds(), input.policy.RecoveryDebounce.Milliseconds(),
			configurationDigest[:], actor.UserID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `UPDATE node_line_group_revisions SET sealed_at=$4
			WHERE tenant_scope_id=$1 AND line_group_id=$2 AND revision=$3`,
			actor.ScopeID, input.groupID, int64(1), now); err != nil {
			return err
		}
		var displayID string
		if err := tx.QueryRow(t.Context(), `SELECT display_id::text FROM node_line_groups
			WHERE tenant_scope_id=$1 AND id=$2`, actor.ScopeID, input.groupID).Scan(&displayID); err != nil {
			return err
		}
		legacy := WriteResult{Group: LineGroupRevision{
			GroupID: input.groupID, DisplayID: displayID, TenantScopeID: actor.ScopeID, Revision: 1,
			Name: input.name, Region: input.region, ResolvedValue: resolvedValue, Note: input.note,
			SortOrder: input.sortOrder, Policy: input.policy, Endpoints: []Endpoint{},
			ConfigurationDigest: configurationDigest[:], CreatedByUserID: actor.UserID,
			CreatedAt: now, SealedAt: now,
		}}
		encodedResponse, err := json.Marshal(legacy)
		if err != nil {
			return err
		}
		var legacyResponse map[string]any
		if err := json.Unmarshal(encodedResponse, &legacyResponse); err != nil {
			return err
		}
		group := legacyResponse["group"].(map[string]any)
		delete(group, "ipv4_resolved_value")
		delete(group, "l2_config_id")
		delete(group, "failover_mode")
		encodedResponse, err = json.Marshal(legacyResponse)
		if err != nil {
			return err
		}
		writeID := uuid.New()
		if _, err := tx.Exec(t.Context(), `INSERT INTO node_scheduling_write_requests(
			id,tenant_scope_id,actor_user_id,operation,idempotency_key,request_digest,target_group_id,created_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, writeID, actor.ScopeID, actor.UserID,
			operationGroupCreate, input.idempotencyKey, input.v233RequestDigest[:], input.groupID, now); err != nil {
			return err
		}
		_, err = tx.Exec(t.Context(), `UPDATE node_scheduling_write_requests
			SET response_body=$2::jsonb,completed_at=$3 WHERE id=$1`, writeID, string(encodedResponse), now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestLineGroupReferenceCreateDeleteRacePreservesInvariant(t *testing.T) {
	fixture := newIntegrationFixture(t)
	targetID := uuid.New()
	targetRequest := fixture.putRequest(targetID, 0, "并发 L2", "reference-race-target")
	targetRequest.Region = "华东"
	if _, err := fixture.service.PutGroup(t.Context(), fixture.actor, targetRequest); err != nil {
		t.Fatal(err)
	}

	blocker, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	lockKey := "node-scheduling-line-group-reference:" + fixture.actor.ScopeID.String()
	if _, err := blocker.Exec(t.Context(), `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, lockKey); err != nil {
		_ = blocker.Rollback(t.Context())
		t.Fatal(err)
	}

	consumerID := uuid.New()
	consumerRequest := fixture.putRequest(consumerID, 0, "并发引用", "reference-race-consumer")
	consumerRequest.Region = "华东"
	consumerRequest.L2ConfigID = &targetID
	type createOutcome struct {
		result WriteResult
		err    error
	}
	createDone := make(chan createOutcome, 1)
	deleteDone := make(chan error, 1)
	go func() {
		result, err := fixture.service.PutGroup(t.Context(), fixture.actor, consumerRequest)
		createDone <- createOutcome{result: result, err: err}
	}()
	go func() {
		_, err := fixture.service.DeleteGroup(t.Context(), fixture.actor, targetID, 1,
			"reference-race-delete", "reference-race-delete-request")
		deleteDone <- err
	}()

	if err := blocker.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	created := <-createDone
	deletedErr := <-deleteDone

	switch {
	case created.err == nil:
		if !errors.Is(deletedErr, ErrReferenceConflict) || created.result.Group.L2ConfigID == nil ||
			*created.result.Group.L2ConfigID != targetID {
			t.Fatalf("create-won outcome created=%#v delete=%v", created, deletedErr)
		}
	case deletedErr == nil:
		if !errors.Is(created.err, ErrInvalidInput) {
			t.Fatalf("delete-won outcome created=%v delete=%v", created.err, deletedErr)
		}
	default:
		t.Fatalf("race produced no successful operation: create=%v delete=%v", created.err, deletedErr)
	}

	var targetActive bool
	var activeReferences int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT
		EXISTS(SELECT 1 FROM node_line_groups WHERE tenant_scope_id=$1 AND id=$2 AND deleted_at IS NULL),
		(SELECT count(*) FROM node_line_groups
		 WHERE tenant_scope_id=$1 AND l2_config_id=$2 AND deleted_at IS NULL)`,
		fixture.actor.ScopeID, targetID).Scan(&targetActive, &activeReferences); err != nil {
		t.Fatal(err)
	}
	if activeReferences > 0 && !targetActive {
		t.Fatalf("invalid final state target_active=%v active_references=%d", targetActive, activeReferences)
	}
}
