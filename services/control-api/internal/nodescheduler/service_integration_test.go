//go:build integration

package nodescheduler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var integrationBaseTime = time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)

type integrationClock struct {
	mu    sync.RWMutex
	value time.Time
}

func (clock *integrationClock) Now() time.Time {
	clock.mu.RLock()
	defer clock.mu.RUnlock()
	return clock.value
}

func (clock *integrationClock) Set(value time.Time) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.value = value
}

type integrationFixture struct {
	pool    *pgxpool.Pool
	clock   *integrationClock
	service *Service
	actor   Actor
}

func TestNodeSchedulingMigrationRoundTrip(t *testing.T) {
	pool := openNodeSchedulingDatabase(t, false)
	migrateNodeSchedulingUpTo(t, pool, 32)
	assertNodeSchedulingTable(t, pool, false)
	applyNodeSchedulingMigration(t, pool, "up")
	assertNodeSchedulingTable(t, pool, true)
	applyNodeSchedulingMigration(t, pool, "down")
	assertNodeSchedulingTable(t, pool, false)
	applyNodeSchedulingMigration(t, pool, "up")
	assertNodeSchedulingTable(t, pool, true)
}

func TestNodeLineGroupMetadataMigration227RoundTripAndEmptyFence(t *testing.T) {
	// Pin the schema head to 227: later migrations change these tables (and 268
	// cannot be rolled back), so facts are seeded with 226/227-era SQL instead of
	// the current service.PutGroup.
	pool := openNodeSchedulingDatabaseThrough(t, 227)
	ctx := t.Context()
	if err := databasetest.MigrateThrough(ctx, pool, "down", 227); err != nil {
		t.Fatalf("rollback empty migration 227: %v", err)
	}
	var metadataColumns int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns
		WHERE table_schema=current_schema() AND table_name='node_line_groups'
		  AND column_name IN ('region','resolved_value','note','sort_order')`).Scan(&metadataColumns); err != nil {
		t.Fatal(err)
	}
	if metadataColumns != 0 {
		t.Fatalf("metadata columns after rollback = %d", metadataColumns)
	}
	if err := databasetest.MigrateThrough(ctx, pool, "up", 227); err != nil {
		t.Fatalf("reapply migration 227: %v", err)
	}

	actor := seedLineGroup227Actor(t, pool, "metadata-migration")
	groupID := uuid.New()
	seedLineGroup227(t, pool, actor, groupID, "migration-defaults", []string{"192.0.2.10", "2001:db8::10"})
	if err := databasetest.MigrateThrough(ctx, pool, "down", 227); err != nil {
		t.Fatalf("rollback migration 227 with representable defaults: %v", err)
	}
	var legacyConfigurationDigest []byte
	if err := pool.QueryRow(ctx, `SELECT configuration_digest FROM node_line_group_revisions
		WHERE tenant_scope_id=$1 AND line_group_id=$2 AND revision=1`, actor.ScopeID, groupID).
		Scan(&legacyConfigurationDigest); err != nil {
		t.Fatalf("read migration 226 revision digest: %v", err)
	}
	if err := databasetest.MigrateThrough(ctx, pool, "up", 227); err != nil {
		t.Fatalf("reapply migration 227 over legacy facts: %v", err)
	}
	var migratedConfigurationDigest []byte
	if err := pool.QueryRow(ctx, `SELECT configuration_digest FROM node_line_group_revisions
		WHERE tenant_scope_id=$1 AND line_group_id=$2 AND revision=1`, actor.ScopeID, groupID).
		Scan(&migratedConfigurationDigest); err != nil {
		t.Fatalf("read migration 227 revision digest: %v", err)
	}
	// Historical digests remain immutable because target snapshots, write receipts, and audits reference them.
	if !bytes.Equal(migratedConfigurationDigest, legacyConfigurationDigest) {
		t.Fatalf("revision configuration digest changed across migration 227: got %x, want %x",
			migratedConfigurationDigest, legacyConfigurationDigest)
	}
	wantResolvedValue := "lg-" + strings.ReplaceAll(groupID.String(), "-", "")
	for _, table := range []struct{ name, idColumn string }{
		{"node_line_groups", "id"}, {"node_line_group_revisions", "line_group_id"},
	} {
		var region, resolvedValue, note string
		var sortOrder int
		if err := pool.QueryRow(ctx, `SELECT region,resolved_value,note,sort_order FROM `+table.name+`
			WHERE tenant_scope_id=$1 AND `+table.idColumn+`=$2`, actor.ScopeID, groupID).
			Scan(&region, &resolvedValue, &note, &sortOrder); err != nil {
			t.Fatalf("read backfilled %s metadata: %v", table.name, err)
		}
		if region != "" || resolvedValue != wantResolvedValue || note != "" || sortOrder != 100 {
			t.Fatalf("backfilled %s metadata = %q/%q/%q/%d", table.name, region, resolvedValue, note, sortOrder)
		}
	}
	var endpoints int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM node_line_endpoints
		WHERE tenant_scope_id=$1 AND line_group_id=$2 AND config_revision=1`, actor.ScopeID, groupID).
		Scan(&endpoints); err != nil || endpoints != 2 {
		t.Fatalf("endpoints across migration 227 = %d, err = %v", endpoints, err)
	}

	// 227 admits an empty (zero-endpoint) revision; rolling back would lose it.
	seedLineGroup227(t, pool, actor, uuid.New(), "migration-empty", nil)
	err := databasetest.MigrateThrough(ctx, pool, "down", 227)
	var databaseError *pgconn.PgError
	if !errors.As(err, &databaseError) || databaseError.Code != "P2271" {
		t.Fatalf("empty revision rollback error = %v, want P2271", err)
	}
	var migrationRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations
		WHERE version=227 AND migration_id='227_node_line_group_metadata'`).Scan(&migrationRows); err != nil {
		t.Fatal(err)
	}
	if migrationRows != 1 {
		t.Fatalf("migration 227 ledger rows after refused rollback = %d", migrationRows)
	}
}

// seedLineGroup227Actor creates only the tenant membership the 226/227 line
// group tables reference; the test seeds facts directly instead of via RBAC.
func seedLineGroup227Actor(t *testing.T, pool *pgxpool.Pool, label string) Actor {
	t.Helper()
	tenantID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `WITH tenant AS (
		INSERT INTO tenants (id,display_name) VALUES ($1,$4)
	), scope AS (
		INSERT INTO access_scopes (id,kind,tenant_id) VALUES ($2,'tenant',$1)
	), member AS (
		INSERT INTO users (id,username,display_name,password_hash) VALUES ($3,$5,$4,'test-only')
	)
	INSERT INTO memberships (scope_id,user_id) VALUES ($2,$3)`,
		tenantID, scopeID, userID, "Tenant "+label, "scheduler-"+label); err != nil {
		t.Fatal(err)
	}
	return Actor{UserID: userID, ScopeID: scopeID}
}

// seedLineGroup227 writes a sealed revision 1 using only columns that exist at
// both 226 and 227, so the 227-only metadata takes its column defaults.
func seedLineGroup227(t *testing.T, pool *pgxpool.Pool, actor Actor, groupID uuid.UUID, name string, addresses []string) {
	t.Helper()
	ctx := t.Context()
	digest := sha256.Sum256([]byte(groupID.String() + "\x00" + name))
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO node_line_groups (
			id,tenant_scope_id,name,current_revision,created_by_user_id,updated_by_user_id,created_at,updated_at
		) VALUES ($1,$2,$3,1,$4,$4,$5,$5)`, groupID, actor.ScopeID, name, actor.UserID, integrationBaseTime); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO node_line_group_revisions (
			line_group_id,tenant_scope_id,revision,name,probe_interval_ms,probe_timeout_ms,
			failure_threshold,recovery_threshold,failure_debounce_ms,recovery_debounce_ms,
			endpoint_count,configuration_digest,created_by_user_id,created_at
		) VALUES ($1,$2,1,$3,10000,2000,3,2,0,0,$4,$5,$6,$7)`, groupID, actor.ScopeID, name,
			len(addresses), digest[:], actor.UserID, integrationBaseTime); err != nil {
			return err
		}
		for index, address := range addresses {
			family := 6
			if !strings.Contains(address, ":") {
				family = 4
			}
			endpointID := uuid.New()
			if _, err := tx.Exec(ctx, `INSERT INTO node_line_endpoints (
				id,tenant_scope_id,line_group_id,config_revision,address,address_family,port,priority,weight
			) VALUES ($1,$2,$3,1,$4,$5,443,$6,1)`, endpointID, actor.ScopeID, groupID, address, family,
				index*10); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO node_line_endpoint_health (
				tenant_scope_id,line_group_id,config_revision,endpoint_id,status,
				consecutive_successes,consecutive_failures,last_sequence,last_changed_at,
				row_revision,created_at,updated_at
			) VALUES ($1,$2,1,$3,'unknown',0,0,0,$4,1,$4,$4)`, actor.ScopeID, groupID, endpointID,
				integrationBaseTime); err != nil {
				return err
			}
		}
		_, err := tx.Exec(ctx, `UPDATE node_line_group_revisions SET sealed_at=$3
			WHERE tenant_scope_id=$1 AND line_group_id=$2 AND revision=1`, actor.ScopeID, groupID, integrationBaseTime)
		return err
	})
	if err != nil {
		t.Fatalf("seed 227-era line group %s: %v", name, err)
	}
}

func TestPutGroupIdempotencyConcurrentCASIsolationAndAuditRollback(t *testing.T) {
	fixture := newIntegrationFixture(t)
	ctx := context.Background()
	groupID := uuid.New()
	request := fixture.putRequest(groupID, 0, "primary-group", "create-primary")
	created, err := fixture.service.PutGroup(ctx, fixture.actor, request)
	if err != nil || created.Group.Revision != 1 || len(created.Group.Endpoints) != 2 {
		t.Fatalf("create result = %#v, %v", created, err)
	}
	replay, err := fixture.service.PutGroup(ctx, fixture.actor, request)
	if err != nil || !replay.Replayed || replay.Group.GroupID != created.Group.GroupID || replay.Group.Revision != 1 {
		t.Fatalf("replay result = %#v, %v", replay, err)
	}
	changed := request
	changed.Name = "changed-payload"
	if _, err := fixture.service.PutGroup(ctx, fixture.actor, changed); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("idempotency conflict error = %v", err)
	}
	assertWriteRequestGuards(t, fixture, groupID)

	const writers = 8
	results := make(chan WriteResult, writers)
	errorsByWriter := make(chan error, writers)
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index := 0; index < writers; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			update := fixture.putRequest(groupID, 1, "primary-group-"+string(rune('a'+index)),
				"cas-update-"+string(rune('a'+index)))
			result, err := fixture.service.PutGroup(ctx, fixture.actor, update)
			results <- result
			errorsByWriter <- err
		}(index)
	}
	close(start)
	wait.Wait()
	close(results)
	close(errorsByWriter)
	successes, conflicts := 0, 0
	for result := range results {
		if result.Group.Revision == 2 {
			successes++
		}
	}
	for err := range errorsByWriter {
		switch {
		case err == nil:
		case errors.Is(err, ErrRevisionConflict):
			conflicts++
		default:
			t.Fatalf("unexpected CAS error = %v", err)
		}
	}
	if successes != 1 || conflicts != writers-1 {
		t.Fatalf("CAS successes=%d conflicts=%d", successes, conflicts)
	}
	current, err := fixture.service.GetCurrent(ctx, fixture.actor, groupID)
	if err != nil || current.Revision != 2 {
		t.Fatalf("current revision = %#v, %v", current, err)
	}
	viewer := seedTenantViewer(t, fixture.pool, fixture.actor.ScopeID, "readonly")
	if _, err := fixture.service.GetCurrent(ctx, viewer, groupID); err != nil {
		t.Fatalf("viewer read error = %v", err)
	}
	denied := fixture.putRequest(groupID, 2, "viewer-write", "viewer-denied")
	if _, err := fixture.service.PutGroup(ctx, viewer, denied); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("viewer write error = %v", err)
	}

	otherActor := seedTenantActor(t, fixture.pool, "other")
	if _, err := fixture.service.GetCurrent(ctx, otherActor, groupID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant get error = %v", err)
	}
	otherRequest := fixture.putRequest(groupID, 0, "other-group", "cross-tenant-create")
	otherResult, err := fixture.service.PutGroup(ctx, otherActor, otherRequest)
	if err != nil || otherResult.Group.TenantScopeID != otherActor.ScopeID || otherResult.Group.Revision != 1 {
		t.Fatalf("isolated same-ID create = %#v, %v", otherResult, err)
	}

	if _, err := fixture.pool.Exec(ctx, `
		CREATE FUNCTION fail_node_scheduling_audit()
		RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
		    RAISE EXCEPTION 'forced node scheduling audit failure';
		END;
		$$;
		CREATE TRIGGER fail_node_scheduling_audit_insert
		BEFORE INSERT ON audit_events
			FOR EACH ROW WHEN (NEW.action = 'node_scheduling.group.create')
		EXECUTE FUNCTION fail_node_scheduling_audit()`); err != nil {
		t.Fatal(err)
	}
	rollbackGroupID := uuid.New()
	rollbackRequest := fixture.putRequest(rollbackGroupID, 0, "rollback-group", "audit-rollback")
	if _, err := fixture.service.PutGroup(ctx, fixture.actor, rollbackRequest); err == nil ||
		!strings.Contains(err.Error(), "forced node scheduling audit failure") {
		t.Fatalf("audit failure error = %v", err)
	}
	var groupCount, writeCount, auditCount int
	if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FROM node_line_groups WHERE id=$1`, rollbackGroupID).Scan(&groupCount); err != nil {
		t.Fatal(err)
	}
	if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FROM node_scheduling_write_requests WHERE idempotency_key=$1`, rollbackRequest.IdempotencyKey).Scan(&writeCount); err != nil {
		t.Fatal(err)
	}
	if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE resource_id=$1`, rollbackGroupID.String()).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if groupCount != 0 || writeCount != 0 || auditCount != 0 {
		t.Fatalf("audit rollback counts group=%d write=%d audit=%d", groupCount, writeCount, auditCount)
	}
	if _, err := fixture.pool.Exec(ctx, `
		DROP TRIGGER fail_node_scheduling_audit_insert ON audit_events;
		DROP FUNCTION fail_node_scheduling_audit()`); err != nil {
		t.Fatal(err)
	}

	var createAuditCount, updateAuditCount int
	if err := fixture.pool.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE action='node_scheduling.group.create'),
		count(*) FILTER (WHERE action='node_scheduling.group.update')
		FROM audit_events WHERE scope_id=$1`, fixture.actor.ScopeID).Scan(&createAuditCount, &updateAuditCount); err != nil {
		t.Fatal(err)
	}
	if createAuditCount != 1 || updateAuditCount != 1 {
		t.Fatalf("successful audit counts create=%d update=%d", createAuditCount, updateAuditCount)
	}
}

func TestDatabaseGuardsTenantRevisionWeightAndProbeTime(t *testing.T) {
	fixture := newIntegrationFixture(t)
	ctx := context.Background()
	groupID := uuid.New()
	created, err := fixture.service.PutGroup(ctx, fixture.actor,
		fixture.putRequest(groupID, 0, "constraint-group", "constraint-create"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(ctx, `
		UPDATE node_line_groups SET current_revision=current_revision+2,updated_at=updated_at
		WHERE tenant_scope_id=$1 AND id=$2`, fixture.actor.ScopeID, groupID); err == nil ||
		!strings.Contains(err.Error(), "advance by one") {
		t.Fatalf("revision jump error = %v", err)
	}

	tx, err := fixture.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// A revision carries its group's DNS resolved values (227/234), as
	// service.PutGroup writes them.
	_, err = tx.Exec(ctx, `
		INSERT INTO node_line_group_revisions (
			line_group_id,tenant_scope_id,revision,name,resolved_value,ipv4_resolved_value,
			probe_interval_ms,probe_timeout_ms,
			failure_threshold,recovery_threshold,failure_debounce_ms,recovery_debounce_ms,
			endpoint_count,configuration_digest,created_by_user_id,created_at
		) SELECT $1,$2,2,'constraint-group',resolved_value,ipv4_resolved_value,10000,3000,3,3,0,0,1,$3,$4,$5
		  FROM node_line_groups WHERE tenant_scope_id=$2 AND id=$1`,
		groupID, fixture.actor.ScopeID, make([]byte, 32), fixture.actor.UserID, integrationBaseTime)
	if err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	_, weightErr := tx.Exec(ctx, `
		INSERT INTO node_line_endpoints (
			id,tenant_scope_id,line_group_id,config_revision,address,address_family,
			port,region,carrier,priority,weight,enabled
		) VALUES ($1,$2,$3,2,'192.0.2.99',4,443,'','',0,0,true)`,
		uuid.New(), fixture.actor.ScopeID, groupID)
	_ = tx.Rollback(ctx)
	assertConstraintError(t, weightErr, "node_line_endpoints_weight_bounds")

	endpointID := created.Group.Endpoints[0].ID
	_, err = fixture.pool.Exec(ctx, `
		UPDATE node_line_endpoint_health SET
			consecutive_successes=1,streak_started_at=created_at + interval '10 minutes',
			last_sequence=1,last_observed_at=created_at + interval '10 minutes',
			last_received_at=created_at,last_probe_digest=$4,last_probe_healthy=true,
			row_revision=row_revision+1
		WHERE tenant_scope_id=$1 AND line_group_id=$2 AND config_revision=1 AND endpoint_id=$3`,
		fixture.actor.ScopeID, groupID, endpointID, make([]byte, 32))
	assertConstraintError(t, err, "node_line_endpoint_health_time_bounds")
	_, err = fixture.pool.Exec(ctx, `
		UPDATE node_line_endpoint_health SET
			consecutive_successes=1,streak_started_at=created_at,
			last_sequence=1,last_observed_at=created_at,
			last_received_at=created_at + interval '25 hours',last_probe_digest=$4,
			last_probe_healthy=true,row_revision=row_revision+1,
			updated_at=created_at + interval '25 hours'
		WHERE tenant_scope_id=$1 AND line_group_id=$2 AND config_revision=1 AND endpoint_id=$3`,
		fixture.actor.ScopeID, groupID, endpointID, make([]byte, 32))
	assertConstraintError(t, err, "node_line_endpoint_health_time_bounds")

	missingScopeID := uuid.New()
	_, err = fixture.pool.Exec(ctx, `
		INSERT INTO node_line_groups (
			id,tenant_scope_id,name,current_revision,created_by_user_id,updated_by_user_id,created_at,updated_at
		) VALUES ($1,$2,'invalid-missing-scope-group',1,$3,$3,$4,$4)`,
		uuid.New(), missingScopeID, fixture.actor.UserID, integrationBaseTime)
	if err == nil {
		t.Fatal("missing scope line group insert succeeded")
	}

	platformScopeID, platformUserID := uuid.New(), uuid.New()
	if _, err := fixture.pool.Exec(ctx, `INSERT INTO access_scopes (id,kind) VALUES ($1,'platform')`, platformScopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(ctx, `INSERT INTO users (id,username,display_name,password_hash) VALUES ($1,'platform-scheduler','Platform','test-only')`, platformUserID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(ctx, `INSERT INTO memberships (scope_id,user_id) VALUES ($1,$2)`, platformScopeID, platformUserID); err != nil {
		t.Fatal(err)
	}
	platformTx, err := fixture.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := platformTx.Exec(ctx, `
		INSERT INTO node_line_groups (
			id,tenant_scope_id,name,current_revision,created_by_user_id,updated_by_user_id,created_at,updated_at
		) VALUES ($1,$2,'valid-platform-group',1,$3,$3,$4,$4)`,
		uuid.New(), platformScopeID, platformUserID, integrationBaseTime); err != nil {
		_ = platformTx.Rollback(ctx)
		t.Fatalf("platform scope insert = %v", err)
	}
	if err := platformTx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestRecordProbeMonotonicThresholdsRevisionAndImmutableSnapshot(t *testing.T) {
	fixture := newIntegrationFixture(t)
	ctx := context.Background()
	groupID := uuid.New()
	created, err := fixture.service.PutGroup(ctx, fixture.actor,
		fixture.putRequest(groupID, 0, "health-group", "health-create"))
	if err != nil {
		t.Fatal(err)
	}
	endpointID := created.Group.Endpoints[0].ID
	probe := func(sequence int64, healthy bool) (ProbeResult, error) {
		observed := integrationBaseTime.Add(time.Duration(sequence) * 10 * time.Second)
		fixture.clock.Set(observed)
		return fixture.service.RecordProbe(ctx, ProbeRequest{
			TenantScopeID: fixture.actor.ScopeID, GroupID: groupID, Revision: 1,
			EndpointID: endpointID, Sequence: sequence, ObservedAt: observed, Healthy: healthy,
		})
	}
	for sequence := int64(1); sequence <= 3; sequence++ {
		result, err := probe(sequence, true)
		if err != nil {
			t.Fatal(err)
		}
		if sequence < 3 && result.Health.Status != HealthUnknown {
			t.Fatalf("sequence %d status = %s", sequence, result.Health.Status)
		}
		if sequence == 3 && (!result.Transitioned || result.Health.Status != HealthHealthy) {
			t.Fatalf("recovery result = %#v", result)
		}
	}
	duplicate, err := probe(3, true)
	if err != nil || !duplicate.Replayed || duplicate.Health.Status != HealthHealthy {
		t.Fatalf("duplicate probe = %#v, %v", duplicate, err)
	}
	if _, err := probe(3, false); !errors.Is(err, ErrProbeConflict) {
		t.Fatalf("same-sequence conflict error = %v", err)
	}
	if _, err := probe(2, true); !errors.Is(err, ErrStaleProbe) {
		t.Fatalf("out-of-order error = %v", err)
	}
	for sequence := int64(4); sequence <= 6; sequence++ {
		result, err := probe(sequence, false)
		if err != nil {
			t.Fatal(err)
		}
		if sequence < 6 && result.Health.Status != HealthHealthy {
			t.Fatalf("failure debounce sequence %d status = %s", sequence, result.Health.Status)
		}
		if sequence == 6 && (!result.Transitioned || result.Health.Status != HealthUnhealthy) {
			t.Fatalf("failure result = %#v", result)
		}
	}
	if _, err := fixture.pool.Exec(ctx, `
		DELETE FROM node_line_endpoint_health
		WHERE tenant_scope_id=$1 AND line_group_id=$2 AND config_revision=1 AND endpoint_id=$3`,
		fixture.actor.ScopeID, groupID, endpointID); err == nil ||
		!strings.Contains(err.Error(), "health rows cannot be deleted") {
		t.Fatalf("health DELETE error = %v", err)
	}
	if _, err := fixture.pool.Exec(ctx, `TRUNCATE node_line_endpoint_health`); err == nil ||
		!strings.Contains(err.Error(), "health rows cannot be deleted") {
		t.Fatalf("health TRUNCATE error = %v", err)
	}
	result, err := probe(7, true)
	if err != nil || result.Health.LastSequence != 7 || result.Health.Status != HealthUnhealthy {
		t.Fatalf("probe after rejected health deletion = %#v, %v", result, err)
	}

	fixture.clock.Set(integrationBaseTime.Add(70 * time.Second))
	update := fixture.putRequest(groupID, 1, "health-group", "health-update")
	updated, err := fixture.service.PutGroup(ctx, fixture.actor, update)
	if err != nil || updated.Group.Revision != 2 || updated.Group.Endpoints[0].Health.Status != HealthUnknown {
		t.Fatalf("new revision health = %#v, %v", updated, err)
	}
	if _, err := fixture.service.RecordProbe(ctx, ProbeRequest{
		TenantScopeID: fixture.actor.ScopeID, GroupID: groupID, Revision: 1,
		EndpointID: endpointID, Sequence: 7, ObservedAt: integrationBaseTime.Add(70 * time.Second), Healthy: true,
	}); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("old revision probe error = %v", err)
	}
	if _, err := fixture.pool.Exec(ctx, `
		UPDATE node_line_group_revisions SET name='mutated'
		WHERE line_group_id=$1 AND revision=1`, groupID); err == nil ||
		!strings.Contains(err.Error(), "immutable") {
		t.Fatalf("sealed revision mutation error = %v", err)
	}
	if _, err := fixture.pool.Exec(ctx, `
		UPDATE node_line_endpoint_health SET last_sequence=last_sequence-1,row_revision=row_revision+1
		WHERE line_group_id=$1 AND config_revision=1 AND endpoint_id=$2`, groupID, endpointID); err == nil ||
		!strings.Contains(err.Error(), "monotonic") {
		t.Fatalf("health regression error = %v", err)
	}
}

func TestPutGroupV226IdempotencyReplayCompatibility(t *testing.T) {
	fixture := newIntegrationFixture(t)
	ctx := t.Context()
	groupID := uuid.New()
	created, err := fixture.service.PutGroup(ctx, fixture.actor,
		fixture.putRequest(groupID, 0, "v226-compatible", "v226-seed"))
	if err != nil {
		t.Fatal(err)
	}
	response, err := json.Marshal(created)
	if err != nil {
		t.Fatal(err)
	}
	insertReceipt := func(key string, digest [32]byte, completed bool) {
		t.Helper()
		writeID := uuid.New()
		if _, err := fixture.pool.Exec(ctx, `
			INSERT INTO node_scheduling_write_requests (
				id,tenant_scope_id,actor_user_id,operation,idempotency_key,request_digest,
				target_group_id,created_at
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			writeID, fixture.actor.ScopeID, fixture.actor.UserID, operationGroupCreate,
			key, digest[:], groupID, integrationBaseTime); err != nil {
			t.Fatal(err)
		}
		if completed {
			if _, err := fixture.pool.Exec(ctx, `
				UPDATE node_scheduling_write_requests
				SET response_body=$2,completed_at=$3 WHERE id=$1`,
				writeID, response, integrationBaseTime); err != nil {
				t.Fatal(err)
			}
		}
	}
	normalize := func(key string, mutate func(*PutGroupRequest)) (PutGroupRequest, normalizedPut) {
		t.Helper()
		request := fixture.putRequest(groupID, 0, "v226-compatible", key)
		if mutate != nil {
			mutate(&request)
		}
		normalized, err := normalizePutRequest(request)
		if err != nil {
			t.Fatal(err)
		}
		return request, normalized
	}

	replayRequest, replayNormalized := normalize("v226-completed", nil)
	insertReceipt(replayRequest.IdempotencyKey, replayNormalized.v226RequestDigest, true)
	replayed, err := fixture.service.PutGroup(ctx, fixture.actor, replayRequest)
	if err != nil || !replayed.Replayed || replayed.Group.GroupID != groupID {
		t.Fatalf("v226 replay result = %#v, %v", replayed, err)
	}

	mismatchRequest, _ := normalize("v226-mismatch", nil)
	insertReceipt(mismatchRequest.IdempotencyKey, sha256.Sum256([]byte("different-request")), true)
	if _, err := fixture.service.PutGroup(ctx, fixture.actor, mismatchRequest); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("mismatched v226 digest error = %v", err)
	}

	unfinishedRequest, unfinishedNormalized := normalize("v226-unfinished", nil)
	insertReceipt(unfinishedRequest.IdempotencyKey, unfinishedNormalized.v226RequestDigest, false)
	if _, err := fixture.service.PutGroup(ctx, fixture.actor, unfinishedRequest); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("unfinished v226 receipt error = %v", err)
	}

	metadataRequest, metadataNormalized := normalize("v226-metadata", func(request *PutGroupRequest) {
		request.Region = "华东"
	})
	insertReceipt(metadataRequest.IdempotencyKey, metadataNormalized.v226RequestDigest, true)
	if _, err := fixture.service.PutGroup(ctx, fixture.actor, metadataRequest); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("metadata-bearing v226 replay error = %v", err)
	}

	currentRequest, currentNormalized := normalize("v227-current", func(request *PutGroupRequest) {
		request.Region = "华东"
	})
	insertReceipt(currentRequest.IdempotencyKey, currentNormalized.requestDigest, true)
	currentReplay, err := fixture.service.PutGroup(ctx, fixture.actor, currentRequest)
	if err != nil || !currentReplay.Replayed {
		t.Fatalf("current digest replay result = %#v, %v", currentReplay, err)
	}
}

func TestPutGroupResolvedValueConflictIsInvalidInput(t *testing.T) {
	fixture := newIntegrationFixture(t)
	first := fixture.putRequest(uuid.New(), 0, "resolved-value-first", "resolved-value-first")
	first.ResolvedValue = "shared-line"
	if _, err := fixture.service.PutGroup(t.Context(), fixture.actor, first); err != nil {
		t.Fatal(err)
	}
	second := fixture.putRequest(uuid.New(), 0, "resolved-value-second", "resolved-value-second")
	second.ResolvedValue = first.ResolvedValue
	_, err := fixture.service.PutGroup(t.Context(), fixture.actor, second)
	if !errors.Is(err, ErrInvalidInput) || errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("resolved value conflict error = %v", err)
	}
}

func newIntegrationFixture(t *testing.T) *integrationFixture {
	t.Helper()
	return newIntegrationFixtureOn(t, openNodeSchedulingDatabase(t, true))
}

// newIntegrationFixtureThrough seeds a fixture on a schema whose head is target.
func newIntegrationFixtureThrough(t *testing.T, target int64) *integrationFixture {
	t.Helper()
	return newIntegrationFixtureOn(t, openNodeSchedulingDatabaseThrough(t, target))
}

func newIntegrationFixtureOn(t *testing.T, pool *pgxpool.Pool) *integrationFixture {
	t.Helper()
	actor := seedTenantActor(t, pool, "primary")
	clock := &integrationClock{value: integrationBaseTime}
	return &integrationFixture{pool: pool, actor: actor, clock: clock, service: NewService(pool, clock.Now)}
}

// openNodeSchedulingDatabaseThrough returns a schema migrated only through target.
func openNodeSchedulingDatabaseThrough(t *testing.T, target int64) *pgxpool.Pool {
	t.Helper()
	pool := openNodeSchedulingDatabase(t, false)
	if err := databasetest.MigrateThrough(context.Background(), pool, "up", target); err != nil {
		t.Fatalf("migrate through %03d: %v", target, err)
	}
	return pool
}

func (fixture *integrationFixture) putRequest(groupID uuid.UUID, revision int64, name, key string) PutGroupRequest {
	return PutGroupRequest{
		GroupID: groupID, ExpectedRevision: revision, Name: name,
		Endpoints: []Endpoint{
			testEndpoint("192.0.2.10", 443, 0, 1),
			testEndpoint("2001:db8::10", 443, 10, 3),
		},
		IdempotencyKey: key, RequestID: key + "-request",
	}
}

func assertWriteRequestGuards(t *testing.T, fixture *integrationFixture, groupID uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	createdAt := integrationBaseTime
	completedInsertID := uuid.New()
	_, err := fixture.pool.Exec(ctx, `
		INSERT INTO node_scheduling_write_requests (
			id,tenant_scope_id,actor_user_id,operation,idempotency_key,request_digest,
			target_group_id,response_body,created_at,completed_at
		) VALUES ($1,$2,$3,'node_scheduling.group.put','direct-completed-insert',$4,$5,'{}'::jsonb,$6,$6)`,
		completedInsertID, fixture.actor.ScopeID, fixture.actor.UserID, make([]byte, 32), groupID, createdAt)
	assertTriggerMessage(t, err, "must start unfinished")

	completionID := uuid.New()
	if _, err := fixture.pool.Exec(ctx, `
		INSERT INTO node_scheduling_write_requests (
			id,tenant_scope_id,actor_user_id,operation,idempotency_key,request_digest,
			target_group_id,created_at
		) VALUES ($1,$2,$3,'node_scheduling.group.put','direct-valid-completion',$4,$5,$6)`,
		completionID, fixture.actor.ScopeID, fixture.actor.UserID, make([]byte, 32), groupID, createdAt); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(ctx, `
		UPDATE node_scheduling_write_requests
		SET response_body='{}'::jsonb,completed_at=$2 WHERE id=$1`, completionID, createdAt); err != nil {
		t.Fatalf("valid direct completion error = %v", err)
	}
	_, err = fixture.pool.Exec(ctx, `
		UPDATE node_scheduling_write_requests
		SET response_body='{"again":true}'::jsonb,completed_at=$2 WHERE id=$1`, completionID, createdAt)
	assertTriggerMessage(t, err, "completed node scheduling write requests are immutable")

	factsID := uuid.New()
	if _, err := fixture.pool.Exec(ctx, `
		INSERT INTO node_scheduling_write_requests (
			id,tenant_scope_id,actor_user_id,operation,idempotency_key,request_digest,
			target_group_id,created_at
		) VALUES ($1,$2,$3,'node_scheduling.group.put','direct-immutable-facts',$4,$5,$6)`,
		factsID, fixture.actor.ScopeID, fixture.actor.UserID, make([]byte, 32), groupID, createdAt); err != nil {
		t.Fatal(err)
	}
	changedDigest := make([]byte, 32)
	changedDigest[0] = 1
	_, err = fixture.pool.Exec(ctx, `
		UPDATE node_scheduling_write_requests SET request_digest=$2 WHERE id=$1`, factsID, changedDigest)
	assertTriggerMessage(t, err, "write request facts are immutable")

	_, err = fixture.pool.Exec(ctx, `DELETE FROM node_scheduling_write_requests WHERE id=$1`, factsID)
	assertTriggerMessage(t, err, "write requests are immutable")
	_, err = fixture.pool.Exec(ctx, `TRUNCATE node_scheduling_write_requests`)
	assertTriggerMessage(t, err, "write requests are immutable")
}

func seedTenantActor(t *testing.T, pool *pgxpool.Pool, label string) Actor {
	t.Helper()
	tenantID, scopeID := uuid.New(), uuid.New()
	userID, managerID, managerRoleID := uuid.New(), uuid.New(), uuid.New()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id,display_name) VALUES ($1,$2)`, tenantID, "Tenant "+label); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes (id,kind,tenant_id) VALUES ($1,'tenant',$2)`, scopeID, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id,username,display_name,password_hash) VALUES ($1,$2,$3,'test-only')`,
		userID, "scheduler-"+label, "Tenant "+label); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id,username,display_name,password_hash) VALUES ($1,$2,$3,'test-only')`,
		managerID, "scheduler-manager-"+label, "Manager "+label); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO memberships (scope_id,user_id) VALUES ($1,$2),($1,$3)`, scopeID, userID, managerID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO roles (id,scope_id,name,description,system_role)
		VALUES ($1,$2,'tenant_owner','node scheduling fixture manager',true)`, managerRoleID, scopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO role_assignments (scope_id,user_id,role_id) VALUES ($1,$2,$3)`, scopeID, managerID, managerRoleID); err != nil {
		t.Fatal(err)
	}
	seedFormalSchedulerRole(t, pool, tenantID, scopeID, managerID, userID,
		"scheduler_"+label, []string{permissionManage, permissionRead})
	return Actor{UserID: userID, ScopeID: scopeID}
}

func seedTenantViewer(t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID, label string) Actor {
	t.Helper()
	userID := uuid.New()
	ctx := context.Background()
	var tenantID, managerID uuid.UUID
	if err := pool.QueryRow(ctx, `
		SELECT scope.tenant_id,assignment.user_id
		FROM access_scopes scope
		JOIN roles role ON role.scope_id=scope.id AND role.system_role AND role.name='tenant_owner'
		JOIN role_assignments assignment ON assignment.scope_id=scope.id AND assignment.role_id=role.id
		WHERE scope.id=$1`, scopeID).Scan(&tenantID, &managerID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id,username,display_name,password_hash) VALUES ($1,$2,$3,'test-only')`,
		userID, "scheduler-"+label, "Viewer "+label); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO memberships (scope_id,user_id) VALUES ($1,$2)`, scopeID, userID); err != nil {
		t.Fatal(err)
	}
	seedFormalSchedulerRole(t, pool, tenantID, scopeID, managerID, userID,
		"scheduler_"+label, []string{permissionRead})
	return Actor{UserID: userID, ScopeID: scopeID}
}

func seedFormalSchedulerRole(
	t *testing.T,
	pool *pgxpool.Pool,
	tenantID, scopeID, managerID, subjectID uuid.UUID,
	name string,
	permissions []string,
) (uuid.UUID, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	roleID, grantID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO custom_roles (
		id,tenant_id,tenant_scope_id,current_name,created_by_user_id,created_by_scope_id,created_at,updated_at
	) VALUES ($1,$2,$3,$4,$5,$3,$6,$6)`,
		roleID, tenantID, scopeID, name, managerID, integrationBaseTime); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO custom_role_revisions (
		role_id,tenant_id,tenant_scope_id,revision,name,permissions,action,
		created_by_user_id,created_by_scope_id,created_at
	) VALUES ($1,$2,$3,1,$4,$5,'identity.custom_role.create',$6,$3,$7)`,
		roleID, tenantID, scopeID, name, permissions, managerID, integrationBaseTime); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE custom_roles
		SET current_revision=1,updated_at=$2 WHERE id=$1`, roleID, integrationBaseTime); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO custom_role_grants (
		id,tenant_id,tenant_scope_id,role_id,role_revision,subject_user_id,
		granted_by_user_id,granted_by_scope_id,granted_at
	) VALUES ($1,$2,$3,$4,1,$5,$6,$3,$7)`,
		grantID, tenantID, scopeID, roleID, subjectID, managerID, integrationBaseTime); err != nil {
		t.Fatal(err)
	}
	return roleID, grantID
}

func openNodeSchedulingDatabase(t *testing.T, migrate bool) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.Ping(ctx); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	schema := "node_scheduling_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^node_scheduling_test_[a-f0-9]{32}$`).MatchString(schema) {
		admin.Close()
		t.Fatalf("unsafe schema %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop node scheduling schema: %v", err)
		}
		admin.Close()
	})
	if migrate {
		if err := database.Migrate(ctx, pool, "up"); err != nil {
			t.Fatal(err)
		}
	}
	return pool
}

func applyNodeSchedulingMigration(t *testing.T, pool *pgxpool.Pool, direction string) {
	t.Helper()
	name := fmt.Sprintf("033_node_scheduling.%s.sql", direction)
	script, err := fs.ReadFile(migrations.FS, name)
	if err != nil {
		t.Fatal(err)
	}
	if err := pgx.BeginFunc(context.Background(), pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), string(script))
		return err
	}); err != nil {
		t.Fatalf("apply %s: %v", name, err)
	}
}

func assertConstraintError(t *testing.T, err error, constraint string) {
	t.Helper()
	var databaseError *pgconn.PgError
	if !errors.As(err, &databaseError) || databaseError.ConstraintName != constraint {
		t.Fatalf("constraint error = %v, want %s", err, constraint)
	}
}

func assertTriggerMessage(t *testing.T, err error, message string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), message) {
		t.Fatalf("trigger error = %v, want message %q", err, message)
	}
}
