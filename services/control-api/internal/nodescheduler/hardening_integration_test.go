//go:build integration

package nodescheduler

import (
	"context"
	"errors"
	"io/fs"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const authorizationTestLock int64 = 72403311

func TestPutGroupAuthorizationSerializesRevocationAndRejectsReplay(t *testing.T) {
	for _, kind := range []string{"assignment", "permission", "tenant", "membership", "account"} {
		t.Run(kind+"/revocation_first", func(t *testing.T) {
			fixture := newIntegrationFixture(t)
			ctx := context.Background()
			tx, err := fixture.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(context.Background()) }()
			if err := applyAuthorizationRevocation(ctx, tx, fixture, kind); err != nil {
				t.Fatal(err)
			}

			groupID := uuid.New()
			request := fixture.putRequest(groupID, 0, "revoked-first", "revoked-first-"+kind)
			result := make(chan error, 1)
			go func() {
				_, err := fixture.service.PutGroup(context.Background(), fixture.actor, request)
				result <- err
			}()
			assertStillBlocked(t, result, "authorization escaped an uncommitted "+kind+" revocation")
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-result:
				if !errors.Is(err, ErrPermissionDenied) {
					t.Fatalf("PutGroup after %s revocation error = %v", kind, err)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("PutGroup remained blocked after %s revocation commit", kind)
			}
			assertSchedulerSideEffects(t, fixture.pool, groupID, request.IdempotencyKey, schedulerSideEffects{})
		})

		t.Run(kind+"/write_first", func(t *testing.T) {
			fixture := newIntegrationFixture(t)
			ctx := context.Background()
			installWriteBlocker(t, fixture.pool)
			blocker, err := fixture.pool.Acquire(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer blocker.Release()
			if _, err := blocker.Exec(ctx, `SELECT pg_advisory_lock($1)`, authorizationTestLock); err != nil {
				t.Fatal(err)
			}
			locked := true
			defer func() {
				if locked {
					_, _ = blocker.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, authorizationTestLock)
				}
			}()

			groupID := uuid.New()
			request := fixture.putRequest(groupID, 0, "write-first", "write-first-"+kind)
			writeResult := make(chan error, 1)
			go func() {
				_, err := fixture.service.PutGroup(context.Background(), fixture.actor, request)
				writeResult <- err
			}()
			waitForAdvisoryWaiter(t, fixture.pool)

			revocationTx, err := fixture.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = revocationTx.Rollback(context.Background()) }()
			revocationResult := make(chan error, 1)
			go func() {
				revocationResult <- applyAuthorizationRevocation(context.Background(), revocationTx, fixture, kind)
			}()
			assertStillBlocked(t, revocationResult, kind+" revocation did not serialize behind authorized write")

			if _, err := blocker.Exec(ctx, `SELECT pg_advisory_unlock($1)`, authorizationTestLock); err != nil {
				t.Fatal(err)
			}
			locked = false
			select {
			case err := <-writeResult:
				if err != nil {
					t.Fatalf("authorized write before %s revocation error = %v", kind, err)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("authorized write remained blocked before %s revocation", kind)
			}
			select {
			case err := <-revocationResult:
				if err != nil {
					t.Fatalf("apply %s revocation: %v", kind, err)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("%s revocation remained blocked after write commit", kind)
			}
			if err := revocationTx.Commit(ctx); err != nil {
				t.Fatal(err)
			}

			before := readSchedulerSideEffects(t, fixture.pool, groupID, request.IdempotencyKey)
			if _, err := fixture.service.PutGroup(ctx, fixture.actor, request); !errors.Is(err, ErrPermissionDenied) {
				t.Fatalf("replay after %s revocation error = %v", kind, err)
			}
			assertSchedulerSideEffects(t, fixture.pool, groupID, request.IdempotencyKey, before)
		})
	}
}

func TestDatabaseRejectsForgedHealthTransitions(t *testing.T) {
	fixture := newIntegrationFixture(t)
	ctx := context.Background()
	groupID := uuid.New()
	created, err := fixture.service.PutGroup(ctx, fixture.actor,
		fixture.putRequest(groupID, 0, "forged-health", "forged-health-create"))
	if err != nil {
		t.Fatal(err)
	}
	endpointID := created.Group.Endpoints[0].ID

	assertForgedHealthRejected(t, fixture, groupID, endpointID, 1, HealthHealthy, 0, 0, true)
	for sequence := int64(1); sequence <= 3; sequence++ {
		observedAt := integrationBaseTime.Add(time.Duration(sequence) * 10 * time.Second)
		fixture.clock.Set(observedAt)
		if _, err := fixture.service.RecordProbe(ctx, ProbeRequest{
			TenantScopeID: fixture.actor.ScopeID, GroupID: groupID, Revision: 1,
			EndpointID: endpointID, Sequence: sequence, ObservedAt: observedAt, Healthy: true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	assertForgedHealthRejected(t, fixture, groupID, endpointID, 4, HealthUnhealthy, 0, 1, false)
	for sequence := int64(4); sequence <= 6; sequence++ {
		observedAt := integrationBaseTime.Add(time.Duration(sequence) * 10 * time.Second)
		fixture.clock.Set(observedAt)
		if _, err := fixture.service.RecordProbe(ctx, ProbeRequest{
			TenantScopeID: fixture.actor.ScopeID, GroupID: groupID, Revision: 1,
			EndpointID: endpointID, Sequence: sequence, ObservedAt: observedAt, Healthy: false,
		}); err != nil {
			t.Fatal(err)
		}
	}
	assertForgedHealthRejected(t, fixture, groupID, endpointID, 7, HealthUnknown, 1, 0, true)
}

func TestSealedRevisionRequiresExactInitialHealthFacts(t *testing.T) {
	fixture := newIntegrationFixture(t)
	ctx := context.Background()
	groupID := uuid.New()
	if _, err := fixture.service.PutGroup(ctx, fixture.actor,
		fixture.putRequest(groupID, 0, "complete-health", "complete-health-create")); err != nil {
		t.Fatal(err)
	}

	tx, err := fixture.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	endpointID := uuid.New()
	insertUnsealedRevision(t, tx, fixture.actor, groupID, 2, endpointID)
	if _, err := tx.Exec(ctx, `UPDATE node_line_group_revisions SET sealed_at=$4
		WHERE tenant_scope_id=$1 AND line_group_id=$2 AND revision=$3`,
		fixture.actor.ScopeID, groupID, int64(2), integrationBaseTime); err != nil {
		t.Fatal(err)
	}
	err = tx.Commit(ctx)
	assertTriggerMessage(t, err, "exactly one initial health row")

	tx, err = fixture.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	endpointID = uuid.New()
	insertUnsealedRevision(t, tx, fixture.actor, groupID, 2, endpointID)
	_, err = tx.Exec(ctx, `INSERT INTO node_line_endpoint_health (
		tenant_scope_id,line_group_id,config_revision,endpoint_id,status,
		consecutive_successes,consecutive_failures,last_sequence,last_changed_at,row_revision,created_at,updated_at
	) VALUES ($1,$2,2,$3,'unknown',1,0,0,$4,1,$4,$4)`,
		fixture.actor.ScopeID, groupID, endpointID, integrationBaseTime)
	assertTriggerMessage(t, err, "must start in the exact initial state")
	_ = tx.Rollback(ctx)

	tx, err = fixture.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	endpointID = uuid.New()
	insertUnsealedRevision(t, tx, fixture.actor, groupID, 2, endpointID)
	if _, err := tx.Exec(ctx, `INSERT INTO node_line_endpoint_health (
		tenant_scope_id,line_group_id,config_revision,endpoint_id,status,
		consecutive_successes,consecutive_failures,last_sequence,last_changed_at,row_revision,created_at,updated_at
	) VALUES ($1,$2,2,$3,'unknown',0,0,0,$4,1,$4,$4)`,
		fixture.actor.ScopeID, groupID, endpointID, integrationBaseTime); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE node_line_group_revisions SET sealed_at=$4
		WHERE tenant_scope_id=$1 AND line_group_id=$2 AND revision=$3`,
		fixture.actor.ScopeID, groupID, int64(2), integrationBaseTime); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	_, err = fixture.pool.Exec(ctx, `INSERT INTO node_line_endpoint_health (
		tenant_scope_id,line_group_id,config_revision,endpoint_id,status,
		consecutive_successes,consecutive_failures,last_sequence,last_changed_at,row_revision,created_at,updated_at
	) VALUES ($1,$2,2,$3,'unknown',0,0,0,$4,1,$4,$4)`,
		fixture.actor.ScopeID, groupID, uuid.New(), integrationBaseTime)
	assertTriggerMessage(t, err, "cannot add health to a sealed")

	tx, err = fixture.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	endpointID = uuid.New()
	insertUnsealedRevision(t, tx, fixture.actor, groupID, 3, endpointID)
	_, err = tx.Exec(ctx, `INSERT INTO node_line_endpoint_health (
		tenant_scope_id,line_group_id,config_revision,endpoint_id,status,
		consecutive_successes,consecutive_failures,last_sequence,last_changed_at,row_revision,created_at,updated_at
	) VALUES ($1,$2,4,$3,'unknown',0,0,0,$4,1,$4,$4)`,
		fixture.actor.ScopeID, groupID, endpointID, integrationBaseTime)
	assertTriggerMessage(t, err, "unsealed node line group revision")
	_ = tx.Rollback(ctx)
}

func TestRevisionSealSerializesSupportingFactInsert(t *testing.T) {
	t.Run("insert_first", func(t *testing.T) {
		fixture := newIntegrationFixture(t)
		ctx := context.Background()
		groupID := uuid.New()
		if _, err := fixture.service.PutGroup(ctx, fixture.actor,
			fixture.putRequest(groupID, 0, "seal-race", "seal-race-insert-first")); err != nil {
			t.Fatal(err)
		}
		seedUnsealedRevision(t, fixture, groupID, 2)

		insertTx, err := fixture.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = insertTx.Rollback(context.Background()) }()
		if err := insertEndpointHealth(ctx, insertTx, fixture.actor, groupID, 2, uuid.New(), "192.0.2.42"); err != nil {
			t.Fatal(err)
		}
		sealTx, err := fixture.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = sealTx.Rollback(context.Background()) }()
		sealResult := make(chan error, 1)
		go func() {
			_, err := sealTx.Exec(context.Background(), `UPDATE node_line_group_revisions SET sealed_at=$4
				WHERE tenant_scope_id=$1 AND line_group_id=$2 AND revision=$3`,
				fixture.actor.ScopeID, groupID, int64(2), integrationBaseTime)
			sealResult <- err
		}()
		assertStillBlocked(t, sealResult, "seal did not serialize behind supporting fact insert")
		if err := insertTx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-sealResult:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("seal remained blocked after supporting fact commit")
		}
		err = sealTx.Commit(ctx)
		assertTriggerMessage(t, err, "exactly one initial health row")
		assertRevisionSupportCount(t, fixture.pool, fixture.actor.ScopeID, groupID, 2, 2, 2, false)
	})

	t.Run("seal_first", func(t *testing.T) {
		fixture := newIntegrationFixture(t)
		ctx := context.Background()
		groupID := uuid.New()
		if _, err := fixture.service.PutGroup(ctx, fixture.actor,
			fixture.putRequest(groupID, 0, "seal-race", "seal-race-seal-first")); err != nil {
			t.Fatal(err)
		}
		seedUnsealedRevision(t, fixture, groupID, 2)

		sealTx, err := fixture.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = sealTx.Rollback(context.Background()) }()
		if _, err := sealTx.Exec(ctx, `UPDATE node_line_group_revisions SET sealed_at=$4
			WHERE tenant_scope_id=$1 AND line_group_id=$2 AND revision=$3`,
			fixture.actor.ScopeID, groupID, int64(2), integrationBaseTime); err != nil {
			t.Fatal(err)
		}
		insertTx, err := fixture.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = insertTx.Rollback(context.Background()) }()
		insertResult := make(chan error, 1)
		go func() {
			insertResult <- insertEndpointHealth(context.Background(), insertTx, fixture.actor,
				groupID, 2, uuid.New(), "192.0.2.42")
		}()
		assertStillBlocked(t, insertResult, "supporting fact insert did not serialize behind seal")
		if err := sealTx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-insertResult:
			assertTriggerMessage(t, err, "sealed node line group revision")
		case <-time.After(5 * time.Second):
			t.Fatal("supporting fact insert remained blocked after seal commit")
		}
		_ = insertTx.Rollback(ctx)
		assertRevisionSupportCount(t, fixture.pool, fixture.actor.ScopeID, groupID, 2, 1, 1, true)
	})
}

func TestInitialHealthTimeMatchesRevisionCreation(t *testing.T) {
	fixture := newIntegrationFixture(t)
	ctx := context.Background()
	groupID := uuid.New()
	if _, err := fixture.service.PutGroup(ctx, fixture.actor,
		fixture.putRequest(groupID, 0, "health-created-at", "health-created-at-create")); err != nil {
		t.Fatal(err)
	}
	tx, err := fixture.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	endpointID := uuid.New()
	insertUnsealedRevision(t, tx, fixture.actor, groupID, 2, endpointID)
	future := integrationBaseTime.Add(time.Hour)
	_, err = tx.Exec(ctx, `INSERT INTO node_line_endpoint_health (
		tenant_scope_id,line_group_id,config_revision,endpoint_id,status,
		consecutive_successes,consecutive_failures,last_sequence,last_changed_at,row_revision,created_at,updated_at
	) VALUES ($1,$2,2,$3,'unknown',0,0,0,$4,1,$4,$4)`,
		fixture.actor.ScopeID, groupID, endpointID, future)
	assertTriggerMessage(t, err, "must start in the exact initial state")
}

func TestEndpointCannotPrecedeParentRevisionAndBypassSeal(t *testing.T) {
	fixture := newIntegrationFixture(t)
	ctx := context.Background()
	groupID := uuid.New()
	if _, err := fixture.service.PutGroup(ctx, fixture.actor,
		fixture.putRequest(groupID, 0, "missing-parent", "missing-parent-create")); err != nil {
		t.Fatal(err)
	}

	orphanTx, err := fixture.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = orphanTx.Rollback(context.Background()) }()
	_, err = orphanTx.Exec(ctx, `INSERT INTO node_line_endpoints (
		id,tenant_scope_id,line_group_id,config_revision,address,address_family,
		port,region,carrier,priority,weight,enabled
	) VALUES ($1,$2,$3,99,'192.0.2.99',4,443,'','',0,1,true)`,
		uuid.New(), fixture.actor.ScopeID, groupID)
	if err != nil {
		assertTriggerMessage(t, err, "requires an existing unsealed node line group revision")
		return
	}

	parentTx, err := fixture.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = parentTx.Rollback(context.Background()) }()
	endpointID := uuid.New()
	insertUnsealedRevision(t, parentTx, fixture.actor, groupID, 99, endpointID)
	if err := insertInitialHealth(ctx, parentTx, fixture.actor, groupID, 99, endpointID); err != nil {
		t.Fatal(err)
	}
	if _, err := parentTx.Exec(ctx, `UPDATE node_line_group_revisions SET sealed_at=$4
		WHERE tenant_scope_id=$1 AND line_group_id=$2 AND revision=$3`,
		fixture.actor.ScopeID, groupID, int64(99), integrationBaseTime); err != nil {
		t.Fatal(err)
	}
	if err := parentTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := orphanTx.Commit(ctx); err == nil {
		assertRevisionSupportCount(t, fixture.pool, fixture.actor.ScopeID, groupID, 99, 1, 1, true)
		t.Fatal("endpoint with a missing parent revision committed after the parent was sealed")
	}
}

func TestNodeSchedulingPopulatedDownRefusesAtomically(t *testing.T) {
	pool := openNodeSchedulingDatabase(t, false)
	ctx := context.Background()
	migrateNodeSchedulingUpTo(t, pool, 33)
	tenantID, scopeID, userID, groupID, endpointID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		return insertNodeSchedulingFacts033(ctx, tx, tenantID, scopeID, userID, groupID, endpointID)
	}); err != nil {
		t.Fatal(err)
	}

	err := execNodeSchedulingMigration(ctx, pool, "down")
	var databaseError *pgconn.PgError
	if !errors.As(err, &databaseError) || databaseError.Code != "P0001" {
		t.Fatalf("populated 033 down error = %v, want P0001", err)
	}
	var groups, revisions, endpoints, health int
	if err := pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM node_line_groups),
		(SELECT count(*) FROM node_line_group_revisions),
		(SELECT count(*) FROM node_line_endpoints),
		(SELECT count(*) FROM node_line_endpoint_health)`).Scan(&groups, &revisions, &endpoints, &health); err != nil {
		t.Fatal(err)
	}
	if groups != 1 || revisions != 1 || endpoints != 1 || health != 1 {
		t.Fatalf("populated down changed facts: groups=%d revisions=%d endpoints=%d health=%d",
			groups, revisions, endpoints, health)
	}
}

func TestNodeSchedulingDownSerializesConcurrentFactWrite(t *testing.T) {
	pool := openNodeSchedulingDatabase(t, false)
	ctx := context.Background()
	migrateNodeSchedulingUpTo(t, pool, 33)
	tenantID, scopeID, userID, groupID, endpointID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	writer, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = writer.Rollback(context.Background()) }()
	if _, err := writer.Exec(ctx, `LOCK TABLE
		node_line_groups,node_line_group_revisions,node_line_endpoints,
		node_line_endpoint_health,node_scheduling_write_requests
		IN ROW EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	err = execNodeSchedulingMigration(ctx, pool, "down")
	var lockError *pgconn.PgError
	if !errors.As(err, &lockError) || lockError.Code != "55P03" {
		t.Fatalf("concurrent 033 down error = %v, want lock_not_available", err)
	}
	if err := insertNodeSchedulingFacts033(ctx, writer, tenantID, scopeID, userID, groupID, endpointID); err != nil {
		t.Fatal(err)
	}
	if err := writer.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	err = execNodeSchedulingMigration(ctx, pool, "down")
	var populatedError *pgconn.PgError
	if !errors.As(err, &populatedError) || populatedError.Code != "P0001" {
		t.Fatalf("033 down after writer commit error = %v, want P0001", err)
	}
	assertRevisionSupportCount(t, pool, scopeID, groupID, 1, 1, 1, true)
}

func TestNodeSchedulingDownLockPreventsConcurrentFactWrite(t *testing.T) {
	pool := openNodeSchedulingDatabase(t, false)
	ctx := context.Background()
	migrateNodeSchedulingUpTo(t, pool, 33)
	tenantID, scopeID, userID, groupID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,display_name) VALUES($1,'033 down lock')`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,username,display_name,password_hash)
		VALUES($1,$2,'033 Down Lock','test')`, userID, "scheduler-"+userID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID); err != nil {
		t.Fatal(err)
	}
	downTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = downTx.Rollback(context.Background()) }()
	if _, err := downTx.Exec(ctx, `LOCK TABLE
		node_scheduling_write_requests,node_line_groups,node_line_group_revisions,
		node_line_endpoints,node_line_endpoint_health
		IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	writeResult := make(chan error, 1)
	go func() {
		_, err := pool.Exec(ctx, `INSERT INTO node_line_groups(
			id,tenant_scope_id,name,current_revision,created_by_user_id,updated_by_user_id,created_at,updated_at
		) VALUES($1,$2,'blocked-down-write',1,$3,$3,$4,$4)`,
			groupID, scopeID, userID, integrationBaseTime)
		writeResult <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiting bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM pg_locks
			WHERE relation='node_line_groups'::regclass
			  AND mode='RowExclusiveLock' AND NOT granted
		)`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("concurrent fact write did not wait for 033 down lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	script, err := fs.ReadFile(migrations.FS, "033_node_scheduling.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := downTx.Exec(ctx, string(script)); err != nil {
		t.Fatal(err)
	}
	if err := downTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-writeResult:
		if err == nil {
			t.Fatal("concurrent fact write succeeded after 033 down acquired its locks")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent fact write remained blocked after 033 down committed")
	}
	assertNodeSchedulingTable(t, pool, false)
}

func TestNodeSchedulingDownDoesNotWaitOnDeferredRevision(t *testing.T) {
	pool := openNodeSchedulingDatabase(t, false)
	ctx := context.Background()
	migrateNodeSchedulingUpTo(t, pool, 33)
	tenantID, scopeID, userID, groupID, endpointID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		return insertNodeSchedulingFacts033(ctx, tx, tenantID, scopeID, userID, groupID, endpointID)
	}); err != nil {
		t.Fatal(err)
	}
	revisionTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = revisionTx.Rollback(context.Background()) }()
	if _, err := revisionTx.Exec(ctx, `INSERT INTO node_line_group_revisions(
		line_group_id,tenant_scope_id,revision,name,probe_interval_ms,probe_timeout_ms,
		failure_threshold,recovery_threshold,failure_debounce_ms,recovery_debounce_ms,
		endpoint_count,configuration_digest,created_by_user_id,created_at
	) VALUES($1,$2,2,'deferred-revision',10000,3000,3,3,0,0,1,$3,$4,$5)`,
		groupID, scopeID, make([]byte, 32), userID, integrationBaseTime); err != nil {
		t.Fatal(err)
	}
	downConn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer downConn.Release()
	if _, err := downConn.Exec(ctx, `SET statement_timeout='500ms'`); err != nil {
		t.Fatal(err)
	}
	script, err := fs.ReadFile(migrations.FS, "033_node_scheduling.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	err = pgx.BeginFunc(ctx, downConn, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, string(script))
		return err
	})
	var lockError *pgconn.PgError
	if !errors.As(err, &lockError) || lockError.Code != "55P03" {
		t.Fatalf("033 down concurrent revision error = %v, want lock_not_available", err)
	}
	if _, err := downConn.Exec(ctx, `RESET statement_timeout`); err != nil {
		t.Fatal(err)
	}
	if err := revisionTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	err = execNodeSchedulingMigration(ctx, pool, "down")
	var populatedError *pgconn.PgError
	if !errors.As(err, &populatedError) || populatedError.Code != "P0001" {
		t.Fatalf("033 down after revision commit error = %v, want P0001", err)
	}
}

func TestFutureTenantSystemRolesReceiveNodeSchedulingPermissions(t *testing.T) {
	pool := openNodeSchedulingDatabase(t, true)
	ctx := context.Background()
	tenantID, scopeID := uuid.New(), uuid.New()
	ownerID, viewerID := uuid.New(), uuid.New()
	ownerRoleID, viewerRoleID := uuid.New(), uuid.New()
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		statements := []struct {
			query string
			args  []any
		}{
			{`INSERT INTO tenants(id,display_name) VALUES($1,'Future tenant')`, []any{tenantID}},
			{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{scopeID, tenantID}},
			{`INSERT INTO users(id,username,display_name,password_hash) VALUES
				($1,$3,'Future Owner','test'),($2,$4,'Future Viewer','test')`,
				[]any{ownerID, viewerID, "future-owner-" + ownerID.String(), "future-viewer-" + viewerID.String()}},
			{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2),($1,$3)`, []any{scopeID, ownerID, viewerID}},
			{`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES
				($1,$3,'tenant_owner','Future tenant owner',true),
				($2,$3,'tenant_viewer','Future tenant viewer',true)`, []any{ownerRoleID, viewerRoleID, scopeID}},
			{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3),($1,$4,$5)`,
				[]any{scopeID, ownerID, ownerRoleID, viewerID, viewerRoleID}},
		}
		for _, statement := range statements {
			if _, err := tx.Exec(ctx, statement.query, statement.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var ownerPermissions, viewerPermissions int
	if err := pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM custom_rbac_effective_permissions($1,$2)
		 WHERE permission_name IN ('node_scheduling.read','node_scheduling.manage')),
		(SELECT count(*) FROM custom_rbac_effective_permissions($1,$3)
		 WHERE permission_name IN ('node_scheduling.read','node_scheduling.manage'))`,
		scopeID, ownerID, viewerID).Scan(&ownerPermissions, &viewerPermissions); err != nil {
		t.Fatal(err)
	}
	if ownerPermissions != 2 || viewerPermissions != 1 {
		t.Fatalf("future role node permissions owner=%d viewer=%d, want 2/1",
			ownerPermissions, viewerPermissions)
	}
	clock := &integrationClock{value: integrationBaseTime}
	owner := Actor{UserID: ownerID, ScopeID: scopeID}
	fixture := &integrationFixture{pool: pool, clock: clock, service: NewService(pool, clock.Now), actor: owner}
	groupID := uuid.New()
	if _, err := fixture.service.PutGroup(ctx, owner,
		fixture.putRequest(groupID, 0, "future-role-group", "future-role-create")); err != nil {
		t.Fatal(err)
	}
	viewer := Actor{UserID: viewerID, ScopeID: scopeID}
	if _, err := fixture.service.GetCurrent(ctx, viewer, groupID); err != nil {
		t.Fatalf("future tenant viewer read error = %v", err)
	}
	if _, err := fixture.service.PutGroup(ctx, viewer,
		fixture.putRequest(groupID, 1, "future-role-denied", "future-role-denied")); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("future tenant viewer write error = %v", err)
	}
}

func TestDatabaseRejectsIPv4MappedIPv6Endpoint(t *testing.T) {
	fixture := newIntegrationFixture(t)
	ctx := context.Background()
	groupID := uuid.New()
	if _, err := fixture.service.PutGroup(ctx, fixture.actor,
		fixture.putRequest(groupID, 0, "mapped-address", "mapped-address-create")); err != nil {
		t.Fatal(err)
	}
	tx, err := fixture.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	insertUnsealedRevision(t, tx, fixture.actor, groupID, 2, uuid.New())
	_, err = tx.Exec(ctx, `INSERT INTO node_line_endpoints(
		id,tenant_scope_id,line_group_id,config_revision,address,address_family,
		port,region,carrier,priority,weight,enabled
	) VALUES($1,$2,$3,2,'::ffff:192.0.2.40',6,443,'','',0,1,true)`,
		uuid.New(), fixture.actor.ScopeID, groupID)
	assertConstraintError(t, err, "node_line_endpoints_address_host")
}

func TestDatabaseRejectsInfiniteHealthTime(t *testing.T) {
	fixture := newIntegrationFixture(t)
	ctx := context.Background()
	groupID := uuid.New()
	created, err := fixture.service.PutGroup(ctx, fixture.actor,
		fixture.putRequest(groupID, 0, "infinite-health", "infinite-health-create"))
	if err != nil {
		t.Fatal(err)
	}
	endpointID := created.Group.Endpoints[0].ID
	for sequence := int64(1); sequence <= 3; sequence++ {
		observedAt := integrationBaseTime.Add(time.Duration(sequence) * 10 * time.Second)
		fixture.clock.Set(observedAt)
		if _, err := fixture.service.RecordProbe(ctx, ProbeRequest{
			TenantScopeID: fixture.actor.ScopeID, GroupID: groupID, Revision: 1,
			EndpointID: endpointID, Sequence: sequence, ObservedAt: observedAt, Healthy: true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	_, err = fixture.pool.Exec(ctx, `UPDATE node_line_endpoint_health SET
		last_sequence=4,last_observed_at='infinity',last_received_at='infinity',
		last_probe_digest=decode(repeat('ff',32),'hex'),last_probe_healthy=true,
		row_revision=row_revision+1,updated_at='infinity'
		WHERE tenant_scope_id=$1 AND line_group_id=$2 AND config_revision=1 AND endpoint_id=$3`,
		fixture.actor.ScopeID, groupID, endpointID)
	assertConstraintError(t, err, "node_line_endpoint_health_finite_time")
}

func TestDatabaseRejectsImmutableFactMutation(t *testing.T) {
	fixture := newIntegrationFixture(t)
	ctx := context.Background()
	groupID := uuid.New()
	created, err := fixture.service.PutGroup(ctx, fixture.actor,
		fixture.putRequest(groupID, 0, "immutable-facts", "immutable-facts-create"))
	if err != nil {
		t.Fatal(err)
	}
	endpointID := created.Group.Endpoints[0].ID
	tests := []struct {
		name, statement, message string
		arguments                []any
	}{
		{"endpoint weight update", `UPDATE node_line_endpoints SET weight=2
			WHERE tenant_scope_id=$1 AND line_group_id=$2 AND config_revision=1 AND id=$3`,
			"node line endpoints are immutable", []any{fixture.actor.ScopeID, groupID, endpointID}},
		{"endpoint revision update", `UPDATE node_line_endpoints SET config_revision=2
			WHERE tenant_scope_id=$1 AND line_group_id=$2 AND config_revision=1 AND id=$3`,
			"node line endpoints are immutable", []any{fixture.actor.ScopeID, groupID, endpointID}},
		{"endpoint delete", `DELETE FROM node_line_endpoints
			WHERE tenant_scope_id=$1 AND line_group_id=$2 AND config_revision=1 AND id=$3`,
			"node line endpoints are immutable", []any{fixture.actor.ScopeID, groupID, endpointID}},
		{"endpoint truncate", `TRUNCATE node_line_endpoints CASCADE`, "node line endpoints are immutable", nil},
		{"revision delete", `DELETE FROM node_line_group_revisions
			WHERE tenant_scope_id=$1 AND line_group_id=$2 AND revision=1`,
			"node line group revisions are immutable", []any{fixture.actor.ScopeID, groupID}},
		{"revision truncate", `TRUNCATE node_line_group_revisions CASCADE`, "node line group revisions are immutable", nil},
		{"group delete", `DELETE FROM node_line_groups WHERE tenant_scope_id=$1 AND id=$2`,
			"node line groups cannot be physically deleted", []any{fixture.actor.ScopeID, groupID}},
		{"group truncate", `TRUNCATE node_line_groups CASCADE`, "node line groups cannot be physically deleted", nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := fixture.pool.Exec(ctx, test.statement, test.arguments...)
			assertTriggerMessage(t, err, test.message)
		})
	}
	current, err := fixture.service.GetCurrent(ctx, fixture.actor, groupID)
	if err != nil || current.Revision != 1 || len(current.Endpoints) != 2 || current.Endpoints[0].Weight != 1 {
		t.Fatalf("facts after rejected mutations = %#v, %v", current, err)
	}
}

func TestFutureProbeRejectionLeavesHealthUnchanged(t *testing.T) {
	fixture := newIntegrationFixture(t)
	ctx := context.Background()
	groupID := uuid.New()
	created, err := fixture.service.PutGroup(ctx, fixture.actor,
		fixture.putRequest(groupID, 0, "future-probe", "future-probe-create"))
	if err != nil {
		t.Fatal(err)
	}
	endpointID := created.Group.Endpoints[0].ID
	before := readHealthFact(t, fixture.pool, fixture.actor.ScopeID, groupID, endpointID)
	_, err = fixture.service.RecordProbe(ctx, ProbeRequest{
		TenantScopeID: fixture.actor.ScopeID, GroupID: groupID, Revision: 1,
		EndpointID: endpointID, Sequence: 1,
		ObservedAt: integrationBaseTime.Add(maxProbeFutureSkew + time.Microsecond), Healthy: true,
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("future probe error = %v", err)
	}
	after := readHealthFact(t, fixture.pool, fixture.actor.ScopeID, groupID, endpointID)
	if after != before {
		t.Fatalf("future probe changed health: before=%#v after=%#v", before, after)
	}
}

type schedulerSideEffects struct {
	groups, revisions, writes, audits int
}

type healthFact struct {
	status                                    string
	consecutiveSuccesses, consecutiveFailures int
	lastSequence, rowRevision                 int64
}

func installWriteBlocker(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `CREATE FUNCTION block_node_scheduling_write_request()
		RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			PERFORM pg_advisory_xact_lock(72403311);
			RETURN NEW;
		END;
		$$;
		CREATE TRIGGER block_node_scheduling_write_request
		BEFORE INSERT ON node_scheduling_write_requests
		FOR EACH ROW EXECUTE FUNCTION block_node_scheduling_write_request()`); err != nil {
		t.Fatal(err)
	}
}

func waitForAdvisoryWaiter(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var waiting bool
		if err := pool.QueryRow(t.Context(), `SELECT EXISTS(
			SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted
		)`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for the authorized write blocker")
}

func assertStillBlocked(t *testing.T, result <-chan error, message string) {
	t.Helper()
	select {
	case err := <-result:
		t.Fatalf("%s: %v", message, err)
	case <-time.After(100 * time.Millisecond):
	}
}

func applyAuthorizationRevocation(ctx context.Context, tx pgx.Tx, fixture *integrationFixture, kind string) error {
	var tenantID, roleID, grantID, managerID uuid.UUID
	var roleRevision int64
	var roleName string
	if err := tx.QueryRow(ctx, `
		SELECT scope.tenant_id,grant_row.role_id,grant_row.id,grant_row.granted_by_user_id,
		       role.current_revision,role.current_name
		FROM access_scopes scope
		JOIN custom_role_grants grant_row
		  ON grant_row.tenant_scope_id=scope.id AND grant_row.subject_user_id=$2
		JOIN custom_roles role ON role.id=grant_row.role_id AND role.tenant_scope_id=scope.id
		WHERE scope.id=$1 AND NOT EXISTS (
			SELECT 1 FROM custom_role_grant_revocations revoked WHERE revoked.grant_id=grant_row.id
		)`, fixture.actor.ScopeID, fixture.actor.UserID).Scan(
		&tenantID, &roleID, &grantID, &managerID, &roleRevision, &roleName); err != nil {
		return err
	}
	revokedAt := integrationBaseTime.Add(time.Minute)
	switch kind {
	case "assignment":
		_, err := tx.Exec(ctx, `INSERT INTO custom_role_grant_revocations (
			id,grant_id,tenant_id,tenant_scope_id,role_id,role_revision,subject_user_id,
			revoked_by_user_id,revoked_by_scope_id,revoked_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$4,$9)`, uuid.New(), grantID, tenantID,
			fixture.actor.ScopeID, roleID, roleRevision, fixture.actor.UserID, managerID, revokedAt)
		return err
	case "permission":
		if _, err := tx.Exec(ctx, `INSERT INTO custom_role_revisions (
			role_id,tenant_id,tenant_scope_id,revision,name,permissions,action,
			created_by_user_id,created_by_scope_id,created_at
		) VALUES ($1,$2,$3,$4,$5,ARRAY['node_scheduling.read']::text[],
			'identity.custom_role.publish',$6,$3,$7)`, roleID, tenantID, fixture.actor.ScopeID,
			roleRevision+1, roleName, managerID, revokedAt); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE custom_roles SET current_revision=$2,updated_at=$3 WHERE id=$1`,
			roleID, roleRevision+1, revokedAt)
		return err
	case "tenant":
		_, err := tx.Exec(ctx, `UPDATE tenants SET status='suspended',updated_at=$2 WHERE id=$1`, tenantID, revokedAt)
		return err
	case "membership":
		_, err := tx.Exec(ctx, `UPDATE memberships SET status='suspended'
			WHERE scope_id=$1 AND user_id=$2`, fixture.actor.ScopeID, fixture.actor.UserID)
		return err
	case "account":
		_, err := tx.Exec(ctx, `UPDATE users SET status='disabled',revision=revision+1,updated_at=$2 WHERE id=$1`,
			fixture.actor.UserID, revokedAt)
		return err
	default:
		return errors.New("unknown authorization revocation kind")
	}
}

func readSchedulerSideEffects(t *testing.T, pool *pgxpool.Pool, groupID uuid.UUID, key string) schedulerSideEffects {
	t.Helper()
	var result schedulerSideEffects
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM node_line_groups WHERE id=$1),
		(SELECT count(*) FROM node_line_group_revisions WHERE line_group_id=$1),
		(SELECT count(*) FROM node_scheduling_write_requests WHERE target_group_id=$1 AND idempotency_key=$2),
		(SELECT count(*) FROM audit_events WHERE resource_type='node_line_group' AND resource_id=$3)`,
		groupID, key, groupID.String()).Scan(&result.groups, &result.revisions, &result.writes, &result.audits); err != nil {
		t.Fatal(err)
	}
	return result
}

func assertSchedulerSideEffects(
	t *testing.T,
	pool *pgxpool.Pool,
	groupID uuid.UUID,
	key string,
	want schedulerSideEffects,
) {
	t.Helper()
	if got := readSchedulerSideEffects(t, pool, groupID, key); got != want {
		t.Fatalf("scheduler side effects = %#v, want %#v", got, want)
	}
}

func readHealthFact(
	t *testing.T,
	pool *pgxpool.Pool,
	tenantScopeID, groupID, endpointID uuid.UUID,
) healthFact {
	t.Helper()
	var fact healthFact
	if err := pool.QueryRow(t.Context(), `SELECT status,consecutive_successes,consecutive_failures,
		last_sequence,row_revision FROM node_line_endpoint_health
		WHERE tenant_scope_id=$1 AND line_group_id=$2 AND config_revision=1 AND endpoint_id=$3`,
		tenantScopeID, groupID, endpointID).Scan(&fact.status, &fact.consecutiveSuccesses,
		&fact.consecutiveFailures, &fact.lastSequence, &fact.rowRevision); err != nil {
		t.Fatal(err)
	}
	return fact
}

func assertForgedHealthRejected(
	t *testing.T,
	fixture *integrationFixture,
	groupID, endpointID uuid.UUID,
	sequence int64,
	status string,
	successes, failures int,
	healthy bool,
) {
	t.Helper()
	observedAt := integrationBaseTime.Add(time.Duration(sequence) * 10 * time.Second)
	_, err := fixture.pool.Exec(t.Context(), `UPDATE node_line_endpoint_health SET
		status=$4,consecutive_successes=$5,consecutive_failures=$6,
		streak_started_at=$7,last_sequence=$8,last_observed_at=$7,last_received_at=$7,
		last_probe_digest=$9,last_probe_healthy=$10,last_changed_at=$7,
		row_revision=row_revision+1,updated_at=$7
		WHERE tenant_scope_id=$1 AND line_group_id=$2 AND config_revision=1 AND endpoint_id=$3`,
		fixture.actor.ScopeID, groupID, endpointID, status, successes, failures,
		observedAt, sequence, make([]byte, 32), healthy)
	assertTriggerMessage(t, err, "does not match its health policy")
}

func insertUnsealedRevision(
	t *testing.T,
	tx pgx.Tx,
	actor Actor,
	groupID uuid.UUID,
	revision int64,
	endpointID uuid.UUID,
) {
	t.Helper()
	ctx := t.Context()
	// A revision carries its group's DNS resolved values (227/234), as
	// service.PutGroup writes them; the group row holds the assigned ones.
	if _, err := tx.Exec(ctx, `INSERT INTO node_line_group_revisions (
		line_group_id,tenant_scope_id,revision,name,resolved_value,ipv4_resolved_value,
		probe_interval_ms,probe_timeout_ms,
		failure_threshold,recovery_threshold,failure_debounce_ms,recovery_debounce_ms,
		endpoint_count,configuration_digest,created_by_user_id,created_at
	) SELECT $1,$2,$3,'complete-health',resolved_value,ipv4_resolved_value,10000,3000,3,3,0,0,1,$4,$5,$6
	  FROM node_line_groups WHERE tenant_scope_id=$2 AND id=$1`,
		groupID, actor.ScopeID, revision, make([]byte, 32), actor.UserID, integrationBaseTime); err != nil {
		_ = tx.Rollback(context.Background())
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO node_line_endpoints (
		id,tenant_scope_id,line_group_id,config_revision,address,address_family,
		port,region,carrier,priority,weight,enabled
	) VALUES ($1,$2,$3,$4,$5,4,443,'','',0,1,true)`,
		endpointID, actor.ScopeID, groupID, revision, "192.0.2.40"); err != nil {
		_ = tx.Rollback(context.Background())
		t.Fatal(err)
	}
}

func seedUnsealedRevision(t *testing.T, fixture *integrationFixture, groupID uuid.UUID, revision int64) {
	t.Helper()
	if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		endpointID := uuid.New()
		insertUnsealedRevision(t, tx, fixture.actor, groupID, revision, endpointID)
		return insertInitialHealth(t.Context(), tx, fixture.actor, groupID, revision, endpointID)
	}); err != nil {
		t.Fatal(err)
	}
}

func insertEndpointHealth(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	groupID uuid.UUID,
	revision int64,
	endpointID uuid.UUID,
	address string,
) error {
	if _, err := tx.Exec(ctx, `INSERT INTO node_line_endpoints (
		id,tenant_scope_id,line_group_id,config_revision,address,address_family,
		port,region,carrier,priority,weight,enabled
	) VALUES ($1,$2,$3,$4,$5,4,443,'','',0,1,true)`,
		endpointID, actor.ScopeID, groupID, revision, address); err != nil {
		return err
	}
	return insertInitialHealth(ctx, tx, actor, groupID, revision, endpointID)
}

func insertInitialHealth(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	groupID uuid.UUID,
	revision int64,
	endpointID uuid.UUID,
) error {
	_, err := tx.Exec(ctx, `INSERT INTO node_line_endpoint_health (
		tenant_scope_id,line_group_id,config_revision,endpoint_id,status,
		consecutive_successes,consecutive_failures,last_sequence,last_changed_at,row_revision,created_at,updated_at
	) VALUES ($1,$2,$3,$4,'unknown',0,0,0,$5,1,$5,$5)`,
		actor.ScopeID, groupID, revision, endpointID, integrationBaseTime)
	return err
}

func insertNodeSchedulingFacts033(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, scopeID, userID, groupID, endpointID uuid.UUID,
) error {
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,'033 populated')`, []any{tenantID}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{scopeID, tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'033 User','test')`, []any{userID, "scheduler-" + userID.String()}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{scopeID, userID}},
		{`INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,created_by_user_id,updated_by_user_id,created_at,updated_at)
		 VALUES($1,$2,'populated-down',1,$3,$3,$4,$4)`, []any{groupID, scopeID, userID, integrationBaseTime}},
		{`INSERT INTO node_line_group_revisions(line_group_id,tenant_scope_id,revision,name,probe_interval_ms,
		 probe_timeout_ms,failure_threshold,recovery_threshold,failure_debounce_ms,recovery_debounce_ms,
		 endpoint_count,configuration_digest,created_by_user_id,created_at)
		 VALUES($1,$2,1,'populated-down',10000,3000,3,3,0,0,1,$3,$4,$5)`, []any{groupID, scopeID, make([]byte, 32), userID, integrationBaseTime}},
		{`INSERT INTO node_line_endpoints(id,tenant_scope_id,line_group_id,config_revision,address,address_family,
		 port,region,carrier,priority,weight,enabled) VALUES($1,$2,$3,1,'192.0.2.33',4,443,'','',0,1,true)`, []any{endpointID, scopeID, groupID}},
		{`INSERT INTO node_line_endpoint_health(tenant_scope_id,line_group_id,config_revision,endpoint_id,status,
		 consecutive_successes,consecutive_failures,last_sequence,last_changed_at,row_revision,created_at,updated_at)
		 VALUES($1,$2,1,$3,'unknown',0,0,0,$4,1,$4,$4)`, []any{scopeID, groupID, endpointID, integrationBaseTime}},
		{`UPDATE node_line_group_revisions SET sealed_at=$3
		 WHERE tenant_scope_id=$1 AND line_group_id=$2 AND revision=1`, []any{scopeID, groupID, integrationBaseTime}},
	}
	for _, statement := range statements {
		if _, err := tx.Exec(ctx, statement.query, statement.args...); err != nil {
			return err
		}
	}
	return nil
}

func assertRevisionSupportCount(
	t *testing.T,
	pool *pgxpool.Pool,
	tenantScopeID, groupID uuid.UUID,
	revision int64,
	wantEndpoints, wantHealth int,
	wantSealed bool,
) {
	t.Helper()
	var endpoints, health int
	var sealed bool
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM node_line_endpoints WHERE tenant_scope_id=$1 AND line_group_id=$2 AND config_revision=$3),
		(SELECT count(*) FROM node_line_endpoint_health WHERE tenant_scope_id=$1 AND line_group_id=$2 AND config_revision=$3),
		(SELECT sealed_at IS NOT NULL FROM node_line_group_revisions
		 WHERE tenant_scope_id=$1 AND line_group_id=$2 AND revision=$3)`,
		tenantScopeID, groupID, revision).Scan(&endpoints, &health, &sealed); err != nil {
		t.Fatal(err)
	}
	if endpoints != wantEndpoints || health != wantHealth || sealed != wantSealed {
		t.Fatalf("revision support endpoints=%d health=%d sealed=%t, want %d/%d/%t",
			endpoints, health, sealed, wantEndpoints, wantHealth, wantSealed)
	}
}

func execNodeSchedulingMigration(ctx context.Context, pool *pgxpool.Pool, direction string) error {
	script, err := fs.ReadFile(migrations.FS, "033_node_scheduling."+direction+".sql")
	if err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, string(script))
		return err
	})
}

func migrateNodeSchedulingUpTo(t *testing.T, pool *pgxpool.Pool, target int) {
	t.Helper()
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".up.sql") {
			continue
		}
		version, err := strconv.Atoi(name[:3])
		if err != nil {
			t.Fatal(err)
		}
		if version > target {
			break
		}
		script, err := fs.ReadFile(migrations.FS, name)
		if err != nil {
			t.Fatal(err)
		}
		if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			_, err := tx.Exec(t.Context(), string(script))
			return err
		}); err != nil {
			t.Fatalf("apply %s: %v", name, err)
		}
	}
}

func assertNodeSchedulingTable(t *testing.T, pool *pgxpool.Pool, exists bool) {
	t.Helper()
	var actual bool
	if err := pool.QueryRow(t.Context(), `SELECT to_regclass('node_line_groups') IS NOT NULL`).Scan(&actual); err != nil {
		t.Fatal(err)
	}
	if actual != exists {
		t.Fatalf("node_line_groups exists = %t, want %t", actual, exists)
	}
}
