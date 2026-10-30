//go:build integration

package migrations_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestEdgeTargetSnapshots074MigrationRoundTrip(t *testing.T) {
	pool, cleanup := newEdgeTargetSnapshots074Pool(t)
	defer cleanup()

	if err := applyEdgeTargetSnapshot074Down(t.Context(), pool); err != nil {
		t.Fatal(err)
	}
	assertEdgeTargetSnapshotMigrationState(t, pool, 73, false)

	if err := applyEdgeTargetSnapshot074Up(t.Context(), pool, edgeTargetSnapshot074Migrations[4]); err != nil {
		t.Fatal(err)
	}
	assertEdgeTargetSnapshotMigrationState(t, pool, 74, true)
}

func TestEdgeTargetSnapshots074DownRejectsExistingFacts(t *testing.T) {
	for _, fact := range []string{"snapshot", "binding"} {
		t.Run(fact, func(t *testing.T) {
			pool, cleanup := newEdgeTargetSnapshots074Pool(t)
			defer cleanup()
			fixture := seedEdgeTargetSnapshot074(t, pool, fact, fact == "binding")
			if fact == "snapshot" {
				if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
					return insertEdgeTargetSnapshot074Facts(t.Context(), tx, fixture)
				}); err != nil {
					t.Fatal(err)
				}
			}

			assertEdgeTargetSnapshot074PGCode(t, applyEdgeTargetSnapshot074Down(t.Context(), pool), "55000")
			assertEdgeTargetSnapshotMigrationState(t, pool, 74, true)
		})
	}
}

func TestEdgeTargetSnapshots074DownSerializesUncommittedWriter(t *testing.T) {
	downScript, err := controlmigrations.FS.ReadFile("074_edge_target_snapshots.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	const lockPrefix = "LOCK TABLE node_line_endpoints IN ACCESS EXCLUSIVE MODE;\n" +
		"LOCK TABLE edge_target_snapshots IN ACCESS EXCLUSIVE MODE;\n" +
		"LOCK TABLE edge_target_snapshot_nodes IN ACCESS EXCLUSIVE MODE;\n\n"
	if !strings.HasPrefix(string(downScript), lockPrefix) {
		t.Fatal("074 down must lock endpoint, snapshot parent, and snapshot child facts before inspection")
	}

	pool, cleanup := newEdgeTargetSnapshots074Pool(t)
	defer cleanup()
	fixture := seedEdgeTargetSnapshot074(t, pool, "race", false)

	writer, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Rollback(context.WithoutCancel(t.Context()))
	var writerPID int
	if err := writer.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&writerPID); err != nil {
		t.Fatal(err)
	}
	if err := insertEdgeTargetSnapshot074Facts(t.Context(), writer, fixture); err != nil {
		t.Fatal(err)
	}

	const applicationName = "edge_target_snapshot_074_down_waiter"
	downPool := newEdgeTargetSnapshot074MigrationPool(t, pool, applicationName)
	defer downPool.Close()
	downContext, cancelDown := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancelDown()
	downConn, err := downPool.Acquire(downContext)
	if err != nil {
		t.Fatal(err)
	}
	var downPID int
	if err := downConn.QueryRow(downContext, `SELECT pg_backend_pid()`).Scan(&downPID); err != nil {
		downConn.Release()
		t.Fatal(err)
	}
	downResult := make(chan error, 1)
	go func() {
		err := applyEdgeTargetSnapshot074Down(downContext, downConn)
		downConn.Release()
		downResult <- err
	}()
	waitEdgeTargetSnapshot074Blocked(t, pool, writerPID, downPID)

	if err := writer.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-downResult:
		assertEdgeTargetSnapshot074PGCode(t, err, "55000")
	case <-downContext.Done():
		t.Fatalf("wait for overlapping 074 down: %v", downContext.Err())
	}

	assertEdgeTargetSnapshotMigrationState(t, pool, 74, true)
	var parents, children int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM edge_target_snapshots WHERE tenant_scope_id=$1 AND id=$2),
		(SELECT count(*) FROM edge_target_snapshot_nodes WHERE tenant_scope_id=$1 AND snapshot_id=$2)`,
		fixture.scopeID, fixture.snapshotID).Scan(&parents, &children); err != nil {
		t.Fatal(err)
	}
	if parents != 1 || children != 1 {
		t.Fatalf("committed facts after rejected down parent=%d child=%d", parents, children)
	}
}

type edgeTargetSnapshot074Fixture struct {
	scopeID, userID, nodeID, groupID, endpointID, snapshotID uuid.UUID
}

type edgeTargetSnapshot074Migration struct {
	version    int64
	identifier string
}

var edgeTargetSnapshot074Migrations = [...]edgeTargetSnapshot074Migration{
	{version: 70, identifier: "070_iam_global_lock_stage2_authority"},
	{version: 71, identifier: "071_iam_stage2b_package_adoption"},
	{version: 72, identifier: "072_challenge_policy_idempotency_retention"},
	{version: 73, identifier: "073_identity_membership_mutation"},
	{version: 74, identifier: "074_edge_target_snapshots"},
}

func seedEdgeTargetSnapshot074(t *testing.T, pool *pgxpool.Pool, suffix string, bindEndpoint bool) edgeTargetSnapshot074Fixture {
	t.Helper()
	fixture := edgeTargetSnapshot074Fixture{
		scopeID: uuid.New(), userID: uuid.New(), nodeID: uuid.New(),
		groupID: uuid.New(), endpointID: uuid.New(), snapshotID: uuid.New(),
	}
	tenantID := uuid.New()
	username := "snapshot074" + strings.ReplaceAll(fixture.userID.String(), "-", "")[:18]
	var endpointNodeID any
	if bindEndpoint {
		endpointNodeID = fixture.nodeID
	}
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		statements := []struct {
			query string
			args  []any
		}{
			{`INSERT INTO tenants(id,display_name) VALUES($1,$2)`, []any{tenantID, "074 " + suffix}},
			{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{fixture.scopeID, tenantID}},
			{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,$3,'hash')`, []any{fixture.userID, username, "074 " + suffix}},
			{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{fixture.scopeID, fixture.userID}},
			{`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id) VALUES($1,$2,$3,'active',$4)`, []any{fixture.nodeID, fixture.scopeID, "074 " + suffix, fixture.userID}},
			{`INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,created_by_user_id,updated_by_user_id,created_at,updated_at)
			 VALUES($1,$2,$3,1,$4,$4,now(),now())`, []any{fixture.groupID, fixture.scopeID, "074 " + suffix, fixture.userID}},
			{`INSERT INTO node_line_group_revisions(line_group_id,tenant_scope_id,revision,name,probe_interval_ms,probe_timeout_ms,
			 failure_threshold,recovery_threshold,failure_debounce_ms,recovery_debounce_ms,endpoint_count,configuration_digest,created_by_user_id,created_at)
			 VALUES($1,$2,1,$3,10000,3000,3,3,0,0,1,$4,$5,now())`, []any{fixture.groupID, fixture.scopeID, "074 " + suffix, make([]byte, 32), fixture.userID}},
			{`INSERT INTO node_line_endpoints(id,tenant_scope_id,line_group_id,config_revision,address,address_family,port,region,carrier,priority,weight,enabled,node_id)
			 VALUES($1,$2,$3,1,'192.0.2.74',4,443,'','',0,1,true,$4)`, []any{fixture.endpointID, fixture.scopeID, fixture.groupID, endpointNodeID}},
			{`INSERT INTO node_line_endpoint_health(tenant_scope_id,line_group_id,config_revision,endpoint_id,status,
			 consecutive_successes,consecutive_failures,last_sequence,last_changed_at,row_revision,created_at,updated_at)
			 VALUES($1,$2,1,$3,'unknown',0,0,0,now(),1,now(),now())`, []any{fixture.scopeID, fixture.groupID, fixture.endpointID}},
		}
		if _, err := tx.Exec(t.Context(), `SET CONSTRAINTS ALL DEFERRED`); err != nil {
			return err
		}
		for _, statement := range statements {
			if _, err := tx.Exec(t.Context(), statement.query, statement.args...); err != nil {
				return err
			}
		}
		_, err := tx.Exec(t.Context(), `UPDATE node_line_group_revisions SET sealed_at=now()
			WHERE tenant_scope_id=$1 AND line_group_id=$2 AND revision=1`, fixture.scopeID, fixture.groupID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func insertEdgeTargetSnapshot074Facts(ctx context.Context, tx pgx.Tx, fixture edgeTargetSnapshot074Fixture) error {
	if _, err := tx.Exec(ctx, `INSERT INTO edge_target_snapshots(
		id,tenant_scope_id,revision,source_line_group_id,source_revision,
		source_configuration_digest,node_set_digest,node_count,created_at)
		VALUES($1,$2,1,$3,1,$4,$4,1,now())`,
		fixture.snapshotID, fixture.scopeID, fixture.groupID, make([]byte, 32)); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO edge_target_snapshot_nodes(
		tenant_scope_id,snapshot_id,snapshot_revision,node_id)
		VALUES($1,$2,1,$3)`, fixture.scopeID, fixture.snapshotID, fixture.nodeID)
	return err
}

func newEdgeTargetSnapshots074Pool(t *testing.T) (*pgxpool.Pool, func()) {
	t.Helper()
	pool, cleanup := new069Pool(t)
	migrate069(t, pool, "up")
	for _, migration := range edgeTargetSnapshot074Migrations {
		if err := applyEdgeTargetSnapshot074Up(t.Context(), pool, migration); err != nil {
			cleanup()
			t.Fatalf("apply migration %d: %v", migration.version, err)
		}
	}
	assertEdgeTargetSnapshotMigrationState(t, pool, 74, true)
	return pool, cleanup
}

func applyEdgeTargetSnapshot074Up(ctx context.Context, pool *pgxpool.Pool, migration edgeTargetSnapshot074Migration) error {
	upScript, err := controlmigrations.FS.ReadFile(migration.identifier + ".up.sql")
	if err != nil {
		return err
	}
	downScript, err := controlmigrations.FS.ReadFile(migration.identifier + ".down.sql")
	if err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, string(upScript)); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO schema_migrations(
			version,migration_id,checksum_sha256,down_checksum_sha256,integrity_state,metadata_recorded_at)
			VALUES($1,$2,$3,$4,'verified',now())`, migration.version, migration.identifier,
			fmt.Sprintf("%x", sha256.Sum256(upScript)), fmt.Sprintf("%x", sha256.Sum256(downScript)))
		return err
	})
}

func applyEdgeTargetSnapshot074Down(ctx context.Context, db interface {
	Begin(context.Context) (pgx.Tx, error)
}) error {
	migration := edgeTargetSnapshot074Migrations[4]
	downScript, err := controlmigrations.FS.ReadFile(migration.identifier + ".down.sql")
	if err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, string(downScript)); err != nil {
			return err
		}
		command, err := tx.Exec(ctx, `DELETE FROM schema_migrations WHERE version=$1`, migration.version)
		if err == nil && command.RowsAffected() != 1 {
			return fmt.Errorf("delete 074 ledger rows = %d, want 1", command.RowsAffected())
		}
		return err
	})
}

func newEdgeTargetSnapshot074MigrationPool(t *testing.T, pool *pgxpool.Pool, applicationName string) *pgxpool.Pool {
	t.Helper()
	config := pool.Config()
	config.MaxConns = 1
	config.MinConns = 0
	config.ConnConfig.RuntimeParams["application_name"] = applicationName
	config.ConnConfig.RuntimeParams["lock_timeout"] = "10s"
	config.ConnConfig.RuntimeParams["statement_timeout"] = "12s"
	migrationPool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	return migrationPool
}

func waitEdgeTargetSnapshot074Blocked(t *testing.T, pool *pgxpool.Pool, writerPID, downPID int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var blocked bool
		if err := pool.QueryRow(ctx,
			`SELECT $1::integer = ANY(pg_catalog.pg_blocking_pids($2::integer))`,
			writerPID, downPID).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for 074 down backend %d to block on writer backend %d",
				downPID, writerPID)
		case <-ticker.C:
		}
	}
}

func assertEdgeTargetSnapshot074PGCode(t *testing.T, err error, want string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != want {
		t.Fatalf("PostgreSQL error = %v, want SQLSTATE %s", err, want)
	}
}

func assertEdgeTargetSnapshotMigrationState(t *testing.T, pool *pgxpool.Pool, wantVersion int64, wantTables bool) {
	t.Helper()
	var version int64
	var snapshots, snapshotNodes, hasNodeID bool
	if err := pool.QueryRow(t.Context(), `SELECT COALESCE(max(version),0) FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT to_regclass('edge_target_snapshots') IS NOT NULL,
		to_regclass('edge_target_snapshot_nodes') IS NOT NULL,
		exists (SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema()
			AND table_name='node_line_endpoints' AND column_name='node_id')`).Scan(&snapshots, &snapshotNodes, &hasNodeID); err != nil {
		t.Fatal(err)
	}
	if version != wantVersion || snapshots != wantTables || snapshotNodes != wantTables || hasNodeID != wantTables {
		t.Fatalf("migration state version=%d snapshots=%t nodes=%t endpoint_node_id=%t", version, snapshots, snapshotNodes, hasNodeID)
	}
}
