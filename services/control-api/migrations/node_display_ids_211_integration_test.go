//go:build integration

package migrations_test

import (
	"context"
	"errors"
	"testing"
	"time"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestNodeDisplayIDs211RoundTripAndRollbackFence(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 210)
	platformScope, tenantScope := uuid.New(), uuid.New()
	tenantID, userID := uuid.New(), uuid.New()
	createdEarly := time.Date(2026, 8, 28, 1, 0, 0, 0, time.UTC)
	createdLate := createdEarly.Add(time.Hour)
	nodeLate := uuid.MustParse("11111111-1111-4111-8111-111111111113")
	nodeEarlyA := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	nodeEarlyB := uuid.MustParse("11111111-1111-4111-8111-111111111112")
	tenantNode := uuid.MustParse("22222222-2222-4222-8222-222222222221")

	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,'Node display tenant')`, []any{tenantID}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'platform',NULL),($2,'tenant',$3)`, []any{platformScope, tenantScope, tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'node-display-211','Node display 211','unused')`, []any{userID}},
		{`INSERT INTO nodes(id,scope_id,name,created_by_user_id,created_at,updated_at) VALUES
			($1,$4,'late',$5,$7,$7),($2,$4,'early-a',$5,$6,$6),($3,$4,'early-b',$5,$6,$6),
			($8,$9,'tenant-first',$5,$6,$6)`, []any{nodeLate, nodeEarlyA, nodeEarlyB, platformScope, userID, createdEarly, createdLate, tenantNode, tenantScope}},
	} {
		if _, err := pool.Exec(t.Context(), statement.query, statement.args...); err != nil {
			t.Fatalf("seed migration 211 fixture: %v", err)
		}
	}

	if err := migrateVersionIsolated(t.Context(), pool, "up", 211); err != nil {
		t.Fatalf("210 -> 211: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 211)
	assertNodeDisplayIDRows211(t, pool, map[uuid.UUID]int64{
		nodeEarlyA: 1,
		nodeEarlyB: 2,
		nodeLate:   3,
		tenantNode: 1,
	})
	var platformNext int64
	if err := pool.QueryRow(t.Context(), `SELECT next_value FROM node_display_id_sequences WHERE scope_id=$1`, platformScope).Scan(&platformNext); err != nil || platformNext != 4 {
		t.Fatalf("platform next_value=(%d,%v), want 4", platformNext, err)
	}
	var tenantSequenceCount int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM node_display_id_sequences WHERE scope_id=$1`, tenantScope).Scan(&tenantSequenceCount); err != nil || tenantSequenceCount != 0 {
		t.Fatalf("tenant sequence count=(%d,%v), want 0", tenantSequenceCount, err)
	}

	_, err := pool.Exec(t.Context(), `INSERT INTO nodes(id,scope_id,name,created_by_user_id) VALUES($1,$2,'missing-display-id',$3)`, uuid.New(), platformScope, userID)
	assertNodeDisplayIDPostgresCode211(t, err, "23502")
	_, err = pool.Exec(t.Context(), `INSERT INTO nodes(id,display_id,scope_id,name,created_by_user_id) VALUES($1,1,$2,'duplicate-display-id',$3)`, uuid.New(), platformScope, userID)
	assertNodeDisplayIDPostgresCode211(t, err, "23505")

	down, err := controlmigrations.FS.ReadFile("211_node_display_ids.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	fenced, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer fenced.Rollback(t.Context())
	if _, err := fenced.Exec(t.Context(), `INSERT INTO schema_migrations(
		version,migration_id,checksum_sha256,down_checksum_sha256,integrity_state,metadata_recorded_at,applied_at)
		VALUES(212,'unexpected_head',repeat('a',64),repeat('b',64),'verified',now(),now())`); err != nil {
		t.Fatal(err)
	}
	_, err = fenced.Exec(t.Context(), string(down))
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "P2110" {
		t.Fatalf("fenced rollback error = %v, want P2110", err)
	}
	if err := fenced.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !nodeDisplayIDColumnExists211(t, pool) {
		t.Fatal("rollback fence changed nodes.display_id")
	}

	if err := migrateVersionIsolated(t.Context(), pool, "down", 211); err != nil {
		t.Fatalf("211 -> 210: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 210)
	if nodeDisplayIDColumnExists211(t, pool) {
		t.Fatal("nodes.display_id remained after rollback")
	}
	var sequenceExists bool
	if err := pool.QueryRow(t.Context(), `SELECT to_regclass(current_schema() || '.node_display_id_sequences') IS NOT NULL`).Scan(&sequenceExists); err != nil || sequenceExists {
		t.Fatalf("node display sequence after rollback = (%v,%v)", sequenceExists, err)
	}
	var nodeCount int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM nodes`).Scan(&nodeCount); err != nil || nodeCount != 4 {
		t.Fatalf("node count after rollback = (%d,%v), want 4", nodeCount, err)
	}

	if err := migrateVersionIsolated(t.Context(), pool, "up", 211); err != nil {
		t.Fatalf("210 -> 211 reapply: %v", err)
	}
	assertNodeDisplayIDRows211(t, pool, map[uuid.UUID]int64{
		nodeEarlyA: 1,
		nodeEarlyB: 2,
		nodeLate:   3,
		tenantNode: 1,
	})
}

func assertNodeDisplayIDRows211(t *testing.T, pool interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}, expected map[uuid.UUID]int64) {
	t.Helper()
	for nodeID, want := range expected {
		var got int64
		if err := pool.QueryRow(t.Context(), `SELECT display_id FROM nodes WHERE id=$1`, nodeID).Scan(&got); err != nil || got != want {
			t.Fatalf("node %s display_id=(%d,%v), want %d", nodeID, got, err, want)
		}
	}
}

func nodeDisplayIDColumnExists211(t *testing.T, pool interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}) bool {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(t.Context(), `SELECT EXISTS(
		SELECT 1 FROM information_schema.columns
		WHERE table_schema=current_schema() AND table_name='nodes' AND column_name='display_id')`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	return exists
}

func assertNodeDisplayIDPostgresCode211(t *testing.T, err error, want string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != want {
		t.Fatalf("postgres error = %v, want %s", err, want)
	}
}
