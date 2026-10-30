//go:build integration

package migrations_test

import (
	"testing"

	"github.com/google/uuid"
)

// TestPackageExpiryRepublication511 (errpage-5, 待出包前全量跑): up/down/up;
// after up the trigger package_expiry is accepted by the three constraints
// and package_expiry_republication_marks exists, after down neither; down is
// refused (P5112) while a package_expiry head is left, and allowed again
// once it is gone.
//
//	TEST_DATABASE_URL=... go -C services/control-api test -tags integration -count=1 \
//	  -run TestPackageExpiryRepublication511 ./migrations/
func TestPackageExpiryRepublication511(t *testing.T) {
	const version = 511
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	tenantID, scopeID := uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,'511 tenant')`, tenantID)
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID)

	marksTable := func() bool {
		t.Helper()
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT to_regclass(current_schema()||'.package_expiry_republication_marks') IS NOT NULL`).
			Scan(&exists); err != nil {
			t.Fatal(err)
		}
		return exists
	}
	insertHead := func() error {
		_, err := pool.Exec(ctx, `INSERT INTO edge_system_republication_heads(scope_id,generation,state,triggers,due_at,attempt,
			created_at,updated_at) VALUES($1,1,'pending',ARRAY['package_expiry'],clock_timestamp(),0,clock_timestamp(),clock_timestamp())`,
			scopeID)
		return err
	}
	insertSegment := func() error {
		_, err := pool.Exec(ctx, `INSERT INTO edge_system_revision_segments(scope_id,from_revision,to_revision,source,recorded_at)
			VALUES($1,1,2,'package_expiry',clock_timestamp())`, scopeID)
		return err
	}
	if err := insertHead(); sqlState(err) != "23514" {
		t.Fatalf("510 accepts trigger package_expiry: %v", err)
	}
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
		if got := marksTable(); got != (step == "up") {
			t.Fatalf("after %s: marks table %t", step, got)
		}
	}
	if err := insertHead(); err != nil {
		t.Fatalf("511 refuses trigger package_expiry: %v", err)
	}
	if err := insertSegment(); err != nil {
		t.Fatalf("511 refuses segment source package_expiry: %v", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P5112" {
		t.Fatalf("down with package_expiry rows: %v, want P5112", err)
	}
	if !marksTable() {
		t.Fatal("refused down dropped the marks table")
	}
	mustExec(t, pool, `DELETE FROM edge_system_republication_heads WHERE scope_id=$1`, scopeID)
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P5112" {
		t.Fatalf("down with a package_expiry segment: %v, want P5112", err)
	}
	mustExec(t, pool, `DELETE FROM edge_system_revision_segments WHERE scope_id=$1`, scopeID)
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down without package_expiry rows: %v", err)
	}
	if marksTable() {
		t.Fatal("down kept the marks table")
	}
	if err := insertHead(); sqlState(err) != "23514" {
		t.Fatalf("down accepts trigger package_expiry: %v", err)
	}
}
