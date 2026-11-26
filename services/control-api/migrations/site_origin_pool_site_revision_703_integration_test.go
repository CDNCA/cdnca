//go:build integration

package migrations_test

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// TestSiteOriginPoolSiteRevision703UpDownUp rolls the origin pool version column up, down and up again on the
// 702 head; it is nullable and refuses a value below 1. (Its writers and the billing bridge origin edit run in the
// site and billingbridge integration tests.)
func TestSiteOriginPoolSiteRevision703UpDownUp(t *testing.T) {
	const version = 703
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	present := func() bool {
		t.Helper()
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns
			WHERE table_schema=current_schema() AND table_name='site_origin_pools' AND column_name='site_revision')`).
			Scan(&exists); err != nil {
			t.Fatal(err)
		}
		return exists
	}
	for _, step := range []struct {
		direction string
		present   bool
	}{{"up", true}, {"down", false}, {"up", true}} {
		if err := migrateVersionIsolated(ctx, pool, step.direction, version); err != nil {
			t.Fatalf("%s %d: %v", step.direction, version, err)
		}
		if got := present(); got != step.present {
			t.Fatalf("after %s: column present=%v", step.direction, got)
		}
	}
	var nullable string
	if err := pool.QueryRow(ctx, `SELECT is_nullable FROM information_schema.columns
		WHERE table_schema=current_schema() AND table_name='site_origin_pools' AND column_name='site_revision'`).
		Scan(&nullable); err != nil || nullable != "YES" {
		t.Fatalf("site_revision nullable=%q err=%v, want YES", nullable, err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// The FKs and pool triggers are not what this checks: insert with them off, then check the constraint.
	if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	var databaseError *pgconn.PgError
	if _, err := tx.Exec(ctx, `INSERT INTO site_origin_pools(site_id,updated_at,site_revision) VALUES(gen_random_uuid(),now(),0)`); !errors.As(err, &databaseError) ||
		databaseError.Code != "23514" {
		t.Fatalf("insert site_revision 0: %v, want 23514", err)
	}
}
