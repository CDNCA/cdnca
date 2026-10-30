//go:build integration

package migrations_test

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestACMEHTTP01CleanupDebtMigration rolls 342 up, down and up on an empty
// schema (the backfill is a no-op there); down refuses once a debt fact
// exists.
func TestACMEHTTP01CleanupDebtMigration(t *testing.T) {
	const version = 342
	pool := migrationPoolAt(t, version-1)
	tables := []string{"acme_http01_site_overlay_states", "acme_http01_site_overlay_epochs",
		"acme_http01_site_overlay_epoch_members", "acme_http01_site_overlay_versions",
		"acme_http01_site_overlay_version_tokens", "acme_http01_node_challenge_epochs",
		"acme_http01_node_overlay_cleanup_debts", "acme_http01_node_overlay_generation_coverages",
		"acme_http01_node_overlay_cleanup_debt_events", "acme_http01_site_overlay_epoch_releases",
		"acme_http01_overlay_backfill_sites", "acme_http01_overlay_backfill_nodes",
		"acme_http01_overlay_backfill_quarantines"}
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(t.Context(), pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
		var present int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM unnest($1::text[]) name
			WHERE to_regclass(current_schema()||'.'||name) IS NOT NULL`, tables).Scan(&present); err != nil {
			t.Fatal(err)
		}
		if want := map[bool]int{true: len(tables), false: 0}[step == "up"]; present != want {
			t.Fatalf("after %s: %d of %d tables", step, present, len(tables))
		}
	}
	// A recorded backfill mark blocks the down migration (P0001).
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO acme_http01_overlay_backfill_nodes(node_id,state,reason_code,
			generation_floor,recorded_at,updated_at) VALUES(gen_random_uuid(),'pending','backfill_063',1,now(),now())`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	err := migrateVersionIsolated(t.Context(), pool, "down", version)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "P0001" {
		t.Fatalf("down with a backfill mark: %v", err)
	}
}
