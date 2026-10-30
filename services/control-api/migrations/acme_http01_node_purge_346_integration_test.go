//go:build integration

package migrations_test

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestACMEHTTP01NodePurgeMigration rolls 346 up, down and up: down restores
// 342's delete guards and epoch check exactly, and refuses once a purged
// member's tombstone exists.
func TestACMEHTTP01NodePurgeMigration(t *testing.T) {
	const version = 346
	pool := migrationPoolAt(t, version-1)
	catalog := func() string {
		var digest string
		if err := pool.QueryRow(t.Context(), `SELECT md5(string_agg(definition, E'\n' ORDER BY definition)) FROM (
			SELECT pg_get_triggerdef(trigger_row.oid) AS definition FROM pg_trigger trigger_row
			JOIN pg_class class_row ON class_row.oid=trigger_row.tgrelid
			WHERE class_row.relname LIKE 'acme_http01_%' AND NOT trigger_row.tgisinternal
			UNION ALL
			SELECT pg_get_functiondef('validate_acme_http01_site_overlay_epoch_342'::regproc)) definitions`).Scan(&digest); err != nil {
			t.Fatal(err)
		}
		return digest
	}
	before := catalog()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(t.Context(), pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
		var present bool
		if err := pool.QueryRow(t.Context(), `SELECT to_regclass(current_schema()||'.acme_http01_site_overlay_epoch_purged_members') IS NOT NULL`).Scan(&present); err != nil {
			t.Fatal(err)
		}
		if present != (step == "up") {
			t.Fatalf("after %s: tombstone table present=%v", step, present)
		}
		if step == "down" && catalog() != before {
			t.Fatal("down did not restore the 342 triggers and epoch check")
		}
	}
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO acme_http01_site_overlay_epoch_purged_members(epoch_id,node_id,purged_at)
			VALUES(gen_random_uuid(),gen_random_uuid(),now())`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	err := migrateVersionIsolated(t.Context(), pool, "down", version)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "P0001" {
		t.Fatalf("down with a tombstone: %v", err)
	}
}
