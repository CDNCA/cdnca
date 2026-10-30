//go:build integration

package migrations_test

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

// TestEdgeSiteObjectsMigration rolls 354 up, down and up: the site object
// tables and the 256 MiB snapshot bound exist only while it is applied, the
// tables are append-only, and the 333 node artifact trigger is restored.
func TestEdgeSiteObjectsMigration(t *testing.T) {
	const version = 354
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
		var tables int
		var bound, trigger, compileBound string
		if err := pool.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM pg_class WHERE relnamespace=current_schema()::regnamespace AND relname IN
			  ('edge_site_object_keys','edge_site_objects','edge_site_object_publications')),
			(SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='config_versions'::regclass
			  AND contype='c' AND pg_get_constraintdef(oid) LIKE '%canonical_snapshot)%'),
			pg_get_functiondef('validate_security_policy_activation_node_artifact_333()'::regprocedure),
			(SELECT string_agg(pg_get_constraintdef(oid),' ') FROM pg_constraint
			  WHERE conrelid='edge_publication_compile_inputs'::regclass AND contype='c'
			    AND pg_get_constraintdef(oid) LIKE '%site_runtime_v2)::text)%')`).
			Scan(&tables, &bound, &trigger, &compileBound); err != nil {
			t.Fatal(err)
		}
		up := step == "up"
		if (tables == 3) != up || strings.Contains(bound, "268435456") != up ||
			strings.Contains(trigger, "edge-site-root") != up ||
			strings.Contains(compileBound, "16777216") != up || strings.Contains(compileBound, "4194304") == up {
			t.Fatalf("after %s: tables=%d bound=%s root-aware trigger=%v", step, tables, bound, strings.Contains(trigger, "edge-site-root"))
		}
	}

	scopeID := uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, scopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO edge_site_object_keys VALUES ($1,1,decode(repeat('ab',32),'hex'),now())`, scopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO edge_site_objects VALUES ($1,1,decode(repeat('cd',32),'hex'),'site',
		decode(repeat('00',16),'hex'),now())`, scopeID); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`UPDATE edge_site_objects SET kind='file'`,
		`DELETE FROM edge_site_object_keys`,
		`TRUNCATE edge_site_objects`,
	} {
		if _, err := pool.Exec(ctx, statement); err == nil || !strings.Contains(err.Error(), "P3542") &&
			!strings.Contains(err.Error(), "immutable") {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	// A recorded content key keeps the binary from rolling back.
	if err := migrateVersionIsolated(ctx, pool, "down", version); err == nil || !strings.Contains(err.Error(), "P3544") &&
		!strings.Contains(err.Error(), "retain site object") {
		t.Fatalf("down with site objects: %v", err)
	}
}
