//go:build integration

package migrations_test

import (
	"testing"

	"github.com/jackc/pgx/v5"
)

// TestCheckFunctionSearchPath659UpDownUp rolls the search_path pin on the
// CHECK-reachable validators up, down and up on the 658 head, and checks that every function
// is pinned after up and unpinned after down.
func TestCheckFunctionSearchPath659UpDownUp(t *testing.T) {
	const version = 659
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	pinned := func() int {
		t.Helper()
		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_proc p
			WHERE p.pronamespace=pg_catalog.to_regnamespace(current_schema())
			  AND p.proname IN ('announcement_codepoint_is_format','announcement_codepoint_is_go_space',
				'announcement_valid_body','announcement_valid_title','plugin_webhook_event_type_valid_122',
				'plugin_webhook_event_types_shape_122','valid_l4_origins_496','validate_l4_runtime_spec_496',
				'validate_l4_runtime_spec_506')
			  AND p.proconfig IS NOT NULL
			  AND EXISTS (SELECT 1 FROM unnest(p.proconfig) c WHERE c LIKE 'search_path=pg_catalog,%')`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	for _, step := range []struct {
		direction string
		want      int
	}{{"up", 9}, {"down", 0}, {"up", 9}} {
		if err := migrateVersionIsolated(ctx, pool, step.direction, version); err != nil {
			t.Fatalf("%s %d: %v", step.direction, version, err)
		}
		if got := pinned(); got != step.want {
			t.Fatalf("after %s: %d pinned functions, want %d", step.direction, got, step.want)
		}
	}
	// With an empty search_path (what pg_restore sets) a pinned validator must still resolve its helpers.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var schema string
	if err := tx.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('search_path','',true)`); err != nil {
		t.Fatal(err)
	}
	var valid bool
	if err := tx.QueryRow(ctx, `SELECT `+pgx.Identifier{schema}.Sanitize()+`.announcement_valid_title('audit')`).Scan(&valid); err != nil || !valid {
		t.Fatalf("announcement_valid_title under empty search_path: %v %v", valid, err)
	}
}
