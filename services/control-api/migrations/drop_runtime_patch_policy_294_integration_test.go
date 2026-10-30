//go:build integration

package migrations_test

import (
	"slices"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestDropRuntimePatchPolicyMigration checks that 294 drops the 156 runtime patch
// policy structures and that its down rebuilds exactly what 156 created.
func TestDropRuntimePatchPolicyMigration(t *testing.T) {
	const version = 294
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	want := runtimePatchPolicyFingerprint294(t, pool)
	if len(want) == 0 {
		t.Fatal("293 schema has no runtime patch policy objects")
	}
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up %d: %v", version, err)
	}
	if got := runtimePatchPolicyFingerprint294(t, pool); len(got) != 0 {
		t.Fatalf("runtime patch policy objects remain after 294: %v", got)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down %d: %v", version, err)
	}
	if got := runtimePatchPolicyFingerprint294(t, pool); !slices.Equal(got, want) {
		for _, line := range want {
			if !slices.Contains(got, line) {
				t.Errorf("missing after 294 down: %s", line)
			}
		}
		for _, line := range got {
			if !slices.Contains(want, line) {
				t.Errorf("unexpected after 294 down: %s", line)
			}
		}
		t.FailNow()
	}
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("re-up %d: %v", version, err)
	}
}

func runtimePatchPolicyFingerprint294(t *testing.T, pool *pgxpool.Pool) []string {
	t.Helper()
	rows, err := pool.Query(t.Context(), `
		SELECT 'column '||c.relname||'.'||a.attname||' '||format_type(a.atttypid,a.atttypmod)||
		       ' notnull='||a.attnotnull||' default='||COALESCE(pg_get_expr(d.adbin,d.adrelid),'')
		FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
		LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum
		WHERE c.relnamespace=current_schema()::regnamespace AND c.relname LIKE 'runtime\_patch\_policy\_%'
		UNION ALL
		SELECT 'table '||c.relname||' acl='||COALESCE(c.relacl::text,'')
		FROM pg_class c WHERE c.relnamespace=current_schema()::regnamespace AND c.relkind='r' AND
		     c.relname LIKE 'runtime\_patch\_policy\_%'
		UNION ALL
		SELECT 'constraint '||c.relname||'.'||k.conname||' '||pg_get_constraintdef(k.oid)
		FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid
		WHERE c.relnamespace=current_schema()::regnamespace AND c.relname LIKE 'runtime\_patch\_policy\_%'
		UNION ALL
		SELECT 'index '||indexname||' '||indexdef FROM pg_indexes
		WHERE schemaname=current_schema() AND tablename LIKE 'runtime\_patch\_policy\_%'
		UNION ALL
		SELECT 'trigger '||c.relname||'.'||g.tgname||' '||pg_get_triggerdef(g.oid)
		FROM pg_trigger g JOIN pg_class c ON c.oid=g.tgrelid
		WHERE c.relnamespace=current_schema()::regnamespace AND c.relname LIKE 'runtime\_patch\_policy\_%' AND
		      NOT g.tgisinternal
		UNION ALL
		SELECT 'function '||p.oid::regprocedure::text||' secdef='||p.prosecdef||
		       ' config='||COALESCE(array_to_string(p.proconfig,','),'')||
		       ' acl='||COALESCE(p.proacl::text,'')||' body='||md5(p.prosrc)
		FROM pg_proc p WHERE p.pronamespace=current_schema()::regnamespace AND p.proname LIKE '%runtime\_patch\_policy%'
	`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var lines []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		lines = append(lines, line)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	slices.Sort(lines)
	return lines
}
