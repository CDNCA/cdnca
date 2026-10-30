//go:build integration

package migrations_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 1.0.35 migrations without a dedicated UpDownUp case (AUDIT-FINAL-1027 L3):
// from the exact predecessor head, up -> down -> up. Rollback must restore the
// predecessor schema object for object (tables, columns, constraints, indexes,
// triggers, functions, grants), and the second up must rebuild the same head.
// The version downgrade gate (G7) relies on these rollbacks being exact.
//
// Known rollback differences are listed with their reason; every other object
// must match exactly, and a listed object must still exist on both sides.
func TestRelease1035MigrationsUpDownUp(t *testing.T) {
	known := map[int64][]string{
		// By design (531 down comment): the body keeps $1/$2 instead of 048's
		// column-shadowed comparison, which let members of other tenants pass.
		531: {"function acme_runtime_actor_is_active_048(uuid,uuid) "},
		// Defects (fix-finalgaps, pending main-session decision): 532 down
		// restores 047 to its pre-531 body instead of 531's (platform members
		// refused after rolling back to 531), and 532 up/down both re-create
		// 084 without SECURITY DEFINER / SET search_path from 084. Neither
		// script can change: 73 records both checksums and 533 pins them.
		532: {"function validate_acme_issuance_operation_snapshot_047() ",
			"function validate_plugin_webhook_actor_target_084() "},
	}
	for _, version := range []int64{531, 532, 535, 536, 538, 540, 542, 543} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			// Built upward from migration 1 (never through a down script),
			// so "before" is the predecessor as a fresh install has it.
			pool := migrationSnapshotPool(t, version-1)
			ctx := t.Context()
			before := migrationSchemaFingerprint(t, pool)
			if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
				t.Fatalf("up %d: %v", version, err)
			}
			applied := migrationSchemaFingerprint(t, pool)
			if slices.Equal(before, applied) {
				t.Fatalf("up %d changed no schema object", version)
			}
			if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
				t.Fatalf("down %d: %v", version, err)
			}
			assertMigrationSchemaEqual(t, fmt.Sprintf("down %d vs %d", version, version-1),
				withoutKnown(t, before, known[version]), withoutKnown(t, migrationSchemaFingerprint(t, pool), known[version]))
			if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
				t.Fatalf("up again %d: %v", version, err)
			}
			assertMigrationSchemaEqual(t, fmt.Sprintf("up again %d vs first up", version),
				applied, migrationSchemaFingerprint(t, pool))
		})
	}
}

// migrationSchemaFingerprint lists every schema object of the pool's current
// schema with its full definition, sorted. Function bodies are compared by
// pg_get_functiondef so a rollback that keeps a newer body is caught.
func migrationSchemaFingerprint(t *testing.T, pool *pgxpool.Pool) []string {
	t.Helper()
	rows, err := pool.Query(t.Context(), `
		SELECT 'relation ' || c.relname || ' ' || c.relkind::text || ' acl=' || COALESCE(c.relacl::text, '')
		FROM pg_class c WHERE c.relnamespace = current_schema()::regnamespace AND c.relkind IN ('r','v','m','S','p')
		UNION ALL
		SELECT 'column ' || c.relname || '.' || a.attname || ' ' || format_type(a.atttypid, a.atttypmod) ||
			CASE WHEN a.attnotnull THEN ' not null' ELSE '' END || ' default=' || COALESCE(pg_get_expr(d.adbin, d.adrelid), '')
		FROM pg_attribute a
		JOIN pg_class c ON c.oid = a.attrelid AND c.relnamespace = current_schema()::regnamespace AND c.relkind IN ('r','v','m','p')
		LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
		WHERE a.attnum > 0 AND NOT a.attisdropped
		UNION ALL
		SELECT 'constraint ' || c.relname || '.' || k.conname || ' ' || pg_get_constraintdef(k.oid)
		FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid
		WHERE k.connamespace = current_schema()::regnamespace
		UNION ALL
		SELECT 'index ' || pg_get_indexdef(i.indexrelid)
		FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
		WHERE c.relnamespace = current_schema()::regnamespace
		UNION ALL
		SELECT 'trigger ' || pg_get_triggerdef(g.oid) || ' enabled=' || g.tgenabled::text
		FROM pg_trigger g JOIN pg_class c ON c.oid = g.tgrelid
		WHERE c.relnamespace = current_schema()::regnamespace AND NOT g.tgisinternal
		UNION ALL
		SELECT 'function ' || p.oid::regprocedure::text || ' acl=' || COALESCE(p.proacl::text, '') || E'\n' ||
			CASE WHEN p.prokind IN ('f','p','w') THEN pg_get_functiondef(p.oid) ELSE p.prokind::text END
		FROM pg_proc p WHERE p.pronamespace = current_schema()::regnamespace AND p.prokind <> 'a'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var item string
		if err := rows.Scan(&item); err != nil {
			t.Fatal(err)
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	slices.Sort(out)
	return out
}

// withoutKnown drops the objects whose first line starts with one of prefixes,
// failing if one of them is absent.
func withoutKnown(t *testing.T, items, prefixes []string) []string {
	t.Helper()
	out := make([]string, 0, len(items))
	seen := map[string]bool{}
	for _, item := range items {
		skip := false
		for _, prefix := range prefixes {
			if strings.HasPrefix(item, prefix) {
				skip, seen[prefix] = true, true
			}
		}
		if !skip {
			out = append(out, item)
		}
	}
	for _, prefix := range prefixes {
		if !seen[prefix] {
			t.Errorf("known rollback difference %q: object missing", prefix)
		}
	}
	return out
}

func assertMigrationSchemaEqual(t *testing.T, label string, want, got []string) {
	t.Helper()
	var missing, extra []string
	for _, item := range want {
		if _, ok := slices.BinarySearch(got, item); !ok {
			missing = append(missing, item)
		}
	}
	for _, item := range got {
		if _, ok := slices.BinarySearch(want, item); !ok {
			extra = append(extra, item)
		}
	}
	if len(missing) == 0 && len(extra) == 0 {
		return
	}
	// An object present on both sides with a different definition is shown
	// as the lines that differ; the rest as their first line.
	head := func(item string) string { first, _, _ := strings.Cut(item, "\n"); return first }
	byHead := map[string]string{}
	for _, item := range extra {
		byHead[head(item)] = item
	}
	var report []string
	for _, item := range missing {
		other, changed := byHead[head(item)]
		if !changed {
			report = append(report, "missing "+head(item))
			continue
		}
		delete(byHead, head(item))
		report = append(report, "changed "+head(item))
		wantLines, gotLines := strings.Split(item, "\n"), strings.Split(other, "\n")
		for _, line := range wantLines {
			if !slices.Contains(gotLines, line) {
				report = append(report, "    - "+line)
			}
		}
		for _, line := range gotLines {
			if !slices.Contains(wantLines, line) {
				report = append(report, "    + "+line)
			}
		}
	}
	for _, item := range byHead {
		report = append(report, "unexpected "+head(item))
	}
	t.Errorf("%s:\n%s", label, strings.Join(report, "\n"))
}
