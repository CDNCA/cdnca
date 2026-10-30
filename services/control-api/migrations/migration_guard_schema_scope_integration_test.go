//go:build integration

package migrations_test

import (
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// seedSiblingSchemaConstraints creates another schema in the same database that carries
// CHECK constraints with the given names, like a second control-api schema (or a
// parallel test schema) at or beyond the same release. Release-head guards must only
// count the catalog rows of the schema being migrated.
func seedSiblingSchemaConstraints(t *testing.T, pool *pgxpool.Pool, names ...string) {
	t.Helper()
	schema := pgx.Identifier{"guard_sibling_" + strings.ReplaceAll(uuid.NewString(), "-", "")}.Sanitize()
	checks := make([]string, 0, len(names))
	for _, name := range names {
		checks = append(checks, "CONSTRAINT "+pgx.Identifier{name}.Sanitize()+" CHECK (value > 0)")
	}
	if _, err := pool.Exec(t.Context(), "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create sibling schema: %v", err)
	}
	if _, err := pool.Exec(t.Context(), "CREATE TABLE "+schema+".guard_names(value integer, "+
		strings.Join(checks, ", ")+")"); err != nil {
		t.Fatalf("seed sibling schema constraints: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := databasetest.CleanupContext()
		defer cancel()
		if _, err := pool.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Errorf("drop sibling schema: %v", err)
		}
	})
}
