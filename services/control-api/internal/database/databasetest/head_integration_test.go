//go:build integration

package databasetest

import (
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// A schema created by FreshSchemaPool must not see sibling schemas of the
// shared TEST_DATABASE_URL database: migration guards query
// information_schema without a table_schema filter, so a sibling at a later
// head made 580 refuse with P5800.
func TestFreshSchemaPoolIsolatesFromSharedDatabase(t *testing.T) {
	base := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if base == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	shared, err := pgx.Connect(t.Context(), base)
	if err != nil {
		t.Fatal(err)
	}
	defer shared.Close(t.Context())
	sibling := pgx.Identifier{"fresh_sibling_probe"}.Sanitize()
	if _, err := shared.Exec(t.Context(), "CREATE SCHEMA IF NOT EXISTS "+sibling+
		"; CREATE TABLE IF NOT EXISTS "+sibling+".analytics_log_exports_v1(scope_generation bigint)"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := CleanupContext()
		defer cancel()
		_, _ = shared.Exec(ctx, "DROP SCHEMA IF EXISTS "+sibling+" CASCADE")
	})

	pool := FreshSchemaPool(t, "fresh_isolation", nil, nil)
	var sharedDB, poolDB, schema string
	if err := shared.QueryRow(t.Context(), "SELECT current_database()").Scan(&sharedDB); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), "SELECT current_database(), current_schema()").Scan(&poolDB, &schema); err != nil {
		t.Fatal(err)
	}
	if poolDB == sharedDB || !strings.HasPrefix(schema, "fresh_isolation_") {
		t.Fatalf("pool database=%q schema=%q, shared database=%q", poolDB, schema, sharedDB)
	}
	var visible int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM information_schema.columns
		WHERE table_name='analytics_log_exports_v1' AND column_name='scope_generation'`).Scan(&visible); err != nil {
		t.Fatal(err)
	}
	if visible != 0 {
		t.Fatalf("fresh schema sees %d sibling scope_generation columns", visible)
	}
}
