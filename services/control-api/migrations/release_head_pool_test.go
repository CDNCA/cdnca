//go:build integration

package migrations_test

import (
	"io/fs"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
)

// releaseHeadMigrationPool returns a schema migrated to the release head. 1.0.35 is the
// initial release, so tests that exercise production runtime code (jobstate, analytics,
// audit chain) must run against the full schema instead of an early migration prefix.
// The template clone is used when the sharded runner provides one.
func releaseHeadMigrationPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if pool := databasetest.ClonedMigratedPool(t, nil); pool != nil {
		return pool
	}
	return packageCommerceRBAC079Pool(t, releaseHeadMigrationVersion(t))
}

func releaseHeadMigrationVersion(t *testing.T) int64 {
	t.Helper()
	matches, err := fs.Glob(controlmigrations.FS, "*.up.sql")
	if err != nil || len(matches) == 0 {
		t.Fatalf("list up migrations: matches=%d err=%v", len(matches), err)
	}
	return int64(len(matches))
}
