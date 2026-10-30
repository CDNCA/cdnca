package databasetest

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TemplateSchema is the schema that holds the migrated objects inside a
// template built by migrations.TestBuildMigrationTemplate.
const TemplateSchema = "migrated"

var templateName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,40}$`)

// ClonedMigratedPool returns a pool on a fresh copy of TEST_DATABASE_TEMPLATE
// (search_path=migrated), migrated up to the release head, or nil when no
// template is configured so the caller can migrate from scratch. The clone is
// dropped on cleanup.
func ClonedMigratedPool(t testing.TB, configure func(*pgxpool.Config)) *pgxpool.Pool {
	t.Helper()
	template := strings.TrimSpace(os.Getenv("TEST_DATABASE_TEMPLATE"))
	if template == "" {
		return nil
	}
	if !templateName.MatchString(template) {
		t.Fatalf("unsafe TEST_DATABASE_TEMPLATE %q", template)
	}
	base := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if base == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	// TEST_DATABASE_TEMPLATE_STRATEGY=file_copy avoids WAL-logging the whole
	// template (PG 15+ default wal_log), which takes ~40s per clone under load.
	strategy := ""
	switch value := strings.ToLower(strings.TrimSpace(os.Getenv("TEST_DATABASE_TEMPLATE_STRATEGY"))); value {
	case "":
	case "file_copy", "wal_log":
		strategy = " STRATEGY " + value
	default:
		t.Fatalf("unsupported TEST_DATABASE_TEMPLATE_STRATEGY %q", value)
	}
	clone := "tpl_clone_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:20]
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+clone+" TEMPLATE "+template+strategy); err != nil {
		_ = admin.Close(ctx)
		t.Fatalf("clone %s: %v", template, err)
	}
	t.Cleanup(func() {
		// Under load a short budget left tpl_clone_* databases behind; a failed
		// drop is reported but does not fail the test that already passed.
		dropCtx, dropCancel := CleanupContext()
		defer dropCancel()
		if _, err := admin.Exec(dropCtx, "DROP DATABASE IF EXISTS "+clone+" WITH (FORCE)"); err != nil {
			t.Logf("drop template clone %s (left behind): %v", clone, err)
		}
		_ = admin.Close(dropCtx)
	})
	config, err := pgxpool.ParseConfig(base)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.Database = clone
	config.ConnConfig.RuntimeParams["search_path"] = TemplateSchema
	if configure != nil {
		configure(config)
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	// Catch a stale template up to the release head (and re-verify checksums).
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatalf("migrate template clone up: %v", err)
	}
	return pool
}
