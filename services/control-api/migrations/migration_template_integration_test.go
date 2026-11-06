//go:build integration

package migrations_test

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Full migrations take many minutes on a loaded machine. A test that only
// needs "migrated through N" can clone a template database instead:
//
//	CDNCA_BUILD_MIGRATION_TEMPLATE=286 TEST_DATABASE_URL=<template db>?search_path=migrated go test -tags integration -run TestBuildMigrationTemplate
//	TEST_DATABASE_TEMPLATE=<template db name> TEST_DATABASE_URL=<any db on that server> go test ...
//
// Migrations require an owner-controlled schema (not public); the template
// keeps it in schema "migrated". Without TEST_DATABASE_TEMPLATE the caller
// falls back to migrating from scratch.

func TestBuildMigrationTemplate(t *testing.T) {
	raw := os.Getenv("CDNCA_BUILD_MIGRATION_TEMPLATE")
	if raw == "" {
		t.Skip("CDNCA_BUILD_MIGRATION_TEMPLATE is not set")
	}
	version, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || version < 1 {
		t.Fatalf("CDNCA_BUILD_MIGRATION_TEMPLATE=%q", raw)
	}
	pool, err := pgxpool.New(t.Context(), os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := migrateVersionIsolated(t.Context(), pool, "up", version); err != nil {
		t.Fatalf("migrate template through %d: %v", version, err)
	}
}

var templateName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,40}$`)

// migrationPoolAt returns a schema migrated through exactly version. A cloned
// template may stop below or above it (templates are rebuilt at the latest
// head), so the clone is rolled up or down one migration at a time; without a
// template the schema is migrated from scratch.
//
// Each step reloads and checks every embedded migration through version, so
// stepping a head template down hundreds of versions took most of the
// package's time (CPU in the migrator, not PostgreSQL). The schema reached for
// a version is kept as a database of this process (steppedSnapshot) and later
// requests clone the nearest kept one at or above it, stepping only the rest.
func migrationPoolAt(t *testing.T, version int64) *pgxpool.Pool {
	t.Helper()
	template := strings.TrimSpace(os.Getenv("TEST_DATABASE_TEMPLATE"))
	if template == "" {
		return packageCommerceRBAC079Pool(t, version)
	}
	if !templateName.MatchString(template) {
		t.Fatalf("unsafe TEST_DATABASE_TEMPLATE %q", template)
	}
	base := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if base == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	clone := "mig_clone_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:20]
	if err := cloneSteppedSnapshot(ctx, admin, base, template, version, clone); err != nil {
		_ = admin.Close(ctx)
		t.Fatalf("schema at %03d from %s: %v", version, template, err)
	}
	t.Cleanup(func() {
		dropCtx, dropCancel := databasetest.CleanupContext()
		defer dropCancel()
		if _, err := admin.Exec(dropCtx, "DROP DATABASE IF EXISTS "+clone+" WITH (FORCE)"); err != nil {
			t.Logf("drop template clone %s (left behind): %v", clone, err)
		}
		_ = admin.Close(dropCtx)
	})
	pool, err := snapshotDatabasePool(ctx, base, clone)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// maxSteppedSnapshots bounds disk use (a head schema is about 65 MB); the
// least recently used one is dropped.
const maxSteppedSnapshots = 16

var steppedSnapshots = struct {
	sync.Mutex
	run   string
	names map[int64]string
	order []int64
}{run: strings.ReplaceAll(uuid.NewString(), "-", "")[:12], names: map[int64]string{}}

// cloneSteppedSnapshot creates database clone holding template's schema
// stepped to exactly version. Under the lock so a snapshot is not dropped
// while it is the source of a clone.
func cloneSteppedSnapshot(ctx context.Context, admin *pgx.Conn, base, template string, version int64, clone string) error {
	steppedSnapshots.Lock()
	defer steppedSnapshots.Unlock()
	name, ok := steppedSnapshots.names[version]
	if !ok {
		source, nearest := template, int64(-1)
		for kept, keptName := range steppedSnapshots.names {
			if kept > version && (nearest < 0 || kept < nearest) {
				source, nearest = keptName, kept
			}
		}
		name = fmt.Sprintf("mig_step_%s_%03d", steppedSnapshots.run, version)
		if err := buildSteppedSnapshot(ctx, admin, base, source, name, version); err != nil {
			return err
		}
		steppedSnapshots.names[version] = name
	}
	order := steppedSnapshots.order[:0]
	for _, kept := range steppedSnapshots.order {
		if kept != version {
			order = append(order, kept)
		}
	}
	steppedSnapshots.order = append(order, version)
	for len(steppedSnapshots.order) > maxSteppedSnapshots {
		oldest := steppedSnapshots.order[0]
		steppedSnapshots.order = steppedSnapshots.order[1:]
		_, _ = admin.Exec(ctx, "DROP DATABASE IF EXISTS "+steppedSnapshots.names[oldest]+" WITH (FORCE)")
		delete(steppedSnapshots.names, oldest)
	}
	_, err := admin.Exec(ctx, "CREATE DATABASE "+clone+" TEMPLATE "+name+cloneStrategy())
	return err
}

func buildSteppedSnapshot(ctx context.Context, admin *pgx.Conn, base, source, name string, version int64) error {
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name+" TEMPLATE "+source+cloneStrategy()); err != nil {
		return err
	}
	built := false
	defer func() {
		if !built {
			_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
		}
	}()
	pool, err := snapshotDatabasePool(ctx, base, name)
	if err != nil {
		return err
	}
	// A template must have no open connections when it is cloned.
	defer pool.Close()
	var current int64
	if err := pool.QueryRow(ctx, `SELECT COALESCE(max(version), 0) FROM schema_migrations`).Scan(&current); err != nil {
		return fmt.Errorf("read template migration version: %w", err)
	}
	for ; current < version; current++ {
		if err := migrateVersionIsolated(ctx, pool, "up", current+1); err != nil {
			return fmt.Errorf("up %d: %w", current+1, err)
		}
	}
	for ; current > version; current-- {
		if err := migrateVersionIsolated(ctx, pool, "down", current); err != nil {
			return fmt.Errorf("down %d: %w", current, err)
		}
	}
	pool.Close()
	built = true
	return nil
}

// cloneStrategy follows TEST_DATABASE_TEMPLATE_STRATEGY (file_copy skips
// WAL-logging the copy; see databasetest.ClonedMigratedPool).
func cloneStrategy() string {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("TEST_DATABASE_TEMPLATE_STRATEGY")), "file_copy") {
		return " STRATEGY file_copy"
	}
	return ""
}

func dropSteppedSnapshots() {
	base := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	steppedSnapshots.Lock()
	defer steppedSnapshots.Unlock()
	if base == "" || len(steppedSnapshots.names) == 0 {
		return
	}
	ctx, cancel := databasetest.CleanupContext()
	defer cancel()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		fmt.Fprintf(os.Stderr, "drop stepped snapshots: %v\n", err)
		return
	}
	defer admin.Close(ctx)
	for _, name := range steppedSnapshots.names {
		if _, err := admin.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)"); err != nil {
			fmt.Fprintf(os.Stderr, "drop stepped snapshot %s: %v\n", name, err)
		}
	}
}
