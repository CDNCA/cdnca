//go:build integration

package migrations_test

import (
	"context"
	"os"
	"regexp"
	"strconv"
	"strings"
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

// clonedMigrationPool returns a pool on a fresh copy of TEST_DATABASE_TEMPLATE,
// or nil when no template is configured.
func clonedMigrationPool(t *testing.T) *pgxpool.Pool {
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
	clone := "mig_clone_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:20]
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+clone+" TEMPLATE "+template); err != nil {
		_ = admin.Close(ctx)
		t.Fatalf("clone %s: %v", template, err)
	}
	t.Cleanup(func() {
		// Under load a short budget left clone databases behind; a failed
		// drop is reported but does not fail the test that already passed.
		dropCtx, dropCancel := databasetest.CleanupContext()
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
	config.ConnConfig.RuntimeParams["search_path"] = "migrated"
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// migrationPoolAt returns a schema migrated through exactly version. A cloned
// template may stop below or above it (templates are rebuilt at the latest
// head), so the clone is rolled up or down one migration at a time; without a
// template the schema is migrated from scratch.
func migrationPoolAt(t *testing.T, version int64) *pgxpool.Pool {
	t.Helper()
	pool := clonedMigrationPool(t)
	if pool == nil {
		return packageCommerceRBAC079Pool(t, version)
	}
	ctx := t.Context()
	var current int64
	if err := pool.QueryRow(ctx, `SELECT COALESCE(max(version), 0) FROM schema_migrations`).Scan(&current); err != nil {
		t.Fatalf("read template migration version: %v", err)
	}
	for ; current < version; current++ {
		if err := migrateVersionIsolated(ctx, pool, "up", current+1); err != nil {
			t.Fatalf("up %d: %v", current+1, err)
		}
	}
	for ; current > version; current-- {
		if err := migrateVersionIsolated(ctx, pool, "down", current); err != nil {
			t.Fatalf("down %d: %v", current, err)
		}
	}
	return pool
}
