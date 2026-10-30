//go:build integration

package node

import (
	"context"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestAllocateNodeDisplayIDConcurrentRollbackAndScopesPostgres(t *testing.T) {
	pool := nodeDisplayIDTestPool(t)
	scopeA, scopeB := uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id) VALUES($1),($2)`, scopeA, scopeB); err != nil {
		t.Fatal(err)
	}

	const workers = 24
	ids := make([]int64, workers)
	errs := make([]error, workers)
	var wait sync.WaitGroup
	for index := range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			tx, err := pool.Begin(t.Context())
			if err != nil {
				errs[index] = err
				return
			}
			defer tx.Rollback(context.Background())
			ids[index], err = allocateNodeDisplayID(t.Context(), tx, scopeA, time.Now().UTC())
			if err == nil {
				err = tx.Commit(t.Context())
			}
			errs[index] = err
		}()
	}
	wait.Wait()
	for index, err := range errs {
		if err != nil {
			t.Fatalf("worker %d allocate node display ID: %v", index, err)
		}
	}
	sort.Slice(ids, func(left, right int) bool { return ids[left] < ids[right] })
	for index, id := range ids {
		if want := int64(index + 1); id != want {
			t.Fatalf("sorted display ID %d = %d, want %d; all=%v", index, id, want, ids)
		}
	}

	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	rolledBackID, err := allocateNodeDisplayID(t.Context(), tx, scopeA, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	tx, err = pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	retriedID, err := allocateNodeDisplayID(t.Context(), tx, scopeA, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if rolledBackID != workers+1 || retriedID != rolledBackID {
		t.Fatalf("rollback/retry IDs = %d/%d, want %d/%d", rolledBackID, retriedID, workers+1, workers+1)
	}

	tx, err = pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	firstScopeBID, err := allocateNodeDisplayID(t.Context(), tx, scopeB, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if firstScopeBID != 1 {
		t.Fatalf("first scope B display ID = %d, want 1", firstScopeBID)
	}
}

func nodeDisplayIDTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "node_display_id_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^node_display_id_test_[a-f0-9]{32}$`).MatchString(schema) {
		admin.Close()
		t.Fatalf("unsafe schema %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		CREATE TABLE access_scopes(id uuid PRIMARY KEY);
		CREATE TABLE node_display_id_sequences(
			scope_id uuid PRIMARY KEY REFERENCES access_scopes(id) ON DELETE RESTRICT,
			next_value bigint NOT NULL CHECK(next_value > 0),
			updated_at timestamptz NOT NULL
		)`); err != nil {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop node display ID schema: %v", err)
		}
		admin.Close()
	})
	return pool
}
