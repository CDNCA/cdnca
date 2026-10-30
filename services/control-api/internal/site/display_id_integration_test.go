package site

import (
	"context"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestAllocateSiteDisplayIDConcurrentPostgres(t *testing.T) {
	databaseURL := os.Getenv("TEST_SITE_DISPLAY_ID_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_SITE_DISPLAY_ID_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("open site display ID test database: %v", err)
	}
	defer pool.Close()

	tenantA, scopeA := uuid.New(), uuid.New()
	tenantB, scopeB := uuid.New(), uuid.New()
	setup, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer setup.Rollback(ctx)
	if _, err := setup.Exec(ctx, `INSERT INTO tenants(id,display_name) VALUES($1,'Site display A'),($2,'Site display B')`, tenantA, tenantB); err != nil {
		t.Fatalf("insert site display ID tenants: %v", err)
	}
	if _, err := setup.Exec(ctx, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2),($3,'tenant',$4)`, scopeA, tenantA, scopeB, tenantB); err != nil {
		t.Fatalf("insert site display ID scopes: %v", err)
	}
	if err := setup.Commit(ctx); err != nil {
		t.Fatalf("commit site display ID scopes: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, _ = pool.Exec(cleanupCtx, `DELETE FROM site_display_id_sequences WHERE scope_id IN ($1,$2)`, scopeA, scopeB)
		_, _ = pool.Exec(cleanupCtx, `DELETE FROM access_scopes WHERE id IN ($1,$2)`, scopeA, scopeB)
		_, _ = pool.Exec(cleanupCtx, `DELETE FROM tenants WHERE id IN ($1,$2)`, tenantA, tenantB)
	})

	const workers = 16
	ids := make([]int64, workers)
	errs := make([]error, workers)
	var wait sync.WaitGroup
	for index := range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			tx, err := pool.Begin(ctx)
			if err != nil {
				errs[index] = err
				return
			}
			defer tx.Rollback(ctx)
			ids[index], err = allocateSiteDisplayID(ctx, tx, scopeA, time.Now().UTC())
			if err == nil {
				err = tx.Commit(ctx)
			}
			errs[index] = err
		}()
	}
	wait.Wait()
	for index, err := range errs {
		if err != nil {
			t.Fatalf("worker %d allocate site display ID: %v", index, err)
		}
	}
	sort.Slice(ids, func(left, right int) bool { return ids[left] < ids[right] })
	for index, id := range ids {
		if want := int64(index + 1); id != want {
			t.Fatalf("sorted display ID %d = %d, want %d; all=%v", index, id, want, ids)
		}
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rolledBackID, err := allocateSiteDisplayID(ctx, tx, scopeA, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	retriedID, err := allocateSiteDisplayID(ctx, tx, scopeA, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if rolledBackID != workers+1 || retriedID != rolledBackID {
		t.Fatalf("rollback/retry IDs = %d/%d, want %d/%d", rolledBackID, retriedID, workers+1, workers+1)
	}

	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	firstTenantBID, err := allocateSiteDisplayID(ctx, tx, scopeB, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if firstTenantBID != 1 {
		t.Fatalf("first tenant B display ID = %d, want 1", firstTenantBID)
	}
}
