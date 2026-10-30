package audit

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestAppendSerializesAfterConcurrentScopeReferences(t *testing.T) {
	pool := isolatedAuditPool(t)
	tenantID, scopeID := uuid.New(), uuid.New()
	if _, err := pool.Exec(context.Background(),
		"INSERT INTO tenants(id,display_name) VALUES($1,'Audit Test')", tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(),
		"INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)", scopeID, tenantID); err != nil {
		t.Fatal(err)
	}

	txs := make([]pgx.Tx, 2)
	for index := range txs {
		tx, err := pool.Begin(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		txs[index] = tx
		t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
		// Any row referencing the scope will do; custom roles may only be
		// created through custom RBAC facts (migration 042), so a system role.
		if _, err := tx.Exec(context.Background(), `
			INSERT INTO roles(id,scope_id,name,description,system_role)
			VALUES($1,$2,$3,'concurrent audit test',true)`, uuid.New(), scopeID, "audit-role-"+string(rune('a'+index))); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	results := make(chan error, len(txs))
	log := New(pool)
	for index, tx := range txs {
		go func(index int, tx pgx.Tx) {
			err := log.Append(ctx, tx, Event{
				ScopeID: scopeID, Action: "audit.concurrent", ResourceType: "role",
				ResourceID: uuid.NewString(), RequestID: "audit-concurrent-" + string(rune('a'+index)),
				Result: "success", Payload: map[string]any{"worker": index},
			})
			if err == nil {
				err = tx.Commit(ctx)
			} else {
				_ = tx.Rollback(context.Background())
			}
			results <- err
		}(index, tx)
	}
	for range txs {
		if err := <-results; err != nil {
			t.Fatalf("concurrent append failed: %v", err)
		}
	}
	if err := log.VerifyScope(context.Background(), scopeID); err != nil {
		t.Fatalf("verify concurrent audit stream: %v", err)
	}
}

func isolatedAuditPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	// A clone of the migrated template when one is configured; migrating
	// 360+ migrations within the 30s budget below fails on a loaded host.
	if pool := databasetest.ClonedMigratedPool(t, nil); pool != nil {
		return pool
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "audit_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^audit_test_[a-f0-9]{32}$`).MatchString(schema) {
		admin.Close()
		t.Fatalf("unsafe schema name %q", schema)
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
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
		t.Fatal(err)
	}
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		pool.Close()
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop schema: %v", err)
		}
		admin.Close()
	})
	return pool
}
