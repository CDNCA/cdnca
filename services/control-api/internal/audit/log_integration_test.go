package audit

import (
	"context"
	"testing"
	"time"

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
	return databasetest.MigratedPool(t, nil)
}
