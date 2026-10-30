//go:build integration

package rbacmanager

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestCustomRBACMutationWaitsForGlobalExclusive(t *testing.T) {
	fixture := newRBACFixture(t)
	holder, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback(context.Background())
	if err := iamlock.AcquireShared(t.Context(), holder); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := fixture.service.CreateRole(context.Background(), fixture.actor, CreateRoleRequest{
			Name: "stage2-wait", Permissions: []string{"sites.read"}, Mutation: mutation("stage2-wait"),
		})
		done <- err
	}()
	assertStage2GlobalExclusiveWaiter(t, fixture)
	if err := holder.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestAuthorizeTenantSessionTxStrongIsolationErrorIsStable(t *testing.T) {
	for _, isolation := range []struct {
		name  string
		level pgx.TxIsoLevel
	}{
		{name: "repeatable-read", level: pgx.RepeatableRead},
		{name: "serializable", level: pgx.Serializable},
	} {
		t.Run(isolation.name, func(t *testing.T) {
			fixture := newRBACFixture(t)
			tx, err := fixture.pool.BeginTx(t.Context(), pgx.TxOptions{IsoLevel: isolation.level})
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			var snapshot string
			if err := tx.QueryRow(t.Context(), `SELECT pg_catalog.txid_current_snapshot()`).Scan(&snapshot); err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.pool.Exec(t.Context(), `UPDATE auth_sessions
				SET revoked_at=$2,revocation_reason='round2-review'
				WHERE id=$1`, fixture.actor.SessionID, fixture.now); err != nil {
				t.Fatal(err)
			}

			_, err = fixture.service.AuthorizeTenantSessionTx(t.Context(), tx,
				AuthenticatedSessionReference{UserID: fixture.actor.UserID, ScopeID: fixture.scopeID,
					SessionID: fixture.actor.SessionID}, ManagePermission)
			if !errors.Is(err, iamlock.ErrUnavailable) {
				t.Fatalf("AuthorizeTenantSessionTx() error = %v, want unavailable", err)
			}
			assertStableAuthorizationError(t, err)
		})
	}
}

func TestAuthorizeTenantSessionTxConcurrentReadersDoNotUpgradeLegacyLock(t *testing.T) {
	fixture := newRBACFixture(t)
	readers := make([]pgx.Tx, 0, 2)
	for range 2 {
		tx, err := fixture.pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, err := tx.Exec(t.Context(), `SET LOCAL deadlock_timeout='50ms'`); err != nil {
			t.Fatal(err)
		}
		if err := iamlock.AcquireShared(t.Context(), tx); err != nil {
			t.Fatal(err)
		}
		if _, err := iamlock.AcquireScopes(t.Context(), tx, []uuid.UUID{fixture.scopeID}); err != nil {
			t.Fatal(err)
		}
		readers = append(readers, tx)
	}

	results := make(chan error, len(readers))
	for _, tx := range readers {
		go func(tx pgx.Tx) {
			_, err := fixture.service.AuthorizeTenantSessionTx(context.Background(), tx,
				AuthenticatedSessionReference{UserID: fixture.actor.UserID, ScopeID: fixture.scopeID,
					SessionID: fixture.actor.SessionID}, ManagePermission)
			results <- err
		}(tx)
	}
	for range readers {
		select {
		case err := <-results:
			if err != nil {
				t.Fatalf("concurrent authorizer = %v, want success", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("concurrent authorizers did not complete")
		}
	}

	mutationDone := make(chan error, 1)
	go func() {
		_, err := fixture.service.CreateRole(context.Background(), fixture.actor, CreateRoleRequest{
			Name: "reader-wait", Permissions: []string{"sites.read"}, Mutation: mutation("reader-wait"),
		})
		mutationDone <- err
	}()
	select {
	case err := <-mutationDone:
		t.Fatalf("mutation bypassed active readers: %v", err)
	case <-time.After(75 * time.Millisecond):
	}
	for _, tx := range readers {
		if err := tx.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if err := <-mutationDone; err != nil {
		t.Fatal(err)
	}
}

func assertStableAuthorizationError(t *testing.T, err error) {
	t.Helper()
	for _, leaked := range []string{"SQLSTATE", "40001", "40P01", "55P03"} {
		if strings.Contains(err.Error(), leaked) {
			t.Fatalf("authorization error leaked %q: %v", leaked, err)
		}
	}
}

func assertStage2GlobalExclusiveWaiter(t *testing.T, fixture *rbacFixture) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var waiting bool
		if err := fixture.pool.QueryRow(t.Context(), `SELECT EXISTS(
			SELECT 1 FROM pg_catalog.pg_locks
			WHERE locktype='advisory' AND classid=1229016321::oid AND objid=1::oid
			  AND objsubid=2 AND mode='ExclusiveLock' AND NOT granted
		)`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("custom RBAC mutation never waited for global exclusive lock")
}
