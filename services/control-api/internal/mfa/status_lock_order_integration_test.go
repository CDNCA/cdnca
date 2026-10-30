package mfa

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// fix-e1 #4: GET /v1/account/mfa answered 503 mfa_unavailable because
// Status (FOR UPDATE OF session,users,membership) and the session
// credential check of a concurrent request on the same session (row locks
// taken one by one) locked users and auth_sessions in opposite orders, and
// both run under shared IAM advisory locks. A blocker on the membership row
// parks the credential check between its row locks so the two interleave
// deterministically; with one lock order neither side may fail.
func TestStatusAndSessionCredentialCheckDoNotDeadlock(t *testing.T) {
	fixture := newMFAFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	tokens, err := identity.NewTokenManager(strings.Repeat("k", 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := sessioncredential.NewVerifier(tokens, fixture.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	actor := fixture.actor
	token, _, err := tokens.Mint(actor.UserID, actor.ScopeID, actor.SessionID)
	if err != nil {
		t.Fatal(err)
	}

	blocker, err := fixture.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Rollback(context.Background()) }()
	if _, err := blocker.Exec(ctx, `SELECT 1 FROM memberships WHERE scope_id=$1 AND user_id=$2 FOR UPDATE`,
		actor.ScopeID, actor.UserID); err != nil {
		t.Fatal(err)
	}

	verified := make(chan error, 1)
	go func() {
		verified <- pgx.BeginFunc(ctx, fixture.pool, func(tx pgx.Tx) error {
			if err := iamlock.AcquireShared(ctx, tx); err != nil {
				return err
			}
			locked, err := iamlock.AcquireScopes(ctx, tx, []uuid.UUID{actor.ScopeID})
			if err != nil {
				return err
			}
			_, err = verifier.VerifyTx(ctx, tx, token, locked)
			return err
		})
	}()
	waitLockWaiters(t, ctx, fixture, 1)

	status := make(chan error, 1)
	go func() {
		_, err := fixture.service.Status(ctx, actor)
		status <- err
	}()
	waitLockWaiters(t, ctx, fixture, 2)

	if err := blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-verified; err != nil {
		t.Errorf("session credential check: %v", err)
	}
	if err := <-status; err != nil {
		t.Errorf("MFA Status: %v", err)
	}
}

// waitLockWaiters waits until want backends of the test database wait on a lock.
func waitLockWaiters(t *testing.T, ctx context.Context, fixture mfaFixture, want int) {
	t.Helper()
	for {
		var waiting int
		if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity
			WHERE datname=current_database() AND wait_event_type='Lock'`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting >= want {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("lock waiters = %d, want %d", waiting, want)
		case <-time.After(20 * time.Millisecond):
		}
	}
}
