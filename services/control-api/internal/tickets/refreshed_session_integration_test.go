package tickets

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

// rotateSession does what the console's token refresh does (identity.Store refresh): a new session of the family,
// the old one marked used and replaced, still unexpired and unrevoked. It answers the new session's actor.
func (f *fixture) rotateSession(t *testing.T, old Actor) Actor {
	t.Helper()
	next := uuid.New()
	refresh := sha256.Sum256(next[:])
	now := f.clock.Now()
	exec(t, f.pool, `INSERT INTO auth_sessions(id,family_id,parent_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
		SELECT $2,family_id,id,user_id,scope_id,$3,$4,expires_at FROM auth_sessions WHERE id=$1`,
		old.SessionID, next, refresh[:], now.Add(-time.Minute))
	exec(t, f.pool, `UPDATE auth_sessions SET used_at=$2, replaced_by_id=$3 WHERE id=$1`, old.SessionID, now.Add(-time.Minute), next)
	rotated := old
	rotated.SessionID = next
	return rotated
}

// the in-transaction session check accepts what PrincipalForSession accepts. A customer
// or staff session another tab's token refresh replaced still creates and replies; revoked, expired, suspended-member
// and role-less sessions are refused. Ticket write receipts are per user (ticket_write_requests.actor_user_id), so the
// refreshed session replays the same key.
func TestTicketWritesAcceptRefreshedSession(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	customer := f.customer
	customerNext := f.rotateSession(t, customer)
	manager := f.manager
	managerNext := f.rotateSession(t, manager)

	created, err := f.service.Create(ctx, customer, "refreshed-create", "req-refreshed-create",
		CreateInput{Category: "technical", Subject: "网站 502", Body: "访问首页返回 502"})
	if err != nil {
		t.Fatalf("replaced customer session create: %v", err)
	}
	if _, err := f.service.Get(ctx, customer, false, created.Ticket.ID); err != nil {
		t.Fatalf("replaced customer session read: %v", err)
	}
	again, err := f.service.Create(ctx, customerNext, "refreshed-create", "req-refreshed-create",
		CreateInput{Category: "technical", Subject: "网站 502", Body: "访问首页返回 502"})
	if err != nil || again.Ticket.ID != created.Ticket.ID {
		t.Fatalf("current session replays the user's receipt %+v %v (ticket %s)", again.Ticket, err, created.Ticket.ID)
	}
	if _, err := f.service.Reply(ctx, customer, false, "refreshed-customer-reply", "req-refreshed-customer-reply",
		created.Ticket.ID, ReplyInput{Body: "补充信息"}); err != nil {
		t.Fatalf("replaced customer session reply: %v", err)
	}
	if _, err := f.service.Reply(ctx, manager, true, "refreshed-staff-reply", "req-refreshed-staff-reply",
		created.Ticket.ID, ReplyInput{Body: "已处理"}); err != nil {
		t.Fatalf("replaced staff session reply: %v", err)
	}

	// Revoked (logout, replay, suspension revoke the family) and expired sessions are refused.
	exec(t, f.pool, `UPDATE auth_sessions SET revoked_at=$2, revocation_reason='logout' WHERE id=$1`, customer.SessionID, f.clock.Now())
	if _, err := f.service.Reply(ctx, customer, false, "revoked-reply", "req-revoked-reply", created.Ticket.ID,
		ReplyInput{Body: "x"}); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("revoked customer session reply: %v", err)
	}
	exec(t, f.pool, `UPDATE auth_sessions SET expires_at=$2 WHERE id=$1`, managerNext.SessionID, f.clock.Now().Add(-time.Second))
	if _, err := f.service.Reply(ctx, managerNext, true, "expired-reply", "req-expired-reply", created.Ticket.ID,
		ReplyInput{Body: "x"}); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expired staff session reply: %v", err)
	}
	// A suspended membership is refused on the refreshed customer session too.
	exec(t, f.pool, `UPDATE memberships SET status='suspended' WHERE scope_id=$1 AND user_id=$2`, customer.ScopeID, customer.UserID)
	if _, err := f.service.Reply(ctx, customerNext, false, "suspended-reply", "req-suspended-reply", created.Ticket.ID,
		ReplyInput{Body: "x"}); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("suspended member reply: %v", err)
	}
	// The role taken away: the replaced staff session lacks the permission.
	exec(t, f.pool, `DELETE FROM role_assignments WHERE scope_id=$1 AND user_id=$2`, manager.ScopeID, manager.UserID)
	if _, err := f.service.Reply(ctx, manager, true, "no-role-reply", "req-no-role-reply", created.Ticket.ID,
		ReplyInput{Body: "x"}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("replaced staff session without the role: %v", err)
	}
}
