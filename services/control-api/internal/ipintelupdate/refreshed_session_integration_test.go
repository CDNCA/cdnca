package ipintelupdate

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
	mustExec(t, f.pool, `INSERT INTO auth_sessions(id,family_id,parent_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
		SELECT $2,family_id,id,user_id,scope_id,$3,$4,expires_at FROM auth_sessions WHERE id=$1`,
		old.SessionID, next, refresh[:], f.now.Add(-time.Minute))
	mustExec(t, f.pool, `UPDATE auth_sessions SET used_at=$2, replaced_by_id=$3 WHERE id=$1`, old.SessionID, f.now.Add(-time.Minute), next)
	rotated := old
	rotated.SessionID = next
	return rotated
}

// the in-transaction session check accepts what PrincipalForSession accepts. A session
// another tab's token refresh replaced still saves the settings; revoked, expired and role-less sessions are refused.
// Write receipts stay per session.
func TestSettingsWritesAcceptRefreshedSession(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	old := f.admin
	current := f.rotateSession(t, old)

	if _, err := f.service.Status(ctx, old); err != nil {
		t.Fatalf("replaced session read: %v", err)
	}
	saved, err := f.service.UpdateSettings(ctx, old, "after-refresh", f.settings(false, secret(testAPISecret)))
	if err != nil {
		t.Fatalf("replaced session save: %v", err)
	}
	if again, err := f.service.UpdateSettings(ctx, old, "after-refresh", f.settings(false, secret(testAPISecret))); err != nil ||
		again.Revision != saved.Revision {
		t.Fatalf("replaced session replay %+v %v", again, err)
	}
	// The receipt is the old session's: the current session's same key is another write.
	if other, err := f.service.UpdateSettings(ctx, current, "after-refresh", f.settings(false, secret(testAPISecret))); err != nil ||
		other.Revision != saved.Revision+1 {
		t.Fatalf("current session, same key %+v %v (old session revision %d)", other, err, saved.Revision)
	}

	// Revoked (logout, replay, suspension revoke the family) and expired sessions are refused.
	mustExec(t, f.pool, `UPDATE auth_sessions SET revoked_at=$2, revocation_reason='logout' WHERE id=$1`, old.SessionID, f.now)
	if _, err := f.service.UpdateSettings(ctx, old, "revoked", f.settings(false, nil)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("revoked session save: %v", err)
	}
	mustExec(t, f.pool, `UPDATE auth_sessions SET expires_at=$2 WHERE id=$1`, current.SessionID, f.now.Add(-time.Second))
	if _, err := f.service.UpdateSettings(ctx, current, "expired", f.settings(false, nil)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expired session save: %v", err)
	}
	// The role taken away: a live, refreshed session lacks the permission.
	user, session := seedActor(t, f.pool, f.admin.ScopeID, f.now, PermissionManage)
	manager := Actor{UserID: user, ScopeID: f.admin.ScopeID, SessionID: session}
	refreshed := f.rotateSession(t, manager)
	mustExec(t, f.pool, `DELETE FROM role_assignments WHERE scope_id=$1 AND user_id=$2`, f.admin.ScopeID, user)
	for name, actor := range map[string]Actor{"replaced": manager, "current": refreshed} {
		if _, err := f.service.UpdateSettings(ctx, actor, "no-role-"+name, f.settings(false, nil)); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("%s session without the role: %v", name, err)
		}
	}
}
