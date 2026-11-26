package dnspupprobe

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnspupprobe/dnspuptest"
	"github.com/google/uuid"
)

// rotateSession does what the console's token refresh does (identity.Store refresh): a new session of the family,
// the old one marked used and replaced, still unexpired and unrevoked. It answers the new session's actor.
func (f *serviceFixture) rotateSession(t *testing.T, old Actor) Actor {
	t.Helper()
	next := uuid.New()
	refresh := sha256.Sum256(next[:])
	mustExecTest(t, f.pool, `INSERT INTO auth_sessions(id,family_id,parent_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
		SELECT $2,family_id,id,user_id,scope_id,$3,$4,expires_at FROM auth_sessions WHERE id=$1`,
		old.SessionID, next, refresh[:], f.now.Add(-time.Minute))
	mustExecTest(t, f.pool, `UPDATE auth_sessions SET used_at=$2, replaced_by_id=$3 WHERE id=$1`, old.SessionID, f.now.Add(-time.Minute), next)
	rotated := old
	rotated.SessionID = next
	return rotated
}

// the in-transaction session check accepts what every other API accepts. A
// session another tab's token refresh replaced still saves settings and starts an mtr; revoked, expired and
// role-less sessions are still refused. Write receipts stay per session.
func TestProbeWritesAcceptRefreshedSession(t *testing.T) {
	f := newServiceFixture(t)
	ctx := t.Context()
	f.enable(t)
	f.fake.Do(func(fake *dnspuptest.Server) {
		fake.AllowedTools = []string{"tcping", "http", "mtr"}
		fake.AnswerTraces = func(dnspuptest.ProbeRequest) []map[string]any {
			return []map[string]any{{"nodeId": "gd-ct", "status": "ok", "trace": map[string]any{"hops": []any{}}}}
		}
	})
	old := f.admin
	current := f.rotateSession(t, old)

	if _, err := f.service.Status(ctx, old); err != nil {
		t.Fatalf("replaced session read: %v", err)
	}
	saved, err := f.service.UpdateSettings(ctx, old, "after-refresh", f.input(true, nil))
	if err != nil || !saved.Enabled {
		t.Fatalf("replaced session save %+v %v", saved, err)
	}
	if again, err := f.service.UpdateSettings(ctx, old, "after-refresh", f.input(true, nil)); err != nil || again.Revision != saved.Revision {
		t.Fatalf("replaced session replay %+v %v", again, err)
	}
	// The receipt is the old session's: the current session's same key is another write.
	if other, err := f.service.UpdateSettings(ctx, current, "after-refresh", f.input(true, nil)); err != nil || other.Revision != saved.Revision+1 {
		t.Fatalf("current session, same key %+v %v (old session revision %d)", other, err, saved.Revision)
	}
	diagnosis, err := f.service.CreateDiagnose(ctx, old, "mtr-after-refresh", DiagnoseInput{Target: "203.0.113.9", Checkpoints: []string{"gd-ct"}})
	if err == nil && diagnosis.Type != "mtr" {
		err = errors.New("not an mtr")
	}
	if err != nil {
		t.Fatalf("replaced session mtr: %v", err)
	}
	if _, err := f.service.GetDiagnose(ctx, old, diagnosis.ID); err != nil {
		t.Fatalf("replaced session reads its mtr: %v", err)
	}

	// Revoked (logout, replay, suspension revoke the family) and expired sessions are refused.
	mustExecTest(t, f.pool, `UPDATE auth_sessions SET revoked_at=$2, revocation_reason='logout' WHERE id=$1`, old.SessionID, f.now)
	if _, err := f.service.UpdateSettings(ctx, old, "revoked", f.input(false, nil)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("revoked session save: %v", err)
	}
	if _, err := f.service.CreateDiagnose(ctx, old, "revoked-mtr", DiagnoseInput{Target: "203.0.113.9",
		Checkpoints: []string{"gd-ct"}}); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("revoked session mtr: %v", err)
	}
	mustExecTest(t, f.pool, `UPDATE auth_sessions SET expires_at=$2 WHERE id=$1`, current.SessionID, f.now.Add(-time.Second))
	if _, err := f.service.UpdateSettings(ctx, current, "expired", f.input(false, nil)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expired session save: %v", err)
	}
	// The role taken away: a live, refreshed session lacks the permission.
	user, session := seedTestActor(t, f.pool, f.admin.ScopeID, f.now, PermissionManage)
	manager := Actor{UserID: user, ScopeID: f.admin.ScopeID, SessionID: session}
	refreshed := f.rotateSession(t, manager)
	mustExecTest(t, f.pool, `DELETE FROM role_assignments WHERE scope_id=$1 AND user_id=$2`, f.admin.ScopeID, user)
	for name, actor := range map[string]Actor{"replaced": manager, "current": refreshed} {
		if _, err := f.service.UpdateSettings(ctx, actor, "no-role-"+name, f.input(false, nil)); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("%s session without the role: %v", name, err)
		}
	}
}

// api_secret omitted keeps the stored secret, "" clears it; a disabled source
// saves without credentials, an enabled one needs the key and a secret.
func TestSettingsCredentialsWhileDisabled(t *testing.T) {
	f := newServiceFixture(t)
	ctx := t.Context()
	f.enable(t)
	noKey := f.input(true, ptr(""))
	noKey.APIKey = ""
	if _, err := f.service.UpdateSettings(ctx, f.admin, "on-no-key", noKey); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("enabled without a key: %v", err)
	}
	if _, err := f.service.UpdateSettings(ctx, f.admin, "on-clear-secret", f.input(true, ptr(""))); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("enabled with the secret cleared: %v", err)
	}
	// Omitted: kept.
	status, err := f.service.UpdateSettings(ctx, f.admin, "off-keep", f.input(false, nil))
	if err != nil || status.Enabled || !status.SecretConfigured || status.APIKey != f.fake.APIKey {
		t.Fatalf("disable keeping the secret %+v %v", status, err)
	}
	// A cleared key with the secret omitted would keep a secret for another key: refused as before.
	cleared := f.input(false, nil)
	cleared.APIKey = ""
	if _, err := f.service.UpdateSettings(ctx, f.admin, "off-no-key-keep", cleared); !errors.Is(err, ErrSecretRequired) {
		t.Fatalf("cleared key keeping the secret: %v", err)
	}
	// "": cleared; a disabled source saves with no credentials at all.
	cleared.APISecret = ptr("")
	if status, err = f.service.UpdateSettings(ctx, f.admin, "off-clear", cleared); err != nil || status.Enabled ||
		status.SecretConfigured || status.APIKey != "" {
		t.Fatalf("disable clearing the credentials %+v %v", status, err)
	}
	cleared.APISecret = nil
	if status, err = f.service.UpdateSettings(ctx, f.admin, "off-empty", cleared); err != nil || status.SecretConfigured || status.APIKey != "" {
		t.Fatalf("disabled without credentials %+v %v", status, err)
	}
	// While disabled a new pair is stored; omitted keeps it, "" clears it.
	if status, err = f.service.UpdateSettings(ctx, f.admin, "off-set", f.input(false, ptr(f.fake.Secret))); err != nil || !status.SecretConfigured {
		t.Fatalf("disabled with a new pair %+v %v", status, err)
	}
	if status, err = f.service.UpdateSettings(ctx, f.admin, "off-keep-2", f.input(false, nil)); err != nil || !status.SecretConfigured {
		t.Fatalf("disabled keeping the pair %+v %v", status, err)
	}
	if status, err = f.service.UpdateSettings(ctx, f.admin, "off-clear-2", f.input(false, ptr(""))); err != nil || status.SecretConfigured {
		t.Fatalf("disabled clearing the secret %+v %v", status, err)
	}
	if _, err := f.service.UpdateSettings(ctx, f.admin, "on-without-secret", f.input(true, nil)); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("enabled without a stored secret: %v", err)
	}
}
