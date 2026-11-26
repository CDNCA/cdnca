package certificateasset

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// rotateCertificateActorSession does what the console's token refresh does (identity.Store refresh): a new session
// of the family, the old one marked used and replaced, still unexpired and unrevoked. It answers the new session.
func rotateCertificateActorSession(t *testing.T, pool *pgxpool.Pool, old uuid.UUID) uuid.UUID {
	t.Helper()
	next := uuid.New()
	refresh := sha256.Sum256(next[:])
	now := time.Now().UTC()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO auth_sessions(id,family_id,parent_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
		SELECT $2,family_id,id,user_id,scope_id,$3,$4,expires_at FROM auth_sessions WHERE id=$1`,
		old, next, refresh[:], now.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE auth_sessions SET used_at=$2, replaced_by_id=$3 WHERE id=$1`, old, now, next); err != nil {
		t.Fatal(err)
	}
	return next
}

// binding and unbinding record a publication intent only for a session
// PrincipalForSession accepts (store and trigger 699). A session another tab's token refresh replaced still binds and
// unbinds; revoked, expired and role-less sessions are refused. Write receipts are per user
// (certificate_asset_write_requests.actor_user_id), so the refreshed session replays the same key.
func TestCertificateBindingAcceptsRefreshedSession(t *testing.T) {
	pool := isolatedCertificateAssetPool(t)
	tenant := createCertificateTenant(t, pool, "refreshed-session")
	store, err := NewStoreWithDependencies(pool, &testEnvelopeCipher{}, audit.New(pool),
		func() time.Time { return certificateTestNow })
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	pki := newCertificateFixture(t, leafOptions{domains: []string{"www.example.com", "api.example.com", "shop.example.com"}})
	imported, err := store.Import(ctx, tenant.actor, ImportRequest{
		TenantScopeID: tenant.actor.ScopeID, Name: "刷新会话证书", Source: SourceUploaded,
		CertificatePEM: pki.certificatePEM, PrivateKeyPEM: pki.privateKeyPEM,
		IdempotencyKey: "refreshed-import", RequestID: "refreshed-import",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Activate(ctx, tenant.actor, ActivateRequest{
		TenantScopeID: tenant.actor.ScopeID, AssetID: imported.Asset.ID, VersionID: imported.Version.ID,
		ExpectedRevision: 1, IdempotencyKey: "refreshed-activate", RequestID: "refreshed-activate",
	}); err != nil {
		t.Fatal(err)
	}
	old := tenant.actor
	current := old
	current.SessionID = rotateCertificateActorSession(t, pool, old.SessionID)
	bind := func(actor Actor, site uuid.UUID, revision int64, key string) (Binding, error) {
		return store.Bind(ctx, actor, BindRequest{
			TenantScopeID: actor.ScopeID, SiteID: site, AssetID: imported.Asset.ID, VersionID: imported.Version.ID,
			ExpectedRevision: revision, IdempotencyKey: key, RequestID: key,
		})
	}
	intents := func(site, session uuid.UUID) int {
		t.Helper()
		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM certificate_publication_intents
			WHERE site_id=$1 AND actor_session_id=$2`, site, session).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}

	bound, err := bind(old, tenant.siteOne, 0, "refreshed-bind")
	if err != nil || !bound.Bound || bound.Revision != 1 {
		t.Fatalf("replaced session bind %#v %v", bound, err)
	}
	if replayed, err := bind(current, tenant.siteOne, 0, "refreshed-bind"); err != nil || replayed.Revision != bound.Revision {
		t.Fatalf("current session replays the user's receipt %#v %v", replayed, err)
	}
	unbound, err := store.Unbind(ctx, old, UnbindRequest{TenantScopeID: old.ScopeID, SiteID: tenant.siteOne,
		ExpectedRevision: bound.Revision, IdempotencyKey: "refreshed-unbind", RequestID: "refreshed-unbind"})
	if err != nil || unbound.Bound {
		t.Fatalf("replaced session unbind %#v %v", unbound, err)
	}
	if n := intents(tenant.siteOne, old.SessionID); n != 2 {
		t.Fatalf("publication intents of the replaced session = %d, want publish and unpublish", n)
	}

	// Revoked (logout, replay, suspension revoke the family) and expired sessions are refused.
	if _, err := pool.Exec(ctx, `UPDATE auth_sessions SET revoked_at=now(), revocation_reason='logout' WHERE id=$1`,
		old.SessionID); err != nil {
		t.Fatal(err)
	}
	if _, err := bind(old, tenant.siteTwo, 0, "revoked-bind"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("revoked session bind: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE auth_sessions SET expires_at=now()-interval '1 second' WHERE id=$1`,
		current.SessionID); err != nil {
		t.Fatal(err)
	}
	if _, err := bind(current, tenant.siteTwo, 0, "expired-bind"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expired session bind: %v", err)
	}
	if n := intents(tenant.siteTwo, old.SessionID) + intents(tenant.siteTwo, current.SessionID); n != 0 {
		t.Fatalf("refused binds left %d publication intents", n)
	}
	// The role taken away: a live, refreshed session lacks certificates.manage.
	fresh := old
	fresh.SessionID = rotateCertificateActorSession(t, pool, insertCertificateActorSession(t, pool, old.ScopeID, old.UserID))
	if _, err := pool.Exec(ctx, `DELETE FROM role_assignments WHERE scope_id=$1 AND user_id=$2`, old.ScopeID, old.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := bind(fresh, tenant.siteThree, 0, "no-role-bind"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("refreshed session without the role: %v", err)
	}
}
