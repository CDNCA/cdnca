//go:build integration

package identity_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/mfacipher"
	"github.com/google/uuid"
)

func setPasswordResetCipher(t *testing.T, service *identity.Service) {
	t.Helper()
	cipher, err := mfacipher.New(mfacipher.Key{ID: "test", Material: bytes.Repeat([]byte{7}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cipher.Close() })
	if err := service.SetTenantMemberPasswordResetCipher(cipher); err != nil {
		t.Fatal(err)
	}
}

// A lost reset
// response is retrieved with the same request, once, within 10 minutes, by
// the same actor; the reset requires a password change at the next sign-in.
func TestTenantMemberPasswordResetRetainedResult(t *testing.T) {
	fixture := seedThrottleFixture(t, 30, 30)
	ctx := t.Context()
	pool, service := fixture.pool, fixture.service
	setPasswordResetCipher(t, service)
	tenantID, scopeID := uuid.New(), uuid.New()
	ownerID, adminID, ownerRole, adminRole, viewerRole := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,'Reset Tenant')`, []any{tenantID}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{scopeID, tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'reset-owner','Owner','x'),($2,'reset-admin','Admin','x')`, []any{ownerID, adminID}},
		{`INSERT INTO memberships(scope_id,user_id,created_at) VALUES($1,$2,now()-interval '1 day'),($1,$3,now())`, []any{scopeID, ownerID, adminID}},
		// tenant_owner gets identity.roles.manage from the 042 trigger; the second administrator only identity.users.manage.
		{`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$4,'tenant_owner','o',true),($2,$4,'reset_users_manager','a',true),($3,$4,'tenant_viewer','v',true)`, []any{ownerRole, adminRole, viewerRole, scopeID}},
		{`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'identity.self.read'),($2,'identity.users.manage'),($2,'identity.self.read'),($3,'identity.self.read')`, []any{ownerRole, adminRole, viewerRole}},
		{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3),($1,$4,$5),($1,$4,$6)`, []any{scopeID, ownerID, ownerRole, adminID, adminRole, viewerRole}},
	} {
		if _, err := pool.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	owner := identity.Principal{UserID: ownerID, ScopeID: scopeID, ScopeKind: "tenant", TenantID: &tenantID}
	admin := identity.Principal{UserID: adminID, ScopeID: scopeID, ScopeKind: "tenant", TenantID: &tenantID}
	member, err := service.CreateTenantMember(ctx, owner, identity.CreateTenantMemberInput{
		Username: "reset-carol", DisplayName: "Carol", Password: "LongEnough-Pass1", RequestID: "create-carol"})
	if err != nil {
		t.Fatal(err)
	}
	other, err := service.CreateTenantMember(ctx, owner, identity.CreateTenantMemberInput{
		Username: "reset-dave", DisplayName: "Dave", Password: "LongEnough-Pass1", RequestID: "create-dave"})
	if err != nil {
		t.Fatal(err)
	}
	login := func(secret string) (identity.AuthResult, error) {
		return service.Login(ctx, identity.LoginInput{Username: "reset-carol", Password: secret},
			identity.RequestInfo{RequestID: "carol-" + uuid.NewString()[:8], SourceIP: "192.0.2.70"})
	}
	revision := func() int64 {
		var value int64
		if err := pool.QueryRow(ctx, `SELECT revision FROM users WHERE id=$1`, member.UserID).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}

	// A key is required.
	if _, err := service.ResetTenantMemberPassword(ctx, owner, member.UserID, "", "r-empty"); !errors.Is(err, identity.ErrInvalidUserInput) {
		t.Fatalf("empty key: %v", err)
	}

	// First reset: response "lost". The default is change-at-next-sign-in.
	first, err := service.ResetTenantMemberPassword(ctx, owner, member.UserID, "lost-key", "r-first")
	if err != nil || len(first.TemporaryPassword) != 24 || first.Replayed || !first.PasswordChangeRequired {
		t.Fatalf("first reset: %+v %v", first, err)
	}
	var required bool
	if err := pool.QueryRow(ctx, `SELECT password_change_required FROM users WHERE id=$1`, member.UserID).Scan(&required); err != nil || !required {
		t.Fatalf("password_change_required after reset: %v %v", required, err)
	}
	// Stored encrypted only.
	var envelope []byte
	if err := pool.QueryRow(ctx, `SELECT envelope FROM tenant_member_password_reset_results WHERE idempotency_key='lost-key'`).Scan(&envelope); err != nil ||
		len(envelope) == 0 || bytes.Contains(envelope, []byte(first.TemporaryPassword)) {
		t.Fatalf("retained envelope: %d bytes, %v", len(envelope), err)
	}
	afterFirst := revision()

	// Another actor, or another member, under the same key: refused, nothing changes.
	if _, err := service.ResetTenantMemberPassword(ctx, admin, member.UserID, "lost-key", "r-admin"); !errors.Is(err, identity.ErrIdempotencyConflict) {
		t.Fatalf("other actor same key: %v", err)
	}
	if _, err := service.ResetTenantMemberPassword(ctx, owner, other.UserID, "lost-key", "r-other"); !errors.Is(err, identity.ErrIdempotencyConflict) {
		t.Fatalf("other member same key: %v", err)
	}

	// Same actor, same key: the same password, without a second reset.
	again, err := service.ResetTenantMemberPassword(ctx, owner, member.UserID, "lost-key", "r-retry")
	if err != nil || !again.Replayed || again.TemporaryPassword != first.TemporaryPassword || !again.PasswordChangeRequired {
		t.Fatalf("retrieve: %+v %v", again, err)
	}
	if revision() != afterFirst {
		t.Fatal("retrieving the result reset the password again")
	}
	// Once: the ciphertext is gone, a further retry is refused and resets nothing.
	if err := pool.QueryRow(ctx, `SELECT envelope FROM tenant_member_password_reset_results WHERE idempotency_key='lost-key'`).Scan(&envelope); err != nil || envelope != nil {
		t.Fatalf("envelope after retrieval: %v %v", envelope, err)
	}
	if _, err := service.ResetTenantMemberPassword(ctx, owner, member.UserID, "lost-key", "r-third"); !errors.Is(err, identity.ErrTenantMemberPasswordResetGone) {
		t.Fatalf("second retrieval: %v", err)
	}
	if revision() != afterFirst {
		t.Fatal("a refused retrieval changed the user")
	}
	if _, err := login(first.TemporaryPassword); err != nil {
		t.Fatalf("retrieved password login: %v", err)
	}

	// 10 minutes: an expired result is not returned, and a retry does not reset.
	second, err := service.ResetTenantMemberPassword(ctx, owner, member.UserID, "expire-key", "r-expire")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE tenant_member_password_reset_results
		SET created_at=created_at-interval '11 minutes', expires_at=expires_at-interval '11 minutes' WHERE idempotency_key='expire-key'`); err != nil {
		t.Fatal(err)
	}
	afterSecond := revision()
	if _, err := service.ResetTenantMemberPassword(ctx, owner, member.UserID, "expire-key", "r-expire-retry"); !errors.Is(err, identity.ErrTenantMemberPasswordResetGone) {
		t.Fatalf("expired retrieval: %v", err)
	}
	if revision() != afterSecond {
		t.Fatal("an expired retrieval reset the password")
	}
	if _, err := login(second.TemporaryPassword); err != nil {
		t.Fatalf("second password login: %v", err)
	}

	// A later reset makes the earlier retained result unusable.
	third, err := service.ResetTenantMemberPassword(ctx, owner, member.UserID, "replaced-key", "r-replaced")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ResetTenantMemberPassword(ctx, admin, member.UserID, "newer-key", "r-newer"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ResetTenantMemberPassword(ctx, owner, member.UserID, "replaced-key", "r-replaced-retry"); !errors.Is(err, identity.ErrTenantMemberPasswordResetGone) {
		t.Fatalf("replaced retrieval: %v", err)
	}
	if _, err := login(third.TemporaryPassword); err == nil {
		t.Fatal("a replaced password still works")
	}

	// Purge (minute loop): expired ciphertext cleared, day-old tombstones deleted.
	if _, err := pool.Exec(ctx, `UPDATE tenant_member_password_reset_results
		SET created_at=created_at-interval '25 hours', expires_at=expires_at-interval '25 hours' WHERE idempotency_key='lost-key'`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE tenant_member_password_reset_results
		SET created_at=created_at-interval '11 minutes', expires_at=expires_at-interval '11 minutes' WHERE idempotency_key='newer-key'`); err != nil {
		t.Fatal(err)
	}
	if _, err := identity.NewStore(pool).PurgeTenantMemberPasswordResetResults(ctx); err != nil {
		t.Fatal(err)
	}
	var lostRows, newerSealed int
	if err := pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM tenant_member_password_reset_results WHERE idempotency_key='lost-key'),
		(SELECT count(*) FROM tenant_member_password_reset_results WHERE idempotency_key='newer-key' AND envelope IS NOT NULL)`).
		Scan(&lostRows, &newerSealed); err != nil || lostRows != 0 || newerSealed != 0 {
		t.Fatalf("purge: lost rows %d, newer sealed %d, %v", lostRows, newerSealed, err)
	}
}
