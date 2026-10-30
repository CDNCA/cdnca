package apikey

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestAuthenticateWithKeyIDReturnsOnlySuccessfulAuthenticationFact(t *testing.T) {
	fixture := newAPIKeyIntegrationFixture(t)
	issued := mustCreateSelfKey(t, fixture, "authentication-usage-key")
	credential := issued.Key.KeyID + "." + issued.Secret

	principal, keyID, authenticatedAt, err := fixture.service.AuthenticateWithKeyID(t.Context(), credential)
	if err != nil {
		t.Fatalf("authenticate with key ID: %v", err)
	}
	if keyID != issued.Key.ID || principal.UserID != fixture.alice.UserID {
		t.Fatalf("authentication fact = (user=%s key=%s), want (user=%s key=%s)",
			principal.UserID, keyID, fixture.alice.UserID, issued.Key.ID)
	}
	if !authenticatedAt.Equal(fixture.clock.Now()) || authenticatedAt.Location() != time.UTC {
		t.Fatalf("authenticated_at = %v, want %v UTC", authenticatedAt, fixture.clock.Now())
	}
	compatible, err := fixture.service.Authenticate(t.Context(), credential)
	if err != nil || compatible.UserID != principal.UserID {
		t.Fatalf("compatibility authentication = (%#v, %v)", compatible, err)
	}
	var lastUsedAt *time.Time
	if err := fixture.pool.QueryRow(t.Context(), `SELECT last_used_at FROM api_keys WHERE id=$1`,
		issued.Key.ID).Scan(&lastUsedAt); err != nil {
		t.Fatal(err)
	}
	if lastUsedAt != nil {
		t.Fatalf("authentication synchronously changed last_used_at to %v", *lastUsedAt)
	}

	for name, raw := range map[string]string{
		"malformed":    "not-a-credential",
		"wrong secret": issued.Key.KeyID + "." + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	} {
		t.Run(name, func(t *testing.T) {
			_, failedKeyID, failedAt, authErr := fixture.service.AuthenticateWithKeyID(t.Context(), raw)
			if !errors.Is(authErr, ErrInvalidCredential) || failedKeyID != uuid.Nil || !failedAt.IsZero() {
				t.Fatalf("failure = (key=%s err=%v), want uuid.Nil and invalid credential", failedKeyID, authErr)
			}
		})
	}
	unknown := "cfk_AAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	_, unknownKeyID, unknownAt, err := fixture.service.AuthenticateWithKeyID(t.Context(), unknown)
	if !errors.Is(err, ErrInvalidCredential) || unknownKeyID != uuid.Nil || !unknownAt.IsZero() {
		t.Fatalf("unknown failure = (key=%s at=%v err=%v)", unknownKeyID, unknownAt, err)
	}

	revoked := mustCreateSelfKey(t, fixture, "authentication-usage-revoked")
	if _, err := fixture.service.RevokeSelf(t.Context(), fixture.alice, MutationInput{
		ID: revoked.Key.ID, ExpectedRevision: revoked.Key.Revision,
		IdempotencyKey: "authentication-usage-revoke", RequestID: "authentication-usage-revoke",
	}); err != nil {
		t.Fatal(err)
	}
	_, revokedKeyID, revokedAt, err := fixture.service.AuthenticateWithKeyID(
		t.Context(), revoked.Key.KeyID+"."+revoked.Secret,
	)
	if !errors.Is(err, ErrInvalidCredential) || revokedKeyID != uuid.Nil || !revokedAt.IsZero() {
		t.Fatalf("revoked failure = (key=%s err=%v)", revokedKeyID, err)
	}

	expiresAt := fixture.clock.Now().Add(time.Minute)
	expired := mustCreateSelfKeyWithExpiry(t, fixture, "authentication-usage-expired", expiresAt)
	fixture.clock.Advance(2 * time.Minute)
	_, expiredKeyID, expiredAt, err := fixture.service.AuthenticateWithKeyID(
		t.Context(), expired.Key.KeyID+"."+expired.Secret,
	)
	if !errors.Is(err, ErrInvalidCredential) || expiredKeyID != uuid.Nil || !expiredAt.IsZero() {
		t.Fatalf("expired failure = (key=%s err=%v)", expiredKeyID, err)
	}
	fixture.clock.Advance(-2 * time.Minute)

	if _, err := fixture.pool.Exec(t.Context(), `DELETE FROM role_assignments
		WHERE scope_id=$1 AND user_id=$2`, fixture.alice.ScopeID, fixture.alice.UserID); err != nil {
		t.Fatal(err)
	}
	_, ineffectiveKeyID, ineffectiveAt, err := fixture.service.AuthenticateWithKeyID(t.Context(), credential)
	if !errors.Is(err, ErrInvalidCredential) || ineffectiveKeyID != uuid.Nil || !ineffectiveAt.IsZero() {
		t.Fatalf("no-effective-scope failure = (key=%s err=%v)", ineffectiveKeyID, err)
	}

	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	_, databaseFailureKeyID, databaseFailureAt, err := fixture.service.AuthenticateWithKeyID(canceled, credential)
	if err == nil || databaseFailureKeyID != uuid.Nil || !databaseFailureAt.IsZero() {
		t.Fatalf("database failure = (key=%s at=%v err=%v)", databaseFailureKeyID, databaseFailureAt, err)
	}
}

func TestPlatformAPIKeyStatusBlocksAuthenticationAndIssuance(t *testing.T) {
	fixture := newAPIKeyIntegrationFixture(t)
	ctx := t.Context()
	issued := mustCreateSelfKey(t, fixture, "platform-api-key-status-active")
	pending, err := fixture.service.AdminCreatePending(ctx, fixture.admin, AdminCreateInput{
		TargetScopeID: fixture.alice.ScopeID, TargetUserID: fixture.alice.UserID,
		Name: "platform status pending", Scopes: []string{"sites.read"}, PendingTTL: time.Hour,
		IdempotencyKey: "platform-api-key-status-pending", RequestID: "platform-api-key-status-pending",
	})
	if err != nil {
		t.Fatalf("create pending key: %v", err)
	}
	if _, err := fixture.pool.Exec(ctx, `INSERT INTO platform_system_other_settings(platform_scope_id,revision,settings,updated_by_user_id,updated_at)
		VALUES($1,1,'{"source_ip_header":"X-Real-IP","api_key_enabled":false,"dns_protection":"","record_repair_mode":"repair","sync_batch":1000,"sync_scope":"line_group","disable_failed_sync_nodes":false,"resource_rank":100,"http_proxy":"","tcp_factor":1.1}'::jsonb,$2,$3)`,
		fixture.admin.ScopeID, fixture.admin.UserID, fixture.clock.Now()); err != nil {
		t.Fatalf("disable platform API keys: %v", err)
	}

	credential := issued.Key.KeyID + "." + issued.Secret
	if _, err := fixture.service.Authenticate(ctx, credential); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("disabled credential authentication error=%v", err)
	}
	before := countAPIKeys(t, fixture.pool)
	if _, err := fixture.service.CreateSelf(ctx, fixture.alice, CreateInput{
		Name: "blocked create", Scopes: []string{"sites.read"}, IdempotencyKey: "platform-api-key-status-create", RequestID: "platform-api-key-status-create",
	}); !errors.Is(err, ErrDisabled) || countAPIKeys(t, fixture.pool) != before {
		t.Fatalf("disabled self create error=%v count=%d want=%d", err, countAPIKeys(t, fixture.pool), before)
	}
	if _, err := fixture.service.AdminCreatePending(ctx, fixture.admin, AdminCreateInput{
		TargetScopeID: fixture.alice.ScopeID, TargetUserID: fixture.alice.UserID,
		Name: "blocked pending", Scopes: []string{"sites.read"}, PendingTTL: time.Hour,
		IdempotencyKey: "platform-api-key-status-admin-create", RequestID: "platform-api-key-status-admin-create",
	}); !errors.Is(err, ErrDisabled) || countAPIKeys(t, fixture.pool) != before {
		t.Fatalf("disabled admin create error=%v count=%d want=%d", err, countAPIKeys(t, fixture.pool), before)
	}
	if _, err := fixture.service.ActivateSelf(ctx, fixture.alice, MutationInput{
		ID: pending.ID, ExpectedRevision: pending.Revision, IdempotencyKey: "platform-api-key-status-activate", RequestID: "platform-api-key-status-activate",
	}); !errors.Is(err, ErrDisabled) {
		t.Fatalf("disabled activation error=%v", err)
	}
	if _, err := fixture.service.RotateSelf(ctx, fixture.alice, MutationInput{
		ID: issued.Key.ID, ExpectedRevision: issued.Key.Revision, IdempotencyKey: "platform-api-key-status-rotate", RequestID: "platform-api-key-status-rotate",
	}); !errors.Is(err, ErrDisabled) {
		t.Fatalf("disabled rotation error=%v", err)
	}
	if _, err := fixture.service.RevokeSelf(ctx, fixture.alice, MutationInput{
		ID: issued.Key.ID, ExpectedRevision: issued.Key.Revision, IdempotencyKey: "platform-api-key-status-revoke", RequestID: "platform-api-key-status-revoke",
	}); err != nil {
		t.Fatalf("revoke remains available while disabled: %v", err)
	}
	if keys, err := fixture.service.ListSelf(ctx, fixture.alice); err != nil || len(keys) != 2 {
		t.Fatalf("list remains available while disabled: count=%d err=%v", len(keys), err)
	}
}
