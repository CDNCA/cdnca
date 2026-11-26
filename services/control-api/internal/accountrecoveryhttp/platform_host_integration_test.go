package accountrecoveryhttp

import (
	"crypto/sha256"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

// Problem 42: a single-domain deployment serves tenant users on the platform
// host, so recovery from that host must reach the user's tenant membership.

func TestPlatformHostRecoversSoleTenantMember(t *testing.T) {
	fixture := newIntegrationFixture(t)
	platformScope := integrationSeedPlatformScope(t, fixture)
	platformHandler := newTrustedHandler(t, fixture, uuid.Nil, platformScope)
	integrationSeedSession(t, fixture, fixture.userID, fixture.scopeID)

	link := requestAndDispatchLinkVia(t, fixture, platformHandler, fixture.username, "platform-tenant-request")

	var challengeTenant, challengeScope, writeScope, eventScope uuid.UUID
	if err := fixture.pool.QueryRow(t.Context(), `SELECT challenge.tenant_id,challenge.scope_id,
		write_request.scope_id,
		(SELECT event.scope_id FROM notification_events event
		 JOIN account_recovery_dispatch_claims claim ON claim.reference=event.anonymous_dispatch_reference
		 WHERE claim.challenge_id=challenge.id)
		FROM account_recovery_challenges challenge
		JOIN account_recovery_write_requests write_request ON write_request.id=challenge.issued_by_write_id
		WHERE write_request.idempotency_key='platform-tenant-request'`).Scan(
		&challengeTenant, &challengeScope, &writeScope, &eventScope); err != nil {
		t.Fatal(err)
	}
	if challengeTenant != fixture.tenantID || challengeScope != fixture.scopeID ||
		writeScope != fixture.scopeID || eventScope != fixture.scopeID {
		t.Fatalf("challenge %s/%s write %s event %s, want tenant %s/%s",
			challengeTenant, challengeScope, writeScope, eventScope, fixture.tenantID, fixture.scopeID)
	}
	var platformWindows, tenantWindows int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT
		count(*) FILTER (WHERE scope_id=$1),count(*) FILTER (WHERE scope_id=$2)
		FROM account_recovery_rate_windows`, platformScope, fixture.scopeID).Scan(&platformWindows, &tenantWindows); err != nil {
		t.Fatal(err)
	}
	if platformWindows != 2 || tenantWindows != 0 {
		t.Fatalf("rate windows platform/tenant = %d/%d, want 2/0", platformWindows, tenantWindows)
	}

	response := postRecoveryConfirmation(t, platformHandler, link.token, link.recoveryContext, "platform-tenant-confirm")
	if response.Code != http.StatusNoContent {
		t.Fatalf("platform host confirmation status=%d body=%s", response.Code, response.Body.String())
	}
	assertLoginPassword(t, fixture, fixture.username, fixture.scopeID, "Changed-password-1234", fixture.password)
	var activeSessions int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM auth_sessions
		WHERE user_id=$1 AND revoked_at IS NULL`, fixture.userID).Scan(&activeSessions); err != nil {
		t.Fatal(err)
	}
	if activeSessions != 0 {
		t.Fatalf("active sessions after reset = %d", activeSessions)
	}
	replay := postRecoveryConfirmation(t, platformHandler, link.token, link.recoveryContext, "platform-tenant-confirm-again")
	if replay.Code != http.StatusBadRequest || responseCode(t, replay) != "account_recovery_invalid_token" {
		t.Fatalf("consumed link reuse status=%d body=%s", replay.Code, replay.Body.String())
	}
}

func TestPlatformHostPlatformUserKeepsPlatformScope(t *testing.T) {
	fixture := newIntegrationFixture(t)
	platformScope := integrationSeedPlatformScope(t, fixture)
	platformHandler := newTrustedHandler(t, fixture, uuid.Nil, platformScope)
	username := "platform-admin@example.test"
	userID := integrationSeedUser(t, fixture, username)
	integrationSeedMembership(t, fixture, platformScope, userID)
	// A platform member that also belongs to a tenant still recovers on the platform scope.
	integrationSeedMembership(t, fixture, fixture.scopeID, userID)

	integrationSeedSession(t, fixture, userID, platformScope)
	integrationSeedSession(t, fixture, userID, fixture.scopeID)

	link := requestAndDispatchLinkVia(t, fixture, platformHandler, username, "platform-user-request")
	var challengeTenant *uuid.UUID
	var challengeScope uuid.UUID
	if err := fixture.pool.QueryRow(t.Context(), `SELECT tenant_id,scope_id FROM account_recovery_challenges
		WHERE user_id=$1`, userID).Scan(&challengeTenant, &challengeScope); err != nil {
		t.Fatal(err)
	}
	if challengeTenant != nil || challengeScope != platformScope {
		t.Fatalf("platform user challenge tenant=%v scope=%s, want NULL/%s", challengeTenant, challengeScope, platformScope)
	}
	response := postRecoveryConfirmation(t, platformHandler, link.token, link.recoveryContext, "platform-user-confirm")
	if response.Code != http.StatusNoContent {
		t.Fatalf("platform user confirmation status=%d body=%s", response.Code, response.Body.String())
	}
	assertLoginPassword(t, fixture, username, platformScope, "Changed-password-1234", fixture.password)
	var active, revoked int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT
		count(*) FILTER (WHERE revoked_at IS NULL),
		count(*) FILTER (WHERE revocation_reason='password_reset')
		FROM auth_sessions WHERE user_id=$1`, userID).Scan(&active, &revoked); err != nil {
		t.Fatal(err)
	}
	if active != 0 || revoked != 2 {
		t.Fatalf("sessions active/revoked across scopes = %d/%d, want 0/2", active, revoked)
	}
}

func TestTenantHostCannotConfirmAnotherTenantsLink(t *testing.T) {
	fixture := newIntegrationFixture(t)
	platformScope := integrationSeedPlatformScope(t, fixture)
	platformHandler := newTrustedHandler(t, fixture, uuid.Nil, platformScope)
	otherTenant, otherScope := integrationSeedTenant(t, fixture.pool)
	otherHandler := newTrustedHandler(t, fixture, otherTenant, otherScope)

	link := requestAndDispatchLinkVia(t, fixture, platformHandler, fixture.username, "cross-tenant-request")
	response := postRecoveryConfirmation(t, otherHandler, link.token, link.recoveryContext, "cross-tenant-confirm")
	if response.Code != http.StatusBadRequest || responseCode(t, response) != "account_recovery_invalid_token" {
		t.Fatalf("other tenant host confirmation status=%d body=%s", response.Code, response.Body.String())
	}
	var consumed int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM account_recovery_challenges
		WHERE consumed_at IS NOT NULL`).Scan(&consumed); err != nil {
		t.Fatal(err)
	}
	if consumed != 0 {
		t.Fatalf("other tenant host consumed %d challenges", consumed)
	}
	// The owning tenant's host still accepts the link.
	response = postRecoveryConfirmation(t, fixture.handler, link.token, link.recoveryContext, "own-tenant-confirm")
	if response.Code != http.StatusNoContent {
		t.Fatalf("own tenant host confirmation status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestPlatformHostUnknownUserCreatesNoChallenge(t *testing.T) {
	fixture := newIntegrationFixture(t)
	platformScope := integrationSeedPlatformScope(t, fixture)
	platformHandler := newTrustedHandler(t, fixture, uuid.Nil, platformScope)

	known := postRecoveryRequest(t, platformHandler, fixture.username, "enum-known")
	unknown := postRecoveryRequest(t, platformHandler, "nobody@example.test", "enum-unknown")
	if known.Code != http.StatusAccepted || unknown.Code != http.StatusAccepted ||
		unknown.Body.String() != known.Body.String() {
		t.Fatalf("known %d %s, unknown %d %s", known.Code, known.Body.String(), unknown.Code, unknown.Body.String())
	}
	var challenges, claims, events int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM account_recovery_challenges),
		(SELECT count(*) FROM account_recovery_dispatch_claims),
		(SELECT count(*) FROM notification_events WHERE event_type='identity.account_recovery')`).Scan(
		&challenges, &claims, &events); err != nil {
		t.Fatal(err)
	}
	if challenges != 1 || claims != 1 || events != 2 {
		t.Fatalf("challenges/claims/events = %d/%d/%d, want 1/1/2", challenges, claims, events)
	}
}

func TestPlatformHostMultiTenantUserFollowsLoginScope(t *testing.T) {
	fixture := newIntegrationFixture(t)
	platformScope := integrationSeedPlatformScope(t, fixture)
	platformHandler := newTrustedHandler(t, fixture, uuid.Nil, platformScope)
	base := fixture.clock.Now()

	username := "two-tenants@example.test"
	userID := integrationSeedUser(t, fixture, username)
	_, newerScope := integrationSeedTenant(t, fixture.pool)
	integrationSeedMembershipAt(t, fixture, newerScope, userID, base.Add(time.Minute))
	integrationSeedMembershipAt(t, fixture, fixture.scopeID, userID, base)
	login, err := identity.NewStore(fixture.pool).FindLoginIdentity(t.Context(), username, nil)
	if err != nil || login.ScopeID != fixture.scopeID {
		t.Fatalf("login scope = %s (%v), want oldest membership %s", login.ScopeID, err, fixture.scopeID)
	}
	link := requestAndDispatchLinkVia(t, fixture, platformHandler, username, "multi-tenant-request")
	assertChallengeScope(t, fixture, userID, fixture.scopeID)
	if response := postRecoveryConfirmation(t, platformHandler, link.token, link.recoveryContext,
		"multi-tenant-confirm"); response.Code != http.StatusNoContent {
		t.Fatalf("multi tenant confirmation status=%d body=%s", response.Code, response.Body.String())
	}
	assertLoginPassword(t, fixture, username, fixture.scopeID, "Changed-password-1234", fixture.password)

	// Sign-in picks a suspended tenant's membership and refuses; recovery stays silent.
	suspendedName := "suspended-first@example.test"
	suspendedUser := integrationSeedUser(t, fixture, suspendedName)
	suspendedTenant, suspendedScope := integrationSeedTenant(t, fixture.pool)
	integrationSeedMembershipAt(t, fixture, suspendedScope, suspendedUser, base)
	integrationSeedMembershipAt(t, fixture, newerScope, suspendedUser, base.Add(time.Minute))
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE tenants SET status='suspended' WHERE id=$1`, suspendedTenant); err != nil {
		t.Fatal(err)
	}
	if response := postRecoveryRequest(t, platformHandler, suspendedName, "suspended-request"); response.Code != http.StatusAccepted {
		t.Fatalf("suspended tenant request status=%d body=%s", response.Code, response.Body.String())
	}
	var challenges int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM account_recovery_challenges
		WHERE user_id=$1`, suspendedUser).Scan(&challenges); err != nil {
		t.Fatal(err)
	}
	if challenges != 0 {
		t.Fatalf("suspended tenant user challenges = %d", challenges)
	}
}

func assertChallengeScope(t *testing.T, fixture *integrationFixture, userID, wantScope uuid.UUID) {
	t.Helper()
	var scopeID uuid.UUID
	if err := fixture.pool.QueryRow(t.Context(), `SELECT scope_id FROM account_recovery_challenges
		WHERE user_id=$1`, userID).Scan(&scopeID); err != nil {
		t.Fatal(err)
	}
	if scopeID != wantScope {
		t.Fatalf("challenge scope = %s, want %s", scopeID, wantScope)
	}
}

func newTrustedHandler(t *testing.T, fixture *integrationFixture, tenantID, scopeID uuid.UUID) *Handler {
	t.Helper()
	handler, err := NewHandler(fixture.service, func(request *http.Request) (TrustedContext, error) {
		key := request.Header.Get("Idempotency-Key")
		return TrustedContext{
			TenantID: tenantID, ScopeID: scopeID, RequestID: "http-" + key,
			TraceID: "trace-" + key, SourceIP: "198.51.100.21",
		}, nil
	}, Config{
		DigestKey: handlerTestKey, Clock: fixture.clock.Now,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func requestAndDispatchLinkVia(
	t *testing.T,
	fixture *integrationFixture,
	handler *Handler,
	username, key string,
) recoveryLink {
	t.Helper()
	original := *fixture
	defer func() { *fixture = original }()
	fixture.handler, fixture.username = handler, username
	return requestAndDispatchLink(t, fixture, key)
}

func assertLoginPassword(
	t *testing.T,
	fixture *integrationFixture,
	username string,
	wantScope uuid.UUID,
	current, previous string,
) {
	t.Helper()
	// The platform host signs in with no scope hint.
	login, err := identity.NewStore(fixture.pool).FindLoginIdentity(t.Context(), username, nil)
	if err != nil {
		t.Fatal(err)
	}
	if login.ScopeID != wantScope || !identity.VerifyPassword(login.PasswordHash, current) ||
		identity.VerifyPassword(login.PasswordHash, previous) {
		t.Fatalf("login scope=%s, want %s; new password accepted=%v old password accepted=%v",
			login.ScopeID, wantScope, identity.VerifyPassword(login.PasswordHash, current),
			identity.VerifyPassword(login.PasswordHash, previous))
	}
}

func integrationSeedPlatformScope(t *testing.T, fixture *integrationFixture) uuid.UUID {
	t.Helper()
	scopeID := uuid.New()
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, scopeID); err != nil {
		t.Fatal(err)
	}
	return scopeID
}

func integrationSeedUser(t *testing.T, fixture *integrationFixture, username string) uuid.UUID {
	t.Helper()
	hash, err := identity.HashPassword(fixture.password)
	if err != nil {
		t.Fatal(err)
	}
	userID := uuid.New()
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO users(
		id,username,display_name,email,password_hash,status,revision,created_at,updated_at
	) VALUES($1,$2,'Recovery HTTP User',$2,$3,'active',1,$4,$4)`, userID, username, hash, fixture.clock.Now()); err != nil {
		t.Fatal(err)
	}
	return userID
}

func integrationSeedMembership(t *testing.T, fixture *integrationFixture, scopeID, userID uuid.UUID) {
	t.Helper()
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id,status)
		VALUES($1,$2,'active')`, scopeID, userID); err != nil {
		t.Fatal(err)
	}
}

func integrationSeedMembershipAt(t *testing.T, fixture *integrationFixture, scopeID, userID uuid.UUID, createdAt time.Time) {
	t.Helper()
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id,status,created_at)
		VALUES($1,$2,'active',$3)`, scopeID, userID, createdAt); err != nil {
		t.Fatal(err)
	}
}

func integrationSeedSession(t *testing.T, fixture *integrationFixture, userID, scopeID uuid.UUID) {
	t.Helper()
	refreshDigest := sha256.Sum256([]byte(uuid.NewString()))
	now := fixture.clock.Now()
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO auth_sessions(
		id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
	) VALUES($1,$2,$3,$4,$5,$6,$7)`, uuid.New(), uuid.New(), userID, scopeID,
		refreshDigest[:], now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
}
