package impersonation

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock/protocol"
	"github.com/cdnca/cdnca/services/control-api/internal/iamstage2b"
	"github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var integrationCodeKey = []byte("impersonation-test-key-32-bytes!!")

type lockedClock struct {
	mu  sync.RWMutex
	now time.Time
}

func (clock *lockedClock) Now() time.Time {
	clock.mu.RLock()
	defer clock.mu.RUnlock()
	return clock.now
}

func (clock *lockedClock) Set(value time.Time) {
	clock.mu.Lock()
	clock.now = value
	clock.mu.Unlock()
}

func (clock *lockedClock) Add(value time.Duration) { clock.Set(clock.Now().Add(value)) }

type tenantFixture struct {
	id      uuid.UUID
	scopeID uuid.UUID
	userID  uuid.UUID
	roleID  uuid.UUID
}

type integrationFixture struct {
	pool      *pgxpool.Pool
	clock     *lockedClock
	service   *Service
	actor     Actor
	denied    Actor
	actorRole uuid.UUID
	tenantA   tenantFixture
	tenantB   tenantFixture
}

func TestMigration038RoundTripAfter037(t *testing.T) {
	pool := isolatedPool(t, false)
	applyMigrationsThrough(t, pool, 38)
	assertMigrationVersion(t, pool, 38)
	assertMigrationApplied(t, pool, 38, true)
	assertTableExists(t, pool, "admin_impersonation_grants", true)
	assertTriggerExists(t, pool, "audit_events", "audit_events_no_truncate", true)

	applyMigrationVersion(t, pool, 38, "down")
	assertMigrationVersion(t, pool, 37)
	assertMigrationApplied(t, pool, 38, false)
	assertTableExists(t, pool, "admin_impersonation_grants", false)
	assertTriggerExists(t, pool, "audit_events", "audit_events_no_truncate", true)

	applyMigrationVersion(t, pool, 38, "up")
	assertMigrationVersion(t, pool, 38)
	assertMigrationApplied(t, pool, 38, true)
	assertTableExists(t, pool, "admin_impersonation_sessions", true)
	assertTriggerExists(t, pool, "audit_events", "audit_events_no_truncate", true)
}

func TestCreateRequiresPermissionTenantIsolationAndIdempotency(t *testing.T) {
	fixture := newIntegrationFixture(t)
	request := fixture.createRequest(t, "create-1", fixture.tenantA)

	if _, err := NewService(fixture.pool, integrationCodeKey[:8]); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("NewService(short code key) error = %v", err)
	}
	if _, err := fixture.service.Create(t.Context(), fixture.denied, request); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("Create(permission denied) error = %v", err)
	}
	wrongSessionActor := fixture.actor
	wrongSessionActor.PrimaryAuthSessionID = fixture.denied.PrimaryAuthSessionID
	wrongSession := fixture.createRequest(t, "wrong-primary-session", fixture.tenantA)
	if _, err := fixture.service.Create(t.Context(), wrongSessionActor, wrongSession); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("Create(wrong primary session) error = %v", err)
	}

	crossTenant := fixture.createRequest(t, "create-cross-tenant", fixture.tenantA)
	crossTenant.SubjectUserID = fixture.tenantB.userID
	if _, err := fixture.service.Create(t.Context(), fixture.actor, crossTenant); !errors.Is(err, ErrPrincipalChanged) {
		t.Fatalf("Create(cross tenant) error = %v", err)
	}

	self := fixture.createRequest(t, "create-self", fixture.tenantA)
	self.SubjectUserID = fixture.actor.UserID
	if _, err := fixture.service.Create(t.Context(), fixture.actor, self); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("Create(self) error = %v", err)
	}

	// A tenant member who also holds the impersonation (administrator) permission
	// is never a valid target. The system-role guard forbids that grant, so the
	// fixture bypasses it for this one statement to prove the service check.
	setTargetAdminGrant := func(statement string) {
		t.Helper()
		if _, err := fixture.pool.Exec(t.Context(), `ALTER TABLE role_permissions DISABLE TRIGGER role_permissions_system_role_guard;
			`+statement+`;
			ALTER TABLE role_permissions ENABLE TRIGGER role_permissions_system_role_guard`); err != nil {
			t.Fatal(err)
		}
	}
	setTargetAdminGrant(`INSERT INTO role_permissions(role_id,permission_name) VALUES('` +
		fixture.tenantB.roleID.String() + `','` + ManagePermission + `')`)
	adminTarget := fixture.createRequest(t, "create-admin-target", fixture.tenantB)
	if _, err := fixture.service.Create(t.Context(), fixture.actor, adminTarget); !errors.Is(err, ErrPrincipalChanged) {
		t.Fatalf("Create(administrator target) error = %v", err)
	}

	nested := fixture.actor
	nested.SessionKind = SessionKindImpersonation
	nestedGrantID := uuid.New()
	nested.ImpersonationGrantID = &nestedGrantID
	nestedRequest := fixture.createRequest(t, "create-nested", fixture.tenantA)
	if _, err := fixture.service.Create(t.Context(), nested, nestedRequest); !errors.Is(err, ErrNested) {
		t.Fatalf("Create(nested) error = %v", err)
	}

	created, err := fixture.service.Create(t.Context(), fixture.actor, request)
	if err != nil {
		t.Fatalf("Create(valid) error = %v", err)
	}
	if created.AuthorizationCode == "" || created.Grant.ExpiresAt.Sub(created.Grant.CreatedAt) != CodeTTL {
		t.Fatalf("created grant = %+v", created)
	}
	var storedReason string
	if err := fixture.pool.QueryRow(t.Context(), `SELECT reason FROM admin_impersonation_grants WHERE id=$1`,
		created.Grant.ID).Scan(&storedReason); err != nil || storedReason != SwitchReason {
		t.Fatalf("stored grant reason = %q err=%v, want %q", storedReason, err, SwitchReason)
	}
	replayed, err := fixture.service.Create(t.Context(), fixture.actor, request)
	if err != nil || !replayed.Replayed || replayed.Grant.ID != created.Grant.ID ||
		replayed.AuthorizationCode != created.AuthorizationCode {
		t.Fatalf("Create(replay) = (%+v, %v), want exact replay", replayed, err)
	}
	conflict := request
	conflict.SubjectUserID = fixture.tenantB.userID
	conflict.TenantID, conflict.TenantScopeID = fixture.tenantB.id, fixture.tenantB.scopeID
	setTargetAdminGrant(`DELETE FROM role_permissions WHERE role_id='` + fixture.tenantB.roleID.String() +
		`' AND permission_name='` + ManagePermission + `'`)
	if _, err := fixture.service.Create(t.Context(), fixture.actor, conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("Create(idempotency conflict) error = %v", err)
	}

	var digestBytes int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT octet_length(code_digest)
		FROM admin_impersonation_grants WHERE id=$1`, created.Grant.ID).Scan(&digestBytes); err != nil {
		t.Fatal(err)
	}
	if digestBytes != 32 {
		t.Fatalf("stored authorization code digest length = %d", digestBytes)
	}
	var leaked bool
	if err := fixture.pool.QueryRow(t.Context(), `SELECT EXISTS(
		SELECT 1 FROM audit_events WHERE payload::text LIKE '%' || $1 || '%')`,
		created.AuthorizationCode).Scan(&leaked); err != nil {
		t.Fatal(err)
	}
	if leaked {
		t.Fatal("raw authorization code leaked into audit payload")
	}
	for _, requestID := range []string{
		request.Context.RequestID, wrongSession.Context.RequestID, crossTenant.Context.RequestID,
		self.Context.RequestID, adminTarget.Context.RequestID, nestedRequest.Context.RequestID,
	} {
		assertAuditedRequest(t, fixture.pool, requestID)
	}

	concurrent := fixture.createRequest(t, "create-concurrent", fixture.tenantA)
	type createOutcome struct {
		result CreateResult
		err    error
	}
	concurrentResults := make(chan createOutcome, 8)
	for range 8 {
		go func() {
			result, err := fixture.service.Create(context.Background(), fixture.actor, concurrent)
			concurrentResults <- createOutcome{result: result, err: err}
		}()
	}
	var concurrentID uuid.UUID
	createdCount := 0
	for range 8 {
		outcome := <-concurrentResults
		if outcome.err != nil {
			t.Fatalf("Create(concurrent replay) error = %v", outcome.err)
		}
		if concurrentID == uuid.Nil {
			concurrentID = outcome.result.Grant.ID
		}
		if outcome.result.Grant.ID != concurrentID {
			t.Fatalf("concurrent create grant ID = %s, want %s", outcome.result.Grant.ID, concurrentID)
		}
		if !outcome.result.Replayed {
			createdCount++
		}
	}
	if createdCount != 1 {
		t.Fatalf("concurrent create non-replayed results = %d, want 1", createdCount)
	}

	firstPayload := fixture.createRequest(t, "create-concurrent-conflict", fixture.tenantA)
	secondPayload := firstPayload
	secondPayload.TenantID, secondPayload.TenantScopeID = fixture.tenantB.id, fixture.tenantB.scopeID
	secondPayload.SubjectUserID = fixture.tenantB.userID
	conflictResults := make(chan error, 2)
	for _, payload := range []CreateRequest{firstPayload, secondPayload} {
		go func() {
			_, err := fixture.service.Create(context.Background(), fixture.actor, payload)
			conflictResults <- err
		}()
	}
	var successes, conflicts int
	for range 2 {
		err := <-conflictResults
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrIdempotencyConflict):
			conflicts++
		default:
			t.Fatalf("Create(concurrent conflict) error = %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent conflict outcomes success=%d conflict=%d", successes, conflicts)
	}
}

func TestExchangeIsAtomicSingleUseAndIdempotent(t *testing.T) {
	fixture := newIntegrationFixture(t)
	created := fixture.mustCreate(t, "race-grant", fixture.tenantA)
	invalidCode := fixture.exchangeRequest(created, "invalid-code-exchange")
	invalidCode.AuthorizationCode = ""
	if _, err := fixture.service.Exchange(t.Context(), invalidCode); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("Exchange(invalid code) error = %v", err)
	}
	assertAuditedRequest(t, fixture.pool, invalidCode.Context.RequestID)
	crossTenant := fixture.exchangeRequest(created, "cross-tenant-exchange")
	crossTenant.TenantID = fixture.tenantB.id
	crossTenant.TenantScopeID = fixture.tenantB.scopeID
	if _, err := fixture.service.Exchange(t.Context(), crossTenant); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("Exchange(cross tenant) error = %v", err)
	}

	type exchangeResult struct {
		request ExchangeRequest
		session Session
		err     error
	}
	results := make(chan exchangeResult, 12)
	for index := 0; index < 12; index++ {
		request := fixture.exchangeRequest(created, fmt.Sprintf("race-%02d", index))
		go func() {
			session, err := fixture.service.Exchange(context.Background(), request)
			results <- exchangeResult{request: request, session: session, err: err}
		}()
	}
	var winner exchangeResult
	winners := 0
	for range 12 {
		result := <-results
		if result.err == nil {
			winner = result
			winners++
			continue
		}
		if !errors.Is(result.err, ErrCodeReplay) {
			t.Fatalf("concurrent Exchange error = %v, want ErrCodeReplay", result.err)
		}
	}
	if winners != 1 {
		t.Fatalf("concurrent exchange winners = %d, want 1", winners)
	}
	if winner.session.Refreshable || winner.session.ExpiresAt.Sub(winner.session.CreatedAt) != SessionTTL {
		t.Fatalf("winner session = %+v", winner.session)
	}
	if winner.session.ActorUserID != fixture.actor.UserID ||
		winner.session.SubjectUserID != fixture.tenantA.userID || winner.session.TenantID != fixture.tenantA.id ||
		winner.session.GrantID != created.Grant.ID {
		t.Fatalf("session identity claims = %+v", winner.session)
	}
	replayed, err := fixture.service.Exchange(t.Context(), winner.request)
	if err != nil || !replayed.Replayed || replayed.ID != winner.session.ID {
		t.Fatalf("Exchange(idempotent replay) = (%+v, %v)", replayed, err)
	}
	var sessionCount int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM admin_impersonation_sessions
		WHERE grant_id=$1`, created.Grant.ID).Scan(&sessionCount); err != nil || sessionCount != 1 {
		t.Fatalf("session count = %d, error = %v", sessionCount, err)
	}
	if err := audit.New(fixture.pool).VerifyScope(t.Context(), fixture.tenantA.scopeID); err != nil {
		t.Fatalf("verify concurrent impersonation audit chain: %v", err)
	}
}

func TestCreateReplayNeverRevealsConsumedRevokedOrExpiredCode(t *testing.T) {
	fixture := newIntegrationFixture(t)

	consumedRequest := fixture.createRequest(t, "replay-consumed", fixture.tenantA)
	consumed, err := fixture.service.Create(t.Context(), fixture.actor, consumedRequest)
	if err != nil {
		t.Fatal(err)
	}
	fixture.mustExchange(t, consumed, "replay-consumed-exchange")
	if replay, err := fixture.service.Create(t.Context(), fixture.actor, consumedRequest); !errors.Is(err, ErrCodeReplay) || replay.AuthorizationCode != "" {
		t.Fatalf("Create(consumed replay) = (%+v, %v)", replay, err)
	}

	revokedRequest := fixture.createRequest(t, "replay-revoked", fixture.tenantA)
	revoked, err := fixture.service.Create(t.Context(), fixture.actor, revokedRequest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.Revoke(t.Context(), fixture.actor,
		fixture.revokeRequest(revoked.Grant, "replay-revoked-revoke")); err != nil {
		t.Fatal(err)
	}
	if replay, err := fixture.service.Create(t.Context(), fixture.actor, revokedRequest); !errors.Is(err, ErrGrantRevoked) || replay.AuthorizationCode != "" {
		t.Fatalf("Create(revoked replay) = (%+v, %v)", replay, err)
	}

	expiredRequest := fixture.createRequest(t, "replay-expired", fixture.tenantA)
	expired, err := fixture.service.Create(t.Context(), fixture.actor, expiredRequest)
	if err != nil {
		t.Fatal(err)
	}
	fixture.clock.Set(expired.Grant.ExpiresAt)
	if replay, err := fixture.service.Create(t.Context(), fixture.actor, expiredRequest); !errors.Is(err, ErrGrantExpired) || replay.AuthorizationCode != "" {
		t.Fatalf("Create(expired replay) = (%+v, %v)", replay, err)
	}
}

func TestUseFailsClosedForRevocationExpiryAndPrincipalChanges(t *testing.T) {
	fixture := newIntegrationFixture(t)
	session := fixture.mustExchange(t, fixture.mustCreate(t, "use-grant", fixture.tenantA), "use-exchange")

	effective, err := fixture.service.Authorize(t.Context(), UseRequest{
		Session: session, Action: "sites.read", Context: requestContext("use-allowed"),
	})
	if err != nil || len(effective.Permissions) == 0 || effective.Session.Banner.ActorDisplayName == "" ||
		effective.Session.Banner.SubjectDisplayName == "" {
		t.Fatalf("Authorize(allowed) = (%+v, %v)", effective, err)
	}
	for index, action := range []string{
		"identity.password.change", "identity.mfa.enroll", "api_key.self.create",
		"billing.adjustment.create", "identity.roles.update", "audit.event.delete", actionCreate,
	} {
		_, err := fixture.service.Authorize(t.Context(), UseRequest{
			Session: session, Action: action, Context: requestContext(fmt.Sprintf("sensitive-%d", index)),
		})
		if !errors.Is(err, ErrSensitiveAction) {
			t.Fatalf("Authorize(%s) error = %v", action, err)
		}
	}

	if _, err := fixture.pool.Exec(t.Context(), `UPDATE users SET status='disabled'
		WHERE id=$1`, fixture.tenantA.userID); err != nil {
		t.Fatal(err)
	}
	assertUseError(t, fixture, session, "target-disabled", ErrPrincipalChanged)
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE users SET status='active' WHERE id=$1`, fixture.tenantA.userID); err != nil {
		t.Fatal(err)
	}

	if _, err := fixture.pool.Exec(t.Context(), `DELETE FROM role_assignments
		WHERE scope_id=$1 AND user_id=$2 AND role_id=$3`, fixture.tenantA.scopeID,
		fixture.tenantA.userID, fixture.tenantA.roleID); err != nil {
		t.Fatal(err)
	}
	assertUseError(t, fixture, session, "target-permission-change", ErrPrincipalChanged)
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id)
		VALUES($1,$2,$3)`, fixture.tenantA.scopeID, fixture.tenantA.userID, fixture.tenantA.roleID); err != nil {
		t.Fatal(err)
	}

	if _, err := fixture.pool.Exec(t.Context(), `DELETE FROM role_assignments
		WHERE scope_id=$1 AND user_id=$2 AND role_id=$3`, fixture.actor.ScopeID,
		fixture.actor.UserID, fixture.actorRole); err != nil {
		t.Fatal(err)
	}
	assertUseError(t, fixture, session, "actor-permission-revoked", ErrPrincipalChanged)
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id)
		VALUES($1,$2,$3)`, fixture.actor.ScopeID, fixture.actor.UserID, fixture.actorRole); err != nil {
		t.Fatal(err)
	}

	tampered := session
	tampered.TenantID = fixture.tenantB.id
	assertUseError(t, fixture, tampered, "session-claim-tamper", ErrPrincipalChanged)

	fixture.clock.Set(session.ExpiresAt)
	assertUseError(t, fixture, session, "session-expired", ErrSessionExpired)
}

func TestOriginPrimarySessionRevocationAndExpiryFailClosed(t *testing.T) {
	for _, operation := range []string{"exchange", "authorize"} {
		for _, state := range []string{"revoked", "expired"} {
			t.Run(operation+"/"+state, func(t *testing.T) {
				fixture := newIntegrationFixture(t)
				created := fixture.mustCreate(t, "origin-"+operation+"-"+state, fixture.tenantA)
				var session Session
				if operation == "authorize" {
					session = fixture.mustExchange(t, created, "origin-authorize-session-"+state)
				}
				if state == "revoked" {
					if _, err := fixture.pool.Exec(t.Context(), `UPDATE auth_sessions
						SET revoked_at=$2,revocation_reason='impersonation-origin-session-test' WHERE id=$1`,
						fixture.actor.PrimaryAuthSessionID, fixture.clock.Now()); err != nil {
						t.Fatal(err)
					}
				} else if _, err := fixture.pool.Exec(t.Context(), `UPDATE auth_sessions SET expires_at=$2 WHERE id=$1`,
					fixture.actor.PrimaryAuthSessionID, fixture.clock.Now()); err != nil {
					t.Fatal(err)
				}

				key := "origin-" + operation + "-" + state + "-denied"
				var err error
				if operation == "exchange" {
					_, err = fixture.service.Exchange(t.Context(), fixture.exchangeRequest(created, key))
				} else {
					var identity EffectiveIdentity
					identity, err = fixture.service.Authorize(t.Context(), UseRequest{
						Session: session, Action: "sites.read", Context: requestContext(key),
					})
					if identity.Session.ID != uuid.Nil || len(identity.Permissions) != 0 {
						t.Fatalf("denied effective identity = %+v", identity)
					}
				}
				if !errors.Is(err, ErrPrincipalChanged) {
					t.Fatalf("%s with %s origin session error = %v, want %v",
						operation, state, err, ErrPrincipalChanged)
				}
				if operation == "exchange" {
					assertRowCount(t, fixture.pool, "admin_impersonation_sessions", "grant_id", created.Grant.ID, 0)
				}
				assertExactImpersonationDeniedAudit(t, fixture.pool, requestContext(key).RequestID,
					map[string]string{"exchange": actionExchange, "authorize": actionUse}[operation], "principal_changed", 1)
			})
		}
	}
}

func TestOriginPrimarySessionDeniedAuditFailureRollsBack(t *testing.T) {
	for _, operation := range []string{"exchange", "authorize"} {
		t.Run(operation, func(t *testing.T) {
			fixture := newIntegrationFixture(t)
			created := fixture.mustCreate(t, "origin-audit-failure-"+operation, fixture.tenantA)
			var session Session
			if operation == "authorize" {
				session = fixture.mustExchange(t, created, "origin-audit-failure-session")
			}
			if _, err := fixture.pool.Exec(t.Context(), `UPDATE auth_sessions
				SET revoked_at=$2,revocation_reason='impersonation-origin-audit-failure' WHERE id=$1`,
				fixture.actor.PrimaryAuthSessionID, fixture.clock.Now()); err != nil {
				t.Fatal(err)
			}
			auditFailure := errors.New("injected origin session denial audit failure")
			appender := &principalChangedFailingAuditAppender{
				delegate: audit.New(fixture.pool), err: auditFailure,
			}
			failing, err := NewServiceWithDependencies(fixture.pool, integrationCodeKey,
				appender, fixture.clock.Now)
			if err != nil {
				t.Fatal(err)
			}
			key := "origin-audit-failure-" + operation + "-denied"
			if operation == "exchange" {
				_, err = failing.Exchange(t.Context(), fixture.exchangeRequest(created, key))
				assertRowCount(t, fixture.pool, "admin_impersonation_sessions", "grant_id", created.Grant.ID, 0)
			} else {
				var identity EffectiveIdentity
				identity, err = failing.Authorize(t.Context(), UseRequest{
					Session: session, Action: "sites.read", Context: requestContext(key),
				})
				if identity.Session.ID != uuid.Nil || len(identity.Permissions) != 0 {
					t.Fatalf("audit-failed effective identity = %+v", identity)
				}
			}
			if !errors.Is(err, auditFailure) {
				t.Fatalf("%s denial audit failure = %v, want %v", operation, err, auditFailure)
			}
			if appender.matches.Load() != 1 {
				t.Fatalf("%s principal-changed denial audit attempts = %d, want 1",
					operation, appender.matches.Load())
			}
			assertExactImpersonationDeniedAudit(t, fixture.pool, requestContext(key).RequestID,
				map[string]string{"exchange": actionExchange, "authorize": actionUse}[operation], "principal_changed", 0)
		})
	}
}

func TestOriginPrimarySessionRevocationLinearizesWithExchangeAndAuthorize(t *testing.T) {
	for _, operation := range []string{"exchange", "authorize"} {
		t.Run("revocation-first/"+operation, func(t *testing.T) {
			fixture := newIntegrationFixture(t)
			created := fixture.mustCreate(t, "origin-revocation-first-"+operation, fixture.tenantA)
			var session Session
			if operation == "authorize" {
				session = fixture.mustExchange(t, created, "origin-revocation-first-session")
			}
			revoker, err := fixture.pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer revoker.Rollback(t.Context())
			var revokerPID int32
			if err := revoker.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&revokerPID); err != nil {
				t.Fatal(err)
			}
			if _, err := revoker.Exec(t.Context(), `UPDATE auth_sessions
				SET revoked_at=$2,revocation_reason='impersonation-origin-race' WHERE id=$1`,
				fixture.actor.PrimaryAuthSessionID, fixture.clock.Now()); err != nil {
				t.Fatal(err)
			}

			key := "origin-revocation-first-" + operation + "-denied"
			result := make(chan error, 1)
			go func() {
				if operation == "exchange" {
					_, callErr := fixture.service.Exchange(context.Background(), fixture.exchangeRequest(created, key))
					result <- callErr
					return
				}
				_, callErr := fixture.service.Authorize(context.Background(), UseRequest{
					Session: session, Action: "sites.read", Context: requestContext(key),
				})
				result <- callErr
			}()
			waitForOriginSessionBlock(t, fixture.pool, revokerPID, result)
			if err := revoker.Commit(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := <-result; !errors.Is(err, ErrPrincipalChanged) {
				t.Fatalf("%s after concurrent origin revocation = %v, want %v",
					operation, err, ErrPrincipalChanged)
			}
			if operation == "exchange" {
				assertRowCount(t, fixture.pool, "admin_impersonation_sessions", "grant_id", created.Grant.ID, 0)
			}
			assertExactImpersonationDeniedAudit(t, fixture.pool, requestContext(key).RequestID,
				map[string]string{"exchange": actionExchange, "authorize": actionUse}[operation], "principal_changed", 1)
		})

		t.Run("operation-first/"+operation, func(t *testing.T) {
			fixture := newIntegrationFixture(t)
			created := fixture.mustCreate(t, "origin-operation-first-"+operation, fixture.tenantA)
			var session Session
			if operation == "authorize" {
				session = fixture.mustExchange(t, created, "origin-operation-first-session")
			}
			entered := make(chan int32, 1)
			release := make(chan struct{})
			blocking := &blockingImpersonationAuditAppender{
				delegate: audit.New(fixture.pool), action: map[string]string{
					"exchange": actionExchange, "authorize": actionUse,
				}[operation], entered: entered, release: release,
			}
			service, err := NewServiceWithDependencies(fixture.pool, integrationCodeKey, blocking,
				fixture.clock.Now)
			if err != nil {
				t.Fatal(err)
			}
			key := "origin-operation-first-" + operation
			result := make(chan error, 1)
			go func() {
				if operation == "exchange" {
					_, callErr := service.Exchange(context.Background(), fixture.exchangeRequest(created, key))
					result <- callErr
					return
				}
				_, callErr := service.Authorize(context.Background(), UseRequest{
					Session: session, Action: "sites.read", Context: requestContext(key),
				})
				result <- callErr
			}()
			select {
			case <-entered:
			case err := <-result:
				t.Fatalf("%s returned before success audit block: %v", operation, err)
			case <-time.After(10 * time.Second):
				t.Fatalf("%s did not reach success audit", operation)
			}

			revoker, err := fixture.pool.Begin(t.Context())
			if err != nil {
				close(release)
				t.Fatal(err)
			}
			if _, err := revoker.Exec(t.Context(), `SET LOCAL lock_timeout='250ms'`); err != nil {
				_ = revoker.Rollback(t.Context())
				close(release)
				t.Fatal(err)
			}
			_, revokeErr := revoker.Exec(t.Context(), `UPDATE auth_sessions
				SET revoked_at=$2,revocation_reason='impersonation-origin-race' WHERE id=$1`,
				fixture.actor.PrimaryAuthSessionID, fixture.clock.Now())
			_ = revoker.Rollback(t.Context())
			close(release)
			callErr := <-result
			var pgErr *pgconn.PgError
			if !errors.As(revokeErr, &pgErr) || pgErr.Code != "55P03" {
				t.Fatalf("origin revocation while %s transaction was open = %v, want lock timeout",
					operation, revokeErr)
			}
			if callErr != nil {
				t.Fatalf("%s before origin revocation = %v", operation, callErr)
			}
			if _, err := fixture.pool.Exec(t.Context(), `UPDATE auth_sessions
				SET revoked_at=$2,revocation_reason='impersonation-origin-race' WHERE id=$1`,
				fixture.actor.PrimaryAuthSessionID, fixture.clock.Now()); err != nil {
				t.Fatalf("origin revocation after %s commit: %v", operation, err)
			}
		})
	}
}

func TestImpersonationIAMMutationsBindExactStage2BAuthority(t *testing.T) {
	for _, operation := range []string{"create", "exchange", "revoke"} {
		t.Run(operation, func(t *testing.T) {
			fixture := newIntegrationFixture(t)
			prepared := prepareImpersonationOperation(t, fixture, operation, "iam-bind-"+operation)
			expected := map[string]iamstage2b.Operation{
				"create":   iamstage2b.OperationImpersonationCreate,
				"exchange": iamstage2b.OperationImpersonationExchange,
				"revoke":   iamstage2b.OperationImpersonationRevoke,
			}[operation]
			appender := stage2bAssertingAuditAppender{
				delegate: audit.New(fixture.pool), action: prepared.action, operation: expected,
				scopes: []uuid.UUID{fixture.actor.ScopeID, fixture.tenantA.scopeID},
			}
			service, err := NewServiceWithDependencies(fixture.pool, integrationCodeKey, appender,
				fixture.clock.Now)
			if err != nil {
				t.Fatal(err)
			}
			result := prepared.invoke(t.Context(), service)
			if result.err != nil {
				t.Fatalf("%s exact Stage2B authority = %v", operation, result.err)
			}
			assertImpersonationOperationSucceeded(t, prepared, result)
		})
	}
}

func TestImpersonationIAMMutationFirstFailsClosed(t *testing.T) {
	mutations := []impersonationIAMMutation{
		{name: "actor-permission", apply: revokeImpersonationActorPermission},
		{name: "actor-membership", apply: suspendImpersonationActorMembership},
		{name: "target-membership", target: true, apply: suspendImpersonationTargetMembership},
		{name: "target-tenant", target: true, apply: suspendImpersonationTargetTenant},
	}
	for _, operation := range []string{"create", "exchange", "authorize", "revoke"} {
		for _, mutation := range mutations {
			if mutation.target && operation == "revoke" {
				continue
			}
			t.Run(operation+"/"+mutation.name, func(t *testing.T) {
				fixture := newIntegrationFixture(t)
				key := "iam-first-" + operation + "-" + mutation.name
				prepared := prepareImpersonationOperation(t, fixture, operation, key)
				holder, err := fixture.pool.Begin(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				defer holder.Rollback(context.Background())
				holderPID := int32(holder.Conn().PgConn().PID())
				if err := protocol.AcquireExclusive(t.Context(), holder); err != nil {
					t.Fatal(err)
				}
				if _, err := protocol.AcquireScopes(t.Context(), holder, mutation.scopes(fixture)); err != nil {
					t.Fatal(err)
				}
				if err := mutation.apply(t.Context(), holder, fixture); err != nil {
					t.Fatal(err)
				}

				result := make(chan impersonationOperationResult, 1)
				go func() { result <- prepared.invoke(context.Background(), fixture.service) }()
				waitForImpersonationIAMBlock(t, fixture.pool, holderPID, result)
				if err := holder.Commit(t.Context()); err != nil {
					t.Fatal(err)
				}
				got := <-result
				want, reason := impersonationMutationDenial(operation, mutation.target)
				if !errors.Is(got.err, want) {
					t.Fatalf("%s after committed %s = %v, want %v", operation, mutation.name, got.err, want)
				}
				assertImpersonationOperationZero(t, got)
				assertImpersonationDeniedSideEffects(t, fixture, prepared)
				assertExactImpersonationDeniedAudit(t, fixture.pool, prepared.requestID,
					prepared.action, reason, 1)
			})
		}
	}
}

func TestImpersonationIAMOperationFirstLinearizesBeforeAuthorityMutation(t *testing.T) {
	for _, operation := range []string{"create", "exchange", "authorize", "revoke"} {
		t.Run(operation, func(t *testing.T) {
			fixture := newIntegrationFixture(t)
			prepared := prepareImpersonationOperation(t, fixture, operation, "iam-operation-first-"+operation)
			entered := make(chan int32, 1)
			release := make(chan struct{})
			released := false
			defer func() {
				if !released {
					close(release)
				}
			}()
			blocking := &blockingImpersonationAuditAppender{
				delegate: audit.New(fixture.pool), action: prepared.action, entered: entered, release: release,
			}
			service, err := NewServiceWithDependencies(fixture.pool, integrationCodeKey, blocking,
				fixture.clock.Now)
			if err != nil {
				t.Fatal(err)
			}
			operationResult := make(chan impersonationOperationResult, 1)
			go func() { operationResult <- prepared.invoke(context.Background(), service) }()
			var operationPID int32
			select {
			case operationPID = <-entered:
			case result := <-operationResult:
				t.Fatalf("%s returned before success audit block: %v", operation, result.err)
			case <-time.After(10 * time.Second):
				t.Fatalf("%s did not reach success audit", operation)
			}

			mutation, err := fixture.pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer mutation.Rollback(context.Background())
			mutationPID := int32(mutation.Conn().PgConn().PID())
			mutationResult := make(chan error, 1)
			go func() {
				if err := protocol.AcquireExclusive(context.Background(), mutation); err != nil {
					mutationResult <- err
					return
				}
				if _, err := protocol.AcquireScopes(context.Background(), mutation,
					[]uuid.UUID{fixture.actor.ScopeID}); err != nil {
					mutationResult <- err
					return
				}
				if err := revokeImpersonationActorPermission(context.Background(), mutation, fixture); err != nil {
					mutationResult <- err
					return
				}
				mutationResult <- mutation.Commit(context.Background())
			}()
			waitForImpersonationIAMMutationBlock(t, fixture.pool, operationPID, mutationPID, mutationResult)
			close(release)
			released = true
			got := <-operationResult
			if got.err != nil {
				t.Fatalf("%s before authority mutation = %v", operation, got.err)
			}
			assertImpersonationOperationSucceeded(t, prepared, got)
			if err := <-mutationResult; err != nil {
				t.Fatalf("authority mutation after %s = %v", operation, err)
			}
		})
	}
}

func TestImpersonationCompletedReplayReauthorizesAndTargetSuspensionStillAllowsRevoke(t *testing.T) {
	for _, operation := range []string{"create", "exchange", "authorize", "revoke"} {
		t.Run("actor-permission/"+operation, func(t *testing.T) {
			fixture := newIntegrationFixture(t)
			prepared := prepareImpersonationOperation(t, fixture, operation, "iam-replay-actor-"+operation)
			first := prepared.invoke(t.Context(), fixture.service)
			if first.err != nil {
				t.Fatalf("initial %s = %v", operation, first.err)
			}
			if err := revokeImpersonationActorPermission(t.Context(), fixture.pool, fixture); err != nil {
				t.Fatal(err)
			}
			prepared = prepared.withContext(requestContext("iam-replay-actor-denied-" + operation))
			replay := prepared.invoke(t.Context(), fixture.service)
			want, reason := impersonationMutationDenial(operation, false)
			if !errors.Is(replay.err, want) {
				t.Fatalf("%s replay after actor permission revoke = %v, want %v", operation, replay.err, want)
			}
			assertImpersonationOperationZero(t, replay)
			assertExactImpersonationDeniedAudit(t, fixture.pool, prepared.requestID,
				prepared.action, reason, 1)
		})
	}

	for _, operation := range []string{"create", "exchange", "authorize"} {
		t.Run("target-suspended/"+operation, func(t *testing.T) {
			fixture := newIntegrationFixture(t)
			prepared := prepareImpersonationOperation(t, fixture, operation, "iam-replay-target-"+operation)
			first := prepared.invoke(t.Context(), fixture.service)
			if first.err != nil {
				t.Fatalf("initial %s = %v", operation, first.err)
			}
			if err := suspendImpersonationTargetTenant(t.Context(), fixture.pool, fixture); err != nil {
				t.Fatal(err)
			}
			prepared = prepared.withContext(requestContext("iam-replay-target-denied-" + operation))
			replay := prepared.invoke(t.Context(), fixture.service)
			if !errors.Is(replay.err, ErrPrincipalChanged) {
				t.Fatalf("%s replay after target suspension = %v, want %v",
					operation, replay.err, ErrPrincipalChanged)
			}
			assertImpersonationOperationZero(t, replay)
			assertExactImpersonationDeniedAudit(t, fixture.pool, prepared.requestID,
				prepared.action, "principal_changed", 1)
		})
	}

	t.Run("target-suspended/revoke", func(t *testing.T) {
		fixture := newIntegrationFixture(t)
		prepared := prepareImpersonationOperation(t, fixture, "revoke", "iam-target-suspended-revoke")
		if err := suspendImpersonationTargetTenant(t.Context(), fixture.pool, fixture); err != nil {
			t.Fatal(err)
		}
		result := prepared.invoke(t.Context(), fixture.service)
		if result.err != nil {
			t.Fatalf("Revoke(target suspended) = %v", result.err)
		}
		assertImpersonationOperationSucceeded(t, prepared, result)
	})
}

func TestRevocationGrantExpiryAndAuditFailureRollback(t *testing.T) {
	fixture := newIntegrationFixture(t)
	created := fixture.mustCreate(t, "revoke-grant", fixture.tenantA)
	session := fixture.mustExchange(t, created, "revoke-exchange")
	revoke := fixture.revokeRequest(created.Grant, "revoke-1")
	revoked, err := fixture.service.Revoke(t.Context(), fixture.actor, revoke)
	if err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	replayed, err := fixture.service.Revoke(t.Context(), fixture.actor, revoke)
	if err != nil || !replayed.Replayed || replayed.ID != revoked.ID {
		t.Fatalf("Revoke(replay) = (%+v, %v)", replayed, err)
	}
	conflict := revoke
	conflict.Reason = "Different revocation payload"
	if _, err := fixture.service.Revoke(t.Context(), fixture.actor, conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("Revoke(conflict) error = %v", err)
	}
	assertUseError(t, fixture, session, "revoked-use", ErrSessionRevoked)

	preRevoked := fixture.mustCreate(t, "pre-revoked-grant", fixture.tenantA)
	if _, err := fixture.service.Revoke(t.Context(), fixture.actor,
		fixture.revokeRequest(preRevoked.Grant, "pre-revoke")); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.Exchange(t.Context(), fixture.exchangeRequest(preRevoked, "pre-revoked-exchange")); !errors.Is(err, ErrGrantRevoked) {
		t.Fatalf("Exchange(revoked) error = %v", err)
	}

	expired := fixture.mustCreate(t, "expired-grant", fixture.tenantA)
	fixture.clock.Set(expired.Grant.ExpiresAt)
	if _, err := fixture.service.Exchange(t.Context(), fixture.exchangeRequest(expired, "expired-exchange")); !errors.Is(err, ErrGrantExpired) {
		t.Fatalf("Exchange(expired) error = %v", err)
	}

	fixture.clock.Add(time.Second)
	auditFailure := errors.New("injected impersonation audit failure")
	failing, err := NewServiceWithDependencies(fixture.pool, integrationCodeKey,
		failingAuditAppender{err: auditFailure}, fixture.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	failedRequest := fixture.createRequest(t, "audit-failed-create", fixture.tenantA)
	if _, err := failing.Create(t.Context(), fixture.actor, failedRequest); !errors.Is(err, auditFailure) {
		t.Fatalf("Create(audit failure) error = %v", err)
	}
	assertRowCount(t, fixture.pool, "admin_impersonation_grants", "idempotency_key", failedRequest.IdempotencyKey, 0)

	forExchange := fixture.mustCreate(t, "audit-failed-exchange-grant", fixture.tenantA)
	failedExchange := fixture.exchangeRequest(forExchange, "audit-failed-exchange")
	if _, err := failing.Exchange(t.Context(), failedExchange); !errors.Is(err, auditFailure) {
		t.Fatalf("Exchange(audit failure) error = %v", err)
	}
	assertRowCount(t, fixture.pool, "admin_impersonation_sessions", "grant_id", forExchange.Grant.ID, 0)
}

func TestAuthorizationFactsRejectDirectSQLMutationAndTruncate(t *testing.T) {
	fixture := newIntegrationFixture(t)
	created := fixture.mustCreate(t, "immutable-grant", fixture.tenantA)
	fixture.mustExchange(t, created, "immutable-exchange")
	if _, err := fixture.service.Revoke(t.Context(), fixture.actor,
		fixture.revokeRequest(created.Grant, "immutable-revoke")); err != nil {
		t.Fatal(err)
	}

	for _, statement := range []string{
		`UPDATE admin_impersonation_grants SET reason=reason WHERE id='` + created.Grant.ID.String() + `'`,
		`DELETE FROM admin_impersonation_grants WHERE id='` + created.Grant.ID.String() + `'`,
		`TRUNCATE admin_impersonation_grants CASCADE`,
		`UPDATE admin_impersonation_sessions SET expires_at=expires_at WHERE grant_id='` + created.Grant.ID.String() + `'`,
		`DELETE FROM admin_impersonation_sessions WHERE grant_id='` + created.Grant.ID.String() + `'`,
		`TRUNCATE admin_impersonation_sessions CASCADE`,
		`UPDATE admin_impersonation_revocations SET reason=reason WHERE grant_id='` + created.Grant.ID.String() + `'`,
		`DELETE FROM admin_impersonation_revocations WHERE grant_id='` + created.Grant.ID.String() + `'`,
		`TRUNCATE admin_impersonation_revocations CASCADE`,
	} {
		if _, err := fixture.pool.Exec(t.Context(), statement); err == nil ||
			!strings.Contains(err.Error(), "authorization facts are append-only") {
			t.Errorf("direct SQL mutation %q error = %v", statement, err)
		}
	}
	forgedCodeDigest := sha256.Sum256([]byte("forged-primary-session-code"))
	forgedPermissionsDigest := sha256.Sum256([]byte("forged-primary-session-permissions"))
	forgedRequestDigest := sha256.Sum256([]byte("forged-primary-session-request"))
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO admin_impersonation_grants(
		id,tenant_id,tenant_scope_id,actor_user_id,actor_scope_id,primary_auth_session_id,
		subject_user_id,code_digest,subject_permissions_digest,reason,idempotency_key,request_digest,
		request_id,trace_id,created_at,expires_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'user_list_switch','forged-primary-session',$10,
		'forged-primary-session','forged-primary-session',$11,$12)`, uuid.New(), fixture.tenantA.id,
		fixture.tenantA.scopeID, fixture.actor.UserID, fixture.actor.ScopeID,
		fixture.denied.PrimaryAuthSessionID, fixture.tenantA.userID, forgedCodeDigest[:],
		forgedPermissionsDigest[:], forgedRequestDigest[:], fixture.clock.Now(),
		fixture.clock.Now().Add(time.Minute)); err == nil ||
		!strings.Contains(err.Error(), "invalid admin impersonation principals") {
		t.Fatalf("forged primary session grant insert error = %v", err)
	}

	forgedSessionGrant := fixture.mustCreate(t, "forged-session-grant", fixture.tenantA)
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO admin_impersonation_sessions (
		id,grant_id,tenant_id,tenant_scope_id,actor_user_id,actor_scope_id,subject_user_id,
		subject_permissions_digest,exchange_idempotency_key,exchange_request_digest,
		request_id,trace_id,created_at,expires_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'forged-session',$8,'forged-session','forged-session',$9,$10)`,
		uuid.New(), forgedSessionGrant.Grant.ID, forgedSessionGrant.Grant.TenantID,
		forgedSessionGrant.Grant.TenantScopeID, forgedSessionGrant.Grant.ActorUserID,
		forgedSessionGrant.Grant.ActorScopeID, forgedSessionGrant.Grant.SubjectUserID,
		make([]byte, 32), forgedSessionGrant.Grant.CreatedAt, forgedSessionGrant.Grant.CreatedAt.Add(time.Minute)); err == nil || !strings.Contains(err.Error(), "invalid admin impersonation session fact") {
		t.Fatalf("forged session insert error = %v", err)
	}

	backdatedGrant := fixture.mustCreate(t, "backdated-revocation-grant", fixture.tenantA)
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO admin_impersonation_revocations (
		id,grant_id,tenant_id,tenant_scope_id,original_actor_user_id,original_actor_scope_id,
		subject_user_id,revoked_by_user_id,revoked_by_scope_id,reason,idempotency_key,
		request_digest,request_id,trace_id,revoked_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'forged','forged-revoke',$10,
		'forged-revoke','forged-revoke',$11)`, uuid.New(), backdatedGrant.Grant.ID,
		backdatedGrant.Grant.TenantID, backdatedGrant.Grant.TenantScopeID,
		backdatedGrant.Grant.ActorUserID, backdatedGrant.Grant.ActorScopeID,
		backdatedGrant.Grant.SubjectUserID, fixture.actor.UserID, fixture.actor.ScopeID,
		make([]byte, 32), backdatedGrant.Grant.CreatedAt.Add(-time.Second)); err == nil || !strings.Contains(err.Error(), "invalid admin impersonation revoker") {
		t.Fatalf("backdated revocation insert error = %v", err)
	}
}

type failingAuditAppender struct{ err error }

func (appender failingAuditAppender) Append(context.Context, pgx.Tx, audit.Event) error {
	return appender.err
}

type principalChangedFailingAuditAppender struct {
	delegate AuditAppender
	err      error
	matches  atomic.Int64
}

func (appender *principalChangedFailingAuditAppender) Append(
	ctx context.Context,
	tx pgx.Tx,
	event audit.Event,
) error {
	if event.Result == "denied" && event.Payload["reason_code"] == "principal_changed" {
		appender.matches.Add(1)
		return appender.err
	}
	return appender.delegate.Append(ctx, tx, event)
}

type blockingImpersonationAuditAppender struct {
	delegate AuditAppender
	action   string
	entered  chan<- int32
	release  <-chan struct{}
}

type stage2bAssertingAuditAppender struct {
	delegate  AuditAppender
	action    string
	operation iamstage2b.Operation
	scopes    []uuid.UUID
}

func (appender stage2bAssertingAuditAppender) Append(
	ctx context.Context,
	tx pgx.Tx,
	event audit.Event,
) error {
	if event.Action == appender.action && event.Result == "success" {
		if err := iamstage2b.AssertAuthorityMutation(ctx, tx, appender.operation, appender.scopes); err != nil {
			return err
		}
	}
	return appender.delegate.Append(ctx, tx, event)
}

type impersonationOperationResult struct {
	created    CreateResult
	session    Session
	identity   EffectiveIdentity
	revocation Revocation
	err        error
}

type preparedImpersonationOperation struct {
	kind          string
	action        string
	requestID     string
	grantID       uuid.UUID
	actor         Actor
	createRequest CreateRequest
	exchange      ExchangeRequest
	use           UseRequest
	revoke        RevokeRequest
}

func prepareImpersonationOperation(
	t *testing.T,
	fixture integrationFixture,
	operation, key string,
) preparedImpersonationOperation {
	t.Helper()
	switch operation {
	case "create":
		request := fixture.createRequest(t, key, fixture.tenantA)
		return preparedImpersonationOperation{kind: operation, action: actionCreate,
			requestID: request.Context.RequestID,
			actor:     fixture.actor, createRequest: request}
	case "exchange":
		created := fixture.mustCreate(t, key+"-grant", fixture.tenantA)
		request := fixture.exchangeRequest(created, key)
		return preparedImpersonationOperation{kind: operation, action: actionExchange,
			requestID: request.Context.RequestID, grantID: created.Grant.ID, exchange: request}
	case "authorize":
		created := fixture.mustCreate(t, key+"-grant", fixture.tenantA)
		session := fixture.mustExchange(t, created, key+"-session")
		request := UseRequest{Session: session, Action: "sites.read", Context: requestContext(key)}
		return preparedImpersonationOperation{kind: operation, action: actionUse,
			requestID: request.Context.RequestID, grantID: created.Grant.ID, use: request}
	case "revoke":
		created := fixture.mustCreate(t, key+"-grant", fixture.tenantA)
		request := fixture.revokeRequest(created.Grant, key)
		return preparedImpersonationOperation{kind: operation, action: actionRevoke,
			requestID: request.Context.RequestID, grantID: created.Grant.ID,
			actor: fixture.actor, revoke: request}
	default:
		t.Fatalf("unknown impersonation operation %q", operation)
		return preparedImpersonationOperation{}
	}
}

func (prepared preparedImpersonationOperation) invoke(ctx context.Context, service *Service) impersonationOperationResult {
	var result impersonationOperationResult
	switch prepared.kind {
	case "create":
		result.created, result.err = service.Create(ctx, prepared.actor, prepared.createRequest)
	case "exchange":
		result.session, result.err = service.Exchange(ctx, prepared.exchange)
	case "authorize":
		result.identity, result.err = service.Authorize(ctx, prepared.use)
	case "revoke":
		result.revocation, result.err = service.Revoke(ctx, prepared.actor, prepared.revoke)
	default:
		result.err = fmt.Errorf("unknown impersonation operation %q", prepared.kind)
	}
	return result
}

func (prepared preparedImpersonationOperation) withContext(value RequestContext) preparedImpersonationOperation {
	prepared.requestID = value.RequestID
	switch prepared.kind {
	case "create":
		prepared.createRequest.Context = value
	case "exchange":
		prepared.exchange.Context = value
	case "authorize":
		prepared.use.Context = value
	case "revoke":
		prepared.revoke.Context = value
	}
	return prepared
}

type impersonationIAMMutation struct {
	name   string
	target bool
	apply  func(context.Context, interface {
		Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	}, integrationFixture) error
}

func (mutation impersonationIAMMutation) scopes(fixture integrationFixture) []uuid.UUID {
	if mutation.target {
		return []uuid.UUID{fixture.tenantA.scopeID}
	}
	return []uuid.UUID{fixture.actor.ScopeID}
}

func revokeImpersonationActorPermission(ctx context.Context, executor interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, fixture integrationFixture) error {
	command, err := executor.Exec(ctx, `DELETE FROM role_permissions
		WHERE role_id=$1 AND permission_name=$2`, fixture.actorRole, ManagePermission)
	return exactMutationResult(command, err)
}

func suspendImpersonationActorMembership(ctx context.Context, executor interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, fixture integrationFixture) error {
	command, err := executor.Exec(ctx, `UPDATE memberships SET status='suspended'
		WHERE scope_id=$1 AND user_id=$2`, fixture.actor.ScopeID, fixture.actor.UserID)
	return exactMutationResult(command, err)
}

func suspendImpersonationTargetMembership(ctx context.Context, executor interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, fixture integrationFixture) error {
	command, err := executor.Exec(ctx, `UPDATE memberships SET status='suspended'
		WHERE scope_id=$1 AND user_id=$2`, fixture.tenantA.scopeID, fixture.tenantA.userID)
	return exactMutationResult(command, err)
}

func suspendImpersonationTargetTenant(ctx context.Context, executor interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, fixture integrationFixture) error {
	command, err := executor.Exec(ctx, `UPDATE tenants SET status='suspended',revision=revision+1
		WHERE id=$1`, fixture.tenantA.id)
	return exactMutationResult(command, err)
}

func exactMutationResult(command pgconn.CommandTag, err error) error {
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return fmt.Errorf("IAM mutation rows = %d, want 1", command.RowsAffected())
	}
	return nil
}

func impersonationMutationDenial(operation string, targetMutation bool) (error, string) {
	if !targetMutation && (operation == "create" || operation == "revoke") {
		return ErrPermissionDenied, "permission_denied"
	}
	return ErrPrincipalChanged, "principal_changed"
}

func assertImpersonationOperationZero(t *testing.T, result impersonationOperationResult) {
	t.Helper()
	if result.created.Grant.ID != uuid.Nil || result.created.AuthorizationCode != "" ||
		result.session.ID != uuid.Nil || result.identity.Session.ID != uuid.Nil ||
		len(result.identity.Permissions) != 0 || result.revocation.ID != uuid.Nil {
		t.Fatalf("denied impersonation result was not zero: %+v", result)
	}
}

func assertImpersonationOperationSucceeded(
	t *testing.T,
	prepared preparedImpersonationOperation,
	result impersonationOperationResult,
) {
	t.Helper()
	switch prepared.kind {
	case "create":
		if result.created.Grant.ID == uuid.Nil || result.created.AuthorizationCode == "" {
			t.Fatalf("Create success result = %+v", result.created)
		}
	case "exchange":
		if result.session.ID == uuid.Nil || result.session.GrantID != prepared.grantID {
			t.Fatalf("Exchange success result = %+v", result.session)
		}
	case "authorize":
		if result.identity.Session.ID == uuid.Nil || len(result.identity.Permissions) == 0 {
			t.Fatalf("Authorize success result = %+v", result.identity)
		}
	case "revoke":
		if result.revocation.ID == uuid.Nil || result.revocation.GrantID != prepared.grantID {
			t.Fatalf("Revoke success result = %+v", result.revocation)
		}
	}
}

func assertImpersonationDeniedSideEffects(
	t *testing.T,
	fixture integrationFixture,
	prepared preparedImpersonationOperation,
) {
	t.Helper()
	switch prepared.kind {
	case "create":
		assertRowCount(t, fixture.pool, "admin_impersonation_grants", "idempotency_key",
			prepared.createRequest.IdempotencyKey, 0)
	case "exchange":
		assertRowCount(t, fixture.pool, "admin_impersonation_sessions", "grant_id", prepared.grantID, 0)
	case "authorize":
		assertRowCount(t, fixture.pool, "admin_impersonation_sessions", "grant_id", prepared.grantID, 1)
		assertRowCount(t, fixture.pool, "admin_impersonation_revocations", "grant_id", prepared.grantID, 0)
	case "revoke":
		assertRowCount(t, fixture.pool, "admin_impersonation_revocations", "grant_id", prepared.grantID, 0)
	}
}

func waitForImpersonationIAMBlock(
	t *testing.T,
	pool *pgxpool.Pool,
	blockerPID int32,
	operationResult <-chan impersonationOperationResult,
) {
	t.Helper()
	waitForImpersonationAdvisoryBlock(t, pool, blockerPID, 0, func() error {
		select {
		case result := <-operationResult:
			return fmt.Errorf("impersonation operation returned before IAM mutation committed: %w", result.err)
		default:
			return nil
		}
	})
}

func waitForImpersonationIAMMutationBlock(
	t *testing.T,
	pool *pgxpool.Pool,
	blockerPID, waiterPID int32,
	mutationResult <-chan error,
) {
	t.Helper()
	waitForImpersonationAdvisoryBlock(t, pool, blockerPID, waiterPID, func() error {
		select {
		case err := <-mutationResult:
			return fmt.Errorf("IAM mutation returned before impersonation committed: %w", err)
		default:
			return nil
		}
	})
}

func waitForImpersonationAdvisoryBlock(
	t *testing.T,
	pool *pgxpool.Pool,
	blockerPID, waiterPID int32,
	returned func() error,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := returned(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-ticker.C:
			var blocked bool
			err := pool.QueryRow(ctx, `SELECT EXISTS (
				SELECT 1 FROM pg_stat_activity activity
				WHERE ($2=0 OR activity.pid=$2) AND $1=ANY(pg_blocking_pids(activity.pid))
				  AND activity.wait_event_type='Lock' AND activity.wait_event='advisory')`,
				blockerPID, waiterPID).Scan(&blocked)
			if err != nil {
				if ctx.Err() != nil {
					t.Fatalf("wait for impersonation IAM lock: %v", ctx.Err())
				}
				t.Fatal(err)
			}
			if blocked {
				return
			}
		case <-ctx.Done():
			t.Fatalf("impersonation IAM operation did not block: %v", ctx.Err())
		}
	}
}

func (appender *blockingImpersonationAuditAppender) Append(
	ctx context.Context,
	tx pgx.Tx,
	event audit.Event,
) error {
	if err := appender.delegate.Append(ctx, tx, event); err != nil {
		return err
	}
	if event.Action != appender.action || event.Result != "success" {
		return nil
	}
	var pid int32
	if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		return err
	}
	select {
	case appender.entered <- pid:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-appender.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func newIntegrationFixture(t *testing.T) integrationFixture {
	t.Helper()
	pool := isolatedPool(t, true)
	clock := &lockedClock{now: time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)}
	fixture := integrationFixture{pool: pool, clock: clock, actorRole: uuid.New()}
	platformScopeID := uuid.New()
	actorUserID, deniedUserID := uuid.New(), uuid.New()
	actorSessionID, deniedSessionID := uuid.New(), uuid.New()
	fixture.tenantA = tenantFixture{id: uuid.New(), scopeID: uuid.New(), userID: uuid.New(), roleID: uuid.New()}
	fixture.tenantB = tenantFixture{id: uuid.New(), scopeID: uuid.New(), userID: uuid.New(), roleID: uuid.New()}

	ctx := context.Background()
	for _, tenant := range []tenantFixture{fixture.tenantA, fixture.tenantB} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,display_name) VALUES($1,$2)`, tenant.id,
			"Impersonation tenant "+tenant.id.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`,
			tenant.scopeID, tenant.id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platformScopeID); err != nil {
		t.Fatal(err)
	}
	for _, user := range []struct {
		id, scopeID           uuid.UUID
		username, displayName string
	}{
		{actorUserID, platformScopeID, "impersonation-admin", "Control administrator"},
		{deniedUserID, platformScopeID, "impersonation-denied", "Unprivileged administrator"},
		{fixture.tenantA.userID, fixture.tenantA.scopeID, "impersonation-target-a", "Tenant user A"},
		{fixture.tenantB.userID, fixture.tenantB.scopeID, "impersonation-target-b", "Tenant user B"},
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO users(id,username,display_name,password_hash)
			VALUES($1,$2,$3,'integration-password-hash')`, user.id, user.username, user.displayName); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`,
			user.scopeID, user.id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO roles(id,scope_id,name,description,system_role)
		VALUES($1,$2,'impersonation_admin','test',true)`, fixture.actorRole, platformScopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO role_permissions(role_id,permission_name) VALUES($1,$2)`,
		fixture.actorRole, ManagePermission); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`,
		platformScopeID, actorUserID, fixture.actorRole); err != nil {
		t.Fatal(err)
	}
	for index, session := range []struct {
		id, userID uuid.UUID
	}{{actorSessionID, actorUserID}, {deniedSessionID, deniedUserID}} {
		refreshDigest := sha256.Sum256([]byte(fmt.Sprintf("impersonation-primary-session-%d", index)))
		if _, err := pool.Exec(ctx, `INSERT INTO auth_sessions(
			id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
		) VALUES($1,$1,$2,$3,$4,$5,$6)`, session.id, session.userID, platformScopeID,
			refreshDigest[:], clock.Now().Add(-time.Hour), clock.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	for _, tenant := range []tenantFixture{fixture.tenantA, fixture.tenantB} {
		if _, err := pool.Exec(ctx, `INSERT INTO roles(id,scope_id,name,description,system_role)
			VALUES($1,$2,'impersonation_target','test',true)`, tenant.roleID, tenant.scopeID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO role_permissions(role_id,permission_name)
			VALUES($1,'sites.read'),($1,'sites.manage')`, tenant.roleID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO role_assignments(scope_id,user_id,role_id)
			VALUES($1,$2,$3)`, tenant.scopeID, tenant.userID, tenant.roleID); err != nil {
			t.Fatal(err)
		}
	}
	fixture.actor = Actor{UserID: actorUserID, ScopeID: platformScopeID,
		PrimaryAuthSessionID: actorSessionID, ScopeKind: "platform", SessionKind: SessionKindPrimary}
	fixture.denied = Actor{UserID: deniedUserID, ScopeID: platformScopeID,
		PrimaryAuthSessionID: deniedSessionID, ScopeKind: "platform", SessionKind: SessionKindPrimary}
	service, err := NewServiceWithDependencies(pool, integrationCodeKey, audit.New(pool), clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	fixture.service = service
	return fixture
}

func (fixture integrationFixture) createRequest(t *testing.T, key string, tenant tenantFixture) CreateRequest {
	t.Helper()
	return CreateRequest{TenantID: tenant.id, TenantScopeID: tenant.scopeID, SubjectUserID: tenant.userID,
		IdempotencyKey: key, Context: requestContext(key)}
}

func (fixture integrationFixture) mustCreate(t *testing.T, key string, tenant tenantFixture) CreateResult {
	t.Helper()
	result, err := fixture.service.Create(t.Context(), fixture.actor, fixture.createRequest(t, key, tenant))
	if err != nil {
		t.Fatalf("Create(%s) error = %v", key, err)
	}
	return result
}

func (fixture integrationFixture) exchangeRequest(created CreateResult, key string) ExchangeRequest {
	return ExchangeRequest{TenantID: created.Grant.TenantID, TenantScopeID: created.Grant.TenantScopeID,
		AuthorizationCode: created.AuthorizationCode, IdempotencyKey: key, Context: requestContext(key)}
}

func (fixture integrationFixture) mustExchange(t *testing.T, created CreateResult, key string) Session {
	t.Helper()
	result, err := fixture.service.Exchange(t.Context(), fixture.exchangeRequest(created, key))
	if err != nil {
		t.Fatalf("Exchange(%s) error = %v", key, err)
	}
	return result
}

func (fixture integrationFixture) revokeRequest(grant Grant, key string) RevokeRequest {
	return RevokeRequest{GrantID: grant.ID, TenantID: grant.TenantID, TenantScopeID: grant.TenantScopeID,
		Reason: "End support access immediately", IdempotencyKey: key, Context: requestContext(key)}
}

func requestContext(key string) RequestContext {
	return RequestContext{RequestID: "request-" + key, TraceID: "trace-" + key}
}

func assertUseError(t *testing.T, fixture integrationFixture, session Session, key string, want error) {
	t.Helper()
	_, err := fixture.service.Authorize(t.Context(), UseRequest{
		Session: session, Action: "sites.read", Context: requestContext(key),
	})
	if !errors.Is(err, want) {
		t.Fatalf("Authorize(%s) error = %v, want %v", key, err, want)
	}
}

func assertAuditedRequest(t *testing.T, pool *pgxpool.Pool, requestID string) {
	t.Helper()
	var count int
	var traceID string
	if err := pool.QueryRow(t.Context(), `SELECT count(*),COALESCE(max(payload->>'trace_id'),'')
		FROM audit_events WHERE request_id=$1`, requestID).Scan(&count, &traceID); err != nil {
		t.Fatal(err)
	}
	if count == 0 || traceID == "" {
		t.Fatalf("audit request %q count=%d trace=%q", requestID, count, traceID)
	}
}

func assertExactImpersonationDeniedAudit(
	t *testing.T,
	pool *pgxpool.Pool,
	requestID, action, reason string,
	want int,
) {
	t.Helper()
	var exact, total int
	if err := pool.QueryRow(t.Context(), `SELECT
		count(*) FILTER (WHERE action=$2 AND result='denied' AND payload->>'reason_code'=$3),
		count(*) FROM audit_events WHERE request_id=$1`, requestID, action, reason).Scan(&exact, &total); err != nil {
		t.Fatal(err)
	}
	if exact != want || total != want {
		t.Fatalf("impersonation denied audit %s exact/total=%d/%d, want %d/%d",
			requestID, exact, total, want, want)
	}
}

func waitForOriginSessionBlock(
	t *testing.T,
	pool *pgxpool.Pool,
	blockerPID int32,
	operationResult <-chan error,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-operationResult:
			t.Fatalf("impersonation operation returned before origin-session revocation committed: %v", err)
		case <-ticker.C:
			var blocked bool
			err := pool.QueryRow(ctx, `SELECT EXISTS (
				SELECT 1 FROM pg_stat_activity activity
				WHERE $1=ANY(pg_blocking_pids(activity.pid))
				  AND activity.query LIKE '%FROM auth_sessions%'
				  AND activity.query LIKE '%FOR UPDATE%')`, blockerPID).Scan(&blocked)
			if err != nil {
				if ctx.Err() != nil {
					t.Fatalf("wait for origin-session lock: %v", ctx.Err())
				}
				t.Fatal(err)
			}
			if blocked {
				return
			}
		case <-ctx.Done():
			t.Fatalf("impersonation operation did not block on origin session: %v", ctx.Err())
		}
	}
}

func assertRowCount(t *testing.T, pool *pgxpool.Pool, table, column string, value any, want int) {
	t.Helper()
	query := `SELECT count(*) FROM ` + pgx.Identifier{table}.Sanitize() + ` WHERE ` +
		pgx.Identifier{column}.Sanitize() + `=$1`
	var count int
	if err := pool.QueryRow(t.Context(), query, value).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != want {
		t.Fatalf("%s count = %d, want %d", table, count, want)
	}
}

func isolatedPool(t *testing.T, migrate bool) *pgxpool.Pool {
	t.Helper()
	if migrate {
		// The service under test runs against the release head.
		return databasetest.MigratedPool(t, nil)
	}
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.Ping(ctx); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	schema := "impersonation_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^impersonation_test_[a-f0-9]{32}$`).MatchString(schema) {
		admin.Close()
		t.Fatalf("unsafe schema %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop impersonation schema: %v", err)
		}
		admin.Close()
	})
	return pool
}

func assertMigrationVersion(t *testing.T, pool *pgxpool.Pool, want int64) {
	t.Helper()
	var got int64
	if err := pool.QueryRow(t.Context(), `SELECT COALESCE(max(version),0) FROM schema_migrations`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("migration version = %d, want %d", got, want)
	}
}

func assertMigrationApplied(t *testing.T, pool *pgxpool.Pool, version int64, want bool) {
	t.Helper()
	var got bool
	if err := pool.QueryRow(t.Context(), `SELECT EXISTS(
		SELECT 1 FROM schema_migrations WHERE version=$1)`, version).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("migration %d applied = %t, want %t", version, got, want)
	}
}

func applyMigrationsThrough(t *testing.T, pool *pgxpool.Pool, target int) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `CREATE TABLE schema_migrations (
		version bigint PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	for version := 1; version <= target; version++ {
		applyMigrationVersion(t, pool, version, "up")
	}
}

func applyMigrationVersion(t *testing.T, pool *pgxpool.Pool, version int, direction string) {
	t.Helper()
	matches, err := fs.Glob(migrations.FS, fmt.Sprintf("%03d_*.%s.sql", version, direction))
	if err != nil || len(matches) != 1 {
		t.Fatalf("migration %03d %s matches=%v error=%v", version, direction, matches, err)
	}
	script, err := fs.ReadFile(migrations.FS, matches[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), string(script)); err != nil {
			return err
		}
		if direction == "up" {
			_, err = tx.Exec(t.Context(), `INSERT INTO schema_migrations(version) VALUES($1)`, version)
		} else {
			_, err = tx.Exec(t.Context(), `DELETE FROM schema_migrations WHERE version=$1`, version)
		}
		return err
	}); err != nil {
		t.Fatalf("apply migration %03d %s: %v", version, direction, err)
	}
}

func assertTableExists(t *testing.T, pool *pgxpool.Pool, table string, want bool) {
	t.Helper()
	var got bool
	if err := pool.QueryRow(t.Context(), `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("table %s exists = %t, want %t", table, got, want)
	}
}

func assertTriggerExists(t *testing.T, pool *pgxpool.Pool, table, trigger string, want bool) {
	t.Helper()
	var got bool
	if err := pool.QueryRow(t.Context(), `SELECT EXISTS(
		SELECT 1 FROM pg_trigger trigger
		JOIN pg_class relation ON relation.oid=trigger.tgrelid
		WHERE relation.relname=$1 AND trigger.tgname=$2 AND NOT trigger.tgisinternal)`, table, trigger).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("trigger %s.%s exists = %t, want %t", table, trigger, got, want)
	}
}
