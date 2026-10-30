package accountrecovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var errInjectedAudit = errors.New("injected account recovery audit failure")

type failingAudit struct{}

func (failingAudit) Append(context.Context, pgx.Tx, audit.Event) error { return errInjectedAudit }

type fixedClock struct {
	mu  sync.Mutex
	now time.Time
}

type passwordHasherSpy struct {
	mu    sync.Mutex
	calls int
}

func (spy *passwordHasherSpy) Hash(password string) (string, error) {
	spy.mu.Lock()
	spy.calls++
	spy.mu.Unlock()
	return identity.HashPassword(password)
}

func (spy *passwordHasherSpy) Calls() int {
	spy.mu.Lock()
	defer spy.mu.Unlock()
	return spy.calls
}

func (c *fixedClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fixedClock) Set(now time.Time) {
	c.mu.Lock()
	c.now = now
	c.mu.Unlock()
}

type fixture struct {
	pool     *pgxpool.Pool
	service  *Service
	store    *notification.Store
	keyring  *DispatchKeyring
	clock    *fixedClock
	tenantID uuid.UUID
	scopeID  uuid.UUID
	userID   uuid.UUID
	username string
	password string
}

type recoveredDelivery struct {
	Token     string
	ExpiresAt time.Time
}

func TestRequestRecoveryIsEnumerationSafeAndInvalidatesOldToken(t *testing.T) {
	f := newFixture(t, 20, 20)
	ctx := t.Context()

	existing, err := f.service.Request(ctx, requestInput(f, f.username, "request-existing", "198.51.100.10"))
	if err != nil {
		t.Fatal(err)
	}
	first := recoveryDeliveryForRequest(t, f, "request-existing")
	nonexistent, err := f.service.Request(ctx, requestInput(f, "missing@example.test", "request-missing", "198.51.100.11"))
	if err != nil {
		t.Fatal(err)
	}
	setUserStatus(t, f.pool, f.userID, "disabled")
	disabled, err := f.service.Request(ctx, requestInput(f, f.username, "request-disabled", "198.51.100.12"))
	if err != nil {
		t.Fatal(err)
	}
	setMembershipStatus(t, f.pool, f.scopeID, f.userID, "suspended")
	setUserStatus(t, f.pool, f.userID, "active")
	suspended, err := f.service.Request(ctx, requestInput(f, f.username, "request-suspended", "198.51.100.14"))
	if err != nil {
		t.Fatal(err)
	}
	if existing != nonexistent || nonexistent != disabled || disabled != suspended {
		t.Fatalf("enumerable responses: existing=%+v nonexistent=%+v disabled=%+v suspended=%+v", existing, nonexistent, disabled, suspended)
	}
	if events, outbox, claims := recoveryDispatchCounts(t, f.pool); events != 4 || outbox != 4 || claims != 1 {
		t.Fatalf("dispatch facts after enumeration cases = %d/%d/%d, want 4/4/1", events, outbox, claims)
	}

	setMembershipStatus(t, f.pool, f.scopeID, f.userID, "active")
	replayed, err := f.service.Request(ctx, requestInput(f, f.username, "request-existing", "198.51.100.10"))
	if err != nil || !replayed.AcceptedAt.Equal(existing.AcceptedAt) {
		t.Fatalf("idempotent request = (%+v, %v)", replayed, err)
	}
	if events, outbox, claims := recoveryDispatchCounts(t, f.pool); events != 4 || outbox != 4 || claims != 1 {
		t.Fatalf("replay duplicated dispatch facts = %d/%d/%d", events, outbox, claims)
	}
	conflict := requestInput(f, "other@example.test", "request-existing", "198.51.100.10")
	if _, err := f.service.Request(ctx, conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("same key with different payload error = %v", err)
	}

	if _, err := f.service.Request(ctx, requestInput(f, f.username, "request-replacement", "198.51.100.13")); err != nil {
		t.Fatal(err)
	}
	second := recoveryDeliveryForRequest(t, f, "request-replacement")
	if second.Token == first.Token {
		t.Fatal("repeated request reused the recovery token")
	}
	if _, err := f.service.Reset(ctx, resetInput(f, first.Token, "replacement-old-token", "Fresh-password-1234")); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("superseded token reset error = %v", err)
	}
	if _, err := f.service.Reset(ctx, resetInput(f, second.Token, "replacement-current-token", "Fresh-password-1234")); err != nil {
		t.Fatalf("current token reset: %v", err)
	}

	assertRateWindowPrivacy(t, f.pool)
	assertNoSecretsInRecoveryAudit(t, f.pool, []string{first.Token, second.Token, "Fresh-password-1234", f.username})
}

func TestRequestRecoveryEnqueuesPublishedSystemUserTemplate(t *testing.T) {
	f := newFixture(t, 20, 20)
	published := notification.TemplateRef{
		ID: "platform_user_account_recovery", Version: 2, Channel: notification.ChannelEmail,
	}
	if err := f.store.SaveTemplate(t.Context(), notification.TemplateDefinition{
		Ref: published, Subject: "找回密码：{{.username}}", Body: "<p>您好，{{.username}}。</p>",
		Variables: []string{"username"},
	}); err != nil {
		t.Fatal(err)
	}
	config := testConfig(f)
	config.TemplateResolver = recoveryTemplateResolver{email: published}
	service, err := NewServiceWithDependencies(f.pool, config, audit.New(f.pool))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Request(t.Context(), requestInput(f, f.username, "published-template", "198.51.100.44")); err != nil {
		t.Fatal(err)
	}
	var templateID, subject, body string
	var templateVersion int64
	if err := f.pool.QueryRow(t.Context(), `SELECT template_id,template_version,subject,body
		FROM notification_outbox ORDER BY created_at DESC,id DESC LIMIT 1`).Scan(
		&templateID, &templateVersion, &subject, &body,
	); err != nil {
		t.Fatal(err)
	}
	if templateID != published.ID || templateVersion != int64(published.Version) ||
		subject != "找回密码：{{.username}}" || body != "<p>您好，{{.username}}。</p>" {
		t.Fatalf("published recovery outbox=(%q,%d,%q,%q)", templateID, templateVersion, subject, body)
	}
}

func TestRequestRecoveryRateLimitsSubjectAndSourcePersistently(t *testing.T) {
	f := newFixture(t, 2, 2)
	ctx := t.Context()
	for i := 0; i < 2; i++ {
		_, err := f.service.Request(ctx, requestInput(f, "missing@example.test", fmt.Sprintf("subject-%d", i), fmt.Sprintf("198.51.100.%d", i+20)))
		if err != nil {
			t.Fatalf("subject request %d: %v", i, err)
		}
	}
	if _, err := f.service.Request(ctx, requestInput(f, "missing@example.test", "subject-limited", "198.51.100.22")); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("subject limit error = %v", err)
	}
	for i := 0; i < 2; i++ {
		_, err := f.service.Request(ctx, requestInput(f, fmt.Sprintf("other-%d@example.test", i), fmt.Sprintf("source-%d", i), "203.0.113.9"))
		if err != nil {
			t.Fatalf("source request %d: %v", i, err)
		}
	}
	if _, err := f.service.Request(ctx, requestInput(f, "another@example.test", "source-limited", "203.0.113.9")); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("source limit error = %v", err)
	}
	if _, err := f.service.Request(ctx, requestInput(f, f.username, "source-limited-existing", "203.0.113.9")); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("existing subject at limited source error = %v", err)
	}
	assertRateWindowPrivacy(t, f.pool)
}

func TestRequestIdempotencyReplayIgnoresSourceIP(t *testing.T) {
	f := newFixture(t, 20, 20)
	ctx := t.Context()
	const key = "request-source-change"

	first, err := f.service.Request(ctx, requestInput(f, f.username, key, "198.51.100.30"))
	if err != nil {
		t.Fatal(err)
	}
	before := tableCounts(t, f.pool)
	replayed, err := f.service.Request(ctx, requestInput(f, f.username, key, "203.0.113.30"))
	if err != nil || !replayed.AcceptedAt.Equal(first.AcceptedAt) {
		t.Fatalf("cross-source request replay = (%+v, %v)", replayed, err)
	}
	if after := tableCounts(t, f.pool); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatalf("cross-source request replay changed facts before=%v after=%v", before, after)
	}

	conflict := requestInput(f, "other@example.test", key, "203.0.113.30")
	if _, err := f.service.Request(ctx, conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("same key with different subject error = %v", err)
	}
}

func TestScopeAndTenantFailClosed(t *testing.T) {
	f := newFixture(t, 10, 10)
	wrongTenant := requestInput(f, f.username, "wrong-tenant", "198.51.100.30")
	wrongTenant.TenantID = uuid.New()
	if _, err := f.service.Request(t.Context(), wrongTenant); !errors.Is(err, ErrScopeMismatch) {
		t.Fatalf("wrong tenant request error = %v", err)
	}
	wrongScope := requestInput(f, f.username, "wrong-scope", "198.51.100.31")
	wrongScope.ScopeID = uuid.New()
	if _, err := f.service.Request(t.Context(), wrongScope); !errors.Is(err, ErrScopeMismatch) {
		t.Fatalf("wrong scope request error = %v", err)
	}
	platformScope := seedPlatformScope(t, f.pool)
	seedMembership(t, f.pool, platformScope, f.userID)
	platform := requestInput(f, f.username, "platform-scope", "198.51.100.32")
	platform.TenantID = uuid.Nil
	platform.ScopeID = platformScope
	accepted, err := f.service.Request(t.Context(), platform)
	if err != nil {
		t.Fatalf("platform scope request error = %v", err)
	}
	missing := platform
	missing.Username = "missing-platform-owner@example.test"
	missing.IdempotencyKey = "platform-scope-missing"
	missing.Context.RequestID = "platform-scope-missing-request-id"
	missing.Context.TraceID = "platform-scope-missing-trace-id"
	missing.Context.SourceIP = "198.51.100.33"
	missingAccepted, err := f.service.Request(t.Context(), missing)
	if err != nil || missingAccepted != accepted {
		t.Fatalf("platform enumeration-safe request = (%+v, %v), want %+v", missingAccepted, err, accepted)
	}
	if events, outbox, claims := recoveryDispatchCounts(t, f.pool); events != 2 || outbox != 2 || claims != 1 {
		t.Fatalf("platform recovery dispatch facts = %d/%d/%d, want 2/2/1", events, outbox, claims)
	}
	var challenges, claims int
	if err := f.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM account_recovery_challenges WHERE scope_id=$1 AND tenant_id IS NULL),
		(SELECT count(*) FROM account_recovery_dispatch_claims WHERE scope_id=$1 AND tenant_id IS NULL)`,
		platformScope).Scan(&challenges, &claims); err != nil {
		t.Fatal(err)
	}
	if challenges != 1 || claims != 1 {
		t.Fatalf("platform recovery challenge/claim = %d/%d, want 1/1", challenges, claims)
	}
}

func TestResetConsumesOnceRevokesAllSessionsAndRejectsPasswordReuse(t *testing.T) {
	f := newFixture(t, 20, 20)
	ctx := t.Context()
	seedSession(t, f.pool, f.userID, f.scopeID, f.clock.Now())
	otherTenant, otherScope := seedTenant(t, f.pool, "Other tenant")
	seedMembership(t, f.pool, otherScope, f.userID)
	seedSession(t, f.pool, f.userID, otherScope, f.clock.Now())
	_ = otherTenant

	if _, err := f.service.Request(ctx, requestInput(f, f.username, "reuse-request", "198.51.100.40")); err != nil {
		t.Fatal(err)
	}
	token := recoveryDeliveryForRequest(t, f, "reuse-request").Token
	if _, err := f.service.Reset(ctx, resetInput(f, token, "reuse-reset", f.password)); !errors.Is(err, ErrPasswordReused) {
		t.Fatalf("password reuse error = %v", err)
	}
	if _, err := f.service.Reset(ctx, resetInput(f, token, "short-password", "Short-1")); !errors.Is(err, ErrPasswordPolicy) { // pwd-policy：至少 8 位、两类字符
		t.Fatalf("short password policy error = %v", err)
	}
	result, err := f.service.Reset(ctx, resetInput(f, token, "reset-success", "Changed-password-1234"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Replayed {
		t.Fatal("first successful reset marked replayed")
	}
	replay, err := f.service.Reset(ctx, resetInput(f, token, "reset-success", "Changed-password-1234"))
	if err != nil || !replay.Replayed || !replay.CompletedAt.Equal(result.CompletedAt) {
		t.Fatalf("idempotent reset = (%+v, %v)", replay, err)
	}
	conflict := resetInput(f, token, "reset-success", "Different-password-1234")
	if _, err := f.service.Reset(ctx, conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("reset same key different payload error = %v", err)
	}
	if _, err := f.service.Reset(ctx, resetInput(f, token, "reset-replay", "Changed-password-1234")); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("consumed token replay error = %v", err)
	}

	var hash string
	if err := f.pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE id=$1`, f.userID).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if !identity.VerifyPassword(hash, "Changed-password-1234") || identity.VerifyPassword(hash, f.password) {
		t.Fatal("password hash was not replaced with Argon2id credential")
	}
	var activeSessions int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM auth_sessions WHERE user_id=$1 AND revoked_at IS NULL`, f.userID).Scan(&activeSessions); err != nil {
		t.Fatal(err)
	}
	if activeSessions != 0 {
		t.Fatalf("active sessions after reset = %d", activeSessions)
	}
	var reasons []string
	rows, err := f.pool.Query(ctx, `SELECT revocation_reason FROM auth_sessions WHERE user_id=$1 ORDER BY scope_id`, f.userID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var reason string
		if err := rows.Scan(&reason); err != nil {
			t.Fatal(err)
		}
		reasons = append(reasons, reason)
	}
	if fmt.Sprint(reasons) != "[password_reset password_reset]" {
		t.Fatalf("session revocation reasons = %v", reasons)
	}
	if err := audit.New(f.pool).VerifyScope(ctx, f.scopeID); err != nil {
		t.Fatalf("verify recovery audit chain: %v", err)
	}
}

func TestResetIdempotencyReplayIgnoresSourceIP(t *testing.T) {
	f := newFixture(t, 20, 20)
	ctx := t.Context()
	if _, err := f.service.Request(ctx, requestInput(f, f.username, "reset-source-request", "198.51.100.40")); err != nil {
		t.Fatal(err)
	}
	token := recoveryDeliveryForRequest(t, f, "reset-source-request").Token
	const key = "reset-source-change"
	firstInput := resetInput(f, token, key, "Changed-password-1234")
	firstInput.Context.SourceIP = "198.51.100.41"
	first, err := f.service.Reset(ctx, firstInput)
	if err != nil {
		t.Fatal(err)
	}
	before := tableCounts(t, f.pool)

	replayInput := resetInput(f, token, key, "Changed-password-1234")
	replayInput.Context.SourceIP = "203.0.113.41"
	replayed, err := f.service.Reset(ctx, replayInput)
	if err != nil || !replayed.Replayed || !replayed.CompletedAt.Equal(first.CompletedAt) {
		t.Fatalf("cross-source reset replay = (%+v, %v)", replayed, err)
	}
	if after := tableCounts(t, f.pool); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatalf("cross-source reset replay changed facts before=%v after=%v", before, after)
	}
	var revision int64
	if err := f.pool.QueryRow(ctx, `SELECT revision FROM users WHERE id=$1`, f.userID).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	if revision != 2 {
		t.Fatalf("user revision after reset replay = %d, want 2", revision)
	}

	conflict := resetInput(f, token, key, "Different-password-1234")
	conflict.Context.SourceIP = "203.0.113.41"
	if _, err := f.service.Reset(ctx, conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("same key with different password error = %v", err)
	}
}

func TestResetExpirationPrincipalCASAndConcurrentSingleWinner(t *testing.T) {
	t.Run("expired", func(t *testing.T) {
		f := newFixture(t, 20, 20)
		if _, err := f.service.Request(t.Context(), requestInput(f, f.username, "expire-request", "198.51.100.50")); err != nil {
			t.Fatal(err)
		}
		delivery := recoveryDeliveryForRequest(t, f, "expire-request")
		f.clock.Set(delivery.ExpiresAt)
		token := delivery.Token
		if _, err := f.service.Reset(t.Context(), resetInput(f, token, "expire-reset", "Changed-password-1234")); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("expired token reset error = %v", err)
		}
	})

	t.Run("principal revision changed", func(t *testing.T) {
		f := newFixture(t, 20, 20)
		if _, err := f.service.Request(t.Context(), requestInput(f, f.username, "cas-request", "198.51.100.51")); err != nil {
			t.Fatal(err)
		}
		token := recoveryDeliveryForRequest(t, f, "cas-request").Token
		if _, err := f.pool.Exec(t.Context(), `UPDATE users SET revision=revision+1 WHERE id=$1`, f.userID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.service.Reset(t.Context(), resetInput(f, token, "cas-reset", "Changed-password-1234")); !errors.Is(err, ErrPrincipalChanged) {
			t.Fatalf("principal CAS error = %v", err)
		}
	})

	t.Run("concurrent single winner", func(t *testing.T) {
		f := newFixture(t, 20, 20)
		if _, err := f.service.Request(t.Context(), requestInput(f, f.username, "race-request", "198.51.100.52")); err != nil {
			t.Fatal(err)
		}
		token := recoveryDeliveryForRequest(t, f, "race-request").Token
		spy := installPasswordHasherSpy(f)
		start := make(chan struct{})
		errs := make(chan error, 2)
		for i := 0; i < 2; i++ {
			go func(index int) {
				<-start
				_, err := f.service.Reset(context.Background(), resetInput(f, token, fmt.Sprintf("race-reset-%d", index), "Changed-password-1234"))
				errs <- err
			}(i)
		}
		close(start)
		var successes, invalid int
		for i := 0; i < 2; i++ {
			err := <-errs
			switch {
			case err == nil:
				successes++
			case errors.Is(err, ErrInvalidToken):
				invalid++
			default:
				t.Fatalf("concurrent reset error = %v", err)
			}
		}
		if successes != 1 || invalid != 1 {
			t.Fatalf("concurrent reset outcomes success=%d invalid=%d", successes, invalid)
		}
		assertPasswordHashCalls(t, spy, 1)
	})
}

func TestResetDefersPasswordHashUntilAuthorizedWinner(t *testing.T) {
	t.Run("invalid token", func(t *testing.T) {
		f := newFixture(t, 20, 20)
		spy := installPasswordHasherSpy(f)
		token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x7d}, tokenBytes))
		if _, err := f.service.Reset(t.Context(), resetInput(f, token, "hash-invalid", "Changed-password-1234")); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("invalid token reset error = %v", err)
		}
		assertPasswordHashCalls(t, spy, 0)
	})

	t.Run("expired token", func(t *testing.T) {
		f := newFixture(t, 20, 20)
		if _, err := f.service.Request(t.Context(), requestInput(f, f.username, "hash-expired-request", "198.51.100.80")); err != nil {
			t.Fatal(err)
		}
		delivery := recoveryDeliveryForRequest(t, f, "hash-expired-request")
		f.clock.Set(delivery.ExpiresAt)
		spy := installPasswordHasherSpy(f)
		if _, err := f.service.Reset(t.Context(), resetInput(f, delivery.Token, "hash-expired", "Changed-password-1234")); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("expired token reset error = %v", err)
		}
		assertPasswordHashCalls(t, spy, 0)
	})

	t.Run("revoked token", func(t *testing.T) {
		f := newFixture(t, 20, 20)
		if _, err := f.service.Request(t.Context(), requestInput(f, f.username, "hash-revoked-first", "198.51.100.81")); err != nil {
			t.Fatal(err)
		}
		first := recoveryDeliveryForRequest(t, f, "hash-revoked-first")
		if _, err := f.service.Request(t.Context(), requestInput(f, f.username, "hash-revoked-second", "198.51.100.82")); err != nil {
			t.Fatal(err)
		}
		spy := installPasswordHasherSpy(f)
		if _, err := f.service.Reset(t.Context(), resetInput(f, first.Token, "hash-revoked", "Changed-password-1234")); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("revoked token reset error = %v", err)
		}
		assertPasswordHashCalls(t, spy, 0)
	})

	t.Run("principal changed", func(t *testing.T) {
		f := newFixture(t, 20, 20)
		if _, err := f.service.Request(t.Context(), requestInput(f, f.username, "hash-principal-request", "198.51.100.83")); err != nil {
			t.Fatal(err)
		}
		token := recoveryDeliveryForRequest(t, f, "hash-principal-request").Token
		if _, err := f.pool.Exec(t.Context(), `UPDATE users SET revision=revision+1 WHERE id=$1`, f.userID); err != nil {
			t.Fatal(err)
		}
		spy := installPasswordHasherSpy(f)
		if _, err := f.service.Reset(t.Context(), resetInput(f, token, "hash-principal", "Changed-password-1234")); !errors.Is(err, ErrPrincipalChanged) {
			t.Fatalf("principal changed reset error = %v", err)
		}
		assertPasswordHashCalls(t, spy, 0)
	})

	t.Run("password reused", func(t *testing.T) {
		f := newFixture(t, 20, 20)
		if _, err := f.service.Request(t.Context(), requestInput(f, f.username, "hash-reused-request", "198.51.100.84")); err != nil {
			t.Fatal(err)
		}
		token := recoveryDeliveryForRequest(t, f, "hash-reused-request").Token
		spy := installPasswordHasherSpy(f)
		if _, err := f.service.Reset(t.Context(), resetInput(f, token, "hash-reused", f.password)); !errors.Is(err, ErrPasswordReused) {
			t.Fatalf("password reused reset error = %v", err)
		}
		assertPasswordHashCalls(t, spy, 0)
	})

	t.Run("success replay and consumed token", func(t *testing.T) {
		f := newFixture(t, 20, 20)
		if _, err := f.service.Request(t.Context(), requestInput(f, f.username, "hash-success-request", "198.51.100.85")); err != nil {
			t.Fatal(err)
		}
		token := recoveryDeliveryForRequest(t, f, "hash-success-request").Token
		spy := installPasswordHasherSpy(f)
		first, err := f.service.Reset(t.Context(), resetInput(f, token, "hash-success", "Changed-password-1234"))
		if err != nil || first.Replayed {
			t.Fatalf("first reset = (%+v, %v)", first, err)
		}
		assertPasswordHashCalls(t, spy, 1)
		replay, err := f.service.Reset(t.Context(), resetInput(f, token, "hash-success", "Changed-password-1234"))
		if err != nil || !replay.Replayed {
			t.Fatalf("idempotent replay = (%+v, %v)", replay, err)
		}
		assertPasswordHashCalls(t, spy, 1)
		if _, err := f.service.Reset(t.Context(), resetInput(f, token, "hash-consumed", "Another-password-1234")); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("consumed token reset error = %v", err)
		}
		assertPasswordHashCalls(t, spy, 1)
	})
}

func TestAuditFailureRollsBackRequestAndReset(t *testing.T) {
	f := newFixture(t, 20, 20)
	bad, err := NewServiceWithDependencies(f.pool, testConfig(f), failingAudit{})
	if err != nil {
		t.Fatal(err)
	}
	before := tableCounts(t, f.pool)
	if _, err := bad.Request(t.Context(), requestInput(f, f.username, "audit-request", "198.51.100.60")); !errors.Is(err, errInjectedAudit) {
		t.Fatalf("request audit failure = %v", err)
	}
	after := tableCounts(t, f.pool)
	if fmt.Sprint(before) != fmt.Sprint(after) {
		t.Fatalf("request audit rollback before=%v after=%v", before, after)
	}

	if _, err := f.service.Request(t.Context(), requestInput(f, f.username, "reset-audit-request", "198.51.100.61")); err != nil {
		t.Fatal(err)
	}
	token := recoveryDeliveryForRequest(t, f, "reset-audit-request").Token
	seedSession(t, f.pool, f.userID, f.scopeID, f.clock.Now())
	var oldHash string
	if err := f.pool.QueryRow(t.Context(), `SELECT password_hash FROM users WHERE id=$1`, f.userID).Scan(&oldHash); err != nil {
		t.Fatal(err)
	}
	before = tableCounts(t, f.pool)
	if _, err := bad.Reset(t.Context(), resetInput(f, token, "audit-reset", "Changed-password-1234")); !errors.Is(err, errInjectedAudit) {
		t.Fatalf("reset audit failure = %v", err)
	}
	after = tableCounts(t, f.pool)
	if fmt.Sprint(before) != fmt.Sprint(after) {
		t.Fatalf("reset audit rollback before=%v after=%v", before, after)
	}
	var currentHash string
	var activeSessions int
	if err := f.pool.QueryRow(t.Context(), `SELECT password_hash FROM users WHERE id=$1`, f.userID).Scan(&currentHash); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM auth_sessions WHERE user_id=$1 AND revoked_at IS NULL`, f.userID).Scan(&activeSessions); err != nil {
		t.Fatal(err)
	}
	if currentHash != oldHash || activeSessions != 1 {
		t.Fatalf("reset audit failure leaked mutation hash_changed=%t active_sessions=%d", currentHash != oldHash, activeSessions)
	}
}

func TestMigrationRoundTripAndDirectSQLProtection(t *testing.T) {
	t.Run("040 down/up", func(t *testing.T) {
		pool := isolatedPoolThrough(t, 67)
		for version := int64(67); version > 40; version-- {
			applyAccountRecoveryMigrationFile(t, pool, accountRecoveryMigrationName(t, version, ".down.sql"), version, false)
		}
		assertMigrationVersion(t, pool, 40)
		assertTableExists(t, pool, "account_recovery_dispatch_claims", false)
		assertTableExists(t, pool, "account_recovery_public_hosts", false)
		applyAccountRecoveryMigrationFile(t, pool, "040_account_recovery.down.sql", 40, false)
		assertMigrationVersion(t, pool, 39)
		assertTableExists(t, pool, "account_recovery_challenges", false)
		applyAccountRecoveryMigrationFile(t, pool, "040_account_recovery.up.sql", 40, true)
		assertMigrationVersion(t, pool, 40)
		seedMigration040Facts(t, pool, true, true, true)
		assertMigration040State(t, pool, [3]int{1, 1, 1})
	})
	t.Run("050 down/up", func(t *testing.T) {
		pool := isolatedPoolThrough(t, 50)
		applyAccountRecoveryMigrationFile(t, pool, "050_account_recovery_dispatch.down.sql", 50, false)
		assertMigrationVersion(t, pool, 49)
		assertTableExists(t, pool, "account_recovery_dispatch_claims", false)
		applyAccountRecoveryMigrationFile(t, pool, "050_account_recovery_dispatch.up.sql", 50, true)
		assertMigrationVersion(t, pool, 50)
	})

	f := newFixture(t, 20, 20)
	pool := f.pool
	if _, err := f.service.Request(t.Context(), requestInput(f, f.username, "tamper-request", "198.51.100.70")); err != nil {
		t.Fatal(err)
	}
	delivery := recoveryDeliveryForRequest(t, f, "tamper-request")
	var challengeID uuid.UUID
	tokenDigest := keyedDigest(testDigestKey, tokenDigestDomain, delivery.Token)
	if err := pool.QueryRow(t.Context(), `SELECT id FROM account_recovery_challenges WHERE token_digest=$1`,
		tokenDigest[:]).Scan(&challengeID); err != nil {
		t.Fatal(err)
	}
	var dispatchReference uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT reference FROM account_recovery_dispatch_claims
		WHERE challenge_id=$1`, challengeID).Scan(&dispatchReference); err != nil {
		t.Fatal(err)
	}
	assertSQLRejected(t, pool, "account recovery challenge transition", `UPDATE account_recovery_challenges
		SET consumed_at=$2, terminal_reason='consumed' WHERE id=$1`, challengeID, f.clock.Now())
	assertSQLRejected(t, pool, "account recovery facts are append-only", `UPDATE account_recovery_challenges
		SET token_digest=$2 WHERE id=$1`, challengeID, bytes.Repeat([]byte{1}, 32))
	assertSQLRejected(t, pool, "account recovery facts are append-only", `DELETE FROM account_recovery_challenges WHERE id=$1`, challengeID)
	assertSQLRejected(t, pool, "account recovery facts cannot be truncated", `TRUNCATE account_recovery_challenges CASCADE`)
	assertSQLRejected(t, pool, "account recovery dispatch claims are append-only", `UPDATE account_recovery_dispatch_claims
		SET aad_sha256=$2 WHERE reference=$1`, dispatchReference, bytes.Repeat([]byte{3}, 32))
	assertSQLRejected(t, pool, "account recovery dispatch claims are append-only", `DELETE FROM account_recovery_dispatch_claims
		WHERE reference=$1`, dispatchReference)
	assertSQLRejected(t, pool, "account recovery dispatch claims cannot be truncated", `TRUNCATE account_recovery_dispatch_claims`)
	assertSQLRejected(t, pool, "account recovery write requests are protected", `UPDATE account_recovery_write_requests
		SET response_code='completed', completed_at=$2 WHERE operation='request' AND idempotency_key=$1`, "tamper-request", f.clock.Now())
	assertSQLRejected(t, pool, "account recovery rate windows are protected", `UPDATE account_recovery_rate_windows SET request_count=0`)
	assertSQLRejected(t, pool, "account recovery rate windows are protected", `DELETE FROM account_recovery_rate_windows`)
	assertSQLRejected(t, pool, "account recovery facts cannot be truncated", `TRUNCATE account_recovery_write_requests CASCADE`)
	incompleteWriteID := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO account_recovery_write_requests(
		id,tenant_id,scope_id,operation,idempotency_key,request_digest,request_id,trace_id,created_at
	) VALUES($1,$2,$3,'request','direct-fake-completion',$4,'direct-request','direct-trace',$5)`,
		incompleteWriteID, f.tenantID, f.scopeID, bytes.Repeat([]byte{2}, 32), f.clock.Now()); err != nil {
		t.Fatal(err)
	}
	assertSQLRejected(t, pool, "account recovery write completion requires audit", `UPDATE account_recovery_write_requests
		SET response_code='accepted',completed_at=$2 WHERE id=$1`, incompleteWriteID, f.clock.Now())
	assertSQLRejected(t, pool, "audit_events is append-only", `UPDATE audit_events SET result='failure' WHERE action='identity.account_recovery.request'`)
	assertSQLRejected(t, pool, "audit_events is append-only", `DELETE FROM audit_events WHERE action='identity.account_recovery.request'`)
	if _, err := pool.Exec(t.Context(), `TRUNCATE audit_events`); err == nil {
		t.Fatal("TRUNCATE audit_events unexpectedly succeeded")
	}
	down050, err := fs.ReadFile(migrations.FS, "050_account_recovery_dispatch.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), string(down050)); err == nil ||
		!strings.Contains(err.Error(), "cannot roll back account recovery dispatch while claims exist") {
		t.Fatalf("lossy 050 down error = %v", err)
	}

	if _, err := f.service.Reset(t.Context(), resetInput(f, delivery.Token, "tamper-reset", "Changed-password-1234")); err != nil {
		t.Fatalf("legitimate reset after rejected tamper: %v", err)
	}
	assertSQLRejected(t, pool, "account recovery challenge transition", `UPDATE account_recovery_challenges
		SET consumed_at=$2 WHERE id=$1`, challengeID, f.clock.Now())
}

func TestMigration040DownRejectsPersistentFactsAtomically(t *testing.T) {
	cases := []struct {
		name                         string
		write, challenge, rateWindow bool
		want                         [3]int
	}{
		{name: "write request", write: true, want: [3]int{1, 0, 0}},
		{name: "challenge and required write", challenge: true, want: [3]int{1, 1, 0}},
		{name: "rate window", rateWindow: true, want: [3]int{0, 0, 1}},
		{name: "all facts", write: true, challenge: true, rateWindow: true, want: [3]int{1, 1, 1}},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			pool := isolatedPoolThrough(t, 40)
			seedMigration040Facts(t, pool, testCase.write, testCase.challenge, testCase.rateWindow)
			assertMigration040State(t, pool, testCase.want)

			script, err := fs.ReadFile(migrations.FS, "040_account_recovery.down.sql")
			if err != nil {
				t.Fatal(err)
			}
			err = pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
				_, err := tx.Exec(t.Context(), string(script))
				return err
			})
			var postgresError *pgconn.PgError
			if !errors.As(err, &postgresError) || postgresError.Code != "55000" ||
				postgresError.Message != "cannot roll back account recovery while facts exist" {
				t.Fatalf("040 lossy down error = %v", err)
			}

			assertMigrationVersion(t, pool, 40)
			assertMigration040State(t, pool, testCase.want)
		})
	}
}

func seedMigration040Facts(t *testing.T, pool *pgxpool.Pool, write, challenge, rateWindow bool) {
	t.Helper()
	tenantID, scopeID := seedTenant(t, pool, "Migration 040 tenant")
	now := time.Date(2026, 7, 23, 1, 0, 0, 0, time.UTC)

	var writeID uuid.UUID
	if write || challenge {
		writeID = uuid.New()
		if _, err := pool.Exec(t.Context(), `INSERT INTO account_recovery_write_requests(
			id,tenant_id,scope_id,operation,idempotency_key,request_digest,request_id,trace_id,created_at
		) VALUES($1,$2,$3,'request',$4,$5,$6,$7,$8)`, writeID, tenantID, scopeID,
			"migration-040-"+writeID.String(), bytes.Repeat([]byte{0x40}, 32),
			"migration-040-request", "migration-040-trace", now); err != nil {
			t.Fatal(err)
		}
	}
	if challenge {
		userID := uuid.New()
		passwordHash, err := identity.HashPassword(testPassword)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(t.Context(), `INSERT INTO users(
			id,username,display_name,email,password_hash,status,revision,created_at,updated_at
		) VALUES($1,$2,'Migration 040 User',$2,$3,'active',1,$4,$4)`,
			userID, "migration-040-"+userID.String()+"@example.test", passwordHash, now); err != nil {
			t.Fatal(err)
		}
		seedMembership(t, pool, scopeID, userID)
		if _, err := pool.Exec(t.Context(), `INSERT INTO account_recovery_challenges(
			id,tenant_id,scope_id,user_id,token_digest,subject_digest,password_revision,
			issued_by_write_id,issued_at,expires_at
		) VALUES($1,$2,$3,$4,$5,$6,1,$7,$8,$9)`, uuid.New(), tenantID, scopeID, userID,
			bytes.Repeat([]byte{0x41}, 32), bytes.Repeat([]byte{0x42}, 32), writeID, now, now.Add(15*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	if rateWindow {
		if _, err := pool.Exec(t.Context(), `INSERT INTO account_recovery_rate_windows(
			tenant_id,scope_id,identifier_kind,identifier_digest,window_started_at,request_count,created_at,updated_at
		) VALUES($1,$2,'subject',$3,$4,1,$4,$4)`, tenantID, scopeID,
			bytes.Repeat([]byte{0x43}, 32), now); err != nil {
			t.Fatal(err)
		}
	}
}

func assertMigration040State(t *testing.T, pool *pgxpool.Pool, want [3]int) {
	t.Helper()
	var got [3]int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM account_recovery_write_requests),
		(SELECT count(*) FROM account_recovery_challenges),
		(SELECT count(*) FROM account_recovery_rate_windows)`).Scan(&got[0], &got[1], &got[2]); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("040 fact counts = %v, want %v", got, want)
	}

	var functions, triggers int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM pg_proc WHERE oid = ANY(ARRAY[
			to_regprocedure('validate_account_recovery_scope()'),
			to_regprocedure('validate_account_recovery_challenge_insert()'),
			to_regprocedure('protect_account_recovery_challenge()'),
			to_regprocedure('protect_account_recovery_write_request()'),
			to_regprocedure('protect_account_recovery_rate_window()'),
			to_regprocedure('prevent_account_recovery_truncate()')
		])),
		(SELECT count(*) FROM pg_trigger
		 WHERE tgrelid = ANY(ARRAY[
			to_regclass('account_recovery_write_requests'),
			to_regclass('account_recovery_challenges'),
			to_regclass('account_recovery_rate_windows')
		 ]) AND tgname = ANY(ARRAY[
			'account_recovery_write_requests_scope',
			'account_recovery_rate_windows_scope',
			'account_recovery_challenges_validate_insert',
			'account_recovery_challenges_protected',
			'account_recovery_write_requests_protected',
			'account_recovery_rate_windows_protected',
			'account_recovery_challenges_no_truncate',
			'account_recovery_write_requests_no_truncate',
			'account_recovery_rate_windows_no_truncate'
		]))`).Scan(&functions, &triggers); err != nil {
		t.Fatal(err)
	}
	if functions != 6 || triggers != 9 {
		t.Fatalf("040 protected objects functions/triggers = %d/%d, want 6/9", functions, triggers)
	}
}

func accountRecoveryMigrationName(t *testing.T, version int64, suffix string) string {
	t.Helper()
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	prefix := fmt.Sprintf("%03d_", version)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), prefix) && strings.HasSuffix(entry.Name(), suffix) {
			return entry.Name()
		}
	}
	t.Fatalf("migration %03d%s not found", version, suffix)
	return ""
}

const testPassword = "Initial-password-1234"

var testDigestKey = bytes.Repeat([]byte{0x4a}, 32)

func newFixture(t *testing.T, subjectLimit, sourceLimit int) *fixture {
	t.Helper()
	return seedFixture(t, isolatedPool(t, true), subjectLimit, sourceLimit)
}

func seedFixture(t *testing.T, pool *pgxpool.Pool, subjectLimit, sourceLimit int) *fixture {
	t.Helper()
	clock := &fixedClock{now: time.Date(2026, 7, 22, 2, 0, 0, 0, time.UTC)}
	store, err := notification.NewStoreWithClock(pool, audit.New(pool), clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetChannelSwitches(t.Context(), notification.ChannelSwitches{Email: true}); err != nil {
		t.Fatal(err)
	}
	template := notification.TemplateRef{ID: "account_recovery", Version: 1, Channel: notification.ChannelEmail}
	if err := store.SaveTemplate(t.Context(), notification.TemplateDefinition{
		Ref: template, Subject: "重置密码", Body: "请使用安全链接重置密码", Variables: []string{},
	}); err != nil && !errors.Is(err, notification.ErrTemplateExists) {
		t.Fatal(err)
	}
	keyring, err := NewDispatchKeyring("recovery-test-v1", map[string][]byte{
		"recovery-test-v1": bytes.Repeat([]byte{0x5b}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	config := testConfigWithLimits(clock, keyring, store, template, subjectLimit, sourceLimit)
	service, err := NewServiceWithDependencies(pool, config, audit.New(pool))
	if err != nil {
		t.Fatal(err)
	}
	tenantID, scopeID := seedTenant(t, pool, "Recovery tenant")
	userID := uuid.New()
	username := "recover@example.test"
	hash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	now := clock.Now()
	if _, err := pool.Exec(t.Context(), `INSERT INTO users (
		id,username,display_name,email,password_hash,status,revision,created_at,updated_at
	) VALUES($1,$2,'Recovery User',$2,$3,'active',1,$4,$4)`, userID, username, hash, now); err != nil {
		t.Fatal(err)
	}
	seedMembership(t, pool, scopeID, userID)
	return &fixture{pool: pool, service: service, store: store, keyring: keyring, clock: clock,
		tenantID: tenantID, scopeID: scopeID, userID: userID, username: username, password: testPassword}
}

func testConfig(f *fixture) Config {
	template := notification.TemplateRef{ID: "account_recovery", Version: 1, Channel: notification.ChannelEmail}
	return testConfigWithLimits(f.clock, f.keyring, f.store, template, 20, 20)
}

func installPasswordHasherSpy(f *fixture) *passwordHasherSpy {
	spy := &passwordHasherSpy{}
	f.service.hashPassword = spy.Hash
	return spy
}

func assertPasswordHashCalls(t *testing.T, spy *passwordHasherSpy, want int) {
	t.Helper()
	if got := spy.Calls(); got != want {
		t.Fatalf("password hash calls = %d, want %d", got, want)
	}
}

func testConfigWithLimits(
	clock *fixedClock,
	keyring *DispatchKeyring,
	store DispatchEnqueuer,
	template notification.TemplateRef,
	subjectLimit, sourceLimit int,
) Config {
	return Config{Clock: clock.Now, DigestKey: testDigestKey,
		TokenTTL: 10 * time.Minute, RateWindow: 15 * time.Minute,
		SubjectLimit: subjectLimit, SourceLimit: sourceLimit, DispatchKeyring: keyring,
		DispatchEnqueuer:  store,
		DispatchTemplates: map[notification.Channel]notification.TemplateRef{template.Channel: template}}
}

func requestInput(f *fixture, username, key, source string) RequestInput {
	return RequestInput{TenantID: f.tenantID, ScopeID: f.scopeID, Username: username,
		IdempotencyKey: key, Context: RequestContext{RequestID: key + "-request-id", TraceID: key + "-trace-id", SourceIP: source}}
}

func resetInput(f *fixture, token, key, password string) ResetInput {
	return ResetInput{TenantID: f.tenantID, ScopeID: f.scopeID, Token: token,
		NewPassword: password, ConfirmPassword: password, IdempotencyKey: key,
		Context: RequestContext{RequestID: key + "-request-id", TraceID: key + "-trace-id", SourceIP: "198.51.100.99"}}
}

func seedTenant(t *testing.T, pool *pgxpool.Pool, name string) (uuid.UUID, uuid.UUID) {
	t.Helper()
	tenantID, scopeID := uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO tenants(id,display_name) VALUES($1,$2)`, tenantID, name); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID); err != nil {
		t.Fatal(err)
	}
	return tenantID, scopeID
}

func seedPlatformScope(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, id); err != nil {
		t.Fatal(err)
	}
	return id
}

func seedMembership(t *testing.T, pool *pgxpool.Pool, scopeID, userID uuid.UUID) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id,status) VALUES($1,$2,'active')`, scopeID, userID); err != nil {
		t.Fatal(err)
	}
}

func seedSession(t *testing.T, pool *pgxpool.Pool, userID, scopeID uuid.UUID, now time.Time) {
	t.Helper()
	refreshDigest := sha256.Sum256([]byte(uuid.NewString()))
	if _, err := pool.Exec(t.Context(), `INSERT INTO auth_sessions(
		id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
	) VALUES($1,$2,$3,$4,$5,$6,$7)`, uuid.New(), uuid.New(), userID, scopeID,
		refreshDigest[:], now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
}

func setUserStatus(t *testing.T, pool *pgxpool.Pool, userID uuid.UUID, status string) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `UPDATE users SET status=$2 WHERE id=$1`, userID, status); err != nil {
		t.Fatal(err)
	}
}

func setMembershipStatus(t *testing.T, pool *pgxpool.Pool, scopeID, userID uuid.UUID, status string) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `UPDATE memberships SET status=$3 WHERE scope_id=$1 AND user_id=$2`, scopeID, userID, status); err != nil {
		t.Fatal(err)
	}
}

func tableCounts(t *testing.T, pool *pgxpool.Pool) []int {
	t.Helper()
	tables := []string{
		"account_recovery_challenges", "account_recovery_dispatch_claims", "account_recovery_rate_windows",
		"account_recovery_write_requests", "notification_events", "notification_outbox", "audit_events",
	}
	result := make([]int, 0, len(tables))
	for _, table := range tables {
		var count int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM `+pgx.Identifier{table}.Sanitize()).Scan(&count); err != nil {
			t.Fatal(err)
		}
		result = append(result, count)
	}
	return result
}

func recoveryDispatchCounts(t *testing.T, pool *pgxpool.Pool) (int, int, int) {
	t.Helper()
	var events, outbox, claims int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM notification_events WHERE event_type='identity.account_recovery'),
		(SELECT count(*) FROM notification_outbox outbox JOIN notification_events event ON event.id=outbox.event_id
		 WHERE event.event_type='identity.account_recovery'),
		(SELECT count(*) FROM account_recovery_dispatch_claims)`).Scan(&events, &outbox, &claims); err != nil {
		t.Fatal(err)
	}
	return events, outbox, claims
}

func recoveryDeliveryForRequest(t *testing.T, f *fixture, idempotencyKey string) recoveredDelivery {
	t.Helper()
	var claim dispatchClaim
	err := f.pool.QueryRow(t.Context(), `SELECT claim.reference,claim.tenant_id,claim.scope_id,claim.user_id,
		claim.challenge_id,claim.kek_key_id,claim.wrapped_data_key,claim.sealed_token,claim.aad_sha256,
		claim.email_digest,claim.phone_digest,claim.issued_at,claim.expires_at
		FROM account_recovery_dispatch_claims claim
		JOIN account_recovery_challenges challenge ON challenge.id=claim.challenge_id
		JOIN account_recovery_write_requests write_request ON write_request.id=challenge.issued_by_write_id
		WHERE claim.scope_id=$1 AND claim.user_id=$2 AND write_request.idempotency_key=$3`,
		f.scopeID, f.userID, idempotencyKey).Scan(
		&claim.Reference, &claim.TenantID, &claim.ScopeID, &claim.UserID, &claim.ChallengeID,
		&claim.KeyID, &claim.WrappedKey, &claim.SealedToken, &claim.AADHash,
		&claim.EmailDigest, &claim.PhoneDigest, &claim.IssuedAt, &claim.ExpiresAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := f.keyring.open(claim.KeyID, claim.WrappedKey, claim.SealedToken, dispatchClaimAAD(claim))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plaintext)
	return recoveredDelivery{Token: string(plaintext), ExpiresAt: claim.ExpiresAt}
}

func assertRateWindowPrivacy(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var invalid int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM account_recovery_rate_windows
		WHERE octet_length(identifier_digest)<>32 OR identifier_digest=decode('', 'hex')`).Scan(&invalid); err != nil {
		t.Fatal(err)
	}
	if invalid != 0 {
		t.Fatalf("invalid private rate identifiers = %d", invalid)
	}
	var leaked int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM account_recovery_rate_windows
		WHERE identifier_digest=convert_to($1,'UTF8')`, "missing@example.test").Scan(&leaked); err != nil {
		t.Fatal(err)
	}
	if leaked != 0 {
		t.Fatalf("plaintext rate identifiers = %d", leaked)
	}
}

func assertNoSecretsInRecoveryAudit(t *testing.T, pool *pgxpool.Pool, secrets []string) {
	t.Helper()
	rows, err := pool.Query(t.Context(), `SELECT payload::text FROM audit_events WHERE action LIKE 'identity.account_recovery.%'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			t.Fatal(err)
		}
		for _, secret := range secrets {
			if strings.Contains(payload, secret) {
				t.Fatal("account recovery audit payload leaked sensitive input")
			}
		}
	}
}

// isolatedPool opens an empty schema, or (migrate) one at the release head:
// the service under test runs against the head schema.
func isolatedPool(t *testing.T, migrate bool) *pgxpool.Pool {
	if !migrate {
		return isolatedPoolThrough(t, 0)
	}
	return databasetest.MigratedPool(t, nil)
}

func isolatedPoolThrough(t *testing.T, through int64) *pgxpool.Pool {
	t.Helper()
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
	schema := "account_recovery_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^account_recovery_test_[a-f0-9]{32}$`).MatchString(schema) {
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
			t.Errorf("drop account recovery schema: %v", err)
		}
		admin.Close()
	})
	if through > 0 {
		migrateAccountRecoveryThrough(t, pool, through)
	}
	return pool
}

type accountRecoveryMigration struct {
	version int64
	name    string
}

func migrateAccountRecoveryThrough(t *testing.T, pool *pgxpool.Pool, through int64) {
	t.Helper()
	ctx := t.Context()
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version bigint PRIMARY KEY,
		applied_at timestamptz NOT NULL DEFAULT now()
	)`); err != nil {
		t.Fatal(err)
	}
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	var items []accountRecoveryMigration
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".up.sql") {
			continue
		}
		underscore := strings.IndexByte(name, '_')
		if underscore < 1 {
			t.Fatalf("invalid migration name %q", name)
		}
		version, err := strconv.ParseInt(name[:underscore], 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		if version <= through {
			items = append(items, accountRecoveryMigration{version: version, name: name})
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].version < items[j].version })
	if int64(len(items)) != through {
		t.Fatalf("account recovery migration count through %03d = %d, want %d", through, len(items), through)
	}
	for _, item := range items {
		applyAccountRecoveryMigrationFile(t, pool, item.name, item.version, true)
	}
}

func applyAccountRecoveryMigrationFile(t *testing.T, pool *pgxpool.Pool, name string, version int64, up bool) {
	t.Helper()
	script, err := fs.ReadFile(migrations.FS, name)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, string(script)); err != nil {
			return err
		}
		if up {
			_, err = tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES($1)`, version)
		} else {
			_, err = tx.Exec(ctx, `DELETE FROM schema_migrations WHERE version=$1`, version)
		}
		return err
	}); err != nil {
		t.Fatalf("apply migration file %s: %v", name, err)
	}
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

func assertSQLRejected(t *testing.T, pool *pgxpool.Pool, message, query string, args ...any) {
	t.Helper()
	_, err := pool.Exec(t.Context(), query, args...)
	if err == nil || !strings.Contains(err.Error(), message) {
		t.Fatalf("SQL %q error = %v, want containing %q", query, err, message)
	}
}

func TestSourceIPMustBeCanonicalizable(t *testing.T) {
	f := newFixture(t, 20, 20)
	input := requestInput(f, f.username, "invalid-source", "not-an-ip")
	if net.ParseIP(input.Context.SourceIP) != nil {
		t.Fatal("test source unexpectedly parsed")
	}
	if _, err := f.service.Request(t.Context(), input); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid source error = %v", err)
	}
}
