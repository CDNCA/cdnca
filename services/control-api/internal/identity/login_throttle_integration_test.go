//go:build integration

package identity_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type throttleSettings struct {
	limit, threshold int
	regionCheck      bool
}

func (settings throttleSettings) GetPublic(context.Context, uuid.UUID) (systemusersettings.PublicSettings, error) {
	return systemusersettings.PublicSettings{SessionTTLSeconds: 3600,
		LoginFailureLimitPerHour: settings.limit, LoginCaptchaThresholdPerHour: settings.threshold,
		SessionRegionCheck: settings.regionCheck}, nil
}

type throttleFixture struct {
	pool     *pgxpool.Pool
	service  *identity.Service
	username string
	password string
}

func seedThrottleFixture(t *testing.T, limit, threshold int) throttleFixture {
	t.Helper()
	pool := newIdentityAuthorityPool(t)
	tokens, err := identity.NewTokenManager(strings.Repeat("t", 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	service, err := identity.NewService(identity.NewStore(pool), tokens, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	service.SetPublicSettingsReader(throttleSettings{limit: limit, threshold: threshold, regionCheck: true})
	if err := service.SetLoginThrottleKey([]byte(strings.Repeat("k", 32))); err != nil {
		t.Fatal(err)
	}
	fixture := throttleFixture{pool: pool, service: service, username: "throttle-" + uuid.NewString()[:8], password: "Correct-horse-battery"}
	hash, err := identity.HashPassword(fixture.password)
	if err != nil {
		t.Fatal(err)
	}
	scopeID, userID := uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'platform',NULL)`, scopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'Throttle',$3)`, userID, fixture.username, hash); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (fixture throttleFixture) login(t *testing.T, password, source string, captcha *identity.LoginCaptchaProof) error {
	t.Helper()
	_, err := fixture.service.Login(t.Context(), identity.LoginInput{Username: fixture.username, Password: password, Captcha: captcha},
		identity.RequestInfo{RequestID: "req-" + uuid.NewString()[:8], SourceIP: source})
	return err
}

func (fixture throttleFixture) captcha(t *testing.T, source string) identity.LoginCaptcha {
	t.Helper()
	captcha, err := fixture.service.IssueLoginCaptcha(t.Context(), source)
	if err != nil {
		t.Fatal(err)
	}
	return captcha
}

func TestLoginThrottleRequiresCaptchaThenLocksAccountSource(t *testing.T) {
	fixture := seedThrottleFixture(t, 4, 2)
	const source = "203.0.113.10"
	for attempt := range 2 {
		if err := fixture.login(t, "wrong", source, nil); !errors.Is(err, identity.ErrInvalidCredentials) {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
	}
	// Threshold reached: even the right password needs a CAPTCHA now.
	if err := fixture.login(t, fixture.password, source, nil); !errors.Is(err, identity.ErrLoginCaptchaRequired) {
		t.Fatalf("captcha not required: %v", err)
	}
	// A wrong answer is refused without checking the password and burns the challenge.
	wrong := fixture.captcha(t, source)
	if err := fixture.login(t, fixture.password, source, &identity.LoginCaptchaProof{ID: wrong.ID, Answer: "00000"}); !errors.Is(err, identity.ErrLoginCaptchaInvalid) {
		t.Fatalf("wrong captcha: %v", err)
	}
	if err := fixture.login(t, fixture.password, source, &identity.LoginCaptchaProof{ID: wrong.ID, Answer: wrong.Answer}); !errors.Is(err, identity.ErrLoginCaptchaInvalid) {
		t.Fatalf("reused captcha: %v", err)
	}
	// A challenge issued to another source does not work here.
	foreign := fixture.captcha(t, "198.51.100.1")
	if err := fixture.login(t, fixture.password, source, &identity.LoginCaptchaProof{ID: foreign.ID, Answer: foreign.Answer}); !errors.Is(err, identity.ErrLoginCaptchaInvalid) {
		t.Fatalf("foreign captcha: %v", err)
	}
	// Two more credential failures with solved CAPTCHAs reach the limit (4).
	for attempt := range 2 {
		solved := fixture.captcha(t, source)
		if err := fixture.login(t, "wrong", source, &identity.LoginCaptchaProof{ID: solved.ID, Answer: strings.ToLower(solved.Answer)}); !errors.Is(err, identity.ErrInvalidCredentials) {
			t.Fatalf("captcha attempt %d: %v", attempt, err)
		}
	}
	var throttled *identity.LoginThrottled
	solved := fixture.captcha(t, source)
	if err := fixture.login(t, fixture.password, source, &identity.LoginCaptchaProof{ID: solved.ID, Answer: solved.Answer}); !errors.As(err, &throttled) ||
		throttled.RetryAfter <= 0 || throttled.RetryAfter > time.Hour+time.Second {
		t.Fatalf("not throttled: %v", err)
	}
	// Another source is not locked out by the attacker's failures.
	if err := fixture.login(t, fixture.password, "198.51.100.2", nil); err != nil {
		t.Fatalf("other source: %v", err)
	}
	var audited int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE action='auth.login.throttled' AND source_ip=$1`, source).Scan(&audited); err != nil || audited < 4 {
		t.Fatalf("throttle audit events = %d err=%v", audited, err)
	}
}

func TestLoginThrottleSuccessClearsFailuresAndParallelAttemptsCannotPassLimit(t *testing.T) {
	fixture := seedThrottleFixture(t, 3, 3)
	const source = "203.0.113.20"
	for range 2 {
		_ = fixture.login(t, "wrong", source, nil)
	}
	if err := fixture.login(t, fixture.password, source, nil); err != nil {
		t.Fatal(err)
	}
	var remaining int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM identity_login_attempts WHERE source_ip=$1`, source).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("success left %d attempts err=%v", remaining, err)
	}
	// Ten parallel wrong passwords from one source: at most `limit` reach the
	// password check, the rest are throttled or must solve a CAPTCHA.
	var wait sync.WaitGroup
	var mu sync.Mutex
	checked := 0
	for range 10 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if err := fixture.login(t, "wrong", source, nil); errors.Is(err, identity.ErrInvalidCredentials) {
				mu.Lock()
				checked++
				mu.Unlock()
			}
		}()
	}
	wait.Wait()
	if checked != 3 {
		t.Fatalf("password checked %d times, want 3", checked)
	}
}

func TestLoginThrottleSourceLimitStopsPasswordSpraying(t *testing.T) {
	fixture := seedThrottleFixture(t, 2, 2)
	const source = "203.0.113.30"
	// limit*5 = 10 failures across unknown accounts lock the source; the CAPTCHA
	// threshold across accounts is threshold*5 = 10 as well.
	for index := range 10 {
		_, err := fixture.service.Login(t.Context(), identity.LoginInput{Username: "spray-" + uuid.NewString()[:6], Password: "x"},
			identity.RequestInfo{RequestID: "spray", SourceIP: source})
		if !errors.Is(err, identity.ErrInvalidCredentials) {
			t.Fatalf("spray %d: %v", index, err)
		}
	}
	var throttled *identity.LoginThrottled
	if err := fixture.login(t, fixture.password, source, nil); !errors.As(err, &throttled) {
		t.Fatalf("sprayed source not throttled: %v", err)
	}
}

func TestLoginCaptchaIssueIsRateLimitedPerSource(t *testing.T) {
	fixture := seedThrottleFixture(t, 30, 3)
	for range 30 {
		fixture.captcha(t, "203.0.113.40")
	}
	if _, err := fixture.service.IssueLoginCaptcha(t.Context(), "203.0.113.40"); !errors.Is(err, identity.ErrLoginCaptchaRateLimited) {
		t.Fatalf("captcha flood: %v", err)
	}
}
