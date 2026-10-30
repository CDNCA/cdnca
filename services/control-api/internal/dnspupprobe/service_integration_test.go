package dnspupprobe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/dnspupprobe/dnspuptest"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type leaseFeatures struct {
	mu      sync.Mutex
	granted map[string]bool
}

func (f *leaseFeatures) ReadValidFeatures(context.Context, pgx.Tx) (map[string]bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	copied := map[string]bool{}
	for key, value := range f.granted {
		copied[key] = value
	}
	return copied, nil
}

func (f *leaseFeatures) grant(on bool) {
	f.mu.Lock()
	f.granted[Feature] = on
	f.mu.Unlock()
}

type serviceFixture struct {
	pool     *pgxpool.Pool
	now      time.Time
	features *leaseFeatures
	service  *Service
	admin    Actor
	viewer   Actor
	fake     *dnspuptest.Server
	base     string
}

func newServiceFixture(t *testing.T) *serviceFixture {
	t.Helper()
	if strings.TrimSpace(os.Getenv("TEST_DATABASE_URL")) == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	pool := integrationPool(t)
	f := &serviceFixture{pool: pool, now: time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC),
		features: &leaseFeatures{granted: map[string]bool{Feature: true}}}
	scope := uuid.New()
	mustExecTest(t, pool, `INSERT INTO access_scopes(id,kind,created_at) VALUES($1,'platform',$2)`, scope, f.now)
	adminUser, adminSession := seedTestActor(t, pool, scope, f.now, PermissionManage)
	viewerUser, viewerSession := seedTestActor(t, pool, scope, f.now)
	f.admin = Actor{UserID: adminUser, ScopeID: scope, SessionID: adminSession, IP: "203.0.113.7"}
	f.viewer = Actor{UserID: viewerUser, ScopeID: scope, SessionID: viewerSession}
	cipher, err := dnsacme.NewAESGCMCredentialCipher("dnspup-probe-test-kek", bytes.Repeat([]byte{0x3c}, 32))
	if err != nil {
		t.Fatal(err)
	}
	alerts, err := notification.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	f.service, err = New(Config{Pool: pool, Cipher: cipher, Features: f.features, Alerts: alerts,
		Now: func() time.Time { return f.now }})
	if err != nil {
		t.Fatal(err)
	}
	var server *httptest.Server
	f.fake, server = dnspuptest.New()
	t.Cleanup(server.Close)
	f.base = server.URL
	return f
}

// integrationPool: a cloned migrated database, else a fresh schema migrated up.
func integrationPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if pool := databasetest.ClonedMigratedPool(t, nil); pool != nil {
		return pool
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	admin, err := pgxpool.New(ctx, os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	schema := "dnspup_probe_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		_, _ = admin.Exec(cleanupCtx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		admin.Close()
	})
	config, err := pgxpool.ParseConfig(os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return pool
}

func mustExecTest(t *testing.T, pool *pgxpool.Pool, query string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), query, args...); err != nil {
		t.Fatalf("%s: %v", strings.Fields(query)[0], err)
	}
}

func seedTestActor(t *testing.T, pool *pgxpool.Pool, scope uuid.UUID, now time.Time, permissions ...string) (uuid.UUID, uuid.UUID) {
	t.Helper()
	user, session, role := uuid.New(), uuid.New(), uuid.New()
	refresh := sha256.Sum256(session[:])
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO users(id,username,display_name,password_hash,status,created_at,updated_at)
			VALUES($1,$2,$2,'not-used','active',$3,$3)`, []any{user, "dpp-" + strings.ReplaceAll(user.String(), "-", "")[:20], now}},
		{`INSERT INTO memberships(scope_id,user_id,status,created_at) VALUES($1,$2,'active',$3)`, []any{scope, user, now}},
		{`INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
			VALUES($1,$1,$2,$3,$4,$5,$6)`, []any{session, user, scope, refresh[:], now.Add(-time.Hour), now.Add(30 * 24 * time.Hour)}},
		{`INSERT INTO roles(id,scope_id,name,description,system_role,created_at) VALUES($1,$2,$3,'dpp',true,$4)`,
			[]any{role, scope, "dpp_" + strings.ReplaceAll(role.String(), "-", "")[:20], now}},
		{`INSERT INTO role_permissions(role_id,permission_name) SELECT $1,name FROM permissions WHERE name=ANY($2::text[])`,
			[]any{role, permissions}},
		{`INSERT INTO role_assignments(scope_id,user_id,role_id,assigned_at) VALUES($1,$2,$3,$4)`, []any{scope, user, role, now}},
	} {
		mustExecTest(t, pool, statement.query, statement.args...)
	}
	return user, session
}

func ptr(value string) *string { return &value }

func (f *serviceFixture) input(enabled bool, secret *string) SettingsInput {
	return SettingsInput{Enabled: enabled, BaseURL: f.base, APIKey: f.fake.APIKey, APISecret: secret}
}

func (f *serviceFixture) count(t *testing.T, query string, args ...any) int {
	t.Helper()
	var value int
	if err := f.pool.QueryRow(t.Context(), query, args...).Scan(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestSettingsSecretRotationAndCapabilityTest(t *testing.T) {
	f := newServiceFixture(t)
	ctx := t.Context()
	// Viewer without the permission is refused; disabled by default.
	if _, err := f.service.Status(ctx, f.viewer); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("viewer status: %v", err)
	}
	status, err := f.service.Status(ctx, f.admin)
	if err != nil || status.Enabled || status.Active || !status.Licensed || len(status.OriginSources) != 3 ||
		status.OriginSources[0] != SourceNode || status.BaseURL != DefaultBaseURL {
		t.Fatalf("initial status %+v %v", status, err)
	}
	// Enabling without a secret is invalid; with one it seals it.
	if _, err := f.service.UpdateSettings(ctx, f.admin, "s1", f.input(true, nil)); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("enable without secret: %v", err)
	}
	status, err = f.service.UpdateSettings(ctx, f.admin, "s2", f.input(true, ptr(f.fake.Secret)))
	if err != nil || !status.Enabled || !status.Active || !status.SecretConfigured || len(status.SecretFingerprint) != 16 {
		t.Fatalf("enable %+v %v", status, err)
	}
	var ciphertext []byte
	if err := f.pool.QueryRow(ctx, `SELECT secret_ciphertext FROM probe_dnspup_settings`).Scan(&ciphertext); err != nil ||
		bytes.Contains(ciphertext, []byte(f.fake.Secret)) {
		t.Fatalf("secret stored in clear or missing: %v", err)
	}
	// Same key replays; a different body under the same key conflicts.
	if again, err := f.service.UpdateSettings(ctx, f.admin, "s2", f.input(true, ptr(f.fake.Secret))); err != nil || again.Revision != status.Revision {
		t.Fatalf("replay %+v %v", again, err)
	}
	if _, err := f.service.UpdateSettings(ctx, f.admin, "s2", f.input(false, nil)); !errors.Is(err, ErrIdempotency) {
		t.Fatalf("idempotency conflict: %v", err)
	}
	// Capability test with the stored secret records the account facts.
	result, err := f.service.TestConnection(ctx, f.admin, "t1", f.input(false, nil))
	if err != nil || !result.OK || !result.AsyncCapable || !result.HTTPAllowed || result.MonthlyLimit != 1000 {
		t.Fatalf("test %+v %v", result, err)
	}
	if status, _ = f.service.Status(ctx, f.admin); !status.AsyncCapable || status.AccountCheckedAt == nil || status.MonthlyLimit != 1000 {
		t.Fatalf("account facts not recorded %+v", status)
	}
	// A dnspup without async capability fails the test.
	f.fake.Do(func(s *dnspuptest.Server) { s.Async = false })
	if result, _ = f.service.TestConnection(ctx, f.admin, "t2", f.input(false, nil)); result.OK || result.ErrorCode != "async_unavailable" {
		t.Fatalf("no async %+v", result)
	}
	f.fake.Do(func(s *dnspuptest.Server) { s.Async = true })
	// A wrong typed secret reports dnspup's code without touching the stored facts.
	if result, _ = f.service.TestConnection(ctx, f.admin, "t3", f.input(false, ptr("wrong-secret-0123456789"))); result.OK ||
		result.HTTPStatus != 401 || result.ErrorCode != "unauthorized" {
		t.Fatalf("wrong secret %+v", result)
	}
	// Changing the key without a new secret: the stored one is not sent to another key.
	other := f.input(true, nil)
	other.APIKey = "dp_key_other_123"
	if _, err := f.service.UpdateSettings(ctx, f.admin, "s3", other); !errors.Is(err, ErrSecretRequired) {
		t.Fatalf("key change keeps old secret: %v", err)
	}
	// Invalid source orders are refused.
	bad := f.input(true, nil)
	bad.OriginSources = []string{SourceNode, SourceNode}
	if _, err := f.service.UpdateSettings(ctx, f.admin, "s4", bad); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("duplicate source: %v", err)
	}
	// Without the module: cannot enable; Runtime gives no dnspup probe.
	f.features.grant(false)
	if _, err := f.service.UpdateSettings(ctx, f.admin, "s5", f.input(true, nil)); !errors.Is(err, ErrFeatureDenied) {
		t.Fatalf("unlicensed enable: %v", err)
	}
	if runtime := f.service.Runtime(ctx); runtime.Probe != nil || runtime.Uses(runtime.OriginSources, SourceDNSPup) {
		t.Fatal("unlicensed runtime offers dnspup")
	}
	f.features.grant(true)
	if f.count(t, `SELECT count(*) FROM audit_events WHERE action=$1 AND result='success'`, ActionSettings) != 1 ||
		f.count(t, `SELECT count(*) FROM audit_events WHERE action=$1 AND result='failure'`, ActionSettings) < 3 {
		t.Fatal("settings writes not audited")
	}
}

func TestRuntimeProbesDegradesAndAlertsOnce(t *testing.T) {
	f := newServiceFixture(t)
	ctx := t.Context()
	recipient := f.admin.UserID
	if _, err := f.service.UpdateSettings(ctx, f.admin, "s1", f.input(true, ptr(f.fake.Secret))); err != nil {
		t.Fatal(err)
	}
	f.fake.Do(func(s *dnspuptest.Server) {
		s.PollsUntilDone = 0
		s.Answer = func(dnspuptest.ProbeRequest) []dnspuptest.Result {
			return []dnspuptest.Result{{NodeID: "gd", Region: "广东", ISP: "电信", Status: "ok", HTTPStatus: 200}}
		}
	})
	runtime := f.service.Runtime(ctx)
	if runtime.Probe == nil {
		t.Fatal("configured runtime has no dnspup probe")
	}
	results, err := runtime.Probe(ctx, ConsumerOrigin, "site-a", "o|443", 1, ProbeRequest{Type: "http", Target: "https://o.example.com/"})
	if err != nil || len(results) != 1 || results[0].HTTPStatus != 200 {
		t.Fatalf("probe %v %v", results, err)
	}
	// Quota exhausted: the source pauses, one alert, later rounds skip dnspup.
	f.fake.Do(func(s *dnspuptest.Server) { s.MonthlyLimit, s.MonthlyUsed = 1, 1 })
	if _, err := runtime.Probe(ctx, ConsumerOrigin, "site-a", "o|443", 2, ProbeRequest{Type: "http", Target: "https://o.example.com/"}); err == nil {
		t.Fatal("quota exceeded must fail")
	}
	status, _ := f.service.Status(ctx, f.admin)
	if status.Active || status.PauseReason != DegradeQuota || status.PauseCode != "quota_exceeded" || status.PausedUntil == nil {
		t.Fatalf("not paused %+v", status)
	}
	if again := f.service.Runtime(ctx); again.Probe != nil {
		t.Fatal("paused runtime still offers dnspup")
	}
	// A second degrade within the same pause does not alert again.
	f.service.Degrade(ctx, status.Revision, DegradeQuota, "quota_exceeded", f.now.Add(2*time.Hour))
	alerts := f.count(t, `SELECT count(*) FROM notification_events WHERE event_type='probe.dnspup.degraded' AND recipient_user_id=$1`, recipient)
	if alerts != 1 { // one event per pause
		t.Fatalf("alerts = %d", alerts)
	}
	firstAlerts := alerts
	// The pause ends: dnspup comes back without operator action.
	f.now = f.now.Add(3 * time.Hour)
	f.fake.Do(func(s *dnspuptest.Server) { s.MonthlyLimit = 1000 })
	if again := f.service.Runtime(ctx); again.Probe == nil {
		t.Fatal("expired pause still blocks dnspup")
	}
	// A degrade reported for an old settings revision (before 换钥) is ignored.
	if _, err := f.service.UpdateSettings(ctx, f.admin, "s2", f.input(true, ptr("dp_secret_rotated_0123456789"))); err != nil {
		t.Fatal(err)
	}
	f.service.Degrade(ctx, status.Revision, DegradeUnauthorized, "unauthorized", f.now.Add(time.Hour))
	if status, _ = f.service.Status(ctx, f.admin); status.PauseReason != "" {
		t.Fatalf("stale revision paused the new key: %+v", status)
	}
	// A rate limit on the new key pauses for Retry-After and alerts once more.
	f.service.Degrade(ctx, status.Revision, DegradeRateLimited, "rate_limited", f.now.Add(time.Minute))
	if status, _ = f.service.Status(ctx, f.admin); status.PauseReason != DegradeRateLimited {
		t.Fatalf("rate limit pause %+v", status)
	}
	if got := f.count(t, `SELECT count(*) FROM notification_events WHERE event_type='probe.dnspup.degraded' AND recipient_user_id=$1`, recipient); got <= firstAlerts {
		t.Fatalf("second pause alerts = %d (first %d)", got, firstAlerts)
	}
	if f.count(t, `SELECT count(*) FROM audit_events WHERE action=$1`, ActionDegrade) < 3 {
		t.Fatal("degrades not audited")
	}
}
