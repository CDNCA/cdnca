package ipintelupdate

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	"github.com/cdnca/cdnca/services/control-api/internal/artifactsync"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Obviously fake dnspup customer API credentials.
const (
	testAPIKey     = "dnp_key_fake_update_000000000000"
	testAPISecret  = "dnp_secret_fake_update_0000000000000000000000"
	snapshotPath   = "/v1/tools/ip-intel-snapshot"
	fixtureRelease = "ipx-98a5f2c77cd73826d2800b2f"
)

// snapshot is the builder test snapshot, optionally as another release with
// another data time (one row dropped so the content differs).
func snapshot(t *testing.T, release, dataUpdatedAt string) []byte {
	t.Helper()
	compressed, err := os.ReadFile("../../../../libs/entitlement/ipintel/builder/testdata/dnspup-snapshot-pull.ndjson.gz")
	if err != nil {
		t.Fatal(err)
	}
	if release == fixtureRelease {
		return compressed
	}
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := io.ReadAll(reader)
	lines := strings.Split(strings.TrimSuffix(string(plain), "\n"), "\n")
	lines = append(lines[:len(lines)-2], lines[len(lines)-1])
	text := strings.Join(lines, "\n") + "\n"
	text = strings.ReplaceAll(text, fixtureRelease, release)
	text = strings.Replace(text, `"rows":195}`, `"rows":194}`, 1)
	text = strings.Replace(text, `"data_updated_at":"2026-10-17T13:19:58Z"`, `"data_updated_at":"`+dataUpdatedAt+`"`, 1)
	var out bytes.Buffer
	writer := gzip.NewWriter(&out)
	_, _ = writer.Write([]byte(text))
	_ = writer.Close()
	return out.Bytes()
}

type fakeDnspup struct {
	mu      sync.Mutex
	release string
	body    []byte
	status  int
	code    string
	gets    int
	heads   int
	lastINM string
}

func (fake *fakeDnspup) set(release string, body []byte) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.release, fake.body, fake.status, fake.code = release, body, 0, ""
}

func (fake *fakeDnspup) fail(status int, code string) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.status, fake.code = status, code
}

func (fake *fakeDnspup) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if r.Method == http.MethodHead {
		fake.heads++
	} else {
		fake.gets++
	}
	fake.lastINM = r.Header.Get("If-None-Match")
	apiError := func(status int, code string) {
		w.Header().Set("X-API-Error-Code", code)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"error":{"code":"` + code + `","message":"x"}}`))
	}
	if r.URL.Path != snapshotPath {
		http.NotFound(w, r)
		return
	}
	if r.Header.Get("X-API-Key") != testAPIKey || r.Header.Get("X-API-Secret") != testAPISecret {
		apiError(http.StatusUnauthorized, "unauthorized")
		return
	}
	if fake.status != 0 {
		apiError(fake.status, fake.code)
		return
	}
	w.Header().Set("ETag", `"`+fake.release+`"`)
	if fake.lastINM == `"`+fake.release+`"` {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("X-IP-Intel-Status", "ready")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	_, _ = w.Write(fake.body)
}

// features is a switchable lease.
type features struct {
	mu      sync.Mutex
	granted map[string]bool
}

func (f *features) ReadValidFeatures(context.Context, pgx.Tx) (map[string]bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	copied := map[string]bool{}
	for key, value := range f.granted {
		copied[key] = value
	}
	return copied, nil
}

func (f *features) grant(on bool) {
	f.mu.Lock()
	f.granted[Feature] = on
	f.mu.Unlock()
}

type fixture struct {
	pool      *pgxpool.Pool
	now       time.Time
	features  *features
	artifacts *artifactsync.Store
	service   *Service
	admin     Actor
	viewer    Actor
	dnspup    *fakeDnspup
	endpoint  string
	published int
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	if strings.TrimSpace(os.Getenv("TEST_DATABASE_URL")) == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	pool := databasetest.ClonedMigratedPool(t, nil)
	if pool == nil {
		var err error
		if pool, err = pgxpool.New(t.Context(), os.Getenv("TEST_DATABASE_URL")); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		if err := database.Migrate(t.Context(), pool, "up"); err != nil {
			t.Fatal(err)
		}
	}
	f := &fixture{pool: pool, now: time.Date(2026, 10, 18, 2, 0, 0, 0, time.UTC), features: &features{granted: map[string]bool{Feature: true}},
		dnspup: &fakeDnspup{}}
	clock := func() time.Time { return f.now }
	scope := uuid.New()
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind,created_at) VALUES($1,'platform',$2)`, scope, f.now)
	adminUser, adminSession := seedActor(t, pool, scope, f.now, PermissionManage)
	viewerUser, viewerSession := seedActor(t, pool, scope, f.now)
	f.admin = Actor{UserID: adminUser, ScopeID: scope, SessionID: adminSession, IP: "203.0.113.7"}
	f.viewer = Actor{UserID: viewerUser, ScopeID: scope, SessionID: viewerSession}
	cipher, err := dnsacme.NewAESGCMCredentialCipher("pa16-test-kek", bytes.Repeat([]byte{0x5a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	f.artifacts = artifactsync.NewStore(pool, clock).WithFeatures(f.features)
	f.service, err = New(Config{Pool: pool, Cipher: cipher, Features: f.features, Publisher: f.artifacts, Now: clock,
		OnPublished: func() { f.published++ }})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(f.dnspup)
	t.Cleanup(server.Close)
	f.endpoint = server.URL + snapshotPath
	f.dnspup.set(fixtureRelease, snapshot(t, fixtureRelease, ""))
	return f
}

func mustExec(t *testing.T, pool *pgxpool.Pool, query string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), query, args...); err != nil {
		t.Fatalf("%s: %v", strings.Fields(query)[0], err)
	}
}

func seedActor(t *testing.T, pool *pgxpool.Pool, scope uuid.UUID, now time.Time, permissions ...string) (uuid.UUID, uuid.UUID) {
	t.Helper()
	user, session, role := uuid.New(), uuid.New(), uuid.New()
	refresh := sha256.Sum256(session[:])
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO users(id,username,display_name,password_hash,status,created_at,updated_at)
			VALUES($1,$2,$2,'not-used','active',$3,$3)`, []any{user, "pa16-" + strings.ReplaceAll(user.String(), "-", "")[:20], now}},
		{`INSERT INTO memberships(scope_id,user_id,status,created_at) VALUES($1,$2,'active',$3)`, []any{scope, user, now}},
		{`INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
			VALUES($1,$1,$2,$3,$4,$5,$6)`, []any{session, user, scope, refresh[:], now.Add(-time.Hour), now.Add(30 * 24 * time.Hour)}},
		{`INSERT INTO roles(id,scope_id,name,description,system_role,created_at) VALUES($1,$2,$3,'pa16',true,$4)`,
			[]any{role, scope, "pa16_" + strings.ReplaceAll(role.String(), "-", "")[:20], now}},
		{`INSERT INTO role_permissions(role_id,permission_name) SELECT $1,name FROM permissions WHERE name=ANY($2::text[])`,
			[]any{role, permissions}},
		{`INSERT INTO role_assignments(scope_id,user_id,role_id,assigned_at) VALUES($1,$2,$3,$4)`, []any{scope, user, role, now}},
	} {
		mustExec(t, pool, statement.query, statement.args...)
	}
	return user, session
}

func secret(value string) *string { return &value }

func (f *fixture) settings(enabled bool, apiSecret *string) SettingsInput {
	return SettingsInput{Enabled: enabled, URL: f.endpoint, APIKey: testAPIKey, APISecret: apiSecret,
		IntervalMinutes: 360, AnchorMinute: 240, TimeZone: "Asia/Shanghai"}
}

func (f *fixture) auditCount(t *testing.T, action, result string) int {
	t.Helper()
	var count int
	if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE action=$1 AND result=$2`, action, result).
		Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestSettingsTestAndCheck(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	// Viewers cannot read or write; nothing reaches dnspup.
	if _, err := f.service.Status(ctx, f.viewer); err != ErrPermissionDenied {
		t.Fatalf("viewer status: %v", err)
	}
	if _, err := f.service.UpdateSettings(ctx, f.viewer, "k-viewer", f.settings(false, secret(testAPISecret))); err != ErrPermissionDenied {
		t.Fatalf("viewer save: %v", err)
	}
	// Enabling needs a secret; invalid schedule is refused.
	if _, err := f.service.UpdateSettings(ctx, f.admin, "k-0", f.settings(true, nil)); err != ErrInvalidInput {
		t.Fatalf("enable without secret: %v", err)
	}
	bad := f.settings(false, nil)
	bad.IntervalMinutes = 5
	if _, err := f.service.UpdateSettings(ctx, f.admin, "k-1", bad); err != ErrInvalidInput {
		t.Fatalf("short interval: %v", err)
	}
	bad = f.settings(false, nil)
	bad.TimeZone = "Mars/Olympus"
	if _, err := f.service.UpdateSettings(ctx, f.admin, "k-2", bad); err != ErrInvalidInput {
		t.Fatalf("unknown zone: %v", err)
	}
	// Without the module the plugin cannot be enabled, tested or checked.
	f.features.grant(false)
	if _, err := f.service.UpdateSettings(ctx, f.admin, "k-3", f.settings(true, secret(testAPISecret))); err != ErrFeatureDenied {
		t.Fatalf("enable unlicensed: %v", err)
	}
	if _, err := f.service.TestConnection(ctx, f.admin, "k-4", f.settings(false, secret(testAPISecret))); err != ErrFeatureDenied {
		t.Fatalf("test unlicensed: %v", err)
	}
	f.features.grant(true)
	// Save disabled with the secret; the view never returns it.
	status, err := f.service.UpdateSettings(ctx, f.admin, "k-5", f.settings(false, secret(testAPISecret)))
	if err != nil || status.Enabled || !status.SecretConfigured || len(status.SecretFingerprint) != 16 || !status.Licensed {
		t.Fatalf("save: %+v %v", status, err)
	}
	if encoded, _ := json.Marshal(status); strings.Contains(string(encoded), testAPISecret) {
		t.Fatal("status returns the secret")
	}
	// Replay returns the first answer; the same key with another body conflicts.
	if again, err := f.service.UpdateSettings(ctx, f.admin, "k-5", f.settings(false, secret(testAPISecret))); err != nil ||
		again.Revision != status.Revision {
		t.Fatalf("replay: %+v %v", again, err)
	}
	if _, err := f.service.UpdateSettings(ctx, f.admin, "k-5", f.settings(true, nil)); err != ErrIdempotency {
		t.Fatalf("conflicting replay: %v", err)
	}
	// Connection test with the stored secret: HEAD only.
	result, err := f.service.TestConnection(ctx, f.admin, "k-6", f.settings(false, nil))
	if err != nil || !result.OK || result.HTTPStatus != 200 || f.dnspup.gets != 0 || f.dnspup.heads != 1 {
		t.Fatalf("test: %+v %v (gets %d heads %d)", result, err, f.dnspup.gets, f.dnspup.heads)
	}
	wrong, err := f.service.TestConnection(ctx, f.admin, "k-7", f.settings(false, secret("dnp_secret_fake_wrong_0000000000000000")))
	if err != nil || wrong.OK || wrong.ErrorCode != "credentials_rejected" {
		t.Fatalf("wrong secret: %+v %v", wrong, err)
	}
	// The stored secret never goes to another host or key.
	other := f.settings(true, nil)
	other.URL = "https://evil.example" + snapshotPath
	if _, err := f.service.TestConnection(ctx, f.admin, "k-8", other); err != ErrSecretRequired {
		t.Fatalf("test other host: %v", err)
	}
	if _, err := f.service.UpdateSettings(ctx, f.admin, "k-9", other); err != ErrSecretRequired {
		t.Fatalf("save other host: %v", err)
	}
	// "Check now" needs the plugin enabled.
	if _, err := f.service.CheckNow(ctx, f.admin, "k-10"); err != ErrDisabled {
		t.Fatalf("check while disabled: %v", err)
	}
	if status, err := f.service.UpdateSettings(ctx, f.admin, "k-11", f.settings(true, nil)); err != nil || !status.Enabled ||
		status.NextCheckAt != nil {
		t.Fatalf("enable: %+v %v", status, err)
	}
	if status, err := f.service.CheckNow(ctx, f.admin, "k-12"); err != nil || !status.CheckRequested {
		t.Fatalf("check: %+v %v", status, err)
	}
	// Audit: successes and refusals recorded with ip, secret nowhere.
	if f.auditCount(t, ActionSettings, "success") < 2 || f.auditCount(t, ActionSettings, "failure") < 3 ||
		f.auditCount(t, ActionTest, "success") < 1 || f.auditCount(t, ActionTest, "failure") < 1 ||
		f.auditCount(t, ActionCheck, "success") != 1 {
		t.Fatal("audit events missing")
	}
	var leaked bool
	if err := f.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM audit_events WHERE payload::text LIKE '%'||$1||'%')
		OR EXISTS(SELECT 1 FROM ip_intel_update_settings WHERE position(convert_to($1,'UTF8') IN secret_ciphertext)>0)
		OR EXISTS(SELECT 1 FROM ip_intel_update_write_requests WHERE response_body::text LIKE '%'||$1||'%')`, testAPISecret).Scan(&leaked); err != nil || leaked {
		t.Fatalf("secret stored in clear: %v %v", leaked, err)
	}
	var ip, changes string
	if err := f.pool.QueryRow(ctx, `SELECT source_ip,changes::text FROM audit_events
		WHERE action=$1 AND result='success' ORDER BY occurred_at DESC,stream_position DESC LIMIT 1`, ActionSettings).Scan(&ip, &changes); err != nil ||
		ip != "203.0.113.7" || !strings.Contains(changes, `"enabled"`) || strings.Contains(changes, testAPISecret) {
		t.Fatalf("settings audit: ip %q changes %q %v", ip, changes, err)
	}
}

func TestPullBuildsLocalLibraryAndKeepsLKG(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	if _, err := f.service.UpdateSettings(ctx, f.admin, "k-0", f.settings(true, secret(testAPISecret))); err != nil {
		t.Fatal(err)
	}
	// First pull: built and stored as ipintel/local revision 1.
	result, err := f.service.PullOnce(ctx, false)
	if err != nil || !result.Ran || result.Outcome != OutcomePublished || result.Revision != 1 || f.published != 1 {
		t.Fatalf("first pull: %+v %v", result, err)
	}
	local, err := f.artifacts.Current(ctx, artifactsync.IPIntelLocalID)
	if err != nil || local == nil || local.Revision != 1 || local.MediaType != artifactcatalog.MediaTypeIPIntel {
		t.Fatalf("local artifact: %+v %v", local, err)
	}
	content, err := f.artifacts.Object(ctx, local.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	entry := artifactcatalog.Entry{ArtifactID: local.ArtifactID, Kind: local.Kind, Version: local.Version, Revision: local.Revision,
		SHA256: local.SHA256, Size: local.Size, MediaType: local.MediaType, RequiresCapability: local.RequiresCapability,
		RequiresFeature: Feature, Encryption: artifactcatalog.EncryptionNone}
	if _, err := artifactcatalog.VerifyIPIntel(entry, content); err != nil {
		t.Fatalf("stored library does not verify: %v", err)
	}
	status, err := f.service.Status(ctx, f.admin)
	if err != nil || status.Local == nil || status.Local.SourceRelease != fixtureRelease || status.NodeUses != artifactsync.IPIntelLocalID ||
		status.LastOutcome != OutcomePublished || status.NextCheckAt == nil {
		t.Fatalf("status after publish: %+v %v", status, err)
	}
	// Next pull aligned on the schedule: 04:00 Asia/Shanghai + k*6h, after now (02:00 UTC = 10:00 +08) → 16:00 +08.
	if want := time.Date(2026, 10, 18, 8, 0, 0, 0, time.UTC); !status.NextCheckAt.Equal(want) {
		t.Fatalf("next check %s, want %s", status.NextCheckAt, want)
	}
	if result, err := f.service.PullOnce(ctx, false); err != nil || result.Ran {
		t.Fatalf("not due: %+v %v", result, err)
	}
	// Due again: 304 with If-None-Match, nothing built.
	f.now = f.now.Add(6 * time.Hour)
	result, err = f.service.PullOnce(ctx, false)
	if err != nil || result.Outcome != OutcomeNotModified || f.dnspup.lastINM != `"`+fixtureRelease+`"` || f.published != 1 {
		t.Fatalf("304: %+v %v", result, err)
	}
	// Failures keep revision 1 and schedule a retry.
	for name, prep := range map[string]func(){
		"quota": func() { f.dnspup.fail(http.StatusTooManyRequests, "quota_exceeded") },
		"older data": func() {
			f.dnspup.set("ipx-0000000000000000000000aa", snapshot(t, "ipx-0000000000000000000000aa", "2026-10-16T00:00:00Z"))
		},
	} {
		prep()
		result, err := f.service.PullOnce(ctx, true)
		if err != nil || result.Outcome != OutcomeFailed || result.ErrorCode == "" {
			t.Fatalf("%s: %+v %v", name, result, err)
		}
		if current, _ := f.artifacts.Current(ctx, artifactsync.IPIntelLocalID); current == nil || current.Revision != 1 {
			t.Fatalf("%s replaced the local library: %+v", name, current)
		}
		status, _ := f.service.Status(ctx, f.admin)
		if status.NextCheckAt == nil || !status.NextCheckAt.Equal(f.now.Add(15*time.Minute)) || status.LastError == "" ||
			strings.Contains(status.LastError, testAPISecret) {
			t.Fatalf("%s state: %+v", name, status)
		}
	}
	// Newer data: revision 2.
	newer := "ipx-0000000000000000000000bb"
	f.dnspup.set(newer, snapshot(t, newer, "2026-10-17T20:00:00Z"))
	if result, err := f.service.PullOnce(ctx, true); err != nil || result.Outcome != OutcomePublished || result.Revision != 2 {
		t.Fatalf("newer: %+v %v", result, err)
	}
	if f.auditCount(t, "plugin.artifact.build", "success") != 2 || f.auditCount(t, ActionPull, "failure") != 2 {
		t.Fatal("pull audit events missing")
	}
	// Module revoked: no pull, the local library is not usable (nodes fall back to the base).
	f.features.grant(false)
	if result, err := f.service.PullOnce(ctx, true); err != nil || result.Ran {
		t.Fatalf("unlicensed pull ran: %+v %v", result, err)
	}
	if current, err := f.artifacts.Current(ctx, artifactsync.IPIntelLocalID); err != nil || current != nil {
		t.Fatalf("unlicensed local library still listed: %+v %v", current, err)
	}
	// The catalog sync never withdraws or overwrites the local row.
	var origin, entryStatus string
	if err := f.pool.QueryRow(ctx, `SELECT origin,status FROM artifact_catalog_entries WHERE artifact_id=$1`, artifactsync.IPIntelLocalID).
		Scan(&origin, &entryStatus); err != nil || origin != "local" || entryStatus != "active" {
		t.Fatalf("local entry: %s %s %v", origin, entryStatus, err)
	}
}

func TestNextPullAlignsOnTheAnchor(t *testing.T) {
	shanghai, _ := time.LoadLocation("Asia/Shanghai")
	for name, test := range map[string]struct {
		now      time.Time
		interval int
		anchor   int
		want     time.Time
	}{
		"daily before anchor": {time.Date(2026, 10, 18, 19, 0, 0, 0, time.UTC), 1440, 240, time.Date(2026, 10, 18, 20, 0, 0, 0, time.UTC)},
		"daily after anchor":  {time.Date(2026, 10, 18, 20, 0, 0, 0, time.UTC), 1440, 240, time.Date(2026, 10, 19, 20, 0, 0, 0, time.UTC)},
		"hourly":              {time.Date(2026, 10, 18, 2, 30, 0, 0, time.UTC), 60, 15, time.Date(2026, 10, 18, 3, 15, 0, 0, time.UTC)},
		"weekly":              {time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC), 10080, 0, time.Date(2026, 10, 21, 16, 0, 0, 0, time.UTC)},
		"before epoch":        {time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC), 1440, 0, time.Date(2025, 12, 31, 16, 0, 0, 0, time.UTC)},
	} {
		if got := NextPull(test.now, test.interval, test.anchor, shanghai); !got.Equal(test.want) {
			t.Errorf("%s: %s, want %s", name, got, test.want)
		}
	}
}
