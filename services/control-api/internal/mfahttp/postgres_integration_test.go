package mfahttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/mfa"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRuntimePostgresBearerEnrollmentStatusAndRevocation(t *testing.T) {
	pool := isolatedMFAHTTPPool(t)
	now := time.Now().UTC()
	tenantID, scopeID, userID, sessionID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	username := "mfa-http-" + uuid.NewString()[:8]
	sessionHash := sha256.Sum256(sessionID[:])
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,'MFA HTTP Test')`, []any{tenantID}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{scopeID, tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,$2,'test-hash')`, []any{userID, username}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{scopeID, userID}},
		{`INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
			VALUES($1,$1,$2,$3,$4,$5,$6)`, []any{sessionID, userID, scopeID, sessionHash[:], now.Add(-time.Minute), now.Add(time.Hour)}},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(t.Context(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}

	tokens, err := identity.NewTokenManager(strings.Repeat("mfa-http-session-secret-", 2), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := sessioncredential.NewVerifier(tokens, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x63}, 32), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	iam, err := iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := NewRuntime(RuntimeConfig{Enabled: true, Core: mfa.Config{
		Clock: time.Now, Random: bytes.NewReader(bytes.Repeat([]byte{0x42}, 512)),
		Issuer: "CDNCA MFA HTTP Test", EnrollmentTTL: 10 * time.Minute,
	}}, RuntimeDependencies{Pool: pool, Identity: identityService, IAM: iam, Cipher: &runtimeCipher{}})
	if err != nil {
		t.Fatal(err)
	}
	rawSession, _, err := tokens.Mint(userID, scopeID, sessionID)
	if err != nil {
		t.Fatal(err)
	}

	request := func(method, path, body, key string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+rawSession)
		req.Header.Set("X-Request-ID", "mfa-http-integration")
		req.Header.Set("Traceparent", testTraceparent)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if key != "" {
			req.Header.Set("Idempotency-Key", key)
		}
		response := httptest.NewRecorder()
		runtime.ServeHTTP(response, req)
		return response
	}

	created := request(http.MethodPost, apiPrefix+"/enrollments", `{"account_label":"mfa-http"}`, "enroll-live")
	if created.Code != http.StatusCreated {
		t.Fatalf("begin enrollment status=%d", created.Code)
	}
	var first map[string]any
	if err := json.Unmarshal(created.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	if first["secret"] == nil || first["provisioning_uri"] == nil {
		t.Fatal("first enrollment omitted one-time material")
	}

	pending := request(http.MethodGet, apiPrefix, "", "")
	if pending.Code != http.StatusOK {
		t.Fatalf("pending status HTTP=%d", pending.Code)
	}
	var status statusView
	if err := json.Unmarshal(pending.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.Status != mfa.StatusPending || status.CredentialID == nil ||
		status.Method != mfa.MethodTOTP || status.EnrollmentExpiresAt == nil {
		t.Fatalf("pending status=%+v", status)
	}

	replay := request(http.MethodPost, apiPrefix+"/enrollments", `{"account_label":"mfa-http"}`, "enroll-live")
	if replay.Code != http.StatusOK {
		t.Fatalf("replay status=%d", replay.Code)
	}
	var replayed map[string]any
	if err := json.Unmarshal(replay.Body.Bytes(), &replayed); err != nil {
		t.Fatal(err)
	}
	if replayed["replayed"] != true || replayed["secret"] != nil || replayed["provisioning_uri"] != nil {
		t.Fatal("replay did not preserve the one-time field contract")
	}

	if _, err := pool.Exec(t.Context(), `UPDATE auth_sessions SET revoked_at=$2,revocation_reason='mfa-http-test'
		WHERE id=$1`, sessionID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	revoked := request(http.MethodGet, apiPrefix, "", "")
	assertAPIError(t, revoked, http.StatusUnauthorized, "mfa_unauthenticated")
}

func isolatedMFAHTTPPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "mfa_http_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^mfa_http_test_[a-f0-9]{32}$`).MatchString(schema) {
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
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
		t.Fatal(err)
	}
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
		t.Fatalf("migrate MFA HTTP schema: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop MFA HTTP schema: %v", err)
		}
		admin.Close()
	})
	return pool
}
