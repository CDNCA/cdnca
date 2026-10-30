package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analytics"
	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/dashboard"
	"github.com/cdnca/cdnca/services/control-api/internal/dashboardhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const testPassword = "test-password-that-is-long-enough"

type testAuthResponse struct {
	AccessToken string             `json:"access_token"`
	TokenType   string             `json:"token_type"`
	ExpiresIn   int64              `json:"expires_in"`
	Principal   identity.Principal `json:"principal"`
}

type testErrorEnvelope struct {
	Error struct {
		Code      string `json:"code"`
		RequestID string `json:"request_id"`
	} `json:"error"`
}

func TestDashboardHandlersMountOnlyCanonicalGETRoutes(t *testing.T) {
	adminCalls := 0
	tenantCalls := 0
	api := New(nil, nil, Config{
		APIKeyPepper: bytes.Repeat([]byte{0x52}, 32),
		AdminDashboardHandler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			adminCalls++
			writer.WriteHeader(http.StatusNoContent)
		}),
		TenantDashboardHandler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			tenantCalls++
			writer.WriteHeader(http.StatusNoContent)
		}),
	})
	if err := api.InitializationError(); err != nil {
		t.Fatalf("initialize dashboard routes: %v", err)
	}
	handler := api.Handler()

	for _, path := range []string{"/v1/admin/dashboard", "/v1/dashboard"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNoContent {
			t.Fatalf("GET %s status = %d, want 204", path, response.Code)
		}
	}
	for _, path := range []string{
		"/v1/admin/dashboard/", "/v1/admin/dashboards", "/v1/dashboard/", "/v1/dashboards",
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNotFound {
			t.Fatalf("GET alias %s status = %d, want 404", path, response.Code)
		}
	}
	for _, path := range []string{"/v1/admin/dashboard", "/v1/dashboard"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, nil))
		if response.Code != http.StatusMethodNotAllowed {
			t.Fatalf("POST %s status = %d, want 405", path, response.Code)
		}
	}
	if adminCalls != 1 || tenantCalls != 1 {
		t.Fatalf("dashboard handler calls = admin:%d tenant:%d, want 1 each", adminCalls, tenantCalls)
	}
}

func TestDashboardHandlersFailClosed(t *testing.T) {
	pepper := bytes.Repeat([]byte{0x52}, 32)
	disabled := New(nil, nil, Config{APIKeyPepper: pepper})
	if err := disabled.InitializationError(); err != nil {
		t.Fatalf("disabled dashboard initialization = %v", err)
	}
	for _, path := range []string{"/v1/admin/dashboard", "/v1/dashboard"} {
		response := httptest.NewRecorder()
		disabled.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNotFound {
			t.Fatalf("disabled GET %s status = %d, want 404", path, response.Code)
		}
	}

	valid := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	for _, config := range []Config{
		{APIKeyPepper: pepper, AdminDashboardHandler: valid},
		{APIKeyPepper: pepper, TenantDashboardHandler: valid},
	} {
		if err := New(nil, nil, config).InitializationError(); err == nil {
			t.Fatal("partial dashboard handler configuration did not fail closed")
		}
	}

	var typedNil *dashboardMountTestHandler
	if err := New(nil, nil, Config{
		APIKeyPepper: pepper, AdminDashboardHandler: typedNil, TenantDashboardHandler: valid,
	}).InitializationError(); err == nil {
		t.Fatal("typed-nil dashboard handler did not fail closed")
	}
}

func TestAnalyticsServiceInjectionIsExclusive(t *testing.T) {
	service, err := analytics.NewService(rejectingAnalyticsStore{})
	if err != nil {
		t.Fatal(err)
	}
	pepper := bytes.Repeat([]byte{0x52}, 32)
	api := New(nil, nil, Config{APIKeyPepper: pepper, AnalyticsService: service})
	if err := api.InitializationError(); err != nil || api.analyticsHandler == nil {
		t.Fatalf("shared analytics service initialization = (%T, %v)", api.analyticsHandler, err)
	}
	api = New(nil, nil, Config{
		APIKeyPepper: pepper, AnalyticsService: service, AnalyticsQueryStore: rejectingAnalyticsStore{},
	})
	if err := api.InitializationError(); err == nil {
		t.Fatal("analytics service and query store were both accepted")
	}
}

type dashboardMountTestHandler struct{}

func (*dashboardMountTestHandler) ServeHTTP(http.ResponseWriter, *http.Request) {}

func TestDashboardHTTPCompositionWithLiveSessionAndRBAC(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	store := identity.NewStore(pool)
	bootstrap, err := store.BootstrapPlatformUser(
		t.Context(), "dashboard-admin", "Dashboard Admin", passwordHash, "dashboard-bootstrap",
	)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := identity.NewTokenManager("dashboard-integration-secret-at-least-thirty-two-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(store, tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	managed, err := identityService.CreateUser(t.Context(), identity.Actor{
		UserID: bootstrap.UserID, ScopeID: bootstrap.ScopeID, ScopeKind: "platform",
	}, identity.CreateUserInput{
		Username: "dashboard-tenant", Password: testPassword,
		Fields: identity.UserFields{DisplayName: "Dashboard Tenant"}, Role: identity.UserRoleOwner,
		IdempotencyKey: "dashboard-create-tenant", RequestID: "dashboard-create-tenant",
	})
	if err != nil {
		t.Fatal(err)
	}
	if managed.TenantID == nil || *managed.TenantID == uuid.Nil || managed.ScopeID == uuid.Nil {
		t.Fatalf("managed dashboard tenant = %+v", managed)
	}

	sessions, err := sessioncredential.NewVerifier(tokens, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x44}, 32), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	iam, err := iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		t.Fatal(err)
	}
	dashboardStore, err := dashboard.NewStore(pool, iam, nil)
	if err != nil {
		t.Fatal(err)
	}
	dashboardHandler, err := dashboardhttp.NewHandler(identityService, dashboardStore, dashboardhttp.Config{})
	if err != nil {
		t.Fatal(err)
	}
	api := New(pool, identityService, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32),
		AdminDashboardHandler: dashboardHandler, TenantDashboardHandler: dashboardHandler,
	})
	if err := api.InitializationError(); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(api.Handler())
	t.Cleanup(server.Close)

	for _, test := range []struct {
		username string
		path     string
	}{
		{username: "dashboard-admin", path: "/v1/admin/dashboard?range=seven_days&timezone=UTC"},
		{username: "dashboard-tenant", path: "/v1/dashboard?range=today&timezone=UTC"},
	} {
		authenticated, _ := loginOK(t, server.Client(), server.URL, test.username)
		response := doRequest(t, server.Client(), http.MethodGet, server.URL+test.path, nil, nil, authenticated.AccessToken)
		var result struct {
			DashboardVersion uint16 `json:"dashboard_version"`
			Analytics        struct {
				Available bool   `json:"available"`
				Reason    string `json:"reason"`
			} `json:"analytics"`
		}
		decodeResponse(t, response, http.StatusOK, &result)
		response.Body.Close()
		if result.DashboardVersion != dashboard.Version || result.Analytics.Available ||
			result.Analytics.Reason != dashboard.ReasonDependencyUnavailable {
			t.Fatalf("GET %s result = %+v", test.path, result)
		}
	}
}

func TestIdentityHTTPFlow(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	store := identity.NewStore(pool)
	bootstrap, err := store.BootstrapPlatformUser(
		context.Background(),
		"admin",
		"Platform Admin",
		passwordHash,
		"test-bootstrap",
	)
	if err != nil {
		t.Fatalf("BootstrapPlatformUser() error = %v", err)
	}
	disabledUserID := insertTestUser(t, pool, bootstrap.ScopeID, "disabled", "Disabled User", passwordHash, "disabled")
	noRoleUserID := insertTestUser(t, pool, bootstrap.ScopeID, "viewer", "No Role User", passwordHash, "active")
	if disabledUserID == uuid.Nil || noRoleUserID == uuid.Nil {
		t.Fatal("test users were not created")
	}

	tokens, err := identity.NewTokenManager("integration-test-secret-at-least-thirty-two-bytes", 5*time.Minute)
	if err != nil {
		t.Fatalf("NewTokenManager() error = %v", err)
	}
	identityService, err := identity.NewService(store, tokens, 24*time.Hour)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	// Without an API key pepper New leaves the API key service unset and
	// /health/ready dereferences it.
	server := httptest.NewServer(New(pool, identityService, Config{
		CookieSecure: false, APIKeyPepper: bytes.Repeat([]byte{0x53}, 32),
	}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()

	t.Run("health endpoints", func(t *testing.T) {
		for _, path := range []string{"/health/live", "/health/ready"} {
			response := doRequest(t, client, http.MethodGet, server.URL+path, nil, nil, "")
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Fatalf("GET %s status = %d, want 200", path, response.StatusCode)
			}
			if response.Header.Get("X-Request-ID") == "" {
				t.Fatalf("GET %s did not return X-Request-ID", path)
			}
		}
	})

	t.Run("invalid input", func(t *testing.T) {
		response := postLogin(t, client, server.URL, map[string]any{
			"username": "admin",
			"unknown":  true,
		}, "request-invalid")
		defer response.Body.Close()
		assertError(t, response, http.StatusBadRequest, "invalid_request", "request-invalid")
	})

	t.Run("wrong password", func(t *testing.T) {
		response := postLogin(t, client, server.URL, map[string]any{
			"username": "admin",
			"password": "definitely-wrong",
		}, "")
		defer response.Body.Close()
		assertError(t, response, http.StatusUnauthorized, "invalid_credentials", "")
	})

	t.Run("disabled account", func(t *testing.T) {
		response := postLogin(t, client, server.URL, map[string]any{
			"username": "disabled",
			"password": testPassword,
		}, "")
		defer response.Body.Close()
		assertError(t, response, http.StatusForbidden, "account_disabled", "")
	})

	t.Run("login and me", func(t *testing.T) {
		result, cookie := loginOK(t, client, server.URL, "admin")
		if result.TokenType != "Bearer" || result.ExpiresIn <= 0 {
			t.Fatalf("login token metadata = (%q, %d)", result.TokenType, result.ExpiresIn)
		}
		if result.Principal.UserID != bootstrap.UserID || result.Principal.ScopeID != bootstrap.ScopeID {
			t.Fatalf("login principal = %#v", result.Principal)
		}
		if result.Principal.DisplayID == "" {
			t.Fatalf("login principal omitted display ID: %#v", result.Principal)
		}
		if !cookie.HttpOnly || cookie.Secure || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/v1/auth" {
			t.Fatalf("refresh cookie attributes = %#v", cookie)
		}
		response := doRequest(t, client, http.MethodGet, server.URL+"/v1/auth/me", nil, nil, result.AccessToken)
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("GET /me status = %d, body = %s", response.StatusCode, readBody(response.Body))
		}
	})

	t.Run("permission denied", func(t *testing.T) {
		result, _ := loginOK(t, client, server.URL, "viewer")
		response := doRequest(t, client, http.MethodGet, server.URL+"/v1/auth/me", nil, nil, result.AccessToken)
		defer response.Body.Close()
		assertError(t, response, http.StatusForbidden, "permission_denied", "")
	})

	t.Run("refresh rotation and replay revokes family", func(t *testing.T) {
		_, firstCookie := loginOK(t, client, server.URL, "admin")
		response := doRequest(t, client, http.MethodPost, server.URL+"/v1/auth/refresh", nil, firstCookie, "")
		var rotated testAuthResponse
		decodeResponse(t, response, http.StatusOK, &rotated)
		secondCookie := responseCookie(t, response)
		response.Body.Close()
		if secondCookie.Value == firstCookie.Value {
			t.Fatal("refresh did not rotate the cookie")
		}

		// A sibling tab presenting the just-rotated cookie is served without a
		// new cookie (the browser already holds the successor).
		sibling := doRequest(t, client, http.MethodPost, server.URL+"/v1/auth/refresh", nil, firstCookie, "")
		var siblingAuth testAuthResponse
		decodeResponse(t, sibling, http.StatusOK, &siblingAuth)
		for _, cookie := range sibling.Cookies() {
			if cookie.Name == refreshCookieName {
				t.Fatalf("sibling refresh set %s (MaxAge=%d)", refreshCookieName, cookie.MaxAge)
			}
		}
		sibling.Body.Close()

		// Outside the grace window the old cookie is replay.
		if _, err := pool.Exec(context.Background(), `UPDATE auth_sessions SET used_at = used_at - interval '31 seconds' WHERE used_at IS NOT NULL`); err != nil {
			t.Fatal(err)
		}
		replay := doRequest(t, client, http.MethodPost, server.URL+"/v1/auth/refresh", nil, firstCookie, "")
		assertError(t, replay, http.StatusUnauthorized, "refresh_replayed", "")
		replay.Body.Close()

		revoked := doRequest(t, client, http.MethodPost, server.URL+"/v1/auth/refresh", nil, secondCookie, "")
		assertError(t, revoked, http.StatusUnauthorized, "invalid_session", "")
		revoked.Body.Close()
	})

	t.Run("logout revokes session and access", func(t *testing.T) {
		result, cookie := loginOK(t, client, server.URL, "admin")
		logout := doRequest(t, client, http.MethodPost, server.URL+"/v1/auth/logout", nil, cookie, "")
		if logout.StatusCode != http.StatusNoContent {
			t.Fatalf("logout status = %d, want 204", logout.StatusCode)
		}
		logout.Body.Close()

		refresh := doRequest(t, client, http.MethodPost, server.URL+"/v1/auth/refresh", nil, cookie, "")
		assertError(t, refresh, http.StatusUnauthorized, "invalid_session", "")
		refresh.Body.Close()

		me := doRequest(t, client, http.MethodGet, server.URL+"/v1/auth/me", nil, nil, result.AccessToken)
		assertError(t, me, http.StatusUnauthorized, "invalid_session", "")
		me.Body.Close()
	})

	t.Run("audit log is append only", func(t *testing.T) {
		if _, err := pool.Exec(context.Background(), "UPDATE audit_events SET action = 'tampered'"); err == nil {
			t.Fatal("audit event update unexpectedly succeeded")
		}
	})

	t.Run("migration rolls back and reapplies", func(t *testing.T) {
		ctx := context.Background()
		pool := migrationRoundTripPool(t, 6)
		for {
			var latestVersion int64
			if err := pool.QueryRow(ctx, "SELECT COALESCE(max(version), 0) FROM schema_migrations").Scan(&latestVersion); err != nil {
				t.Fatalf("inspect latest migration: %v", err)
			}
			if latestVersion <= 6 {
				break
			}
			if err := database.Migrate(ctx, pool, "down"); err != nil {
				t.Fatalf("Migrate(down %d) error = %v", latestVersion, err)
			}
		}
		if err := database.Migrate(ctx, pool, "down"); err != nil {
			t.Fatalf("Migrate(down 006) error = %v", err)
		}
		var identityWriteTable *string
		if err := pool.QueryRow(ctx, "SELECT to_regclass('identity_write_requests')::text").Scan(&identityWriteTable); err != nil {
			t.Fatalf("inspect identity write table after rollback: %v", err)
		}
		if identityWriteTable != nil {
			t.Fatalf("identity_write_requests still exists after migration 006 rollback: %s", *identityWriteTable)
		}
		if err := database.Migrate(ctx, pool, "down"); err != nil {
			t.Fatalf("Migrate(down 005) error = %v", err)
		}
		for _, table := range []string{"dns_providers", "dns_zones", "dns_records", "certificate_orders", "dns_acme_outbox", "dns_acme_write_requests"} {
			var relation *string
			if err := pool.QueryRow(ctx, "SELECT to_regclass($1)::text", table).Scan(&relation); err != nil {
				t.Fatalf("inspect %s after rollback: %v", table, err)
			}
			if relation != nil {
				t.Fatalf("%s still exists after migration 005 rollback: %s", table, *relation)
			}
		}
		if err := database.Migrate(ctx, pool, "down"); err != nil {
			t.Fatalf("Migrate(down 004) error = %v", err)
		}
		var entitlementTable *string
		if err := pool.QueryRow(ctx, "SELECT to_regclass('control_installation_entitlement')::text").Scan(&entitlementTable); err != nil {
			t.Fatalf("inspect entitlement table after rollback: %v", err)
		}
		if entitlementTable != nil {
			t.Fatalf("entitlement table still exists after migration 004 rollback: %s", *entitlementTable)
		}
		if err := database.Migrate(ctx, pool, "down"); err != nil {
			t.Fatalf("Migrate(down 003) error = %v", err)
		}
		var sitesTable *string
		if err := pool.QueryRow(ctx, "SELECT to_regclass('sites')::text").Scan(&sitesTable); err != nil {
			t.Fatalf("inspect sites table after rollback: %v", err)
		}
		if sitesTable != nil {
			t.Fatalf("sites table still exists after migration 003 rollback: %s", *sitesTable)
		}
		if err := database.Migrate(ctx, pool, "down"); err != nil {
			t.Fatalf("Migrate(down 002) error = %v", err)
		}
		var nodesTable *string
		if err := pool.QueryRow(ctx, "SELECT to_regclass('nodes')::text").Scan(&nodesTable); err != nil {
			t.Fatalf("inspect nodes table after rollback: %v", err)
		}
		if nodesTable != nil {
			t.Fatalf("nodes table still exists after migration 002 rollback: %s", *nodesTable)
		}
		if err := database.Migrate(ctx, pool, "down"); err != nil {
			t.Fatalf("Migrate(down 001) error = %v", err)
		}
		var usersTable *string
		if err := pool.QueryRow(ctx, "SELECT to_regclass('users')::text").Scan(&usersTable); err != nil {
			t.Fatalf("inspect users table after rollback: %v", err)
		}
		if usersTable != nil {
			t.Fatalf("users table still exists after rollback: %s", *usersTable)
		}
		if err := database.Migrate(ctx, pool, "up"); err != nil {
			t.Fatalf("Migrate(up) after rollback error = %v", err)
		}
		if err := pool.QueryRow(ctx, "SELECT to_regclass('users')::text").Scan(&usersTable); err != nil {
			t.Fatalf("inspect users table after reapply: %v", err)
		}
		if usersTable == nil {
			t.Fatal("users table is missing after migration reapply")
		}
		if err := pool.QueryRow(ctx, "SELECT to_regclass('nodes')::text").Scan(&nodesTable); err != nil {
			t.Fatalf("inspect nodes table after reapply: %v", err)
		}
		if nodesTable == nil {
			t.Fatal("nodes table is missing after migration reapply")
		}
		if err := pool.QueryRow(ctx, "SELECT to_regclass('sites')::text").Scan(&sitesTable); err != nil {
			t.Fatalf("inspect sites table after reapply: %v", err)
		}
		if sitesTable == nil {
			t.Fatal("sites table is missing after migration reapply")
		}
		if err := pool.QueryRow(ctx, "SELECT to_regclass('control_installation_entitlement')::text").Scan(&entitlementTable); err != nil {
			t.Fatalf("inspect entitlement table after reapply: %v", err)
		}
		if entitlementTable == nil {
			t.Fatal("entitlement table is missing after migration reapply")
		}
		for _, table := range []string{"dns_providers", "dns_zones", "dns_records", "certificate_orders", "dns_acme_outbox", "dns_acme_write_requests"} {
			var relation *string
			if err := pool.QueryRow(ctx, "SELECT to_regclass($1)::text", table).Scan(&relation); err != nil {
				t.Fatalf("inspect %s after reapply: %v", table, err)
			}
			if relation == nil {
				t.Fatalf("%s is missing after migration reapply", table)
			}
		}
		if err := pool.QueryRow(ctx, "SELECT to_regclass('identity_write_requests')::text").Scan(&identityWriteTable); err != nil {
			t.Fatalf("inspect identity write table after reapply: %v", err)
		}
		if identityWriteTable == nil {
			t.Fatal("identity_write_requests is missing after migration reapply")
		}
		var identityPermissionCount int
		if err := pool.QueryRow(ctx, `
			SELECT count(*) FROM permissions
			WHERE name IN ('identity.self.update', 'identity.password.change')`,
		).Scan(&identityPermissionCount); err != nil {
			t.Fatalf("inspect identity permissions after reapply: %v", err)
		}
		if identityPermissionCount != 2 {
			t.Fatalf("identity permission count = %d, want 2", identityPermissionCount)
		}
		var sitePermissionCount int
		if err := pool.QueryRow(ctx, `
			SELECT count(*) FROM permissions WHERE name IN ('sites.read', 'sites.manage')`,
		).Scan(&sitePermissionCount); err != nil {
			t.Fatalf("inspect site permissions after reapply: %v", err)
		}
		if sitePermissionCount != 2 {
			t.Fatalf("site permission count = %d, want 2", sitePermissionCount)
		}
		var dnsPermissionCount int
		if err := pool.QueryRow(ctx, `
			SELECT count(*) FROM permissions
			WHERE name IN ('dns.read', 'dns.manage', 'certificates.read', 'certificates.manage')`,
		).Scan(&dnsPermissionCount); err != nil {
			t.Fatalf("inspect DNS permissions after reapply: %v", err)
		}
		if dnsPermissionCount != 4 {
			t.Fatalf("DNS permission count = %d, want 4", dnsPermissionCount)
		}
	})
}

func isolatedTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	return isolatedTestSchema(t, true)
}

// migrationRoundTripPool returns a schema migrated only through target.
// Migration 268's down is a deliberate one-way gate (P2682), so early-migration
// round trips must not start from the release head.
func migrationRoundTripPool(t *testing.T, target int64) *pgxpool.Pool {
	t.Helper()
	pool := isolatedTestSchema(t, false)
	if err := databasetest.MigrateThrough(context.Background(), pool, "up", target); err != nil {
		t.Fatalf("migrate through %03d: %v", target, err)
	}
	return pool
}

func isolatedTestSchema(t *testing.T, migrate bool) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	// 从 1 号装载到发布头（280+ 个迁移）在共享 PG、高负载下会超过 30 秒；只放宽夹具的建库时限。
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	adminPool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("open test administration pool: %v", err)
	}
	schema := "control_api_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^control_api_test_[a-f0-9]{32}$`).MatchString(schema) {
		adminPool.Close()
		t.Fatalf("refusing unexpected test schema name %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := adminPool.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		adminPool.Close()
		t.Fatalf("create isolated test schema: %v", err)
	}

	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		adminPool.Close()
		t.Fatalf("parse test database URL: %v", err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		_, _ = adminPool.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		adminPool.Close()
		t.Fatalf("open isolated test pool: %v", err)
	}
	if migrate {
		if err := database.Migrate(ctx, pool, "up"); err != nil {
			pool.Close()
			_, _ = adminPool.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
			adminPool.Close()
			t.Fatalf("migrate isolated test schema: %v", err)
		}
	}
	t.Cleanup(func() {
		pool.Close()
		// Dropping a release-head schema (thousands of objects) takes well over
		// 15 seconds on a loaded shared PostgreSQL.
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		if _, err := adminPool.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop isolated test schema: %v", err)
		}
		adminPool.Close()
	})
	return pool
}

func insertTestUser(
	t *testing.T,
	pool *pgxpool.Pool,
	scopeID uuid.UUID,
	username string,
	displayName string,
	passwordHash string,
	status string,
) uuid.UUID {
	t.Helper()
	userID := uuid.New()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `
		INSERT INTO users (id, username, display_name, password_hash, status)
		VALUES ($1, $2, $3, $4, $5)`, userID, username, displayName, passwordHash, status); err != nil {
		t.Fatalf("insert test user %q: %v", username, err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO memberships (scope_id, user_id) VALUES ($1, $2)`, scopeID, userID); err != nil {
		t.Fatalf("insert test membership %q: %v", username, err)
	}
	return userID
}

func postLogin(t *testing.T, client *http.Client, baseURL string, body any, requestID string) *http.Response {
	t.Helper()
	return doRequest(t, client, http.MethodPost, baseURL+"/v1/auth/login", body, nil, "", requestID)
}

func loginOK(t *testing.T, client *http.Client, baseURL string, username string) (testAuthResponse, *http.Cookie) {
	t.Helper()
	response := postLogin(t, client, baseURL, map[string]any{
		"username": username,
		"password": testPassword,
	}, "")
	var result testAuthResponse
	decodeResponse(t, response, http.StatusOK, &result)
	cookie := responseCookie(t, response)
	response.Body.Close()
	return result, cookie
}

func doRequest(
	t *testing.T,
	client *http.Client,
	method string,
	url string,
	body any,
	cookie *http.Cookie,
	accessToken string,
	requestIDs ...string,
) *http.Response {
	t.Helper()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("encode request body: %v", err)
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		request.AddCookie(cookie)
	}
	if accessToken != "" {
		request.Header.Set("Authorization", "Bearer "+accessToken)
	}
	if len(requestIDs) > 0 && requestIDs[0] != "" {
		request.Header.Set("X-Request-ID", requestIDs[0])
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("perform request: %v", err)
	}
	return response
}

func decodeResponse(t *testing.T, response *http.Response, expectedStatus int, destination any) {
	t.Helper()
	if response.StatusCode != expectedStatus {
		t.Fatalf("response status = %d, want %d, body = %s", response.StatusCode, expectedStatus, readBody(response.Body))
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if err := json.Unmarshal(withoutBasicSyncStatus(body), destination); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}

// decodeSiteResponseBody is decodeResponse's body decoding for goroutines
// that cannot call t.Fatal.
func decodeSiteResponseBody(body io.Reader, destination any) error {
	encoded, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	return json.Unmarshal(withoutBasicSyncStatus(encoded), destination)
}

// withoutBasicSyncStatus drops basic.sync_status from a site response: the
// server derives it (PJ-C02, 497) and siteBasicPayload, which the tests reuse
// to read responses, refuses it as a request field.
func withoutBasicSyncStatus(body []byte) []byte {
	if !bytes.Contains(body, []byte(`"sync_status"`)) {
		return body
	}
	var decoded any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if decoder.Decode(&decoded) != nil {
		return body
	}
	var strip func(value any, underBasic bool)
	strip = func(value any, underBasic bool) {
		switch typed := value.(type) {
		case map[string]any:
			if underBasic {
				delete(typed, "sync_status")
			}
			for key, child := range typed {
				strip(child, key == "basic")
			}
		case []any:
			for _, child := range typed {
				strip(child, false)
			}
		}
	}
	strip(decoded, false)
	encoded, err := json.Marshal(decoded)
	if err != nil {
		return body
	}
	return encoded
}

func assertError(t *testing.T, response *http.Response, status int, code string, requestID string) {
	t.Helper()
	var envelope testErrorEnvelope
	decodeResponse(t, response, status, &envelope)
	if envelope.Error.Code != code {
		t.Fatalf("error code = %q, want %q", envelope.Error.Code, code)
	}
	if envelope.Error.RequestID == "" {
		t.Fatal("error request_id is empty")
	}
	if requestID != "" && envelope.Error.RequestID != requestID {
		t.Fatalf("error request_id = %q, want %q", envelope.Error.RequestID, requestID)
	}
}

func responseCookie(t *testing.T, response *http.Response) *http.Cookie {
	t.Helper()
	for _, cookie := range response.Cookies() {
		if cookie.Name == refreshCookieName && cookie.MaxAge >= 0 {
			return cookie
		}
	}
	t.Fatalf("response did not include %s cookie", refreshCookieName)
	return nil
}

func readBody(reader io.Reader) string {
	body, _ := io.ReadAll(reader)
	return fmt.Sprintf("%s", body)
}
