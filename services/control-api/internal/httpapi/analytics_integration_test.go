package httpapi

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analytics"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
)

// average_bandwidth_bps must equal response_bytes*8 / window seconds (13*8/3600
// for the one-hour test window); Client.Summary rejects inconsistent rows.
const analyticsSummaryRow = `{"metric_version":1,"request_count":7,"request_bytes":11,"response_bytes":13,"total_bytes":24,"average_bandwidth_bps":0.028888888888888888,"status_2xx":5,"status_3xx":1,"status_4xx":1,"status_5xx":0,"security_events":3,"security_event_rows":3,"cache_hit_requests":0,"cache_hit_bytes":0,"unique_client_ips":1}` + "\n"

func TestAnalyticsHTTPFlow(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	identityStore := identity.NewStore(pool)
	bootstrap, err := identityStore.BootstrapPlatformUser(
		context.Background(), "analytics-admin", "Analytics Admin", passwordHash, "analytics-bootstrap",
	)
	if err != nil {
		t.Fatal(err)
	}
	insertTestUser(t, pool, bootstrap.ScopeID, "analytics-viewer", "Analytics Viewer", passwordHash, "active")
	permissionUserID := insertTestUser(t, pool, bootstrap.ScopeID, "analytics-permission", "Analytics Permission", passwordHash, "active")
	var permissionRoleID string
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO roles (id, scope_id, name, description, system_role)
		VALUES (gen_random_uuid(), $1, 'analytics_permission_test', 'Analytics live permission test', true)
		RETURNING id::text`, bootstrap.ScopeID).Scan(&permissionRoleID); err != nil {
		t.Fatalf("create analytics permission test role: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO role_permissions (role_id, permission_name) VALUES ($1, 'platform.admin')`,
		permissionRoleID); err != nil {
		t.Fatalf("grant analytics test permission: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO role_assignments (scope_id, user_id, role_id) VALUES ($1, $2, $3)`,
		bootstrap.ScopeID, permissionUserID, permissionRoleID); err != nil {
		t.Fatalf("assign analytics test role: %v", err)
	}
	tokens, err := identity.NewTokenManager("analytics-integration-secret-at-least-thirty-two-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identityStore, tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	clickHouse := &analyticsClickHouseStub{body: analyticsSummaryRow}
	clickHouseServer := httptest.NewTLSServer(clickHouse)
	t.Cleanup(clickHouseServer.Close)
	queryStore, err := analytics.NewClient(analytics.Config{
		Endpoint:         clickHouseServer.URL,
		Database:         "cdnca_analytics",
		Username:         "analytics_reader",
		Password:         "analytics-password",
		QueryTimeout:     100 * time.Millisecond,
		MaxResponseBytes: 2048,
	}, clickHouseServer.Client())
	if err != nil {
		t.Fatal(err)
	}
	api := New(pool, identityService, Config{
		CookieSecure:        false,
		APIKeyPepper:        bytes.Repeat([]byte{0x24}, 32),
		AnalyticsQueryStore: queryStore,
		AnalyticsHandlerConfig: analytics.HandlerConfig{
			QueryTimeout:     200 * time.Millisecond,
			MaxResponseBytes: 1024,
		},
	})
	if err := api.InitializationError(); err != nil {
		t.Fatalf("initialize analytics HTTP API: %v", err)
	}
	server := httptest.NewServer(api.Handler())
	t.Cleanup(server.Close)
	client := server.Client()

	platformAuth, _ := loginWithPassword(t, client, server.URL, "analytics-admin", testPassword)
	viewerAuth, _ := loginWithPassword(t, client, server.URL, "analytics-viewer", testPassword)
	permissionAuth, _ := loginWithPassword(t, client, server.URL, "analytics-permission", testPassword)
	tenantUser := createManagedUser(t, client, server.URL, platformAuth.AccessToken, "analytics-create-tenant", map[string]any{
		"username": "analytics-tenant", "password": tenantPassword, "display_name": "Analytics Tenant",
		"email": nil, "phone": nil, "role": identity.UserRoleOwner,
	})
	tenantAuth, _ := loginWithPassword(t, client, server.URL, tenantUser.Username, tenantPassword)
	if tenantAuth.Principal.TenantID == nil {
		t.Fatal("tenant principal has no tenant ID")
	}
	issued := createSelfAPIKey(t, client, server.URL, tenantAuth.AccessToken, "analytics-api-key", map[string]any{
		"name": "analytics reader", "scopes": []string{"sites.read"},
		"expires_at": time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
	})
	apiCredential := issued.Key.KeyID + "." + issued.Secret
	window := "from=2026-07-23T00%3A00%3A00Z&to=2026-07-23T01%3A00%3A00Z"

	t.Run("tenant bearer derives ClickHouse scope and preserves request ID", func(t *testing.T) {
		clickHouse.reset(http.StatusOK, analyticsSummaryRow, 0)
		response := analyticsRequest(t, client, server.URL+"/v1/analytics/summary?"+window,
			"Bearer "+tenantAuth.AccessToken, "analytics-tenant-request")
		var result struct {
			Data analytics.Summary `json:"data"`
		}
		decodeResponse(t, response, http.StatusOK, &result)
		defer response.Body.Close()
		if result.Data.RequestCount != 7 || response.Header.Get("X-Request-ID") != "analytics-tenant-request" {
			t.Fatalf("tenant analytics response = %#v request ID=%q", result, response.Header.Get("X-Request-ID"))
		}
		request := clickHouse.singleRequest(t)
		if request.database != "cdnca_analytics" || request.username != "analytics_reader" ||
			request.password != "analytics-password" || request.parameters.Get("param_tenant_scoped") != "1" ||
			request.parameters.Get("param_tenant_id") != tenantAuth.Principal.TenantID.String() ||
			!strings.Contains(request.body, "FROM access_hourly_facts_v1") {
			t.Fatalf("tenant ClickHouse request = %#v", request)
		}
	})

	t.Run("CdncaKey uses the same live tenant scope", func(t *testing.T) {
		clickHouse.reset(http.StatusOK, analyticsSummaryRow, 0)
		response := analyticsRequest(t, client, server.URL+"/v1/analytics/summary?"+window,
			"CdncaKey "+apiCredential, "analytics-key-request")
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("API key analytics status=%d body=%s", response.StatusCode, readBody(response.Body))
		}
		request := clickHouse.singleRequest(t)
		if request.parameters.Get("param_tenant_id") != tenantAuth.Principal.TenantID.String() {
			t.Fatalf("API key tenant ID = %q", request.parameters.Get("param_tenant_id"))
		}
	})

	t.Run("platform global and selected tenant are distinct", func(t *testing.T) {
		clickHouse.reset(http.StatusOK, analyticsSummaryRow, 0)
		global := analyticsRequest(t, client, server.URL+"/v1/admin/analytics/summary?"+window,
			"Bearer "+platformAuth.AccessToken, "analytics-platform-global")
		defer global.Body.Close()
		if global.StatusCode != http.StatusOK {
			t.Fatalf("platform global status=%d body=%s", global.StatusCode, readBody(global.Body))
		}
		if request := clickHouse.singleRequest(t); request.parameters.Get("param_tenant_scoped") != "0" {
			t.Fatalf("platform global parameters = %v", request.parameters)
		}

		clickHouse.reset(http.StatusOK, analyticsSummaryRow, 0)
		selected := analyticsRequest(t, client, server.URL+"/v1/admin/analytics/summary?"+window+
			"&tenant_id="+tenantAuth.Principal.TenantID.String(), "Bearer "+platformAuth.AccessToken, "analytics-platform-tenant")
		defer selected.Body.Close()
		if selected.StatusCode != http.StatusOK {
			t.Fatalf("platform tenant status=%d body=%s", selected.StatusCode, readBody(selected.Body))
		}
		request := clickHouse.singleRequest(t)
		if request.parameters.Get("param_tenant_scoped") != "1" ||
			request.parameters.Get("param_tenant_id") != tenantAuth.Principal.TenantID.String() {
			t.Fatalf("platform tenant parameters = %v", request.parameters)
		}
	})

	t.Run("scope and permission failures never query storage", func(t *testing.T) {
		for _, test := range []struct {
			name       string
			path       string
			token      string
			wantStatus int
			wantCode   string
		}{
			{name: "tenant admin route", path: "/v1/admin/analytics/summary?" + window, token: tenantAuth.AccessToken, wantStatus: 403, wantCode: "analytics_scope_forbidden"},
			{name: "platform tenant route", path: "/v1/analytics/summary?" + window, token: platformAuth.AccessToken, wantStatus: 403, wantCode: "analytics_scope_forbidden"},
			{name: "tenant override", path: "/v1/analytics/summary?" + window + "&tenant_id=" + tenantAuth.Principal.TenantID.String(), token: tenantAuth.AccessToken, wantStatus: 403, wantCode: "analytics_scope_forbidden"},
			{name: "tenant empty override", path: "/v1/analytics/summary?" + window + "&tenant_id=", token: tenantAuth.AccessToken, wantStatus: 403, wantCode: "analytics_scope_forbidden"},
			{name: "platform empty tenant", path: "/v1/admin/analytics/summary?" + window + "&tenant_id=", token: platformAuth.AccessToken, wantStatus: 400, wantCode: "analytics_invalid_request"},
			{name: "permission", path: "/v1/admin/analytics/summary?" + window, token: viewerAuth.AccessToken, wantStatus: 403, wantCode: "analytics_permission_denied"},
		} {
			t.Run(test.name, func(t *testing.T) {
				clickHouse.reset(http.StatusOK, analyticsSummaryRow, 0)
				response := analyticsRequest(t, client, server.URL+test.path, "Bearer "+test.token, "analytics-denied")
				defer response.Body.Close()
				assertAnalyticsError(t, response, test.wantStatus, test.wantCode, "analytics-denied")
				if count := clickHouse.requestCount(); count != 0 {
					t.Fatalf("denied request reached ClickHouse %d times", count)
				}
			})
		}
	})

	t.Run("storage failure timeout and response limit remain query-local", func(t *testing.T) {
		clickHouse.reset(http.StatusServiceUnavailable, "unavailable", 0)
		unavailable := analyticsRequest(t, client, server.URL+"/v1/analytics/summary?"+window,
			"Bearer "+tenantAuth.AccessToken, "analytics-unavailable")
		assertAnalyticsError(t, unavailable, http.StatusServiceUnavailable, "analytics_storage_unavailable", "analytics-unavailable")
		unavailable.Body.Close()

		clickHouse.reset(http.StatusOK, analyticsSummaryRow, 500*time.Millisecond)
		timedOut := analyticsRequest(t, client, server.URL+"/v1/analytics/summary?"+window,
			"Bearer "+tenantAuth.AccessToken, "analytics-timeout")
		assertAnalyticsError(t, timedOut, http.StatusGatewayTimeout, "analytics_query_timeout", "analytics-timeout")
		timedOut.Body.Close()

		clickHouse.reset(http.StatusOK, strings.Repeat("x", 2049), 0)
		tooLarge := analyticsRequest(t, client, server.URL+"/v1/analytics/summary?"+window,
			"Bearer "+tenantAuth.AccessToken, "analytics-too-large")
		assertAnalyticsError(t, tooLarge, http.StatusBadGateway, "analytics_response_too_large", "analytics-too-large")
		tooLarge.Body.Close()

		ready := doRequest(t, client, http.MethodGet, server.URL+"/health/ready", nil, nil, "", "analytics-ready")
		defer ready.Body.Close()
		if ready.StatusCode != http.StatusOK {
			t.Fatalf("readiness after analytics failure status=%d body=%s", ready.StatusCode, readBody(ready.Body))
		}
	})

	t.Run("authorization changes take effect on the next request", func(t *testing.T) {
		revoke := apiKeyRequest(t, client, http.MethodPost,
			server.URL+"/v1/account/api-keys/"+issued.Key.ID.String()+"/revoke", map[string]any{},
			tenantAuth.AccessToken, "", "analytics-revoke-key", `"1"`, "analytics-revoke-key")
		if revoke.StatusCode != http.StatusOK {
			t.Fatalf("revoke analytics API key status=%d body=%s", revoke.StatusCode, readBody(revoke.Body))
		}
		revoke.Body.Close()

		clickHouse.reset(http.StatusOK, analyticsSummaryRow, 0)
		revokedKey := analyticsRequest(t, client, server.URL+"/v1/analytics/summary?"+window,
			"CdncaKey "+apiCredential, "analytics-revoked-key")
		assertAnalyticsError(t, revokedKey, http.StatusUnauthorized, "analytics_authentication_required", "analytics-revoked-key")
		revokedKey.Body.Close()
		if count := clickHouse.requestCount(); count != 0 {
			t.Fatalf("revoked API key reached ClickHouse %d times", count)
		}

		clickHouse.reset(http.StatusOK, analyticsSummaryRow, 0)
		grantedPermission := analyticsRequest(t, client, server.URL+"/v1/admin/analytics/summary?"+window,
			"Bearer "+permissionAuth.AccessToken, "analytics-live-permission")
		if grantedPermission.StatusCode != http.StatusOK {
			t.Fatalf("granted analytics permission status=%d body=%s", grantedPermission.StatusCode, readBody(grantedPermission.Body))
		}
		grantedPermission.Body.Close()
		clickHouse.singleRequest(t)
		if _, err := pool.Exec(context.Background(), `
			DELETE FROM role_permissions
			WHERE role_id = $1 AND permission_name = 'platform.admin'`, permissionRoleID); err != nil {
			t.Fatalf("revoke analytics permission grant: %v", err)
		}
		clickHouse.reset(http.StatusOK, analyticsSummaryRow, 0)
		revokedPermission := analyticsRequest(t, client, server.URL+"/v1/admin/analytics/summary?"+window,
			"Bearer "+permissionAuth.AccessToken, "analytics-revoked-permission")
		assertAnalyticsError(t, revokedPermission, http.StatusForbidden, "analytics_permission_denied", "analytics-revoked-permission")
		revokedPermission.Body.Close()
		if count := clickHouse.requestCount(); count != 0 {
			t.Fatalf("principal without permission grant reached ClickHouse %d times", count)
		}

		if _, err := pool.Exec(context.Background(), `
			DELETE FROM role_assignments
			WHERE scope_id = $1 AND user_id = $2`, tenantUser.ScopeID, tenantUser.ID); err != nil {
			t.Fatalf("revoke analytics role assignment: %v", err)
		}
		clickHouse.reset(http.StatusOK, analyticsSummaryRow, 0)
		revokedRole := analyticsRequest(t, client, server.URL+"/v1/analytics/summary?"+window,
			"Bearer "+tenantAuth.AccessToken, "analytics-revoked-role")
		assertAnalyticsError(t, revokedRole, http.StatusForbidden, "analytics_permission_denied", "analytics-revoked-role")
		revokedRole.Body.Close()
		if count := clickHouse.requestCount(); count != 0 {
			t.Fatalf("principal without role binding reached ClickHouse %d times", count)
		}

		if _, err := pool.Exec(context.Background(), `
			UPDATE memberships SET status = 'suspended'
			WHERE scope_id = $1 AND user_id = $2`, tenantUser.ScopeID, tenantUser.ID); err != nil {
			t.Fatalf("suspend analytics membership: %v", err)
		}
		clickHouse.reset(http.StatusOK, analyticsSummaryRow, 0)
		disabledMembership := analyticsRequest(t, client, server.URL+"/v1/analytics/summary?"+window,
			"Bearer "+tenantAuth.AccessToken, "analytics-suspended-membership")
		assertAnalyticsError(t, disabledMembership, http.StatusUnauthorized, "analytics_authentication_required", "analytics-suspended-membership")
		disabledMembership.Body.Close()
		if count := clickHouse.requestCount(); count != 0 {
			t.Fatalf("suspended membership reached ClickHouse %d times", count)
		}
	})
}

func TestAnalyticsRoutesExposeUnavailableStateWhenDisabled(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/v1/analytics/summary", nil)
	response := httptest.NewRecorder()
	New(nil, nil, Config{}).Handler().ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("disabled analytics route status=%d, want 503", response.Code)
	}
	if response.Header().Get("X-Request-ID") == "" {
		t.Fatal("disabled route did not pass through request ID middleware")
	}
}

func TestAnalyticsHandlerInitializationFailureIsReported(t *testing.T) {
	api := New(nil, nil, Config{
		APIKeyPepper:           bytes.Repeat([]byte{0x52}, 32),
		AnalyticsQueryStore:    rejectingAnalyticsStore{},
		AnalyticsHandlerConfig: analytics.HandlerConfig{MaxResponseBytes: 1},
	})
	if err := api.InitializationError(); err == nil {
		t.Fatal("invalid analytics handler config was accepted")
	}
}

func analyticsRequest(t *testing.T, client *http.Client, rawURL, authorization, requestID string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", authorization)
	request.Header.Set("X-Request-ID", requestID)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func assertAnalyticsError(t *testing.T, response *http.Response, status int, code, requestID string) {
	t.Helper()
	var envelope testErrorEnvelope
	decodeResponse(t, response, status, &envelope)
	if envelope.Error.Code != code || envelope.Error.RequestID != requestID || response.Header.Get("X-Request-ID") != requestID {
		t.Fatalf("analytics error = %#v header request ID=%q", envelope, response.Header.Get("X-Request-ID"))
	}
}

type analyticsClickHouseRequest struct {
	database   string
	username   string
	password   string
	parameters url.Values
	body       string
}

type analyticsClickHouseStub struct {
	mu       sync.Mutex
	status   int
	body     string
	delay    time.Duration
	requests []analyticsClickHouseRequest
}

func (stub *analyticsClickHouseStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	encoded, _ := io.ReadAll(r.Body)
	username, password, _ := r.BasicAuth()
	stub.mu.Lock()
	status, body, delay := stub.status, stub.body, stub.delay
	stub.requests = append(stub.requests, analyticsClickHouseRequest{
		database: r.URL.Query().Get("database"), username: username, password: password,
		parameters: r.URL.Query(), body: string(encoded),
	})
	stub.mu.Unlock()
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
	}
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func (stub *analyticsClickHouseStub) reset(status int, body string, delay time.Duration) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.status = status
	stub.body = body
	stub.delay = delay
	stub.requests = nil
}

func (stub *analyticsClickHouseStub) requestCount() int {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	return len(stub.requests)
}

func (stub *analyticsClickHouseStub) singleRequest(t *testing.T) analyticsClickHouseRequest {
	t.Helper()
	stub.mu.Lock()
	defer stub.mu.Unlock()
	if len(stub.requests) != 1 {
		t.Fatalf("ClickHouse request count = %d, want 1", len(stub.requests))
	}
	return stub.requests[0]
}

type rejectingAnalyticsStore struct{}

func (rejectingAnalyticsStore) Summary(context.Context, analytics.Scope, analytics.Filter) (analytics.Summary, error) {
	return analytics.Summary{}, analytics.ErrTransport
}

func (rejectingAnalyticsStore) Trend(context.Context, analytics.Scope, analytics.Filter) ([]analytics.TrendPoint, error) {
	return nil, analytics.ErrTransport
}

func (rejectingAnalyticsStore) Rank(context.Context, analytics.Scope, analytics.Filter, analytics.RankDimension, uint16, string) (analytics.RankPage, error) {
	return analytics.RankPage{}, analytics.ErrTransport
}
