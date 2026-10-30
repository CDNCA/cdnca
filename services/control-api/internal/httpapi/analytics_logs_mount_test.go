package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analytics"
	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
	"github.com/cdnca/cdnca/services/control-api/internal/apikey"
	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/rbacmanager"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	analyticsLogsMigrationTimeout = 5 * time.Minute
	analyticsLogsRequestTimeout   = 5 * time.Second
)

var analyticsLogsExactPaths = []string{
	"/v1/admin/analytics/logs/access",
	"/v1/analytics/logs/access",
	"/v1/admin/analytics/logs/block-events",
	"/v1/analytics/logs/block-events",
	"/v1/admin/analytics/logs/blocks/current",
	"/v1/analytics/logs/blocks/current",
	"/v1/admin/analytics/logs/blocks/current-count",
	"/v1/analytics/logs/blocks/current-count",
	"/v1/admin/analytics/logs/blocks/history",
	"/v1/analytics/logs/blocks/history",
	"/v1/admin/analytics/logs/cc-bans",
	"/v1/analytics/logs/cc-bans",
}

var analyticsLogsUnlockPaths = []string{
	"/v1/admin/analytics/logs/blocks/current/018f0000-0000-7000-8000-000000000010/unlock",
	"/v1/analytics/logs/blocks/current/018f0000-0000-7000-8000-000000000010/unlock",
}

func TestAnalyticsLogsRoutesAreDisabledByDefault(t *testing.T) {
	api := New(nil, nil, Config{
		AnalyticsQueryStore: rejectingAnalyticsStore{},
		AnalyticsHandlerConfig: analytics.HandlerConfig{
			QueryTimeout: time.Second, MaxResponseBytes: 1024,
		},
	})
	for _, path := range analyticsLogsExactPaths {
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNotFound {
			t.Errorf("disabled analytics logs route %s status = %d, want 404", path, response.Code)
		}
	}
}

func TestAnalyticsLogsTypedNilHandlerFailsClosed(t *testing.T) {
	var typedNil *analyticsLogsMountNilHandler
	var typedNilFunc analyticsLogsMountNilHandlerFunc
	for _, handler := range []http.Handler{typedNil, typedNilFunc} {
		api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), AnalyticsLogsHandler: handler})
		if api.InitializationError() == nil {
			t.Fatalf("typed nil analytics logs handler %T was accepted", handler)
		}
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, analyticsLogsExactPaths[0], nil))
		if response.Code != http.StatusNotFound {
			t.Fatalf("typed nil analytics logs route status = %d, want 404", response.Code)
		}
	}
}

func TestAnalyticsLogsMountOwnsOnlyExactPathsAndMethods(t *testing.T) {
	probe := new(analyticsLogsMountProbe)
	handler := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), AnalyticsLogsHandler: probe}).Handler()
	for _, path := range analyticsLogsExactPaths {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Header.Set("Authorization", "Bearer preserved-credential")
		request.Header.Set("X-Request-ID", "analytics-logs-mount")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNoContent || response.Header().Get("X-Request-ID") != "analytics-logs-mount" {
			t.Errorf("GET %s status=%d request_id=%q", path, response.Code, response.Header().Get("X-Request-ID"))
		}
	}
	if calls := probe.count(); calls != len(analyticsLogsExactPaths) {
		t.Fatalf("analytics logs GET calls = %d, want %d", calls, len(analyticsLogsExactPaths))
	}
	for _, path := range analyticsLogsUnlockPaths {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"reason_code":"false_positive_confirmed"}`))
		request.Header.Set("Authorization", "Bearer preserved-credential")
		request.Header.Set("X-Request-ID", "analytics-logs-mount")
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Errorf("POST %s status=%d, want 204", path, response.Code)
		}
	}

	for _, path := range analyticsLogsExactPaths {
		for _, method := range []string{http.MethodPost, http.MethodHead, http.MethodOptions} {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(method, path, nil))
			allowed := strings.Split(response.Header().Get("Allow"), ", ")
			if response.Code != http.StatusMethodNotAllowed || !slices.Contains(allowed, http.MethodGet) {
				t.Errorf("%s %s status=%d Allow=%q", method, path, response.Code, response.Header().Get("Allow"))
			}
		}
	}
	for _, path := range []string{
		"/v1/analytics/logs/access/",
		"/v1/analytics/logs/access/neighbor",
		"/v1/analytics/logs/access-extra",
		"/v1/admin/analytics/logs/blocks/current/",
		"/v1/admin/analytics/logs/blocks/history/neighbor",
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNotFound {
			t.Errorf("adjacent analytics logs route %s status = %d, want 404", path, response.Code)
		}
	}
	if calls := probe.count(); calls != len(analyticsLogsExactPaths)+len(analyticsLogsUnlockPaths) {
		t.Fatalf("non-owned analytics logs requests reached handler: calls=%d", calls)
	}
	for _, observation := range probe.snapshot() {
		if observation.authorization != "Bearer preserved-credential" || observation.requestID != "analytics-logs-mount" {
			t.Fatalf("forwarded analytics logs request = %#v", observation)
		}
	}
}

func TestAnalyticsLogsExportRoutesAreMounted(t *testing.T) {
	probe := new(analyticsLogsMountProbe)
	handler := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), AnalyticsLogsHandler: probe}).Handler()
	routes := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/v1/analytics/logs/access/exports"},
		{http.MethodPost, "/v1/analytics/logs/access/exports"},
		{http.MethodGet, "/v1/analytics/logs/access/exports/018f0000-0000-7000-8000-000000000010"},
		{http.MethodPost, "/v1/analytics/logs/access/exports/018f0000-0000-7000-8000-000000000010/download-grants"},
		{http.MethodGet, "/v1/analytics/logs/access/exports/018f0000-0000-7000-8000-000000000010/download"},
	}
	for _, route := range routes {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(route.method, route.path, nil))
		if response.Code != http.StatusNoContent {
			t.Errorf("%s %s status=%d, want 204", route.method, route.path, response.Code)
		}
	}
	if calls := probe.count(); calls != len(routes) {
		t.Fatalf("analytics export calls = %d, want %d", calls, len(routes))
	}
}

func TestAnalyticsLogsAndExistingAnalyticsRoutesCoexist(t *testing.T) {
	probe := new(analyticsLogsMountProbe)
	api := New(nil, nil, Config{
		APIKeyPepper:         bytes.Repeat([]byte{0x52}, 32),
		AnalyticsQueryStore:  rejectingAnalyticsStore{},
		AnalyticsLogsHandler: probe,
		AnalyticsHandlerConfig: analytics.HandlerConfig{
			QueryTimeout: time.Second, MaxResponseBytes: 1024,
		},
	})
	handler := api.Handler()
	logs := httptest.NewRecorder()
	handler.ServeHTTP(logs, httptest.NewRequest(http.MethodGet, "/v1/analytics/logs/access", nil))
	if logs.Code != http.StatusNoContent || probe.count() != 1 {
		t.Fatalf("analytics logs route status=%d calls=%d", logs.Code, probe.count())
	}
	summary := httptest.NewRecorder()
	handler.ServeHTTP(summary, httptest.NewRequest(http.MethodGet, "/v1/analytics/summary", nil))
	if summary.Code != http.StatusUnauthorized || probe.count() != 1 {
		t.Fatalf("existing analytics route status=%d logs calls=%d", summary.Code, probe.count())
	}
}

func TestAnalyticsLogsMountCanonicalizesRequestIDWithoutChangingCredentials(t *testing.T) {
	probe := new(analyticsLogsMountProbe)
	handler := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), AnalyticsLogsHandler: probe}).Handler()
	request := httptest.NewRequest(http.MethodGet, "/v1/analytics/logs/access", nil)
	request.Header.Add("Authorization", "Bearer first")
	request.Header.Add("Authorization", "Bearer second")
	request.Header.Set("X-Request-ID", "invalid request id")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	observations := probe.snapshot()
	if response.Code != http.StatusNoContent || len(observations) != 1 {
		t.Fatalf("canonical request status=%d observations=%d", response.Code, len(observations))
	}
	observation := observations[0]
	if _, err := uuid.Parse(observation.requestID); err != nil || response.Header().Get("X-Request-ID") != observation.requestID {
		t.Fatalf("canonical request ID=%q response=%q error=%v", observation.requestID, response.Header().Get("X-Request-ID"), err)
	}
	if len(observation.authorizationValues) != 2 {
		t.Fatalf("authorization values changed at mount: %#v", observation.authorizationValues)
	}
}

func TestAnalyticsLogsSharedHandlerPostgres179Smoke(t *testing.T) {
	pool := analyticsLogsIsolatedTestPool(t)
	var version string
	if err := pool.QueryRow(t.Context(), "SHOW server_version_num").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != "170009" {
		t.Fatalf("PostgreSQL server_version_num = %s, want 170009", version)
	}
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	identityStore := identity.NewStore(pool)
	if _, err := identityStore.BootstrapPlatformUser(
		t.Context(), "analytics-logs-admin", "Analytics Logs Admin", passwordHash, "analytics-logs-bootstrap",
	); err != nil {
		t.Fatal(err)
	}
	tokens, err := identity.NewTokenManager("analytics-logs-shared-handler-secret", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identityStore, tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pepper := bytes.Repeat([]byte{0x35}, 32)
	sessions, err := sessioncredential.NewVerifier(tokens, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	apiKeyVerifier, err := apikeycredential.NewVerifier(pepper, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := iamlock.NewAuthorizer(sessions, apiKeyVerifier)
	if err != nil {
		t.Fatal(err)
	}
	var clickHouseCalls atomic.Int64
	now := time.Now().UTC().Truncate(time.Millisecond)
	clickHouse := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		clickHouseCalls.Add(1)
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"event_id": "shared-handler-event", "occurred_at_ms": now.UnixMilli(),
			"site_id": uuid.NewString(), "node_id": uuid.NewString(), "host": "example.test",
			"request_id": "analytics-logs-shared", "trace_id": "analytics-logs-shared",
			"config_version_id": "40000000-0000-4000-8000-000000000001", "snapshot_ms": now.UnixMilli(),
			"uri_path": "/asset.js", "client_ip": "2001:db8::1", "country_code": "CN",
			"carrier": "carrier-a", "method": "GET", "protocol": "HTTP/2", "cache_status": "HIT",
			"upstream_result": "ok", "status_code": 200, "request_bytes": 0, "response_bytes": 100,
			"duration_us": 0, "latest_version_count": 1,
		})
	}))
	logsHandler, err := analyticslog.NewRuntimeHandler(analyticslog.RuntimeConfig{
		Enabled: true,
		HTTP: analyticslog.HTTPConfig{
			Client: analyticslog.ClientConfig{
				Endpoint: clickHouse.URL, Database: "analytics_logs_shared_handler",
				QueryTimeout: time.Second, MaxResponseBytes: 1 << 20,
				CursorKeyring: analyticslog.CursorKeyring{ActiveKID: "mount-test", Keys: map[string][]byte{
					"mount-test": bytes.Repeat([]byte{0x4d}, 32),
				}},
			},
			Handler: analyticslog.HandlerConfig{QueryTimeout: 2 * time.Second, MaxResponseBytes: 1 << 20},
		},
	}, analyticslog.HTTPDependencies{
		Identity: identityService, APIKeys: apikey.NewService(pool, pepper, time.Now), Pool: pool, IAM: authorizer,
	})
	if err != nil {
		clickHouse.Close()
		t.Fatal(err)
	}
	api := New(pool, identityService, Config{APIKeyPepper: pepper, AnalyticsLogsHandler: logsHandler})
	if err := api.InitializationError(); err != nil {
		clickHouse.Close()
		t.Fatal(err)
	}
	server := httptest.NewServer(api.Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	client.Timeout = analyticsLogsRequestTimeout
	platformAuth, _ := loginWithPassword(t, client, server.URL, "analytics-logs-admin", testPassword)
	tenantManager := createManagedUser(t, client, server.URL, platformAuth.AccessToken, "analytics-logs-tenant", map[string]any{
		"username": "analytics-logs-manager", "password": tenantPassword,
		"display_name": "Analytics Logs Manager", "email": nil, "phone": nil, "role": identity.UserRoleOwner,
	})
	managerAuth, _ := loginWithPassword(t, client, server.URL, tenantManager.Username, tenantPassword)
	managerUserID, managerScopeID, managerSessionID, err := tokens.Parse(managerAuth.AccessToken)
	if err != nil || managerUserID != tenantManager.ID || managerScopeID != tenantManager.ScopeID {
		t.Fatalf("analytics logs manager session facts = (%s, %s, %s, %v)",
			managerUserID, managerScopeID, managerSessionID, err)
	}
	readerID := uuid.New()
	readerPasswordHash, err := identity.HashPassword(tenantPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO users(id,username,display_name,password_hash)
			VALUES($1,'analytics-logs-reader','Analytics Logs Reader',$2)`, readerID, readerPasswordHash); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`,
			tenantManager.ScopeID, readerID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	rbacService, err := rbacmanager.NewService(pool, analyticsLogsStepUpVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	rbacActor := rbacmanager.Actor{
		UserID: managerUserID, ScopeID: managerScopeID, SessionID: managerSessionID,
		ScopeKind: "tenant", IdentityDomain: rbacmanager.CustomerControlIdentityDomain,
	}
	mutation := func(key string) rbacmanager.MutationContext {
		return rbacmanager.MutationContext{
			IdempotencyKey: key, RequestID: key, TraceID: key,
			StepUp: rbacmanager.StepUpProof{Token: "analytics-logs-step-up"},
		}
	}
	analyticsRole, err := rbacService.CreateRole(t.Context(), rbacActor, rbacmanager.CreateRoleRequest{
		Name: "analytics-logs-smoke", Permissions: []string{"api_keys.self.manage", "sites.manage", "sites.read"},
		Mutation: mutation("analytics-logs-role-create"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rbacService.AssignRole(t.Context(), rbacActor, rbacmanager.AssignRoleRequest{
		RoleID: analyticsRole.ID, ExpectedRoleRevision: analyticsRole.CurrentRevision,
		SubjectUserID: readerID, Mutation: mutation("analytics-logs-role-assign"),
	}); err != nil {
		t.Fatal(err)
	}
	readerAuth, _ := loginWithPassword(t, client, server.URL, "analytics-logs-reader", tenantPassword)
	issued := createSelfAPIKey(t, client, server.URL, readerAuth.AccessToken, "analytics-logs-api-key", map[string]any{
		"name": "analytics logs reader", "scopes": []string{"sites.manage", "sites.read"},
		"expires_at": time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
	})
	credential := issued.Key.KeyID + "." + issued.Secret
	query := url.Values{
		"from": {now.Add(-time.Hour).Format(time.RFC3339)},
		"to":   {now.Add(time.Hour).Format(time.RFC3339)},
	}.Encode()
	for _, authorization := range []string{"Bearer " + readerAuth.AccessToken, "CdncaKey " + credential} {
		response := analyticsLogsSharedRequest(t, client, server.URL+"/v1/analytics/logs/access?"+query, authorization)
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			t.Fatalf("analytics logs shared query status = %d", response.StatusCode)
		}
		response.Body.Close()
	}
	beforeDuplicate := clickHouseCalls.Load()
	duplicate, err := http.NewRequest(http.MethodGet, server.URL+"/v1/analytics/logs/access?"+query, nil)
	if err != nil {
		t.Fatal(err)
	}
	duplicate.Header.Add("Authorization", "Bearer "+readerAuth.AccessToken)
	duplicate.Header.Add("Authorization", "Bearer duplicate")
	duplicateResponse, err := client.Do(duplicate)
	if err != nil {
		t.Fatal(err)
	}
	duplicateResponse.Body.Close()
	if duplicateResponse.StatusCode != http.StatusUnauthorized || clickHouseCalls.Load() != beforeDuplicate {
		t.Fatalf("duplicate Authorization status=%d ClickHouse before=%d after=%d",
			duplicateResponse.StatusCode, beforeDuplicate, clickHouseCalls.Load())
	}
	beforeRevocation := clickHouseCalls.Load()
	analyticsRole, err = rbacService.PublishRevision(t.Context(), rbacActor, rbacmanager.PublishRevisionRequest{
		RoleID: analyticsRole.ID, ExpectedRevision: analyticsRole.CurrentRevision,
		Permissions: []string{"api_keys.self.manage", "sites.manage"},
		Mutation:    mutation("analytics-logs-role-revoke-read"),
	})
	if err != nil || analyticsRole.CurrentRevision != 2 {
		t.Fatalf("publish analytics logs role revocation = (%#v, %v)", analyticsRole, err)
	}
	for _, authorization := range []string{"Bearer " + readerAuth.AccessToken, "CdncaKey " + credential} {
		response := analyticsLogsSharedRequest(t, client, server.URL+"/v1/analytics/logs/access?"+query, authorization)
		if response.StatusCode != http.StatusForbidden {
			response.Body.Close()
			t.Fatalf("revoked analytics logs query status = %d, want 403", response.StatusCode)
		}
		response.Body.Close()
	}
	if calls := clickHouseCalls.Load(); calls != beforeRevocation {
		t.Fatalf("revoked analytics logs requests reached ClickHouse: before=%d after=%d", beforeRevocation, calls)
	}
	clickHouse.Close()
	ready, err := client.Get(server.URL + "/health/ready")
	if err != nil {
		t.Fatal(err)
	}
	defer ready.Body.Close()
	if ready.StatusCode != http.StatusOK {
		t.Fatalf("readiness after ClickHouse shutdown status = %d", ready.StatusCode)
	}
}

type analyticsLogsStepUpVerifier struct{}

func (analyticsLogsStepUpVerifier) VerifyAndConsume(
	_ context.Context,
	tx pgx.Tx,
	proof rbacmanager.StepUpProof,
	check rbacmanager.StepUpCheck,
) (rbacmanager.StepUpEvidence, error) {
	if tx == nil || proof.Token != "analytics-logs-step-up" || check.Audience != "custom-rbac" ||
		check.Actor.SessionID == uuid.Nil || check.RequestID == "" || check.TraceID == "" {
		return rbacmanager.StepUpEvidence{}, rbacmanager.ErrStepUpRequired
	}
	return rbacmanager.StepUpEvidence{ProofID: uuid.New(), Method: "totp", VerifiedAt: time.Now().UTC()}, nil
}

type analyticsLogsMountNilHandler struct{}

func (*analyticsLogsMountNilHandler) ServeHTTP(http.ResponseWriter, *http.Request) {}

type analyticsLogsMountNilHandlerFunc func(http.ResponseWriter, *http.Request)

func (handler analyticsLogsMountNilHandlerFunc) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	handler(writer, request)
}

type analyticsLogsMountObservation struct {
	authorization       string
	authorizationValues []string
	requestID           string
}

type analyticsLogsMountProbe struct {
	mu           sync.Mutex
	observations []analyticsLogsMountObservation
}

func (probe *analyticsLogsMountProbe) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	probe.mu.Lock()
	probe.observations = append(probe.observations, analyticsLogsMountObservation{
		authorization:       request.Header.Get("Authorization"),
		authorizationValues: append([]string(nil), request.Header.Values("Authorization")...),
		requestID:           request.Header.Get("X-Request-ID"),
	})
	probe.mu.Unlock()
	writer.WriteHeader(http.StatusNoContent)
}

func (probe *analyticsLogsMountProbe) count() int {
	probe.mu.Lock()
	defer probe.mu.Unlock()
	return len(probe.observations)
}

func (probe *analyticsLogsMountProbe) snapshot() []analyticsLogsMountObservation {
	probe.mu.Lock()
	defer probe.mu.Unlock()
	return append([]analyticsLogsMountObservation(nil), probe.observations...)
}

func analyticsLogsSharedRequest(t *testing.T, client *http.Client, rawURL, authorization string) *http.Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), analyticsLogsRequestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", authorization)
	request.Header.Set("X-Request-ID", "analytics-logs-shared")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func analyticsLogsIsolatedTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	setupCtx, setupCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer setupCancel()
	adminPool, err := pgxpool.New(setupCtx, databaseURL)
	if err != nil {
		t.Fatalf("open analytics logs test administration pool: %v", err)
	}
	schema := "analytics_logs_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^analytics_logs_test_[a-f0-9]{32}$`).MatchString(schema) {
		adminPool.Close()
		t.Fatalf("refusing unexpected analytics logs test schema name %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := adminPool.Exec(setupCtx, "CREATE SCHEMA "+identifier); err != nil {
		adminPool.Close()
		t.Fatalf("create analytics logs test schema: %v", err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		_, _ = adminPool.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		adminPool.Close()
		t.Fatalf("parse analytics logs test database URL: %v", err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(setupCtx, config)
	if err != nil {
		_, _ = adminPool.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		adminPool.Close()
		t.Fatalf("open analytics logs test pool: %v", err)
	}
	migrationCtx, migrationCancel := context.WithTimeout(context.Background(), analyticsLogsMigrationTimeout)
	defer migrationCancel()
	if err := database.Migrate(migrationCtx, pool, "up"); err != nil {
		pool.Close()
		_, _ = adminPool.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		adminPool.Close()
		t.Fatalf("migrate analytics logs test schema: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		if _, err := adminPool.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop analytics logs test schema: %v", err)
		}
		adminPool.Close()
	})
	return pool
}
