//go:build integration

package analyticslog

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikey"
	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type analyticsLogClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *analyticsLogClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *analyticsLogClock) Set(now time.Time) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.now = now
}

type analyticsLogAuthorizationFixture struct {
	pool              *pgxpool.Pool
	identity          *identity.Service
	apiKeys           *apikey.Service
	iam               *iamlock.Authorizer
	clock             *analyticsLogClock
	tenantA           uuid.UUID
	tenantB           uuid.UUID
	tenantScope       uuid.UUID
	tenantUser        uuid.UUID
	tenantRole        uuid.UUID
	tenantPrincipal   identity.Principal
	tenantToken       string
	platformRole      uuid.UUID
	platformToken     string
	activeKey         apikey.IssuedKey
	activeCredential  string
	queryWindow       url.Values
	clickHouseCalls   atomic.Int64
	clickHouseTenants chan string
}

type analyticsAuthenticationBarrier struct {
	inner       AuthenticatePrincipalFunc
	arrived     chan struct{}
	release     chan struct{}
	releaseOnce sync.Once
}

func (barrier *analyticsAuthenticationBarrier) Authenticate(request *http.Request) (Principal, error) {
	principal, err := barrier.inner(request)
	if err != nil {
		return Principal{}, err
	}
	select {
	case barrier.arrived <- struct{}{}:
	case <-request.Context().Done():
		return Principal{}, request.Context().Err()
	}
	select {
	case <-barrier.release:
		return principal, nil
	case <-request.Context().Done():
		return Principal{}, request.Context().Err()
	}
}

func (barrier *analyticsAuthenticationBarrier) releaseRequests() {
	barrier.releaseOnce.Do(func() { close(barrier.release) })
}

type analyticsAuthorizationFacts struct {
	audits, sessions, revokedSessions, apiKeys, apiKeyRevisions, apiKeyWrites int64
	roleAssignments, rolePermissions, clickHouse                              int64
}

func TestProductionEightRouteCredentialContractWithPostgres17(t *testing.T) {
	fixture := newAnalyticsLogAuthorizationFixture(t)
	handler := fixture.newHandler(t, fixture.pool, fixture.iam)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	tenantQuery := cloneValues(fixture.queryWindow)
	platformQuery := cloneValues(fixture.queryWindow)
	platformQuery.Set("tenant_id", fixture.tenantB.String())
	routes := []struct {
		name          string
		path          string
		query         url.Values
		authorization string
		status        int
		code          string
		tenant        uuid.UUID
	}{
		{name: "tenant_access", path: "/v1/analytics/logs/access", query: tenantQuery,
			authorization: "CdncaKey " + fixture.activeCredential, status: http.StatusOK, tenant: fixture.tenantA},
		{name: "platform_access", path: "/v1/admin/analytics/logs/access", query: platformQuery,
			authorization: "Bearer " + fixture.platformToken, status: http.StatusOK, tenant: fixture.tenantB},
		// Block events query ClickHouse's security events; current/history
		// blocks are served from PostgreSQL by BlockStateHandler.
		{name: "tenant_block_events", path: "/v1/analytics/logs/block-events", query: tenantQuery,
			authorization: "CdncaKey " + fixture.activeCredential, status: http.StatusOK, tenant: fixture.tenantA},
		{name: "platform_block_events", path: "/v1/admin/analytics/logs/block-events", query: platformQuery,
			authorization: "Bearer " + fixture.platformToken, status: http.StatusOK, tenant: fixture.tenantB},
		{name: "tenant_current", path: "/v1/analytics/logs/blocks/current", query: url.Values{},
			authorization: "CdncaKey " + fixture.activeCredential, status: http.StatusOK},
		{name: "platform_current", path: "/v1/admin/analytics/logs/blocks/current",
			query:         url.Values{"tenant_id": {fixture.tenantB.String()}},
			authorization: "Bearer " + fixture.platformToken, status: http.StatusOK},
		{name: "tenant_history", path: "/v1/analytics/logs/blocks/history", query: url.Values{},
			authorization: "CdncaKey " + fixture.activeCredential, status: http.StatusOK},
		{name: "platform_history", path: "/v1/admin/analytics/logs/blocks/history",
			query:         url.Values{"tenant_id": {fixture.tenantB.String()}},
			authorization: "Bearer " + fixture.platformToken, status: http.StatusOK},
	}
	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			response := fixture.request(t, server.URL, route.path, route.query, route.authorization)
			assertProductionResponse(t, response, route.status, route.code)
			if route.tenant != uuid.Nil {
				if tenant := <-fixture.clickHouseTenants; tenant != route.tenant.String() {
					t.Fatalf("ClickHouse tenant = %q, want %s", tenant, route.tenant)
				}
			}
		})
	}
	if calls := fixture.clickHouseCalls.Load(); calls != 4 {
		t.Fatalf("eight routes made %d ClickHouse calls, want 4 (access and block events)", calls)
	}

	response := fixture.request(t, server.URL, "/v1/analytics/logs/access", fixture.queryWindow,
		"Bearer "+fixture.tenantToken)
	assertProductionResponse(t, response, http.StatusOK, "")
	if tenant := <-fixture.clickHouseTenants; tenant != fixture.tenantA.String() {
		t.Fatalf("tenant Bearer ClickHouse scope = %q", tenant)
	}

	before := fixture.clickHouseCalls.Load()
	response = fixture.request(t, server.URL, "/v1/admin/analytics/logs/access", platformQuery,
		"CdncaKey "+fixture.activeCredential)
	assertProductionResponse(t, response, http.StatusUnauthorized, "analytics_logs_authentication_required")
	response = fixture.request(t, server.URL, "/v1/analytics/logs/access/neighbor", tenantQuery,
		"Bearer "+fixture.tenantToken)
	assertProductionResponse(t, response, http.StatusNotFound, "analytics_logs_route_not_found")
	if fixture.clickHouseCalls.Load() != before {
		t.Fatal("platform API key or neighboring path reached ClickHouse")
	}
}

func TestProductionAPIKeyLifecycleScopeAndTenantBindingWithPostgres17(t *testing.T) {
	fixture := newAnalyticsLogAuthorizationFixture(t)
	handler := fixture.newHandler(t, fixture.pool, fixture.iam)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	before := fixture.clickHouseCalls.Load()
	for _, authorization := range []string{"", "Basic credential", "Bearer not-a-session", "CdncaKey invalid"} {
		response := fixture.request(t, server.URL, "/v1/analytics/logs/access", fixture.queryWindow, authorization)
		assertProductionResponse(t, response, http.StatusUnauthorized, "analytics_logs_authentication_required")
	}
	if fixture.clickHouseCalls.Load() != before {
		t.Fatal("invalid credentials reached ClickHouse")
	}

	limited := fixture.issueKey(t, "analytics sites manage only", []string{"sites.manage"}, 24*time.Hour)
	response := fixture.request(t, server.URL, "/v1/analytics/logs/access", fixture.queryWindow,
		"CdncaKey "+rawAPIKey(limited))
	assertProductionResponse(t, response, http.StatusForbidden, "analytics_logs_permission_denied")

	crossTenant := cloneValues(fixture.queryWindow)
	crossTenant.Set("tenant_id", fixture.tenantB.String())
	for _, authorization := range []string{
		"Bearer " + fixture.tenantToken,
		"CdncaKey " + fixture.activeCredential,
	} {
		response = fixture.request(t, server.URL, "/v1/analytics/logs/access", crossTenant, authorization)
		assertProductionResponse(t, response, http.StatusForbidden, "analytics_logs_scope_forbidden")
	}

	revoked := fixture.issueKey(t, "analytics revoked", []string{ReadPermission}, 24*time.Hour)
	if _, err := fixture.apiKeys.RevokeSelf(t.Context(), fixture.tenantPrincipal, apikey.MutationInput{
		ID: revoked.Key.ID, ExpectedRevision: revoked.Key.Revision,
		IdempotencyKey: "analytics-revoke-" + uuid.NewString(), RequestID: "analytics-revoke",
	}); err != nil {
		t.Fatal(err)
	}
	response = fixture.request(t, server.URL, "/v1/analytics/logs/access", fixture.queryWindow,
		"CdncaKey "+rawAPIKey(revoked))
	assertProductionResponse(t, response, http.StatusUnauthorized, "analytics_logs_authentication_required")

	expired := fixture.issueKey(t, "analytics expired", []string{ReadPermission}, time.Hour)
	fixture.clock.Set(fixture.clock.Now().Add(2 * time.Hour))
	response = fixture.request(t, server.URL, "/v1/analytics/logs/access", fixture.queryWindow,
		"CdncaKey "+rawAPIKey(expired))
	assertProductionResponse(t, response, http.StatusUnauthorized, "analytics_logs_authentication_required")
	fixture.clock.Set(fixture.clock.Now().Add(-2 * time.Hour))

	if fixture.clickHouseCalls.Load() != before {
		t.Fatalf("denied API key requests reached ClickHouse: before=%d after=%d",
			before, fixture.clickHouseCalls.Load())
	}
}

func TestProductionLiveAuthorizationAndDependencyFailureWithPostgres17(t *testing.T) {
	fixture := newAnalyticsLogAuthorizationFixture(t)
	handler := fixture.newHandler(t, fixture.pool, fixture.iam)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	response := fixture.request(t, server.URL, "/v1/analytics/logs/access", fixture.queryWindow,
		"Bearer "+fixture.tenantToken)
	assertProductionResponse(t, response, http.StatusOK, "")
	<-fixture.clickHouseTenants
	before := fixture.clickHouseCalls.Load()

	if _, err := fixture.pool.Exec(t.Context(), `DELETE FROM role_assignments
		WHERE scope_id=$1 AND user_id=$2 AND role_id=$3`,
		fixture.tenantScope, fixture.tenantUser, fixture.tenantRole); err != nil {
		t.Fatal(err)
	}
	response = fixture.request(t, server.URL, "/v1/analytics/logs/access", fixture.queryWindow,
		"Bearer "+fixture.tenantToken)
	assertProductionResponse(t, response, http.StatusForbidden, "analytics_logs_permission_denied")
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id)
		VALUES($1,$2,$3)`, fixture.tenantScope, fixture.tenantUser, fixture.tenantRole); err != nil {
		t.Fatal(err)
	}

	if _, err := fixture.apiKeys.RevokeSelf(t.Context(), fixture.tenantPrincipal, apikey.MutationInput{
		ID: fixture.activeKey.Key.ID, ExpectedRevision: fixture.activeKey.Key.Revision,
		IdempotencyKey: "analytics-live-revoke-" + uuid.NewString(), RequestID: "analytics-live-revoke",
	}); err != nil {
		t.Fatal(err)
	}
	response = fixture.request(t, server.URL, "/v1/analytics/logs/access", fixture.queryWindow,
		"CdncaKey "+fixture.activeCredential)
	assertProductionResponse(t, response, http.StatusUnauthorized, "analytics_logs_authentication_required")

	platformQuery := cloneValues(fixture.queryWindow)
	platformQuery.Set("tenant_id", fixture.tenantB.String())
	if _, err := fixture.pool.Exec(t.Context(), `DELETE FROM role_permissions
		WHERE role_id=$1 AND permission_name='platform.admin'`, fixture.platformRole); err != nil {
		t.Fatal(err)
	}
	response = fixture.request(t, server.URL, "/v1/admin/analytics/logs/access", platformQuery,
		"Bearer "+fixture.platformToken)
	assertProductionResponse(t, response, http.StatusForbidden, "analytics_logs_permission_denied")
	if fixture.clickHouseCalls.Load() != before {
		t.Fatal("revoked authorization reached ClickHouse")
	}

	config := fixture.pool.Config().Copy()
	closedPool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	closedHandler := fixture.newHandler(t, closedPool, fixture.iam)
	closedPool.Close()
	request := httptest.NewRequest(http.MethodGet,
		"/v1/analytics/logs/access?"+fixture.queryWindow.Encode(), nil)
	request.Header.Set("Authorization", "Bearer "+fixture.tenantToken)
	recorder := httptest.NewRecorder()
	closedHandler.ServeHTTP(recorder, request)
	assertHandlerError(t, recorder, http.StatusServiceUnavailable, "analytics_logs_storage_unavailable")
	if fixture.clickHouseCalls.Load() != before {
		t.Fatal("unavailable authorization dependency reached ClickHouse")
	}
}

func TestProductionPostAuthenticationRevocationRechecksIAMWithPostgres17(t *testing.T) {
	for _, test := range []struct {
		name          string
		authorization func(*analyticsLogAuthorizationFixture) string
	}{
		{name: "session", authorization: func(fixture *analyticsLogAuthorizationFixture) string {
			return "Bearer " + fixture.tenantToken
		}},
		{name: "api_key", authorization: func(fixture *analyticsLogAuthorizationFixture) string {
			return "CdncaKey " + fixture.activeCredential
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newAnalyticsLogAuthorizationFixture(t)
			requestPool, applicationName := newAnalyticsBoundedPool(t, fixture.pool, 4)
			tokens, err := identity.NewTokenManager(strings.Repeat("analyticslog-test-secret-", 2), 24*time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			identityService, err := identity.NewService(identity.NewStore(requestPool), tokens, 24*time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			apiKeyService := apikey.NewService(requestPool, bytes.Repeat([]byte{7}, 32), fixture.clock.Now)
			clickHouse := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				fixture.clickHouseCalls.Add(1)
			}))
			t.Cleanup(clickHouse.Close)
			handler, err := NewHTTPHandler(HTTPConfig{
				Client: ClientConfig{
					Endpoint: clickHouse.URL, Database: "analyticslog_post_authentication_revoke",
					QueryTimeout: time.Second, MaxResponseBytes: 1 << 20, CursorKeyring: testLogCursorKeyring(),
				},
				Handler: HandlerConfig{
					QueryTimeout: 2 * time.Second, MaxResponseBytes: 1 << 20,
					Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
				},
			}, HTTPDependencies{
				Identity: identityService, APIKeys: apiKeyService, Pool: requestPool, IAM: fixture.iam,
			})
			if err != nil {
				t.Fatal(err)
			}

			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			blocker, err := fixture.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = blocker.Rollback(context.Background()) }()
			if err := iamlock.AcquireExclusive(ctx, blocker); err != nil {
				t.Fatal(err)
			}
			response := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				request := httptest.NewRequestWithContext(ctx, http.MethodGet,
					"/v1/analytics/logs/access?"+fixture.queryWindow.Encode(), nil)
				request.Header.Set("Authorization", test.authorization(fixture))
				recorder := httptest.NewRecorder()
				handler.ServeHTTP(recorder, request)
				response <- recorder
			}()

			waitForAnalyticsIAMWaiters(t, ctx, fixture.pool, applicationName, 1)
			if _, err := blocker.Exec(ctx, `DELETE FROM role_assignments
				WHERE scope_id=$1 AND user_id=$2 AND role_id=$3`,
				fixture.tenantScope, fixture.tenantUser, fixture.tenantRole); err != nil {
				t.Fatal(err)
			}
			if err := blocker.Commit(ctx); err != nil {
				t.Fatal(err)
			}

			select {
			case recorder := <-response:
				assertHandlerError(t, recorder, http.StatusForbidden, "analytics_logs_permission_denied")
			case <-ctx.Done():
				t.Fatalf("revoked %s request did not complete: %v", test.name, ctx.Err())
			}
			if calls := fixture.clickHouseCalls.Load(); calls != 0 {
				t.Fatalf("revoked %s request reached ClickHouse %d times", test.name, calls)
			}
		})
	}
}

func TestProductionIAMRejectionDoesNotStarveBoundedPool(t *testing.T) {
	const concurrentRequests = 4
	tests := []struct {
		name              string
		invalidCredential bool
		limitedAPIKey     bool
		revokeSession     bool
		wantStatus        int
		wantCode          string
	}{
		{name: "invalid credential", invalidCredential: true,
			wantStatus: http.StatusUnauthorized, wantCode: "analytics_logs_authentication_required"},
		{name: "valid without permission", limitedAPIKey: true,
			wantStatus: http.StatusForbidden, wantCode: "analytics_logs_permission_denied"},
		{name: "formally revoked session", revokeSession: true,
			wantStatus: http.StatusUnauthorized, wantCode: "analytics_logs_authentication_required"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newAnalyticsLogAuthorizationFixture(t)
			requestPool, applicationName := newAnalyticsBoundedPool(t, fixture.pool, concurrentRequests)
			tokens, err := identity.NewTokenManager(strings.Repeat("analyticslog-test-secret-", 2), 24*time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			identityService, err := identity.NewService(identity.NewStore(requestPool), tokens, 24*time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			apiKeyService := apikey.NewService(requestPool, bytes.Repeat([]byte{7}, 32), fixture.clock.Now)
			authenticate := credentialAuthenticator(identityService, apiKeyService)
			authorizationHeader := "Bearer " + fixture.tenantToken
			if test.invalidCredential {
				session, err := identityService.AuthenticateSession(t.Context(), fixture.tenantToken)
				if err != nil {
					t.Fatal(err)
				}
				// A correctly signed token naming no session: CredentialScope accepts
				// it, so the rejection comes from the IAM-locked session preflight
				// (a malformed token is refused before any lock and never waits).
				unknownSession, _, err := tokens.Mint(fixture.tenantUser, fixture.tenantScope, uuid.New())
				if err != nil {
					t.Fatal(err)
				}
				principal := authenticatedPrincipal(session.Principal, credentialSession,
					unknownSession, session.SessionID)
				authenticate = func(*http.Request) (Principal, error) { return principal, nil }
				authorizationHeader = "Bearer " + unknownSession
			}
			if test.limitedAPIKey {
				limited := fixture.issueKey(t, "analytics pool starvation limited", []string{"sites.manage"}, 24*time.Hour)
				authorizationHeader = "CdncaKey " + rawAPIKey(limited)
			}

			barrier := &analyticsAuthenticationBarrier{
				inner: authenticate, arrived: make(chan struct{}, concurrentRequests), release: make(chan struct{}),
			}
			defer barrier.releaseRequests()
			handler := fixture.newPoolStarvationHandler(
				t, requestPool, identityService, apiKeyService, barrier.Authenticate)
			requestCtx, cancelRequests := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancelRequests()
			start := make(chan struct{})
			results := make(chan *httptest.ResponseRecorder, concurrentRequests)
			for index := 0; index < concurrentRequests; index++ {
				go func() {
					<-start
					request := httptest.NewRequestWithContext(requestCtx, http.MethodGet,
						"/v1/analytics/logs/access?"+fixture.queryWindow.Encode(), nil)
					request.Header.Set("Authorization", authorizationHeader)
					response := httptest.NewRecorder()
					handler.ServeHTTP(response, request)
					results <- response
				}()
			}
			close(start)
			for index := 0; index < concurrentRequests; index++ {
				select {
				case <-barrier.arrived:
				case <-requestCtx.Done():
					t.Fatalf("requests did not finish HTTP authentication outside transactions: %v", requestCtx.Err())
				}
			}

			if test.revokeSession {
				_, _, sessionID, err := tokens.Parse(fixture.tenantToken)
				if err != nil {
					t.Fatal(err)
				}
				var refreshHash []byte
				if err := fixture.pool.QueryRow(requestCtx,
					`SELECT refresh_token_hash FROM auth_sessions WHERE id=$1`, sessionID).Scan(&refreshHash); err != nil {
					t.Fatal(err)
				}
				if err := identity.NewStore(fixture.pool).RevokeSessionFamily(
					requestCtx, refreshHash, "analytics-pool-starvation-revoke"); err != nil {
					t.Fatal(err)
				}
			}
			before := readAnalyticsAuthorizationFacts(t, fixture)
			blocker, err := fixture.pool.Begin(requestCtx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = blocker.Rollback(context.Background()) }()
			if err := iamlock.AcquireExclusive(requestCtx, blocker); err != nil {
				t.Fatal(err)
			}
			barrier.releaseRequests()
			waitForAnalyticsIAMWaiters(t, requestCtx, fixture.pool, applicationName, concurrentRequests)
			if acquired := requestPool.Stat().AcquiredConns(); acquired != concurrentRequests {
				t.Fatalf("acquired business connections=%d want=%d", acquired, concurrentRequests)
			}
			if err := blocker.Rollback(requestCtx); err != nil {
				t.Fatal(err)
			}

			for index := 0; index < concurrentRequests; index++ {
				select {
				case response := <-results:
					assertHandlerError(t, response, test.wantStatus, test.wantCode)
				case <-requestCtx.Done():
					t.Fatalf("request %d exceeded bounded completion deadline: %v", index, requestCtx.Err())
				}
			}
			if acquired := requestPool.Stat().AcquiredConns(); acquired != 0 {
				t.Fatalf("acquired connections after rejection=%d want=0", acquired)
			}
			assertAnalyticsAuthorizationFacts(t, fixture, before)
		})
	}
}

func newAnalyticsLogAuthorizationFixture(t *testing.T) *analyticsLogAuthorizationFixture {
	t.Helper()
	pool := isolatedAnalyticsLogPool(t)
	baseNow := time.Now().UTC().Truncate(time.Millisecond)
	fixture := &analyticsLogAuthorizationFixture{
		pool: pool, clock: &analyticsLogClock{now: baseNow}, tenantA: uuid.New(), tenantB: uuid.New(),
		tenantScope: uuid.New(), tenantUser: uuid.New(), tenantRole: uuid.New(), platformRole: uuid.New(),
		queryWindow:       queryValues(baseNow.Add(-time.Hour), baseNow.Add(time.Minute)),
		clickHouseTenants: make(chan string, 16),
	}
	tenantBScope, platformScope, platformUser := uuid.New(), uuid.New(), uuid.New()
	tenantSession, platformSession := uuid.New(), uuid.New()

	for _, tenant := range []struct {
		id   uuid.UUID
		name string
	}{{fixture.tenantA, "Analytics Tenant A"}, {fixture.tenantB, "Analytics Tenant B"}} {
		if _, err := pool.Exec(t.Context(), `INSERT INTO tenants(id,display_name) VALUES($1,$2)`,
			tenant.id, tenant.name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind,tenant_id)
		VALUES($1,'tenant',$2),($3,'tenant',$4)`,
		fixture.tenantScope, fixture.tenantA, tenantBScope, fixture.tenantB); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`,
		platformScope); err != nil {
		t.Fatal(err)
	}
	for _, user := range []struct {
		id       uuid.UUID
		scopeID  uuid.UUID
		username string
	}{{fixture.tenantUser, fixture.tenantScope, "analyticslog-tenant"},
		{platformUser, platformScope, "analyticslog-platform"}} {
		if _, err := pool.Exec(t.Context(), `INSERT INTO users(id,username,display_name,password_hash)
			VALUES($1,$2,$2,'test-only-hash')`, user.id, user.username); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`,
			user.scopeID, user.id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO roles(id,scope_id,name,system_role)
		VALUES($1,$2,'tenant_owner',true),($3,$4,'platform_owner',true)`,
		fixture.tenantRole, fixture.tenantScope, fixture.platformRole, platformScope); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO role_permissions(role_id,permission_name)
		VALUES($1,'sites.read'),($1,'sites.manage'),($1,'api_keys.self.manage'),($2,'platform.admin')`,
		fixture.tenantRole, fixture.platformRole); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id)
		VALUES($1,$2,$3),($4,$5,$6)`, fixture.tenantScope, fixture.tenantUser, fixture.tenantRole,
		platformScope, platformUser, fixture.platformRole); err != nil {
		t.Fatal(err)
	}
	for index, session := range []struct {
		id, userID, scopeID uuid.UUID
	}{{tenantSession, fixture.tenantUser, fixture.tenantScope}, {platformSession, platformUser, platformScope}} {
		hash := bytes.Repeat([]byte{byte(index + 1)}, 32)
		if _, err := pool.Exec(t.Context(), `INSERT INTO auth_sessions(
			id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
		) VALUES($1,$2,$3,$4,$5,$6,$7)`, session.id, uuid.New(), session.userID, session.scopeID,
			hash, baseNow.Add(-time.Hour), baseNow.Add(24*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}

	tokens, err := identity.NewTokenManager(strings.Repeat("analyticslog-test-secret-", 2), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	fixture.identity, err = identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pepper := bytes.Repeat([]byte{7}, 32)
	fixture.apiKeys = apikey.NewService(pool, pepper, fixture.clock.Now)
	sessions, err := sessioncredential.NewVerifier(tokens, fixture.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	apiKeyVerifier, err := apikeycredential.NewVerifier(pepper, fixture.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	fixture.iam, err = iamlock.NewAuthorizer(sessions, apiKeyVerifier)
	if err != nil {
		t.Fatal(err)
	}
	fixture.tenantToken, _, err = tokens.Mint(fixture.tenantUser, fixture.tenantScope, tenantSession)
	if err != nil {
		t.Fatal(err)
	}
	fixture.platformToken, _, err = tokens.Mint(platformUser, platformScope, platformSession)
	if err != nil {
		t.Fatal(err)
	}
	authenticated, err := fixture.identity.AuthenticateSession(t.Context(), fixture.tenantToken)
	if err != nil {
		t.Fatal(err)
	}
	fixture.tenantPrincipal = authenticated.Principal
	fixture.activeKey = fixture.issueKey(t, "analytics active", []string{ReadPermission}, 24*time.Hour)
	fixture.activeCredential = rawAPIKey(fixture.activeKey)
	return fixture
}

func (fixture *analyticsLogAuthorizationFixture) issueKey(
	t *testing.T,
	name string,
	scopes []string,
	ttl time.Duration,
) apikey.IssuedKey {
	t.Helper()
	expiresAt := fixture.clock.Now().Add(ttl)
	issued, err := fixture.apiKeys.CreateSelf(t.Context(), fixture.tenantPrincipal, apikey.CreateInput{
		Name: name, Scopes: scopes, ExpiresAt: &expiresAt,
		IdempotencyKey: "analytics-create-" + uuid.NewString(), RequestID: "analytics-create",
	})
	if err != nil {
		t.Fatal(err)
	}
	return issued
}

func rawAPIKey(issued apikey.IssuedKey) string {
	return issued.Key.KeyID + "." + issued.Secret
}

func (fixture *analyticsLogAuthorizationFixture) newHandler(
	t *testing.T,
	pool *pgxpool.Pool,
	authorizer *iamlock.Authorizer,
) http.Handler {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Millisecond)
	clickHouse := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		fixture.clickHouseCalls.Add(1)
		fixture.clickHouseTenants <- request.URL.Query().Get("param_tenant_id")
		query, _ := io.ReadAll(request.Body)
		if strings.Contains(string(query), "FROM security_event_query_index_state_v1") {
			return // no security events: an empty block-event page
		}
		_ = json.NewEncoder(writer).Encode(accessTestRow("production-event", now.Add(-time.Minute), "/asset.js"))
	}))
	t.Cleanup(clickHouse.Close)
	handler, err := NewHTTPHandler(HTTPConfig{
		Client: ClientConfig{
			Endpoint: clickHouse.URL, Database: "analyticslog_authorization", QueryTimeout: time.Second,
			MaxResponseBytes: 1 << 20, CursorKeyring: testLogCursorKeyring(),
		},
		Handler: HandlerConfig{
			QueryTimeout: 2 * time.Second, MaxResponseBytes: 1 << 20,
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
	}, HTTPDependencies{Identity: fixture.identity, APIKeys: fixture.apiKeys, Pool: pool, IAM: authorizer})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func (fixture *analyticsLogAuthorizationFixture) newPoolStarvationHandler(
	t *testing.T,
	pool *pgxpool.Pool,
	identityService *identity.Service,
	apiKeyService *apikey.Service,
	authenticate AuthenticatePrincipalFunc,
) http.Handler {
	t.Helper()
	clickHouse := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		fixture.clickHouseCalls.Add(1)
	}))
	t.Cleanup(clickHouse.Close)
	handler, err := newHTTPHandler(HTTPConfig{
		Client: ClientConfig{
			Endpoint: clickHouse.URL, Database: "analyticslog_pool_starvation",
			QueryTimeout: 250 * time.Millisecond, MaxResponseBytes: 1 << 20, CursorKeyring: testLogCursorKeyring(),
		},
		Handler: HandlerConfig{
			QueryTimeout: time.Second, MaxResponseBytes: 1 << 20,
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
	}, handlerDependencies{
		Authenticate: authenticate,
		Authorizer: &iamAuthorizer{
			pool: pool, authorizer: fixture.iam, identity: identityService, apiKeys: apiKeyService,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func newAnalyticsBoundedPool(
	t *testing.T,
	source *pgxpool.Pool,
	maxConns int32,
) (*pgxpool.Pool, string) {
	t.Helper()
	applicationName := "analytics_pool_starvation_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	config := source.Config().Copy()
	config.ConnConfig.RuntimeParams["application_name"] = applicationName
	config.MaxConns = maxConns
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool, applicationName
}

func waitForAnalyticsIAMWaiters(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	applicationName string,
	want int,
) {
	t.Helper()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting int
		if err := pool.QueryRow(ctx, `SELECT count(*)
			FROM pg_catalog.pg_locks lock
			JOIN pg_catalog.pg_stat_activity activity ON activity.pid=lock.pid
			WHERE activity.application_name=$1 AND lock.locktype='advisory'
			  AND lock.classid=1229016321::oid AND lock.objid=1::oid AND lock.objsubid=2
			  AND lock.mode='ShareLock' AND NOT lock.granted`, applicationName).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting == want {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("IAM waiters=%d want=%d: %v", waiting, want, ctx.Err())
		case <-ticker.C:
		}
	}
}

func readAnalyticsAuthorizationFacts(
	t *testing.T,
	fixture *analyticsLogAuthorizationFixture,
) analyticsAuthorizationFacts {
	t.Helper()
	facts := analyticsAuthorizationFacts{clickHouse: fixture.clickHouseCalls.Load()}
	if err := fixture.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM audit_events),
		(SELECT count(*) FROM auth_sessions),
		(SELECT count(*) FROM auth_sessions WHERE revoked_at IS NOT NULL),
		(SELECT count(*) FROM api_keys),
		(SELECT COALESCE(sum(revision),0) FROM api_keys),
		(SELECT count(*) FROM api_key_write_requests),
		(SELECT count(*) FROM role_assignments),
		(SELECT count(*) FROM role_permissions)`).Scan(
		&facts.audits, &facts.sessions, &facts.revokedSessions, &facts.apiKeys,
		&facts.apiKeyRevisions, &facts.apiKeyWrites, &facts.roleAssignments, &facts.rolePermissions,
	); err != nil {
		t.Fatal(err)
	}
	return facts
}

func assertAnalyticsAuthorizationFacts(
	t *testing.T,
	fixture *analyticsLogAuthorizationFixture,
	want analyticsAuthorizationFacts,
) {
	t.Helper()
	if got := readAnalyticsAuthorizationFacts(t, fixture); got != want {
		t.Fatalf("analytics authorization facts=%+v want=%+v", got, want)
	}
}

func (fixture *analyticsLogAuthorizationFixture) request(
	t *testing.T,
	baseURL string,
	path string,
	query url.Values,
	authorization string,
) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, baseURL+path+"?"+query.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func isolatedAnalyticsLogPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	var version string
	if err := admin.QueryRow(ctx, "SHOW server_version_num").Scan(&version); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	// 只钉大版本 17：小版本是同大版本的补丁发布，不改变本测试依赖的 RLS/角色语义；
	// 钉死 170005 会让 17.x 补丁升级（本机 17.9）误报失败。
	if len(version) != 6 || !strings.HasPrefix(version, "17") {
		admin.Close()
		t.Fatalf("PostgreSQL server_version_num = %s, want major version 17", version)
	}
	schema := "analyticslog_rbac_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^analyticslog_rbac_[a-f0-9]{32}$`).MatchString(schema) {
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
	// Replaying every migration takes far longer than the 30 s setup budget
	// under load; give it the 10 min databasetest.FreshSchemaPool uses.
	migrateCtx, migrateCancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer migrateCancel()
	if err := database.Migrate(migrateCtx, pool, "up"); err != nil {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop analyticslog schema: %v", err)
		}
		admin.Close()
	})
	return pool
}

func assertProductionResponse(t *testing.T, response *http.Response, status int, code string) {
	t.Helper()
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != status {
		t.Fatalf("status=%d want=%d body=%s", response.StatusCode, status, body)
	}
	if code == "" {
		return
	}
	var envelope errorEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Error.Code != code || envelope.Error.RequestID == "" {
		t.Fatalf("error=%#v want code=%q", envelope.Error, code)
	}
	for _, forbidden := range []string{"SELECT", "password", "postgres", "Bearer", "CdncaKey"} {
		if strings.Contains(string(body), forbidden) {
			t.Fatalf("response leaked %q: %s", forbidden, body)
		}
	}
}

func cloneValues(values url.Values) url.Values {
	clone := make(url.Values, len(values))
	for key, items := range values {
		clone[key] = append([]string(nil), items...)
	}
	return clone
}
