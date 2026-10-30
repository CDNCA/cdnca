package analyticsconnectionshttp

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsconnections"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

const (
	testTenantID       = "11111111-1111-4111-8111-111111111111"
	testSubscriptionID = "22222222-2222-4222-8222-222222222222"
)

var testFrom = time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)

type retentionStoreStub struct {
	queries []RetentionStoreQuery
	rows    []analyticsconnections.RetentionRow
	err     error
	wait    bool
}

func (store *retentionStoreStub) QueryRetention(ctx context.Context, query RetentionStoreQuery) ([]analyticsconnections.RetentionRow, error) {
	store.queries = append(store.queries, query)
	if store.wait {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return append([]analyticsconnections.RetentionRow(nil), store.rows...), store.err
}

func TestRetentionHTTPQueriesTenantAndAdminScopes(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		session   identity.AuthenticatedSession
		wantLimit int
	}{
		{
			name: "tenant", path: retentionURL(false, ""),
			session: testSession("tenant", []string{"sites.read"}, true), wantLimit: defaultRetentionLimit + 1,
		},
		{
			name: "admin", path: retentionURL(true, "&tenant_id="+testTenantID+"&limit=7"),
			session: testSession("platform", []string{"platform.admin", "sites.read"}, false), wantLimit: 8,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &retentionStoreStub{rows: []analyticsconnections.RetentionRow{retentionRowFixture(testTenantID)}}
			handler := newTestHandler(t, store, func(*http.Request) (identity.AuthenticatedSession, error) {
				return test.session, nil
			}, HandlerConfig{})
			request := httptest.NewRequest(http.MethodGet, test.path, nil)
			request.Header.Set("X-Request-ID", "retention-request-1")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)

			if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" ||
				response.Header().Get("X-Request-ID") != "retention-request-1" ||
				response.Header().Get("Content-Type") != "application/json" {
				t.Fatalf("response = %d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
			}
			if len(store.queries) != 1 || store.queries[0].TenantID != testTenantID ||
				store.queries[0].SubscriptionID != testSubscriptionID || store.queries[0].Limit != test.wantLimit {
				t.Fatalf("store queries = %#v", store.queries)
			}
			var page RetentionPage
			if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil || len(page.Items) != 1 ||
				page.Items[0].TenantID != testTenantID || page.Items[0].EvidenceDigest == "" {
				t.Fatalf("page = %#v err=%v", page, err)
			}
		})
	}
}

func TestRetentionHTTPAuthenticatesBeforeParsingAndFailsClosed(t *testing.T) {
	store := &retentionStoreStub{}
	handler := newTestHandler(t, store, func(*http.Request) (identity.AuthenticatedSession, error) {
		return identity.AuthenticatedSession{}, errors.New("revoked secret")
	}, HandlerConfig{})
	request := httptest.NewRequest(http.MethodGet,
		"/v1/analytics/connections/retention?subscription_id=bad&tenant_id=forged&from=bad", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assertRetentionError(t, response, http.StatusUnauthorized, "retention_authentication_required")
	if len(store.queries) != 0 || strings.Contains(response.Body.String(), "revoked secret") {
		t.Fatalf("authentication failure leaked or reached store: calls=%d body=%s", len(store.queries), response.Body.String())
	}

	tests := []struct {
		name    string
		path    string
		session identity.AuthenticatedSession
		status  int
		code    string
	}{
		{name: "tenant override", path: retentionURL(false, "&tenant_id="+testTenantID), session: testSession("tenant", []string{"sites.read"}, true), status: 400, code: "retention_invalid_request"},
		{name: "tenant permission", path: retentionURL(false, ""), session: testSession("tenant", nil, true), status: 403, code: "retention_permission_denied"},
		{name: "admin role", path: retentionURL(true, "&tenant_id="+testTenantID), session: testSession("platform", []string{"sites.read"}, false), status: 403, code: "retention_permission_denied"},
		{name: "admin tenant required", path: retentionURL(true, ""), session: testSession("platform", []string{"platform.admin", "sites.read"}, false), status: 400, code: "retention_invalid_request"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &retentionStoreStub{}
			handler := newTestHandler(t, store, func(*http.Request) (identity.AuthenticatedSession, error) { return test.session, nil }, HandlerConfig{})
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, test.path, nil))
			assertRetentionError(t, response, test.status, test.code)
			if len(store.queries) != 0 {
				t.Fatal("rejected scope reached store")
			}
		})
	}
}

func TestRetentionHTTPRejectsAmbiguousOrUnboundedQueriesBeforeStore(t *testing.T) {
	session := testSession("tenant", []string{"sites.read"}, true)
	valid := retentionURL(false, "")
	tests := []struct {
		name, path string
		body       string
	}{
		{name: "unknown", path: valid + "&unknown=1"},
		{name: "duplicate", path: valid + "&limit=1&limit=2"},
		{name: "encoded key", path: strings.Replace(valid, "subscription_id", "subscription%5fid", 1)},
		{name: "subscription", path: strings.Replace(valid, testSubscriptionID, "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", 1)},
		{name: "non UTC", path: strings.Replace(valid, "2026-08-07T00%3A00%3A00Z", "2026-08-07T08%3A00%3A00%2B08%3A00", 1)},
		{name: "reversed", path: strings.Replace(valid, "2026-08-08T00%3A00%3A00Z", "2026-08-06T00%3A00%3A00Z", 1)},
		{name: "window", path: strings.Replace(valid, "2026-08-08T00%3A00%3A00Z", "2026-10-08T00%3A00%3A00Z", 1)},
		{name: "limit", path: valid + "&limit=01"},
		{name: "query bytes", path: valid + "&padding=" + strings.Repeat("x", maximumRetentionQueryBytes)},
		{name: "body", path: valid, body: "not allowed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &retentionStoreStub{}
			handler := newTestHandler(t, store, func(*http.Request) (identity.AuthenticatedSession, error) { return session, nil }, HandlerConfig{})
			request := httptest.NewRequest(http.MethodGet, test.path, strings.NewReader(test.body))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			assertRetentionError(t, response, http.StatusBadRequest, "retention_invalid_request")
			if len(store.queries) != 0 {
				t.Fatal("invalid query reached store")
			}
		})
	}
}

func TestRetentionHTTPTimeoutErrorsAndResponseCapacityAreStable(t *testing.T) {
	session := testSession("tenant", []string{"sites.read"}, true)
	tests := []struct {
		name   string
		store  *retentionStoreStub
		config HandlerConfig
		status int
		code   string
	}{
		{name: "timeout", store: &retentionStoreStub{wait: true}, config: HandlerConfig{QueryTimeout: time.Millisecond}, status: http.StatusRequestTimeout, code: "retention_request_timeout"},
		{name: "store secret", store: &retentionStoreStub{err: errors.New("secret ClickHouse response")}, status: http.StatusServiceUnavailable, code: "retention_unavailable"},
		{name: "scope mismatch", store: &retentionStoreStub{rows: []analyticsconnections.RetentionRow{retentionRowFixture("33333333-3333-4333-8333-333333333333")}}, status: http.StatusBadGateway, code: "retention_invalid_response"},
		{name: "encoded response", store: &retentionStoreStub{rows: []analyticsconnections.RetentionRow{retentionRowFixture(testTenantID)}}, config: HandlerConfig{MaxResponseBytes: 256}, status: http.StatusBadGateway, code: "retention_response_too_large"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := newTestHandler(t, test.store, func(*http.Request) (identity.AuthenticatedSession, error) { return session, nil }, test.config)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, retentionURL(false, ""), nil))
			assertRetentionError(t, response, test.status, test.code)
			if strings.Contains(response.Body.String(), "secret ClickHouse response") {
				t.Fatalf("store error leaked: %s", response.Body.String())
			}
		})
	}

	store := &retentionStoreStub{}
	handler := newTestHandler(t, store, func(*http.Request) (identity.AuthenticatedSession, error) { return session, nil }, HandlerConfig{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := httptest.NewRequest(http.MethodGet, retentionURL(false, ""), nil).WithContext(ctx)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assertRetentionError(t, response, http.StatusRequestTimeout, "retention_request_timeout")
}

func TestRetentionHTTPConstructorRequiresDependencies(t *testing.T) {
	if _, err := NewHandler(nil, nil, HandlerConfig{}); err == nil {
		t.Fatal("NewHandler accepted nil dependencies")
	}
}

func newTestHandler(t *testing.T, store RetentionStore, authenticate AuthenticateFunc, config HandlerConfig) *Handler {
	t.Helper()
	handler, err := NewHandler(store, authenticate, config)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func retentionURL(admin bool, suffix string) string {
	path := "/v1/analytics/connections/retention"
	if admin {
		path = "/v1/admin/analytics/connections/retention"
	}
	return path + "?subscription_id=" + testSubscriptionID +
		"&from=2026-08-07T00%3A00%3A00Z&to=2026-08-08T00%3A00%3A00Z" + suffix
}

func testSession(kind string, permissions []string, tenant bool) identity.AuthenticatedSession {
	principal := identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: kind, Permissions: permissions}
	if tenant {
		value := uuid.MustParse(testTenantID)
		principal.TenantID = &value
	}
	return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: principal}
}

func retentionRowFixture(tenantID string) analyticsconnections.RetentionRow {
	periodEnd := testFrom.Add(time.Hour)
	row := analyticsconnections.RetentionRow{
		Metric: "connections", TenantID: tenantID, SubscriptionID: testSubscriptionID,
		PeriodStart: testFrom, PeriodEnd: periodEnd, Value: 17, FinalizedThrough: periodEnd,
		SourceWatermark: 9, RetentionUntil: periodEnd.Add(analyticsconnections.DefaultRetentionTTL),
	}
	row.EvidenceDigest = sha256.Sum256([]byte("retention-evidence"))
	return row
}

func assertRetentionError(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if response.Code != status || !strings.Contains(response.Body.String(), `"code":"`+code+`"`) ||
		strings.Contains(response.Body.String(), "secret") || response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("X-Request-ID") == "" {
		t.Fatalf("response = %d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
}
