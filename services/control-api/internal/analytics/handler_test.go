package analytics

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestHandlerSeparatesPlatformAndTenantRoutes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		path       string
		actor      Actor
		wantScope  scopeKind
		wantTenant string
	}{
		{
			name:      "platform global",
			path:      handlerURL("/v1/admin/analytics/summary", ""),
			actor:     Actor{ScopeKind: "platform", Permissions: []string{"platform.admin"}},
			wantScope: scopeAdmin,
		},
		{
			name:       "platform tenant target",
			path:       handlerURL("/v1/admin/analytics/summary", "tenant_id="+testTenantID),
			actor:      Actor{ScopeKind: "platform", Permissions: []string{ReadPermission}},
			wantScope:  scopeTenant,
			wantTenant: testTenantID,
		},
		{
			name:       "tenant implicit target",
			path:       handlerURL("/v1/analytics/summary", ""),
			actor:      Actor{ScopeKind: "tenant", TenantID: testTenantID, Permissions: []string{ReadPermission}},
			wantScope:  scopeTenant,
			wantTenant: testTenantID,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := &recordingQueryStore{summary: Summary{MetricVersion: MetricVersion, RequestCount: 7}}
			handler := mustHandler(t, store, test.actor, HandlerConfig{})
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, test.path, nil)
			request.Header.Set("X-Request-ID", "analytics-test-request")
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d body = %s", response.Code, response.Body.String())
			}
			if store.scope.kind != test.wantScope || store.scope.tenantID != test.wantTenant {
				t.Fatalf("scope = %#v", store.scope)
			}
			if response.Header().Get("X-Request-ID") != "analytics-test-request" || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("headers = %v", response.Header())
			}
			var body struct {
				Data Summary       `json:"data"`
				Meta queryMetadata `json:"meta"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body.Data.RequestCount != 7 || body.Meta.Timezone != "UTC" || body.Meta.From != "2099-01-01T00:00:00Z" {
				t.Fatalf("body = %#v", body)
			}
		})
	}
}

func TestHandlerRejectsScopeAndAuthenticationFailures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		path       string
		actor      Actor
		authErr    error
		wantStatus int
		wantCode   string
	}{
		{
			name: "tenant override", path: handlerURL("/v1/analytics/summary", "tenant_id="+testTenantID),
			actor:      Actor{ScopeKind: "tenant", TenantID: testTenantID, Permissions: []string{ReadPermission}},
			wantStatus: http.StatusForbidden, wantCode: "analytics_scope_forbidden",
		},
		{
			name: "tenant empty override", path: handlerURL("/v1/analytics/summary", "tenant_id="),
			actor:      Actor{ScopeKind: "tenant", TenantID: testTenantID, Permissions: []string{ReadPermission}},
			wantStatus: http.StatusForbidden, wantCode: "analytics_scope_forbidden",
		},
		{
			name: "tenant on admin route", path: handlerURL("/v1/admin/analytics/summary", ""),
			actor:      Actor{ScopeKind: "tenant", TenantID: testTenantID, Permissions: []string{ReadPermission}},
			wantStatus: http.StatusForbidden, wantCode: "analytics_scope_forbidden",
		},
		{
			name: "missing permission", path: handlerURL("/v1/analytics/summary", ""),
			actor:      Actor{ScopeKind: "tenant", TenantID: testTenantID},
			wantStatus: http.StatusForbidden, wantCode: "analytics_permission_denied",
		},
		{
			name: "unauthenticated", path: handlerURL("/v1/analytics/summary", ""),
			authErr:    errors.New("secret auth detail"),
			wantStatus: http.StatusUnauthorized, wantCode: "analytics_authentication_required",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := &recordingQueryStore{}
			service, err := NewService(store)
			if err != nil {
				t.Fatal(err)
			}
			handler, err := NewHandler(service, func(*http.Request) (Actor, error) {
				return test.actor, test.authErr
			}, HandlerConfig{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
			if err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, test.path, nil))
			assertHandlerError(t, response, test.wantStatus, test.wantCode)
			if store.queryCalled {
				t.Fatal("store was called after request denial")
			}
			if strings.Contains(response.Body.String(), "secret") {
				t.Fatal("response leaked authentication detail")
			}
		})
	}
}

func TestHandlerValidatesWindowFiltersAndQueryShape(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		path string
	}{
		{name: "missing from", path: "/v1/analytics/summary?to=2099-01-01T02:00:00Z"},
		{name: "non RFC3339", path: "/v1/analytics/summary?from=2099-01-01+00:00:00&to=2099-01-01T02:00:00Z"},
		{name: "not minute aligned", path: "/v1/analytics/summary?from=2099-01-01T00:00:30Z&to=2099-01-01T02:00:00Z"},
		{name: "too wide", path: "/v1/analytics/summary?from=2099-01-01T00:00:00Z&to=2099-02-02T00:00:00Z"},
		{name: "invalid site", path: handlerURL("/v1/analytics/summary", "site_id=bad")},
		{name: "unknown query", path: handlerURL("/v1/analytics/summary", "unknown=value")},
		{name: "duplicate query", path: handlerURL("/v1/analytics/summary", "site_id="+testSiteID+"&site_id="+testSiteID)},
		{name: "rank zero limit", path: handlerURL("/v1/analytics/top/url", "limit=0")},
		{name: "rank invalid domain", path: handlerURL("/v1/analytics/top/url", "domain=bad_domain")},
		{name: "rank oversized cursor", path: handlerURL("/v1/analytics/top/url", "cursor="+strings.Repeat("a", maxCursorSize+1))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := &recordingQueryStore{}
			handler := mustHandler(t, store, Actor{
				ScopeKind: "tenant", TenantID: testTenantID, Permissions: []string{ReadPermission},
			}, HandlerConfig{})
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, test.path, nil))
			assertHandlerError(t, response, http.StatusBadRequest, "analytics_invalid_request")
			if store.queryCalled {
				t.Fatal("store was called for invalid query")
			}
		})
	}
}

func TestHandlerRejectsEmptyPlatformTenantTarget(t *testing.T) {
	t.Parallel()
	store := &recordingQueryStore{}
	handler := mustHandler(t, store, Actor{
		ScopeKind: "platform", Permissions: []string{"platform.admin"},
	}, HandlerConfig{})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet,
		handlerURL("/v1/admin/analytics/summary", "tenant_id="), nil))
	assertHandlerError(t, response, http.StatusBadRequest, "analytics_invalid_request")
	if store.queryCalled {
		t.Fatal("store was called for an empty platform tenant target")
	}
}

func TestHandlerNormalizesUTCAndReturnsTrend(t *testing.T) {
	t.Parallel()
	store := &recordingQueryStore{trend: []TrendPoint{{
		Hour: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC), MetricVersion: MetricVersion,
		RequestCount: 2, TotalBytes: 50,
	}}}
	handler := mustHandler(t, store, Actor{
		ScopeKind: "tenant", TenantID: testTenantID, Permissions: []string{ReadPermission},
	}, HandlerConfig{})
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet,
		"/v1/analytics/hourly-trend?from=2099-01-01T08:00:00%2B08:00&to=2099-01-01T10:00:00%2B08:00", nil)
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", response.Code, response.Body.String())
	}
	if store.filter.From.Hour() != 0 || store.filter.From.Location() != time.UTC {
		t.Fatalf("filter = %#v", store.filter)
	}
	if !strings.Contains(response.Body.String(), `"hour":"2099-01-01T00:00:00Z"`) ||
		!strings.Contains(response.Body.String(), `"from":"2099-01-01T00:00:00Z"`) {
		t.Fatalf("body = %s", response.Body.String())
	}
}

func TestHandlerRankAndJA4(t *testing.T) {
	t.Parallel()
	store := &recordingQueryStore{rank: RankPage{
		Items:      []RankItem{{Key: "/asset.js", RequestCount: 4, ResponseBytes: 100}},
		NextCursor: "next", SnapshotAt: time.Date(2099, 1, 1, 3, 0, 0, 0, time.UTC),
	}}
	handler := mustHandler(t, store, Actor{
		ScopeKind: "tenant", TenantID: testTenantID, Permissions: []string{ReadPermission},
	}, HandlerConfig{})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet,
		handlerURL("/v1/analytics/top/url", "limit=25&cursor=prior&domain=CDN.example.test."), nil))
	if response.Code != http.StatusOK || store.dimension != RankByURL || store.limit != 25 || store.cursor != "prior" {
		t.Fatalf("status=%d body=%s store=%#v", response.Code, response.Body.String(), store)
	}
	if store.filter.Domain != "cdn.example.test" {
		t.Fatalf("domain = %q", store.filter.Domain)
	}
	if !strings.Contains(response.Body.String(), `"next_cursor":"next"`) ||
		!strings.Contains(response.Body.String(), `"snapshot_at":"2099-01-01T03:00:00Z"`) {
		t.Fatalf("body = %s", response.Body.String())
	}

	store.queryCalled = false
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, handlerURL("/v1/analytics/top/ja4", ""), nil))
	if response.Code != http.StatusOK || !store.queryCalled || store.dimension != RankByJA4 {
		t.Fatalf("status=%d body=%s store=%#v", response.Code, response.Body.String(), store)
	}
	if !strings.Contains(response.Body.String(), `"dimension":"ja4"`) {
		t.Fatalf("body = %s", response.Body.String())
	}
}

func TestHandlerRankRefererCanonicalizesDomainsAndBindsListenPort(t *testing.T) {
	t.Parallel()
	store := &recordingQueryStore{rank: RankPage{
		Items:      []RankItem{{Key: "__unknown__", RequestCount: 1, ResponseBytes: 10}},
		SnapshotAt: time.Date(2099, 1, 1, 3, 0, 0, 0, time.UTC),
	}}
	handler := mustHandler(t, store, Actor{
		ScopeKind: "tenant", TenantID: testTenantID, Permissions: []string{ReadPermission},
	}, HandlerConfig{})
	query := url.Values{
		"domain":      {"CDN.example.test. cdn.example.test static.example.test"},
		"listen_port": {"443"},
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet,
		handlerURL("/v1/analytics/top/referer", query.Encode()), nil))
	if response.Code != http.StatusOK || store.dimension != RankByReferer || store.filter.ListenPort != 443 ||
		store.filter.Domain != "cdn.example.test static.example.test" {
		t.Fatalf("status=%d body=%s store=%#v", response.Code, response.Body.String(), store)
	}
	if !strings.Contains(response.Body.String(), `"dimension":"referer"`) {
		t.Fatalf("body = %s", response.Body.String())
	}
}

func TestHandlerRankRejectsInvalidListenPortAndDomainSet(t *testing.T) {
	t.Parallel()
	store := &recordingQueryStore{}
	handler := mustHandler(t, store, Actor{
		ScopeKind: "tenant", TenantID: testTenantID, Permissions: []string{ReadPermission},
	}, HandlerConfig{})
	tests := []string{
		"listen_port=0",
		"listen_port=65536",
		url.Values{"domain": {strings.Repeat("cdn.example.test ", 64) + "extra.example.test"}}.Encode(),
	}
	for _, extra := range tests {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet,
			handlerURL("/v1/analytics/top/domain", extra), nil))
		assertHandlerError(t, response, http.StatusBadRequest, "analytics_invalid_request")
	}
	if store.queryCalled {
		t.Fatal("store was called for an invalid rank filter")
	}
}

func TestHandlerMapsStorageFailuresWithoutLeakingDetails(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{name: "transport", err: ErrTransport, wantStatus: 503, wantCode: "analytics_storage_unavailable"},
		{name: "storage 503", err: &HTTPError{StatusCode: 503}, wantStatus: 503, wantCode: "analytics_storage_unavailable"},
		{name: "storage 400", err: &HTTPError{StatusCode: 400}, wantStatus: 502, wantCode: "analytics_storage_rejected"},
		{name: "invalid response", err: ErrInvalidResponse, wantStatus: 502, wantCode: "analytics_storage_invalid_response"},
		{name: "storage response limit", err: ErrResponseTooLarge, wantStatus: 502, wantCode: "analytics_response_too_large"},
		{name: "timeout", err: context.DeadlineExceeded, wantStatus: 504, wantCode: "analytics_query_timeout"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := &recordingQueryStore{err: test.err}
			handler := mustHandler(t, store, Actor{
				ScopeKind: "tenant", TenantID: testTenantID, Permissions: []string{ReadPermission},
			}, HandlerConfig{})
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, handlerURL("/v1/analytics/summary", ""), nil))
			assertHandlerError(t, response, test.wantStatus, test.wantCode)
			if strings.Contains(response.Body.String(), test.err.Error()) {
				t.Fatalf("response leaked internal error: %s", response.Body.String())
			}
		})
	}
}

func TestHandlerBoundsExecutionAndEncodedResponse(t *testing.T) {
	t.Parallel()
	store := &contextQueryStore{}
	service, err := NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(service, func(*http.Request) (Actor, error) {
		return Actor{ScopeKind: "tenant", TenantID: testTenantID, Permissions: []string{ReadPermission}}, nil
	}, HandlerConfig{QueryTimeout: 10 * time.Millisecond, MaxResponseBytes: 512, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, handlerURL("/v1/analytics/summary", ""), nil))
	assertHandlerError(t, response, http.StatusGatewayTimeout, "analytics_query_timeout")

	largeStore := &recordingQueryStore{trend: make([]TrendPoint, 20)}
	handler = mustHandler(t, largeStore, Actor{
		ScopeKind: "tenant", TenantID: testTenantID, Permissions: []string{ReadPermission},
	}, HandlerConfig{MaxResponseBytes: 512})
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, handlerURL("/v1/analytics/hourly-trend", ""), nil))
	assertHandlerError(t, response, http.StatusBadGateway, "analytics_response_too_large")
}

func TestHandlerStableRouteErrorsAndConfiguration(t *testing.T) {
	t.Parallel()
	store := &recordingQueryStore{}
	handler := mustHandler(t, store, Actor{
		ScopeKind: "tenant", TenantID: testTenantID, Permissions: []string{ReadPermission},
	}, HandlerConfig{})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/analytics/missing", nil))
	assertHandlerError(t, response, http.StatusNotFound, "analytics_route_not_found")

	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, handlerURL("/v1/analytics/summary", ""), nil))
	assertHandlerError(t, response, http.StatusMethodNotAllowed, "analytics_method_not_allowed")
	if response.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("Allow = %q", response.Header().Get("Allow"))
	}

	service, err := NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewHandler(nil, func(*http.Request) (Actor, error) { return Actor{}, nil }, HandlerConfig{}); !errors.Is(err, ErrInvalidHandlerConfig) {
		t.Fatalf("nil service error = %v", err)
	}
	if _, err := NewHandler(service, nil, HandlerConfig{}); !errors.Is(err, ErrInvalidHandlerConfig) {
		t.Fatalf("nil auth error = %v", err)
	}
	if _, err := NewHandler(service, func(*http.Request) (Actor, error) { return Actor{}, nil }, HandlerConfig{QueryTimeout: 31 * time.Second}); !errors.Is(err, ErrInvalidHandlerConfig) {
		t.Fatalf("timeout config error = %v", err)
	}
}

type contextQueryStore struct{}

func (*contextQueryStore) Summary(ctx context.Context, _ Scope, _ Filter) (Summary, error) {
	<-ctx.Done()
	return Summary{}, ctx.Err()
}

func (*contextQueryStore) Trend(ctx context.Context, _ Scope, _ Filter) ([]TrendPoint, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (*contextQueryStore) Rank(ctx context.Context, _ Scope, _ Filter, _ RankDimension, _ uint16, _ string) (RankPage, error) {
	<-ctx.Done()
	return RankPage{}, ctx.Err()
}

func mustHandler(t *testing.T, store QueryStore, actor Actor, config HandlerConfig) *Handler {
	t.Helper()
	service, err := NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	if config.Logger == nil {
		config.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	handler, err := NewHandler(service, func(*http.Request) (Actor, error) { return actor, nil }, config)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func handlerURL(path, extra string) string {
	query := url.Values{
		"from": {"2099-01-01T00:00:00Z"},
		"to":   {"2099-01-01T02:00:00Z"},
	}
	base := path + "?" + query.Encode()
	if extra != "" {
		base += "&" + extra
	}
	return base
}

func assertHandlerError(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, status, response.Body.String())
	}
	var envelope errorEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Error.Code != code || envelope.Error.RequestID == "" {
		t.Fatalf("error = %#v, want code %q", envelope.Error, code)
	}
}
