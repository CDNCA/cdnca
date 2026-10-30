package analyticslog

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

const (
	tenantA = "10000000-0000-4000-8000-00000000000a"
	tenantB = "10000000-0000-4000-8000-00000000000b"
	siteA   = "20000000-0000-4000-8000-00000000000a"
	nodeA   = "30000000-0000-4000-8000-00000000000a"
	configA = "40000000-0000-4000-8000-00000000000a"
)

type recordingStore struct {
	accessPage  AccessPage
	blockPage   BlockEventPage
	err         error
	accessCalls int
	blockCalls  int
	lastScope   scope
	lastFilter  Filter
	lastLimit   uint16
	lastCursor  string
}

func (store *recordingStore) ListAccess(
	_ context.Context,
	scope scope,
	filter Filter,
	limit uint16,
	cursor string,
) (AccessPage, error) {
	store.accessCalls++
	store.record(scope, filter, limit, cursor)
	return store.accessPage, store.err
}

func (store *recordingStore) ListBlockEvents(
	_ context.Context,
	scope scope,
	filter Filter,
	limit uint16,
	cursor string,
) (BlockEventPage, error) {
	store.blockCalls++
	store.record(scope, filter, limit, cursor)
	return store.blockPage, store.err
}

func (store *recordingStore) record(scope scope, filter Filter, limit uint16, cursor string) {
	store.lastScope = scope
	store.lastFilter = filter
	store.lastLimit = limit
	store.lastCursor = cursor
}

func TestServiceEnforcesScopeAndWindow(t *testing.T) {
	store := &recordingStore{}
	service := newTestService(t, store)
	tenant := Actor{ScopeKind: "tenant", TenantID: tenantA, Permissions: []string{ReadPermission}}
	platform := Actor{ScopeKind: "platform", Permissions: []string{"platform.admin"}}

	request := QueryRequest{Audience: AudienceTenant, Filter: validFilter(), Limit: DefaultLimit}
	if _, err := service.ListAccess(context.Background(), tenant, request); err != nil {
		t.Fatal(err)
	}
	if store.lastScope.tenantID != tenantA {
		t.Fatalf("tenant scope = %q", store.lastScope.tenantID)
	}
	request.Audience = AudiencePlatform
	request.TenantID = tenantB
	if _, err := service.ListAccess(context.Background(), platform, request); err != nil {
		t.Fatal(err)
	}
	if store.lastScope.tenantID != tenantB {
		t.Fatalf("platform scope = %q", store.lastScope.tenantID)
	}

	// Without a tenant filter the platform reads every tenant.
	request.TenantID = ""
	if _, err := service.ListAccess(context.Background(), platform, request); err != nil || !store.lastScope.platform() {
		t.Fatalf("platform-wide scope = %q err = %v", store.lastScope.tenantID, err)
	}
	request.Audience = AudienceTenant
	request.TenantID = tenantA
	if _, err := service.ListAccess(context.Background(), tenant, request); !errors.Is(err, ErrScopeForbidden) {
		t.Fatalf("tenant override error = %v", err)
	}
	request.TenantID = ""
	request.Filter.To = request.Filter.From.Add(31*24*time.Hour + time.Millisecond)
	if _, err := service.ListAccess(context.Background(), tenant, request); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("oversize window error = %v", err)
	}
	request.Filter = validFilter()
	request.Filter.From = request.Filter.From.Add(time.Nanosecond)
	if _, err := service.ListAccess(context.Background(), tenant, request); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("sub-millisecond boundary error = %v", err)
	}
	request.Filter = validFilter()
	tenant.Permissions = nil
	if _, err := service.ListAccess(context.Background(), tenant, request); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("permission error = %v", err)
	}
	tenant.Permissions = []string{"platform.admin"}
	if _, err := service.ListAccess(context.Background(), tenant, request); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("tenant platform.admin error = %v", err)
	}
	request.Cursor = "payload.invalid-mac"
	tenant.Permissions = []string{ReadPermission}
	if _, err := service.ListAccess(context.Background(), tenant, request); !errors.Is(err, ErrCapabilityUnsupported) {
		t.Fatalf("unsupported cursor error = %v", err)
	}
	if store.accessCalls != 3 {
		t.Fatalf("rejected requests reached store: calls=%d", store.accessCalls)
	}
}

func TestHandlerScopeFiltersAndSensitiveResponse(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	store := &recordingStore{accessPage: AccessPage{
		Items: []AccessLog{{
			EventID: "event-a", OccurredAt: now.Add(-time.Minute), SiteID: siteA, NodeID: nodeA,
			RequestID: "request-a", TraceID: "trace-a", ConfigVersion: configA,
			Host: "example.test", URIPath: "/asset.js?token=query-secret#fragment", ClientIP: "2001:db8::1",
			CountryCode: "CN", Carrier: "carrier-a", Method: "GET", Protocol: "HTTP/2",
			CacheStatus: "HIT", StatusCode: 200, ResponseBytes: 1024,
		}},
	}}
	actor := Actor{ScopeKind: "tenant", TenantID: tenantA, Permissions: []string{ReadPermission}}
	handler := newTestHandler(t, store, actor, HandlerConfig{})
	values := queryValues(now.Add(-time.Hour), now)
	values.Set("site_id", strings.ToUpper(siteA))
	values.Set("node_id", nodeA)
	values.Set("client_ip", "2001:0db8::1")
	values.Set("uri_path", "/asset.js")
	values.Set("status_code", "200")
	values.Set("method", "get")
	values.Set("protocol", "HTTP/2")
	values.Set("cache_status", "HIT")
	values.Set("country_code", "cn")
	values.Set("carrier", "carrier-a")
	values.Set("limit", "25")

	response := doGET(handler, "/v1/analytics/logs/access", values)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
	if store.lastScope.tenantID != tenantA || store.lastFilter.SiteID != siteA ||
		store.lastFilter.ClientIP != "2001:db8::1" || store.lastFilter.URIPath != "/asset.js" ||
		store.lastFilter.Method != "GET" || store.lastLimit != 25 {
		t.Fatalf("store query = scope:%#v filter:%#v limit:%d", store.lastScope, store.lastFilter, store.lastLimit)
	}
	body := response.Body.String()
	for _, secret := range []string{"query-secret", "Authorization", "Cookie", "Bearer ", "CdncaKey ", "#fragment"} {
		if strings.Contains(body, secret) {
			t.Fatalf("response leaked %q: %s", secret, body)
		}
	}
	if !strings.Contains(body, `"uri_path":"/asset.js"`) || strings.Contains(body, `"page"`) ||
		!strings.Contains(body, `"request_id":"request-a"`) || !strings.Contains(body, `"trace_id":"trace-a"`) ||
		!strings.Contains(body, `"config_version_id":"`+configA+`"`) ||
		!strings.Contains(body, `"consistency":"snapshot"`) ||
		!strings.Contains(body, `"replacement_consistency":"latest_event_id_at_snapshot"`) ||
		!strings.Contains(body, `"pagination":"keyset"`) || strings.Contains(body, "watermark") ||
		strings.Contains(body, "cursor") {
		t.Fatalf("response did not contain sanitized data: %s", body)
	}
}

func TestHandlerMapsAccessAndSecurityPageCursorMetadata(t *testing.T) {
	now := time.Date(2026, 7, 28, 4, 0, 0, 0, time.UTC)
	store := &recordingStore{
		accessPage: AccessPage{
			Items: []AccessLog{{EventID: "access-a", OccurredAt: now.Add(-time.Minute), SiteID: siteA, NodeID: nodeA,
				RequestID: "request-access", TraceID: "trace-access", ConfigVersion: configA,
				Host: "example.test", URIPath: "/asset", ClientIP: "192.0.2.1", Method: "GET", Protocol: "HTTP/2",
				CacheStatus: "HIT", StatusCode: 200}},
			NextCursor: "access.cursor", SnapshotAt: now,
		},
		blockPage: BlockEventPage{
			Items: []BlockEvent{{EventID: "security-a", OccurredAt: now.Add(-time.Minute), SiteID: siteA, NodeID: nodeA,
				RequestID: "request-security", TraceID: "trace-security", ConfigVersion: configA,
				Host: "example.test", URIPath: "/blocked", ClientIP: "192.0.2.1", EventType: "waf", Action: "block",
				Severity: "high", RuleID: "rule-a", StatusCode: 403}},
			NextCursor: "security.cursor", SnapshotAt: now,
		},
	}
	actor := Actor{ScopeKind: "tenant", TenantID: tenantA, Permissions: []string{ReadPermission}}
	handler := newTestHandler(t, store, actor, HandlerConfig{})
	values := queryValues(now.Add(-time.Hour), now)

	access := doGET(handler, "/v1/analytics/logs/access", values)
	if access.Code != http.StatusOK || !strings.Contains(access.Body.String(), `"next_cursor":"access.cursor"`) ||
		!strings.Contains(access.Body.String(), `"config_version_id":"`+configA+`"`) ||
		!strings.Contains(access.Body.String(), `"snapshot_at":"2026-07-28T04:00:00Z"`) ||
		!strings.Contains(access.Body.String(), `"pagination":"keyset"`) {
		t.Fatalf("access cursor response = %d %s", access.Code, access.Body.String())
	}
	security := doGET(handler, "/v1/analytics/logs/block-events", values)
	if security.Code != http.StatusOK || store.blockCalls != 1 ||
		!strings.Contains(security.Body.String(), `"request_id":"request-security"`) ||
		!strings.Contains(security.Body.String(), `"next_cursor":"security.cursor"`) ||
		!strings.Contains(security.Body.String(), `"pagination":"keyset"`) {
		t.Fatalf("security cursor response = %d %s", security.Code, security.Body.String())
	}
}

func TestHandlerPlatformScopeAndStableErrors(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	store := &recordingStore{accessPage: AccessPage{Items: []AccessLog{}}}
	platform := Actor{ScopeKind: "platform", Permissions: []string{"platform.admin"}}
	handler := newTestHandler(t, store, platform, HandlerConfig{})
	values := queryValues(now.Add(-time.Hour), now)

	if response := doGET(handler, "/v1/admin/analytics/logs/access", values); response.Code != http.StatusOK || !store.lastScope.platform() {
		t.Fatalf("platform-wide response=%d scope=%q body=%s", response.Code, store.lastScope.tenantID, response.Body.String())
	}
	values.Set("tenant_id", tenantB)
	response := doGET(handler, "/v1/admin/analytics/logs/access", values)
	if response.Code != http.StatusOK || store.lastScope.tenantID != tenantB {
		t.Fatalf("platform response=%d scope=%q body=%s", response.Code, store.lastScope.tenantID, response.Body.String())
	}

	tenant := Actor{ScopeKind: "tenant", TenantID: tenantA, Permissions: []string{ReadPermission}}
	tenantHandler := newTestHandler(t, store, tenant, HandlerConfig{})
	assertHandlerError(t, doGET(tenantHandler, "/v1/analytics/logs/access", values), 403, "analytics_logs_scope_forbidden")

	bad := queryValues(now.Add(-time.Hour), now)
	bad.Set("unknown", "x') OR 1=1 --")
	assertHandlerError(t, doGET(tenantHandler, "/v1/analytics/logs/access", bad), 400, "analytics_logs_invalid_request")
	assertHandlerError(t, doGET(tenantHandler, "/v1/analytics/logs/missing", nil), 404, "analytics_logs_route_not_found")

	unauthenticated := newTestHandlerWithAuth(t, store, func(*http.Request) (Actor, error) {
		return Actor{}, errors.New("secret auth detail")
	}, HandlerConfig{})
	unauthorized := doGET(unauthenticated, "/v1/analytics/logs/access", queryValues(now.Add(-time.Hour), now))
	assertHandlerError(t, unauthorized, 401, "analytics_logs_authentication_required")
	if strings.Contains(unauthorized.Body.String(), "secret auth detail") {
		t.Fatalf("authentication error leaked detail: %s", unauthorized.Body.String())
	}
}

func TestHandlerStrictRawQueryAndUnsupportedCursor(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	store := &recordingStore{accessPage: AccessPage{Items: []AccessLog{}}}
	actor := Actor{ScopeKind: "tenant", TenantID: tenantA, Permissions: []string{ReadPermission}}
	handler := newTestHandler(t, store, actor, HandlerConfig{})
	base := queryValues(now.Add(-time.Hour), now).Encode()
	invalid := map[string]string{
		"malformed_percent": base + "&site_id=%zz",
		"truncated_percent": base + "&site_id=%",
		"duplicate":         base + "&site_id=" + siteA + "&site_id=" + siteA,
		"empty_site":        base + "&site_id=",
		"empty_status":      base + "&status_code=",
		"path_query":        base + "&uri_path=%2Fprivate%3Ftoken%3Dsecret",
		"path_fragment":     base + "&uri_path=%2Fprivate%23secret",
		"path_not_origin":   base + "&uri_path=private",
		"empty_cursor":      base + "&cursor=",
		"empty_required":    "from=&to=" + now.Format(time.RFC3339Nano),
		"too_long":          base + "&carrier=" + strings.Repeat("a", maximumRawQueryBytes),
	}
	for name, rawQuery := range invalid {
		t.Run(name, func(t *testing.T) {
			assertHandlerError(t, doRawGET(handler, "/v1/analytics/logs/access", rawQuery), 400,
				"analytics_logs_invalid_request")
		})
	}
	if store.accessCalls != 0 {
		t.Fatalf("invalid raw query reached store: calls=%d", store.accessCalls)
	}

	for name, cursor := range map[string]string{
		"payload": `{"v":1}`, "mac": "payload.invalid-mac", "query": "changed-query",
		"scope": "changed-scope", "time": "changed-time", "keyset": "changed-keyset",
	} {
		t.Run("cursor_"+name, func(t *testing.T) {
			values := queryValues(now.Add(-time.Hour), now)
			values.Set("cursor", cursor)
			assertHandlerError(t, doGET(handler, "/v1/analytics/logs/access", values), 422,
				"analytics_logs_capability_unsupported")
		})
	}
	if store.accessCalls != 0 {
		t.Fatalf("unsupported cursor reached store: calls=%d", store.accessCalls)
	}

	assertHandlerError(t, doRawGET(handler, "/v1/analytics/logs/blocks/current", "tenant_id=%zz"), 400,
		"analytics_logs_invalid_request")
}

func TestNewHandlerRejectsResponseLimitAboveFrozenMaximum(t *testing.T) {
	store := &recordingStore{}
	service := newTestService(t, store)
	_, err := NewHandler(service, func(*http.Request) (Actor, error) { return Actor{}, nil }, HandlerConfig{
		MaxResponseBytes: maximumHandlerResponse + 1,
	})
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("response limit error=%v", err)
	}
}

func TestBlockStateRoutesFailBeforeStore(t *testing.T) {
	store := &recordingStore{}
	tenant := Actor{ScopeKind: "tenant", TenantID: tenantA, Permissions: []string{ReadPermission}}
	handler := newTestHandler(t, store, tenant, HandlerConfig{})
	for _, path := range []string{"/v1/analytics/logs/blocks/current", "/v1/analytics/logs/blocks/current-count", "/v1/analytics/logs/blocks/history"} {
		assertHandlerError(t, doGET(handler, path, nil), 422, "analytics_logs_capability_unsupported")
	}
	if store.accessCalls != 0 || store.blockCalls != 0 {
		t.Fatalf("unsupported state queried store: access=%d block=%d", store.accessCalls, store.blockCalls)
	}

	platform := Actor{ScopeKind: "platform", Permissions: []string{"platform.admin"}}
	platformHandler := newTestHandler(t, store, platform, HandlerConfig{})
	assertHandlerError(t, doGET(platformHandler, "/v1/admin/analytics/logs/blocks/current", nil), 422, "analytics_logs_capability_unsupported")
	assertHandlerError(t, doGET(platformHandler, "/v1/admin/analytics/logs/blocks/current", url.Values{"tenant_id": {tenantA}}),
		422, "analytics_logs_capability_unsupported")
	assertHandlerError(t, doGET(platformHandler, "/v1/admin/analytics/logs/blocks/current-count", nil), 422, "analytics_logs_capability_unsupported")
	assertHandlerError(t, doGET(platformHandler, "/v1/admin/analytics/logs/blocks/current-count", url.Values{"tenant_id": {tenantA}}),
		422, "analytics_logs_capability_unsupported")
	if store.accessCalls != 0 || store.blockCalls != 0 {
		t.Fatal("platform unsupported state queried store")
	}
}

func TestHandlerStorageAndTimeoutErrors(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	actor := Actor{ScopeKind: "tenant", TenantID: tenantA, Permissions: []string{ReadPermission}}
	store := &recordingStore{err: errors.New("clickhouse http://secret.invalid query SELECT token")}
	handler := newTestHandler(t, store, actor, HandlerConfig{})
	response := doGET(handler, "/v1/analytics/logs/access", queryValues(now.Add(-time.Hour), now))
	assertHandlerError(t, response, 503, "analytics_logs_unavailable")
	if strings.Contains(response.Body.String(), "clickhouse") || strings.Contains(response.Body.String(), "SELECT") {
		t.Fatalf("storage detail leaked: %s", response.Body.String())
	}

	timeoutStore := &blockingStore{}
	timeoutHandler := newTestHandler(t, timeoutStore, actor, HandlerConfig{QueryTimeout: 15 * time.Millisecond})
	assertHandlerError(t, doGET(timeoutHandler, "/v1/analytics/logs/access", queryValues(now.Add(-time.Hour), now)),
		504, "analytics_logs_query_timeout")
}

type blockingStore struct{}

func (*blockingStore) ListAccess(ctx context.Context, _ scope, _ Filter, _ uint16, _ string) (AccessPage, error) {
	<-ctx.Done()
	return AccessPage{}, ctx.Err()
}

func (*blockingStore) ListBlockEvents(ctx context.Context, _ scope, _ Filter, _ uint16, _ string) (BlockEventPage, error) {
	<-ctx.Done()
	return BlockEventPage{}, ctx.Err()
}

func validFilter() Filter {
	from := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	return Filter{From: from, To: from.Add(time.Hour)}
}

func queryValues(from, to time.Time) url.Values {
	return url.Values{"from": {from.Format(time.RFC3339Nano)}, "to": {to.Format(time.RFC3339Nano)}}
}

func newTestService(t *testing.T, store Store) *Service {
	t.Helper()
	service, err := NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func newTestHandler(t *testing.T, store Store, actor Actor, config HandlerConfig) *Handler {
	t.Helper()
	return newTestHandlerWithAuth(t, store, func(*http.Request) (Actor, error) { return actor, nil }, config)
}

func newTestHandlerWithAuth(t *testing.T, store Store, authenticate AuthenticateFunc, config HandlerConfig) *Handler {
	t.Helper()
	config.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	handler, err := NewHandler(newTestService(t, store), authenticate, config)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func doGET(handler http.Handler, path string, values url.Values) *httptest.ResponseRecorder {
	target := path
	if values != nil {
		target += "?" + values.Encode()
	}
	request := httptest.NewRequest(http.MethodGet, target, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func doRawGET(handler http.Handler, path, rawQuery string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.URL.RawQuery = rawQuery
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func assertHandlerError(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status=%d want=%d body=%s", response.Code, status, response.Body.String())
	}
	var envelope errorEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Error.Code != code || envelope.Error.RequestID == "" {
		t.Fatalf("error=%#v want code=%q", envelope.Error, code)
	}
	if response.Header().Get("X-Request-ID") != envelope.Error.RequestID {
		t.Fatalf("request id header=%q envelope=%q", response.Header().Get("X-Request-ID"), envelope.Error.RequestID)
	}
}
