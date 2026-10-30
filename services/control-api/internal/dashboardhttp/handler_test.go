package dashboardhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analytics"
	"github.com/cdnca/cdnca/services/control-api/internal/dashboard"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

var handlerTestNow = time.Date(2026, time.March, 18, 3, 27, 41, 0, time.UTC)

type fakeAuthenticator struct {
	session identity.AuthenticatedSession
	err     error
	raw     string
	calls   int
}

func (fake *fakeAuthenticator) AuthenticateSession(_ context.Context, raw string) (identity.AuthenticatedSession, error) {
	fake.calls++
	fake.raw = raw
	return fake.session, fake.err
}

type fakeReader struct {
	admin       dashboard.AdminResponse
	tenant      dashboard.TenantResponse
	err         error
	adminCalls  int
	tenantCalls int
	actor       dashboard.Actor
	query       dashboard.Query
}

func (fake *fakeReader) Admin(_ context.Context, actor dashboard.Actor, query dashboard.Query) (dashboard.AdminResponse, error) {
	fake.adminCalls++
	fake.actor, fake.query = actor, query
	return fake.admin, fake.err
}

func (fake *fakeReader) Tenant(_ context.Context, actor dashboard.Actor, query dashboard.Query) (dashboard.TenantResponse, error) {
	fake.tenantCalls++
	fake.actor, fake.query = actor, query
	return fake.tenant, fake.err
}

func TestHandlerRoutesAuthenticateAndDeriveTenantActor(t *testing.T) {
	tenantID, scopeID, userID, sessionID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	auth := &fakeAuthenticator{session: identity.AuthenticatedSession{
		SessionID: sessionID,
		Principal: identity.Principal{UserID: userID, ScopeID: scopeID, ScopeKind: "tenant", TenantID: &tenantID},
	}}
	reader := &fakeReader{tenant: dashboard.TenantResponse{DashboardVersion: dashboard.Version}}
	handler := newTestHandler(t, auth, reader, 1<<20)

	request := httptest.NewRequest(http.MethodGet, "/v1/dashboard?range=today&timezone=Asia%2FShanghai", nil)
	request.Header.Set("Authorization", "Bearer signed-session")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
	if auth.raw != "signed-session" || reader.tenantCalls != 1 || reader.adminCalls != 0 {
		t.Fatalf("auth raw=%q tenant calls=%d admin calls=%d", auth.raw, reader.tenantCalls, reader.adminCalls)
	}
	if reader.actor.RawSession != "signed-session" || reader.actor.SessionID != sessionID ||
		reader.actor.UserID != userID || reader.actor.ScopeID != scopeID || reader.actor.TenantID != tenantID {
		t.Fatalf("derived actor = %#v", reader.actor)
	}
	if reader.query.Range != "today" || reader.query.Timezone != "Asia/Shanghai" || !reader.query.AsOf.Equal(handlerTestNow) {
		t.Fatalf("query = %#v", reader.query)
	}
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Request-ID") == "" {
		t.Fatalf("response headers = %#v", response.Header())
	}
}

func TestHandlerStrictQueryRejectsTenantOverrideUnknownDuplicateAndEmpty(t *testing.T) {
	tests := []struct {
		rawQuery string
		wantCode int
	}{
		{rawQuery: "range=today&timezone=UTC&tenant_id=", wantCode: http.StatusForbidden},
		{rawQuery: "range=today&timezone=UTC&tenant_id=" + uuid.NewString(), wantCode: http.StatusForbidden},
		{rawQuery: "range=today&timezone=UTC&unknown=1", wantCode: http.StatusBadRequest},
		{rawQuery: "range=today&range=yesterday&timezone=UTC", wantCode: http.StatusBadRequest},
		{rawQuery: "range=today&timezone=UTC&timezone=Asia%2FShanghai", wantCode: http.StatusBadRequest},
		{rawQuery: "range=&timezone=UTC", wantCode: http.StatusBadRequest},
		{rawQuery: "range=today&timezone=", wantCode: http.StatusBadRequest},
		{rawQuery: "range=today", wantCode: http.StatusBadRequest},
		{rawQuery: "range=today&timezone=UTC&bad=%zz", wantCode: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.rawQuery, func(t *testing.T) {
			auth := tenantAuthenticator()
			reader := new(fakeReader)
			handler := newTestHandler(t, auth, reader, 1<<20)
			request := httptest.NewRequest(http.MethodGet, "/v1/dashboard?"+test.rawQuery, nil)
			request.Header.Set("Authorization", "Bearer signed-session")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.wantCode {
				t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
			}
			if response.Header().Get("X-Request-ID") == "" || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("response headers = %#v", response.Header())
			}
			if reader.tenantCalls != 0 || reader.adminCalls != 0 {
				t.Fatal("reader was called for invalid query")
			}
		})
	}
}

func TestHandlerRejectsInvalidAuthenticationAndSelfAssertedIdentity(t *testing.T) {
	tests := []struct {
		name      string
		headers   http.Header
		authError error
		wantCode  int
	}{
		{name: "missing", headers: http.Header{}, wantCode: http.StatusUnauthorized},
		{name: "wrong scheme", headers: http.Header{"Authorization": {"bearer token"}}, wantCode: http.StatusUnauthorized},
		{name: "duplicate", headers: http.Header{"Authorization": {"Bearer one", "Bearer two"}}, wantCode: http.StatusUnauthorized},
		{name: "whitespace", headers: http.Header{"Authorization": {"Bearer has space"}}, wantCode: http.StatusUnauthorized},
		{name: "comma", headers: http.Header{"Authorization": {"Bearer one,two"}}, wantCode: http.StatusUnauthorized},
		{name: "identity header", headers: http.Header{"Authorization": {"Bearer token"}, "X-Tenant-Id": {uuid.NewString()}}, wantCode: http.StatusBadRequest},
		{name: "invalid session", headers: http.Header{"Authorization": {"Bearer token"}}, authError: identity.ErrInvalidSession, wantCode: http.StatusUnauthorized},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			auth := tenantAuthenticator()
			auth.err = test.authError
			reader := new(fakeReader)
			handler := newTestHandler(t, auth, reader, 1<<20)
			request := httptest.NewRequest(http.MethodGet, "/v1/dashboard?range=today&timezone=UTC", nil)
			request.Header = test.headers
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.wantCode {
				t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
			}
			if response.Header().Get("X-Request-ID") == "" || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("response headers = %#v", response.Header())
			}
			if reader.tenantCalls != 0 || reader.adminCalls != 0 {
				t.Fatal("reader was called after authentication rejection")
			}
		})
	}
}

func TestHandlerClassifiesAuthenticationFailuresWithoutLeakingDependencyErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode int
		wantErr  string
	}{
		{name: "invalid session", err: identity.ErrInvalidSession, wantCode: http.StatusUnauthorized, wantErr: "dashboard_authentication_required"},
		{name: "cancelled", err: context.Canceled, wantCode: http.StatusRequestTimeout, wantErr: "dashboard_request_cancelled"},
		{name: "deadline", err: context.DeadlineExceeded, wantCode: http.StatusGatewayTimeout, wantErr: "dashboard_query_timeout"},
		{name: "dependency failure", err: errors.New("session database unavailable"), wantCode: http.StatusServiceUnavailable, wantErr: "dashboard_storage_unavailable"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			auth := tenantAuthenticator()
			auth.err = test.err
			reader := new(fakeReader)
			handler := newTestHandler(t, auth, reader, 1<<20)
			request := httptest.NewRequest(http.MethodGet, "/v1/dashboard?range=today&timezone=UTC", nil)
			request.Header.Set("Authorization", "Bearer token")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)

			if response.Code != test.wantCode {
				t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
			}
			if reader.tenantCalls != 0 || reader.adminCalls != 0 {
				t.Fatal("reader was called after authentication failure")
			}
			if response.Header().Get("X-Request-ID") == "" || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("response headers = %#v", response.Header())
			}
			var envelope struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.Error.Code != test.wantErr {
				t.Fatalf("error code = %q, want %q", envelope.Error.Code, test.wantErr)
			}
			if strings.Contains(response.Body.String(), test.err.Error()) {
				t.Fatalf("response leaked authentication dependency error: %s", response.Body.String())
			}
		})
	}
}

func TestHandlerEnforcesAudienceMethodAndExactPath(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		path     string
		actor    *fakeAuthenticator
		wantCode int
	}{
		{name: "tenant actor on admin", method: http.MethodGet, path: "/v1/admin/dashboard?range=seven_days&timezone=UTC", actor: tenantAuthenticator(), wantCode: http.StatusForbidden},
		{name: "platform actor on tenant", method: http.MethodGet, path: "/v1/dashboard?range=today&timezone=UTC", actor: platformAuthenticator(), wantCode: http.StatusForbidden},
		{name: "post", method: http.MethodPost, path: "/v1/dashboard?range=today&timezone=UTC", actor: tenantAuthenticator(), wantCode: http.StatusMethodNotAllowed},
		{name: "trailing slash", method: http.MethodGet, path: "/v1/dashboard/?range=today&timezone=UTC", actor: tenantAuthenticator(), wantCode: http.StatusNotFound},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := new(fakeReader)
			handler := newTestHandler(t, test.actor, reader, 1<<20)
			request := httptest.NewRequest(test.method, test.path, nil)
			request.Header.Set("Authorization", "Bearer signed-session")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.wantCode {
				t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
			}
			if test.method != http.MethodGet && response.Header().Get("Allow") != http.MethodGet {
				t.Fatalf("Allow = %q", response.Header().Get("Allow"))
			}
		})
	}
}

func TestHandlerMapsStableErrorsAndResponseLimit(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		limit    int
		response dashboard.TenantResponse
		wantCode int
		wantErr  string
	}{
		{name: "permission", err: dashboard.ErrPermissionDenied, limit: 1 << 20, wantCode: http.StatusForbidden, wantErr: "dashboard_permission_denied"},
		{name: "storage", err: dashboard.ErrUnavailable, limit: 1 << 20, wantCode: http.StatusServiceUnavailable, wantErr: "dashboard_storage_unavailable"},
		{name: "cancelled", err: context.Canceled, limit: 1 << 20, wantCode: http.StatusRequestTimeout, wantErr: "dashboard_request_cancelled"},
		{name: "deadline", err: context.DeadlineExceeded, limit: 1 << 20, wantCode: http.StatusGatewayTimeout, wantErr: "dashboard_query_timeout"},
		{name: "internal", err: errors.New("unclassified dependency error"), limit: 1 << 20, wantCode: http.StatusInternalServerError, wantErr: "dashboard_internal_error"},
		{name: "too large", limit: 512, response: dashboard.TenantResponse{DashboardVersion: dashboard.Version, Meta: dashboard.Meta{Timezone: strings.Repeat("x", 600)}}, wantCode: http.StatusBadGateway, wantErr: "dashboard_response_too_large"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			auth := tenantAuthenticator()
			reader := &fakeReader{err: test.err, tenant: test.response}
			handler := newTestHandler(t, auth, reader, test.limit)
			request := httptest.NewRequest(http.MethodGet, "/v1/dashboard?range=today&timezone=UTC", nil)
			request.Header.Set("Authorization", "Bearer token")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.wantCode {
				t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
			}
			if response.Header().Get("X-Request-ID") == "" || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("response headers = %#v", response.Header())
			}
			var envelope struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.Error.Code != test.wantErr {
				t.Fatalf("error code = %q, want %q", envelope.Error.Code, test.wantErr)
			}
			if strings.Contains(response.Body.String(), "SQLSTATE") {
				t.Fatal("response leaked storage detail")
			}
		})
	}
}

func TestHandlerSerializesWideMetricsLimitsAndAbsentLeaseExactly(t *testing.T) {
	const (
		wideUnsigned = uint64(9007199254740993)
		wideTraffic  = int64(1 << 60)
	)
	tenantAuth := tenantAuthenticator()
	tenantReader := &fakeReader{tenant: dashboard.TenantResponse{
		DashboardVersion: dashboard.Version,
		Subscriptions: dashboard.Available(dashboard.TenantSubscriptionStats{Items: []dashboard.SubscriptionItem{
			{SiteLimit: -1, DomainLimit: -1, NodeLimit: -1, TrafficLimitBytes: -1},
			{SiteLimit: 1, DomainLimit: 2, NodeLimit: 3, TrafficLimitBytes: dashboard.SubscriptionLimit(wideTraffic)},
		}}),
		Analytics: dashboard.Available(dashboard.AnalyticsOverview{
			Summary: dashboard.AnalyticsStats(analytics.Summary{
				MetricVersion: analytics.MetricVersion,
				RequestCount:  wideUnsigned, RequestBytes: wideUnsigned + 1,
				ResponseBytes: wideUnsigned + 2, TotalBytes: wideUnsigned + 3,
				AverageBandwidthBPS: 1.5,
				Status2xx:           wideUnsigned + 4, Status3xx: wideUnsigned + 5,
				Status4xx: wideUnsigned + 6, Status5xx: wideUnsigned + 7,
				SecurityEvents: wideUnsigned + 8,
			}), Trend: []dashboard.AnalyticsTrendPoint{}, Top: []dashboard.AnalyticsRankSnapshot{},
		}),
	}}
	tenantHandler := newTestHandler(t, tenantAuth, tenantReader, 1<<20)
	tenantRequest := httptest.NewRequest(http.MethodGet, "/v1/dashboard?range=today&timezone=UTC", nil)
	tenantRequest.Header.Set("Authorization", "Bearer token")
	tenantResponse := httptest.NewRecorder()
	tenantHandler.ServeHTTP(tenantResponse, tenantRequest)
	if tenantResponse.Code != http.StatusOK {
		t.Fatalf("tenant status = %d body=%s", tenantResponse.Code, tenantResponse.Body.String())
	}
	var tenantBody struct {
		Subscriptions struct {
			Value struct {
				Items []map[string]json.RawMessage `json:"items"`
			} `json:"value"`
		} `json:"subscriptions"`
		Analytics struct {
			Value struct {
				Summary map[string]json.RawMessage `json:"summary"`
			} `json:"value"`
		} `json:"analytics"`
	}
	if err := json.Unmarshal(tenantResponse.Body.Bytes(), &tenantBody); err != nil {
		t.Fatal(err)
	}
	metricValues := map[string]string{
		"request_count": "9007199254740993", "request_bytes": "9007199254740994",
		"response_bytes": "9007199254740995", "total_bytes": "9007199254740996",
		"status_2xx": "9007199254740997", "status_3xx": "9007199254740998",
		"status_4xx": "9007199254740999", "status_5xx": "9007199254741000",
		"security_events": "9007199254741001",
	}
	for field, want := range metricValues {
		if got := string(tenantBody.Analytics.Value.Summary[field]); got != `"`+want+`"` {
			t.Fatalf("analytics %s = %s, want quoted %s", field, got, want)
		}
	}
	for _, field := range []string{"site_limit", "domain_limit", "node_limit", "traffic_limit_bytes"} {
		if got := string(tenantBody.Subscriptions.Value.Items[0][field]); got != `"-1"` {
			t.Fatalf("infinite %s = %s, want quoted -1", field, got)
		}
	}
	if got := string(tenantBody.Subscriptions.Value.Items[1]["traffic_limit_bytes"]); got != `"1152921504606846976"` {
		t.Fatalf("wide traffic limit = %s", got)
	}

	adminReader := &fakeReader{admin: dashboard.AdminResponse{
		DashboardVersion: dashboard.Version,
		Entitlement:      dashboard.Available(dashboard.EntitlementStats{Status: "uninstalled"}),
	}}
	adminHandler := newTestHandler(t, platformAuthenticator(), adminReader, 1<<20)
	adminRequest := httptest.NewRequest(http.MethodGet, "/v1/admin/dashboard?range=seven_days&timezone=UTC", nil)
	adminRequest.Header.Set("Authorization", "Bearer token")
	adminResponse := httptest.NewRecorder()
	adminHandler.ServeHTTP(adminResponse, adminRequest)
	if adminResponse.Code != http.StatusOK {
		t.Fatalf("admin status = %d body=%s", adminResponse.Code, adminResponse.Body.String())
	}
	var adminBody struct {
		Entitlement struct {
			Value map[string]json.RawMessage `json:"value"`
		} `json:"entitlement"`
	}
	if err := json.Unmarshal(adminResponse.Body.Bytes(), &adminBody); err != nil {
		t.Fatal(err)
	}
	leaseStatus, exists := adminBody.Entitlement.Value["lease_status"]
	if !exists || string(leaseStatus) != "null" {
		t.Fatalf("uninstalled lease_status = %s exists=%t, want null", leaseStatus, exists)
	}
}

func newTestHandler(t *testing.T, auth *fakeAuthenticator, reader *fakeReader, maxResponse int) http.Handler {
	t.Helper()
	handler, err := NewHandler(auth, reader, Config{
		Now: func() time.Time { return handlerTestNow }, QueryTimeout: time.Second, MaxResponseBytes: maxResponse,
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func tenantAuthenticator() *fakeAuthenticator {
	tenantID := uuid.New()
	return &fakeAuthenticator{session: identity.AuthenticatedSession{
		SessionID: uuid.New(), Principal: identity.Principal{
			UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant", TenantID: &tenantID,
		},
	}}
}

func platformAuthenticator() *fakeAuthenticator {
	return &fakeAuthenticator{session: identity.AuthenticatedSession{
		SessionID: uuid.New(), Principal: identity.Principal{
			UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform",
		},
	}}
}

var _ SessionAuthenticator = (*fakeAuthenticator)(nil)
var _ Reader = (*fakeReader)(nil)
var _ = errors.Is
