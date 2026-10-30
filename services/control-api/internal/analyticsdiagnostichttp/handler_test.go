package analyticsdiagnostichttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsdiagnostic"
	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
)

type sourceStub struct {
	page analyticslog.AccessPage
	err  error
}

func (source *sourceStub) ReadAccess(context.Context, analyticsdiagnostic.Actor, analyticsdiagnostic.QueryRequest) (analyticslog.AccessPage, error) {
	return source.page, source.err
}

func TestHandlerExposesTenantDiagnosticsWithoutRawFacts(t *testing.T) {
	to := time.Date(2026, 8, 8, 2, 0, 0, 0, time.UTC)
	service, _ := analyticsdiagnostic.NewService(&sourceStub{page: analyticslog.AccessPage{Items: []analyticslog.AccessLog{{
		EventID: "event-1", OccurredAt: to.Add(-time.Minute), SiteID: testSiteID, NodeID: testNodeID,
		RequestID: "request-1", TraceID: "trace-1", ConfigVersion: "config-1", Host: "cdn.example.test",
		URIPath: "/health", StatusCode: 502, UpstreamResult: "secret-upstream-detail",
	}}}})
	handler, err := NewHandler(service, func(*http.Request) (analyticsdiagnostic.Actor, error) {
		return analyticsdiagnostic.Actor{ScopeKind: "tenant", TenantID: testTenantID,
			Permissions: []string{analyticslog.ReadPermission}}, nil
	}, Config{QueryTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	target := "/v1/analytics/site-quality-diagnostics?from=2026-08-08T01:00:00Z&to=2026-08-08T02:00:00Z&site_id=" + testSiteID + "&limit=20"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, target, nil))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"category":"upstream_5xx"`) ||
		strings.Contains(recorder.Body.String(), "secret-upstream-detail") {
		t.Fatalf("status/body = %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestHandlerRejectsScopeOverrideAndUnknownEvidence(t *testing.T) {
	service, _ := analyticsdiagnostic.NewService(&sourceStub{err: analyticsdiagnostic.ErrEvidenceUnavailable})
	handler, _ := NewHandler(service, func(*http.Request) (analyticsdiagnostic.Actor, error) {
		return analyticsdiagnostic.Actor{ScopeKind: "tenant", TenantID: testTenantID,
			Permissions: []string{analyticslog.ReadPermission}}, nil
	}, Config{QueryTimeout: time.Second})
	for _, target := range []string{
		"/v1/analytics/site-quality-diagnostics?from=2026-08-08T01:00:00Z&to=2026-08-08T02:00:00Z&tenant_id=" + testTenantID,
		"/v1/admin/analytics/site-quality-diagnostics?from=2026-08-08T01:00:00Z&to=2026-08-08T02:00:00Z",
	} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, target, nil))
		if recorder.Code != http.StatusForbidden && recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d", target, recorder.Code)
		}
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet,
		"/v1/analytics/site-quality-diagnostics?from=2026-08-08T01:00:00Z&to=2026-08-08T02:00:00Z&limit=20", nil))
	if recorder.Code != http.StatusServiceUnavailable || strings.Contains(recorder.Body.String(), "clickhouse") {
		t.Fatalf("unavailable status/body = %d %s", recorder.Code, recorder.Body.String())
	}
}

const (
	testTenantID = "018f0000-0000-7000-8000-000000000001"
	testSiteID   = "018f0000-0000-7000-8000-000000000002"
	testNodeID   = "018f0000-0000-7000-8000-000000000003"
)
