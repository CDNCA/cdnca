package analytics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRealtimeHandlerRoutesAndScopesAtomically(t *testing.T) {
	from := time.Date(2026, 8, 7, 1, 0, 0, 0, time.UTC)
	store := &realtimeStoreFixture{result: validRealtimeResult(from, from.Add(time.Hour))}
	service, _ := NewService(store)
	handler, err := NewHandler(service, func(request *http.Request) (Actor, error) {
		if request.URL.Path == "/v1/admin/analytics/site-realtime" {
			return Actor{ScopeKind: "platform", Permissions: []string{"platform.admin"}}, nil
		}
		return Actor{ScopeKind: "tenant", TenantID: "018f0000-0000-7000-8000-000000000001", Permissions: []string{ReadPermission}}, nil
	}, HandlerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{
		"/v1/analytics/site-realtime?from=2026-08-07T01:00:00Z&to=2026-08-07T02:00:00Z&site_id=018f0000-0000-7000-8000-000000000002&host=cdn.example.test%20static.example.test&listen_port=443",
		"/v1/admin/analytics/site-realtime?tenant_id=018f0000-0000-7000-8000-000000000001&from=2026-08-07T01:00:00Z&to=2026-08-07T02:00:00Z",
	} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, target, nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", target, recorder.Code, recorder.Body.String())
		}
		if strings.Contains(target, "host=") && store.filter.Host != "cdn.example.test static.example.test" {
			t.Fatalf("multi-host filter=%q", store.filter.Host)
		}
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet,
		"/v1/admin/analytics/site-realtime?from=2026-08-07T01:00:00Z&to=2026-08-07T02:00:00Z", nil))
	if recorder.Code != http.StatusOK || store.scope.kind != scopeAdmin {
		t.Fatalf("platform global status=%d scope=%#v body=%s", recorder.Code, store.scope, recorder.Body.String())
	}
}

func TestRealtimeHandlerReturnsProvenEmptyZeroSeries(t *testing.T) {
	from := time.Date(2026, 8, 7, 1, 0, 0, 0, time.UTC)
	filter := RealtimeFilter{From: from, To: from.Add(time.Hour)}
	reader := &realtimeExpectedCountFixture{evidence: provenEmptyRealtimeExpectedEvidence("", filter)}
	service, err := NewServiceWithRealtimeExpectedCounts(&realtimeStoreFixture{result: zeroRealtimeResult()}, reader)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(service, func(*http.Request) (Actor, error) {
		return Actor{ScopeKind: "platform", Permissions: []string{"platform.admin"}}, nil
	}, HandlerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	target := "/v1/admin/analytics/site-realtime?from=2026-08-07T01:00:00Z&to=2026-08-07T02:00:00Z"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, target, nil))
	body := recorder.Body.String()
	if recorder.Code != http.StatusOK || !strings.Contains(body, `"series":[]`) || !strings.Contains(body, `"requests":0`) ||
		!strings.Contains(body, `"expected_events":0`) || !strings.Contains(body, `"finalized_through":"2026-08-07T02:00:00Z"`) {
		t.Fatalf("proven empty status=%d body=%s", recorder.Code, body)
	}
	reader.evidence.CoveredWindows = 0
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, target, nil))
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), "analytics_realtime_evidence_unavailable") {
		t.Fatalf("unproven empty status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
