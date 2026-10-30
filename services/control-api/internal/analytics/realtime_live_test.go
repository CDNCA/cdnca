package analytics

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// stats-platform-l7: the realtime monitor (query_version=4) reads the newest
// facts, the unsettled current hour included, instead of only settled hours.
// The settlement authority is never consulted, nothing is excluded, and the
// platform audience without a tenant reads every tenant.
func TestRealtimeLiveReadsUnsettledHoursPlatformWide(t *testing.T) {
	to := time.Date(2026, 10, 24, 8, 30, 0, 0, time.UTC)
	from := to.Add(-time.Hour)
	store := &realtimeStoreFixture{result: validRealtimeResult(from, to)}
	// Nothing is settled: the strict and v3 paths would show no data.
	reader := &realtimeExpectedCountFixture{err: errors.New("settlement authority must not be read")}
	service, err := NewServiceWithRealtimeExpectedCounts(store, reader)
	if err != nil {
		t.Fatal(err)
	}
	platform := Actor{ScopeKind: "platform", Permissions: []string{"platform.admin"}}
	result, err := service.Realtime(t.Context(), platform, RealtimeRequest{Audience: AudiencePlatform, From: from, To: to, Live: true})
	if err != nil {
		t.Fatalf("live read error = %v", err)
	}
	if store.scope.kind != scopeAdmin || len(store.filter.ExcludedWindows) != 0 || !store.filter.From.Equal(from) || !store.filter.To.Equal(to) {
		t.Fatalf("live store call scope=%+v filter=%+v", store.scope, store.filter)
	}
	if !reader.filter.From.IsZero() {
		t.Fatal("live read consulted the settlement authority")
	}
	evidence := result.Evidence
	if result.Summary.Requests != 12 || !evidence.CoverageComplete || evidence.RequestedWindows != 2 || evidence.CoveredWindows != 2 ||
		len(evidence.MissingWindows) != 0 || evidence.ExpectedEvents != 0 || evidence.ErrorPPM != 0 ||
		!evidence.FinalizedThrough.Equal(time.Unix(0, 0).UTC()) {
		t.Fatalf("live result = %+v", result)
	}

	// A tenant still reads only itself.
	tenant := Actor{ScopeKind: "tenant", TenantID: rankTenantA, Permissions: []string{ReadPermission}}
	if _, err := service.Realtime(t.Context(), tenant, RealtimeRequest{Audience: AudienceTenant, From: from, To: to, Live: true}); err != nil {
		t.Fatal(err)
	}
	if store.scope.kind != scopeTenant || store.scope.tenantID != rankTenantA {
		t.Fatalf("tenant live scope = %+v", store.scope)
	}
	if _, err := service.Realtime(t.Context(), tenant, RealtimeRequest{Audience: AudienceTenant, TenantID: rankTenantB, From: from, To: to, Live: true}); !errors.Is(err, ErrScopeForbidden) {
		t.Fatalf("tenant naming another tenant error = %v", err)
	}

	// Inconsistent facts still fail closed.
	store.result.Series[0].Requests = 11
	if _, err := service.Realtime(t.Context(), platform, RealtimeRequest{Audience: AudiencePlatform, From: from, To: to, Live: true}); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("inconsistent live facts error = %v", err)
	}
}

func TestRealtimeLiveHandlerVersion(t *testing.T) {
	to := time.Date(2026, 10, 24, 8, 30, 0, 0, time.UTC)
	from := to.Add(-time.Hour)
	store := &realtimeStoreFixture{result: validRealtimeResult(from, to)}
	service, _ := NewServiceWithRealtimeExpectedCounts(store, &realtimeExpectedCountFixture{err: errors.New("unused")})
	handler, _ := NewHandler(service, func(*http.Request) (Actor, error) {
		return Actor{ScopeKind: "platform", Permissions: []string{"platform.admin"}}, nil
	}, HandlerConfig{})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet,
		"/v1/admin/analytics/site-realtime?query_version=4&from="+from.Format(time.RFC3339)+"&to="+to.Format(time.RFC3339), nil))
	var response struct {
		Data struct {
			Summary  RealtimeMetrics `json:"summary"`
			Evidence map[string]any  `json:"evidence"`
		} `json:"data"`
		Meta map[string]any `json:"meta"`
	}
	if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &response) != nil {
		t.Fatalf("live status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if response.Meta["query_version"] != float64(4) || response.Data.Summary.Requests != 12 ||
		response.Data.Evidence["coverage_complete"] != true || store.scope.kind != scopeAdmin {
		t.Fatalf("live response=%s", recorder.Body.String())
	}
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet,
		"/v1/admin/analytics/site-realtime?query_version=5&from="+from.Format(time.RFC3339)+"&to="+to.Format(time.RFC3339), nil))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("unknown version status=%d", recorder.Code)
	}
}
