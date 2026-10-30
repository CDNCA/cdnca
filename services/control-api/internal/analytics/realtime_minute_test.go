package analytics

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func TestRealtimeMinuteExactProjectionUsesBoundingEvidence(t *testing.T) {
	from := time.Date(2026, 9, 25, 10, 17, 0, 0, time.UTC)
	filter := RealtimeFilter{From: from, To: from.Add(63 * time.Minute)}
	coverage := realtimeCoverageFilter(filter)
	store := &realtimeStoreFixture{result: validRealtimeResult(from, coverage.To)}
	store.result.Evidence.ObservedEvents = 20 // Twelve requests in the exact subrange; twenty in full coverage.
	reader := &realtimeExpectedCountFixture{evidence: completeRealtimeExpectedEvidence("", coverage, 20)}
	service, _ := NewServiceWithRealtimeExpectedCounts(store, reader)
	actor := Actor{ScopeKind: "platform", Permissions: []string{"platform.admin"}}
	result, err := service.Realtime(t.Context(), actor, RealtimeRequest{Audience: AudiencePlatform, From: filter.From, To: filter.To})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(store.filter, filter) || !reflect.DeepEqual(reader.filter, filter) || result.Summary.Requests != 12 ||
		result.Evidence.ExpectedEvents != 20 || result.Evidence.ObservedEvents != 20 || result.Evidence.AccessSourceCount != 12 ||
		!result.Evidence.CoverageFrom.Equal(coverage.From) || !result.Evidence.CoverageTo.Equal(coverage.To) || result.SeriesBucketSeconds != 60 {
		t.Fatalf("query rounded or evidence conflated: store=%+v reader=%+v result=%+v", store.filter, reader.filter, result)
	}
	reader.evidence.CoveredWindows--
	store.filter = RealtimeFilter{}
	if _, err = service.Realtime(t.Context(), actor, RealtimeRequest{Audience: AudiencePlatform, From: filter.From, To: filter.To}); !errors.Is(err, ErrRealtimeEvidenceUnavailable) || !store.filter.From.IsZero() {
		t.Fatalf("incomplete bounding evidence must fail before projection: %v", err)
	}
	reader.evidence = completeRealtimeExpectedEvidence("", coverage, 25)
	if _, err = service.Realtime(t.Context(), actor, RealtimeRequest{Audience: AudiencePlatform, From: filter.From, To: filter.To}); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("missing full-window access facts must fail: %v", err)
	}
}

func TestRealtimeMinuteLimitsAndDownsampling(t *testing.T) {
	from := time.Date(2026, 9, 1, 10, 17, 0, 0, time.UTC)
	for _, minutes := range []int{1, 60, 744, 745, 1440, 31 * 24 * 60} {
		filter := RealtimeFilter{From: from, To: from.Add(time.Duration(minutes) * time.Minute)}
		if !validRealtimeFilter(filter) {
			t.Fatalf("valid minute range rejected: %d", minutes)
		}
		seconds := int64(realtimeBucketSeconds(filter))
		if seconds%60 != 0 || (int64(minutes)*60+seconds-1)/seconds > maximumRealtimePoints {
			t.Fatalf("unbounded series: minutes=%d bucket=%d", minutes, seconds)
		}
		if minutes == 31*24*60 {
			coverage := realtimeCoverageFilter(filter)
			evidence := completeRealtimeExpectedEvidence("", coverage, 0)
			if evidence.RequestedWindows != 745 || !validRealtimeExpectedEvidence(evidence, AdminScope(), filter) || seconds != 3600 {
				t.Fatalf("31-day boundary: %+v bucket=%d", evidence, seconds)
			}
		}
	}
	for _, duration := range []time.Duration{0, -time.Minute, 31*24*time.Hour + time.Minute, time.Minute + time.Second} {
		if validRealtimeFilter(RealtimeFilter{From: from, To: from.Add(duration)}) {
			t.Fatalf("invalid duration accepted: %v", duration)
		}
	}
}

func TestRealtimeMinuteHandlerScopesAndMetadata(t *testing.T) {
	from := time.Date(2026, 9, 25, 10, 17, 0, 0, time.UTC)
	to := from.Add(30 * time.Minute)
	for _, platform := range []bool{false, true} {
		filter := RealtimeFilter{From: from, To: to}
		tenant := rankTenantA
		actor := Actor{ScopeKind: "tenant", TenantID: tenant, Permissions: []string{ReadPermission}}
		path := "/v1/analytics/site-realtime"
		if platform {
			tenant = ""
			actor = Actor{ScopeKind: "platform", Permissions: []string{"platform.admin"}}
			path = "/v1/admin/analytics/site-realtime"
		}
		store := &realtimeStoreFixture{result: validRealtimeResult(from, from.Truncate(time.Hour).Add(time.Hour))}
		reader := &realtimeExpectedCountFixture{evidence: completeRealtimeExpectedEvidence(tenant, realtimeCoverageFilter(filter), 12)}
		service, _ := NewServiceWithRealtimeExpectedCounts(store, reader)
		handler, _ := NewHandler(service, func(*http.Request) (Actor, error) { return actor, nil }, HandlerConfig{})
		query := "?query_version=2&from=" + from.Format(time.RFC3339) + "&to=" + to.Format(time.RFC3339)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path+query, nil))
		var response struct {
			Data RealtimeResult               `json:"data"`
			Meta struct{ From, To time.Time } `json:"meta"`
		}
		if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &response) != nil ||
			!response.Meta.From.Equal(from) || !response.Meta.To.Equal(to) || store.scope.tenantID != tenant {
			t.Fatalf("scope=%+v status=%d body=%s", store.scope, recorder.Code, recorder.Body.String())
		}
		actor.Permissions = nil
		recorder = httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path+query, nil))
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("permission denial status=%d", recorder.Code)
		}
	}
}

func TestRealtimeMinuteRequiresAuthorityAndPreservesCancellation(t *testing.T) {
	from := time.Date(2026, 9, 25, 10, 17, 0, 0, time.UTC)
	request := RealtimeRequest{Audience: AudiencePlatform, From: from, To: from.Add(time.Minute)}
	actor := Actor{ScopeKind: "platform", Permissions: []string{"platform.admin"}}
	service, _ := NewService(&realtimeStoreFixture{result: validRealtimeResult(from, from.Add(time.Hour))})
	if _, err := service.Realtime(t.Context(), actor, request); !errors.Is(err, ErrRealtimeEvidenceUnavailable) {
		t.Fatalf("minute without independent authority: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := service.Realtime(ctx, actor, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled minute query: %v", err)
	}
}
