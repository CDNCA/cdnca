package analytics

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type realtimeStoreFixture struct {
	scope  Scope
	filter RealtimeFilter
	result RealtimeResult
	err    error
}

type realtimeExpectedCountFixture struct {
	scope    Scope
	filter   RealtimeFilter
	evidence RealtimeExpectedEvidence
	err      error
}

func (reader *realtimeExpectedCountFixture) ExpectedRealtimeEvidence(_ context.Context, scope Scope, filter RealtimeFilter) (RealtimeExpectedEvidence, error) {
	reader.scope, reader.filter = scope, filter
	return reader.evidence, reader.err
}

func (*realtimeStoreFixture) Summary(context.Context, Scope, Filter) (Summary, error) {
	return Summary{}, nil
}
func (*realtimeStoreFixture) Trend(context.Context, Scope, Filter) ([]TrendPoint, error) {
	return nil, nil
}
func (*realtimeStoreFixture) Rank(context.Context, Scope, Filter, RankDimension, uint16, string) (RankPage, error) {
	return RankPage{}, nil
}
func (store *realtimeStoreFixture) Realtime(_ context.Context, scope Scope, filter RealtimeFilter) (RealtimeResult, error) {
	store.scope, store.filter = scope, filter
	return store.result, store.err
}

func TestRealtimeBindsPlatformScopeAndMultipleHosts(t *testing.T) {
	var query string
	var parameters url.Values
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		query, parameters = string(body), request.URL.Query()
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
	from := time.Date(2026, 8, 7, 1, 0, 0, 0, time.UTC)
	filter := RealtimeFilter{From: from, To: from.Add(time.Hour), Host: "cdn.example.test static.example.test"}
	if _, err := client.Realtime(t.Context(), AdminScope(), filter); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("empty ClickHouse response error=%v", err)
	}
	for key, expected := range map[string]string{
		"param_tenant_scoped": "0", "param_tenant_id": nilUUIDValue,
		"param_has_host": "1", "param_host": filter.Host,
	} {
		if actual := parameters.Get(key); actual != expected {
			t.Fatalf("%s=%q want %q", key, actual, expected)
		}
	}
	for _, token := range []string{
		"{tenant_scoped:UInt8}=0", "has(splitByChar(' ',{host:String}),host)",
		"SELECT tenant_id,node_id,domain,listen_port,maxIf(connections,in_range)", "connection_series",
	} {
		if !strings.Contains(query, token) {
			t.Fatalf("realtime query missing %q", token)
		}
	}
	if strings.Contains(query, filter.Host) {
		t.Fatal("host filter was interpolated into ClickHouse SQL")
	}
}

func TestRealtimeUsesSessionTenantScopeAndRequiresCompleteEvidence(t *testing.T) {
	from := time.Date(2026, 8, 7, 1, 0, 0, 0, time.UTC)
	to := from.Add(6 * time.Hour)
	store := &realtimeStoreFixture{result: validRealtimeResult(from, to)}
	service, err := NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	request := RealtimeRequest{Audience: AudienceTenant, From: from, To: to,
		SiteID: "018f0000-0000-7000-8000-000000000002", Host: "cdn.example.test", ListenPort: 443}
	result, err := service.Realtime(t.Context(), Actor{ScopeKind: "tenant",
		TenantID: "018f0000-0000-7000-8000-000000000001", Permissions: []string{ReadPermission}}, request)
	if err != nil {
		t.Fatalf("Realtime() error = %v", err)
	}
	if store.scope.kind != scopeTenant || store.scope.tenantID != "018f0000-0000-7000-8000-000000000001" {
		t.Fatalf("scope = %#v", store.scope)
	}
	if store.filter.Host != "cdn.example.test" || store.filter.ListenPort != 443 || result.Evidence.AccessSourceCount != 12 {
		t.Fatalf("filter/result = %#v %#v", store.filter, result)
	}
	store.result.Evidence.ConnectionSourceCount = 0
	if _, err := service.Realtime(t.Context(), Actor{ScopeKind: "tenant",
		TenantID: "018f0000-0000-7000-8000-000000000001", Permissions: []string{ReadPermission}}, request); !errors.Is(err, ErrRealtimeEvidenceUnavailable) {
		t.Fatalf("missing evidence error = %v", err)
	}
}

func TestRealtimeAllowsPlatformGlobalScopeAndRejectsExcessErrorPPM(t *testing.T) {
	from := time.Date(2026, 8, 7, 1, 0, 0, 0, time.UTC)
	store := &realtimeStoreFixture{result: validRealtimeResult(from, from.Add(time.Hour))}
	service, _ := NewService(store)
	actor := Actor{ScopeKind: "platform", Permissions: []string{"platform.admin"}}
	if _, err := service.Realtime(t.Context(), actor, RealtimeRequest{Audience: AudiencePlatform, From: from, To: from.Add(time.Hour)}); err != nil {
		t.Fatalf("platform global error = %v", err)
	}
	if store.scope.kind != scopeAdmin || store.scope.tenantID != "" {
		t.Fatalf("platform global scope = %#v", store.scope)
	}
	store.result.Evidence.ErrorPPM = maximumRealtimeErrorPPM + 1
	if _, err := service.Realtime(t.Context(), actor, RealtimeRequest{Audience: AudiencePlatform,
		TenantID: "018f0000-0000-7000-8000-000000000001", From: from, To: from.Add(time.Hour)}); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("excess error ppm = %v", err)
	}
}

func TestRealtimeUsesDurableExpectedCountAuthority(t *testing.T) {
	from := time.Date(2026, 8, 7, 1, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	store := &realtimeStoreFixture{result: validRealtimeResult(from, to)}
	store.result.Evidence.ExpectedEvents = 999
	filter := RealtimeFilter{From: from, To: to, SiteID: "018f0000-0000-7000-8000-000000000002", Host: "cdn.example.test", ListenPort: 443}
	reader := &realtimeExpectedCountFixture{evidence: completeRealtimeExpectedEvidence(
		"018f0000-0000-7000-8000-000000000001", filter, store.result.Evidence.ObservedEvents)}
	service, err := NewServiceWithRealtimeExpectedCounts(store, reader)
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Realtime(t.Context(), Actor{ScopeKind: "tenant",
		TenantID: "018f0000-0000-7000-8000-000000000001", Permissions: []string{ReadPermission}},
		RealtimeRequest{Audience: AudienceTenant, From: from, To: to,
			SiteID: "018f0000-0000-7000-8000-000000000002", Host: "cdn.example.test", ListenPort: 443})
	if err != nil {
		t.Fatal(err)
	}
	if result.Evidence.ExpectedEvents != 12 || result.Evidence.ErrorPPM != 0 ||
		reader.scope.kind != scopeTenant || reader.filter.ListenPort != 443 {
		t.Fatalf("durable authority result/reader = %#v %#v %#v", result.Evidence, reader.scope, reader.filter)
	}
}

func TestRealtimeAllowsOnlyDurablyCoveredZeroTraffic(t *testing.T) {
	from := time.Date(2026, 8, 7, 1, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	filter := RealtimeFilter{From: from, To: to, SiteID: "018f0000-0000-7000-8000-000000000002", Host: "cdn.example.test", ListenPort: 443}
	store := &realtimeStoreFixture{result: zeroRealtimeResult()}
	reader := &realtimeExpectedCountFixture{evidence: completeRealtimeExpectedEvidence(
		"018f0000-0000-7000-8000-000000000001", filter, 0)}
	service, err := NewServiceWithRealtimeExpectedCounts(store, reader)
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Realtime(t.Context(), Actor{ScopeKind: "tenant",
		TenantID: "018f0000-0000-7000-8000-000000000001", Permissions: []string{ReadPermission}},
		RealtimeRequest{Audience: AudienceTenant, From: from, To: to, SiteID: filter.SiteID, Host: filter.Host, ListenPort: filter.ListenPort})
	if err != nil {
		t.Fatalf("Realtime() zero traffic error = %v", err)
	}
	if result.Summary.Requests != 0 || result.Evidence.ExpectedEvents != 0 || result.Evidence.ObservedEvents != 0 ||
		!result.Evidence.FinalizedThrough.Equal(to) || !result.Evidence.SourceWatermark.Equal(to) {
		t.Fatalf("zero traffic result = %#v", result)
	}
}

func TestRealtimeZeroTrafficCoverageFailsClosed(t *testing.T) {
	from := time.Date(2026, 8, 7, 1, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	filter := RealtimeFilter{From: from, To: to, SiteID: "018f0000-0000-7000-8000-000000000002", Host: "cdn.example.test", ListenPort: 443}
	tenantID := "018f0000-0000-7000-8000-000000000001"
	tests := []struct {
		name   string
		mutate func(*RealtimeExpectedEvidence)
	}{
		{name: "missing window", mutate: func(value *RealtimeExpectedEvidence) { value.CoveredWindows = 0 }},
		{name: "incomplete access sources", mutate: func(value *RealtimeExpectedEvidence) { value.AccessSourcesFinalized-- }},
		{name: "incomplete connection sources", mutate: func(value *RealtimeExpectedEvidence) { value.ConnectionSourcesFinalized-- }},
		{name: "stale finalization", mutate: func(value *RealtimeExpectedEvidence) { value.FinalizedThrough = from }},
		{name: "stale source watermark", mutate: func(value *RealtimeExpectedEvidence) { value.SourceWatermark = from }},
		{name: "tenant mismatch", mutate: func(value *RealtimeExpectedEvidence) { value.TenantID = "018f0000-0000-7000-8000-000000000009" }},
		{name: "site mismatch", mutate: func(value *RealtimeExpectedEvidence) { value.SiteID = "018f0000-0000-7000-8000-000000000009" }},
		{name: "host mismatch", mutate: func(value *RealtimeExpectedEvidence) { value.Host = "other.example.test" }},
		{name: "port mismatch", mutate: func(value *RealtimeExpectedEvidence) { value.ListenPort = 8443 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evidence := completeRealtimeExpectedEvidence(tenantID, filter, 0)
			test.mutate(&evidence)
			service, err := NewServiceWithRealtimeExpectedCounts(&realtimeStoreFixture{result: zeroRealtimeResult()},
				&realtimeExpectedCountFixture{evidence: evidence})
			if err != nil {
				t.Fatal(err)
			}
			_, err = service.Realtime(t.Context(), Actor{ScopeKind: "tenant", TenantID: tenantID, Permissions: []string{ReadPermission}},
				RealtimeRequest{Audience: AudienceTenant, From: from, To: to, SiteID: filter.SiteID, Host: filter.Host, ListenPort: filter.ListenPort})
			if !errors.Is(err, ErrRealtimeEvidenceUnavailable) {
				t.Fatalf("Realtime() error = %v, want ErrRealtimeEvidenceUnavailable", err)
			}
		})
	}
}

func TestRealtimeProvenEmptyEvidenceReturnsZeroBaseline(t *testing.T) {
	from := time.Date(2026, 8, 7, 1, 0, 0, 0, time.UTC)
	to := from.Add(3 * time.Hour)
	tenantID := "018f0000-0000-7000-8000-000000000001"
	filter := RealtimeFilter{From: from, To: to}
	actor := Actor{ScopeKind: "tenant", TenantID: tenantID, Permissions: []string{ReadPermission}}
	request := RealtimeRequest{Audience: AudienceTenant, From: from, To: to}
	service, err := NewServiceWithRealtimeExpectedCounts(&realtimeStoreFixture{result: zeroRealtimeResult()},
		&realtimeExpectedCountFixture{evidence: provenEmptyRealtimeExpectedEvidence(tenantID, filter)})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Realtime(t.Context(), actor, request)
	if err != nil {
		t.Fatalf("proven empty evidence error = %v", err)
	}
	if result.Summary != (RealtimeMetrics{}) || len(result.Series) != 0 || len(result.Top) != 0 ||
		result.Evidence.ExpectedEvents != 0 || result.Evidence.ObservedEvents != 0 || result.Evidence.ErrorPPM != 0 ||
		result.Evidence.AccessSourceCount != 0 || result.Evidence.ConnectionSourceCount != 0 ||
		!result.Evidence.FinalizedThrough.Equal(to) || !result.Evidence.SourceWatermark.Equal(to) {
		t.Fatalf("proven empty result = %#v", result)
	}
}

func TestRealtimeProvenEmptyEvidenceFailsClosed(t *testing.T) {
	from := time.Date(2026, 8, 7, 1, 0, 0, 0, time.UTC)
	to := from.Add(3 * time.Hour)
	tenantID := "018f0000-0000-7000-8000-000000000001"
	filter := RealtimeFilter{From: from, To: to}
	actor := Actor{ScopeKind: "tenant", TenantID: tenantID, Permissions: []string{ReadPermission}}
	request := RealtimeRequest{Audience: AudienceTenant, From: from, To: to}
	tests := []struct {
		name     string
		evidence func(*RealtimeExpectedEvidence)
		result   func(*RealtimeResult)
	}{
		{name: "expected events without sources", evidence: func(value *RealtimeExpectedEvidence) { value.ExpectedEvents = 1 }},
		{name: "uncovered window", evidence: func(value *RealtimeExpectedEvidence) { value.CoveredWindows-- }},
		{name: "access sources without connection sources", evidence: func(value *RealtimeExpectedEvidence) {
			value.AccessSourcesExpected, value.AccessSourcesFinalized = 1, 1
		}},
		{name: "connection sources without access sources", evidence: func(value *RealtimeExpectedEvidence) {
			value.ConnectionSourcesExpected, value.ConnectionSourcesFinalized = 1, 1
		}},
		{name: "unfinished hour", evidence: func(value *RealtimeExpectedEvidence) { value.FinalizedThrough = to.Add(-time.Hour) }},
		{name: "observed access events", result: func(value *RealtimeResult) { value.Evidence.ObservedEvents = 1 }},
		{name: "observed connection receipts", result: func(value *RealtimeResult) { value.Evidence.ConnectionSourceCount = 1 }},
		{name: "observed connections", result: func(value *RealtimeResult) { value.Summary.Connections = 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evidence, result := provenEmptyRealtimeExpectedEvidence(tenantID, filter), zeroRealtimeResult()
			if test.evidence != nil {
				test.evidence(&evidence)
			}
			if test.result != nil {
				test.result(&result)
			}
			service, err := NewServiceWithRealtimeExpectedCounts(&realtimeStoreFixture{result: result},
				&realtimeExpectedCountFixture{evidence: evidence})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := service.Realtime(t.Context(), actor, request); !errors.Is(err, ErrRealtimeEvidenceUnavailable) {
				t.Fatalf("Realtime() error = %v, want ErrRealtimeEvidenceUnavailable", err)
			}
		})
	}
}

func provenEmptyRealtimeExpectedEvidence(tenantID string, filter RealtimeFilter) RealtimeExpectedEvidence {
	evidence := completeRealtimeExpectedEvidence(tenantID, filter, 0)
	evidence.AccessSourcesExpected, evidence.AccessSourcesFinalized = 0, 0
	evidence.ConnectionSourcesExpected, evidence.ConnectionSourcesFinalized = 0, 0
	return evidence
}

func TestRealtimeDependencyFailuresAndNonzeroMismatchRemainClosed(t *testing.T) {
	from := time.Date(2026, 8, 7, 1, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	request := RealtimeRequest{Audience: AudienceTenant, From: from, To: to}
	actor := Actor{ScopeKind: "tenant", TenantID: "018f0000-0000-7000-8000-000000000001", Permissions: []string{ReadPermission}}

	clickHouseService, _ := NewService(&realtimeStoreFixture{err: fmt.Errorf("%w: clickhouse unavailable", ErrTransport)})
	if _, err := clickHouseService.Realtime(t.Context(), actor, request); !errors.Is(err, ErrRealtimeEvidenceUnavailable) {
		t.Fatalf("ClickHouse dependency error = %v", err)
	}

	filter := RealtimeFilter{From: from, To: to}
	pgService, _ := NewServiceWithRealtimeExpectedCounts(&realtimeStoreFixture{result: validRealtimeResult(from, to)},
		&realtimeExpectedCountFixture{err: fmt.Errorf("%w: postgres unavailable", ErrRealtimeEvidenceUnavailable)})
	if _, err := pgService.Realtime(t.Context(), actor, request); !errors.Is(err, ErrRealtimeEvidenceUnavailable) {
		t.Fatalf("PostgreSQL dependency error = %v", err)
	}

	mismatch := completeRealtimeExpectedEvidence(actor.TenantID, filter, 10)
	mismatchService, _ := NewServiceWithRealtimeExpectedCounts(&realtimeStoreFixture{result: validRealtimeResult(from, to)},
		&realtimeExpectedCountFixture{evidence: mismatch})
	if _, err := mismatchService.Realtime(t.Context(), actor, request); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("nonzero expected/observed mismatch error = %v", err)
	}
}

func completeRealtimeExpectedEvidence(tenantID string, filter RealtimeFilter, expected uint64) RealtimeExpectedEvidence {
	windows := uint16(filter.To.Sub(filter.From) / time.Hour)
	return RealtimeExpectedEvidence{
		TenantID: tenantID, From: filter.From, To: filter.To, SiteID: filter.SiteID, Host: filter.Host, ListenPort: filter.ListenPort,
		ExpectedEvents: expected, RequestedWindows: windows, CoveredWindows: windows,
		AccessSourcesExpected: 2, AccessSourcesFinalized: 2, ConnectionSourcesExpected: 1, ConnectionSourcesFinalized: 1,
		FinalizedThrough: filter.To, SourceWatermark: filter.To,
	}
}

func zeroRealtimeResult() RealtimeResult {
	return RealtimeResult{MetricVersion: MetricVersion, Series: []RealtimePoint{}, Top: []RealtimeTopItem{}}
}

func TestAccessEventListenPortKeepsLegacyZeroAndProductionPort(t *testing.T) {
	event := validAccessEvent("realtime-port")
	event.ListenPort = 0
	if err := validateAccessEvent(event); err != nil {
		t.Fatalf("legacy port: %v", err)
	}
	event.ListenPort = 443
	if err := validateAccessEvent(event); err != nil {
		t.Fatalf("port 443: %v", err)
	}
}

func validRealtimeResult(from, to time.Time) RealtimeResult {
	return RealtimeResult{MetricVersion: MetricVersion,
		Summary: RealtimeMetrics{Requests: 12, TrafficBytes: 1200, BandwidthBPS: 160, Connections: 3,
			Status2xx: 10, Status4xx: 1, Status5xx: 1, CacheHits: 8, CacheMisses: 4, Errors: 1,
			AverageDurationUS: 200, OriginConnectUS: 20, OriginFirstByteUS: 60, OriginTotalUS: 100},
		Series: []RealtimePoint{{Bucket: from, Requests: 12, TrafficBytes: 1200, Connections: 3}},
		Top:    []RealtimeTopItem{{Host: "cdn.example.test", ListenPort: 443, Requests: 12, TrafficBytes: 1200}},
		Evidence: RealtimeEvidence{AccessSourceCount: 12, ConnectionSourceCount: 1, ExpectedEvents: 12,
			ObservedEvents: 12, FinalizedThrough: to, SourceWatermark: to}}
}
