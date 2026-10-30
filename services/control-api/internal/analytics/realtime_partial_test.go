package analytics

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// partialRealtimeExpectedEvidence settles the first hour of a six-hour range
// and leaves the remaining five unfinalized.
func partialRealtimeExpectedEvidence(tenantID string, filter RealtimeFilter) RealtimeExpectedEvidence {
	evidence := completeRealtimeExpectedEvidence(tenantID, filter, 12)
	evidence.CoveredWindows = 1
	evidence.FinalizedThrough, evidence.SourceWatermark = filter.From.Add(time.Hour), filter.From.Add(time.Hour)
	for hour := filter.From.Add(time.Hour); hour.Before(filter.To); hour = hour.Add(time.Hour) {
		evidence.MissingWindows = append(evidence.MissingWindows, hour)
	}
	return evidence
}

func TestRealtimePartialCoverageOnlyForMinutePanel(t *testing.T) {
	from := time.Date(2026, 10, 22, 3, 0, 0, 0, time.UTC)
	to := from.Add(6 * time.Hour)
	filter := RealtimeFilter{From: from, To: to}
	actor := Actor{ScopeKind: "tenant", TenantID: rankTenantA, Permissions: []string{ReadPermission}}
	store := &realtimeStoreFixture{result: validRealtimeResult(from, from.Add(time.Hour))}
	reader := &realtimeExpectedCountFixture{evidence: partialRealtimeExpectedEvidence(rankTenantA, filter)}
	service, err := NewServiceWithRealtimeExpectedCounts(store, reader)
	if err != nil {
		t.Fatal(err)
	}
	request := RealtimeRequest{Audience: AudienceTenant, From: from, To: to}
	if _, err := service.Realtime(t.Context(), actor, request); !errors.Is(err, ErrRealtimeEvidenceUnavailable) {
		t.Fatalf("strict caller accepted partial evidence: %v", err)
	}
	request.AllowPartialCoverage = true
	result, err := service.Realtime(t.Context(), actor, request)
	if err != nil {
		t.Fatalf("partial panel read error = %v", err)
	}
	if len(store.filter.ExcludedWindows) != 5 || !store.filter.ExcludedWindows[0].Equal(from.Add(time.Hour)) {
		t.Fatalf("unsettled hours not excluded from facts: %+v", store.filter.ExcludedWindows)
	}
	evidence := result.Evidence
	if evidence.CoverageComplete || evidence.RequestedWindows != 6 || evidence.CoveredWindows != 1 || len(evidence.MissingWindows) != 5 ||
		result.Summary.Requests != 12 || evidence.ErrorPPM != 0 {
		t.Fatalf("partial result = %+v", result)
	}

	// Settled hours keep reconciliation: mismatched counts still fail.
	reader.evidence.ExpectedEvents = 100
	if _, err := service.Realtime(t.Context(), actor, request); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("partial mismatch error = %v", err)
	}
	// Settled hours must still be finalized through their end.
	reader.evidence = partialRealtimeExpectedEvidence(rankTenantA, filter)
	reader.evidence.FinalizedThrough = from
	if _, err := service.Realtime(t.Context(), actor, request); !errors.Is(err, ErrRealtimeEvidenceUnavailable) {
		t.Fatalf("stale settled hour error = %v", err)
	}
	// Missing windows must account for every uncovered hour.
	reader.evidence = partialRealtimeExpectedEvidence(rankTenantA, filter)
	reader.evidence.MissingWindows = reader.evidence.MissingWindows[1:]
	if _, err := service.Realtime(t.Context(), actor, request); !errors.Is(err, ErrRealtimeEvidenceUnavailable) {
		t.Fatalf("inconsistent missing windows error = %v", err)
	}
}

func TestRealtimeNoSettledHourReturnsEmptyUncoveredResult(t *testing.T) {
	from := time.Date(2026, 10, 22, 3, 0, 0, 0, time.UTC)
	to := from.Add(12 * time.Hour)
	filter := RealtimeFilter{From: from, To: to}
	evidence := completeRealtimeExpectedEvidence("", filter, 0)
	epoch := time.Unix(0, 0).UTC()
	evidence.CoveredWindows, evidence.FinalizedThrough, evidence.SourceWatermark = 0, epoch, epoch
	evidence.AccessSourcesExpected, evidence.AccessSourcesFinalized = 0, 0
	evidence.ConnectionSourcesExpected, evidence.ConnectionSourcesFinalized = 0, 0
	for hour := from; hour.Before(to); hour = hour.Add(time.Hour) {
		evidence.MissingWindows = append(evidence.MissingWindows, hour)
	}
	store := &realtimeStoreFixture{result: validRealtimeResult(from, to)}
	service, _ := NewServiceWithRealtimeExpectedCounts(store, &realtimeExpectedCountFixture{evidence: evidence})
	handler, _ := NewHandler(service, func(*http.Request) (Actor, error) {
		return Actor{ScopeKind: "platform", Permissions: []string{"platform.admin"}}, nil
	}, HandlerConfig{})
	query := "from=" + from.Format(time.RFC3339) + "&to=" + to.Format(time.RFC3339)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/admin/analytics/site-realtime?"+query, nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("legacy response status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/admin/analytics/site-realtime?query_version=3&"+query, nil))
	var response struct {
		Data struct {
			Summary  RealtimeMetrics `json:"summary"`
			Series   []RealtimePoint `json:"series"`
			Evidence map[string]any  `json:"evidence"`
		} `json:"data"`
	}
	if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &response) != nil {
		t.Fatalf("panel status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	missing, _ := response.Data.Evidence["missing_windows"].([]any)
	if response.Data.Summary != (RealtimeMetrics{}) || len(response.Data.Series) != 0 ||
		response.Data.Evidence["coverage_complete"] != false || response.Data.Evidence["covered_windows"] != float64(0) ||
		response.Data.Evidence["requested_windows"] != float64(12) || len(missing) != 12 || !store.filter.From.IsZero() {
		t.Fatalf("uncovered panel response=%s store=%+v", recorder.Body.String(), store.filter)
	}
}

func TestPostgresRealtimeExpectedEvidenceReturnsMissingWindows(t *testing.T) {
	from := time.Date(2026, 10, 22, 3, 0, 0, 0, time.UTC)
	to := from.Add(3 * time.Hour)
	settled := from.Add(time.Hour)
	row := func(covered string, missing []time.Time) realtimeEvidenceRowFixture {
		return realtimeEvidenceRowFixture{scan: func(destinations ...any) error {
			for index, value := range []string{"5", "3", covered} {
				*destinations[index].(*string) = value
			}
			*destinations[3].(*bool) = false
			for index, value := range []string{"2", "2", "1", "1"} {
				*destinations[index+4].(*string) = value
			}
			*destinations[8].(**time.Time) = &settled
			*destinations[9].(**time.Time) = &settled
			*destinations[10].(*[]time.Time) = missing
			return nil
		}}
	}
	queryer := &realtimeEvidenceQueryFixture{row: row("1", []time.Time{from.Add(time.Hour), from.Add(2 * time.Hour)})}
	reader := &PostgresRealtimeExpectedCountReader{queryer: queryer}
	evidence, err := reader.ExpectedRealtimeEvidence(t.Context(), AdminScope(), RealtimeFilter{From: from, To: to})
	if err != nil {
		t.Fatalf("partial evidence error = %v", err)
	}
	if evidence.CoveredWindows != 1 || len(evidence.MissingWindows) != 2 || evidence.ExpectedEvents != 5 ||
		!evidence.FinalizedThrough.Equal(settled) {
		t.Fatalf("partial evidence = %+v", evidence)
	}
	for _, token := range []string{"FILTER(WHERE NOT settled.settled)", "JOIN settled ON settled.hour=expected.hour", "GROUP BY expected.hour"} {
		if !strings.Contains(queryer.query, token) {
			t.Errorf("query missing %q", token)
		}
	}
	for name, fixture := range map[string]realtimeEvidenceRowFixture{
		"count mismatch":   row("1", []time.Time{from.Add(time.Hour)}),
		"window outside":   row("1", []time.Time{from.Add(time.Hour), to}),
		"window unordered": row("1", []time.Time{from.Add(2 * time.Hour), from.Add(time.Hour)}),
		"window unaligned": row("1", []time.Time{from.Add(time.Hour), from.Add(2*time.Hour + time.Minute)}),
	} {
		reader := &PostgresRealtimeExpectedCountReader{queryer: &realtimeEvidenceQueryFixture{row: fixture}}
		if _, err := reader.ExpectedRealtimeEvidence(t.Context(), AdminScope(), RealtimeFilter{From: from, To: to}); !errors.Is(err, ErrRealtimeEvidenceUnavailable) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
}

func TestRealtimeClickHouseExcludesUnsettledHours(t *testing.T) {
	from := time.Date(2026, 10, 22, 3, 0, 0, 0, time.UTC)
	excluded := []time.Time{from.Add(time.Hour), from.Add(2 * time.Hour)}
	var query, parameter string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		query, parameter = string(body), request.URL.Query().Get("param_excluded_hours_ms")
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
	_, _ = client.Realtime(t.Context(), AdminScope(), RealtimeFilter{From: from, To: from.Add(3 * time.Hour), ExcludedWindows: excluded})
	want := "[" + strconv.FormatInt(excluded[0].UnixMilli(), 10) + "," + strconv.FormatInt(excluded[1].UnixMilli(), 10) + "]"
	if parameter != want || strings.Count(query, "NOT has({excluded_hours_ms:Array(Int64)}") != 2 {
		t.Fatalf("excluded parameter=%q want %q; access and connection scans must both exclude", parameter, want)
	}
	_, _ = client.Realtime(t.Context(), AdminScope(), RealtimeFilter{From: from, To: from.Add(time.Hour)})
	if parameter != "[]" {
		t.Fatalf("complete coverage excluded parameter=%q", parameter)
	}
}
