package analytics

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsrealtime"
)

var _ analyticsrealtime.Source = (*RealtimeV2Source)(nil)

const (
	realtimeV2TenantID = "018f0000-0000-7000-8000-000000000001"
	realtimeV2SiteID   = "018f0000-0000-7000-8000-000000000002"
	realtimeV2NodeID   = "018f0000-0000-7000-8000-000000000003"
)

type realtimeV2Call struct {
	query      string
	parameters url.Values
}

type realtimeV2CoverageFixture struct {
	err   error
	calls int
}

func (fixture *realtimeV2CoverageFixture) RealtimeV2Coverage(
	_ context.Context,
	scope analyticsrealtime.Scope,
	filter analyticsrealtime.Filter,
) (RealtimeV2CoverageAuthority, error) {
	fixture.calls++
	if fixture.err != nil {
		return RealtimeV2CoverageAuthority{}, fixture.err
	}
	sourceWatermark := filter.To.Add(time.Minute)
	coverageFrom := filter.From.Truncate(time.Hour)
	coverageTo := filter.To.Truncate(time.Hour)
	if !filter.To.Equal(coverageTo) {
		coverageTo = coverageTo.Add(time.Hour)
	}
	windows := uint16(coverageTo.Sub(coverageFrom) / time.Hour)
	return RealtimeV2CoverageAuthority{
		TenantID: scope.TenantID, From: filter.From, To: filter.To, SiteID: filter.SiteID,
		Domain: filter.Domain, ListenPort: filter.ListenPort,
		RequestedWindows: windows, CoveredWindows: windows, ExpectedDimensions: uint64(windows), CoveredDimensions: uint64(windows),
		AccessSourcesExpected: uint64(windows), AccessSourcesFinalized: uint64(windows),
		ConnectionSourcesExpected: uint64(windows), ConnectionSourcesFinalized: uint64(windows),
		FinalizedThrough: coverageTo, SourceWatermark: sourceWatermark,
	}, nil
}

func TestRealtimeV2SourceUsesOneAuthoritativeSnapshotAcrossSections(t *testing.T) {
	filter := realtimeV2Filter()
	snapshot := realtimeV2Snapshot(filter)
	var calls []realtimeV2Call
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		encoded, _ := io.ReadAll(request.Body)
		calls = append(calls, realtimeV2Call{query: string(encoded), parameters: request.URL.Query()})
		switch len(calls) {
		case 1:
			_, _ = io.WriteString(writer, realtimeV2SnapshotRow(snapshot))
		case 2:
			_, _ = io.WriteString(writer,
				realtimeV2BasicSummaryRow(snapshot, 2, 3)+
					realtimeV2BasicPointRow(snapshot, filter.From, 1)+
					realtimeV2BasicPointRow(snapshot, filter.From.Add(filter.Bucket), 2))
		case 3:
			_, _ = io.WriteString(writer,
				realtimeV2QualitySummaryRow(snapshot, 2)+
					realtimeV2QualityPointRow(snapshot, filter.From))
		case 4:
			_, _ = io.WriteString(writer,
				realtimeV2OriginSummaryRow(snapshot, 2)+
					realtimeV2OriginPointRow(snapshot, filter.From))
		case 5:
			_, _ = io.WriteString(writer,
				realtimeV2RankRow(snapshot, 2, "a.example.test", 3, 300)+
					realtimeV2RankRow(snapshot, 2, "b.example.test", 2, 200))
		default:
			t.Errorf("unexpected storage call %d", len(calls))
		}
	}))
	t.Cleanup(server.Close)
	source := newRealtimeV2TestSource(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
	scope := analyticsrealtime.Scope{TenantID: realtimeV2TenantID}

	resolved, err := source.ResolveSnapshot(t.Context(), scope, filter)
	if err != nil || resolved != snapshot {
		t.Fatalf("ResolveSnapshot() = %#v, %v; want %#v", resolved, err, snapshot)
	}
	filter.Snapshot = resolved
	basic, err := source.LoadBasic(t.Context(), scope, filter)
	if err != nil || basic.FactCount != 2 || basic.Requests != 3 || basic.Connections != 3 || len(basic.Series) != 2 {
		t.Fatalf("LoadBasic() = %#v, %v", basic, err)
	}
	quality, err := source.LoadQuality(t.Context(), scope, filter)
	if err != nil || quality.FactCount != 2 || quality.Status2xx != 2 || len(quality.Series) != 1 {
		t.Fatalf("LoadQuality() = %#v, %v", quality, err)
	}
	origin, err := source.LoadOrigin(t.Context(), scope, filter)
	if err != nil || origin.FactCount != 2 || origin.ConnectUS != 10 || len(origin.Series) != 1 {
		t.Fatalf("LoadOrigin() = %#v, %v", origin, err)
	}
	rank, err := source.LoadRank(t.Context(), scope, filter)
	if err != nil || rank.FactCount != 2 || len(rank.Items) != 2 || rank.Items[0].Key != "a.example.test" || rank.HasMore {
		t.Fatalf("LoadRank() = %#v, %v", rank, err)
	}

	if len(calls) != 5 {
		t.Fatalf("storage calls = %d, want 5", len(calls))
	}
	assertRealtimeV2SnapshotSQL(t, calls[0].query)
	wantSnapshot := strconv.FormatInt(snapshot.At.UnixMilli(), 10)
	for index, call := range calls[1:] {
		if got := call.parameters.Get("param_snapshot_ms"); got != wantSnapshot {
			t.Errorf("section %d snapshot = %q, want %q", index, got, wantSnapshot)
		}
		assertRealtimeV2AccessSQL(t, call.query)
		assertRealtimeV2Parameters(t, call.parameters, filter)
	}
	assertRealtimeV2ConnectionsSQL(t, calls[1].query)
	if strings.Contains(calls[2].query+calls[3].query+calls[4].query, "connections_ingest_receipts_v1") {
		t.Fatal("non-basic section queried connection receipts")
	}
}

func TestRealtimeV2SourceRejectsMalformedOrMismatchedFacts(t *testing.T) {
	filter := realtimeV2Filter()
	filter.Snapshot = realtimeV2Snapshot(filter)
	tests := []struct {
		name     string
		response string
		call     func(*RealtimeV2Source) error
		want     error
	}{
		{
			name:     "unknown field",
			response: strings.TrimSuffix(realtimeV2QualitySummaryRow(filter.Snapshot, 1), "}\n") + `,"raw_secret":"must-not-pass"}` + "\n",
			call: func(source *RealtimeV2Source) error {
				_, err := source.LoadQuality(t.Context(), analyticsrealtime.Scope{TenantID: realtimeV2TenantID}, filter)
				return err
			},
			want: analyticsrealtime.ErrInvalidResponse,
		},
		{
			name: "snapshot mismatch",
			response: realtimeV2OriginSummaryRow(analyticsrealtime.Snapshot{
				At: filter.Snapshot.At.Add(time.Millisecond), SourceWatermark: filter.Snapshot.SourceWatermark,
				FinalizedThrough: filter.Snapshot.FinalizedThrough, ExpiresAt: filter.Snapshot.ExpiresAt,
			}, 1),
			call: func(source *RealtimeV2Source) error {
				_, err := source.LoadOrigin(t.Context(), analyticsrealtime.Scope{TenantID: realtimeV2TenantID}, filter)
				return err
			},
			want: analyticsrealtime.ErrInvalidSnapshot,
		},
		{
			name:     "missing connection authority",
			response: realtimeV2BasicSummaryRow(filter.Snapshot, 1, -1),
			call: func(source *RealtimeV2Source) error {
				_, err := source.LoadBasic(t.Context(), analyticsrealtime.Scope{TenantID: realtimeV2TenantID}, filter)
				return err
			},
			want: analyticsrealtime.ErrDependencyUnavailable,
		},
		{
			name: "rank row budget",
			response: realtimeV2RankRow(filter.Snapshot, 4, "a.example.test", 4, 400) +
				realtimeV2RankRow(filter.Snapshot, 4, "b.example.test", 3, 300) +
				realtimeV2RankRow(filter.Snapshot, 4, "c.example.test", 2, 200) +
				realtimeV2RankRow(filter.Snapshot, 4, "d.example.test", 1, 100),
			call: func(source *RealtimeV2Source) error {
				bounded := filter
				bounded.Limit = 2
				_, err := source.LoadRank(t.Context(), analyticsrealtime.Scope{TenantID: realtimeV2TenantID}, bounded)
				return err
			},
			want: analyticsrealtime.ErrInvalidResponse,
		},
		{
			name: "rank order",
			response: realtimeV2RankRow(filter.Snapshot, 2, "smaller.example.test", 1, 100) +
				realtimeV2RankRow(filter.Snapshot, 2, "larger.example.test", 2, 200),
			call: func(source *RealtimeV2Source) error {
				_, err := source.LoadRank(t.Context(), analyticsrealtime.Scope{TenantID: realtimeV2TenantID}, filter)
				return err
			},
			want: analyticsrealtime.ErrInvalidResponse,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(writer, test.response)
			}))
			t.Cleanup(server.Close)
			source := newRealtimeV2TestSource(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
			if err := test.call(source); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestRealtimeV2SourcePreservesContextAndHidesTransportDetails(t *testing.T) {
	filter := realtimeV2Filter()
	filter.Snapshot = realtimeV2Snapshot(filter)
	requests := 0
	client := mustClient(t, Config{Endpoint: "https://analytics.example.test", Database: "analytics_test"}, realtimeV2HTTPClientFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return nil, errors.New("storage-password-must-not-leak")
	}))
	source, err := NewRealtimeV2Source(client, new(realtimeV2CoverageFixture))
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := source.LoadQuality(canceled, analyticsrealtime.Scope{TenantID: realtimeV2TenantID}, filter); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled error = %v", err)
	}
	_, err = source.LoadQuality(context.Background(), analyticsrealtime.Scope{TenantID: realtimeV2TenantID}, filter)
	if !errors.Is(err, analyticsrealtime.ErrDependencyUnavailable) || strings.Contains(err.Error(), "storage-password") {
		t.Fatalf("transport error = %v", err)
	}
	if requests != 1 {
		t.Fatalf("transport calls = %d, want 1", requests)
	}
}

func TestRealtimeV2SourceRequiresCoverageBeforeClickHouse(t *testing.T) {
	requests := 0
	client := mustClient(t, Config{Endpoint: "https://analytics.example.test", Database: "analytics_test"}, realtimeV2HTTPClientFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return nil, errors.New("ClickHouse must not be reached")
	}))
	coverage := &realtimeV2CoverageFixture{err: analyticsrealtime.ErrDependencyUnavailable}
	source, err := NewRealtimeV2Source(client, coverage)
	if err != nil {
		t.Fatal(err)
	}
	_, err = source.ResolveSnapshot(t.Context(), analyticsrealtime.Scope{TenantID: realtimeV2TenantID}, realtimeV2Filter())
	if !errors.Is(err, analyticsrealtime.ErrDependencyUnavailable) || requests != 0 || coverage.calls != 1 {
		t.Fatalf("coverage error=%v ClickHouse requests=%d coverage calls=%d", err, requests, coverage.calls)
	}
}

type realtimeV2HTTPClientFunc func(*http.Request) (*http.Response, error)

func (do realtimeV2HTTPClientFunc) Do(request *http.Request) (*http.Response, error) {
	return do(request)
}

func newRealtimeV2TestSource(t *testing.T, config Config, httpClient HTTPClient) *RealtimeV2Source {
	t.Helper()
	client := mustClient(t, config, httpClient)
	source, err := NewRealtimeV2Source(client, new(realtimeV2CoverageFixture))
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func realtimeV2Filter() analyticsrealtime.Filter {
	from := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	return analyticsrealtime.Filter{
		From: from, To: from.Add(2 * time.Hour), Timezone: "Asia/Shanghai", SiteID: realtimeV2SiteID,
		Bucket: time.Minute, RankBy: analyticsrealtime.RankByHost, Limit: 2,
	}
}

func realtimeV2Snapshot(filter analyticsrealtime.Filter) analyticsrealtime.Snapshot {
	at := filter.To.Add(time.Minute).Truncate(time.Millisecond)
	return analyticsrealtime.Snapshot{
		At: at, SourceWatermark: uint64(at.UnixMilli()), FinalizedThrough: filter.To,
		ExpiresAt: at.Add(5 * time.Minute),
	}
}

func realtimeV2SnapshotRow(snapshot analyticsrealtime.Snapshot) string {
	return `{"snapshot_ms":` + strconv.FormatInt(snapshot.At.UnixMilli(), 10) +
		`,"expires_at_ms":` + strconv.FormatInt(snapshot.ExpiresAt.UnixMilli(), 10) + "}\n"
}

func realtimeV2BasicSummaryRow(snapshot analyticsrealtime.Snapshot, factCount uint64, connections int64) string {
	connection := strconv.FormatInt(connections, 10)
	if connections < 0 {
		connection = "null"
	}
	return `{"kind":"summary","snapshot_ms":` + strconv.FormatInt(snapshot.At.UnixMilli(), 10) +
		`,"fact_count":` + strconv.FormatUint(factCount, 10) +
		`,"requests":3,"traffic_bytes":300,"bandwidth_bps":10,"connections":` + connection +
		`,"connection_finalized_through_ms":` + strconv.FormatInt(snapshot.FinalizedThrough.UnixMilli(), 10) + "}\n"
}

func realtimeV2BasicPointRow(snapshot analyticsrealtime.Snapshot, bucket time.Time, requests uint64) string {
	return `{"kind":"series","snapshot_ms":` + strconv.FormatInt(snapshot.At.UnixMilli(), 10) +
		`,"bucket_ms":` + strconv.FormatInt(bucket.UnixMilli(), 10) +
		`,"requests":` + strconv.FormatUint(requests, 10) + `,"traffic_bytes":100,"bandwidth_bps":2,"connections":1}` + "\n"
}

func realtimeV2QualitySummaryRow(snapshot analyticsrealtime.Snapshot, factCount uint64) string {
	return `{"kind":"summary","snapshot_ms":` + strconv.FormatInt(snapshot.At.UnixMilli(), 10) +
		`,"fact_count":` + strconv.FormatUint(factCount, 10) +
		`,"status_2xx":2,"status_3xx":0,"status_4xx":0,"status_5xx":0,"cache_hits":1,"cache_misses":1,"errors":0,"average_duration_us":10}` + "\n"
}

func realtimeV2QualityPointRow(snapshot analyticsrealtime.Snapshot, bucket time.Time) string {
	return `{"kind":"series","snapshot_ms":` + strconv.FormatInt(snapshot.At.UnixMilli(), 10) +
		`,"bucket_ms":` + strconv.FormatInt(bucket.UnixMilli(), 10) +
		`,"status_2xx":2,"status_3xx":0,"status_4xx":0,"status_5xx":0}` + "\n"
}

func realtimeV2OriginSummaryRow(snapshot analyticsrealtime.Snapshot, factCount uint64) string {
	return `{"kind":"summary","snapshot_ms":` + strconv.FormatInt(snapshot.At.UnixMilli(), 10) +
		`,"fact_count":` + strconv.FormatUint(factCount, 10) +
		`,"connect_us":10,"first_byte_us":20,"total_us":30}` + "\n"
}

func realtimeV2OriginPointRow(snapshot analyticsrealtime.Snapshot, bucket time.Time) string {
	return `{"kind":"series","snapshot_ms":` + strconv.FormatInt(snapshot.At.UnixMilli(), 10) +
		`,"bucket_ms":` + strconv.FormatInt(bucket.UnixMilli(), 10) +
		`,"connect_us":10,"first_byte_us":20,"total_us":30}` + "\n"
}

func realtimeV2RankRow(snapshot analyticsrealtime.Snapshot, factCount uint64, key string, requests, traffic uint64) string {
	return `{"snapshot_ms":` + strconv.FormatInt(snapshot.At.UnixMilli(), 10) +
		`,"fact_count":` + strconv.FormatUint(factCount, 10) + `,"key":"` + key + `","label":"` + key +
		`","requests":` + strconv.FormatUint(requests, 10) + `,"traffic_bytes":` + strconv.FormatUint(traffic, 10) + "}\n"
}

func assertRealtimeV2SnapshotSQL(t *testing.T, query string) {
	t.Helper()
	for _, token := range []string{
		"site_realtime_access_facts_v1 FINAL", "ingested_at AS snapshot_at", "updated_at AS snapshot_at", "max(snapshot_at)",
	} {
		if !strings.Contains(query, token) {
			t.Errorf("snapshot SQL missing %q: %s", token, query)
		}
	}
}

func assertRealtimeV2AccessSQL(t *testing.T, query string) {
	t.Helper()
	for _, token := range []string{
		"site_realtime_access_facts_v1 FINAL", "JOIN access_events FINAL", "event_id", "node_id",
		"{tenant_id:UUID}", "{has_site:UInt8}", "{site_id:UUID}", "{has_node:UInt8}", "{node_id:UUID}",
		"{has_domain:UInt8}", "{domain:String}", "{has_port:UInt8}", "{listen_port:UInt16}",
		"{from_ms:UInt64}", "{to_ms:UInt64}", "{snapshot_ms:UInt64}",
	} {
		if !strings.Contains(query, token) {
			t.Errorf("section SQL missing %q: %s", token, query)
		}
	}
	if strings.Count(query, "fromUnixTimestamp64Milli({snapshot_ms:UInt64}, 'UTC')") < 2 {
		t.Errorf("section SQL does not fence both facts and node authority: %s", query)
	}
	if strings.Contains(query, "facts.source_watermark") || strings.Contains(query, "facts.finalized_through") {
		t.Errorf("access facts still self-assert source coverage: %s", query)
	}
}

func assertRealtimeV2ConnectionsSQL(t *testing.T, query string) {
	t.Helper()
	for _, token := range []string{
		"connections_ingest_receipts_v1 FINAL", "state_rank >= 2",
		"updated_at <= fromUnixTimestamp64Milli({snapshot_ms:UInt64}, 'UTC')",
		"node_id != toUUID", "domain != ''", "listen_port BETWEEN 1 AND 65535",
	} {
		if !strings.Contains(query, token) {
			t.Errorf("basic SQL missing %q: %s", token, query)
		}
	}
}

func assertRealtimeV2Parameters(t *testing.T, parameters url.Values, filter analyticsrealtime.Filter) {
	t.Helper()
	checks := map[string]string{
		"param_tenant_id": realtimeV2TenantID, "param_from_ms": strconv.FormatInt(filter.From.UnixMilli(), 10),
		"param_to_ms": strconv.FormatInt(filter.To.UnixMilli(), 10), "param_timezone": filter.Timezone,
		"param_has_site": "1", "param_site_id": realtimeV2SiteID, "param_has_node": "0",
		"param_has_domain": "0", "param_has_port": "0", "param_bucket_ms": strconv.FormatInt(filter.Bucket.Milliseconds(), 10),
	}
	for key, want := range checks {
		if got := parameters.Get(key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
}
