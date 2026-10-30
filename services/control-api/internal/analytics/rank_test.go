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
	"sync"
	"testing"
	"time"
)

func TestRankUsesFixedParameterizedQueries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		dimension RankDimension
		wantIndex string
	}{
		{dimension: RankByURL, wantIndex: "tupleElement(latest, 4)"},
		{dimension: RankByIP, wantIndex: "tupleElement(latest, 5)"},
		{dimension: RankByDomain, wantIndex: "tupleElement(latest, 6)"},
		{dimension: RankByRegion, wantIndex: "tupleElement(latest, 7)"},
		{dimension: RankByCarrier, wantIndex: "tupleElement(latest, 8)"},
		{dimension: RankByJA4, wantIndex: "tupleElement(latest, 9)"},
	}
	for _, test := range tests {
		t.Run(string(test.dimension), func(t *testing.T) {
			t.Parallel()
			var body string
			var parameters url.Values
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				encoded, _ := io.ReadAll(request.Body)
				body = string(encoded)
				parameters = request.URL.Query()
				_, _ = io.WriteString(writer, `{"key":"value","request_count":2,"response_bytes":100}`+"\n")
			}))
			defer server.Close()
			client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
			scope, err := TenantScope(testTenantID)
			if err != nil {
				t.Fatal(err)
			}
			filter := validFilter()
			filter.SiteID = testSiteID
			filter.Domain = "cdn.example.test"
			filter.NodeID = testNodeID
			page, err := client.Rank(context.Background(), scope, filter, test.dimension, 10, "")
			if err != nil {
				t.Fatal(err)
			}
			if len(page.Items) != 1 || page.Items[0].Key != "value" || page.SnapshotAt.Location() != time.UTC {
				t.Fatalf("page = %#v", page)
			}
			if !strings.Contains(body, test.wantIndex) || !strings.Contains(body, "GROUP BY tenant_id, event_id") ||
				!strings.Contains(body, "ORDER BY response_bytes DESC, request_count DESC, key ASC") {
				t.Fatalf("unexpected SQL: %s", body)
			}
			for _, value := range []string{testTenantID, testSiteID, testNodeID, filter.Domain} {
				if strings.Contains(body, value) {
					t.Fatalf("SQL interpolated %q", value)
				}
			}
			checks := map[string]string{
				"param_tenant_scoped": "1", "param_tenant_id": testTenantID,
				"param_has_site": "1", "param_site_id": testSiteID,
				"param_has_domain": "1", "param_domain": filter.Domain,
				"param_has_node": "1", "param_node_id": testNodeID,
				"param_row_limit": "11", "param_has_cursor": "0",
			}
			for key, expected := range checks {
				if actual := parameters.Get(key); actual != expected {
					t.Fatalf("%s = %q, want %q", key, actual, expected)
				}
			}
			if snapshot, err := strconv.ParseInt(parameters.Get("param_snapshot_ms"), 10, 64); err != nil || snapshot <= 0 {
				t.Fatalf("snapshot = %q", parameters.Get("param_snapshot_ms"))
			}
		})
	}
}

func TestRankAcceptsMinuteAlignedWindows(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, `{"key":"example.test","request_count":1,"response_bytes":1}`+"\n")
	}))
	defer server.Close()
	client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
	filter := validFilter()
	filter.From = time.Date(2099, 1, 1, 0, 10, 0, 0, time.UTC)
	filter.To = filter.From.Add(10 * time.Minute)
	if _, err := client.Rank(context.Background(), AdminScope(), filter, RankByDomain, 10, ""); err != nil {
		t.Fatalf("minute-aligned rank error = %v", err)
	}
}

func TestRankAppliesWindowAndAuthorityAfterLatestReplacement(t *testing.T) {
	t.Parallel()
	for _, dimension := range []RankDimension{
		RankByURL, RankByIP, RankByDomain, RankByRegion, RankByCarrier, RankByJA4,
		RankByProvince, RankByBrowser, RankByOS,
	} {
		query, ok := rankQuery(dimension)
		if !ok {
			t.Fatalf("no query for %s", dimension)
		}
		path := "path"
		if HistoryRankable(dimension) {
			path = "''"
		}
		t.Run(string(dimension), func(t *testing.T) {
			t.Parallel()
			winner := strings.Index(query, "argMax(")
			row := strings.Index(query, "tuple(occurred_at, site_id, node_id, "+path+", client_ip, host, country_code, carrier")
			tieBreak := strings.Index(query, "tuple(ingested_at, occurred_at, site_id, node_id, "+path+", client_ip, host, country_code, carrier")
			latest := strings.Index(query, "GROUP BY tenant_id, event_id")
			window := strings.Index(query, "tupleElement(latest, 1) >= fromUnixTimestamp64Milli")
			authority := strings.Index(query, "tupleElement(latest, 2) = toUUID")
			if winner < 0 || row < winner || tieBreak < row || latest < tieBreak || window < latest || authority < latest {
				t.Fatalf("rank query filters before selecting deterministic latest replacement: %s", query)
			}
		})
	}
}

func TestRankCursorKeepsSnapshotAndOrderBoundary(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var calls []url.Values
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		calls = append(calls, request.URL.Query())
		call := len(calls)
		mu.Unlock()
		if call == 1 {
			_, _ = io.WriteString(writer,
				`{"key":"/a","request_count":5,"response_bytes":500}`+"\n"+
					`{"key":"/b","request_count":4,"response_bytes":400}`+"\n"+
					`{"key":"/c","request_count":3,"response_bytes":300}`+"\n")
			return
		}
		_, _ = io.WriteString(writer, `{"key":"/c","request_count":3,"response_bytes":300}`+"\n")
	}))
	defer server.Close()
	client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
	filter := validFilter()
	first, err := client.Rank(context.Background(), AdminScope(), filter, RankByURL, 2, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Items) != 2 || first.NextCursor == "" {
		t.Fatalf("first page = %#v", first)
	}
	second, err := client.Rank(context.Background(), AdminScope(), filter, RankByURL, 2, first.NextCursor)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Items) != 1 || second.Items[0].Key != "/c" || !second.SnapshotAt.Equal(first.SnapshotAt) {
		t.Fatalf("second page = %#v", second)
	}
	if calls[1].Get("param_snapshot_ms") != calls[0].Get("param_snapshot_ms") ||
		calls[1].Get("param_has_cursor") != "1" || calls[1].Get("param_cursor_response_bytes") != "400" ||
		calls[1].Get("param_cursor_request_count") != "4" || calls[1].Get("param_cursor_key") != "/b" {
		t.Fatalf("second parameters = %v", calls[1])
	}

	changed := filter
	changed.NodeID = testNodeID
	if _, err := client.Rank(context.Background(), AdminScope(), changed, RankByURL, 2, first.NextCursor); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("changed-filter cursor error = %v", err)
	}
	state, err := decodeRankCursor(first.NextCursor, rankFingerprint(AdminScope(), filter, RankByURL))
	if err != nil {
		t.Fatal(err)
	}
	state.SnapshotMilli = time.Now().UTC().Add(2 * time.Minute).UnixMilli()
	futureCursor, err := encodeRankCursor(state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Rank(context.Background(), AdminScope(), filter, RankByURL, 2, futureCursor); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("future cursor error = %v", err)
	}
}

func TestRankRejectsUnknownDimensionAndBadCursor(t *testing.T) {
	t.Parallel()
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests++ }))
	defer server.Close()
	client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
	if _, err := client.Rank(context.Background(), AdminScope(), validFilter(), RankDimension("unknown"), 10, ""); !errors.Is(err, ErrDimensionUnsupported) {
		t.Fatalf("unknown dimension error = %v", err)
	}
	if _, err := client.Rank(context.Background(), AdminScope(), validFilter(), RankByURL, 0, ""); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("limit error = %v", err)
	}
	if _, err := client.Rank(context.Background(), AdminScope(), validFilter(), RankByURL, 10, "not-base64!"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("cursor error = %v", err)
	}
	if requests != 0 {
		t.Fatalf("storage requests = %d", requests)
	}
}

func TestRankByJA4ProjectsMissingFingerprintsAsUnknown(t *testing.T) {
	t.Parallel()
	for _, fragment := range []string{
		"ifNull(nullIf(tupleElement(latest, 9), ''), '__unknown__') AS key",
		"tuple(occurred_at, site_id, node_id, path, client_ip, host, country_code, carrier, ja4, response_bytes, listen_port)",
		"tuple(ingested_at, occurred_at, site_id, node_id, path, client_ip, host, country_code, carrier, ifNull(ja4, ''), response_bytes, listen_port)",
		"sum(tupleElement(latest, 10))",
	} {
		if !strings.Contains(rankByJA4SQL, fragment) {
			t.Fatalf("JA4 query missing %q: %s", fragment, rankByJA4SQL)
		}
	}
}

func TestRankRefererBindsCanonicalDomainsAndListenPort(t *testing.T) {
	t.Parallel()
	var query string
	var parameters url.Values
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		query, parameters = string(body), request.URL.Query()
		_, _ = io.WriteString(writer, `{"key":"https://source.example/path","request_count":2,"response_bytes":100}`+"\n")
	}))
	defer server.Close()
	client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
	filter := validFilter()
	filter.Domain = "CDN.Example.Test. cdn.example.test STATIC.example.test"
	filter.ListenPort = 443
	page, err := client.Rank(context.Background(), AdminScope(), filter, RankByReferer, 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].Key != "https://source.example/path" {
		t.Fatalf("page = %#v", page)
	}
	for key, expected := range map[string]string{
		"param_has_domain": "1", "param_domain": "cdn.example.test static.example.test",
		"param_has_listen_port": "1", "param_listen_port": "443",
	} {
		if actual := parameters.Get(key); actual != expected {
			t.Fatalf("%s = %q, want %q", key, actual, expected)
		}
	}
	for _, token := range []string{
		"lower(header_name) = 'referer'", "mapValues(tupleElement(latest, 11))",
		"mapKeys(tupleElement(latest, 11))", "has(splitByChar(' ', {domain:String})",
		"tupleElement(latest, 10) = {listen_port:UInt16}", "'__unknown__'",
	} {
		if !strings.Contains(query, token) {
			t.Fatalf("referer query missing %q: %s", token, query)
		}
	}
	if strings.Contains(query, filter.Domain) {
		t.Fatal("domain filter was interpolated into ClickHouse SQL")
	}
}

func TestRankRejectsInvalidDomainSetsBeforeDispatch(t *testing.T) {
	t.Parallel()
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests++ }))
	defer server.Close()
	client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
	filter := validFilter()
	filter.Domain = strings.Repeat("cdn.example.test ", 64) + "extra.example.test"
	if _, err := client.Rank(context.Background(), AdminScope(), filter, RankByDomain, 10, ""); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("oversized domain set error = %v", err)
	}
	filter.Domain = "valid.example.test bad_domain"
	if _, err := client.Rank(context.Background(), AdminScope(), filter, RankByDomain, 10, ""); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid domain set error = %v", err)
	}
	if requests != 0 {
		t.Fatalf("storage requests = %d", requests)
	}
}

// Rankings with a low-cardinality key read the history facts, so their range
// is the history retention, not the 7-day access log TTL.
func TestHistoryRankingsNeverReadRawAccessEvents(t *testing.T) {
	for _, dimension := range []RankDimension{RankByIP, RankByDomain, RankByRegion, RankByCarrier, RankByProvince, RankByBrowser, RankByOS} {
		query, ok := rankQuery(dimension)
		if !ok || !HistoryRankable(dimension) || strings.Contains(query, "FROM access_events") ||
			!strings.Contains(query, "FROM access_hourly_facts_v1") {
			t.Errorf("%s ranking does not read the history facts", dimension)
		}
	}
	for _, dimension := range []RankDimension{RankByURL, RankByJA4, RankByReferer} {
		if HistoryRankable(dimension) {
			t.Errorf("%s ranking must stay on the access log", dimension)
		}
	}
}
