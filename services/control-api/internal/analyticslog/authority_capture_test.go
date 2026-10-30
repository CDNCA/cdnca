package analyticslog

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestAccessQueryReturnsAuthorityCaptureAndBindsJA4OriginFilters(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.July, 29, 0, 0, 0, 0, time.UTC)
	taskID := "task-source"
	ja4 := "t13d1516h2_8daaf6152771"
	connect, firstByte, total := uint64(100), uint64(250), uint64(400)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		query := request.URL.Query()
		for key, want := range map[string]string{
			"param_ja4":                      ja4,
			"param_origin_connect_us_min":    "100",
			"param_origin_connect_us_max":    "100",
			"param_origin_first_byte_us_min": "250",
			"param_origin_first_byte_us_max": "250",
			"param_origin_total_us_min":      "400",
			"param_origin_total_us_max":      "400",
		} {
			if got := query.Get(key); got != want {
				t.Errorf("%s = %q, want %q", key, got, want)
			}
		}
		row := accessRow{
			EventID: "capture-row", OccurredAtMS: now.Add(-time.Second).UnixMilli(), SiteID: siteA, NodeID: nodeA,
			RequestID: "request", TraceID: "trace", ConfigVersion: configA,
			TaskID: &taskID, InstallationID: "install-authority", RequestHeaders: map[string]string{"Authorization": "[REDACTED]"},
			ResponseHeaders: map[string]string{"Set-Cookie": "[REDACTED]"}, RequestBody: stringPointer(`{"account":9007199254740993}`),
			ResponseBody: stringPointer(`{}`), JA4: &ja4, OriginConnectUS: &connect, OriginFirstByteUS: &firstByte, OriginTotalUS: &total,
			Host: "example.test", URIPath: "/asset", ClientIP: "2001:db8::1", CountryCode: "CN", Carrier: "carrier-a",
			Method: "GET", Protocol: "HTTP/2", CacheStatus: "HIT", UpstreamResult: "ok", StatusCode: 200,
			VersionCount: 1, SnapshotMS: now.UnixMilli(),
		}
		if err := json.NewEncoder(writer).Encode(row); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	client := newUnitClient(t, server, time.Second)
	filter := Filter{
		From: now.Add(-time.Hour), To: now, JA4: ja4,
		OriginConnectUSMin: &connect, OriginConnectUSMax: &connect,
		OriginFirstByteUSMin: &firstByte, OriginFirstByteUSMax: &firstByte,
		OriginTotalUSMin: &total, OriginTotalUSMax: &total,
	}
	page, err := client.ListAccess(context.Background(), scope{tenantID: tenantA}, filter, 10, "")
	if err != nil {
		t.Fatalf("ListAccess() error = %v", err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("items = %#v", page.Items)
	}
	item := page.Items[0]
	if item.InstallationID != "install-authority" || item.TaskID == nil || *item.TaskID != taskID || item.JA4 == nil || *item.JA4 != ja4 {
		t.Fatalf("authority fields = %#v", item)
	}
	account, ok := item.RequestBody["account"].(json.Number)
	if !ok || account.String() != "9007199254740993" || item.ResponseBody == nil || len(item.ResponseBody) != 0 {
		t.Fatalf("capture bodies = %#v / %#v", item.RequestBody, item.ResponseBody)
	}
}

func stringPointer(value string) *string { return &value }

func TestParseQueryAcceptsJA4AndOriginTimingRanges(t *testing.T) {
	t.Parallel()
	values := url.Values{
		"from": {"2026-07-28T23:00:00Z"}, "to": {"2026-07-29T00:00:00Z"},
		"ja4": {"t13d1516h2_8daaf6152771"}, "origin_connect_us_min": {"100"}, "origin_connect_us_max": {"200"},
		"origin_first_byte_us_min": {"250"}, "origin_first_byte_us_max": {"300"},
		"origin_total_us_min": {"400"}, "origin_total_us_max": {"500"},
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/analytics/logs/access?"+values.Encode(), nil)
	route, ok := resolveRoute(request.URL.Path)
	if !ok {
		t.Fatal("access route not resolved")
	}
	query, err := parseQuery(request, route)
	if err != nil {
		t.Fatalf("parseQuery() error = %v", err)
	}
	if query.Filter.JA4 != values.Get("ja4") || query.Filter.OriginConnectUSMin == nil || *query.Filter.OriginConnectUSMin != 100 ||
		query.Filter.OriginTotalUSMax == nil || *query.Filter.OriginTotalUSMax != 500 {
		t.Fatalf("capture filter = %#v", query.Filter)
	}
}
