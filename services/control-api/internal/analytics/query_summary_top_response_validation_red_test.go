package analytics

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

const (
	querySummaryTopTestSiteID = "20000000-0000-0000-0000-00000000000a"
	querySummaryTopTestNodeID = "30000000-0000-0000-0000-00000000000b"
)

func TestSummaryRejectsInvalidResponseRowsFailClosed(t *testing.T) {
	base := validSummaryWire()
	tests := []struct {
		name   string
		mutate func(map[string]any)
		raw    []byte
	}{
		{name: "wrong metric version", mutate: func(row map[string]any) { row["metric_version"] = 2 }},
		{name: "zero rows", raw: []byte{}},
		{name: "multiple rows", raw: append(summaryWire(base), summaryWire(base)...)},
		{name: "missing required field", mutate: func(row map[string]any) { delete(row, "request_bytes") }},
		{name: "null required field", mutate: func(row map[string]any) { row["request_bytes"] = nil }},
		{name: "total bytes mismatch", mutate: func(row map[string]any) { row["total_bytes"] = uint64(901) }},
		{name: "total bytes overflow", mutate: func(row map[string]any) {
			row["request_bytes"] = uint64(math.MaxUint64)
			row["response_bytes"] = uint64(1)
			row["total_bytes"] = uint64(0)
		}},
		{name: "status buckets exceed requests", mutate: func(row map[string]any) { row["status_2xx"] = uint64(8) }},
		{name: "zero requests with non-empty response", mutate: func(row map[string]any) {
			row["request_count"] = uint64(0)
		}},
		{name: "positive bandwidth without response bytes", mutate: func(row map[string]any) {
			row["request_bytes"] = uint64(0)
			row["response_bytes"] = uint64(0)
			row["total_bytes"] = uint64(0)
			row["average_bandwidth_bps"] = 1.0
		}},
		{name: "bandwidth mismatch", mutate: func(row map[string]any) { row["average_bandwidth_bps"] = 1.0 }},
		{name: "negative bandwidth", mutate: func(row map[string]any) { row["average_bandwidth_bps"] = -1.0 }},
		{name: "non-finite bandwidth", raw: []byte("{\"metric_version\":1,\"request_count\":1,\"request_bytes\":1,\"response_bytes\":1,\"total_bytes\":2,\"average_bandwidth_bps\":1e999,\"status_2xx\":1,\"status_3xx\":0,\"status_4xx\":0,\"status_5xx\":0,\"security_events\":0}\n")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := test.raw
			if body == nil {
				row := cloneWire(base)
				test.mutate(row)
				body = summaryWire(row)
			}
			client := newSummaryTopResponseTestClient(t, body, nil)
			summary, err := client.Summary(context.Background(), AdminScope(), validFilter())
			if !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("Summary() error = %v, want ErrInvalidResponse", err)
			}
			if summary != (Summary{}) {
				t.Fatalf("Summary() returned partial value: %#v", summary)
			}
		})
	}
}

func TestSummaryAcceptsLegitimateOneXXGapAndValidatesPresence(t *testing.T) {
	tests := []struct {
		name string
		row  map[string]any
		want Summary
	}{
		{
			name: "rounded bandwidth",
			row:  validSummaryWire(),
			want: Summary{RequestCount: 7, TotalBytes: 900, AverageBandwidthBPS: 0.8888888889, Status2xx: 5},
		},
		{
			name: "zero bytes and bandwidth",
			row: func() map[string]any {
				row := validSummaryWire()
				row["request_bytes"] = uint64(0)
				row["response_bytes"] = uint64(0)
				row["total_bytes"] = uint64(0)
				row["average_bandwidth_bps"] = 0.0
				return row
			}(),
			want: Summary{RequestCount: 7, TotalBytes: 0, AverageBandwidthBPS: 0, Status2xx: 5},
		},
		{
			name: "legitimate 1xx gap",
			row: func() map[string]any {
				row := validSummaryWire()
				row["request_count"] = uint64(3)
				row["request_bytes"] = uint64(10)
				row["response_bytes"] = uint64(20)
				row["total_bytes"] = uint64(30)
				row["average_bandwidth_bps"] = float64(20*8) / (2 * 60 * 60)
				row["status_2xx"] = uint64(2)
				row["status_3xx"] = uint64(0)
				row["status_4xx"] = uint64(0)
				row["status_5xx"] = uint64(0)
				row["security_events"] = uint64(0)
				return row
			}(),
			want: Summary{RequestCount: 3, TotalBytes: 30, AverageBandwidthBPS: float64(20*8) / (2 * 60 * 60), Status2xx: 2},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := newSummaryTopResponseTestClient(t, summaryWire(test.row), nil)
			summary, err := client.Summary(context.Background(), AdminScope(), validFilter())
			if err != nil {
				t.Fatalf("Summary() error = %v", err)
			}
			if summary.RequestCount != test.want.RequestCount || summary.TotalBytes != test.want.TotalBytes ||
				summary.AverageBandwidthBPS != test.want.AverageBandwidthBPS || summary.Status2xx != test.want.Status2xx {
				t.Fatalf("Summary() = %#v", summary)
			}
		})
	}
}

func TestSummaryRejectsRawInvalidUTF8(t *testing.T) {
	body := []byte("{\"metric_version\":1,\"request_count\":1,\"request_bytes\":1,\"response_bytes\":1,\"total_bytes\":2,\"average_bandwidth_bps\":1,\"status_2xx\":1,\"status_3xx\":0,\"status_4xx\":0,\"status_5xx\":0,\"security_events\":0,\"x\":\xC2}\n")
	client := newSummaryTopResponseTestClient(t, body, nil)
	if summary, err := client.Summary(context.Background(), AdminScope(), validFilter()); !errors.Is(err, ErrInvalidResponse) || summary != (Summary{}) {
		t.Fatalf("Summary() = %#v, error = %v", summary, err)
	}
}

func TestTopRejectsInvalidRowsForEveryDimension(t *testing.T) {
	base := validTopWire(querySummaryTopTestSiteID, 5, 50, 0)
	tests := []struct {
		name      string
		dimension TopDimension
		mutate    func(map[string]any)
		raw       []byte
	}{
		{name: "site missing key", dimension: TopBySite, mutate: func(row map[string]any) { delete(row, "key") }},
		{name: "site uppercase uuid", dimension: TopBySite, mutate: func(row map[string]any) { row["key"] = strings.ToUpper(querySummaryTopTestSiteID) }},
		{name: "node nil uuid", dimension: TopByNode, mutate: func(row map[string]any) { row["key"] = "00000000-0000-0000-0000-000000000000" }},
		{name: "status non-canonical", dimension: TopByStatusCode, mutate: func(row map[string]any) { row["key"] = "0200" }},
		{name: "status out of range", dimension: TopByStatusCode, mutate: func(row map[string]any) { row["key"] = "600" }},
		{name: "security action empty", dimension: TopBySecurityAction, mutate: func(row map[string]any) { row["key"] = "" }},
		{name: "security action too long", dimension: TopBySecurityAction, mutate: func(row map[string]any) { row["key"] = strings.Repeat("a", 65) }},
		{name: "null metric field", dimension: TopBySite, mutate: func(row map[string]any) { row["request_count"] = nil }},
		{name: "site zero request shape", dimension: TopBySite, mutate: func(row map[string]any) { row["request_count"] = uint64(0) }},
		{name: "site security event shape", dimension: TopBySite, mutate: func(row map[string]any) { row["security_events"] = uint64(1) }},
		{name: "status zero request shape", dimension: TopByStatusCode, mutate: func(row map[string]any) { row["request_count"] = uint64(0) }},
		{name: "security action zero event shape", dimension: TopBySecurityAction, mutate: func(row map[string]any) { row["security_events"] = uint64(0) }},
		{name: "security action request bytes", dimension: TopBySecurityAction, mutate: func(row map[string]any) {
			row["key"] = "block"
			row["security_events"] = uint64(1)
			row["request_count"] = uint64(0)
			row["response_bytes"] = uint64(1)
		}},
		{name: "duplicate keys", dimension: TopByStatusCode, raw: []byte("{\"key\":\"200\",\"request_count\":2,\"response_bytes\":10,\"security_events\":0}\n{\"key\":\"200\",\"request_count\":1,\"response_bytes\":5,\"security_events\":0}\n")},
		{name: "reverse strict order", dimension: TopByStatusCode, raw: []byte("{\"key\":\"200\",\"request_count\":1,\"response_bytes\":10,\"security_events\":0}\n{\"key\":\"201\",\"request_count\":2,\"response_bytes\":5,\"security_events\":0}\n")},
		{name: "response exceeds exact limit", dimension: TopByStatusCode, raw: []byte("{\"key\":\"200\",\"request_count\":2,\"response_bytes\":10,\"security_events\":0}\n{\"key\":\"201\",\"request_count\":1,\"response_bytes\":5,\"security_events\":0}\n")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := test.raw
			if body == nil {
				row := cloneWire(base)
				if test.dimension == TopByStatusCode {
					row["key"] = "200"
				}
				if test.dimension == TopBySecurityAction && row["key"] == querySummaryTopTestSiteID {
					row["key"] = "block"
				}
				test.mutate(row)
				body = topWire(row)
			}
			var observed url.Values
			client := newSummaryTopResponseTestClient(t, body, &observed)
			items, err := client.Top(context.Background(), AdminScope(), validFilter(), test.dimension, 1)
			if !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("Top() error = %v, want ErrInvalidResponse", err)
			}
			if items != nil {
				t.Fatalf("Top() returned partial items: %#v", items)
			}
			if test.name == "response exceeds exact limit" && observed.Get("param_row_limit") != "1" {
				t.Fatalf("row limit = %q, want exact requested limit 1", observed.Get("param_row_limit"))
			}
		})
	}
}

func TestTopReturnsRequestedBoundWithoutProbeFailure(t *testing.T) {
	rows := [][]byte{
		[]byte("{\"key\":\"200\",\"request_count\":2,\"response_bytes\":10,\"security_events\":0}\n"),
		[]byte("{\"key\":\"201\",\"request_count\":1,\"response_bytes\":5,\"security_events\":0}\n"),
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		rowLimit, err := strconv.Atoi(request.URL.Query().Get("param_row_limit"))
		if err != nil || rowLimit < 0 || rowLimit > len(rows) {
			t.Errorf("param_row_limit = %q", request.URL.Query().Get("param_row_limit"))
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		for _, row := range rows[:rowLimit] {
			_, _ = writer.Write(row)
		}
	}))
	t.Cleanup(server.Close)
	client, err := NewClient(Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
	if err != nil {
		t.Fatal(err)
	}

	items, err := client.Top(context.Background(), AdminScope(), validFilter(), TopByStatusCode, 1)
	if err != nil {
		t.Fatalf("Top() error = %v", err)
	}
	if len(items) != 1 || items[0].Key != "200" {
		t.Fatalf("Top() = %#v, want only the best row", items)
	}
}

func TestTopRejectsRawInvalidUTF8AndControls(t *testing.T) {
	for _, test := range []struct {
		name string
		key  []byte
	}{
		{name: "invalid utf8", key: []byte{0xc2}},
		{name: "c0", key: []byte{0x01}},
		{name: "c1", key: []byte{0xc2, 0x80}},
		{name: "del", key: []byte{0x7f}},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := []byte("{\"key\":\"")
			body = append(body, test.key...)
			body = append(body, []byte("\",\"request_count\":1,\"response_bytes\":1,\"security_events\":0}\n")...)
			client := newSummaryTopResponseTestClient(t, body, nil)
			if items, err := client.Top(context.Background(), AdminScope(), validFilter(), TopBySecurityAction, 1); !errors.Is(err, ErrInvalidResponse) || items != nil {
				t.Fatalf("Top() = %#v, error = %v", items, err)
			}
		})
	}
}

func TestTopAcceptsEmptyAndLegalEqualCountOrdering(t *testing.T) {
	tests := []struct {
		name      string
		dimension TopDimension
		body      []byte
	}{
		{name: "empty", dimension: TopBySite},
		{name: "site equal metrics", dimension: TopBySite, body: []byte("{\"key\":\"20000000-0000-0000-0000-000000000001\",\"request_count\":2,\"response_bytes\":10,\"security_events\":0}\n{\"key\":\"30000000-0000-0000-0000-000000000001\",\"request_count\":2,\"response_bytes\":10,\"security_events\":0}\n")},
		{name: "status equal metrics", dimension: TopByStatusCode, body: []byte("{\"key\":\"200\",\"request_count\":2,\"response_bytes\":10,\"security_events\":0}\n{\"key\":\"201\",\"request_count\":2,\"response_bytes\":10,\"security_events\":0}\n")},
		{name: "security equal metrics", dimension: TopBySecurityAction, body: []byte("{\"key\":\"allow\",\"request_count\":0,\"response_bytes\":0,\"security_events\":2}\n{\"key\":\"block\",\"request_count\":0,\"response_bytes\":0,\"security_events\":2}\n")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := test.body
			if body == nil {
				body = []byte{}
			}
			client := newSummaryTopResponseTestClient(t, body, nil)
			items, err := client.Top(context.Background(), AdminScope(), validFilter(), test.dimension, 3)
			if err != nil {
				t.Fatalf("Top() error = %v", err)
			}
			if len(items) == 0 && test.body != nil {
				t.Fatal("Top() returned no legal rows")
			}
		})
	}
}

func TestTopAcceptsLegalUnicodeSecurityAction(t *testing.T) {
	body := []byte("{\"key\":\"允许\",\"request_count\":0,\"response_bytes\":0,\"security_events\":1}\n")
	client := newSummaryTopResponseTestClient(t, body, nil)
	items, err := client.Top(context.Background(), AdminScope(), validFilter(), TopBySecurityAction, 1)
	if err != nil {
		t.Fatalf("Top() error = %v", err)
	}
	if len(items) != 1 || items[0].Key != "允许" {
		t.Fatalf("Top() = %#v", items)
	}
}

func validSummaryWire() map[string]any {
	return map[string]any{
		"metric_version":        uint64(MetricVersion),
		"request_count":         uint64(7),
		"request_bytes":         uint64(100),
		"response_bytes":        uint64(800),
		"total_bytes":           uint64(900),
		"average_bandwidth_bps": 0.8888888889,
		"status_2xx":            uint64(5),
		"status_3xx":            uint64(0),
		"status_4xx":            uint64(1),
		"status_5xx":            uint64(1),
		"security_events":       uint64(2),
		"security_event_rows": uint64(2),
		"cache_hit_requests":    uint64(0),
		"cache_hit_bytes":       uint64(0),
		"unique_client_ips":     uint64(0),
	}
}

func validTopWire(key string, requestCount, responseBytes, securityEvents uint64) map[string]any {
	return map[string]any{"key": key, "request_count": requestCount, "response_bytes": responseBytes, "security_events": securityEvents}
}

func cloneWire(value map[string]any) map[string]any {
	clone := make(map[string]any, len(value))
	for key, item := range value {
		clone[key] = item
	}
	return clone
}

func summaryWire(row map[string]any) []byte {
	encoded, err := json.Marshal(row)
	if err != nil {
		panic(err)
	}
	return append(encoded, '\n')
}

func topWire(row map[string]any) []byte {
	return summaryWire(row)
}

func newSummaryTopResponseTestClient(t *testing.T, body []byte, observed *url.Values) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if observed != nil {
			*observed = request.URL.Query()
		}
		_, _ = writer.Write(body)
	}))
	t.Cleanup(server.Close)
	client, err := NewClient(Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	return client
}
