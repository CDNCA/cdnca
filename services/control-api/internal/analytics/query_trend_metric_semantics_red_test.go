package analytics

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTrendRejectsMissingAndNullMetricFields(t *testing.T) {
	from := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	required := []string{
		"metric_version", "request_count", "request_bytes", "response_bytes", "total_bytes",
		"average_bandwidth_bps", "status_2xx", "status_3xx", "status_4xx", "status_5xx", "security_events",
		"cache_hit_requests", "cache_hit_bytes", "unique_client_ips",
	}
	for _, field := range required {
		for _, invalid := range []struct {
			name   string
			mutate func(map[string]any)
		}{
			{name: "missing", mutate: func(row map[string]any) { delete(row, field) }},
			{name: "null", mutate: func(row map[string]any) { row[field] = nil }},
		} {
			t.Run(field+"/"+invalid.name, func(t *testing.T) {
				row := validTrendMetricWire(from)
				invalid.mutate(row)
				assertTrendInvalidResponse(t, from, trendMetricWire(t, row))
			})
		}
	}
}

func TestTrendRejectsMissingAndNullBucket(t *testing.T) {
	from := time.Unix(0, 0).UTC()
	for _, invalid := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "missing", mutate: func(row map[string]any) { delete(row, "bucket_unix") }},
		{name: "null", mutate: func(row map[string]any) { row["bucket_unix"] = nil }},
	} {
		t.Run(invalid.name, func(t *testing.T) {
			row := validTrendMetricWire(from)
			invalid.mutate(row)
			assertTrendInvalidResponse(t, from, trendMetricWire(t, row))
		})
	}
}

func TestTrendRejectsInconsistentMetricRows(t *testing.T) {
	from := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "total bytes mismatch", mutate: func(row map[string]any) { row["total_bytes"] = uint64(31) }},
		{name: "total bytes overflow", mutate: func(row map[string]any) {
			row["request_bytes"] = uint64(math.MaxUint64)
			row["response_bytes"] = uint64(1)
			row["total_bytes"] = uint64(0)
		}},
		{name: "negative bandwidth", mutate: func(row map[string]any) { row["average_bandwidth_bps"] = -1.0 }},
		{name: "positive bandwidth without response bytes", mutate: func(row map[string]any) {
			row["request_bytes"] = uint64(0)
			row["response_bytes"] = uint64(0)
			row["total_bytes"] = uint64(0)
			row["average_bandwidth_bps"] = 1.0
		}},
		{name: "status sum overflow", mutate: func(row map[string]any) {
			row["request_count"] = uint64(math.MaxUint64)
			row["status_2xx"] = uint64(math.MaxUint64)
			row["status_3xx"] = uint64(1)
		}},
		{name: "status sum exceeds requests", mutate: func(row map[string]any) {
			row["request_count"] = uint64(1)
			row["status_2xx"] = uint64(1)
			row["status_3xx"] = uint64(1)
		}},
		{name: "zero requests with request bytes", mutate: func(row map[string]any) {
			row["request_count"] = uint64(0)
			row["request_bytes"] = uint64(1)
			row["response_bytes"] = uint64(0)
			row["total_bytes"] = uint64(1)
			row["average_bandwidth_bps"] = 0.0
			row["status_2xx"] = uint64(0)
		}},
		{name: "zero requests with response bytes", mutate: func(row map[string]any) {
			row["request_count"] = uint64(0)
			row["request_bytes"] = uint64(0)
			row["response_bytes"] = uint64(1)
			row["total_bytes"] = uint64(1)
			row["average_bandwidth_bps"] = 1.0
			row["status_2xx"] = uint64(0)
		}},
		{name: "zero requests with total bytes", mutate: func(row map[string]any) {
			row["request_count"] = uint64(0)
			row["request_bytes"] = uint64(0)
			row["response_bytes"] = uint64(0)
			row["total_bytes"] = uint64(1)
			row["average_bandwidth_bps"] = 0.0
			row["status_2xx"] = uint64(0)
		}},
		{name: "zero requests with status", mutate: func(row map[string]any) {
			row["request_count"] = uint64(0)
			row["request_bytes"] = uint64(0)
			row["response_bytes"] = uint64(0)
			row["total_bytes"] = uint64(0)
			row["average_bandwidth_bps"] = 0.0
			row["status_2xx"] = uint64(1)
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			row := validTrendMetricWire(from)
			test.mutate(row)
			assertTrendInvalidResponse(t, from, trendMetricWire(t, row))
		})
	}
}

func TestTrendAcceptsCompleteMetricRows(t *testing.T) {
	from := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		rows []map[string]any
	}{
		{name: "all zero", rows: []map[string]any{zeroTrendMetricWire(from)}},
		{name: "one xx gap", rows: []map[string]any{func() map[string]any {
			row := validTrendMetricWire(from)
			row["request_count"] = uint64(3)
			row["status_2xx"] = uint64(2)
			return row
		}()}},
		{name: "security only", rows: []map[string]any{func() map[string]any {
			row := zeroTrendMetricWire(from)
			row["security_events"] = uint64(2)
			return row
		}()}},
		{name: "two ordered rows", rows: []map[string]any{
			validTrendMetricWire(from),
			func() map[string]any {
				row := validTrendMetricWire(from.Add(time.Hour))
				row["request_count"] = uint64(4)
				row["request_bytes"] = uint64(40)
				row["response_bytes"] = uint64(60)
				row["total_bytes"] = uint64(100)
				row["average_bandwidth_bps"] = 2.5
				row["status_2xx"] = uint64(3)
				row["status_4xx"] = uint64(1)
				row["security_events"] = uint64(2)
				return row
			}(),
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var body []byte
			for _, row := range test.rows {
				body = append(body, trendMetricWire(t, row)...)
			}
			client := newTrendMetricResponseTestClient(t, body)
			points, err := client.Trend(context.Background(), AdminScope(), Filter{From: from, To: from.Add(3 * time.Hour)})
			if err != nil {
				t.Fatalf("Trend() error = %v", err)
			}
			if len(points) != len(test.rows) {
				t.Fatalf("Trend() points = %#v, want %d rows", points, len(test.rows))
			}
			for index, row := range test.rows {
				if got := points[index]; got.Hour.Unix() != row["bucket_unix"].(int64) ||
					got.MetricVersion != row["metric_version"].(uint16) ||
					got.RequestCount != row["request_count"].(uint64) ||
					got.RequestBytes != row["request_bytes"].(uint64) ||
					got.ResponseBytes != row["response_bytes"].(uint64) ||
					got.TotalBytes != row["total_bytes"].(uint64) ||
					got.AverageBandwidthBPS != row["average_bandwidth_bps"].(float64) ||
					got.Status2xx != row["status_2xx"].(uint64) || got.Status3xx != row["status_3xx"].(uint64) ||
					got.Status4xx != row["status_4xx"].(uint64) || got.Status5xx != row["status_5xx"].(uint64) ||
					got.SecurityEvents != row["security_events"].(uint64) {
					t.Fatalf("Trend() point %d = %#v, want %#v", index, got, row)
				}
			}
		})
	}
}

func validTrendMetricWire(bucket time.Time) map[string]any {
	return map[string]any{
		"bucket_unix": bucket.Unix(), "metric_version": uint16(MetricVersion),
		"request_count": uint64(2), "request_bytes": uint64(10), "response_bytes": uint64(20),
		"total_bytes": uint64(30), "average_bandwidth_bps": 1.5,
		"status_2xx": uint64(2), "status_3xx": uint64(0), "status_4xx": uint64(0), "status_5xx": uint64(0),
		"security_events":    uint64(1),
		"security_event_rows": uint64(1),
		"cache_hit_requests": uint64(1), "cache_hit_bytes": uint64(15), "unique_client_ips": uint64(1),
	}
}

func zeroTrendMetricWire(bucket time.Time) map[string]any {
	row := validTrendMetricWire(bucket)
	for _, field := range []string{
		"request_count", "request_bytes", "response_bytes", "total_bytes",
		"status_2xx", "status_3xx", "status_4xx", "status_5xx", "security_events",
		"cache_hit_requests", "cache_hit_bytes", "unique_client_ips",
	} {
		row[field] = uint64(0)
	}
	row["average_bandwidth_bps"] = 0.0
	return row
}

func trendMetricWire(t *testing.T, row map[string]any) []byte {
	t.Helper()
	encoded, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	return append(encoded, '\n')
}

func assertTrendInvalidResponse(t *testing.T, from time.Time, body []byte) {
	t.Helper()
	client := newTrendMetricResponseTestClient(t, body)
	points, err := client.Trend(context.Background(), AdminScope(), Filter{From: from, To: from.Add(3 * time.Hour)})
	if !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("Trend() error = %v, want ErrInvalidResponse", err)
	}
	if points != nil {
		t.Fatalf("Trend() returned partial points: %#v", points)
	}
}

func newTrendMetricResponseTestClient(t *testing.T, body []byte) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write(body)
	}))
	t.Cleanup(server.Close)
	client, err := NewClient(Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	return client
}
