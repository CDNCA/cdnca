package analytics

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type queryRowCapacityValue struct {
	Value int `json:"value"`
}

func TestQueryRowsRejectsNonPositiveAndOverCapacityResponses(t *testing.T) {
	t.Run("non-positive maximum rejects before HTTP", func(t *testing.T) {
		for _, maximumRows := range []int{0, -1} {
			var requests atomic.Int32
			client := newQueryRowCapacityClient(t, nil, &requests, nil)
			rows, err := queryRows[queryRowCapacityValue](client, context.Background(), "SELECT 1 FORMAT JSONEachRow", nil, maximumRows)
			if !errors.Is(err, ErrInvalidResponse) || rows != nil {
				t.Fatalf("queryRows(maximumRows=%d) = %#v, %v; want nil, ErrInvalidResponse", maximumRows, rows, err)
			}
			if requests.Load() != 0 {
				t.Fatalf("queryRows(maximumRows=%d) HTTP requests = %d, want 0", maximumRows, requests.Load())
			}
		}
	})

	t.Run("exact maximum is accepted", func(t *testing.T) {
		var requests atomic.Int32
		client := newQueryRowCapacityClient(t, []byte("{\"value\":1}\n{\"value\":2}\n"), &requests, nil)
		rows, err := queryRows[queryRowCapacityValue](client, context.Background(), "SELECT 1 FORMAT JSONEachRow", nil, 2)
		if err != nil || len(rows) != 2 || rows[0].Value != 1 || rows[1].Value != 2 {
			t.Fatalf("queryRows() = %#v, %v; want values 1 and 2", rows, err)
		}
		if requests.Load() != 1 {
			t.Fatalf("queryRows() HTTP requests = %d, want 1", requests.Load())
		}
	})

	t.Run("first excess row fails closed before append", func(t *testing.T) {
		var requests atomic.Int32
		client := newQueryRowCapacityClient(t, []byte("{\"value\":1}\n{\"value\":2}\n{\"value\":3}\n"), &requests, nil)
		rows, err := queryRows[queryRowCapacityValue](client, context.Background(), "SELECT 1 FORMAT JSONEachRow", nil, 2)
		if !errors.Is(err, ErrInvalidResponse) || rows != nil {
			t.Fatalf("queryRows() = %#v, %v; want nil, ErrInvalidResponse", rows, err)
		}
		if requests.Load() != 1 {
			t.Fatalf("queryRows() HTTP requests = %d, want 1", requests.Load())
		}
	})

	t.Run("Summary permits one response row", func(t *testing.T) {
		row := "{\"metric_version\":1,\"request_count\":0,\"request_bytes\":0,\"response_bytes\":0," +
			"\"total_bytes\":0,\"average_bandwidth_bps\":0,\"status_2xx\":0,\"status_3xx\":0," +
			"\"status_4xx\":0,\"status_5xx\":0,\"security_events\":0,\"security_event_rows\":0," +
			"\"cache_hit_requests\":0,\"cache_hit_bytes\":0,\"unique_client_ips\":0}\n"
		client := newQueryRowCapacityClient(t, []byte(row+row), nil, nil)
		summary, err := client.Summary(context.Background(), AdminScope(), validFilter())
		if !errors.Is(err, ErrInvalidResponse) || summary != (Summary{}) {
			t.Fatalf("Summary() = %#v, %v; want zero result and ErrInvalidResponse", summary, err)
		}
	})

	t.Run("Trend permits exactly the aligned filter hours up to 745", func(t *testing.T) {
		from := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
		const maximumRows = 745
		var body strings.Builder
		for index := 0; index < maximumRows; index++ {
			body.WriteString("{\"bucket_unix\":")
			body.WriteString(strconv.FormatInt(from.Add(time.Duration(index)*time.Hour).Unix(), 10))
			body.WriteString(",\"metric_version\":1,\"request_count\":0,\"request_bytes\":0,\"response_bytes\":0," +
				"\"total_bytes\":0,\"average_bandwidth_bps\":0,\"status_2xx\":0,\"status_3xx\":0," +
				"\"status_4xx\":0,\"status_5xx\":0,\"security_events\":0,\"security_event_rows\":0," +
				"\"cache_hit_requests\":0,\"cache_hit_bytes\":0,\"unique_client_ips\":0}\n")
		}
		client := newQueryRowCapacityClient(t, []byte(body.String()), nil, nil)
		points, err := client.Trend(context.Background(), AdminScope(), Filter{From: from, To: from.Add(maximumRows * time.Hour)})
		if err != nil || len(points) != maximumRows {
			t.Fatalf("Trend() returned %d points, %v; want %d points, nil", len(points), err, maximumRows)
		}
		if !points[0].Hour.Equal(from) || !points[maximumRows-1].Hour.Equal(from.Add((maximumRows-1)*time.Hour)) ||
			points[0].MetricVersion != MetricVersion || points[maximumRows-1].MetricVersion != MetricVersion {
			t.Fatalf("Trend() boundary points = %#v, %#v", points[0], points[maximumRows-1])
		}
	})

	t.Run("Top rejects a response over the exact limit", func(t *testing.T) {
		body := []byte("{\"key\":\"10000000-0000-0000-0000-000000000001\",\"request_count\":4,\"response_bytes\":40,\"security_events\":0}\n" +
			"{\"key\":\"20000000-0000-0000-0000-000000000001\",\"request_count\":3,\"response_bytes\":30,\"security_events\":0}\n" +
			"{\"key\":\"30000000-0000-0000-0000-000000000001\",\"request_count\":2,\"response_bytes\":20,\"security_events\":0}\n")
		var parameters url.Values
		client := newQueryRowCapacityClient(t, body, nil, &parameters)
		items, err := client.Top(context.Background(), AdminScope(), validFilter(), TopBySite, 2)
		if !errors.Is(err, ErrInvalidResponse) || items != nil {
			t.Fatalf("Top() = %#v, %v; want nil, ErrInvalidResponse", items, err)
		}
		if got := parameters.Get("param_row_limit"); got != "2" {
			t.Fatalf("Top() row_limit = %q, want exact requested limit 2", got)
		}
	})
}

func newQueryRowCapacityClient(t *testing.T, encoded []byte, requests *atomic.Int32, parameters *url.Values) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if requests != nil {
			requests.Add(1)
		}
		if parameters != nil {
			*parameters = request.URL.Query()
		}
		_, _ = writer.Write(encoded)
	}))
	t.Cleanup(server.Close)
	return mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
}
