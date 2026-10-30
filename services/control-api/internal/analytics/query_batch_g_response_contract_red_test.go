package analytics

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestQueryResponsesRejectDuplicateObjectFieldsFailClosed(t *testing.T) {
	filter := validFilter()

	t.Run("summary", func(t *testing.T) {
		body := []byte(`{"metric_version":2,"metric_version":1,"request_count":7,"request_bytes":100,"response_bytes":800,"total_bytes":900,"average_bandwidth_bps":0.8888888889,"status_2xx":5,"status_3xx":0,"status_4xx":1,"status_5xx":1,"security_events":2,"security_event_rows":2,"cache_hit_requests":0,"cache_hit_bytes":0,"unique_client_ips":1}` + "\n")
		client := newBatchGQueryResponseClient(t, body)

		result, err := client.Summary(context.Background(), AdminScope(), filter)
		if !errors.Is(err, ErrInvalidResponse) || result != (Summary{}) {
			t.Fatalf("Summary() = %#v, %v; want zero result and ErrInvalidResponse", result, err)
		}
	})

	t.Run("trend", func(t *testing.T) {
		body := []byte(`{"bucket_unix":4070905200,"bucket_unix":4070908800,"metric_version":1,"request_count":0,"request_bytes":0,"response_bytes":0,"total_bytes":0,"average_bandwidth_bps":0,"status_2xx":0,"status_3xx":0,"status_4xx":0,"status_5xx":0,"security_events":0,"security_event_rows":0,"cache_hit_requests":0,"cache_hit_bytes":0,"unique_client_ips":0}` + "\n")
		client := newBatchGQueryResponseClient(t, body)

		result, err := client.Trend(context.Background(), AdminScope(), filter)
		if !errors.Is(err, ErrInvalidResponse) || result != nil {
			t.Fatalf("Trend() = %#v, %v; want nil and ErrInvalidResponse", result, err)
		}
	})

	t.Run("top", func(t *testing.T) {
		body := []byte(`{"key":"invalid","key":"200","request_count":1,"response_bytes":0,"security_events":0}` + "\n")
		client := newBatchGQueryResponseClient(t, body)

		result, err := client.Top(context.Background(), AdminScope(), filter, TopByStatusCode, 1)
		if !errors.Is(err, ErrInvalidResponse) || result != nil {
			t.Fatalf("Top() = %#v, %v; want nil and ErrInvalidResponse", result, err)
		}
	})
}

func newBatchGQueryResponseClient(t *testing.T, body []byte) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write(body)
	}))
	t.Cleanup(server.Close)
	return mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
}
