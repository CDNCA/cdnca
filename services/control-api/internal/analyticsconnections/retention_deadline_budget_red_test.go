package analyticsconnections

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"testing"
	"time"
)

func TestClickHouseRetentionReaderUsesCallerDeadlineBudget(t *testing.T) {
	var captured *http.Request
	client := retentionHTTPClient(func(request *http.Request) (*http.Response, error) {
		captured = request
		return retentionResponse(http.StatusOK, retentionRow("2026-08-07T00:00:00Z", "2026-08-07T01:00:00Z", 7)+"\n"), nil
	})
	reader, err := NewClickHouseRetentionReader(
		ClickHouseConfig{Endpoint: "http://127.0.0.1:8123", Database: "analytics", OperationTimeout: time.Second, MaxResponseBytes: 8192},
		RetentionConfig{MaxRows: 1, MaxResponseBytes: 4096, TTL: DefaultRetentionTTL, Now: func() time.Time {
			return time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
		}},
		client,
	)
	if err != nil {
		t.Fatalf("reader: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	rows, err := reader.Read(ctx, validRetentionClickHouseQuery())
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows=%#v err=%v", rows, err)
	}
	if captured == nil {
		t.Fatal("ClickHouse was not dispatched")
	}
	values := captured.URL.Query()
	maxExecutionTime, err := strconv.ParseFloat(values.Get("max_execution_time"), 64)
	if err != nil || maxExecutionTime <= 0 || maxExecutionTime >= 1 || maxExecutionTime > 0.100 {
		t.Fatalf("max_execution_time=%q parsed=%v err=%v, want caller-bounded positive value <= 0.100s", values.Get("max_execution_time"), maxExecutionTime, err)
	}
	if values.Get("max_result_rows") != "2" || values.Get("result_overflow_mode") != "throw" {
		t.Fatalf("capacity parameters drifted: max_result_rows=%q overflow=%q", values.Get("max_result_rows"), values.Get("result_overflow_mode"))
	}
}

func TestClickHouseRetentionReaderFloorsConfiguredTimeout(t *testing.T) {
	t.Run("fractional millisecond", func(t *testing.T) {
		var captured *http.Request
		reader, err := NewClickHouseRetentionReader(
			ClickHouseConfig{Endpoint: "http://127.0.0.1:8123", Database: "analytics", OperationTimeout: 1500 * time.Microsecond, MaxResponseBytes: 8192},
			RetentionConfig{MaxRows: 1, MaxResponseBytes: 4096, TTL: DefaultRetentionTTL, Now: func() time.Time {
				return time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
			}},
			retentionHTTPClient(func(request *http.Request) (*http.Response, error) {
				captured = request
				return retentionResponse(http.StatusOK, retentionRow("2026-08-07T00:00:00Z", "2026-08-07T01:00:00Z", 7)+"\n"), nil
			}),
		)
		if err != nil {
			t.Fatalf("reader: %v", err)
		}
		if _, err := reader.Read(context.Background(), validRetentionClickHouseQuery()); err != nil {
			t.Fatalf("read: %v", err)
		}
		if captured == nil {
			t.Fatal("ClickHouse was not dispatched")
		}
		got, err := strconv.ParseFloat(captured.URL.Query().Get("max_execution_time"), 64)
		if err != nil || got <= 0 || got > 0.001 {
			t.Fatalf("max_execution_time=%q parsed=%v err=%v, want positive value <= 0.001s", captured.URL.Query().Get("max_execution_time"), got, err)
		}
	})

	t.Run("sub millisecond fails before dispatch", func(t *testing.T) {
		calls := 0
		reader, err := NewClickHouseRetentionReader(
			ClickHouseConfig{Endpoint: "http://127.0.0.1:8123", Database: "analytics", OperationTimeout: 500 * time.Microsecond, MaxResponseBytes: 8192},
			RetentionConfig{MaxRows: 1, MaxResponseBytes: 4096},
			retentionHTTPClient(func(*http.Request) (*http.Response, error) {
				calls++
				return retentionResponse(http.StatusOK, retentionRow("2026-08-07T00:00:00Z", "2026-08-07T01:00:00Z", 7)+"\n"), nil
			}),
		)
		if err != nil {
			t.Fatalf("reader: %v", err)
		}
		_, err = reader.Read(context.Background(), validRetentionClickHouseQuery())
		if !errors.Is(err, context.DeadlineExceeded) || calls != 0 {
			t.Fatalf("err=%v calls=%d, want deadline exceeded with zero dispatch", err, calls)
		}
	})
}
