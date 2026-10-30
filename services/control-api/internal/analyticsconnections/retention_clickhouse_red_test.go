package analyticsconnections

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type retentionHTTPClient func(*http.Request) (*http.Response, error)

func (client retentionHTTPClient) Do(request *http.Request) (*http.Response, error) {
	return client(request)
}

func TestClickHouseRetentionReaderUsesScopedBoundedParameterizedQuery(t *testing.T) {
	var captured *http.Request
	var statement string
	client := retentionHTTPClient(func(request *http.Request) (*http.Response, error) {
		captured = request
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatalf("read query: %v", err)
		}
		statement = string(body)
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
	query := validRetentionClickHouseQuery()
	rows, err := reader.Read(context.Background(), query)
	if err != nil || len(rows) != 1 || rows[0].Value != 7 {
		t.Fatalf("rows=%#v err=%v", rows, err)
	}
	if captured == nil || captured.Method != http.MethodPost {
		t.Fatalf("request=%#v", captured)
	}
	values := captured.URL.Query()
	for key, want := range map[string]string{
		"database":             "analytics",
		"param_tenant":         query.TenantID,
		"param_subscription":   query.SubscriptionID,
		"param_from":           query.From.Format(time.RFC3339Nano),
		"param_to":             query.To.Format(time.RFC3339Nano),
		"param_limit":          "2",
		"max_execution_time":   "1.000",
		"max_result_rows":      "2",
		"result_overflow_mode": "throw",
		"output_format_json_quote_64bit_integers": "0",
	} {
		if got := values.Get(key); got != want {
			t.Errorf("query parameter %s=%q want %q", key, got, want)
		}
	}
	for _, required := range []string{
		"FROM package_metric_finalized_v1", "tenant_id={tenant:UUID}",
		"package_subscription_id={subscription:UUID}", "period_start>={from:DateTime64(3)}",
		"period_end<={to:DateTime64(3)}", "LIMIT {limit:UInt64}", "FORMAT JSONEachRow",
		"source_watermark", "evidence_digest", "retention_until",
	} {
		if !strings.Contains(statement, required) {
			t.Errorf("query missing %q: %s", required, statement)
		}
	}
	for _, secret := range []string{query.TenantID, query.SubscriptionID, query.From.Format(time.RFC3339Nano), query.To.Format(time.RFC3339Nano)} {
		if strings.Contains(statement, secret) {
			t.Fatalf("scope value was interpolated into query: %q", secret)
		}
	}
}

func TestClickHouseRetentionReaderFailsClosedForCapacityInvalidRowsAndCancellation(t *testing.T) {
	query := validRetentionClickHouseQuery()
	t.Run("invalid request before dispatch", func(t *testing.T) {
		calls := 0
		reader := mustRetentionClickHouseReader(t, RetentionConfig{MaxRows: 1, MaxResponseBytes: 4096}, retentionHTTPClient(func(*http.Request) (*http.Response, error) {
			calls++
			return retentionResponse(http.StatusOK, "{}\n"), nil
		}))
		_, err := reader.Read(context.Background(), RetentionQuery{})
		if !errors.Is(err, ErrRetentionInvalidRequest) || calls != 0 {
			t.Fatalf("err=%v calls=%d", err, calls)
		}
	})

	t.Run("cancelled caller before dispatch", func(t *testing.T) {
		calls := 0
		reader := mustRetentionClickHouseReader(t, RetentionConfig{MaxRows: 1, MaxResponseBytes: 4096}, retentionHTTPClient(func(*http.Request) (*http.Response, error) {
			calls++
			return retentionResponse(http.StatusOK, "{}\n"), nil
		}))
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := reader.Read(ctx, query)
		if !errors.Is(err, context.Canceled) || calls != 0 {
			t.Fatalf("err=%v calls=%d", err, calls)
		}
	})

	for _, test := range []struct {
		name string
		body string
		want error
	}{
		{name: "empty response", body: "", want: ErrRetentionInvalidResponse},
		{name: "invalid response", body: "{}\n", want: ErrRetentionInvalidResponse},
		{name: "limit plus one", body: retentionRow("2026-08-07T00:00:00Z", "2026-08-07T01:00:00Z", 7) + "\n" + retentionRow("2026-08-07T01:00:00Z", "2026-08-07T02:00:00Z", 8) + "\n", want: ErrRetentionResponseTooLarge},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader := mustRetentionClickHouseReader(t, RetentionConfig{MaxRows: 1, MaxResponseBytes: 4096}, retentionHTTPClient(func(*http.Request) (*http.Response, error) {
				return retentionResponse(http.StatusOK, test.body), nil
			}))
			rows, err := reader.Read(context.Background(), query)
			if !errors.Is(err, test.want) || rows != nil {
				t.Fatalf("rows=%#v err=%v want=%v", rows, err, test.want)
			}
		})
	}

	t.Run("byte limit", func(t *testing.T) {
		reader := mustRetentionClickHouseReader(t, RetentionConfig{MaxRows: 1, MaxResponseBytes: 64}, retentionHTTPClient(func(*http.Request) (*http.Response, error) {
			return retentionResponse(http.StatusOK, retentionRow("2026-08-07T00:00:00Z", "2026-08-07T01:00:00Z", 7)), nil
		}))
		rows, err := reader.Read(context.Background(), query)
		if !errors.Is(err, ErrRetentionResponseTooLarge) || rows != nil {
			t.Fatalf("rows=%#v err=%v", rows, err)
		}
	})

	t.Run("operation timeout", func(t *testing.T) {
		client := retentionHTTPClient(func(request *http.Request) (*http.Response, error) {
			<-request.Context().Done()
			return nil, request.Context().Err()
		})
		reader, err := NewClickHouseRetentionReader(
			ClickHouseConfig{Endpoint: "http://127.0.0.1:8123", Database: "analytics", OperationTimeout: 10 * time.Millisecond, MaxResponseBytes: 8192},
			RetentionConfig{MaxRows: 1, MaxResponseBytes: 4096}, client,
		)
		if err != nil {
			t.Fatal(err)
		}
		_, err = reader.Read(context.Background(), query)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestClickHouseRetentionReaderBoundsAndClosesNonSuccessResponses(t *testing.T) {
	body := &retentionTrackingBody{remaining: 4096, marker: "secret-clickhouse-payload"}
	reader, err := NewClickHouseRetentionReader(
		ClickHouseConfig{Endpoint: "http://127.0.0.1:8123", Database: "analytics", OperationTimeout: time.Second, MaxResponseBytes: 64},
		RetentionConfig{MaxRows: 1, MaxResponseBytes: 64},
		retentionHTTPClient(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusInternalServerError, Body: body}, nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := reader.Read(context.Background(), validRetentionClickHouseQuery())
	if !errors.Is(err, ErrClickHouseUnavailable) || rows != nil {
		t.Fatalf("rows=%#v err=%v", rows, err)
	}
	if !body.closed || body.read > 65 {
		t.Fatalf("closed=%v bytes read=%d", body.closed, body.read)
	}
	if strings.Contains(err.Error(), body.marker) {
		t.Fatalf("backend response leaked: %v", err)
	}
}

func mustRetentionClickHouseReader(t *testing.T, config RetentionConfig, client HTTPClient) *ClickHouseRetentionReader {
	t.Helper()
	reader, err := NewClickHouseRetentionReader(
		ClickHouseConfig{Endpoint: "http://127.0.0.1:8123", Database: "analytics", OperationTimeout: time.Second, MaxResponseBytes: 8192},
		config, client,
	)
	if err != nil {
		t.Fatalf("reader: %v", err)
	}
	return reader
}

func validRetentionClickHouseQuery() RetentionQuery {
	return RetentionQuery{
		TenantID: retentionTenant, SubscriptionID: retentionSubscription,
		From: time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC),
		To:   time.Date(2026, 8, 7, 2, 0, 0, 0, time.UTC),
	}
}

func retentionResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body))}
}

type retentionTrackingBody struct {
	remaining int
	read      int
	closed    bool
	marker    string
}

func (body *retentionTrackingBody) Read(encoded []byte) (int, error) {
	if body.remaining == 0 {
		return 0, io.EOF
	}
	count := len(encoded)
	if count > body.remaining {
		count = body.remaining
	}
	for index := 0; index < count; index++ {
		encoded[index] = body.marker[index%len(body.marker)]
	}
	body.remaining -= count
	body.read += count
	return count, nil
}

func (body *retentionTrackingBody) Close() error {
	body.closed = true
	return nil
}
