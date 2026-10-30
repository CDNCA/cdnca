package analyticslog

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientExecuteBindsClickHouseToEffectiveContextDeadline(t *testing.T) {
	t.Run("parent deadline", func(t *testing.T) {
		transport := &deadlineBudgetHTTPClient{}
		client := newDeadlineBudgetClient(t, transport)
		ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
		defer cancel()
		if err := client.execute(ctx, "SELECT 1 FORMAT JSONEachRow", nil, func([]byte) error { return nil }); err != nil {
			t.Fatal(err)
		}
		budget, err := strconv.ParseFloat(transport.maxExecutionTime, 64)
		if err != nil || budget <= 0 || budget > 0.4 {
			t.Fatalf("max_execution_time=%q, want positive parent budget <=0.400s", transport.maxExecutionTime)
		}
		if transport.timeoutOverflowMode != "throw" {
			t.Fatalf("timeout_overflow_mode=%q, want throw", transport.timeoutOverflowMode)
		}
	})

	t.Run("already canceled", func(t *testing.T) {
		transport := &deadlineBudgetHTTPClient{}
		client := newDeadlineBudgetClient(t, transport)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := client.execute(ctx, "SELECT 1 FORMAT JSONEachRow", nil, func([]byte) error { return nil })
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("execute() error=%v, want context.Canceled", err)
		}
		if calls := transport.calls.Load(); calls != 0 {
			t.Fatalf("HTTP calls=%d, want zero after caller cancellation", calls)
		}
	})
}

type deadlineBudgetHTTPClient struct {
	calls               atomic.Int64
	maxExecutionTime    string
	timeoutOverflowMode string
}

func (client *deadlineBudgetHTTPClient) Do(request *http.Request) (*http.Response, error) {
	client.calls.Add(1)
	client.maxExecutionTime = request.URL.Query().Get("max_execution_time")
	client.timeoutOverflowMode = request.URL.Query().Get("timeout_overflow_mode")
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("{}\n")),
	}, nil
}

func newDeadlineBudgetClient(t *testing.T, httpClient HTTPClient) *Client {
	t.Helper()
	client, err := NewClient(ClientConfig{
		Endpoint: "http://127.0.0.1:8123", Database: "task_analyticslog_deadline_budget",
		QueryTimeout: 5 * time.Second, CursorKeyring: testLogCursorKeyring(),
	}, httpClient)
	if err != nil {
		t.Fatal(err)
	}
	return client
}
