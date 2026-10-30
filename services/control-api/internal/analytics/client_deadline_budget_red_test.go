package analytics

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

type deadlineBudgetHTTPClient struct {
	dispatches          int
	maxExecutionSeconds []float64
}

func (client *deadlineBudgetHTTPClient) Do(request *http.Request) (*http.Response, error) {
	client.dispatches++
	value, err := strconv.ParseFloat(request.URL.Query().Get("max_execution_time"), 64)
	if err == nil {
		client.maxExecutionSeconds = append(client.maxExecutionSeconds, value)
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(summaryResponse())),
	}, nil
}

func TestClientExecuteBoundsClickHouseDeadline(t *testing.T) {
	httpClient := &deadlineBudgetHTTPClient{}
	client := mustClient(t, Config{
		Endpoint: "https://clickhouse.example.test", Database: "analytics_test", QueryTimeout: 5 * time.Second,
	}, httpClient)

	caller, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	deadline, ok := caller.Deadline()
	if !ok {
		t.Fatal("caller deadline missing")
	}
	callerBudget := time.Until(deadline)
	if _, err := client.Summary(caller, AdminScope(), validFilter()); err != nil {
		t.Fatal(err)
	}
	if len(httpClient.maxExecutionSeconds) != 1 {
		t.Fatalf("captured max_execution_time values = %v", httpClient.maxExecutionSeconds)
	}
	if got := httpClient.maxExecutionSeconds[0]; got <= 0 || got > callerBudget.Seconds() {
		t.Fatalf("max_execution_time = %v, caller budget = %v", got, callerBudget.Seconds())
	}

	const configuredTimeout = 1500 * time.Millisecond
	configuredHTTPClient := &deadlineBudgetHTTPClient{}
	configuredClient := mustClient(t, Config{
		Endpoint: "https://clickhouse.example.test", Database: "analytics_test", QueryTimeout: configuredTimeout,
	}, configuredHTTPClient)
	if _, err := configuredClient.Summary(context.Background(), AdminScope(), validFilter()); err != nil {
		t.Fatal(err)
	}
	if len(configuredHTTPClient.maxExecutionSeconds) != 1 {
		t.Fatalf("captured configured max_execution_time values = %v", configuredHTTPClient.maxExecutionSeconds)
	}
	if got := configuredHTTPClient.maxExecutionSeconds[0]; got <= 0 || got > configuredTimeout.Seconds() {
		t.Fatalf("max_execution_time = %v, configured ceiling = %v", got, configuredTimeout.Seconds())
	}
}

func TestClientExecuteRejectsDoneContextBeforeDispatch(t *testing.T) {
	httpClient := &deadlineBudgetHTTPClient{}
	client := mustClient(t, Config{
		Endpoint: "https://clickhouse.example.test", Database: "analytics_test", QueryTimeout: time.Second,
	}, httpClient)

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Summary(canceled, AdminScope(), validFilter()); err != context.Canceled {
		t.Fatalf("canceled error = %v", err)
	}
	expired, expire := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer expire()
	if _, err := client.Summary(expired, AdminScope(), validFilter()); err != context.DeadlineExceeded {
		t.Fatalf("expired error = %v", err)
	}
	if httpClient.dispatches != 0 {
		t.Fatalf("HTTP dispatches for done contexts = %d", httpClient.dispatches)
	}
}
