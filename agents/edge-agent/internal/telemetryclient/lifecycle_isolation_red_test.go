package telemetryclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type failureIsolatedTelemetryRunner interface {
	RunFailureIsolated(context.Context, func(string))
}

func TestOBSUsageAOwnedLifecycleHookBreaksDeliberateFailureCoupling(t *testing.T) {
	trafficContext, stopTraffic := context.WithCancel(context.Background())
	defer stopTraffic()
	worker, err := NewWorker(WorkerConfig{
		MaximumEvents: 1, EmptyInterval: time.Millisecond,
		InitialBackoff: time.Millisecond, MaximumBackoff: 2 * time.Millisecond,
	}, backpressuredSpool{}, unreachableBackpressurePublisher{})
	if err != nil {
		t.Fatal(err)
	}
	worker.jitter = func(time.Duration) time.Duration { return time.Millisecond }
	runner, ok := any(worker).(failureIsolatedTelemetryRunner)
	if !ok {
		t.Fatal("telemetry worker has no owned failure-isolation composition hook")
	}

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		select {
		case <-trafficContext.Done():
			http.Error(writer, "traffic lifecycle cancelled", http.StatusServiceUnavailable)
		default:
			writer.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()

	telemetryContext, cancelTelemetry := context.WithCancel(trafficContext)
	reported := make(chan string, 1)
	done := make(chan struct{})
	go func() {
		runner.RunFailureIsolated(telemetryContext, func(code string) { reported <- code })
		close(done)
	}()
	deadline := time.Now().Add(time.Second)
	for !worker.Snapshot().Degraded && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancelTelemetry()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("isolated telemetry lifecycle did not terminate")
	}
	select {
	case code := <-reported:
		if code != "TELEMETRY_BACKPRESSURE" && code != "TELEMETRY_UNAVAILABLE" {
			t.Fatalf("unexpected isolated telemetry code %q", code)
		}
	default:
		t.Fatal("isolated telemetry failure was not reported")
	}
	if err := trafficContext.Err(); err != nil {
		t.Fatalf("telemetry lifecycle cancelled existing traffic: %v", err)
	}
	response, err := http.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("existing request failed after telemetry shutdown: %d", response.StatusCode)
	}
	if !errors.Is(telemetryContext.Err(), context.Canceled) {
		t.Fatalf("telemetry context state=%v", telemetryContext.Err())
	}
}
