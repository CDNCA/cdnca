package telemetryclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
)

type backpressuredSpool struct{}

func (backpressuredSpool) Flush(context.Context, eventspool.Publisher, int) (eventspool.PublishResult, error) {
	return eventspool.PublishResult{}, ErrBackpressure
}

func (backpressuredSpool) Stats() (eventspool.Stats, error) { return eventspool.Stats{}, nil }

type unreachableBackpressurePublisher struct{}

func (unreachableBackpressurePublisher) Publish(context.Context, []eventspool.Publication) (eventspool.PublishAck, error) {
	return eventspool.PublishAck{}, errors.New("must not be reached")
}

func TestOBSUsageATelemetryBackpressureCannotCancelExistingTraffic(t *testing.T) {
	trafficContext, stopTraffic := context.WithCancel(context.Background())
	defer stopTraffic()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		select {
		case <-trafficContext.Done():
			http.Error(writer, "traffic context stopped", http.StatusServiceUnavailable)
		default:
			writer.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()

	worker, err := NewWorker(WorkerConfig{
		MaximumEvents: 1, EmptyInterval: time.Millisecond,
		InitialBackoff: time.Millisecond, MaximumBackoff: 2 * time.Millisecond,
	}, backpressuredSpool{}, unreachableBackpressurePublisher{})
	if err != nil {
		t.Fatal(err)
	}
	worker.jitter = func(time.Duration) time.Duration { return time.Millisecond }
	telemetryContext, stopTelemetry := context.WithCancel(trafficContext)
	done := make(chan error, 1)
	go func() { done <- worker.Run(telemetryContext) }()
	deadline := time.Now().Add(time.Second)
	for !worker.Snapshot().Degraded && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if snapshot := worker.Snapshot(); !snapshot.Running || !snapshot.Degraded || snapshot.LastErrorCode != "TELEMETRY_BACKPRESSURE" {
		t.Fatalf("telemetry backpressure state=%+v", snapshot)
	}

	for attempt := 0; attempt < 3; attempt++ {
		response, requestErr := http.Get(server.URL)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("existing traffic failed under telemetry backpressure: status=%d", response.StatusCode)
		}
	}
	select {
	case <-trafficContext.Done():
		t.Fatal("telemetry failure propagated into the existing traffic context")
	default:
	}

	stopTelemetry()
	if runErr := <-done; !errors.Is(runErr, context.Canceled) {
		t.Fatalf("worker shutdown error=%v", runErr)
	}
}

var _ Spool = backpressuredSpool{}
var _ eventspool.Publisher = unreachableBackpressurePublisher{}
