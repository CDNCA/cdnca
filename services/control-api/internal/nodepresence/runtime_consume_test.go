package nodepresence

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

type scriptedConsumer struct {
	mu      sync.Mutex
	results []error
	calls   int
}

func (c *scriptedConsumer) Next(ctx context.Context) (Delivery, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if len(c.results) == 0 {
		return nil, ctx.Err()
	}
	err := c.results[0]
	c.results = c.results[1:]
	return nil, err
}

func (*scriptedConsumer) Close() error { return nil }

// consumeRuntime runs consume with a fake clock and a recording sleep; stopAfter
// sleeps cancel the context.
func consumeRuntime(consumer heartbeatConsumer, stopAfter int) (*Runtime, context.Context, *[]time.Duration, *time.Time) {
	ctx, cancel := context.WithCancel(context.Background())
	clock := time.Unix(1_800_000_000, 0)
	slept := []time.Duration{}
	runtime := &Runtime{consumer: consumer, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	runtime.now = func() time.Time { return clock }
	runtime.sleep = func(ctx context.Context, delay time.Duration) error {
		slept = append(slept, delay)
		clock = clock.Add(delay)
		if len(slept) == stopAfter {
			cancel()
			return ctx.Err()
		}
		return nil
	}
	return runtime, ctx, &slept, &clock
}

// A failed durable fetch used to end consume,
// Run and the whole control API process.
func TestConsumeRetriesFetchErrorsWithBackoffUntilCanceled(t *testing.T) {
	failure := fmt.Errorf("fetch durable heartbeat: %w", errors.New("nats: no responders available for request"))
	consumer := &scriptedConsumer{results: []error{failure, failure, failure, failure, failure, failure, failure, failure}}
	runtime, ctx, slept, _ := consumeRuntime(consumer, 8)
	if err := runtime.consume(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("consume() = %v, want it to keep retrying until the context ends", err)
	}
	want := []time.Duration{1, 2, 4, 8, 16, 30, 30, 30}
	for i := range want {
		want[i] *= time.Second
	}
	if fmt.Sprint(*slept) != fmt.Sprint(want) {
		t.Fatalf("backoff = %v, want %v (capped at 30 s)", *slept, want)
	}
}

func TestConsumeBackoffResetsAfterAHealthyFetch(t *testing.T) {
	failure := errors.New("fetch durable heartbeat: connection closed")
	consumer := &scriptedConsumer{results: []error{failure, failure, ErrNoMessage, failure, failure}}
	runtime, ctx, slept, _ := consumeRuntime(consumer, 4)
	if err := runtime.consume(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("consume() = %v", err)
	}
	want := []time.Duration{time.Second, 2 * time.Second, time.Second, 2 * time.Second}
	if fmt.Sprint(*slept) != fmt.Sprint(want) {
		t.Fatalf("backoff = %v, want %v", *slept, want)
	}
	if err := runtime.Ready(); err != nil {
		t.Fatalf("Ready() right after a fresh failure run = %v", err)
	}
}

func TestReadyReportsAFetchThatKeepsFailingAndRecovers(t *testing.T) {
	failure := errors.New("fetch durable heartbeat: consumer not found")
	results := make([]error, 8)
	for i := range results {
		results[i] = failure
	}
	consumer := &scriptedConsumer{results: results}
	runtime, ctx, _, clock := consumeRuntime(consumer, 8)
	if err := runtime.Ready(); err != nil {
		t.Fatalf("Ready() before any failure = %v", err)
	}
	_ = runtime.consume(ctx)
	// 1+2+4+8+16+30+30 s have passed since the first failure.
	if err := runtime.Ready(); err == nil || !errors.Is(err, failure) {
		t.Fatalf("Ready() after a fetch failing for %s = %v, want the fetch error", clock.Sub(time.Unix(1_800_000_000, 0)), err)
	}
	// A message-less but healthy fetch clears it.
	runtime.fetchSucceeded()
	if err := runtime.Ready(); err != nil {
		t.Fatalf("Ready() after recovery = %v", err)
	}
}

func TestConsumeStopsPromptlyWhenCanceledDuringBackoff(t *testing.T) {
	consumer := &scriptedConsumer{results: []error{errors.New("boom"), errors.New("boom")}}
	runtime := &Runtime{consumer: consumer, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.consume(ctx) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("consume() = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("consume did not stop on cancellation while backing off")
	}
}
