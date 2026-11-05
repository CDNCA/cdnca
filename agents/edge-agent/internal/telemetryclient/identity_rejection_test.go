package telemetryclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewaytunnel"
)

// A gateway refusing the node certificate backs telemetry off 30s, 1m, ...
// instead of its 10ms..30s reconnect backoff; a network error keeps the
// normal backoff and an accepted flush resets the identity backoff.
func TestWorkerBacksOffIdentityRejection(t *testing.T) {
	rejected := fmt.Errorf("gateway tunnel upgrade 401 Unauthorized: %w", gatewaytunnel.ErrNodeIdentityRejected)
	spool := &scriptedSpool{responses: make(chan flushResponse, 8)}
	for _, err := range []error{rejected, &net.OpError{Op: "dial", Err: errors.New("connection refused")}, rejected, nil, rejected} {
		spool.responses <- flushResponse{err: err}
	}
	worker, err := NewWorker(WorkerConfig{MaximumEvents: 10, EmptyInterval: time.Millisecond,
		InitialBackoff: time.Millisecond, MaximumBackoff: 10 * time.Millisecond}, spool, unusedPublisher{})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var bases []time.Duration
	worker.jitter = func(base time.Duration) time.Duration {
		mu.Lock()
		bases = append(bases, base)
		mu.Unlock()
		return time.Millisecond
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		mu.Lock()
		count := len(bases)
		mu.Unlock()
		if count >= 7 || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() = %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	// Each error asks the normal backoff first; a rejection then asks the
	// identity backoff, which replaces it.
	var identity, normal []time.Duration
	for _, base := range bases {
		if base >= gatewaytunnel.IdentityRetryInitial {
			identity = append(identity, base)
		} else {
			normal = append(normal, base)
		}
	}
	if fmt.Sprint(identity) != fmt.Sprint([]time.Duration{30 * time.Second, time.Minute, 30 * time.Second}) {
		t.Fatalf("identity backoff = %v (all %v), want [30s 1m0s 30s]", identity, bases)
	}
	if len(normal) != 4 || normal[len(normal)-1] > 10*time.Millisecond {
		t.Fatalf("normal backoff = %v, want 4 waits within the 10ms maximum", normal)
	}
}
