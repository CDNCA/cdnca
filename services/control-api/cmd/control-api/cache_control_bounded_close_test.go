package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func TestCacheControlProductionCloseIgnoresTypedNilNATSConnection(t *testing.T) {
	var connection *nats.Conn
	if err := closeCacheControlProductionResourcesContext(t.Context(), nil, connection); err != nil {
		t.Fatalf("typed-nil cache control NATS connection close = %v", err)
	}
}

func TestCacheControlProductionCloseIsBoundedOrderedAndIdempotent(t *testing.T) {
	dependencies := configuredCacheControlRuntimeDependencies(t)
	started := make(chan struct{})
	release := make(chan struct{})
	operations := make([]string, 0, 3)
	worker := &fakeCacheControlWorker{
		configured: true,
		run: func(ctx context.Context, _ func(error)) error {
			close(started)
			<-release
			return ctx.Err()
		},
		close: func() error {
			operations = append(operations, "worker")
			return nil
		},
	}
	runtime := newCacheControlRuntimeTestSubject(dependencies, worker)
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(t.Context()) }()
	<-started

	connection := cacheControlCloseRecorder{
		drain: func() error {
			operations = append(operations, "unexpected drain")
			return nil
		},
		close: func() { operations = append(operations, "nats") },
	}
	closeCtx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	startedClose := time.Now()
	err := closeCacheControlProductionResourcesContext(closeCtx, runtime, connection)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(startedClose) >= time.Second {
		t.Fatalf("bounded close elapsed=%v error=%v", time.Since(startedClose), err)
	}
	if got := strings.Join(operations, ","); got != "worker,nats" {
		t.Fatalf("bounded close order=%q", got)
	}

	close(release)
	if err := <-runDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("release cache worker: %v", err)
	}
	if err := runtime.CloseContext(t.Context()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("idempotent close error=%v", err)
	}
	if worker.closeCalls.Load() != 1 {
		t.Fatalf("worker close calls=%d", worker.closeCalls.Load())
	}
}
