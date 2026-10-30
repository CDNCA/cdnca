package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cccoord"
)

func TestCCCoordinationRuntimeRunsConsumerAndCoordinatorUntilShutdown(t *testing.T) {
	consumer := &ccRuntimeConsumerStub{}
	coordinator := &ccRuntimeCoordinatorStub{}
	runtime := &ccCoordinationRuntime{consumer: consumer, coordinator: coordinator}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	deadline := time.After(time.Second)
	for consumer.calls.Load() == 0 || coordinator.calls.Load() == 0 {
		select {
		case <-deadline:
			t.Fatal("runtime did not exercise both durable loops")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	if err := <-done; err != context.Canceled {
		t.Fatalf("Run() error = %v", err)
	}
	if err := runtime.Close(); err != nil || consumer.closes.Load() != 1 {
		t.Fatalf("Close() = %v closes=%d", err, consumer.closes.Load())
	}
}

type ccRuntimeConsumerStub struct {
	calls  atomic.Int64
	closes atomic.Int64
}

func (stub *ccRuntimeConsumerStub) RunOnce(ctx context.Context) (cccoord.ObserveResult, error) {
	stub.calls.Add(1)
	select {
	case <-ctx.Done():
		return cccoord.ObserveResult{}, ctx.Err()
	case <-time.After(time.Millisecond):
		return cccoord.ObserveResult{}, nil
	}
}

func (stub *ccRuntimeConsumerStub) Close() error {
	stub.closes.Add(1)
	return nil
}

type ccRuntimeCoordinatorStub struct{ calls atomic.Int64 }

func (stub *ccRuntimeCoordinatorStub) RunOnce(context.Context) (cccoord.RunResult, error) {
	stub.calls.Add(1)
	return cccoord.RunResult{}, nil
}
