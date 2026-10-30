package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgrade"
)

type nativeStatusStub struct {
	publish func(context.Context, string) error
}

func (nativeStatusStub) Run(context.Context, []byte) (controlplaneupgrade.Receipt, error) {
	return controlplaneupgrade.Receipt{}, nil
}
func (nativeStatusStub) Probe(context.Context) (controlplaneupgrade.NativeStandaloneStatus, error) {
	return controlplaneupgrade.NativeStandaloneStatus{}, nil
}
func (runner nativeStatusStub) PublishStatus(ctx context.Context, path string) error {
	return runner.publish(ctx, path)
}

func TestNativeStatusHeartbeatContinuesWhileLoopIsBusyAndPublishesFinalState(t *testing.T) {
	var calls atomic.Int32
	var finished atomic.Bool
	var final atomic.Bool
	heartbeat := make(chan struct{}, 1)
	runner := nativeStatusStub{publish: func(_ context.Context, path string) error {
		if path != "/run/native/status.json" {
			t.Errorf("path=%q", path)
		}
		if calls.Add(1) > 1 {
			select {
			case heartbeat <- struct{}{}:
			default:
			}
		}
		if finished.Load() {
			final.Store(true)
		}
		return nil
	}}
	err := runNativeWithStatus(t.Context(), runner, "/run/native/status.json", time.Millisecond, func(ctx context.Context) error {
		select {
		case <-heartbeat:
			finished.Store(true)
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
			t.Fatal("heartbeat stopped while execution loop was busy")
			return nil
		}
	})
	if err != nil || !final.Load() {
		t.Fatalf("final status persisted=%v err=%v", final.Load(), err)
	}
}

func TestNativeStatusHeartbeatCancellationDoesNotReplaceSuccessfulLoop(t *testing.T) {
	var calls atomic.Int32
	started := make(chan struct{})
	runner := nativeStatusStub{publish: func(ctx context.Context, _ string) error {
		if calls.Add(1) == 2 {
			close(started)
			<-ctx.Done()
			return ctx.Err()
		}
		return nil
	}}
	err := runNativeWithStatus(t.Context(), runner, "/run/native/status.json", time.Millisecond, func(context.Context) error {
		select {
		case <-started:
			return nil
		case <-time.After(time.Second):
			t.Fatal("heartbeat did not start")
			return nil
		}
	})
	if err != nil || calls.Load() < 3 {
		t.Fatalf("successful loop was replaced by cancellation err=%v calls=%d", err, calls.Load())
	}
}

func TestNativeStatusWriteFailureStopsLoopAndRemainsError(t *testing.T) {
	want := errors.New("status persistence failed")
	for _, failAt := range []int32{1, 2} {
		var calls atomic.Int32
		var loopCalled atomic.Bool
		runner := nativeStatusStub{publish: func(context.Context, string) error {
			if calls.Add(1) == failAt {
				return want
			}
			return nil
		}}
		err := runNativeWithStatus(t.Context(), runner, "/run/native/status.json", time.Millisecond, func(ctx context.Context) error {
			loopCalled.Store(true)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Second):
				t.Fatal("status failure did not cancel loop")
				return nil
			}
		})
		if !errors.Is(err, want) || (failAt == 1 && loopCalled.Load()) {
			t.Fatalf("failure=%d err=%v loop=%v", failAt, err, loopCalled.Load())
		}
	}
}
