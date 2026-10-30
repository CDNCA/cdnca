package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/announcement"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/notificationruntime"
)

// The notification and announcement runtimes used to take control-api down
// after 8 / 3 consecutive failures (about 1-2 minutes / 15 seconds) while
// PostgreSQL restarted. A temporarily unavailable database now ends the
// attempt uncounted and runWithDBBackoff runs it again.

// fakeNotificationCore fails its first `fail` Runs with err, then runs until
// cancelled; it is ready only while a Run is in progress.
type fakeNotificationCore struct {
	notificationTestCore
	fail    int
	err     error
	runs    atomic.Int32
	running atomic.Bool
}

func newFakeNotificationCore(fail int, err error) *fakeNotificationCore {
	core := &fakeNotificationCore{fail: fail, err: err}
	core.ready = func(context.Context, notification.ChannelSwitches) error {
		if !core.running.Load() {
			return notificationruntime.ErrWorkerNotRunning
		}
		return nil
	}
	return core
}

func (core *fakeNotificationCore) Run(ctx context.Context) error {
	if int(core.runs.Add(1)) <= core.fail {
		// Startup readiness passes before the database goes away.
		core.running.Store(true)
		time.Sleep(20 * time.Millisecond)
		core.running.Store(false)
		return core.err
	}
	core.running.Store(true)
	defer core.running.Store(false)
	<-ctx.Done()
	return nil
}

// ctx is shared with the supervisor, like main.go does with its signal context.
func startFakeNotificationRuntime(t *testing.T, ctx context.Context, core *fakeNotificationCore) *notificationProcessRuntime {
	t.Helper()
	runtime, err := startNotificationProcessRuntime(
		ctx, core, notification.ChannelSwitches{Email: true}, time.Second, time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	return runtime
}

func waitForDBBackoff2(t *testing.T, timeout time.Duration, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestNotificationRuntimeSurvivesPGRestartUnderBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	core := newFakeNotificationCore(1, pgTerminatedError())
	runtime := startFakeNotificationRuntime(t, ctx, core)
	failures := make(chan error, 1)
	supervised := make(chan struct{})
	go func() {
		runRequiredNotificationRuntime(ctx, runtime, failures)
		close(supervised)
	}()

	waitForDBBackoff2(t, time.Second, "database error", func() bool { return core.runs.Load() == 1 && !core.running.Load() })
	if err := runtime.ReadinessProbe().Ready(); err == nil {
		t.Fatal("notification runtime ready while the database is unavailable")
	}
	waitForDBBackoff2(t, 10*time.Second, "notification runtime ready again", func() bool {
		return core.runs.Load() == 2 && runtime.ReadinessProbe().Ready() == nil
	})
	select {
	case err := <-failures:
		t.Fatalf("notification runtime reported terminal after 57P01 (process would exit): %v", err)
	default:
	}
	cancel()
	<-supervised
	select {
	case err := <-failures:
		t.Fatalf("notification runtime reported terminal on shutdown: %v", err)
	default:
	}
}

func TestNotificationRuntimeNonDatabaseFailureStillExits(t *testing.T) {
	// After MaxConsecutiveFailures the core returns ErrWorkerExited.
	core := newFakeNotificationCore(1, notificationruntime.ErrWorkerExited)
	runtime := startFakeNotificationRuntime(t, context.Background(), core)
	failures := make(chan error, 1)
	runRequiredNotificationRuntime(context.Background(), runtime, failures)
	select {
	case err := <-failures:
		if !errors.Is(err, notificationruntime.ErrWorkerExited) || err.Error() != "notification runtime stopped" {
			t.Fatalf("terminal error = %v", err)
		}
	default:
		t.Fatal("non-database failure was not reported")
	}
	if runs := core.runs.Load(); runs != 1 {
		t.Fatalf("core.Run called %d times, want 1", runs)
	}
}

// Run waits for the attempt started with the process; once that attempt was
// returned, the next Run starts the worker again and readiness recovers.
func TestNotificationProcessRuntimeRunRestartsWorker(t *testing.T) {
	core := newFakeNotificationCore(1, pgTerminatedError())
	runtime := startFakeNotificationRuntime(t, context.Background(), core)
	if err := runtime.Run(context.Background()); !isTransientDBError(err) {
		t.Fatalf("first Run = %v, want the database error", err)
	}
	if err := runtime.ReadinessProbe().Ready(); err == nil {
		t.Fatal("ready after the worker stopped")
	}
	done := make(chan error, 1)
	go func() { done <- runtime.Run(context.Background()) }()
	waitForDBBackoff2(t, time.Second, "readiness after Run restarted the worker", func() bool {
		return runtime.ReadinessProbe().Ready() == nil
	})
	if err := runtime.Run(context.Background()); !errors.Is(err, notificationruntime.ErrAlreadyRunning) {
		t.Fatalf("concurrent Run = %v, want ErrAlreadyRunning", err)
	}
	if err := runtime.workerError(); err != nil {
		t.Fatalf("previous terminal error was not cleared: %v", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, notificationruntime.ErrWorkerExited) {
		t.Fatalf("Run after Close = %v", err)
	}
	if err := runtime.Run(context.Background()); !errors.Is(err, notificationruntime.ErrWorkerNotRunning) {
		t.Fatalf("Run after Close = %v, want ErrWorkerNotRunning", err)
	}
	if runs := core.runs.Load(); runs != 2 {
		t.Fatalf("core.Run called %d times, want 2", runs)
	}
}

// Cancelling the supervisor context ends Run even if the runtime's own
// context is still alive.
func TestNotificationProcessRuntimeRunHonoursCallerContext(t *testing.T) {
	core := newFakeNotificationCore(0, nil)
	runtime := startFakeNotificationRuntime(t, context.Background(), core)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run ignored its context")
	}
	if err := runtime.ReadinessProbe().Ready(); err != nil {
		t.Fatalf("worker attempt was disturbed: %v", err)
	}
}

func newFakeAnnouncementRuntime(publishDue func(context.Context, int) ([]announcement.Announcement, error)) *announcementRuntime {
	ctx, cancel := context.WithCancel(context.Background())
	runtime := &announcementRuntime{
		store: &announcement.Store{}, publishDue: publishDue,
		config: announcementRuntimeConfig{
			Enabled: true, ExternalChannel: announcementExternalChannelDisabled, PollInterval: 5 * time.Millisecond,
			OperationTimeout: time.Second, ShutdownTimeout: time.Second, BatchSize: 1,
		},
		context: ctx, cancel: cancel, done: make(chan struct{}),
	}
	runtime.state.Store(announcementStateReady)
	runtime.lastErrorCode.Store("")
	return runtime
}

func TestAnnouncementRuntimeSurvivesPGRestartUnderBackoff(t *testing.T) {
	var calls atomic.Int32
	// announcementFailureThreshold database errors (the old limit), then recovery.
	runtime := newFakeAnnouncementRuntime(func(context.Context, int) ([]announcement.Announcement, error) {
		if calls.Add(1) <= announcementFailureThreshold {
			return nil, pgTerminatedError()
		}
		return nil, nil
	})
	t.Cleanup(func() { _ = runtime.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	failures := make(chan error, 1)
	supervised := make(chan struct{})
	go func() {
		runRequiredAnnouncementRuntime(ctx, runtime, failures)
		close(supervised)
	}()

	waitForDBBackoff2(t, time.Second, "database error", func() bool { return calls.Load() >= 1 })
	waitForDBBackoff2(t, time.Second, "backoff state", func() bool { return runtime.Ready() != nil })
	waitForDBBackoff2(t, 30*time.Second, "announcement runtime working again", func() bool {
		return calls.Load() > announcementFailureThreshold+1 && runtime.Ready() == nil
	})
	if got := runtime.consecutiveFail.Load(); got != 0 {
		t.Fatalf("database errors counted as scheduler failures: %d", got)
	}
	select {
	case err := <-failures:
		t.Fatalf("announcement runtime reported terminal after 57P01 (process would exit): %v", err)
	default:
	}
	cancel()
	_ = runtime.Close()
	<-supervised
	select {
	case err := <-failures:
		t.Fatalf("announcement runtime reported terminal on shutdown: %v", err)
	default:
	}
}

func TestAnnouncementRuntimeNonDatabaseFailureKeepsThreshold(t *testing.T) {
	sentinel := errors.New("announcement store rejected batch")
	var calls atomic.Int32
	runtime := newFakeAnnouncementRuntime(func(context.Context, int) ([]announcement.Announcement, error) {
		calls.Add(1)
		return nil, sentinel
	})
	t.Cleanup(func() { _ = runtime.Close() })
	failures := make(chan error, 1)
	runRequiredAnnouncementRuntime(context.Background(), runtime, failures)
	select {
	case err := <-failures:
		if !errors.Is(err, sentinel) || err.Error() != "announcement runtime stopped" {
			t.Fatalf("terminal error = %v", err)
		}
	default:
		t.Fatal("non-database failure was not reported")
	}
	if got := calls.Load(); got != announcementFailureThreshold {
		t.Fatalf("PublishDue called %d times, want %d", got, announcementFailureThreshold)
	}
	if err := runtime.Ready(); err == nil {
		t.Fatal("failed announcement runtime remained ready")
	}
}

func TestAnnouncementRuntimeRunRestartsAfterDatabaseError(t *testing.T) {
	var calls atomic.Int32
	runtime := newFakeAnnouncementRuntime(func(context.Context, int) ([]announcement.Announcement, error) {
		if calls.Add(1) == 1 {
			return nil, pgTerminatedError()
		}
		return nil, nil
	})
	if err := runtime.Run(context.Background()); !isTransientDBError(err) {
		t.Fatalf("first Run = %v, want the database error", err)
	}
	if err := runtime.Ready(); err == nil {
		t.Fatal("ready while the database is unavailable")
	}
	done := make(chan error, 1)
	go func() { done <- runtime.Run(context.Background()) }()
	waitForDBBackoff2(t, time.Second, "second Run publishing", func() bool { return calls.Load() >= 2 })
	if err := runtime.Ready(); err != nil {
		t.Fatalf("ready after rerun = %v", err)
	}
	if err := runtime.Run(context.Background()); err == nil {
		t.Fatal("concurrent Run was accepted")
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("Run after Close = %v", err)
	}
	if err := runtime.Run(context.Background()); err == nil {
		t.Fatal("Run after Close was accepted")
	}
}
