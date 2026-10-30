package notificationruntime

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
)

var errTestDatabaseRestart = errors.New("terminating connection due to administrator command")

func transientTestError(err error) bool { return errors.Is(err, errTestDatabaseRestart) }

// A temporarily unavailable database ends Run with the original error without
// counting towards MaxConsecutiveFailures; Run can be called again and the
// runtime becomes ready after the first successful batch of the retry.
func TestRuntimeTransientDatabaseErrorEndsRunUncountedAndRunRestarts(t *testing.T) {
	processor := &scriptedProcessor{errors: []error{errTestDatabaseRestart, errTestDatabaseRestart, errTestDatabaseRestart}}
	runtime := testRuntime(t, processor, RuntimeConfig{
		IdleWait: time.Millisecond, MaxConsecutiveFailures: 1, TransientError: transientTestError,
	})
	for attempt := 1; attempt <= 3; attempt++ {
		if err := runtime.Run(context.Background()); !errors.Is(err, errTestDatabaseRestart) {
			t.Fatalf("attempt %d: Run = %v, want the database error", attempt, err)
		}
		health := runtime.Health()
		if health.ConsecutiveFailures != 0 || health.State != StateBackoff || health.WorkerRunning {
			t.Fatalf("attempt %d: health after database error = %+v", attempt, health)
		}
		if err := runtime.Ready(context.Background(), notification.ChannelSwitches{Email: true}); err == nil {
			t.Fatalf("attempt %d: runtime ready while the database is unavailable", attempt)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	waitFor(t, time.Second, func() bool {
		return runtime.Ready(context.Background(), notification.ChannelSwitches{Email: true}) == nil
	})
	if err := runtime.Run(context.Background()); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("concurrent Run = %v, want ErrAlreadyRunning", err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run after cancel = %v", err)
	}
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Run(context.Background()); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("Run after Close = %v, want ErrAlreadyRunning", err)
	}
}

// Other batch errors keep the consecutive-failure limit and stop the worker.
func TestRuntimeNonDatabaseErrorKeepsConsecutiveFailureLimit(t *testing.T) {
	storeDown := errors.New("notification store unavailable")
	processor := &scriptedProcessor{errors: []error{storeDown, storeDown, storeDown, storeDown}}
	runtime := testRuntime(t, processor, RuntimeConfig{
		ErrorBackoffBase: time.Millisecond, ErrorBackoffMax: time.Millisecond,
		MaxConsecutiveFailures: 3, TransientError: transientTestError,
	})
	if err := runtime.Run(context.Background()); !errors.Is(err, ErrWorkerExited) {
		t.Fatalf("Run = %v, want ErrWorkerExited", err)
	}
	if calls := len(processor.callTimes()); calls != 3 {
		t.Fatalf("batches = %d, want 3", calls)
	}
	if health := runtime.Health(); health.ConsecutiveFailures != 3 || health.State != StateFailed {
		t.Fatalf("health = %+v", health)
	}
}
