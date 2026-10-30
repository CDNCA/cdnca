package acmeworker

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type reconcileIssuer struct {
	mu         sync.Mutex
	active     int
	maxActive  int
	calls      int
	release    <-chan struct{}
	onFirstRun func()
}

func (i *reconcileIssuer) Issue(ctx context.Context, request IssueRequest) (IssueResult, error) {
	i.mu.Lock()
	i.active++
	i.calls++
	if i.active > i.maxActive {
		i.maxActive = i.active
	}
	onFirstRun := i.onFirstRun
	i.onFirstRun = nil
	i.mu.Unlock()
	if onFirstRun != nil {
		onFirstRun()
	}
	if i.release != nil {
		select {
		case <-i.release:
		case <-ctx.Done():
			i.finish()
			return IssueResult{}, contextFailure(ctx.Err())
		}
	}
	i.finish()
	return IssueResult{OrderURI: request.OperationID}, nil
}

func (i *reconcileIssuer) finish() {
	i.mu.Lock()
	i.active--
	i.mu.Unlock()
}

func TestReconcilerRunOnceBoundsConcurrency(t *testing.T) {
	operations := newMemoryOperations()
	requests := make([]IssueRequest, 6)
	for index := range requests {
		requests[index] = validIssueRequest(ChallengeDNS01, "reconcile.example.test")
		setRequestOrderID(&requests[index], string(rune('a'+index)))
		operations.items[operationKey(requests[index].TenantID, requests[index].OperationID)] = &memoryOperation{
			request: requests[index], lease: OperationLease{
				State: OperationState{Status: OperationRetryWait},
			},
		}
	}
	release := make(chan struct{})
	issuer := &reconcileIssuer{release: release}
	config := DefaultReconcilerConfig()
	config.Clock = func() time.Time { return testNow }
	config.MaxConcurrent = 2
	reconciler, err := NewReconciler(config, issuer, operations)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan []ReconcileResult, 1)
	go func() {
		results, _ := reconciler.RunOnce(context.Background())
		done <- results
	}()
	deadline := time.After(time.Second)
	for {
		issuer.mu.Lock()
		active := issuer.active
		issuer.mu.Unlock()
		if active == 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("reconciler did not start two workers")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	close(release)
	results := <-done
	issuer.mu.Lock()
	defer issuer.mu.Unlock()
	if len(results) != len(requests) || issuer.calls != len(requests) || issuer.maxActive != 2 || issuer.active != 0 {
		t.Fatalf("results=%d calls=%d max=%d active=%d", len(results), issuer.calls, issuer.maxActive, issuer.active)
	}
}

func TestReconcilerRunStartsImmediatelyAndCancels(t *testing.T) {
	operations := newMemoryOperations()
	request := validIssueRequest(ChallengeDNS01, "startup.example.test")
	operations.items[operationKey(request.TenantID, request.OperationID)] = &memoryOperation{
		request: request, lease: OperationLease{State: OperationState{Status: OperationRetryWait}},
	}
	ctx, cancel := context.WithCancel(context.Background())
	issuer := &reconcileIssuer{onFirstRun: cancel}
	config := DefaultReconcilerConfig()
	config.Clock = func() time.Time { return testNow }
	config.Interval = time.Hour
	reconciler, err := NewReconciler(config, issuer, operations)
	if err != nil {
		t.Fatal(err)
	}
	if err := reconciler.Run(ctx); err != context.Canceled {
		t.Fatalf("Run() error = %v", err)
	}
	issuer.mu.Lock()
	defer issuer.mu.Unlock()
	if issuer.calls != 1 || issuer.active != 0 {
		t.Fatalf("calls=%d active=%d", issuer.calls, issuer.active)
	}
}

type flakyReconcileOperations struct {
	*memoryOperations
	mu       sync.Mutex
	failures int
	calls    int
}

func (operations *flakyReconcileOperations) Recoverable(
	ctx context.Context,
	now time.Time,
	limit int,
) ([]IssueRequest, error) {
	operations.mu.Lock()
	operations.calls++
	if operations.failures > 0 {
		operations.failures--
		operations.mu.Unlock()
		return nil, errors.New("temporary recovery store failure")
	}
	operations.mu.Unlock()
	return operations.memoryOperations.Recoverable(ctx, now, limit)
}

func TestReconcilerRunRetriesRecoverableFailuresWithoutDuplicateProcessing(t *testing.T) {
	memory := newMemoryOperations()
	request := validIssueRequest(ChallengeDNS01, "recover-after-store.example.test")
	memory.items[operationKey(request.TenantID, request.OperationID)] = &memoryOperation{
		request: request, lease: OperationLease{State: OperationState{Status: OperationRetryWait}},
	}
	operations := &flakyReconcileOperations{memoryOperations: memory, failures: 2}
	issuer := &reconcileIssuer{}
	config := DefaultReconcilerConfig()
	config.Clock = func() time.Time { return testNow }
	config.Interval = time.Minute
	config.ErrorBackoff = time.Second
	ctx, cancel := context.WithCancel(context.Background())
	var waits []time.Duration
	reconciler, err := newReconciler(config, issuer, operations,
		func(waitCtx context.Context, duration time.Duration) error {
			waits = append(waits, duration)
			if len(waits) == 3 {
				cancel()
				return waitCtx.Err()
			}
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if err := reconciler.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v", err)
	}
	operations.mu.Lock()
	recoveryCalls := operations.calls
	operations.mu.Unlock()
	issuer.mu.Lock()
	issueCalls, maximum := issuer.calls, issuer.maxActive
	issuer.mu.Unlock()
	if recoveryCalls != 3 || issueCalls != 1 || maximum != 1 ||
		len(waits) != 3 || waits[0] != config.ErrorBackoff ||
		waits[1] != config.ErrorBackoff || waits[2] != config.Interval {
		t.Fatalf("recoveries=%d issues=%d maximum=%d waits=%v", recoveryCalls, issueCalls, maximum, waits)
	}
}

func TestReconcilerRunCancelsDuringRecoverableBackoff(t *testing.T) {
	operations := &flakyReconcileOperations{memoryOperations: newMemoryOperations(), failures: 1}
	config := DefaultReconcilerConfig()
	config.ErrorBackoff = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	var waited time.Duration
	reconciler, err := newReconciler(config, &reconcileIssuer{}, operations,
		func(waitCtx context.Context, duration time.Duration) error {
			waited = duration
			cancel()
			return waitForRenewalContext(waitCtx, duration)
		})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err := reconciler.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v", err)
	}
	if waited != config.ErrorBackoff || time.Since(started) > time.Second {
		t.Fatalf("waited=%s elapsed=%s", waited, time.Since(started))
	}
}

func TestReconcilerRejectsUnsafeErrorBackoff(t *testing.T) {
	for _, backoff := range []time.Duration{0, time.Hour + time.Nanosecond} {
		config := DefaultReconcilerConfig()
		config.ErrorBackoff = backoff
		if _, err := NewReconciler(config, &reconcileIssuer{}, newMemoryOperations()); ErrorCodeOf(err) != CodeInvalidInput {
			t.Fatalf("ErrorBackoff=%s error=%v", backoff, err)
		}
	}
}
