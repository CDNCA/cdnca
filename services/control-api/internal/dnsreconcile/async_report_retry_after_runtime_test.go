package dnsreconcile

import (
	"context"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/google/uuid"
)

type asyncRetryYieldStore struct {
	*memoryStore
	yieldCalls int
	delay      time.Duration
	result     dnscheck.ReconcileResult
}

func (store *asyncRetryYieldStore) checkpointApplyAfter(
	_ context.Context,
	lease ApplyLease,
	result dnscheck.ReconcileResult,
	delay time.Duration,
) (Task, error) {
	store.yieldCalls++
	store.delay = delay
	store.result = result
	lease.Task.Result = result
	return lease.Task, nil
}

func TestActiveRetryAfterRecognizesAsyncTransientSnapshots(t *testing.T) {
	hint := 37 * time.Second
	for _, taskStatus := range []dnscheck.TaskStatus{dnscheck.TaskApplying, dnscheck.TaskPropagating} {
		for _, operationStatus := range []dnscheck.OperationStatus{
			dnscheck.OperationRunning,
			dnscheck.OperationTransientFailed,
		} {
			for _, class := range []dnscheck.ProviderErrorClass{dnscheck.ProviderErrorTransient, dnscheck.ProviderErrorTimeout} {
				result := asyncRetryAfterResult(taskStatus, operationStatus, hint)
				result.Operations[0].ErrorClass = class
				if got := activeRetryAfter(result); got != hint {
					t.Fatalf("activeRetryAfter(%s,%s,%s) = %s, want %s", taskStatus, operationStatus, class, got, hint)
				}
			}
		}
	}

	for _, result := range []dnscheck.ReconcileResult{
		asyncRetryAfterResult(dnscheck.TaskReadyToCommit, dnscheck.OperationTransientFailed, hint),
		func() dnscheck.ReconcileResult {
			result := asyncRetryAfterResult(dnscheck.TaskPropagating, dnscheck.OperationTransientFailed, hint)
			result.ErrorCode = "dependency_unavailable"
			return result
		}(),
		func() dnscheck.ReconcileResult {
			result := asyncRetryAfterResult(dnscheck.TaskPropagating, dnscheck.OperationTransientFailed, hint)
			result.Operations[0].ErrorCode = "dependency_unavailable"
			return result
		}(),
		func() dnscheck.ReconcileResult {
			result := asyncRetryAfterResult(dnscheck.TaskPropagating, dnscheck.OperationTransientFailed, hint)
			result.Operations[0].ErrorClass = dnscheck.ProviderErrorPermanent
			return result
		}(),
	} {
		if got := activeRetryAfter(result); got != 0 {
			t.Fatalf("activeRetryAfter(%#v) = %s, want no provider deferral", result, got)
		}
	}
}

func TestRunApplyClaimYieldsAsyncTransientBeforeResolutionOrMutation(t *testing.T) {
	now := time.Date(2026, 8, 7, 15, 30, 0, 0, time.UTC)
	store := &asyncRetryYieldStore{memoryStore: newMemoryStore()}
	checkers := &testCheckerResolver{}
	providers := &testProviderResolver{}
	runtime := &Runtime{
		config: RuntimeConfig{ApplyLeaseDuration: time.Minute, Now: func() time.Time { return now }},
		store:  store, checkers: checkers, providers: providers, entitlement: testEntitlement{},
	}
	result := asyncRetryAfterResult(dnscheck.TaskApplying, dnscheck.OperationTransientFailed, 37*time.Second)
	lease := ApplyLease{
		Task:     Task{ID: uuid.New(), TenantID: uuid.New(), SiteID: uuid.New(), Result: result},
		WorkerID: "async-report-worker", Attempt: 4, LeaseID: uuid.New(), LeaseExpiresAt: now.Add(16 * time.Minute),
	}

	if _, err := runtime.runApplyClaim(t.Context(), lease); err != nil {
		t.Fatal(err)
	}
	if store.yieldCalls != 1 || store.delay < 37*time.Second || store.delay > 37*time.Second+3700*time.Millisecond {
		t.Fatalf("yield calls=%d delay=%s, want one bounded provider deferral", store.yieldCalls, store.delay)
	}
	if checkers.calls != 0 || providers.calls != 0 {
		t.Fatalf("resolver calls=(checker=%d provider=%d), want zero before durable yield", checkers.calls, providers.calls)
	}
	if store.result.Operations[0].Status != dnscheck.OperationTransientFailed ||
		store.result.Operations[0].RetryAfter != 37*time.Second {
		t.Fatalf("yielded result = %#v, want unmodified async report", store.result)
	}
}

func asyncRetryAfterResult(
	taskStatus dnscheck.TaskStatus,
	operationStatus dnscheck.OperationStatus,
	hint time.Duration,
) dnscheck.ReconcileResult {
	return dnscheck.ReconcileResult{
		Status: taskStatus,
		Operations: []dnscheck.OperationResult{{
			Status: operationStatus, ErrorClass: dnscheck.ProviderErrorTransient,
			ErrorCode: "provider_rate_limited", RetryAfter: hint,
		}},
	}
}
