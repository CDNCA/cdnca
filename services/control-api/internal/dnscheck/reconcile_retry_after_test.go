package dnscheck

import (
	"context"
	"testing"
	"time"
)

func TestNormalizeProviderRetryAfterBoundsDurableHint(t *testing.T) {
	for _, test := range []struct {
		name  string
		input time.Duration
		want  time.Duration
	}{
		{name: "negative", input: -time.Second, want: 0},
		{name: "zero", input: 0, want: 0},
		{name: "positive", input: 5 * time.Minute, want: 5 * time.Minute},
		{name: "capped", input: 2 * time.Hour, want: time.Hour},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := normalizeProviderRetryAfter(test.input); got != test.want {
				t.Fatalf("normalizeProviderRetryAfter(%s) = %s, want %s", test.input, got, test.want)
			}
		})
	}
}

func TestDurableRetryAfterExhaustionPreservesPropagatingRecovery(t *testing.T) {
	now := time.Date(2026, 8, 6, 10, 0, 0, 0, time.UTC)
	checker, request := newHealthyReconcileFixture(t, now)
	provider := &fakeProviderAdapter{revision: request.Provider.Revision}
	provider.mutate = func(_ *fakeProviderAdapter, _ int, _ ProviderMutation) (ProviderMutationResult, error) {
		return ProviderMutationResult{}, &ProviderError{
			Class: ProviderErrorTransient, Code: "provider_rate_limited", RetryAfter: 2 * time.Hour,
		}
	}
	reconciler := newTestReconciler(t, checker, provider, now, func(config *ReconcilerConfig) {
		config.ProviderAttempts = 1
	})
	prepared, err := reconciler.PrepareApply(ReconcileRequest{
		IdempotencyKey: "retry-after-exhaustion", Check: request,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := reconciler.ResumeApply(context.Background(), prepared, prepared.Result, nil)
	if err != nil {
		t.Fatalf("ResumeApply() error = %v", err)
	}
	if result.Status != TaskPropagating || result.ErrorCode != "provider_rate_limited" ||
		len(result.Operations) != 1 || result.Operations[0].Status != OperationRunning ||
		result.Operations[0].RetryAfter != time.Hour {
		t.Fatalf("result = %#v, want propagating recovery with one-hour hint", result)
	}
}

func TestDurableRetryAfterResumeConsumesBeforeMutationAndClearsOnSuccess(t *testing.T) {
	now := time.Date(2026, 8, 6, 10, 0, 0, 0, time.UTC)
	checker, request := newHealthyReconcileFixture(t, now)
	provider := &fakeProviderAdapter{revision: request.Provider.Revision}
	var mutationCalls int
	slept := false
	provider.mutate = func(_ *fakeProviderAdapter, _ int, mutation ProviderMutation) (ProviderMutationResult, error) {
		mutationCalls++
		if !slept {
			t.Fatalf("provider mutation occurred before durable retry delay was consumed")
		}
		return provider.succeed(mutationCalls, mutation)
	}
	newReconciler := func(sleep func(context.Context, time.Duration) error) *Reconciler {
		return newTestReconciler(t, checker, provider, now, func(config *ReconcilerConfig) {
			config.ProviderAttempts = 1
			config.Sleep = sleep
		})
	}
	first := newReconciler(func(context.Context, time.Duration) error { return nil })
	prepared, err := first.PrepareApply(ReconcileRequest{
		IdempotencyKey: "retry-after-resume", Check: request,
	})
	if err != nil {
		t.Fatal(err)
	}
	provider.mutate = func(_ *fakeProviderAdapter, _ int, _ ProviderMutation) (ProviderMutationResult, error) {
		return ProviderMutationResult{}, &ProviderError{
			Class: ProviderErrorTransient, Code: "provider_rate_limited", RetryAfter: 90 * time.Minute,
		}
	}
	persisted, err := first.ResumeApply(context.Background(), prepared, prepared.Result, nil)
	if err != nil || persisted.Status != TaskPropagating || persisted.Operations[0].RetryAfter != time.Hour {
		t.Fatalf("first ResumeApply() = (%#v, %v), want propagating durable hint", persisted, err)
	}
	provider.mutate = func(_ *fakeProviderAdapter, _ int, mutation ProviderMutation) (ProviderMutationResult, error) {
		mutationCalls++
		if !slept {
			t.Fatalf("provider mutation occurred before durable retry delay was consumed")
		}
		return provider.succeed(mutationCalls, mutation)
	}
	var delays []time.Duration
	resumed := newReconciler(func(_ context.Context, delay time.Duration) error {
		delays = append(delays, delay)
		if delay == time.Hour {
			slept = true
		}
		return nil
	})
	result, err := resumed.ResumeApply(context.Background(), prepared, persisted, nil)
	if err != nil {
		t.Fatalf("resumed ResumeApply() error = %v", err)
	}
	if len(delays) == 0 || delays[0] != time.Hour {
		t.Fatalf("sleep delays = %v, want one-hour durable delay first", delays)
	}
	if result.Status != TaskReadyToCommit || result.Operations[0].Status != OperationSucceeded ||
		result.Operations[0].RetryAfter != 0 {
		t.Fatalf("resumed result = %#v, want successful operation with cleared hint", result)
	}
}
