package dnscheck

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestDurableResumeRejectsInitialRevisionDrift(t *testing.T) {
	for _, test := range []struct {
		name          string
		commit        bool
		driftPrepared bool
	}{
		{name: "apply current drift"},
		{name: "apply prepared and current drift", driftPrepared: true},
		{name: "commit current drift", commit: true},
		{name: "commit prepared and current drift", commit: true, driftPrepared: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Date(2026, 8, 5, 17, 0, 0, 0, time.UTC)
			checker, request := newHealthyReconcileFixture(t, now)
			driftedRevision := request.Provider.Revision + 1
			provider := &fakeProviderAdapter{revision: driftedRevision}
			reconciler := newTestReconciler(t, checker, provider, now, nil)
			prepared, err := reconciler.PrepareApply(ReconcileRequest{
				IdempotencyKey: "initial-revision-drift", Check: request,
			})
			if err != nil {
				t.Fatal(err)
			}
			current := prepared.Result
			current.InitialRevision = driftedRevision
			if test.driftPrepared {
				prepared.Result.InitialRevision = driftedRevision
			}
			if test.commit {
				if len(current.Operations) != 1 || len(current.DeferredDeletes) != 1 {
					t.Fatalf("prepared operations = %#v; deferred = %#v", current.Operations, current.DeferredDeletes)
				}
				current.Status = TaskReadyToCommit
				current.ProviderRevision = driftedRevision
				current.Operations[0].Status = OperationSucceeded
				current.Operations[0].Attempts = 1
				current.Operations[0].ProviderRequestID = "provider-apply-request"
				current.Operations[0].ProviderRecordID = "provider-created-record"
				current.Operations[0].ProviderRevision = driftedRevision
			}

			checkpointCalls := 0
			checkpoint := func(context.Context, ReconcileResult) error {
				checkpointCalls++
				return nil
			}
			var result ReconcileResult
			if test.commit {
				result, err = reconciler.ResumeCommit(t.Context(), prepared, current, checkpoint)
			} else {
				result, err = reconciler.ResumeApply(t.Context(), prepared, current, checkpoint)
			}
			_, revisionCalls, mutations := provider.snapshot()
			if !errors.Is(err, ErrInvalidInput) || !reflect.DeepEqual(result, ReconcileResult{}) ||
				revisionCalls != 0 || len(mutations) != 0 || checkpointCalls != 0 {
				t.Fatalf("resume = (%#v,%v); revisionCalls=%d mutations=%#v checkpoints=%d",
					result, err, revisionCalls, mutations, checkpointCalls)
			}
		})
	}

	for _, commit := range []bool{false, true} {
		name := "apply valid control"
		if commit {
			name = "commit valid control"
		}
		t.Run(name, func(t *testing.T) {
			now := time.Date(2026, 8, 5, 17, 0, 0, 0, time.UTC)
			checker, request := newHealthyReconcileFixture(t, now)
			providerRevision := request.Provider.Revision
			if commit {
				providerRevision++
			}
			provider := &fakeProviderAdapter{revision: providerRevision}
			reconciler := newTestReconciler(t, checker, provider, now, nil)
			prepared, err := reconciler.PrepareApply(ReconcileRequest{
				IdempotencyKey: "initial-revision-valid-control", Check: request,
			})
			if err != nil {
				t.Fatal(err)
			}
			current := prepared.Result
			if commit {
				current.Status = TaskReadyToCommit
				current.ProviderRevision = providerRevision
				current.Operations[0].Status = OperationSucceeded
				current.Operations[0].Attempts = 1
				current.Operations[0].ProviderRequestID = "provider-apply-request"
				current.Operations[0].ProviderRecordID = "provider-created-record"
				current.Operations[0].ProviderRevision = providerRevision
			}
			checkpointCalls := 0
			checkpoint := func(context.Context, ReconcileResult) error {
				checkpointCalls++
				return nil
			}
			var result ReconcileResult
			if commit {
				result, err = reconciler.ResumeCommit(t.Context(), prepared, current, checkpoint)
				if err != nil || result.Status != TaskCommitted {
					t.Fatalf("valid ResumeCommit() = (%#v,%v)", result, err)
				}
			} else {
				result, err = reconciler.ResumeApply(t.Context(), prepared, current, checkpoint)
				if err != nil || result.Status != TaskReadyToCommit {
					t.Fatalf("valid ResumeApply() = (%#v,%v)", result, err)
				}
			}
			_, _, mutations := provider.snapshot()
			if len(mutations) != 1 || checkpointCalls == 0 {
				t.Fatalf("valid control mutations=%#v checkpoints=%d", mutations, checkpointCalls)
			}
		})
	}
}

func TestDurableApplyResumesAfterCheckpointFailureWithoutDuplicateMutation(t *testing.T) {
	now := time.Date(2026, 7, 28, 10, 0, 0, 0, time.UTC)
	checker, request := newHealthyReconcileFixture(t, now)
	provider := newDurableIdempotentProvider(request.Provider.Revision)
	reconciler := newTestReconciler(t, checker, provider, now, nil)
	prepared, err := reconciler.PrepareApply(ReconcileRequest{
		IdempotencyKey: "durable-apply", Check: request,
	})
	if err != nil {
		t.Fatal(err)
	}

	checkpointFailure := errors.New("checkpoint unavailable")
	persisted := prepared.Result
	_, err = reconciler.ResumeApply(t.Context(), prepared, prepared.Result,
		func(_ context.Context, result ReconcileResult) error {
			if len(result.Operations) > 0 && result.Operations[0].Status == OperationSucceeded {
				return checkpointFailure
			}
			persisted = result
			return nil
		})
	if !errors.Is(err, checkpointFailure) || persisted.Operations[0].Status == OperationSucceeded {
		t.Fatalf("first ResumeApply() = (%#v, %v)", persisted, err)
	}

	restarted := newTestReconciler(t, checker, provider, now, nil)
	result, err := restarted.ResumeApply(t.Context(), prepared, persisted, nil)
	if err != nil || result.Status != TaskReadyToCommit {
		t.Fatalf("restarted ResumeApply() = (%#v, %v)", result, err)
	}
	if calls, effects := provider.counts(); calls != 2 || effects != 1 {
		t.Fatalf("provider calls/effects = %d/%d, want 2/1", calls, effects)
	}
}

func TestDurableCommitResumesAfterCheckpointFailureWithoutDuplicateDelete(t *testing.T) {
	now := time.Date(2026, 7, 28, 10, 0, 0, 0, time.UTC)
	checker, request := newHealthyReconcileFixture(t, now)
	provider := newDurableIdempotentProvider(request.Provider.Revision)
	reconciler := newTestReconciler(t, checker, provider, now, nil)
	prepared, err := reconciler.PrepareApply(ReconcileRequest{
		IdempotencyKey: "durable-commit", Check: request,
	})
	if err != nil {
		t.Fatal(err)
	}
	applied, err := reconciler.ResumeApply(t.Context(), prepared, prepared.Result, nil)
	if err != nil || applied.Status != TaskReadyToCommit {
		t.Fatalf("ResumeApply() = (%#v, %v)", applied, err)
	}

	checkpointFailure := errors.New("commit checkpoint unavailable")
	persisted := applied
	_, err = reconciler.ResumeCommit(t.Context(), prepared, applied,
		func(_ context.Context, result ReconcileResult) error {
			if result.DeferredDeletes[0].Status == OperationSucceeded {
				return checkpointFailure
			}
			persisted = result
			return nil
		})
	if !errors.Is(err, checkpointFailure) || persisted.DeferredDeletes[0].Status == OperationSucceeded {
		t.Fatalf("first ResumeCommit() = (%#v, %v)", persisted, err)
	}

	restarted := newTestReconciler(t, checker, provider, now, nil)
	committed, err := restarted.ResumeCommit(t.Context(), prepared, persisted, nil)
	if err != nil || committed.Status != TaskCommitted {
		t.Fatalf("restarted ResumeCommit() = (%#v, %v)", committed, err)
	}
	if calls, effects := provider.counts(); calls != 3 || effects != 2 {
		t.Fatalf("provider calls/effects = %d/%d, want 3/2", calls, effects)
	}
}

func TestDurableContinuationsPreserveCumulativeProviderAttempts(t *testing.T) {
	now := time.Date(2026, 8, 3, 16, 0, 0, 0, time.UTC)

	t.Run("apply", func(t *testing.T) {
		checker, request := newHealthyReconcileFixture(t, now)
		provider := &fakeProviderAdapter{revision: request.Provider.Revision}
		reconciler := newTestReconciler(t, checker, provider, now, nil)
		prepared, err := reconciler.PrepareApply(ReconcileRequest{
			IdempotencyKey: "durable-apply-attempt-continuation", Check: request,
		})
		if err != nil {
			t.Fatal(err)
		}
		current := prepared.Result
		current.Status = TaskApplying
		current.Operations[0].Status = OperationPlanned
		current.Operations[0].Attempts = 3

		result, err := reconciler.ResumeApply(t.Context(), prepared, current, nil)
		if err != nil || result.Status != TaskReadyToCommit || result.Operations[0].Attempts != 4 {
			t.Fatalf("continued apply = (%#v,%v), want cumulative attempt 4", result, err)
		}
		if current.Operations[0].Attempts != 3 {
			t.Fatalf("continued apply mutated immutable input attempts=%d", current.Operations[0].Attempts)
		}
	})

	t.Run("commit", func(t *testing.T) {
		checker, request := newHealthyReconcileFixture(t, now)
		provider := &fakeProviderAdapter{revision: request.Provider.Revision + 1}
		reconciler := newTestReconciler(t, checker, provider, now, nil)
		prepared, err := reconciler.PrepareApply(ReconcileRequest{
			IdempotencyKey: "durable-commit-attempt-continuation", Check: request,
		})
		if err != nil {
			t.Fatal(err)
		}
		current := prepared.Result
		current.Status = TaskReadyToCommit
		current.ProviderRevision = request.Provider.Revision + 1
		current.Operations[0].Status = OperationSucceeded
		current.Operations[0].Attempts = 1
		current.Operations[0].ProviderRequestID = "provider-apply-request"
		current.Operations[0].ProviderRecordID = "provider-created-record"
		current.Operations[0].ProviderRevision = request.Provider.Revision + 1
		current.DeferredDeletes[0].Status = OperationPlanned
		current.DeferredDeletes[0].Attempts = 3

		result, err := reconciler.ResumeCommit(t.Context(), prepared, current, nil)
		if err != nil || result.Status != TaskCommitted || result.DeferredDeletes[0].Attempts != 4 {
			t.Fatalf("continued commit = (%#v,%v), want cumulative attempt 4", result, err)
		}
		if current.DeferredDeletes[0].Attempts != 3 {
			t.Fatalf("continued commit mutated immutable input attempts=%d", current.DeferredDeletes[0].Attempts)
		}
	})
}

func TestDurableApplyDoesNotRerunPersistedPermanentFailure(t *testing.T) {
	now := time.Date(2026, 7, 28, 10, 0, 0, 0, time.UTC)
	checker, request := newHealthyReconcileFixture(t, now)
	provider := &fakeProviderAdapter{revision: request.Provider.Revision,
		mutate: func(_ *fakeProviderAdapter, _ int, _ ProviderMutation) (ProviderMutationResult, error) {
			return ProviderMutationResult{}, &ProviderError{
				Class: ProviderErrorPermanent, Code: "provider_rejected", ProviderRequestID: "provider-failure-1",
			}
		}}
	reconciler := newTestReconciler(t, checker, provider, now, nil)
	prepared, err := reconciler.PrepareApply(ReconcileRequest{IdempotencyKey: "durable-failure", Check: request})
	if err != nil {
		t.Fatal(err)
	}

	crash := errors.New("crash before terminal checkpoint")
	persisted := prepared.Result
	operationPersisted := false
	_, err = reconciler.ResumeApply(t.Context(), prepared, prepared.Result,
		func(_ context.Context, result ReconcileResult) error {
			if operationPersisted && result.Status == TaskFailed {
				return crash
			}
			persisted = result
			if result.Operations[0].Status == OperationPermanentFailed {
				operationPersisted = true
			}
			return nil
		})
	if !errors.Is(err, crash) || persisted.Operations[0].Status != OperationPermanentFailed ||
		persisted.Status != TaskApplying {
		t.Fatalf("first ResumeApply() = (%#v, %v)", persisted, err)
	}

	restarted := newTestReconciler(t, checker, provider, now, nil)
	result, err := restarted.ResumeApply(t.Context(), prepared, persisted, nil)
	if err != nil || result.Status != TaskFailed || result.ErrorCode != "provider_rejected" {
		t.Fatalf("restarted ResumeApply() = (%#v, %v)", result, err)
	}
	_, _, mutations := provider.snapshot()
	if len(mutations) != 1 {
		t.Fatalf("provider mutations = %d, want 1", len(mutations))
	}
}

func TestDurableApplyResumeDoesNotRegressPropagationPhase(t *testing.T) {
	now := time.Date(2026, 7, 28, 10, 0, 0, 0, time.UTC)
	checker, request := newHealthyReconcileFixture(t, now)
	provider := &fakeProviderAdapter{revision: request.Provider.Revision}
	reconciler := newTestReconciler(t, checker, provider, now, nil)
	prepared, err := reconciler.PrepareApply(ReconcileRequest{IdempotencyKey: "durable-propagation", Check: request})
	if err != nil {
		t.Fatal(err)
	}
	checkpointFailure := errors.New("stop in propagation")
	var persisted ReconcileResult
	_, err = reconciler.ResumeApply(t.Context(), prepared, prepared.Result,
		func(_ context.Context, result ReconcileResult) error {
			persisted = result
			if result.Status == TaskPropagating {
				return checkpointFailure
			}
			return nil
		})
	if !errors.Is(err, checkpointFailure) || persisted.Status != TaskPropagating {
		t.Fatalf("first ResumeApply() = (%#v, %v)", persisted, err)
	}

	statuses := make([]TaskStatus, 0)
	result, err := reconciler.ResumeApply(t.Context(), prepared, persisted,
		func(_ context.Context, result ReconcileResult) error {
			statuses = append(statuses, result.Status)
			return nil
		})
	if err != nil || result.Status != TaskReadyToCommit {
		t.Fatalf("resumed ResumeApply() = (%#v, %v)", result, err)
	}
	for _, status := range statuses {
		if status == TaskApplying {
			t.Fatalf("propagation resume regressed through statuses %#v", statuses)
		}
	}
}

type durableIdempotentProvider struct {
	mu       sync.Mutex
	revision int64
	calls    int
	effects  int
	results  map[string]ProviderMutationResult
}

func newDurableIdempotentProvider(revision int64) *durableIdempotentProvider {
	return &durableIdempotentProvider{revision: revision, results: make(map[string]ProviderMutationResult)}
}

func (provider *durableIdempotentProvider) CurrentRevision(context.Context, ProviderRevisionRequest) (int64, error) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return provider.revision, nil
}

func (provider *durableIdempotentProvider) Mutate(_ context.Context, mutation ProviderMutation) (ProviderMutationResult, error) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	provider.calls++
	if result, found := provider.results[mutation.ClientRequestID]; found {
		return result, nil
	}
	if mutation.ExpectedRevision != provider.revision {
		return ProviderMutationResult{}, ErrProviderRevisionConflict
	}
	provider.effects++
	provider.revision++
	recordID := mutation.Operation.RecordID
	if mutation.Operation.Action == ProviderCreate {
		recordID = fmt.Sprintf("durable-created-%d", provider.effects)
	}
	result := ProviderMutationResult{
		ProviderRequestID: fmt.Sprintf("durable-provider-%d", provider.effects),
		RecordID:          recordID,
		Revision:          provider.revision,
	}
	provider.results[mutation.ClientRequestID] = result
	return result, nil
}

func (provider *durableIdempotentProvider) counts() (int, int) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return provider.calls, provider.effects
}
