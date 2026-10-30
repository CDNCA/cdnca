package dnsreconcile

import (
	"context"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
)

func TestRuntimeKeepsPropagatingTaskRunningInsteadOfFinishingIt(t *testing.T) {
	now := time.Date(2026, 8, 5, 16, 0, 0, 0, time.UTC)
	request, checker := runtimeFixture(t, now)
	store := &rejectPropagatingFinishStore{memoryStore: newMemoryStore()}
	provider := &runtimeRecoveryProvider{revision: request.Check.Provider.Revision}
	runtime, err := NewRuntime(testRuntimeConfig(), RuntimeDependencies{
		Store: store, CheckerResolver: &testCheckerResolver{checker: checker},
		ProviderResolver: &testProviderResolver{provider: provider}, Entitlement: testEntitlement{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Apply(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	completed, err := runtime.RunOnce(context.Background(), request.TenantID, "recovery-worker", 1)
	if err != nil || len(completed) != 1 || completed[0].Result.Status != dnscheck.TaskPropagating {
		t.Fatalf("RunOnce() = (%#v, %v), want propagating task with running job", completed, err)
	}
	if provider.calls != 1 {
		t.Fatalf("provider calls = %d, want one recovery-pending call", provider.calls)
	}
	store.mu.Lock()
	checkpointCalls, revision := store.checkpointCalls, store.task.Revision
	store.mu.Unlock()
	if checkpointCalls != 4 || revision != 5 {
		t.Fatalf("checkpoint calls/revision = %d/%d, want 4/5 without duplicate final write", checkpointCalls, revision)
	}
}

type rejectPropagatingFinishStore struct {
	*memoryStore
	checkpointCalls int
}

func (store *rejectPropagatingFinishStore) CheckpointApply(ctx context.Context, lease ApplyLease, result dnscheck.ReconcileResult) (Task, error) {
	store.mu.Lock()
	store.checkpointCalls++
	store.mu.Unlock()
	return store.memoryStore.CheckpointApply(ctx, lease, result)
}

func (store *rejectPropagatingFinishStore) FinishApply(ctx context.Context, lease ApplyLease, result dnscheck.ReconcileResult) (Task, error) {
	if result.Status == dnscheck.TaskPropagating {
		return Task{}, ErrInvalidInput
	}
	return store.memoryStore.FinishApply(ctx, lease, result)
}

type runtimeRecoveryProvider struct {
	revision int64
	calls    int
}

func (provider *runtimeRecoveryProvider) CurrentRevision(context.Context, dnscheck.ProviderRevisionRequest) (int64, error) {
	return provider.revision, nil
}

func (provider *runtimeRecoveryProvider) Mutate(context.Context, dnscheck.ProviderMutation) (dnscheck.ProviderMutationResult, error) {
	provider.calls++
	return dnscheck.ProviderMutationResult{}, &dnscheck.ProviderError{
		Class: dnscheck.ProviderErrorTransient, Code: "provider_recovery_pending",
		ProviderRequestID: "runtime-recovery-request",
	}
}
