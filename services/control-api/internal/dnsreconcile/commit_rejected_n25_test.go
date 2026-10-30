package dnsreconcile

import (
	"context"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/google/uuid"
)

// rejectingCommitStore refuses every commit checkpoint that is not the
// failure, like the PostgreSQL store refused deferred deletes before the N25 fix.
type rejectingCommitStore struct {
	*memoryStore
	rejected int
	failed   []dnscheck.ReconcileResult
}

func (store *rejectingCommitStore) CheckpointCommit(ctx context.Context, lease CommitLease, result dnscheck.ReconcileResult) (Task, error) {
	if result.Status != dnscheck.TaskCommitFailed || result.ErrorCode != checkpointRejectedCode {
		store.rejected++
		return Task{}, ErrInvalidInput
	}
	store.failed = append(store.failed, result)
	return store.memoryStore.CheckpointCommit(ctx, lease, result)
}

// N25 fallback: a commit checkpoint the store rejects can never be persisted
// by retrying. The commit used to keep its 16-minute lease, silently; it now
// ends commit_failed with a named code at once, so callers see the reason.
func TestRuntimeFailsCommitWhenStoreRejectsCheckpoint(t *testing.T) {
	request, checker := runtimeFixture(t, testRuntimeConfig().Now())
	memory := newMemoryStore()
	store := &rejectingCommitStore{memoryStore: memory}
	provider := &testProvider{revision: request.Check.Provider.Revision}
	runtime, err := NewRuntime(testRuntimeConfig(), RuntimeDependencies{
		Store: store, CheckerResolver: &testCheckerResolver{checker: checker},
		ProviderResolver: &testProviderResolver{provider: provider}, Entitlement: testEntitlement{},
	})
	if err != nil {
		t.Fatal(err)
	}
	queued, err := runtime.Apply(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	completed, err := runtime.RunOnce(t.Context(), request.TenantID, "dns-worker-1", 1)
	if err != nil || len(completed) != 1 || completed[0].Result.Status != dnscheck.TaskReadyToCommit {
		t.Fatalf("RunOnce() = (%#v, %v)", completed, err)
	}
	failed, err := runtime.Commit(t.Context(), CommitRequest{
		TenantID: request.TenantID, SiteID: request.SiteID, TaskID: queued.ID,
		ActorUserID: request.ActorUserID, IdempotencyKey: "commit-1", RequestID: uuid.NewString(),
		Traceparent: testTraceparent(), ExpectedRevision: completed[0].Revision,
	})
	if err != nil {
		t.Fatalf("Commit() error = %v, want the rejected commit failed instead", err)
	}
	if store.rejected != 1 || len(store.failed) != 1 || failed.Result.Status != dnscheck.TaskCommitFailed ||
		failed.Result.ErrorCode != checkpointRejectedCode || failed.Result.ErrorClass != dnscheck.ProviderErrorPermanent {
		t.Fatalf("rejected=%d failed=%d result=%s/%s/%q, want 1/1 commit_failed/permanent/%s", store.rejected,
			len(store.failed), failed.Result.Status, failed.Result.ErrorClass, failed.Result.ErrorCode, checkpointRejectedCode)
	}
	for _, mutation := range provider.snapshot() {
		if mutation.Operation.Action == dnscheck.ProviderDelete {
			t.Fatal("provider delete ran without a persisted intent")
		}
	}
}
