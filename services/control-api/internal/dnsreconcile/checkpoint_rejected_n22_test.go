package dnsreconcile

import (
	"context"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnspropagation"
	"github.com/google/uuid"
)

// rejectingRetryStore refuses the first completion checkpoint as invalid,
// like the PostgreSQL store refused propagation retries before the N22 fix.
type rejectingRetryStore struct {
	propagationRuntimeStore
	rejected int
	finished []dnscheck.ReconcileResult
}

func (store *rejectingRetryStore) FinishApply(ctx context.Context, lease ApplyLease, result dnscheck.ReconcileResult) (Task, error) {
	if result.Status != dnscheck.TaskFailed {
		store.rejected++
		return Task{}, ErrInvalidInput
	}
	store.finished = append(store.finished, result)
	return store.memoryStore.FinishApply(ctx, lease, result)
}

// N22 fallback: a checkpoint the store rejects as invalid can never be
// persisted by retrying it. The claim used to keep its lease for 16 minutes
// (worker only logged a WARN); the task now fails with a named code at once,
// so the CNAME allocation shows the reason and "重新生成".
func TestRuntimeFailsTaskWhenStoreRejectsCheckpoint(t *testing.T) {
	request, _ := runtimeFixture(t, time.Now())
	store := &rejectingRetryStore{propagationRuntimeStore: propagationRuntimeStore{memoryStore: newMemoryStore()}}
	engine := &propagationEngineRecorder{}
	config := testRuntimeConfig()
	config.PropagationEnabled = true
	runtime, err := NewRuntime(config, RuntimeDependencies{
		Store: store, ProviderResolver: &testProviderResolver{provider: &testProvider{revision: request.Check.Provider.Revision}},
		Entitlement: testEntitlement{},
		Propagation: PropagationDependencies{
			Engine: engine, RetryStates: &propagationRetryStoreRecorder{},
			ContextResolver: &propagationContextResolverRecorder{context: PropagationContext{
				ScopeID: uuid.New(), ProviderID: uuid.New(), ZoneID: request.Check.Provider.ZoneID, Zone: "example.test",
			}},
			Policy: dnspropagation.ProviderRetryPolicy{
				BaseDelay: time.Second, MaxDelay: time.Minute, BudgetWindow: time.Hour,
				CircuitOpen: time.Minute, AttemptsPerZone: 10, TransientFailuresToOpen: 3,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Apply(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	tasks, err := runtime.RunOnce(t.Context(), request.TenantID, "n22-worker", 1)
	if err != nil {
		t.Fatalf("RunOnce() error = %v, want the rejected task failed instead", err)
	}
	if store.rejected != 1 || len(store.finished) != 1 || len(tasks) != 1 {
		t.Fatalf("rejected=%d finished=%d tasks=%d, want 1/1/1", store.rejected, len(store.finished), len(tasks))
	}
	failed := store.finished[0]
	if failed.Status != dnscheck.TaskFailed || failed.ErrorCode != checkpointRejectedCode ||
		failed.ErrorClass != dnscheck.ProviderErrorPermanent {
		t.Fatalf("finished = %s/%s/%q, want failed/permanent/%s", failed.Status, failed.ErrorClass,
			failed.ErrorCode, checkpointRejectedCode)
	}
}
