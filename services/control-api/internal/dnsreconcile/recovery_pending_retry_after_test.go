package dnsreconcile

import (
	"context"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnspropagation"
	"github.com/google/uuid"
)

// postgresRulesStore applies two checks PostgresStore makes before writing:
// a delayed checkpoint must be propagating (checkpointApplyAfter) and
// FinishApply takes only a terminal or ready result.
type postgresRulesStore struct {
	propagationRuntimeStore
	yields   int
	finished []dnscheck.ReconcileResult
}

func (store *postgresRulesStore) checkpointApplyAfter(ctx context.Context, lease ApplyLease,
	result dnscheck.ReconcileResult, delay time.Duration) (Task, error) {
	if delay <= 0 || delay > maximumRetryAfterDeferral || result.Status != dnscheck.TaskPropagating {
		return Task{}, ErrInvalidInput
	}
	store.yields++
	result, _ = consumeRetryAfterHints(result)
	return store.CheckpointApply(ctx, lease, result)
}

func (store *postgresRulesStore) FinishApply(ctx context.Context, lease ApplyLease, result dnscheck.ReconcileResult) (Task, error) {
	if result.Status != dnscheck.TaskReadyToCommit && result.Status != dnscheck.TaskCommitted &&
		result.Status != dnscheck.TaskFailed && result.Status != dnscheck.TaskCancelled &&
		result.Status != dnscheck.TaskTimedOut {
		return Task{}, ErrInvalidInput
	}
	store.finished = append(store.finished, result)
	return store.memoryStore.FinishApply(ctx, lease, result)
}

// recoveryPendingProvider answers like ReconcileAdapter when the record it
// just created is not found by the follow-up lookup: the claim is marked
// uncertain and provider_recovery_pending carries RetryAfter 1s.
type recoveryPendingProvider struct{ revision int64 }

func (provider *recoveryPendingProvider) CurrentRevision(context.Context, dnscheck.ProviderRevisionRequest) (int64, error) {
	return provider.revision, nil
}

func (provider *recoveryPendingProvider) Mutate(context.Context, dnscheck.ProviderMutation) (dnscheck.ProviderMutationResult, error) {
	return dnscheck.ProviderMutationResult{}, &dnscheck.ProviderError{
		Class: dnscheck.ProviderErrorTransient, Code: "provider_recovery_pending",
		RetryAfter: time.Second, ProviderRequestID: "dns-reconcile-recovery",
	}
}

// A recovery-pending write used to fail the
// task with dns_reconcile_checkpoint_rejected on its first claim. The
// applying checkpoint carrying RetryAfter went to checkpointApplyAfter, which
// takes only propagating results (ErrInvalidInput), and the propagating
// result was then handed to FinishApply. The task must stay propagating and
// give its lease back for the provider's RetryAfter instead.
func TestRuntimeKeepsRecoveryPendingWriteWithRetryAfterPropagating(t *testing.T) {
	request, _ := runtimeFixture(t, time.Now())
	store := &postgresRulesStore{propagationRuntimeStore: propagationRuntimeStore{memoryStore: newMemoryStore()}}
	config := testRuntimeConfig()
	config.PropagationEnabled = true
	runtime, err := NewRuntime(config, RuntimeDependencies{
		Store: store, ProviderResolver: &testProviderResolver{provider: &recoveryPendingProvider{revision: request.Check.Provider.Revision}},
		Entitlement: testEntitlement{},
		Propagation: PropagationDependencies{
			Engine: &propagationEngineRecorder{}, RetryStates: &propagationRetryStoreRecorder{},
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
	tasks, err := runtime.RunOnce(t.Context(), request.TenantID, "recovery-worker", 1)
	if err != nil || len(tasks) != 1 {
		t.Fatalf("RunOnce() = (%d tasks, %v), want one task", len(tasks), err)
	}
	if len(store.finished) != 0 {
		t.Fatalf("finished = %s/%q, want the recovery-pending task kept running",
			store.finished[0].Status, store.finished[0].ErrorCode)
	}
	if tasks[0].Result.Status != dnscheck.TaskPropagating || store.yields != 1 {
		t.Fatalf("status=%s yields=%d, want propagating with one RetryAfter yield", tasks[0].Result.Status, store.yields)
	}
	operation := tasks[0].Result.Operations[0]
	if operation.ErrorCode != "provider_recovery_pending" || operation.RetryAfter != 0 {
		t.Fatalf("operation = %s/%q retry_after=%s, want recovery pending with RetryAfter consumed",
			operation.Status, operation.ErrorCode, operation.RetryAfter)
	}
}
