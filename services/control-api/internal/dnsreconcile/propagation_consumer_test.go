package dnsreconcile

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnspropagation"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
)

type propagationRuntimeStore struct{ *memoryStore }

func (store *propagationRuntimeStore) checkpointApplyAfter(
	ctx context.Context,
	lease ApplyLease,
	result dnscheck.ReconcileResult,
	_ time.Duration,
) (Task, error) {
	return store.CheckpointApply(ctx, lease, result)
}

func (store *propagationRuntimeStore) Create(
	_ context.Context,
	request ApplyRequest,
	prepared dnscheck.PreparedReconcile,
) (Task, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.task.ID != uuid.Nil {
		return store.task, true, nil
	}
	now := time.Now().UTC()
	store.task = Task{
		ID: uuid.New(), TenantID: request.TenantID, SiteID: request.SiteID,
		ActorUserID: request.ActorUserID, RequestID: request.RequestID, Revision: 1,
		RequiredConsecutive: request.RequiredConsecutive, Prepared: prepared, Result: prepared.Result,
		CreatedAt: now, UpdatedAt: now,
		Job: jobstate.StoredJob{TenantID: request.TenantID, Kind: JobKind, State: jobstate.StateQueued},
	}
	store.task.Job.ID = store.task.ID
	return store.task, false, nil
}

type propagationEngineRecorder struct {
	mu       sync.Mutex
	requests []dnspropagation.Request
	results  []dnspropagation.Result
	errors   []error
}

func (engine *propagationEngineRecorder) Observe(
	_ context.Context,
	request dnspropagation.Request,
) (dnspropagation.Result, error) {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	engine.requests = append(engine.requests, request)
	index := len(engine.requests) - 1
	if index < len(engine.errors) && engine.errors[index] != nil {
		return dnspropagation.Result{}, engine.errors[index]
	}
	if index < len(engine.results) {
		return engine.results[index], nil
	}
	now := time.Now().UTC()
	authority := dnspropagation.Observation{
		OperationID: request.OperationID, Role: dnspropagation.RoleAuthoritative,
		ResolverID: "authority-default", Status: dnspropagation.ResponseAnswer,
		Records: append([]dnspropagation.RRSet(nil), request.Expected...), TTL: time.Minute, ObservedAt: now,
	}
	public := dnspropagation.Observation{
		OperationID: request.OperationID, Role: dnspropagation.RolePublicRecursive,
		ResolverID: "public-default", Status: dnspropagation.ResponseAnswer,
		Records: append([]dnspropagation.RRSet(nil), request.Expected...), TTL: time.Minute, ObservedAt: now,
	}
	return dnspropagation.Result{
		TenantID: request.TenantID, ZoneID: request.ZoneID, OperationID: request.OperationID,
		Reason: dnspropagation.ReasonConverged, Success: true, LKG: dnspropagation.LKGPromote,
		AuthoritativeVotes: 1, PublicVotes: 1, RequiredPublic: 1,
		Observations: []dnspropagation.Observation{authority, public},
	}, nil
}

func (engine *propagationEngineRecorder) snapshot() []dnspropagation.Request {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	return append([]dnspropagation.Request(nil), engine.requests...)
}

type propagationRetryStoreRecorder struct {
	mu      sync.Mutex
	state   dnspropagation.ProviderRetryState
	found   bool
	loads   []dnspropagation.ProviderRetryKey
	writes  []uint64
	loadErr error
}

func (store *propagationRetryStoreRecorder) Load(
	_ context.Context,
	key dnspropagation.ProviderRetryKey,
) (dnspropagation.ProviderRetryStoreResult, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.loads = append(store.loads, key)
	if store.loadErr != nil {
		return dnspropagation.ProviderRetryStoreResult{}, false, store.loadErr
	}
	return dnspropagation.ProviderRetryStoreResult{State: store.state, UpdatedAt: time.Now().UTC()}, store.found, nil
}

func (store *propagationRetryStoreRecorder) CompareAndSwap(
	_ context.Context,
	_ dnspropagation.ProviderRetryKey,
	expected uint64,
	next dnspropagation.ProviderRetryState,
	updatedAt time.Time,
) (dnspropagation.ProviderRetryStoreResult, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if expected != store.state.Revision || next.Revision != expected+1 || updatedAt.IsZero() {
		return dnspropagation.ProviderRetryStoreResult{}, dnspropagation.ErrProviderRetryStateConflict
	}
	store.state, store.found = next, true
	store.writes = append(store.writes, next.Revision)
	return dnspropagation.ProviderRetryStoreResult{State: next, UpdatedAt: updatedAt.UTC()}, nil
}

type propagationContextResolverRecorder struct {
	context PropagationContext
	calls   int
	inputs  [][4]uuid.UUID
	err     error
}

func (resolver *propagationContextResolverRecorder) ResolvePropagationContext(
	_ context.Context,
	tenantID, siteID, zoneID, actorUserID uuid.UUID,
) (PropagationContext, error) {
	resolver.calls++
	resolver.inputs = append(resolver.inputs, [4]uuid.UUID{tenantID, siteID, zoneID, actorUserID})
	return resolver.context, resolver.err
}

// Provider write + provider lookup completes the
// task; the propagation engine is not consulted by apply or commit, so it can
// neither hold the CNAME nor fail it.
func TestRuntimeEnabledPropagationCompletesOnProviderLookupWithoutPropagation(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	request, _ := runtimeFixture(t, now)
	store := &propagationRuntimeStore{memoryStore: newMemoryStore()}
	provider := &testProvider{revision: request.Check.Provider.Revision}
	engine := &propagationEngineRecorder{}
	retryStates := &propagationRetryStoreRecorder{}
	contextResolver := &propagationContextResolverRecorder{context: PropagationContext{
		ScopeID: uuid.New(), ProviderID: uuid.New(), ZoneID: request.Check.Provider.ZoneID,
		Zone: "example.test",
	}}
	config := testRuntimeConfig()
	config.PropagationEnabled = true
	config.RequiredConsecutive = 1
	config.Now = func() time.Time { return now }
	runtime, err := NewRuntime(config, RuntimeDependencies{
		Store: store, ProviderResolver: &testProviderResolver{provider: provider}, Entitlement: testEntitlement{},
		Propagation: PropagationDependencies{
			Engine: engine, RetryStates: retryStates, ContextResolver: contextResolver,
			Policy: dnspropagation.ProviderRetryPolicy{
				BaseDelay: time.Second, MaxDelay: time.Minute, BudgetWindow: time.Hour,
				CircuitOpen: time.Minute, AttemptsPerZone: 10, TransientFailuresToOpen: 3,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	queued, err := runtime.Apply(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	applied, err := runtime.RunOnce(t.Context(), request.TenantID, "propagation-worker", 1)
	if err != nil || len(applied) != 1 || applied[0].Result.Status != dnscheck.TaskReadyToCommit {
		t.Fatalf("RunOnce() = (%#v,%v), want ready after real propagation", applied, err)
	}
	if provider.mutationCount() != 1 || len(engine.snapshot()) != 0 {
		t.Fatalf("provider/engine calls = %d/%d, want 1/0", provider.mutationCount(), len(engine.snapshot()))
	}
	committed, err := runtime.Commit(t.Context(), CommitRequest{
		TenantID: request.TenantID, SiteID: request.SiteID, TaskID: queued.ID,
		ActorUserID: request.ActorUserID, IdempotencyKey: "propagation-commit",
		RequestID: uuid.NewString(), Traceparent: testTraceparent(), ExpectedRevision: applied[0].Revision,
	})
	if err != nil || committed.Result.Status != dnscheck.TaskCommitted {
		t.Fatalf("Commit() = (%#v,%v), want committed", committed, err)
	}
	if len(engine.snapshot()) != 0 || contextResolver.calls != 0 || len(retryStates.loads) != 0 {
		t.Fatalf("propagation consulted: engine=%d context=%d loads=%d", len(engine.snapshot()),
			contextResolver.calls, len(retryStates.loads))
	}
}

func TestRuntimeEnabledPropagationFailsClosedWithoutEveryExplicitDependency(t *testing.T) {
	valid := RuntimeDependencies{
		Store: &memoryStore{}, ProviderResolver: &testProviderResolver{provider: &testProvider{}},
		Entitlement: testEntitlement{}, Propagation: PropagationDependencies{
			Engine: &propagationEngineRecorder{}, RetryStates: &propagationRetryStoreRecorder{},
			ContextResolver: &propagationContextResolverRecorder{}, Policy: dnspropagation.ProviderRetryPolicy{
				BaseDelay: time.Second, MaxDelay: time.Minute, BudgetWindow: time.Hour,
				CircuitOpen: time.Minute, AttemptsPerZone: 2, TransientFailuresToOpen: 2,
			},
		},
	}
	config := testRuntimeConfig()
	config.PropagationEnabled = true
	for name, mutate := range map[string]func(*RuntimeDependencies){
		"engine":           func(value *RuntimeDependencies) { value.Propagation.Engine = nil },
		"retry states":     func(value *RuntimeDependencies) { value.Propagation.RetryStates = nil },
		"context resolver": func(value *RuntimeDependencies) { value.Propagation.ContextResolver = nil },
	} {
		t.Run(name, func(t *testing.T) {
			dependencies := valid
			mutate(&dependencies)
			if runtime, err := NewRuntime(config, dependencies); runtime != nil || !errors.Is(err, ErrUnavailable) {
				t.Fatalf("NewRuntime() = (%#v,%v), want fail closed", runtime, err)
			}
		})
	}
}
