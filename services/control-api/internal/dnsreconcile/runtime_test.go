package dnsreconcile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
)

type jitClaimStore struct {
	*memoryStore
	mu                sync.Mutex
	leases            []ApplyLease
	claimed           []bool
	claimRequests     []ClaimRequest
	events            []string
	heartbeatCalls    int
	finishCalls       int
	finishErrors      map[uuid.UUID]error
	cancelOnHeartbeat map[uuid.UUID]context.CancelFunc
	violateLimit      bool
}

func newJITClaimStore(tasks ...Task) *jitClaimStore {
	leases := make([]ApplyLease, len(tasks))
	for index, task := range tasks {
		leases[index] = ApplyLease{Task: task, LeaseID: uuid.New(), Attempt: 1}
	}
	return &jitClaimStore{
		memoryStore:       newMemoryStore(),
		leases:            leases,
		claimed:           make([]bool, len(tasks)),
		finishErrors:      make(map[uuid.UUID]error),
		cancelOnHeartbeat: make(map[uuid.UUID]context.CancelFunc),
	}
}

func (store *jitClaimStore) Claim(_ context.Context, request ClaimRequest) ([]ApplyLease, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.claimRequests = append(store.claimRequests, request)
	limit := request.Limit
	if store.violateLimit {
		limit = 2
	}
	claims := make([]ApplyLease, 0, limit)
	labels := ""
	for index := range store.leases {
		if store.claimed[index] || len(claims) == limit {
			continue
		}
		store.claimed[index] = true
		lease := store.leases[index]
		lease.WorkerID = request.WorkerID
		lease.LeaseExpiresAt = time.Now().Add(request.LeaseDuration)
		claims = append(claims, lease)
		if labels != "" {
			labels += ","
		}
		labels += lease.Task.RequestID
	}
	if len(claims) > 0 {
		store.events = append(store.events, fmt.Sprintf("claim(%d):%s", request.Limit, labels))
	}
	return claims, nil
}

func (store *jitClaimStore) HeartbeatApply(_ context.Context, lease ApplyLease, duration time.Duration) (ApplyLease, error) {
	store.mu.Lock()
	store.heartbeatCalls++
	store.events = append(store.events, "process:"+lease.Task.RequestID)
	cancel := store.cancelOnHeartbeat[lease.Task.ID]
	delete(store.cancelOnHeartbeat, lease.Task.ID)
	store.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	lease.LeaseExpiresAt = time.Now().Add(duration)
	return lease, nil
}

func (store *jitClaimStore) CheckpointApply(_ context.Context, lease ApplyLease, result dnscheck.ReconcileResult) (Task, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	lease.Task.Result = result
	for index := range store.leases {
		if store.leases[index].Task.ID == lease.Task.ID {
			store.leases[index].Task = lease.Task
			break
		}
	}
	return lease.Task, nil
}

func (store *jitClaimStore) FinishApply(_ context.Context, lease ApplyLease, result dnscheck.ReconcileResult) (Task, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.finishCalls++
	if err := store.finishErrors[lease.Task.ID]; err != nil {
		store.events = append(store.events, "finish-error:"+lease.Task.RequestID)
		return Task{}, err
	}
	store.events = append(store.events, "finish:"+lease.Task.RequestID)
	lease.Task.Result = result
	for index := range store.leases {
		if store.leases[index].Task.ID == lease.Task.ID {
			store.leases[index].Task = lease.Task
			break
		}
	}
	return lease.Task, nil
}

func (store *jitClaimStore) snapshot() ([]ClaimRequest, []string, []bool, int, int) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return append([]ClaimRequest(nil), store.claimRequests...), append([]string(nil), store.events...),
		append([]bool(nil), store.claimed...), store.heartbeatCalls, store.finishCalls
}

func TestRuntimeRunOnceClaimsJustInTime(t *testing.T) {
	terminalTask := func(tenantID uuid.UUID, label string) Task {
		return Task{
			ID: uuid.New(), TenantID: tenantID, SiteID: uuid.New(), ActorUserID: uuid.New(),
			RequestID: label, RequiredConsecutive: 2,
			Result: dnscheck.ReconcileResult{Status: dnscheck.TaskReadyToCommit},
		}
	}
	newRuntime := func(t *testing.T, store Store, checker *dnscheck.Checker, provider dnscheck.ProviderAdapter) *Runtime {
		t.Helper()
		if provider == nil {
			provider = &testProvider{revision: 7}
		}
		runtime, err := NewRuntime(testRuntimeConfig(), RuntimeDependencies{
			Store: store, CheckerResolver: &testCheckerResolver{checker: checker},
			ProviderResolver: &testProviderResolver{provider: provider}, Entitlement: testEntitlement{},
		})
		if err != nil {
			t.Fatal(err)
		}
		return runtime
	}

	t.Run("task error does not preclaim next", func(t *testing.T) {
		tenantID := uuid.New()
		taskA, taskB := terminalTask(tenantID, "A"), terminalTask(tenantID, "B")
		sentinel := errors.New("finish A unavailable")
		store := newJITClaimStore(taskA, taskB)
		store.finishErrors[taskA.ID] = sentinel
		runtime := newRuntime(t, store, nil, nil)

		completed, err := runtime.RunOnce(t.Context(), tenantID, "jit-error", 2)
		requests, _, claimed, _, _ := store.snapshot()
		if !errors.Is(err, sentinel) || len(completed) != 0 || len(requests) != 1 ||
			requests[0].Limit != 1 || !claimed[0] || claimed[1] {
			t.Fatalf("first RunOnce()=(%#v,%v); requests=%#v claimed=%v", completed, err, requests, claimed)
		}

		delete(store.finishErrors, taskA.ID)
		completed, err = runtime.RunOnce(t.Context(), tenantID, "jit-error", 2)
		requests, _, _, _, _ = store.snapshot()
		if err != nil || len(completed) != 1 || completed[0].ID != taskB.ID {
			t.Fatalf("second RunOnce()=(%#v,%v); requests=%#v", completed, err, requests)
		}
		for _, request := range requests {
			if request.Limit != 1 {
				t.Fatalf("Claim limit=%d, want 1", request.Limit)
			}
		}
	})

	t.Run("terminal tasks claim and finish in order", func(t *testing.T) {
		tenantID := uuid.New()
		taskA, taskB := terminalTask(tenantID, "A"), terminalTask(tenantID, "B")
		store := newJITClaimStore(taskA, taskB)
		runtime := newRuntime(t, store, nil, nil)
		completed, err := runtime.RunOnce(t.Context(), tenantID, "jit-terminal", 2)
		requests, events, _, _, _ := store.snapshot()
		wantEvents := []string{"claim(1):A", "process:A", "finish:A", "claim(1):B", "process:B", "finish:B"}
		if err != nil || len(completed) != 2 || completed[0].ID != taskA.ID || completed[1].ID != taskB.ID ||
			len(requests) != 2 || requests[0].Limit != 1 || requests[1].Limit != 1 ||
			!reflect.DeepEqual(events, wantEvents) {
			t.Fatalf("RunOnce()=(%#v,%v); requests=%#v events=%v", completed, err, requests, events)
		}
	})

	t.Run("propagating task retains lease and stops", func(t *testing.T) {
		now := time.Date(2026, 8, 5, 18, 0, 0, 0, time.UTC)
		request, checker := runtimeFixture(t, now)
		prepared, err := dnscheck.PrepareReconcile(dnscheck.ReconcileRequest{
			IdempotencyKey: "jit-propagating", Check: request.Check,
		}, func() time.Time { return now })
		if err != nil {
			t.Fatal(err)
		}
		taskA := Task{
			ID: uuid.New(), TenantID: request.TenantID, SiteID: request.SiteID,
			ActorUserID: request.ActorUserID, RequestID: "A", RequiredConsecutive: 2,
			Prepared: prepared, Result: prepared.Result,
		}
		taskB := terminalTask(request.TenantID, "B")
		store := newJITClaimStore(taskA, taskB)
		provider := &runtimeRecoveryProvider{revision: request.Check.Provider.Revision}
		runtime := newRuntime(t, store, checker, provider)

		completed, err := runtime.RunOnce(t.Context(), request.TenantID, "jit-propagating", 2)
		requests, _, claimed, _, _ := store.snapshot()
		if err != nil || len(completed) != 1 || completed[0].ID != taskA.ID ||
			completed[0].Result.Status != dnscheck.TaskPropagating || len(requests) != 1 || claimed[1] {
			t.Fatalf("first RunOnce()=(%#v,%v); requests=%#v claimed=%v", completed, err, requests, claimed)
		}
		completed, err = runtime.RunOnce(t.Context(), request.TenantID, "jit-propagating", 2)
		if err != nil || len(completed) != 1 || completed[0].ID != taskB.ID {
			t.Fatalf("second RunOnce()=(%#v,%v)", completed, err)
		}
	})

	t.Run("empty claim returns", func(t *testing.T) {
		tenantID := uuid.New()
		store := newJITClaimStore()
		runtime := newRuntime(t, store, nil, nil)
		completed, err := runtime.RunOnce(t.Context(), tenantID, "jit-empty", 3)
		requests, _, _, heartbeatCalls, finishCalls := store.snapshot()
		if err != nil || len(completed) != 0 || len(requests) != 1 || requests[0].Limit != 1 ||
			heartbeatCalls != 0 || finishCalls != 0 {
			t.Fatalf("RunOnce()=(%#v,%v); requests=%#v executions=%d/%d",
				completed, err, requests, heartbeatCalls, finishCalls)
		}
	})

	t.Run("parent cancellation stops claims", func(t *testing.T) {
		tenantID := uuid.New()
		t.Run("during task", func(t *testing.T) {
			taskA, taskB := terminalTask(tenantID, "A"), terminalTask(tenantID, "B")
			store := newJITClaimStore(taskA, taskB)
			ctx, cancel := context.WithCancel(t.Context())
			store.cancelOnHeartbeat[taskA.ID] = cancel
			runtime := newRuntime(t, store, nil, nil)
			completed, err := runtime.RunOnce(ctx, tenantID, "jit-cancel", 2)
			requests, _, claimed, _, _ := store.snapshot()
			if !errors.Is(err, context.Canceled) || len(completed) != 1 || completed[0].ID != taskA.ID ||
				len(requests) != 1 || requests[0].Limit != 1 || claimed[1] {
				t.Fatalf("RunOnce()=(%#v,%v); requests=%#v claimed=%v", completed, err, requests, claimed)
			}
		})

		t.Run("before first claim", func(t *testing.T) {
			store := newJITClaimStore(terminalTask(tenantID, "A"))
			runtime := newRuntime(t, store, nil, nil)
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			completed, err := runtime.RunOnce(ctx, tenantID, "jit-cancelled", 2)
			requests, _, _, heartbeatCalls, finishCalls := store.snapshot()
			if !errors.Is(err, context.Canceled) || len(completed) != 0 || len(requests) != 0 ||
				heartbeatCalls != 0 || finishCalls != 0 {
				t.Fatalf("RunOnce()=(%#v,%v); requests=%#v executions=%d/%d",
					completed, err, requests, heartbeatCalls, finishCalls)
			}
		})
	})

	t.Run("multi claim response fails closed", func(t *testing.T) {
		tenantID := uuid.New()
		store := newJITClaimStore(terminalTask(tenantID, "A"), terminalTask(tenantID, "B"))
		store.violateLimit = true
		runtime := newRuntime(t, store, nil, nil)
		completed, err := runtime.RunOnce(t.Context(), tenantID, "jit-violation", 2)
		requests, _, _, heartbeatCalls, finishCalls := store.snapshot()
		if !errors.Is(err, ErrUnavailable) || len(completed) != 0 || len(requests) != 1 ||
			requests[0].Limit != 1 || heartbeatCalls != 0 || finishCalls != 0 {
			t.Fatalf("RunOnce()=(%#v,%v); requests=%#v executions=%d/%d",
				completed, err, requests, heartbeatCalls, finishCalls)
		}
	})
}

func TestRuntimeFailsClosedWithoutEveryProductionDependency(t *testing.T) {
	config := testRuntimeConfig()
	valid := RuntimeDependencies{
		Store: &memoryStore{}, CheckerResolver: &testCheckerResolver{},
		ProviderResolver: &testProviderResolver{}, Entitlement: testEntitlement{},
	}
	tests := map[string]func(RuntimeDependencies) RuntimeDependencies{
		"store":       func(value RuntimeDependencies) RuntimeDependencies { value.Store = nil; return value },
		"checker":     func(value RuntimeDependencies) RuntimeDependencies { value.CheckerResolver = nil; return value },
		"provider":    func(value RuntimeDependencies) RuntimeDependencies { value.ProviderResolver = nil; return value },
		"entitlement": func(value RuntimeDependencies) RuntimeDependencies { value.Entitlement = nil; return value },
	}
	for name, remove := range tests {
		t.Run(name, func(t *testing.T) {
			if runtime, err := NewRuntime(config, remove(valid)); runtime != nil || !errors.Is(err, ErrUnavailable) {
				t.Fatalf("NewRuntime() = (%T, %v)", runtime, err)
			}
		})
	}
}

func TestRuntimeFailsClosedWithInvalidEngineConfig(t *testing.T) {
	dependencies := RuntimeDependencies{
		Store: &memoryStore{}, CheckerResolver: &testCheckerResolver{},
		ProviderResolver: &testProviderResolver{}, Entitlement: testEntitlement{},
	}
	config := testRuntimeConfig()
	config.ProviderAttempts = 0
	if runtime, err := NewRuntime(config, dependencies); runtime != nil || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("NewRuntime() = (%T, %v)", runtime, err)
	}
}

func TestRuntimeFailsClosedWhenLeaseDoesNotCoverExecutionWindow(t *testing.T) {
	dependencies := RuntimeDependencies{
		Store: &memoryStore{}, CheckerResolver: &testCheckerResolver{},
		ProviderResolver: &testProviderResolver{}, Entitlement: testEntitlement{},
	}
	for _, field := range []string{"apply", "commit"} {
		t.Run(field, func(t *testing.T) {
			config := testRuntimeConfig()
			if field == "apply" {
				config.ApplyLeaseDuration = config.OverallTimeout
			} else {
				config.CommitLeaseDuration = config.OverallTimeout
			}
			if runtime, err := NewRuntime(config, dependencies); runtime != nil || !errors.Is(err, ErrUnavailable) {
				t.Fatalf("NewRuntime() = (%T, %v)", runtime, err)
			}
		})
	}
}

func TestRuntimePersistsApplyBeforeWorkerAndDefersDeleteUntilCommit(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	request, checker := runtimeFixture(t, now)
	store := newMemoryStore()
	provider := &testProvider{revision: request.Check.Provider.Revision}
	var mutationWithoutIntent bool
	var deleteWithoutFreshHeartbeat bool
	provider.beforeMutate = func(mutation dnscheck.ProviderMutation) {
		store.mu.Lock()
		defer store.mu.Unlock()
		if mutation.Operation.Action == dnscheck.ProviderCreate &&
			store.task.Result.Operations[0].Status != dnscheck.OperationRunning {
			mutationWithoutIntent = true
		}
		if mutation.Operation.Action == dnscheck.ProviderDelete {
			if store.task.Result.DeferredDeletes[0].Status != dnscheck.OperationRunning {
				mutationWithoutIntent = true
			}
			if store.heartbeatCommitCalls == 0 {
				deleteWithoutFreshHeartbeat = true
			}
		}
	}
	providerResolver := &testProviderResolver{provider: provider}
	checkerResolver := &testCheckerResolver{checker: checker}
	runtime, err := NewRuntime(testRuntimeConfig(), RuntimeDependencies{
		Store: store, CheckerResolver: checkerResolver,
		ProviderResolver: providerResolver, Entitlement: testEntitlement{},
	})
	if err != nil {
		t.Fatal(err)
	}

	dryRun, err := runtime.DryRun(t.Context(), DryRunRequest{
		TenantID: request.TenantID, SiteID: request.SiteID, ActorUserID: request.ActorUserID,
		RequestID: uuid.NewString(), Check: request.Check,
	})
	if err != nil || dryRun.Status != dnscheck.TaskDryRun || providerResolver.calls != 0 || checkerResolver.calls != 0 {
		t.Fatalf("DryRun() = (%#v, %v), resolver calls=%d/%d", dryRun, err, providerResolver.calls, checkerResolver.calls)
	}
	for _, operation := range dryRun.Operations {
		if operation.ClientRequestID != "" {
			t.Fatalf("dry-run exposed provider request id %q", operation.ClientRequestID)
		}
	}

	queued, err := runtime.Apply(t.Context(), request)
	if err != nil || queued.ID == uuid.Nil || queued.Result.Status != dnscheck.TaskDryRun {
		t.Fatalf("Apply() = (%#v, %v)", queued, err)
	}
	if provider.mutationCount() != 0 {
		t.Fatal("Apply performed provider mutation before worker claim")
	}

	completed, err := runtime.RunOnce(t.Context(), request.TenantID, "dns-worker-1", 1)
	if err != nil || len(completed) != 1 || completed[0].Result.Status != dnscheck.TaskReadyToCommit {
		t.Fatalf("RunOnce() = (%#v, %v)", completed, err)
	}
	mutations := provider.snapshot()
	if len(mutations) != 1 || mutations[0].Operation.Action != dnscheck.ProviderCreate {
		t.Fatalf("apply mutations = %#v", mutations)
	}

	commit := CommitRequest{
		TenantID: request.TenantID, SiteID: request.SiteID, TaskID: queued.ID,
		ActorUserID: request.ActorUserID, IdempotencyKey: "commit-1", RequestID: uuid.NewString(),
		Traceparent: testTraceparent(), ExpectedRevision: completed[0].Revision,
	}
	committed, err := runtime.Commit(t.Context(), commit)
	if err != nil || committed.Result.Status != dnscheck.TaskCommitted {
		t.Fatalf("Commit() = (%#v, %v)", committed, err)
	}
	mutations = provider.snapshot()
	if len(mutations) != 2 || mutations[1].Operation.Action != dnscheck.ProviderDelete ||
		mutations[0].ClientRequestID == "" || mutations[1].ClientRequestID == "" {
		t.Fatalf("commit mutations = %#v", mutations)
	}
	if mutationWithoutIntent || deleteWithoutFreshHeartbeat {
		t.Fatalf("provider mutation lacked durable intent=%t or fresh commit heartbeat=%t",
			mutationWithoutIntent, deleteWithoutFreshHeartbeat)
	}
	expectedDeleteID := dnsOperationRequestID(
		request.TenantID, request.IdempotencyKey, completed[0].Result.PayloadDigest,
		"commit", completed[0].Result.DeferredDeletes[0].SourceSequence,
	)
	if mutations[1].ClientRequestID != expectedDeleteID || store.commitWorker != commitWorkerID(commit) ||
		store.commitWorker == commit.RequestID {
		t.Fatalf("commit identity mutation=%q worker=%q", mutations[1].ClientRequestID, store.commitWorker)
	}
}

func TestRuntimeResumesWithPersistedRequiredConsecutive(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	request, checker := runtimeFixture(t, now)
	store := newMemoryStore()
	provider := &testProvider{revision: request.Check.Provider.Revision}
	dependencies := RuntimeDependencies{
		Store: store, CheckerResolver: &testCheckerResolver{checker: checker},
		ProviderResolver: &testProviderResolver{provider: provider}, Entitlement: testEntitlement{},
	}
	creator, err := NewRuntime(testRuntimeConfig(), dependencies)
	if err != nil {
		t.Fatal(err)
	}
	created, err := creator.Apply(t.Context(), request)
	if err != nil || created.RequiredConsecutive != 2 {
		t.Fatalf("Apply() = (%#v, %v)", created, err)
	}

	restartedConfig := testRuntimeConfig()
	restartedConfig.RequiredConsecutive = 3
	restarted, err := NewRuntime(restartedConfig, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := restarted.Apply(t.Context(), request)
	if err != nil || !replayed.Replayed || replayed.RequiredConsecutive != 2 {
		t.Fatalf("replayed Apply() = (%#v, %v)", replayed, err)
	}
	completed, err := restarted.RunOnce(t.Context(), request.TenantID, "dns-worker-restarted", 1)
	if err != nil || len(completed) != 1 || completed[0].RequiredConsecutive != 2 ||
		len(completed[0].Result.Propagation) != 2 {
		t.Fatalf("RunOnce() = (%#v, %v)", completed, err)
	}
}

func TestRuntimeFencesRecoveredApplyBeforeProviderMutation(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	request, checker := runtimeFixture(t, now)
	store := newMemoryStore()
	provider := &testProvider{revision: request.Check.Provider.Revision}
	runtime, err := NewRuntime(testRuntimeConfig(), RuntimeDependencies{
		Store: store, CheckerResolver: &testCheckerResolver{checker: checker},
		ProviderResolver: &testProviderResolver{provider: provider}, Entitlement: testEntitlement{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Apply(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.task.Result.Status = dnscheck.TaskApplying
	store.heartbeatApplyError = ErrClaimLost
	store.mu.Unlock()

	if _, err := runtime.RunOnce(t.Context(), request.TenantID, "expired-batch-worker", 2); !errors.Is(err, ErrClaimLost) {
		t.Fatalf("RunOnce() error=%v", err)
	}
	if provider.mutationCount() != 0 || store.heartbeatApplyCalls != 1 {
		t.Fatalf("provider mutations=%d heartbeat calls=%d", provider.mutationCount(), store.heartbeatApplyCalls)
	}
}

type memoryStore struct {
	mu                   sync.Mutex
	task                 Task
	claimed              bool
	commitWorker         string
	heartbeatApplyCalls  int
	heartbeatApplyError  error
	heartbeatCommitCalls int
}

func newMemoryStore() *memoryStore { return &memoryStore{} }

func (store *memoryStore) Create(_ context.Context, request ApplyRequest, prepared dnscheck.PreparedReconcile) (Task, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.task.ID != uuid.Nil {
		if store.task.Prepared.Result.PayloadDigest != prepared.Result.PayloadDigest {
			return Task{}, false, ErrIdempotencyConflict
		}
		return store.task, true, nil
	}
	if request.RequiredConsecutive != 2 {
		return Task{}, false, ErrInvalidInput
	}
	now := time.Now().UTC()
	store.task = Task{
		ID: uuid.New(), TenantID: request.TenantID, SiteID: request.SiteID, Revision: 1,
		ActorUserID: request.ActorUserID, RequestID: request.RequestID,
		RequiredConsecutive: request.RequiredConsecutive, Prepared: prepared,
		Result: prepared.Result, CreatedAt: now, UpdatedAt: now,
		Job: jobstate.StoredJob{TenantID: request.TenantID, Kind: JobKind, State: jobstate.StateQueued},
	}
	store.task.Job.ID = store.task.ID
	return store.task, false, nil
}

func (store *memoryStore) Get(_ context.Context, tenantID, taskID uuid.UUID) (Task, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.task.TenantID != tenantID || store.task.ID != taskID {
		return Task{}, ErrNotFound
	}
	return store.task, nil
}

func (store *memoryStore) Claim(_ context.Context, request ClaimRequest) ([]ApplyLease, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.claimed || store.task.ID == uuid.Nil {
		return nil, nil
	}
	store.claimed = true
	return []ApplyLease{{
		Task: store.task, WorkerID: request.WorkerID, Attempt: 1,
		LeaseID: uuid.New(), LeaseExpiresAt: time.Now().Add(request.LeaseDuration),
	}}, nil
}

func (store *memoryStore) HeartbeatApply(_ context.Context, lease ApplyLease, duration time.Duration) (ApplyLease, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.heartbeatApplyCalls++
	if store.heartbeatApplyError != nil {
		return ApplyLease{}, store.heartbeatApplyError
	}
	lease.LeaseExpiresAt = time.Now().Add(duration)
	return lease, nil
}

func (store *memoryStore) CheckpointApply(_ context.Context, _ ApplyLease, result dnscheck.ReconcileResult) (Task, error) {
	return store.checkpoint(result), nil
}

func (store *memoryStore) FinishApply(_ context.Context, _ ApplyLease, result dnscheck.ReconcileResult) (Task, error) {
	store.mu.Lock()
	store.claimed = true
	store.mu.Unlock()
	return store.checkpoint(result), nil
}

func (store *memoryStore) AcquireCommit(_ context.Context, request CommitRequest, workerID string, duration time.Duration) (CommitLease, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if request.ExpectedRevision != store.task.Revision || request.TaskID != store.task.ID {
		return CommitLease{}, false, ErrRevisionConflict
	}
	store.commitWorker = workerID
	return CommitLease{
		Task: store.task, WorkerID: workerID, Attempt: 1, LeaseID: uuid.New(),
		LeaseExpiresAt: time.Now().Add(duration), Command: request,
	}, false, nil
}

func (store *memoryStore) HeartbeatCommit(_ context.Context, lease CommitLease, duration time.Duration) (CommitLease, error) {
	store.mu.Lock()
	store.heartbeatCommitCalls++
	store.mu.Unlock()
	lease.LeaseExpiresAt = time.Now().Add(duration)
	return lease, nil
}

func (store *memoryStore) CheckpointCommit(_ context.Context, _ CommitLease, result dnscheck.ReconcileResult) (Task, error) {
	return store.checkpoint(result), nil
}

func (store *memoryStore) Cancel(_ context.Context, request CancelRequest) (Task, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if request.TaskID != store.task.ID {
		return Task{}, false, ErrNotFound
	}
	store.task.Result.Status = dnscheck.TaskCancelled
	store.task.Revision++
	return store.task, false, nil
}

func (store *memoryStore) RecordProviderReport(_ context.Context, request ProviderReportRequest) (ReportResult, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if request.TaskID != store.task.ID {
		return ReportResult{}, ErrNotFound
	}
	return ReportResult{Task: store.task}, nil
}

func (store *memoryStore) checkpoint(result dnscheck.ReconcileResult) Task {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.task.Result = result
	store.task.Revision++
	store.task.UpdatedAt = time.Now().UTC()
	return store.task
}

type testEntitlement struct{}

func (testEntitlement) AuthorizeDNSReconcile(context.Context, EntitlementRequest) error {
	return nil
}

type testCheckerResolver struct {
	checker *dnscheck.Checker
	calls   int
}

func (resolver *testCheckerResolver) ResolveChecker(context.Context, uuid.UUID, uuid.UUID) (*dnscheck.Checker, error) {
	resolver.calls++
	return resolver.checker, nil
}

type testProviderResolver struct {
	provider dnscheck.ProviderAdapter
	calls    int
}

func (resolver *testProviderResolver) ResolveProvider(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (dnscheck.ProviderAdapter, error) {
	resolver.calls++
	return resolver.provider, nil
}

type testResolver struct{ value string }

func (resolver testResolver) Resolve(ctx context.Context, _ dnscheck.ResolverEndpoint, query dnscheck.DNSQuery) (dnscheck.DNSResponse, error) {
	if err := ctx.Err(); err != nil {
		return dnscheck.DNSResponse{}, err
	}
	return dnscheck.DNSResponse{Authoritative: true, Answers: []dnscheck.DNSRecord{{
		Name: query.Name, Type: query.Type, TTL: 60, Value: resolver.value,
	}}}, nil
}

type testProvider struct {
	mu           sync.Mutex
	revision     int64
	mutations    []dnscheck.ProviderMutation
	beforeMutate func(dnscheck.ProviderMutation)
}

func (provider *testProvider) CurrentRevision(context.Context, dnscheck.ProviderRevisionRequest) (int64, error) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return provider.revision, nil
}

func (provider *testProvider) Mutate(_ context.Context, mutation dnscheck.ProviderMutation) (dnscheck.ProviderMutationResult, error) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if provider.beforeMutate != nil {
		provider.beforeMutate(mutation)
	}
	if mutation.ExpectedRevision != provider.revision {
		return dnscheck.ProviderMutationResult{}, dnscheck.ErrProviderRevisionConflict
	}
	provider.mutations = append(provider.mutations, mutation)
	provider.revision++
	recordID := mutation.Operation.RecordID
	if mutation.Operation.Action == dnscheck.ProviderCreate {
		recordID = fmt.Sprintf("created-%d", len(provider.mutations))
	}
	return dnscheck.ProviderMutationResult{
		ProviderRequestID: fmt.Sprintf("provider-%d", len(provider.mutations)),
		RecordID:          recordID, Revision: provider.revision,
	}, nil
}

func (provider *testProvider) mutationCount() int {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return len(provider.mutations)
}

func (provider *testProvider) snapshot() []dnscheck.ProviderMutation {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return append([]dnscheck.ProviderMutation(nil), provider.mutations...)
}

func runtimeFixture(t *testing.T, _ time.Time) (ApplyRequest, *dnscheck.Checker) {
	t.Helper()
	tenantID := uuid.New()
	siteID := uuid.New()
	zoneID := uuid.New()
	authority, err := dnscheck.NewResolverEndpoint("udp", netip.MustParseAddr("192.0.2.10").String(), 53)
	if err != nil {
		t.Fatal(err)
	}
	public, err := dnscheck.NewResolverEndpoint("udp", netip.MustParseAddr("198.51.100.10").String(), 53)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := dnscheck.NewEndpointPolicy(authority, public)
	if err != nil {
		t.Fatal(err)
	}
	checker, err := dnscheck.NewChecker(dnscheck.Config{
		Resolver: testResolver{value: "192.0.2.10"}, EndpointPolicy: policy,
		AuthoritativeResolvers: []dnscheck.NamedResolver{{Name: "authority", Endpoint: authority}},
		PublicResolvers:        []dnscheck.NamedResolver{{Name: "public", Endpoint: public}},
		QueryTimeout:           time.Second, Attempts: 1, MaxCNAMEDepth: 4, Now: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	check := dnscheck.CheckRequest{
		TenantID: tenantID, SiteID: siteID, Name: "www.example.test",
		Expected: []dnscheck.ExpectedRecord{{Type: dnscheck.RecordA, Values: []string{"192.0.2.10"}}},
		TTL:      60, PropagationWindow: 5 * time.Minute,
		Provider: dnscheck.ProviderSnapshot{
			TenantID: tenantID, SiteID: siteID, ZoneID: zoneID, Revision: 7,
			Records: []dnscheck.ProviderRecord{{
				RecordID: "old-record", Name: "www.example.test", Type: dnscheck.RecordA,
				Value: "192.0.2.20", TTL: 60,
			}},
		},
	}
	return ApplyRequest{
		TenantID: tenantID, SiteID: siteID, ActorUserID: uuid.New(), IdempotencyKey: "apply-1",
		RequestID: uuid.NewString(), Traceparent: testTraceparent(), ExpectedRevision: 7, Check: check,
	}, checker
}

func testRuntimeConfig() RuntimeConfig {
	return RuntimeConfig{
		ProviderAttempts: 2, ProviderTimeout: time.Second, PollAttempts: 3,
		RequiredConsecutive: 2, InitialBackoff: time.Millisecond, MaximumBackoff: time.Second,
		OverallTimeout: 30 * time.Second, ApplyLeaseDuration: time.Minute, CommitLeaseDuration: time.Minute,
		Now: time.Now, Sleep: func(context.Context, time.Duration) error { return nil }, Random: func() float64 { return 0.5 },
	}
}

func dnsOperationRequestID(tenantID uuid.UUID, key, digest, phase string, sequence int) string {
	input := tenantID.String() + "\x00" + key + "\x00" + digest + "\x00" + phase + "\x00" + strconv.Itoa(sequence)
	sum := sha256.Sum256([]byte(input))
	return "dns-" + hex.EncodeToString(sum[:16])
}

func testTraceparent() string {
	return "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
}
