package dnsreconcile

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/google/uuid"
)

type dependencyUnavailableStore struct {
	*jitClaimStore
	checkpointCalls  int
	yieldCalls       int
	checkpointErr    error
	checkpointResult dnscheck.ReconcileResult
	yieldDelay       time.Duration
	yieldLease       ApplyLease
	now              func() time.Time
	notBefore        time.Time
}

func (store *dependencyUnavailableStore) CheckpointApply(
	ctx context.Context,
	lease ApplyLease,
	result dnscheck.ReconcileResult,
) (Task, error) {
	store.mu.Lock()
	store.checkpointCalls++
	store.checkpointResult = result
	err := store.checkpointErr
	store.mu.Unlock()
	if err != nil {
		return Task{}, err
	}
	return store.jitClaimStore.CheckpointApply(ctx, lease, result)
}

func (store *dependencyUnavailableStore) checkpointApplyAfter(
	ctx context.Context,
	lease ApplyLease,
	result dnscheck.ReconcileResult,
	delay time.Duration,
) (Task, error) {
	store.mu.Lock()
	store.yieldCalls++
	store.checkpointResult = result
	store.yieldDelay = delay
	store.yieldLease = lease
	err := store.checkpointErr
	store.mu.Unlock()
	if err != nil {
		return Task{}, err
	}
	task, err := store.jitClaimStore.CheckpointApply(ctx, lease, result)
	if err != nil {
		return Task{}, err
	}
	store.mu.Lock()
	for index := range store.leases {
		if store.leases[index].Task.ID == lease.Task.ID {
			store.claimed[index] = false
			store.leases[index].Attempt = lease.Attempt + 1
			store.leases[index].LeaseID = uuid.New()
			break
		}
	}
	now := time.Now
	if store.now != nil {
		now = store.now
	}
	store.notBefore = now().Add(delay)
	store.mu.Unlock()
	return task, nil
}

func (store *dependencyUnavailableStore) Claim(ctx context.Context, request ClaimRequest) ([]ApplyLease, error) {
	store.mu.Lock()
	now := time.Now
	if store.now != nil {
		now = store.now
	}
	blocked := request.TenantID != store.leases[0].Task.TenantID ||
		!store.notBefore.IsZero() && now().Before(store.notBefore)
	store.mu.Unlock()
	if blocked {
		return nil, nil
	}
	return store.jitClaimStore.Claim(ctx, request)
}

type unavailableCheckerResolver struct {
	checker *dnscheck.Checker
	err     error
	calls   int
}

func (resolver *unavailableCheckerResolver) ResolveChecker(
	context.Context,
	uuid.UUID,
	uuid.UUID,
) (*dnscheck.Checker, error) {
	resolver.calls++
	return resolver.checker, resolver.err
}

type unavailableProviderResolver struct {
	provider dnscheck.ProviderAdapter
	err      error
	calls    int
}

func (resolver *unavailableProviderResolver) ResolveProvider(
	context.Context,
	uuid.UUID,
	uuid.UUID,
	uuid.UUID,
) (dnscheck.ProviderAdapter, error) {
	resolver.calls++
	return resolver.provider, resolver.err
}

func TestRuntimeCheckpointsDependencyUnavailableAsLKG(t *testing.T) {
	fixedNow := time.Date(2026, 8, 6, 9, 30, 0, 0, time.UTC)
	dependencyError := errors.New("resolver dependency offline")

	tests := []struct {
		name            string
		checkerFailure  bool
		resolverError   error
		checkpointError error
	}{
		{name: "checker nil", checkerFailure: true},
		{name: "checker error", checkerFailure: true, resolverError: dependencyError},
		{name: "provider nil"},
		{name: "provider error", resolverError: dependencyError},
		{
			name: "checkpoint error", checkerFailure: true, resolverError: dependencyError,
			checkpointError: errors.New("checkpoint unavailable"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, checker := runtimeFixture(t, fixedNow)
			prepared, err := dnscheck.PrepareReconcile(dnscheck.ReconcileRequest{
				IdempotencyKey: request.IdempotencyKey,
				Check:          request.Check,
			}, func() time.Time { return fixedNow.Add(-time.Minute) })
			if err != nil {
				t.Fatal(err)
			}

			readyAt := fixedNow.Add(-30 * time.Second)
			lkg := prepared.Result
			lkg.Status = dnscheck.TaskApplying
			lkg.Replayed = true
			lkg.ReadyAt = &readyAt
			lkg.InitialRevision = 7
			lkg.ProviderRevision = 8
			lkg.ErrorClass = dnscheck.ProviderErrorPermanent
			lkg.ErrorCode = "previous_error"
			lkg.CompensationPlan = []dnscheck.ProviderOperation{{
				Action: dnscheck.ProviderDelete, RecordID: "task-owned-record",
			}}
			task := Task{
				ID: uuid.New(), TenantID: request.TenantID, SiteID: request.SiteID,
				ActorUserID: request.ActorUserID, RequestID: request.RequestID,
				RequiredConsecutive: 2, Prepared: prepared, Result: lkg,
			}
			store := &dependencyUnavailableStore{
				jitClaimStore: newJITClaimStore(task), checkpointErr: test.checkpointError,
				now: func() time.Time { return fixedNow },
			}
			provider := &testProvider{revision: request.Check.Provider.Revision}
			checkerResolver := &unavailableCheckerResolver{checker: checker}
			providerResolver := &unavailableProviderResolver{provider: provider}
			if test.checkerFailure {
				checkerResolver.checker = nil
				checkerResolver.err = test.resolverError
			} else {
				providerResolver.provider = nil
				providerResolver.err = test.resolverError
			}
			config := testRuntimeConfig()
			config.Now = func() time.Time { return fixedNow }
			runtime, err := NewRuntime(config, RuntimeDependencies{
				Store: store, CheckerResolver: checkerResolver,
				ProviderResolver: providerResolver, Entitlement: testEntitlement{},
			})
			if err != nil {
				t.Fatal(err)
			}

			completed, runErr := runtime.RunOnce(t.Context(), request.TenantID, "dependency-lkg-worker", 1)
			if test.checkpointError != nil {
				if !errors.Is(runErr, test.checkpointError) || len(completed) != 0 {
					t.Fatalf("RunOnce() = (%#v, %v), want raw checkpoint error", completed, runErr)
				}
			} else if runErr != nil || len(completed) != 1 {
				t.Fatalf("RunOnce() = (%#v, %v), want one propagating LKG task", completed, runErr)
			}

			expected := lkg
			expected.Status = dnscheck.TaskPropagating
			expected.ErrorClass = dnscheck.ProviderErrorTransient
			expected.ErrorCode = "dependency_unavailable"
			expected.CompensationPlan = nil
			expected.UpdatedAt = fixedNow
			store.mu.Lock()
			checkpointCalls := store.checkpointCalls
			yieldCalls := store.yieldCalls
			yieldDelay := store.yieldDelay
			yieldLease := store.yieldLease
			checkpointResult := store.checkpointResult
			finishCalls := store.finishCalls
			heartbeatCalls := store.heartbeatCalls
			store.mu.Unlock()
			if checkpointCalls != 0 || yieldCalls != 1 || finishCalls != 0 || heartbeatCalls != 1 {
				t.Fatalf("checkpoint/yield/finish/heartbeat calls = %d/%d/%d/%d, want 0/1/0/1",
					checkpointCalls, yieldCalls, finishCalls, heartbeatCalls)
			}
			if yieldDelay < config.InitialBackoff || yieldDelay > config.MaximumBackoff ||
				yieldLease.Task.TenantID != request.TenantID || yieldLease.Task.ID != task.ID {
				t.Fatalf("yield delay/lease = %s/%#v", yieldDelay, yieldLease)
			}
			if !reflect.DeepEqual(checkpointResult, expected) {
				t.Fatalf("checkpoint result = %#v, want preserved LKG %#v", checkpointResult, expected)
			}
			if test.checkerFailure {
				if checkerResolver.calls != 1 || providerResolver.calls != 0 {
					t.Fatalf("checker/provider resolver calls = %d/%d, want 1/0",
						checkerResolver.calls, providerResolver.calls)
				}
			} else if checkerResolver.calls != 1 || providerResolver.calls != 1 {
				t.Fatalf("checker/provider resolver calls = %d/%d, want 1/1",
					checkerResolver.calls, providerResolver.calls)
			}
			if provider.mutationCount() != 0 {
				t.Fatalf("provider mutations = %d, want 0", provider.mutationCount())
			}
			if test.checkpointError == nil && !reflect.DeepEqual(completed[0].Result, expected) {
				t.Fatalf("completed result = %#v, want checkpointed LKG %#v", completed[0].Result, expected)
			}
		})
	}
}

func TestRuntimeDependencyUnavailableYieldAllowsRestartAfterNotBeforeWithTenantFence(t *testing.T) {
	now := time.Date(2026, 8, 8, 2, 0, 0, 0, time.UTC)
	request, _ := runtimeFixture(t, now)
	prepared, err := dnscheck.PrepareReconcile(dnscheck.ReconcileRequest{
		IdempotencyKey: request.IdempotencyKey, Check: request.Check,
	}, func() time.Time { return now.Add(-time.Minute) })
	if err != nil {
		t.Fatal(err)
	}
	task := Task{
		ID: uuid.New(), TenantID: request.TenantID, SiteID: request.SiteID,
		ActorUserID: request.ActorUserID, RequestID: request.RequestID,
		RequiredConsecutive: 2, Prepared: prepared, Result: prepared.Result,
	}
	store := &dependencyUnavailableStore{jitClaimStore: newJITClaimStore(task), now: func() time.Time { return now }}
	checkerResolver := &unavailableCheckerResolver{err: errors.New("checker offline")}
	config := testRuntimeConfig()
	config.Now = func() time.Time { return now }
	runtime, err := NewRuntime(config, RuntimeDependencies{
		Store: store, CheckerResolver: checkerResolver,
		ProviderResolver: &unavailableProviderResolver{}, Entitlement: testEntitlement{},
	})
	if err != nil {
		t.Fatal(err)
	}

	first, err := runtime.RunOnce(t.Context(), request.TenantID, "dependency-worker-a", 1)
	if err != nil || len(first) != 1 {
		t.Fatalf("first RunOnce() = (%#v, %v)", first, err)
	}
	store.mu.Lock()
	firstDelay := store.yieldDelay
	firstNotBefore := store.notBefore
	store.mu.Unlock()
	if immediate, err := runtime.RunOnce(t.Context(), request.TenantID, "dependency-worker-b", 1); err != nil || len(immediate) != 0 {
		t.Fatalf("immediate RunOnce() = (%#v, %v), want not-before fence", immediate, err)
	}
	now = firstNotBefore
	if foreign, err := runtime.RunOnce(t.Context(), uuid.New(), "foreign-tenant-worker", 1); err != nil || len(foreign) != 0 {
		t.Fatalf("foreign RunOnce() = (%#v, %v), want tenant fence", foreign, err)
	}
	restarted, err := runtime.RunOnce(t.Context(), request.TenantID, "dependency-worker-b", 1)
	if err != nil || len(restarted) != 1 || checkerResolver.calls != 2 {
		t.Fatalf("restarted RunOnce() = (%#v, %v), checker calls=%d", restarted, err, checkerResolver.calls)
	}
	store.mu.Lock()
	secondDelay := store.yieldDelay
	yieldCalls := store.yieldCalls
	store.mu.Unlock()
	if yieldCalls != 2 || secondDelay < firstDelay || secondDelay > config.MaximumBackoff {
		t.Fatalf("yield calls/delays = %d/%s/%s", yieldCalls, firstDelay, secondDelay)
	}
}

func TestRuntimeNonDependencyCheckpointKeepsRegularPath(t *testing.T) {
	store := &dependencyUnavailableStore{jitClaimStore: newJITClaimStore()}
	runtime := &Runtime{store: store}
	lease := ApplyLease{Task: Task{ID: uuid.New(), TenantID: uuid.New()}, Attempt: 1, LeaseID: uuid.New(), WorkerID: "worker"}
	result := dnscheck.ReconcileResult{Status: dnscheck.TaskApplying}
	if _, err := runtime.checkpointApply(t.Context(), lease, result); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	checkpointCalls, yieldCalls := store.checkpointCalls, store.yieldCalls
	store.mu.Unlock()
	if checkpointCalls != 1 || yieldCalls != 0 {
		t.Fatalf("checkpoint/yield calls = %d/%d, want 1/0", checkpointCalls, yieldCalls)
	}
}

func TestPostgresDependencyUnavailableCheckpointAndYieldShareTransaction(t *testing.T) {
	source, err := os.ReadFile("postgres_store.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, required := range []string{
		`!consumed && result.ErrorCode != "dependency_unavailable"`,
		"insertTaskEvent(ctx, tx, current, source, attempt, leaseID, workerID, checkpointResult, now)",
		"jobstate.VoluntaryYieldTx(ctx, tx, jobstate.VoluntaryYieldInput{",
		"NotBefore: now.Add(retryDelay)",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("Postgres dependency yield transaction missing %q", required)
		}
	}
}

func TestRuntimeRejectsPersistedQuorumAbovePollAttempts(t *testing.T) {
	fixedNow := time.Date(2026, 8, 6, 10, 0, 0, 0, time.UTC)
	request, checker := runtimeFixture(t, fixedNow)
	prepared, err := dnscheck.PrepareReconcile(dnscheck.ReconcileRequest{
		IdempotencyKey: request.IdempotencyKey,
		Check:          request.Check,
	}, func() time.Time { return fixedNow })
	if err != nil {
		t.Fatal(err)
	}
	task := Task{
		ID: uuid.New(), TenantID: request.TenantID, SiteID: request.SiteID,
		ActorUserID: request.ActorUserID, RequestID: request.RequestID,
		RequiredConsecutive: 2, Prepared: prepared, Result: prepared.Result,
	}
	store := &dependencyUnavailableStore{jitClaimStore: newJITClaimStore(task)}
	provider := &testProvider{revision: request.Check.Provider.Revision}
	checkerResolver := &unavailableCheckerResolver{checker: checker}
	providerResolver := &unavailableProviderResolver{provider: provider}
	config := testRuntimeConfig()
	config.PollAttempts = 1
	config.RequiredConsecutive = 1
	config.Now = func() time.Time { return fixedNow }
	runtime, err := NewRuntime(config, RuntimeDependencies{
		Store: store, CheckerResolver: checkerResolver,
		ProviderResolver: providerResolver, Entitlement: testEntitlement{},
	})
	if err != nil {
		t.Fatal(err)
	}

	completed, runErr := runtime.RunOnce(t.Context(), request.TenantID, "incompatible-quorum-worker", 1)
	if !errors.Is(runErr, ErrUnavailable) || len(completed) != 0 {
		t.Fatalf("RunOnce() = (%#v, %v), want original unavailable error", completed, runErr)
	}
	store.mu.Lock()
	checkpointCalls := store.checkpointCalls
	finishCalls := store.finishCalls
	heartbeatCalls := store.heartbeatCalls
	store.mu.Unlock()
	if checkpointCalls != 0 || finishCalls != 0 || heartbeatCalls != 1 {
		t.Fatalf("checkpoint/finish/heartbeat calls = %d/%d/%d, want 0/0/1",
			checkpointCalls, finishCalls, heartbeatCalls)
	}
	if checkerResolver.calls != 0 || providerResolver.calls != 0 || provider.mutationCount() != 0 {
		t.Fatalf("checker/provider resolver calls and mutations = %d/%d/%d, want 0/0/0",
			checkerResolver.calls, providerResolver.calls, provider.mutationCount())
	}
}
