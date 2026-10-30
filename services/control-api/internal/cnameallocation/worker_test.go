package cnameallocation

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsreconcile"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
)

func TestCanonicalTargetValuesFreezeSealedSoldPackageEndpoints(t *testing.T) {
	values, err := canonicalTargetValues([]string{
		"2001:db8::2", "192.0.2.20", "2001:0db8:0:0:0:0:0:2", "192.0.2.10", "192.0.2.20",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := TargetValues{A: []string{"192.0.2.10", "192.0.2.20"}, AAAA: []string{"2001:db8::2"}}
	if !reflect.DeepEqual(values, want) {
		t.Fatalf("canonicalTargetValues() = %#v, want %#v", values, want)
	}
	single, err := canonicalTargetValues([]string{"192.0.2.10"})
	if err != nil || single.AAAA == nil || len(single.AAAA) != 0 {
		t.Fatalf("single-family AAAA must be empty, not nil: %#v %v", single, err)
	}
	for _, invalid := range [][]string{nil, {"192.0.2.1/32"}, {"::ffff:192.0.2.1"}} {
		if _, err := canonicalTargetValues(invalid); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("canonicalTargetValues(%v) error = %v", invalid, err)
		}
	}
}

func TestWorkerResumesFrozenChildAndSettlesWithOriginalLeaseFence(t *testing.T) {
	tenantID, scopeID, siteID, jobID, allocationID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	leaseID, childID, actorID := uuid.New(), uuid.New(), uuid.New()
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	target := Target{
		TenantID: tenantID, ScopeID: scopeID, SiteID: siteID, AllocationID: allocationID, JobID: jobID,
		PackageSubscriptionID: uuid.New(), NodeGroupID: uuid.New(), NodeGroupRevision: 7,
		ProviderID: uuid.New(), ZoneID: uuid.New(), ZoneRevision: 11, OwnerName: "edge.example.test",
		ActorUserID: actorID, RequestID: "request-1", AllocationRevision: 3, TTL: 300,
		Values: TargetValues{A: []string{"192.0.2.10"}}, Digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ChildTaskID: childID, ChildTaskRevision: 4,
	}
	claims := &fakeCNAMEClaims{claim: jobstate.Claim{Job: jobstate.StoredJob{
		ID: jobID, TenantID: tenantID, Kind: databaseJobKind, Attempt: 2,
	}, LeaseID: leaseID, WorkerID: "worker-1", LeaseExpiresAt: now.Add(time.Minute)}}
	targets := &fakeCNAMEStore{target: target}
	reconcile := &fakeCNAMEReconcile{task: dnsreconcile.Task{
		ID: childID, TenantID: tenantID, SiteID: siteID, ActorUserID: actorID, Revision: 4,
		Result: dnscheck.ReconcileResult{Status: dnscheck.TaskCommitted},
	}}
	worker, err := NewWorker(WorkerConfig{WorkerID: "worker-1", LeaseDuration: time.Minute, Now: func() time.Time { return now }}, WorkerDependencies{
		Claims: claims, Targets: targets, Reconcile: reconcile,
	})
	if err != nil {
		t.Fatal(err)
	}
	didWork, err := worker.RunOnce(context.Background(), tenantID)
	if err != nil || !didWork {
		t.Fatalf("RunOnce() = (%v,%v)", didWork, err)
	}
	if reconcile.applyCalls != 0 || reconcile.getCalls != 1 || targets.completeCalls != 1 {
		t.Fatalf("calls apply/get/complete = %d/%d/%d", reconcile.applyCalls, reconcile.getCalls, targets.completeCalls)
	}
	if targets.completed.WorkerID != "worker-1" || targets.completed.Attempt != 2 ||
		targets.completed.LeaseID != leaseID || targets.completed.ExpectedRevision != target.AllocationRevision {
		t.Fatalf("settlement fence = %#v", targets.completed)
	}
}

func TestWorkerStartsOneChildFromFrozenTargetAndPersistsCorrelationBeforeYield(t *testing.T) {
	tenantID, scopeID, siteID, jobID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	target := Target{
		TenantID: tenantID, ScopeID: scopeID, SiteID: siteID, AllocationID: uuid.New(), JobID: jobID,
		PackageSubscriptionID: uuid.New(), NodeGroupID: uuid.New(), NodeGroupRevision: 9,
		ProviderID: uuid.New(), ZoneID: uuid.New(), ZoneRevision: 5, OwnerName: "edge.example.test",
		ActorUserID: uuid.New(), RequestID: "request-2", AllocationRevision: 1, TTL: 300,
		Values: TargetValues{A: []string{"192.0.2.10"}, AAAA: []string{"2001:db8::1"}},
		Digest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	claims := &fakeCNAMEClaims{claim: jobstate.Claim{Job: jobstate.StoredJob{
		ID: jobID, TenantID: tenantID, Kind: databaseJobKind, Attempt: 1,
	}, LeaseID: uuid.New(), WorkerID: "worker-2", LeaseExpiresAt: now.Add(time.Minute)}}
	targets := &fakeCNAMEStore{target: target}
	reconcile := &fakeCNAMEReconcile{task: dnsreconcile.Task{ID: uuid.New(), TenantID: tenantID, SiteID: siteID, Revision: 1,
		Result: dnscheck.ReconcileResult{Status: dnscheck.TaskApplying}}}
	worker, err := NewWorker(WorkerConfig{WorkerID: "worker-2", LeaseDuration: time.Minute, Now: func() time.Time { return now }}, WorkerDependencies{
		Claims: claims, Targets: targets, Reconcile: reconcile,
	})
	if err != nil {
		t.Fatal(err)
	}
	if didWork, err := worker.RunOnce(context.Background(), tenantID); err != nil || !didWork {
		t.Fatalf("RunOnce() = (%v,%v)", didWork, err)
	}
	if reconcile.applyCalls != 1 || targets.attachCalls != 1 || targets.completeCalls != 0 || targets.failCalls != 0 {
		t.Fatalf("calls apply/attach/complete/fail = %d/%d/%d/%d", reconcile.applyCalls, targets.attachCalls, targets.completeCalls, targets.failCalls)
	}
	if got := reconcile.applied.Check; got.Name != target.OwnerName || got.TTL != 300 || got.Provider.ZoneID != target.ZoneID || got.Provider.Revision != target.ZoneRevision ||
		len(got.Expected) != 2 || got.Expected[0].Type != dnscheck.RecordA || got.Expected[1].Type != dnscheck.RecordAAAA {
		t.Fatalf("frozen reconcile request = %#v", got)
	}
	if reconcile.applied.ExpectedRevision != target.ZoneRevision || reconcile.applied.Traceparent == "" {
		t.Fatalf("apply fencing metadata = %#v", reconcile.applied)
	}
}

func TestWorkerPreparesDurableIntentBeforeClaimingAllocation(t *testing.T) {
	tenantID := uuid.New()
	claim := jobstate.Claim{Job: jobstate.StoredJob{ID: uuid.New(), TenantID: tenantID, Kind: "dns.cname.intent", Attempt: 1},
		LeaseID: uuid.New(), WorkerID: "worker-intent", LeaseExpiresAt: time.Now().Add(time.Minute)}
	claims := &kindClaims{intent: claim}
	intents := &fakeIntentStore{}
	worker, err := NewWorker(WorkerConfig{WorkerID: "worker-intent", LeaseDuration: time.Minute}, WorkerDependencies{
		Intents: intents, Claims: claims, Targets: &fakeCNAMEStore{}, Reconcile: &fakeCNAMEReconcile{},
	})
	if err != nil {
		t.Fatal(err)
	}
	didWork, err := worker.RunOnce(context.Background(), tenantID)
	if err != nil || !didWork || intents.calls != 1 || claims.allocationClaims != 0 {
		t.Fatalf("intent preparation = work:%v err:%v calls:%d allocation claims:%d", didWork, err, intents.calls, claims.allocationClaims)
	}
}

type fakeIntentStore struct {
	calls     int
	onPrepare func()
}

func (store *fakeIntentStore) PrepareIntent(context.Context, jobstate.Claim) error {
	store.calls++
	if store.onPrepare != nil {
		store.onPrepare()
	}
	return nil
}

func TestWorkerTransientIntentDoesNotBlockAnotherTenant(t *testing.T) {
	first, second := uuid.New(), uuid.New()
	claims := &tenantIntentClaims{claims: map[uuid.UUID]jobstate.Claim{
		first:  {Job: jobstate.StoredJob{ID: uuid.New(), TenantID: first, Attempt: 1}, LeaseID: uuid.New(), WorkerID: "worker"},
		second: {Job: jobstate.StoredJob{ID: uuid.New(), TenantID: second, Attempt: 1}, LeaseID: uuid.New(), WorkerID: "worker"},
	}}
	intents := &sequencedIntentStore{errors: []error{ErrUnavailable, nil}}
	worker, err := NewWorker(WorkerConfig{WorkerID: "worker", LeaseDuration: time.Minute}, WorkerDependencies{
		Intents: intents, Claims: claims, Targets: &fakeCNAMEStore{}, Reconcile: &fakeCNAMEReconcile{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.runTenants(context.Background(), []uuid.UUID{first, second}); err != nil || intents.calls != 2 {
		t.Fatalf("runTenants() err=%v calls=%d", err, intents.calls)
	}
}

func TestWorkerDNS03RunProcessesPendingWorkBeforeFirstTick(t *testing.T) {
	tenantID := uuid.New()
	claim := jobstate.Claim{Job: jobstate.StoredJob{ID: uuid.New(), TenantID: tenantID, Kind: "dns.cname.intent", Attempt: 1},
		LeaseID: uuid.New(), WorkerID: "worker-immediate", LeaseExpiresAt: time.Now().Add(time.Minute)}
	claims := &kindClaims{intent: claim}
	ctx, cancel := context.WithCancel(context.Background())
	intents := &fakeIntentStore{onPrepare: cancel}
	tenants := &fakeTenantSource{tenants: []uuid.UUID{tenantID}}
	worker, err := NewWorker(WorkerConfig{WorkerID: "worker-immediate", LeaseDuration: time.Minute, PollInterval: time.Hour}, WorkerDependencies{
		Tenants: tenants, Intents: intents, Claims: claims, Targets: &fakeCNAMEStore{}, Reconcile: &fakeCNAMEReconcile{},
	})
	if err != nil {
		t.Fatal(err)
	}
	timeout := time.AfterFunc(200*time.Millisecond, cancel)
	defer timeout.Stop()
	if err := worker.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v", err)
	}
	if tenants.calls != 1 || intents.calls != 1 {
		t.Fatalf("immediate calls tenants/intents = %d/%d", tenants.calls, intents.calls)
	}
}

func TestWorkerDNS03ConsumesTenantBacklogUntilEmptyWithinFairBound(t *testing.T) {
	t.Run("empty queue stops after multiple jobs", func(t *testing.T) {
		tenantID := uuid.New()
		claims := newQueuedClaims(tenantID, 3)
		targets := &fakeCNAMEStore{target: committedTarget(tenantID)}
		worker := mustBacklogWorker(t, claims, targets)
		if err := worker.runTenants(t.Context(), []uuid.UUID{tenantID}); err != nil {
			t.Fatal(err)
		}
		if targets.completeCalls != 3 || claims.calls[tenantID] != 4 {
			t.Fatalf("complete/claim calls = %d/%d", targets.completeCalls, claims.calls[tenantID])
		}
	})

	t.Run("round is bounded and resumes remainder", func(t *testing.T) {
		tenantID := uuid.New()
		claims := newQueuedClaims(tenantID, maxJobsPerTenantRound+2)
		targets := &fakeCNAMEStore{target: committedTarget(tenantID)}
		worker := mustBacklogWorker(t, claims, targets)
		if err := worker.runTenants(t.Context(), []uuid.UUID{tenantID}); err != nil {
			t.Fatal(err)
		}
		if targets.completeCalls != maxJobsPerTenantRound || claims.calls[tenantID] != maxJobsPerTenantRound {
			t.Fatalf("first round complete/claim calls = %d/%d", targets.completeCalls, claims.calls[tenantID])
		}
		if err := worker.runTenants(t.Context(), []uuid.UUID{tenantID}); err != nil {
			t.Fatal(err)
		}
		if targets.completeCalls != maxJobsPerTenantRound+2 || claims.calls[tenantID] != maxJobsPerTenantRound+3 {
			t.Fatalf("second round complete/claim calls = %d/%d", targets.completeCalls, claims.calls[tenantID])
		}
	})
}

func TestWorkerDNS03TransientClaimDoesNotBlockOtherTenant(t *testing.T) {
	for _, transient := range []error{ErrClaimLost, ErrUnavailable} {
		t.Run(transient.Error(), func(t *testing.T) {
			first, second := uuid.New(), uuid.New()
			claims := newQueuedClaims(second, 1)
			claims.errors[first] = transient
			targets := &fakeCNAMEStore{target: committedTarget(second)}
			worker := mustBacklogWorker(t, claims, targets)
			if err := worker.runTenants(t.Context(), []uuid.UUID{first, second}); err != nil {
				t.Fatal(err)
			}
			if targets.completeCalls != 1 || claims.calls[first] != 1 || claims.calls[second] != 2 {
				t.Fatalf("complete=%d claim calls=%v", targets.completeCalls, claims.calls)
			}
		})
	}
}

func TestWorkerDNS03RepeatedRunOnceDoesNotRepeatAttachOrComplete(t *testing.T) {
	for _, test := range []struct {
		name   string
		target Target
		attach int
		done   int
	}{
		{name: "attach", target: pendingTarget(uuid.New()), attach: 1},
		{name: "complete", target: committedTarget(uuid.New()), done: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			claim := jobstate.Claim{Job: jobstate.StoredJob{ID: test.target.JobID, TenantID: test.target.TenantID, Kind: databaseJobKind, Attempt: 1},
				LeaseID: uuid.New(), WorkerID: "worker-repeat", LeaseExpiresAt: time.Now().Add(time.Minute)}
			claims := &fakeCNAMEClaims{claim: claim}
			targets := &fakeCNAMEStore{target: test.target}
			reconcile := &fakeCNAMEReconcile{task: dnsreconcile.Task{ID: test.target.ChildTaskID, TenantID: test.target.TenantID,
				SiteID: test.target.SiteID, Result: dnscheck.ReconcileResult{Status: dnscheck.TaskCommitted}}}
			if reconcile.task.ID == uuid.Nil {
				reconcile.task.ID = uuid.New()
				reconcile.task.Result.Status = dnscheck.TaskApplying
			}
			worker, err := NewWorker(WorkerConfig{WorkerID: "worker-repeat", LeaseDuration: time.Minute}, WorkerDependencies{
				Claims: claims, Targets: targets, Reconcile: reconcile,
			})
			if err != nil {
				t.Fatal(err)
			}
			if didWork, err := worker.RunOnce(t.Context(), test.target.TenantID); err != nil || !didWork {
				t.Fatalf("first RunOnce() = (%v,%v)", didWork, err)
			}
			if didWork, err := worker.RunOnce(t.Context(), test.target.TenantID); err != nil || didWork {
				t.Fatalf("second RunOnce() = (%v,%v)", didWork, err)
			}
			if targets.attachCalls != test.attach || targets.completeCalls != test.done {
				t.Fatalf("attach/complete = %d/%d", targets.attachCalls, targets.completeCalls)
			}
		})
	}
}

type fakeTenantSource struct {
	tenants []uuid.UUID
	calls   int
}

func (source *fakeTenantSource) PendingTenants(context.Context, int) ([]uuid.UUID, error) {
	source.calls++
	return append([]uuid.UUID(nil), source.tenants...), nil
}

type queuedClaims struct {
	jobs   map[uuid.UUID][]jobstate.Claim
	errors map[uuid.UUID]error
	calls  map[uuid.UUID]int
}

func newQueuedClaims(tenantID uuid.UUID, count int) *queuedClaims {
	claims := &queuedClaims{jobs: map[uuid.UUID][]jobstate.Claim{}, errors: map[uuid.UUID]error{}, calls: map[uuid.UUID]int{}}
	for range count {
		claims.jobs[tenantID] = append(claims.jobs[tenantID], jobstate.Claim{Job: jobstate.StoredJob{
			ID: uuid.New(), TenantID: tenantID, Kind: databaseJobKind, Attempt: 1,
		}, LeaseID: uuid.New(), WorkerID: "worker-backlog", LeaseExpiresAt: time.Now().Add(time.Minute)})
	}
	return claims
}

func (claims *queuedClaims) Claim(_ context.Context, input jobstate.ClaimInput) ([]jobstate.Claim, error) {
	claims.calls[input.TenantID]++
	if err := claims.errors[input.TenantID]; err != nil {
		delete(claims.errors, input.TenantID)
		return nil, err
	}
	queue := claims.jobs[input.TenantID]
	if len(queue) == 0 {
		return nil, nil
	}
	claims.jobs[input.TenantID] = queue[1:]
	return []jobstate.Claim{queue[0]}, nil
}

func pendingTarget(tenantID uuid.UUID) Target {
	return Target{TenantID: tenantID, ScopeID: uuid.New(), SiteID: uuid.New(), AllocationID: uuid.New(), JobID: uuid.New(),
		ActorUserID: uuid.New(), ZoneID: uuid.New(), ZoneRevision: 1, AllocationRevision: 1, TTL: 300,
		OwnerName: "edge.example.test", Values: TargetValues{A: []string{"192.0.2.10"}},
		Digest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", RequestID: "dns03-request"}
}

func committedTarget(tenantID uuid.UUID) Target {
	target := pendingTarget(tenantID)
	target.ChildTaskID = uuid.New()
	return target
}

func mustBacklogWorker(t *testing.T, claims ClaimStore, targets *fakeCNAMEStore) *Worker {
	t.Helper()
	worker, err := NewWorker(WorkerConfig{WorkerID: "worker-backlog", LeaseDuration: time.Minute}, WorkerDependencies{
		Claims: claims, Targets: targets, Reconcile: &fakeCNAMEReconcile{task: dnsreconcile.Task{
			ID: targets.target.ChildTaskID, TenantID: targets.target.TenantID, SiteID: targets.target.SiteID,
			Result: dnscheck.ReconcileResult{Status: dnscheck.TaskCommitted},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return worker
}

type tenantIntentClaims struct{ claims map[uuid.UUID]jobstate.Claim }

func (claims *tenantIntentClaims) Claim(_ context.Context, input jobstate.ClaimInput) ([]jobstate.Claim, error) {
	claim, ok := claims.claims[input.TenantID]
	if !ok {
		return nil, nil
	}
	delete(claims.claims, input.TenantID)
	return []jobstate.Claim{claim}, nil
}

type sequencedIntentStore struct {
	errors []error
	calls  int
}

func (store *sequencedIntentStore) PrepareIntent(context.Context, jobstate.Claim) error {
	err := store.errors[store.calls]
	store.calls++
	return err
}

type kindClaims struct {
	intent           jobstate.Claim
	used             bool
	allocationClaims int
}

func (claims *kindClaims) Claim(_ context.Context, input jobstate.ClaimInput) ([]jobstate.Claim, error) {
	if input.Kind == "dns.cname.intent" && !claims.used {
		claims.used = true
		return []jobstate.Claim{claims.intent}, nil
	}
	claims.allocationClaims++
	return nil, nil
}

type fakeCNAMEClaims struct {
	claim jobstate.Claim
	used  bool
}

func (fake *fakeCNAMEClaims) Claim(context.Context, jobstate.ClaimInput) ([]jobstate.Claim, error) {
	if fake.used {
		return nil, nil
	}
	fake.used = true
	return []jobstate.Claim{fake.claim}, nil
}

type fakeCNAMEStore struct {
	target                                Target
	attached                              uuid.UUID
	completed                             ResultRequest
	attachCalls, completeCalls, failCalls int
	yieldCalls                            int
	yieldClaim                            jobstate.Claim
	yieldDelay                            time.Duration
}

func (fake *fakeCNAMEStore) Yield(_ context.Context, claim jobstate.Claim, delay time.Duration) error {
	fake.yieldCalls++
	fake.yieldClaim, fake.yieldDelay = claim, delay
	return nil
}

func (fake *fakeCNAMEStore) LoadTarget(context.Context, jobstate.Claim) (Target, error) {
	return fake.target, nil
}
func (fake *fakeCNAMEStore) AttachChild(_ context.Context, _ jobstate.Claim, _ Target, task dnsreconcile.Task) error {
	fake.attachCalls++
	fake.attached = task.ID
	return nil
}
func (fake *fakeCNAMEStore) Complete(_ context.Context, request ResultRequest) (Allocation, error) {
	fake.completeCalls++
	fake.completed = request
	return Allocation{}, nil
}
func (fake *fakeCNAMEStore) Fail(_ context.Context, request ResultRequest) (Allocation, error) {
	fake.failCalls++
	fake.completed = request
	return Allocation{}, nil
}

type fakeCNAMEReconcile struct {
	task                              dnsreconcile.Task
	applied                           dnsreconcile.ApplyRequest
	applyCalls, getCalls, commitCalls int
}

func (fake *fakeCNAMEReconcile) Apply(_ context.Context, request dnsreconcile.ApplyRequest) (dnsreconcile.Task, error) {
	fake.applyCalls++
	fake.applied = request
	return fake.task, nil
}
func (fake *fakeCNAMEReconcile) Get(context.Context, uuid.UUID, uuid.UUID) (dnsreconcile.Task, error) {
	fake.getCalls++
	return fake.task, nil
}
func (fake *fakeCNAMEReconcile) Commit(context.Context, dnsreconcile.CommitRequest) (dnsreconcile.Task, error) {
	fake.commitCalls++
	return fake.task, nil
}
