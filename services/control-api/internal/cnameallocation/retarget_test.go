package cnameallocation

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsreconcile"
	"github.com/google/uuid"
)

type fakeRetargets struct {
	open     []Retarget
	plans    int
	attached []uuid.UUID
	settled  map[uuid.UUID]string
}

func (fake *fakeRetargets) PlanRetargets(context.Context) (int, error) { fake.plans++; return 0, nil }
func (fake *fakeRetargets) OpenRetargets(context.Context) ([]Retarget, error) {
	return fake.open, nil
}
func (fake *fakeRetargets) AttachRetarget(_ context.Context, retarget Retarget, _ dnsreconcile.Task) error {
	fake.attached = append(fake.attached, retarget.ID)
	return nil
}
func (fake *fakeRetargets) SettleRetarget(_ context.Context, retarget Retarget, state, failure string) error {
	if fake.settled == nil {
		fake.settled = map[uuid.UUID]string{}
	}
	fake.settled[retarget.ID] = state + ":" + failure
	return nil
}

func retargetFixture(child uuid.UUID) Retarget {
	return Retarget{ID: uuid.New(), TenantID: uuid.New(), ScopeID: uuid.New(), AllocationID: uuid.New(),
		SiteID: uuid.New(), ZoneID: uuid.New(), ZoneRevision: 4, OwnerName: "label.cdn.example.com",
		Values: TargetValues{A: []string{"192.0.2.2"}}, Digest: strings.Repeat("ab", 32), ActorUserID: uuid.New(),
		RequestID: "cname-retarget/x/1", ChildTaskID: child, ChildTaskRevision: 1}
}

func TestWorkerRetargetAppliesServingValuesThenCommitsAndSettles(t *testing.T) {
	pending := retargetFixture(uuid.Nil)
	applying := retargetFixture(uuid.New())
	store := &fakeRetargets{open: []Retarget{pending, applying}}
	reconcile := &fakeCNAMEReconcile{task: dnsreconcile.Task{ID: uuid.New(), Revision: 2,
		Result: dnscheck.ReconcileResult{Status: dnscheck.TaskReadyToCommit}}}
	worker, err := NewWorker(WorkerConfig{WorkerID: "w", LeaseDuration: time.Minute, RetargetInterval: time.Hour},
		WorkerDependencies{Claims: &fakeCNAMEClaims{}, Targets: &fakeCNAMEStore{}, Reconcile: reconcile, Retargets: store})
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.RunRetargets(t.Context()); err != nil {
		t.Fatal(err)
	}
	if reconcile.applyCalls != 1 || reconcile.applied.SiteID != pending.SiteID ||
		reconcile.applied.IdempotencyKey != "cnrt-"+pending.Digest || reconcile.applied.ExpectedRevision != 4 ||
		len(reconcile.applied.Check.Expected) != 1 || reconcile.applied.Check.Expected[0].Values[0] != "192.0.2.2" ||
		reconcile.applied.Check.Name != pending.OwnerName {
		t.Fatalf("apply = %d %+v", reconcile.applyCalls, reconcile.applied)
	}
	if len(store.attached) != 1 || store.attached[0] != pending.ID {
		t.Fatalf("attached = %v", store.attached)
	}
	// The ready task is committed; the fake keeps returning ReadyToCommit, so
	// the row is left in flight rather than settled.
	if reconcile.commitCalls != 1 || store.settled[applying.ID] != "" {
		t.Fatalf("commit = %d settled = %v", reconcile.commitCalls, store.settled)
	}
	reconcile.task.Result.Status = dnscheck.TaskCommitted
	worker.lastRetarget = time.Time{}
	store.open = []Retarget{applying}
	if err := worker.RunRetargets(t.Context()); err != nil {
		t.Fatal(err)
	}
	if store.settled[applying.ID] != "committed:" {
		t.Fatalf("settled = %v", store.settled)
	}
	// Paced by RetargetInterval.
	plans := store.plans
	if err := worker.RunRetargets(t.Context()); err != nil || store.plans != plans {
		t.Fatalf("retarget ran again inside its interval: %v", err)
	}
}

type failingApplyReconcile struct {
	fakeCNAMEReconcile
	err error
}

func (fake *failingApplyReconcile) Apply(context.Context, dnsreconcile.ApplyRequest) (dnsreconcile.Task, error) {
	return dnsreconcile.Task{}, fake.err
}

func TestWorkerRetargetFailsDefinitiveApplyAndKeepsTransientForRetry(t *testing.T) {
	for _, test := range []struct {
		err  error
		want string
	}{{dnsreconcile.ErrOperationInFlight, ""}, {dnsreconcile.ErrUnavailable, ""}, {dnsreconcile.ErrInvalidInput, "failed:dns_reconcile_invalid_request"},
		{dnsreconcile.ErrPermissionDenied, "failed:dns_permission_denied"}} {
		retarget := retargetFixture(uuid.Nil)
		store := &fakeRetargets{open: []Retarget{retarget}}
		worker, err := NewWorker(WorkerConfig{WorkerID: "w", LeaseDuration: time.Minute},
			WorkerDependencies{Claims: &fakeCNAMEClaims{}, Targets: &fakeCNAMEStore{},
				Reconcile: &failingApplyReconcile{err: test.err}, Retargets: store})
		if err != nil {
			t.Fatal(err)
		}
		if err := worker.RunRetargets(t.Context()); err != nil {
			t.Fatal(err)
		}
		if store.settled[retarget.ID] != test.want || len(store.attached) != 0 {
			t.Fatalf("%v: settled=%v attached=%v", test.err, store.settled, store.attached)
		}
	}
}

type failingCommitReconcile struct {
	fakeCNAMEReconcile
	err error
}

func (fake *failingCommitReconcile) Commit(context.Context, dnsreconcile.CommitRequest) (dnsreconcile.Task, error) {
	fake.commitCalls++
	return dnsreconcile.Task{}, fake.err
}

// N25: a commit error was skipped silently (continue, no log), so a rejected
// commit left the retarget applying forever. A definitive error now fails the
// retarget with a readable code (the planner retries after
// retargetRetryAfter); a transient one is retried on the next pass.
func TestWorkerRetargetFailsRejectedCommitAndKeepsTransientForRetry(t *testing.T) {
	for _, test := range []struct {
		err  error
		want string
	}{
		{dnsreconcile.ErrUnavailable, ""}, {dnsreconcile.ErrOperationInFlight, ""}, {dnsreconcile.ErrCommitNotReady, ""},
		{dnsreconcile.ErrInvalidInput, "failed:dns_reconcile_commit_rejected"},
		{dnsreconcile.ErrIdempotencyConflict, "failed:dns_reconcile_commit_rejected"},
	} {
		retarget := retargetFixture(uuid.New())
		store := &fakeRetargets{open: []Retarget{retarget}}
		reconcile := &failingCommitReconcile{err: test.err, fakeCNAMEReconcile: fakeCNAMEReconcile{task: dnsreconcile.Task{
			ID: retarget.ChildTaskID, Revision: 2, Result: dnscheck.ReconcileResult{Status: dnscheck.TaskReadyToCommit}}}}
		worker, err := NewWorker(WorkerConfig{WorkerID: "w", LeaseDuration: time.Minute},
			WorkerDependencies{Claims: &fakeCNAMEClaims{}, Targets: &fakeCNAMEStore{}, Reconcile: reconcile, Retargets: store})
		if err != nil {
			t.Fatal(err)
		}
		if err := worker.RunRetargets(t.Context()); err != nil {
			t.Fatal(err)
		}
		if reconcile.commitCalls != 1 || store.settled[retarget.ID] != test.want {
			t.Fatalf("%v: commits=%d settled=%v, want %q", test.err, reconcile.commitCalls, store.settled, test.want)
		}
	}
}

// A commit that ends commit_failed (the store refused its checkpoint) fails the retarget.
func TestWorkerRetargetFailsCommitFailedTask(t *testing.T) {
	retarget := retargetFixture(uuid.New())
	store := &fakeRetargets{open: []Retarget{retarget}}
	reconcile := &fakeCNAMEReconcile{task: dnsreconcile.Task{ID: retarget.ChildTaskID, Revision: 2,
		Result: dnscheck.ReconcileResult{Status: dnscheck.TaskReadyToCommit}}}
	committed := &commitResultReconcile{fakeCNAMEReconcile: reconcile, result: dnscheck.ReconcileResult{
		Status: dnscheck.TaskCommitFailed, ErrorCode: "dns_reconcile_checkpoint_rejected"}}
	worker, err := NewWorker(WorkerConfig{WorkerID: "w", LeaseDuration: time.Minute},
		WorkerDependencies{Claims: &fakeCNAMEClaims{}, Targets: &fakeCNAMEStore{}, Reconcile: committed, Retargets: store})
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.RunRetargets(t.Context()); err != nil {
		t.Fatal(err)
	}
	if store.settled[retarget.ID] != "failed:dns_reconcile_failed" {
		t.Fatalf("settled = %v", store.settled)
	}
}

type commitResultReconcile struct {
	*fakeCNAMEReconcile
	result dnscheck.ReconcileResult
}

func (fake *commitResultReconcile) Commit(context.Context, dnsreconcile.CommitRequest) (dnsreconcile.Task, error) {
	fake.commitCalls++
	task := fake.task
	task.Result = fake.result
	return task, nil
}
