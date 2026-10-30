package cnameallocation

import (
	"context"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsreconcile"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
)

func childSettledFixture(t *testing.T, task dnsreconcile.Task) (*Worker, *fakeCNAMEStore, uuid.UUID) {
	t.Helper()
	tenantID := uuid.New()
	target := Target{TenantID: tenantID, ScopeID: uuid.New(), SiteID: uuid.New(), AllocationID: uuid.New(), JobID: uuid.New(),
		ZoneID: uuid.New(), ZoneRevision: 2, OwnerName: "16pkdu5t.cdn.868yun.com", ActorUserID: uuid.New(), RequestID: "r",
		AllocationRevision: 1, TTL: 600, Values: TargetValues{A: []string{"192.0.2.78", "192.0.2.85"}}, ChildTaskID: task.ID,
		Digest: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}
	claims := &fakeCNAMEClaims{claim: jobstate.Claim{Job: jobstate.StoredJob{ID: target.JobID, TenantID: tenantID,
		Kind: databaseJobKind, Attempt: 12, MaxAttempts: maximumJobAttempts}, LeaseID: uuid.New(), WorkerID: "w"}}
	targets := &fakeCNAMEStore{target: target}
	task.TenantID, task.SiteID = tenantID, target.SiteID
	worker, err := NewWorker(WorkerConfig{WorkerID: "w", LeaseDuration: time.Minute},
		WorkerDependencies{Claims: claims, Targets: targets, Reconcile: &fakeCNAMEReconcile{task: task}})
	if err != nil {
		t.Fatal(err)
	}
	return worker, targets, tenantID
}

// N14 follow-up: both records were written, the propagation check gave up and
// jobstate finalized the reconcile job failed (retries_exhausted) while its
// last result was still "propagating". The allocation (37b17da4, attempt 12)
// kept polling it as in flight and the site showed "生成中" for good. It now
// fails with dns_propagation_unconfirmed: the site shows the reason and the
// regenerate button.
func TestWorkerFailsAllocationWhenChildJobEndedWithoutCommit(t *testing.T) {
	written := []dnscheck.OperationResult{{Status: dnscheck.OperationSucceeded}, {Status: dnscheck.OperationSucceeded}}
	for _, test := range []struct {
		name     string
		status   dnscheck.TaskStatus
		job      jobstate.State
		ops      []dnscheck.OperationResult
		wantCode string
	}{
		{"propagating, job retries_exhausted", dnscheck.TaskPropagating, jobstate.StateFailed, written, "dns_propagation_unconfirmed"},
		{"result failed after the writes", dnscheck.TaskFailed, jobstate.StateFailed, written, "dns_propagation_unconfirmed"},
		{"timed out after the writes", dnscheck.TaskTimedOut, jobstate.StateFailed, written, "dns_propagation_unconfirmed"},
		{"write failed", dnscheck.TaskFailed, jobstate.StateFailed,
			[]dnscheck.OperationResult{{Status: dnscheck.OperationSucceeded}, {Status: dnscheck.OperationPermanentFailed}}, "dns_reconcile_failed"},
		{"commit failed", dnscheck.TaskCommitFailed, jobstate.StateFailed, written, "dns_reconcile_failed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			worker, targets, tenantID := childSettledFixture(t, dnsreconcile.Task{ID: uuid.New(), Revision: 5,
				Result: dnscheck.ReconcileResult{Status: test.status, Operations: test.ops},
				Job:    jobstate.StoredJob{State: test.job}})
			if _, err := worker.RunOnce(context.Background(), tenantID); err != nil {
				t.Fatal(err)
			}
			if targets.failCalls != 1 || targets.yieldCalls != 0 || targets.completed.FailureCode != test.wantCode {
				t.Fatalf("fail=%d yield=%d code=%q, want one failure %q", targets.failCalls, targets.yieldCalls,
					targets.completed.FailureCode, test.wantCode)
			}
		})
	}
	// still running: keep polling
	worker, targets, tenantID := childSettledFixture(t, dnsreconcile.Task{ID: uuid.New(), Revision: 5,
		Result: dnscheck.ReconcileResult{Status: dnscheck.TaskPropagating, Operations: written},
		Job:    jobstate.StoredJob{State: jobstate.StateQueued}})
	if _, err := worker.RunOnce(context.Background(), tenantID); err != nil || targets.failCalls != 0 || targets.yieldCalls != 1 {
		t.Fatalf("in-flight child: fail=%d yield=%d err=%v", targets.failCalls, targets.yieldCalls, err)
	}
}

// From the write to the listed CNAME: the child commits after the write
// (about 1 s) and three healthy checks 1 s apart (InitialBackoff, N14 fix);
// the allocation sees it at its next poll. With the 2 s fast polls the
// address is listed within 10 s of the write; the old 5 s doubling polls
// (5, 10, 20 s) left it 35 s.
func TestCNAMEListedWithinTenSecondsOfTheWrite(t *testing.T) {
	const childCommittedAfter = 1*time.Second + 3*time.Second // write + 3 consecutive checks
	elapsed := time.Duration(0)
	for attempt := uint32(1); elapsed < childCommittedAfter; attempt++ {
		targets := &fakeCNAMEStore{}
		worker := &Worker{dependencies: WorkerDependencies{Targets: targets}}
		if err := worker.yield(context.Background(), jobstate.Claim{Job: jobstate.StoredJob{Attempt: attempt,
			MaxAttempts: maximumJobAttempts}}); err != nil {
			t.Fatal(err)
		}
		elapsed += targets.yieldDelay
	}
	if elapsed > 10*time.Second {
		t.Fatalf("CNAME listed %s after the write, want at most 10s", elapsed)
	}
}
