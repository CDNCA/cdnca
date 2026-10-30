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

// FX40: once the child reconcile task is attached (or still in flight) the
// allocation job gives its lease back with a short back-off instead of holding
// it to expiry (16 minutes in production) before it can commit.
func TestWorkerYieldsLeaseWhileChildTaskIsInFlight(t *testing.T) {
	for _, test := range []struct {
		name      string
		child     uuid.UUID
		status    dnscheck.TaskStatus
		attempt   uint32
		wantYield time.Duration
	}{
		{"attached", uuid.Nil, dnscheck.TaskApplying, 1, 2 * time.Second},
		{"in_flight", uuid.New(), dnscheck.TaskPropagating, 3, 2 * time.Second},
		{"fast_polls_end", uuid.New(), dnscheck.TaskPropagating, 7, 8 * time.Second},
		{"capped", uuid.New(), dnscheck.TaskApplying, 14, 5 * time.Minute},
		// Near max_attempts the lease is kept so the last attempts are not
		// spent on yields (the job then retries on lease expiry as before).
		{"last_attempts", uuid.New(), dnscheck.TaskApplying, maximumJobAttempts - 1, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Date(2026, 10, 17, 10, 0, 0, 0, time.UTC)
			tenantID, siteID := uuid.New(), uuid.New()
			target := Target{TenantID: tenantID, ScopeID: uuid.New(), SiteID: siteID, AllocationID: uuid.New(),
				JobID: uuid.New(), ZoneID: uuid.New(), ZoneRevision: 2, OwnerName: "edge.example.test", ActorUserID: uuid.New(),
				RequestID: "request-yield", AllocationRevision: 1, TTL: 300, Values: TargetValues{A: []string{"192.0.2.10"}},
				Digest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", ChildTaskID: test.child, ChildTaskRevision: 1}
			claims := &fakeCNAMEClaims{claim: jobstate.Claim{Job: jobstate.StoredJob{ID: target.JobID, TenantID: tenantID,
				Kind: databaseJobKind, Attempt: test.attempt, MaxAttempts: maximumJobAttempts}, LeaseID: uuid.New(),
				WorkerID: "worker-yield", LeaseExpiresAt: now.Add(16 * time.Minute)}}
			targets := &fakeCNAMEStore{target: target}
			reconcile := &fakeCNAMEReconcile{task: dnsreconcile.Task{ID: uuid.New(), TenantID: tenantID, SiteID: siteID,
				Revision: 1, Result: dnscheck.ReconcileResult{Status: test.status}}}
			worker, err := NewWorker(WorkerConfig{WorkerID: "worker-yield", LeaseDuration: 16 * time.Minute,
				Now: func() time.Time { return now }}, WorkerDependencies{Claims: claims, Targets: targets, Reconcile: reconcile})
			if err != nil {
				t.Fatal(err)
			}
			if didWork, err := worker.RunOnce(context.Background(), tenantID); err != nil || !didWork {
				t.Fatalf("RunOnce() = (%v,%v)", didWork, err)
			}
			if test.wantYield == 0 {
				if targets.yieldCalls != 0 {
					t.Fatalf("yielded %d times near max_attempts", targets.yieldCalls)
				}
				return
			}
			if targets.yieldCalls != 1 || targets.yieldDelay != test.wantYield || targets.yieldClaim.LeaseID != claims.claim.LeaseID {
				t.Fatalf("yield = %d calls, delay %v, claim %+v", targets.yieldCalls, targets.yieldDelay, targets.yieldClaim)
			}
		})
	}
}

// A settled child is completed in the same pass; nothing is yielded.
func TestWorkerDoesNotYieldSettledChild(t *testing.T) {
	now := time.Date(2026, 10, 17, 10, 0, 0, 0, time.UTC)
	tenantID, siteID := uuid.New(), uuid.New()
	target := Target{TenantID: tenantID, ScopeID: uuid.New(), SiteID: siteID, AllocationID: uuid.New(), JobID: uuid.New(),
		ZoneID: uuid.New(), ZoneRevision: 2, OwnerName: "edge.example.test", ActorUserID: uuid.New(), RequestID: "r",
		AllocationRevision: 1, TTL: 300, Values: TargetValues{A: []string{"192.0.2.10"}}, ChildTaskID: uuid.New(),
		Digest: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}
	claims := &fakeCNAMEClaims{claim: jobstate.Claim{Job: jobstate.StoredJob{ID: target.JobID, TenantID: tenantID,
		Kind: databaseJobKind, Attempt: 2, MaxAttempts: maximumJobAttempts}, LeaseID: uuid.New(), WorkerID: "w"}}
	targets := &fakeCNAMEStore{target: target}
	reconcile := &fakeCNAMEReconcile{task: dnsreconcile.Task{ID: target.ChildTaskID, TenantID: tenantID, SiteID: siteID,
		Revision: 3, Result: dnscheck.ReconcileResult{Status: dnscheck.TaskCommitted}}}
	worker, err := NewWorker(WorkerConfig{WorkerID: "w", LeaseDuration: time.Minute, Now: func() time.Time { return now }},
		WorkerDependencies{Claims: claims, Targets: targets, Reconcile: reconcile})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := worker.RunOnce(context.Background(), tenantID); err != nil || targets.completeCalls != 1 || targets.yieldCalls != 0 {
		t.Fatalf("complete=%d yield=%d err=%v", targets.completeCalls, targets.yieldCalls, err)
	}
}
