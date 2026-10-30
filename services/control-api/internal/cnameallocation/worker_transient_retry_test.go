package cnameallocation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsreconcile"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
)

func TestWorkerUnavailableApplyRetriesSameJobWithoutTerminalMutation(t *testing.T) {
	tenantID, siteID, jobID := uuid.New(), uuid.New(), uuid.New()
	target := Target{
		TenantID: tenantID, ScopeID: uuid.New(), SiteID: siteID, AllocationID: uuid.New(), JobID: jobID,
		ActorUserID: uuid.New(), ZoneID: uuid.New(), ZoneRevision: 4, AllocationRevision: 2,
		OwnerName: "edge.example.test", TTL: 300, Values: TargetValues{A: []string{"192.0.2.10"}},
		Digest: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
	}
	claims := &transientRetryClaims{claims: []jobstate.Claim{
		{Job: jobstate.StoredJob{ID: jobID, TenantID: tenantID, Kind: databaseJobKind, Attempt: 1},
			LeaseID: uuid.New(), WorkerID: "worker-transient", LeaseExpiresAt: time.Now().Add(time.Minute)},
		{Job: jobstate.StoredJob{ID: jobID, TenantID: tenantID, Kind: databaseJobKind, Attempt: 2},
			LeaseID: uuid.New(), WorkerID: "worker-transient", LeaseExpiresAt: time.Now().Add(time.Minute)},
		{Job: jobstate.StoredJob{ID: jobID, TenantID: tenantID, Kind: databaseJobKind, Attempt: 3},
			LeaseID: uuid.New(), WorkerID: "worker-transient", LeaseExpiresAt: time.Now().Add(time.Minute)},
	}}
	targets := &transientRetryTargets{target: target}
	reconcile := &transientRetryReconcile{
		applyErrors: []error{dnsreconcile.ErrUnavailable, dnsreconcile.ErrOperationInFlight, nil},
		task: dnsreconcile.Task{ID: uuid.New(), TenantID: tenantID, SiteID: siteID, Revision: 1,
			Result: dnscheck.ReconcileResult{Status: dnscheck.TaskApplying}},
	}
	worker, err := NewWorker(WorkerConfig{WorkerID: "worker-transient", LeaseDuration: time.Minute}, WorkerDependencies{
		Claims: claims, Targets: targets, Reconcile: reconcile,
	})
	if err != nil {
		t.Fatal(err)
	}

	for attempt := 1; attempt <= 2; attempt++ {
		didWork, transientErr := worker.RunOnce(t.Context(), tenantID)
		if !didWork || !errors.Is(transientErr, ErrUnavailable) {
			t.Errorf("transient RunOnce attempt %d = (%v,%v), want work with retryable unavailable", attempt, didWork, transientErr)
		}
		if targets.attachCalls != 0 || targets.completeCalls != 0 || targets.failCalls != 0 {
			t.Errorf("transient attempt %d mutations attach/complete/fail = %d/%d/%d, want 0/0/0",
				attempt, targets.attachCalls, targets.completeCalls, targets.failCalls)
		}
	}

	didWork, err := worker.RunOnce(t.Context(), tenantID)
	if err != nil || !didWork {
		t.Fatalf("second RunOnce() = (%v,%v)", didWork, err)
	}
	if len(targets.loadedClaims) != 3 || targets.loadedClaims[0].Job.ID != jobID ||
		targets.loadedClaims[1].Job.ID != jobID || targets.loadedClaims[0].Job.Attempt != 1 ||
		targets.loadedClaims[2].Job.ID != jobID || targets.loadedClaims[1].Job.Attempt != 2 ||
		targets.loadedClaims[2].Job.Attempt != 3 {
		t.Fatalf("retry claims = %#v", targets.loadedClaims)
	}
	wantKey := "cname-" + target.Digest
	if len(reconcile.applyRequests) != 3 || reconcile.applyRequests[0].IdempotencyKey != wantKey ||
		reconcile.applyRequests[1].IdempotencyKey != wantKey || reconcile.applyRequests[2].IdempotencyKey != wantKey {
		t.Fatalf("retry apply keys = %#v, want %q", reconcile.applyRequests, wantKey)
	}
	if targets.attachCalls != 1 || targets.completeCalls != 0 || targets.failCalls != 0 {
		t.Fatalf("final mutations attach/complete/fail = %d/%d/%d, want 1/0/0",
			targets.attachCalls, targets.completeCalls, targets.failCalls)
	}
}

type transientRetryClaims struct {
	claims []jobstate.Claim
}

func (claims *transientRetryClaims) Claim(context.Context, jobstate.ClaimInput) ([]jobstate.Claim, error) {
	if len(claims.claims) == 0 {
		return nil, nil
	}
	claim := claims.claims[0]
	claims.claims = claims.claims[1:]
	return []jobstate.Claim{claim}, nil
}

type transientRetryTargets struct {
	target                                Target
	loadedClaims                          []jobstate.Claim
	attachCalls, completeCalls, failCalls int
}

func (targets *transientRetryTargets) LoadTarget(_ context.Context, claim jobstate.Claim) (Target, error) {
	targets.loadedClaims = append(targets.loadedClaims, claim)
	return targets.target, nil
}

func (targets *transientRetryTargets) AttachChild(context.Context, jobstate.Claim, Target, dnsreconcile.Task) error {
	targets.attachCalls++
	return nil
}

func (targets *transientRetryTargets) Yield(context.Context, jobstate.Claim, time.Duration) error {
	return nil
}

func (targets *transientRetryTargets) Complete(context.Context, ResultRequest) (Allocation, error) {
	targets.completeCalls++
	return Allocation{}, nil
}

func (targets *transientRetryTargets) Fail(context.Context, ResultRequest) (Allocation, error) {
	targets.failCalls++
	return Allocation{}, nil
}

type transientRetryReconcile struct {
	applyErrors   []error
	applyRequests []dnsreconcile.ApplyRequest
	task          dnsreconcile.Task
}

func (reconcile *transientRetryReconcile) Apply(_ context.Context, request dnsreconcile.ApplyRequest) (dnsreconcile.Task, error) {
	reconcile.applyRequests = append(reconcile.applyRequests, request)
	err := reconcile.applyErrors[0]
	reconcile.applyErrors = reconcile.applyErrors[1:]
	if err != nil {
		return dnsreconcile.Task{}, err
	}
	return reconcile.task, nil
}

func (reconcile *transientRetryReconcile) Get(context.Context, uuid.UUID, uuid.UUID) (dnsreconcile.Task, error) {
	return dnsreconcile.Task{}, errors.New("unexpected Get")
}

func (reconcile *transientRetryReconcile) Commit(context.Context, dnsreconcile.CommitRequest) (dnsreconcile.Task, error) {
	return dnsreconcile.Task{}, errors.New("unexpected Commit")
}
