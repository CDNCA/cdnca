package cnameallocation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsreconcile"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
)

type permanentSnapshotError struct{ code string }

func (err permanentSnapshotError) Error() string       { return "snapshot: " + err.code }
func (err permanentSnapshotError) FailureCode() string { return err.code }

// N1: the provider said the zone is not hosted (DNSPod code 13). The job
// must fail with that code instead of returning ErrUnavailable silently and
// waiting for the lease to expire again and again. A transient snapshot
// error still keeps the job for a later attempt.
func TestWorkerFailsJobWithProviderSnapshotCode(t *testing.T) {
	for _, tc := range []struct {
		name     string
		err      error
		wantFail bool
	}{
		{"zone not hosted", permanentSnapshotError{code: "dns_zone_not_hosted"}, true},
		{"transient", errors.New("provider timeout"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tenantID, jobID := uuid.New(), uuid.New()
			target := Target{TenantID: tenantID, ScopeID: uuid.New(), SiteID: uuid.New(), AllocationID: uuid.New(),
				JobID: jobID, ZoneID: uuid.New(), ZoneRevision: 1, OwnerName: "5ksukk1m.cdn.example.test",
				RequestID: "request-n1", AllocationRevision: 1, TTL: 300, ActorUserID: uuid.New(),
				Values: TargetValues{A: []string{"192.0.2.10"}}, Digest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}
			claims := &fakeCNAMEClaims{claim: jobstate.Claim{Job: jobstate.StoredJob{ID: jobID, TenantID: tenantID,
				Kind: databaseJobKind, Attempt: 1}, LeaseID: uuid.New(), WorkerID: "w"}}
			targets := &fakeCNAMEStore{target: target}
			reconcile := &fakeCNAMEReconcile{task: dnsreconcile.Task{ID: uuid.New()}}
			worker, err := NewWorker(WorkerConfig{WorkerID: "w", LeaseDuration: time.Minute}, WorkerDependencies{
				Claims: claims, Targets: targets, Reconcile: reconcile, Snapshots: &fakeProviderSnapshot{err: tc.err}})
			if err != nil {
				t.Fatal(err)
			}
			_, runErr := worker.RunOnce(context.Background(), tenantID)
			if reconcile.applyCalls != 0 {
				t.Fatalf("apply calls = %d, want none without a snapshot", reconcile.applyCalls)
			}
			if tc.wantFail {
				if runErr != nil || targets.failCalls != 1 || targets.completed.FailureCode != "dns_zone_not_hosted" {
					t.Fatalf("RunOnce err=%v fail calls=%d code=%q, want job failed with dns_zone_not_hosted",
						runErr, targets.failCalls, targets.completed.FailureCode)
				}
				return
			}
			if !errors.Is(runErr, ErrUnavailable) || targets.failCalls != 0 {
				t.Fatalf("RunOnce err=%v fail calls=%d, want ErrUnavailable and no failure", runErr, targets.failCalls)
			}
		})
	}
}
