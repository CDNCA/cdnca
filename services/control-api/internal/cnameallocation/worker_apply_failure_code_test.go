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

// fix-regen2: a refused Apply failed the allocation as dns_reconcile_unavailable
// whatever the cause, so "the operator is not the tenant's" read as
// "DNS 服务商调用失败" on the site list.
func TestWorkerFailsRefusedApplyWithItsCause(t *testing.T) {
	for _, test := range []struct {
		err  error
		want string
	}{
		{dnsreconcile.ErrPermissionDenied, "dns_permission_denied"},
		{errors.Join(dnsreconcile.ErrPermissionDenied, errors.New("gate")), "dns_permission_denied"},
		{dnsreconcile.ErrEntitlementDenied, "dns_reconcile_entitlement_denied"},
		{dnsreconcile.ErrNotFound, "dns_reconcile_not_found"},
		{dnsreconcile.ErrInvalidInput, "dns_reconcile_invalid_request"},
		{dnsreconcile.ErrIdempotencyConflict, "dns_reconcile_idempotency_conflict"},
		{dnsreconcile.ErrRevisionConflict, "dns_reconcile_revision_conflict"},
		{errors.New("something else"), "dns_reconcile_unavailable"},
	} {
		tenantID, jobID := uuid.New(), uuid.New()
		target := Target{
			TenantID: tenantID, ScopeID: uuid.New(), SiteID: uuid.New(), AllocationID: uuid.New(), JobID: jobID,
			ZoneID: uuid.New(), ZoneRevision: 5, OwnerName: "edge.example.test", ActorUserID: uuid.New(),
			RequestID: "request-refused", AllocationRevision: 1, TTL: 300,
			Values: TargetValues{A: []string{"192.0.2.10"}},
			Digest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		}
		claims := &fakeCNAMEClaims{claim: jobstate.Claim{Job: jobstate.StoredJob{
			ID: jobID, TenantID: tenantID, Kind: databaseJobKind, Attempt: 1,
		}, LeaseID: uuid.New(), WorkerID: "worker-refused", LeaseExpiresAt: time.Now().Add(time.Minute)}}
		targets := &fakeCNAMEStore{target: target}
		worker, err := NewWorker(WorkerConfig{WorkerID: "worker-refused", LeaseDuration: time.Minute}, WorkerDependencies{
			Claims: claims, Targets: targets, Reconcile: &failingApplyReconcile{err: test.err},
		})
		if err != nil {
			t.Fatal(err)
		}
		if didWork, err := worker.RunOnce(context.Background(), tenantID); err != nil || !didWork {
			t.Fatalf("%v: RunOnce() = (%v,%v)", test.err, didWork, err)
		}
		if targets.failCalls != 1 || targets.completed.FailureCode != test.want {
			t.Fatalf("%v: fail calls %d code %q, want %q", test.err, targets.failCalls, targets.completed.FailureCode, test.want)
		}
	}
}
