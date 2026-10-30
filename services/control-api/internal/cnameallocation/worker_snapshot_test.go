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

type fakeProviderSnapshot struct {
	records []dnscheck.ProviderRecord
	err     error
	calls   []string
}

func (fake *fakeProviderSnapshot) OwnerRecords(_ context.Context, tenantID, siteID, zoneID uuid.UUID,
	owner string) ([]dnscheck.ProviderRecord, error) {
	fake.calls = append(fake.calls, owner)
	return fake.records, fake.err
}

func plannedActions(t *testing.T, request dnsreconcile.ApplyRequest) map[string]string {
	t.Helper()
	prepared, err := dnscheck.PrepareReconcile(dnscheck.ReconcileRequest{IdempotencyKey: request.IdempotencyKey,
		Check: request.Check}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	actions := map[string]string{}
	for _, operation := range prepared.Result.Plan.Operations {
		actions[operation.Value] = string(operation.Action)
	}
	return actions
}

// Retargeting to fewer addresses (a node paused, a standby IP taken offline)
// must delete the value that is no longer published: the reconcile request
// carries the provider's current records of the owner.
func TestRetargetDeletesStaleProviderValues(t *testing.T) {
	retarget := retargetFixture(uuid.Nil)
	retarget.Values = TargetValues{A: []string{"192.0.2.2"}}
	snapshot := &fakeProviderSnapshot{records: []dnscheck.ProviderRecord{
		{RecordID: "rec-1", Name: retarget.OwnerName + ".", Type: dnscheck.RecordA, Value: "192.0.2.1", TTL: 300},
		{RecordID: "rec-2", Name: retarget.OwnerName + ".", Type: dnscheck.RecordA, Value: "192.0.2.2", TTL: 300},
	}}
	store := &fakeRetargets{open: []Retarget{retarget}}
	reconcile := &fakeCNAMEReconcile{task: dnsreconcile.Task{ID: uuid.New(), Revision: 1,
		Result: dnscheck.ReconcileResult{Status: dnscheck.TaskApplying}}}
	worker, err := NewWorker(WorkerConfig{WorkerID: "w", LeaseDuration: time.Minute},
		WorkerDependencies{Claims: &fakeCNAMEClaims{}, Targets: &fakeCNAMEStore{}, Reconcile: reconcile, Retargets: store,
			Snapshots: snapshot})
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.RunRetargets(t.Context()); err != nil {
		t.Fatal(err)
	}
	if reconcile.applyCalls != 1 || len(snapshot.calls) != 1 {
		t.Fatalf("apply=%d snapshot calls=%v", reconcile.applyCalls, snapshot.calls)
	}
	if actions := plannedActions(t, reconcile.applied); actions["192.0.2.1"] != "delete" || actions["192.0.2.2"] != "" {
		t.Fatalf("planned actions = %v, want only a delete of the stale value", actions)
	}
	// A different snapshot is a different request: it must not reuse the key.
	first := reconcile.applied.IdempotencyKey
	worker2, _ := NewWorker(WorkerConfig{WorkerID: "w", LeaseDuration: time.Minute},
		WorkerDependencies{Claims: &fakeCNAMEClaims{}, Targets: &fakeCNAMEStore{}, Reconcile: reconcile,
			Retargets: &fakeRetargets{open: []Retarget{retarget}}, Snapshots: &fakeProviderSnapshot{}})
	if err := worker2.RunRetargets(t.Context()); err != nil {
		t.Fatal(err)
	}
	if reconcile.applied.IdempotencyKey == first {
		t.Fatal("idempotency key ignores the provider snapshot")
	}
}

// When the provider cannot be listed the retarget waits (transient) rather
// than publishing without knowing what has to be removed.
func TestRetargetWaitsWhenProviderSnapshotIsUnavailable(t *testing.T) {
	retarget := retargetFixture(uuid.Nil)
	store := &fakeRetargets{open: []Retarget{retarget}}
	reconcile := &fakeCNAMEReconcile{}
	worker, _ := NewWorker(WorkerConfig{WorkerID: "w", LeaseDuration: time.Minute},
		WorkerDependencies{Claims: &fakeCNAMEClaims{}, Targets: &fakeCNAMEStore{}, Reconcile: reconcile, Retargets: store,
			Snapshots: &fakeProviderSnapshot{err: errors.New("provider down")}})
	if err := worker.RunRetargets(t.Context()); err != nil {
		t.Fatal(err)
	}
	if reconcile.applyCalls != 0 || store.settled[retarget.ID] != "" {
		t.Fatalf("apply=%d settled=%v", reconcile.applyCalls, store.settled)
	}
}

// The first publication of a target also replaces whatever the owner holds.
func TestTargetPublicationIncludesProviderSnapshot(t *testing.T) {
	tenantID, siteID := uuid.New(), uuid.New()
	target := Target{TenantID: tenantID, ScopeID: uuid.New(), SiteID: siteID, AllocationID: uuid.New(), JobID: uuid.New(),
		ZoneID: uuid.New(), ZoneRevision: 2, OwnerName: "edge.example.test", ActorUserID: uuid.New(), RequestID: "r",
		AllocationRevision: 1, TTL: 300, Values: TargetValues{A: []string{"192.0.2.10"}},
		Digest: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}
	claims := &fakeCNAMEClaims{claim: claimFor(target)}
	reconcile := &fakeCNAMEReconcile{task: dnsreconcile.Task{ID: uuid.New(), TenantID: tenantID, SiteID: siteID, Revision: 1,
		Result: dnscheck.ReconcileResult{Status: dnscheck.TaskApplying}}}
	snapshot := &fakeProviderSnapshot{records: []dnscheck.ProviderRecord{
		{RecordID: "old", Name: "edge.example.test.", Type: dnscheck.RecordA, Value: "198.51.100.9", TTL: 300}}}
	worker, _ := NewWorker(WorkerConfig{WorkerID: "w", LeaseDuration: time.Minute},
		WorkerDependencies{Claims: claims, Targets: &fakeCNAMEStore{target: target}, Reconcile: reconcile, Snapshots: snapshot})
	if _, err := worker.RunOnce(t.Context(), tenantID); err != nil {
		t.Fatal(err)
	}
	// The stale record is rewritten to the published value (update keyed by
	// its new value; the old one is its PreviousValue).
	prepared, err := dnscheck.PrepareReconcile(dnscheck.ReconcileRequest{IdempotencyKey: reconcile.applied.IdempotencyKey,
		Check: reconcile.applied.Check}, time.Now)
	if err != nil || len(prepared.Result.Plan.Operations) != 1 {
		t.Fatalf("plan = %+v %v", prepared.Result.Plan.Operations, err)
	}
	if operation := prepared.Result.Plan.Operations[0]; operation.Action != dnscheck.ProviderUpdate ||
		operation.RecordID != "old" || operation.PreviousValue != "198.51.100.9" || operation.Value != "192.0.2.10" {
		t.Fatalf("operation = %+v, want the old value replaced", operation)
	}
}

func claimFor(target Target) jobstate.Claim {
	return jobstate.Claim{Job: jobstate.StoredJob{ID: target.JobID, TenantID: target.TenantID, Kind: databaseJobKind,
		Attempt: 1, MaxAttempts: maximumJobAttempts}, LeaseID: uuid.New(), WorkerID: "w", LeaseExpiresAt: time.Now().Add(time.Minute)}
}

// The default line's reconcile leaves records on other lines alone: the
// aggregated edge scheduler writes the site CNAME per line there (ADR 0008
// §6.1), and a default-line plan must not delete them as unexpected.
func TestRetargetIgnoresOtherLineRecords(t *testing.T) {
	retarget := retargetFixture(uuid.Nil)
	retarget.Values = TargetValues{A: []string{"192.0.2.2"}}
	snapshot := &fakeProviderSnapshot{records: []dnscheck.ProviderRecord{
		{RecordID: "rec-1", Name: retarget.OwnerName + ".", Type: dnscheck.RecordA, Value: "192.0.2.2", TTL: 300, Line: "默认"},
		{RecordID: "rec-2", Name: retarget.OwnerName + ".", Type: dnscheck.RecordCNAME, Value: "cf.example.net.", TTL: 60, Line: "境外"},
		{RecordID: "rec-3", Name: retarget.OwnerName + ".", Type: dnscheck.RecordA, Value: "192.0.2.9", TTL: 300, Line: "aliyun:cn_telecom_anhui"},
	}}
	reconcile := &fakeCNAMEReconcile{task: dnsreconcile.Task{ID: uuid.New(), Revision: 1,
		Result: dnscheck.ReconcileResult{Status: dnscheck.TaskApplying}}}
	worker, err := NewWorker(WorkerConfig{WorkerID: "w", LeaseDuration: time.Minute},
		WorkerDependencies{Claims: &fakeCNAMEClaims{}, Targets: &fakeCNAMEStore{}, Reconcile: reconcile,
			Retargets: &fakeRetargets{open: []Retarget{retarget}}, Snapshots: snapshot})
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.RunRetargets(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, record := range reconcile.applied.Check.Provider.Records {
		if record.RecordID != "rec-1" {
			t.Fatalf("default-line request carries %+v", record)
		}
	}
	if actions := plannedActions(t, reconcile.applied); len(actions) != 0 {
		t.Fatalf("planned actions = %v, want none", actions)
	}
}
