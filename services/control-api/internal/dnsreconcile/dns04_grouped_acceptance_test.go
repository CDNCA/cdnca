//go:build integration

package dnsreconcile

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
)

func TestDNS04GroupedAcceptancePersistsPreparedTaskAndUnifiedJobAcrossRestart(t *testing.T) {
	pool := openDNSReconcileStoreDatabase(t)
	clock := &dnsReconcileStoreClock{value: dnsReconcileStoreNow}
	tenantID, siteID := seedDNSReconcileStoreSite(t, pool, "dns04_grouped_restart")
	request, prepared := dnsReconcileStoreRequest(t, pool, tenantID, siteID, "dns04-grouped", "192.0.2.10")
	store := newDNSReconcileStore(t, pool, clock)

	created, replayed, err := store.Create(t.Context(), request, prepared)
	if err != nil || replayed || created.ID == uuid.Nil {
		t.Fatalf("Create() = (%+v,%t,%v)", created, replayed, err)
	}
	restarted := newDNSReconcileStore(t, pool, clock)
	persisted, err := restarted.Get(t.Context(), tenantID, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.ID != created.ID || persisted.Job.ID != created.ID || persisted.Job.Kind != JobKind ||
		persisted.Job.State != jobstate.StateQueued || persisted.Prepared.Result.PayloadDigest != prepared.Result.PayloadDigest ||
		persisted.RequiredConsecutive != request.RequiredConsecutive {
		t.Fatalf("persisted task = %+v", persisted)
	}

	lease := claimDNSReconcileStore(t, restarted, tenantID, "dns04-grouped-worker", time.Minute)
	if lease.Task.ID != created.ID || lease.LeaseID == uuid.Nil || lease.Attempt != 1 {
		t.Fatalf("durable lease = %+v", lease)
	}
}
