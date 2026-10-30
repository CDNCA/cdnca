package securitycoordmetrics

import (
	"sync"
	"testing"
)

func TestRegistryKeepsBoundedConcurrentSecurityCoordinationCounters(t *testing.T) {
	registry := NewRegistry()
	const workers = 32
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			registry.RecordCCObserve(CCObserve{Accepted: 2, Duplicates: 1, Rejected: 1, Queued: 1, Reason: ReasonCapacityRejected})
			registry.RecordCCCoordination(CCCoordination{Claimed: 2, Published: 1, Retryable: 1, ActivationActive: 1})
			registry.RecordCCRelease(CCRelease{Reason: ReasonFalsePositiveConfirmed})
			registry.RecordFirewallDispatch(FirewallDispatch{Claimed: 2, Published: 1, Duplicates: 1, Retryable: 1, Reason: ReasonPublishTimeout})
			registry.RecordFirewallACK(FirewallACK{Disposition: ACKRescued, Terminal: TerminalRolledBack, Recovery: true, GlobalOutcome: GlobalRolledBack})
		}()
	}
	group.Wait()

	snapshot := registry.Snapshot()
	if snapshot.CC.ObserveRuns != workers || snapshot.CC.Accepted != workers*2 ||
		snapshot.CC.Duplicates != workers || snapshot.CC.CapacityRejected != workers ||
		snapshot.CC.CoordinationPublished != workers || snapshot.CC.FalsePositiveReleases != workers {
		t.Fatalf("CC snapshot = %+v", snapshot.CC)
	}
	if snapshot.Firewall.DispatchRuns != workers || snapshot.Firewall.Published != workers ||
		snapshot.Firewall.PubACKDuplicates != workers || snapshot.Firewall.PublishTimeout != workers ||
		snapshot.Firewall.ACKRescued != workers || snapshot.Firewall.RolledBack != workers ||
		snapshot.Firewall.Recoveries != workers || snapshot.Firewall.GlobalRolledBack != workers {
		t.Fatalf("firewall snapshot = %+v", snapshot.Firewall)
	}
}

func TestCapacityRejectionIsNotReportedAsSuccessfulEviction(t *testing.T) {
	registry := NewRegistry()
	registry.RecordCCObserve(CCObserve{Accepted: 1, Rejected: 1, Reason: ReasonCapacityRejected})
	snapshot := registry.Snapshot()
	if snapshot.CC.CapacityRejected != 1 || snapshot.CC.Queued != 0 || snapshot.CC.CoordinationPublished != 0 {
		t.Fatalf("capacity snapshot = %+v", snapshot.CC)
	}
}
