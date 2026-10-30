package main

import (
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/cccoord"
	"github.com/cdnca/cdnca/services/control-api/internal/securitycoordmetrics"
)

func TestCCCoordinationRuntimeExportsObserveAndCoordinationSnapshots(t *testing.T) {
	runtime := &ccCoordinationRuntime{metrics: securitycoordmetrics.NewRegistry()}
	runtime.recordObserve(cccoord.ObserveResult{Accepted: 3, Duplicates: 1, Rejected: 1, Queued: 2}, cccoord.ErrCapacity)
	runtime.recordCoordination(cccoord.RunResult{Claimed: 2, Published: 1, Retryable: 1, ActivationActive: 1}, nil)
	snapshot := runtime.MetricsSnapshot().CC
	if snapshot.ObserveRuns != 1 || snapshot.Accepted != 3 || snapshot.Duplicates != 1 ||
		snapshot.CapacityRejected != 1 || snapshot.CoordinationRuns != 1 ||
		snapshot.CoordinationPublished != 1 || snapshot.CoordinationRetryable != 1 || snapshot.ActivationActive != 1 {
		t.Fatalf("snapshot = %+v", snapshot)
	}
}
