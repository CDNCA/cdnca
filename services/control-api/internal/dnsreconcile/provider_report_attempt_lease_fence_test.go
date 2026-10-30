package dnsreconcile

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
)

func TestProviderReportAttemptLeaseFenceContract(t *testing.T) {
	model, err := os.ReadFile("model.go")
	if err != nil {
		t.Fatal(err)
	}
	store, err := os.ReadFile("postgres_store.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{
		"WorkloadID",
		"JobAttempt",
		"LeaseID",
	} {
		if !strings.Contains(string(model), marker) {
			t.Fatalf("provider report request missing %q", marker)
		}
	}
	for _, marker := range []string{
		"liveAttempt, liveLeaseID, liveWorkerID, err := loadLiveApplyClaim(",
		"request.WorkloadID != liveWorkerID",
		"request.JobAttempt != uint32(liveAttempt)",
		"request.LeaseID != liveLeaseID",
		"jobstate.VoluntaryYieldTx(ctx, tx, jobstate.VoluntaryYieldInput{",
		"NotBefore: now.Add(retryDelay)",
		"\"workload\", int(request.JobAttempt), request.LeaseID, request.WorkloadID,",
	} {
		if !strings.Contains(string(store), marker) {
			t.Fatalf("provider report store missing fence marker %q", marker)
		}
	}
}

func TestConsumeRetryAfterHintsClearsTransientFailureAcrossPhases(t *testing.T) {
	result := dnscheck.ReconcileResult{
		Operations: []dnscheck.OperationResult{{
			Status: dnscheck.OperationTransientFailed, ErrorClass: dnscheck.ProviderErrorTransient,
			RetryAfter: 37 * time.Second,
		}},
		DeferredDeletes: []dnscheck.OperationResult{{
			Status: dnscheck.OperationTransientFailed, ErrorClass: dnscheck.ProviderErrorTimeout,
			RetryAfter: 41 * time.Second,
		}},
	}
	cleared, consumed := consumeRetryAfterHints(result)
	if !consumed || cleared.Operations[0].RetryAfter != 0 || cleared.DeferredDeletes[0].RetryAfter != 0 {
		t.Fatalf("consumeRetryAfterHints() = (%#v,%v), want both hints cleared", cleared, consumed)
	}
	if result.Operations[0].RetryAfter == 0 || result.DeferredDeletes[0].RetryAfter == 0 {
		t.Fatal("consumeRetryAfterHints mutated its input")
	}
}
