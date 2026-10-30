package dnscheck

import (
	"testing"
	"time"
)

func TestMergeProviderReportClearsRetryAfterOnSuccessfulApply(t *testing.T) {
	current := OperationResult{
		ClientRequestID: "apply-request",
		Operation:       ProviderOperation{Action: ProviderCreate},
		Status:          OperationRunning,
		RetryAfter:      45 * time.Second,
		ReportSequence:  3,
	}
	report := ProviderReport{
		ClientRequestID: "apply-request",
		Status:          OperationSucceeded,
		Sequence:        4,
	}

	got, changed := MergeProviderReport(current, report)
	if !changed {
		t.Fatal("MergeProviderReport() changed = false, want true")
	}
	if got.Status != OperationSucceeded || got.RetryAfter != 0 {
		t.Fatalf("MergeProviderReport() = %#v, want successful operation with cleared retry hint", got)
	}
}

func TestMergeProviderReportClearsRetryAfterOnSuccessfulDeferredDelete(t *testing.T) {
	current := OperationResult{
		ClientRequestID: "delete-request",
		Operation:       ProviderOperation{Action: ProviderDelete},
		Status:          OperationRunning,
		RetryAfter:      time.Minute,
		ReportSequence:  7,
	}
	report := ProviderReport{
		ClientRequestID: "delete-request",
		Status:          OperationSucceeded,
		Sequence:        8,
	}

	got, changed := MergeProviderReport(current, report)
	if !changed {
		t.Fatal("MergeProviderReport() changed = false, want true")
	}
	if got.Status != OperationSucceeded || got.RetryAfter != 0 {
		t.Fatalf("MergeProviderReport() = %#v, want successful deferred delete with cleared retry hint", got)
	}
}

func TestMergeProviderReportPreservesRetryAfterForNonSuccess(t *testing.T) {
	for _, status := range []OperationStatus{OperationRunning, OperationTransientFailed} {
		t.Run(string(status), func(t *testing.T) {
			current := OperationResult{
				ClientRequestID: "provider-request",
				Status:          OperationRunning,
				RetryAfter:      90 * time.Second,
				ReportSequence:  10,
			}
			report := ProviderReport{
				ClientRequestID: "provider-request",
				Status:          status,
				Sequence:        11,
			}

			got, changed := MergeProviderReport(current, report)
			if !changed || got.RetryAfter != current.RetryAfter {
				t.Fatalf("MergeProviderReport() = (%#v, %t), want retained retry hint", got, changed)
			}
		})
	}
}

func TestMergeProviderReportRejectedPreservesRetryAfter(t *testing.T) {
	current := OperationResult{
		ClientRequestID: "provider-request",
		Status:          OperationRunning,
		RetryAfter:      2 * time.Minute,
		ReportSequence:  12,
	}

	for _, report := range []ProviderReport{
		{ClientRequestID: "provider-request", Status: OperationRunning, Sequence: 12},
		{ClientRequestID: "provider-request", Status: OperationRunning, Sequence: 11},
		{ClientRequestID: "other-request", Status: OperationSucceeded, Sequence: 13},
	} {
		got, changed := MergeProviderReport(current, report)
		if changed || got != current {
			t.Fatalf("MergeProviderReport(%#v) = (%#v, %t), want unchanged current", report, got, changed)
		}
	}
}
