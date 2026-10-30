package dnscheck

import (
	"testing"
	"time"
)

func TestResumeApplyReplaysAsyncTransientFailureWithoutCompensation(t *testing.T) {
	now := time.Date(2026, 8, 7, 15, 0, 0, 0, time.UTC)
	for _, taskStatus := range []TaskStatus{TaskApplying, TaskPropagating} {
		t.Run(string(taskStatus), func(t *testing.T) {
			checker, request := newHealthyReconcileFixture(t, now)
			provider := &fakeProviderAdapter{revision: request.Provider.Revision}
			reconciler := newTestReconciler(t, checker, provider, now, func(config *ReconcilerConfig) {
				config.PollAttempts = 1
				config.RequiredConsecutive = 1
			})
			prepared, err := reconciler.PrepareApply(ReconcileRequest{
				IdempotencyKey: "async-transient-" + string(taskStatus), Check: request,
			})
			if err != nil {
				t.Fatal(err)
			}
			current := prepared.Result
			current.Status = taskStatus
			current.ErrorClass = ProviderErrorTransient
			current.ErrorCode = "provider_rate_limited"
			current.Operations[0].Status = OperationTransientFailed
			current.Operations[0].ErrorClass = ProviderErrorTransient
			current.Operations[0].ErrorCode = "provider_rate_limited"
			current.Operations[0].RetryAfter = 0 // The durable scheduler already consumed the hint.
			current.Operations[0].ReportSequence++
			current.CompensationPlan = []ProviderOperation{{Action: ProviderDelete, RecordID: "must-not-run"}}
			requestID := current.Operations[0].ClientRequestID

			result, err := reconciler.ResumeApply(t.Context(), prepared, current, nil)
			if err != nil {
				t.Fatalf("ResumeApply() error = %v", err)
			}
			if result.Status != TaskReadyToCommit || result.ErrorClass != ProviderErrorNone || result.ErrorCode != "" ||
				result.Operations[0].Status != OperationSucceeded || len(result.CompensationPlan) != 0 {
				t.Fatalf("ResumeApply() = %#v, want successful recovery without compensation", result)
			}
			_, _, mutations := provider.snapshot()
			if len(mutations) != 1 || mutations[0].ClientRequestID != requestID {
				t.Fatalf("mutations = %#v, want one exact replay of %q", mutations, requestID)
			}
		})
	}
}
