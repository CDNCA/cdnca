package dnscheck

import (
	"testing"
	"time"
)

func TestProviderInvalidResponsePreservesValidatedRequestIdentity(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	checker, request := newHealthyReconcileFixture(t, now)

	for _, test := range []struct {
		name      string
		response  ProviderMutationResult
		wantID    string
		operation ProviderOperation
	}{
		{
			name: "stale revision",
			response: ProviderMutationResult{
				ProviderRequestID: "provider-stale-revision", RecordID: "record-created",
				Revision: request.Provider.Revision,
			},
			wantID:    "provider-stale-revision",
			operation: ProviderOperation{Action: ProviderCreate},
		},
		{
			name: "invalid created record identity",
			response: ProviderMutationResult{
				ProviderRequestID: "provider-invalid-record", RecordID: "record?invalid",
				Revision: request.Provider.Revision + 1,
			},
			wantID:    "provider-invalid-record",
			operation: ProviderOperation{Action: ProviderCreate},
		},
		{
			name: "invalid provider request identity remains absent",
			response: ProviderMutationResult{
				ProviderRequestID: "provider request invalid", RecordID: "record-created",
				Revision: request.Provider.Revision + 1,
			},
			operation: ProviderOperation{Action: ProviderCreate},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			provider := &fakeProviderAdapter{revision: request.Provider.Revision}
			provider.mutate = func(_ *fakeProviderAdapter, _ int, _ ProviderMutation) (ProviderMutationResult, error) {
				return test.response, nil
			}
			reconciler := newTestReconciler(t, checker, provider, now, nil)
			result := reconciler.executeProviderOperation(t.Context(), OperationResult{
				ClientRequestID: "control-request", Status: OperationRunning, ReportSequence: 4,
				Operation: test.operation,
			}, request, request.Provider.Revision)

			if result.Status != OperationPermanentFailed || result.ErrorClass != ProviderErrorPermanent ||
				result.ErrorCode != "invalid_provider_response" || result.ProviderRequestID != test.wantID ||
				result.ProviderRecordID != "" || result.ProviderRevision != 0 || result.ReportSequence != 5 {
				t.Fatalf("invalid provider response receipt = %#v", result)
			}
		})
	}
}
