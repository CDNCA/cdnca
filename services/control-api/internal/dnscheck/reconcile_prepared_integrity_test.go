package dnscheck

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestDurableResumeRejectsPreparedIdentityDriftBeforeIO(t *testing.T) {
	tests := []struct {
		name   string
		commit bool
		drift  func(*PreparedReconcile, *ReconcileResult)
	}{
		{
			name: "prepared request",
			drift: func(prepared *PreparedReconcile, _ *ReconcileResult) {
				prepared.Request.Name = "foreign.example.test."
			},
		},
		{
			name: "prepared plan",
			drift: func(prepared *PreparedReconcile, _ *ReconcileResult) {
				prepared.Result.Plan.Operations[0].Name = "foreign.example.test."
			},
		},
		{
			name: "current apply operation",
			drift: func(_ *PreparedReconcile, current *ReconcileResult) {
				current.Operations[0].Operation.Name = "foreign.example.test."
			},
		},
		{
			name:   "current deferred delete",
			commit: true,
			drift: func(_ *PreparedReconcile, current *ReconcileResult) {
				current.DeferredDeletes[0].Operation.RecordID = "foreign-record"
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
			checker, request := newHealthyReconcileFixture(t, now)
			providerRevision := request.Provider.Revision
			if test.commit {
				providerRevision++
			}
			provider := &fakeProviderAdapter{revision: providerRevision}
			reconciler := newTestReconciler(t, checker, provider, now, nil)
			prepared, err := reconciler.PrepareApply(ReconcileRequest{
				IdempotencyKey: "prepared-identity-drift", Check: request,
			})
			if err != nil {
				t.Fatal(err)
			}
			current := cloneReconcileResult(prepared.Result)
			if test.commit {
				current.Status = TaskReadyToCommit
				current.ProviderRevision = providerRevision
				current.Operations[0].Status = OperationSucceeded
				current.Operations[0].Attempts = 1
				current.Operations[0].ProviderRequestID = "provider-apply-request"
				current.Operations[0].ProviderRecordID = "provider-created-record"
				current.Operations[0].ProviderRevision = providerRevision
			}
			test.drift(&prepared, &current)

			checkpointCalls := 0
			checkpoint := func(context.Context, ReconcileResult) error {
				checkpointCalls++
				return nil
			}
			var result ReconcileResult
			if test.commit {
				result, err = reconciler.ResumeCommit(t.Context(), prepared, current, checkpoint)
			} else {
				result, err = reconciler.ResumeApply(t.Context(), prepared, current, checkpoint)
			}
			_, revisionCalls, mutations := provider.snapshot()
			if !errors.Is(err, ErrInvalidInput) || !reflect.DeepEqual(result, ReconcileResult{}) ||
				checkpointCalls != 0 || revisionCalls != 0 || len(mutations) != 0 {
				t.Fatalf("resume = (%#v,%v); checkpoints=%d revisionCalls=%d mutations=%#v",
					result, err, checkpointCalls, revisionCalls, mutations)
			}
		})
	}
}
