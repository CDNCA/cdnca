package dnscheck

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestDurableCommitDoesNotRerunPersistedTerminalDelete(t *testing.T) {
	tests := []struct {
		name       string
		status     OperationStatus
		errorClass ProviderErrorClass
		errorCode  string
	}{
		{
			name: "permanent failure", status: OperationPermanentFailed,
			errorClass: ProviderErrorPermanent, errorCode: "record_rejected",
		},
		{
			name: "revision conflict", status: OperationRevisionConflict,
			errorClass: ProviderErrorRevisionConflict, errorCode: "revision_conflict",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			now := time.Date(2026, 8, 7, 14, 0, 0, 0, time.UTC)
			checker, request := newHealthyReconcileFixture(t, now)
			providerRevision := request.Provider.Revision + 1
			provider := &fakeProviderAdapter{revision: providerRevision}
			reconciler := newTestReconciler(t, checker, provider, now, nil)
			prepared, err := reconciler.PrepareApply(ReconcileRequest{
				IdempotencyKey: "terminal-commit-resume", Check: request,
			})
			if err != nil {
				t.Fatal(err)
			}
			current := cloneReconcileResult(prepared.Result)
			current.Status = TaskCommitFailed
			current.ProviderRevision = providerRevision
			current.Operations[0].Status = OperationSucceeded
			current.Operations[0].Attempts = 1
			current.Operations[0].ProviderRequestID = "provider-apply-request"
			current.Operations[0].ProviderRecordID = "provider-created-record"
			current.Operations[0].ProviderRevision = providerRevision
			current.DeferredDeletes[0].Status = test.status
			current.DeferredDeletes[0].Attempts = 3
			current.DeferredDeletes[0].ClientRequestID = operationRequestID(
				current.TenantID, prepared.IdempotencyKey, current.PayloadDigest,
				"commit", current.DeferredDeletes[0].SourceSequence,
			)
			current.DeferredDeletes[0].ProviderRequestID = "provider-delete-failure"
			current.DeferredDeletes[0].ErrorClass = test.errorClass
			current.DeferredDeletes[0].ErrorCode = test.errorCode
			current.DeferredDeletes[0].ReportSequence = 2
			current.ErrorClass = test.errorClass
			current.ErrorCode = test.errorCode
			want := cloneReconcileResult(current)

			checkpointCalls := 0
			result, err := reconciler.ResumeCommit(t.Context(), prepared, current,
				func(context.Context, ReconcileResult) error {
					checkpointCalls++
					return nil
				})
			_, revisionCalls, mutations := provider.snapshot()
			resolverCalls := 0
			resolver := checker.resolver.(*fakeResolver)
			query := DNSQuery{Name: prepared.Request.Name, Type: prepared.Request.Expected[0].Type}
			for _, named := range append(append([]NamedResolver(nil), checker.authoritative...), checker.public...) {
				resolverCalls += resolver.callCount(named.Endpoint, query)
			}
			if !errors.Is(err, ErrCommitNotReady) || !reflect.DeepEqual(result, want) ||
				resolverCalls != 0 || revisionCalls != 0 || len(mutations) != 0 || checkpointCalls != 0 {
				t.Fatalf("ResumeCommit()=(%#v,%v); resolver=%d revision=%d mutations=%#v checkpoints=%d",
					result, err, resolverCalls, revisionCalls, mutations, checkpointCalls)
			}
		})
	}
}
