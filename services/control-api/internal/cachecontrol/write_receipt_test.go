package cachecontrol

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// fix-cacheflow5: only definite refusals become receipts, with the code the
// HTTP layer answers; not-found, permission, conflicts and dependency
// failures do not (they read as never received).
func TestWriteRejectionCodeKeepsOnlyDefiniteRefusals(t *testing.T) {
	for _, item := range []struct {
		err  error
		code string
	}{
		{fmt.Errorf("persist: %w", &TargetError{Ordinal: 3, Reason: TargetReasonHostNotServed}), "invalid_request"},
		{ErrWildcardTargetHost, "wildcard_target_host"},
		{ErrInvalidInput, "invalid_request"},
		{fmt.Errorf("cancel cache operation: %w", ErrInvalidTransition), "invalid_operation_transition"},
		{ErrRetriesExhausted, "retries_exhausted"},
		{ErrEntitlementDenied, "entitlement_denied"},
		{ErrSiteLocked, "site_locked"},
		{ErrDailyLimitExceeded, "daily_limit_exceeded"},
		{ErrNoCarryingNode, "no_carrying_node"},
		{ErrTargetNodeUnavailable, "target_node_unavailable"},
		{ErrWildcardPurgeUnsupported, "wildcard_purge_unsupported"},
	} {
		rejection, ok := writeRejectionCode(item.err)
		if !ok || rejection.Code != item.code {
			t.Errorf("%v: rejection=%+v ok=%v, want %s", item.err, rejection, ok, item.code)
		}
	}
	if rejection, _ := writeRejectionCode(&TargetError{Ordinal: 3, Reason: TargetReasonHostNotServed}); rejection.TargetOrdinal != 3 ||
		rejection.TargetReason != TargetReasonHostNotServed {
		t.Fatalf("target rejection=%+v", rejection)
	}
	for _, err := range []error{
		ErrNotFound, ErrPermissionDenied, ErrIdempotencyConflict, context.Canceled,
		context.DeadlineExceeded, errors.New("connection reset"),
	} {
		if _, ok := writeRejectionCode(err); ok {
			t.Errorf("%v must not become a receipt", err)
		}
	}
}

func TestWriteReceiptRequestShape(t *testing.T) {
	operationID := uuid.New()
	for _, item := range []struct {
		request WriteReceiptRequest
		valid   bool
	}{
		{WriteReceiptRequest{Action: WriteCreate, IdempotencyKey: "k-1"}, true},
		{WriteReceiptRequest{Action: WriteCreate, OperationID: operationID, IdempotencyKey: "k-1"}, false},
		{WriteReceiptRequest{Action: WriteRetry, OperationID: operationID, IdempotencyKey: "k-1"}, true},
		{WriteReceiptRequest{Action: WriteCancel, IdempotencyKey: "k-1"}, false},
		{WriteReceiptRequest{Action: WriteResubmit, OperationID: operationID, IdempotencyKey: "k-1"}, true},
		{WriteReceiptRequest{Action: "delete", OperationID: operationID, IdempotencyKey: "k-1"}, false},
		{WriteReceiptRequest{Action: WriteCreate, IdempotencyKey: "-bad"}, false},
		{WriteReceiptRequest{Action: WriteCreate, IdempotencyKey: strings.Repeat("k", 129)}, false},
	} {
		if got := validWriteReceiptRequest(item.request); got != item.valid {
			t.Errorf("%+v valid=%v, want %v", item.request, got, item.valid)
		}
	}
}
