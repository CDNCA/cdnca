package securityactivation

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestWorkerItemKeyIsStableUntilAuthoritativeFactsChange(t *testing.T) {
	now := time.Date(2026, 8, 2, 8, 0, 0, 0, time.UTC)
	item := workerItem{status: StatusCanary, updatedAt: now, receiptSeq: 2}
	item.input.CandidateID = uuid.New()
	first := workerItemKey(item)
	if first != workerItemKey(item) || len(first) != len("worker.")+64 {
		t.Fatalf("worker key is not canonical: %q", first)
	}
	received := now.Add(time.Second)
	item.receiptAt = &received
	if workerItemKey(item) == first {
		t.Fatal("receipt watermark did not change the worker key")
	}
	second := workerItemKey(item)
	recoveryReceipt := now.Add(2 * time.Second)
	item.recoveryReceiptAt = &recoveryReceipt
	item.recoveryReceiptSeq = 3
	if workerItemKey(item) == second {
		t.Fatal("recovery receipt watermark did not change the worker key")
	}
	second = workerItemKey(item)
	item.status = StatusExpanding
	if workerItemKey(item) == second {
		t.Fatal("candidate state did not change the worker key")
	}
}

// N2: row contention from a concurrent writer (node heartbeat, deadlock,
// serialization failure) skips the item for this pass; the worker keeps
// running instead of stopping control-api.
func TestIgnorableWorkerErrorSkipsRowContention(t *testing.T) {
	for _, code := range []string{"55P03", "40001", "40P01"} {
		err := fmt.Errorf("security activation dependency: lock node: %w", &pgconn.PgError{Code: code})
		if !ignorableWorkerError(err) {
			t.Errorf("SQLSTATE %s stops the worker, want a retry next pass", code)
		}
	}
	for _, err := range []error{
		&pgconn.PgError{Code: "23505"},
		errors.New("security activation dependency: signing failed"),
	} {
		if ignorableWorkerError(err) {
			t.Errorf("%v is ignored, want it to stay terminal", err)
		}
	}
}
