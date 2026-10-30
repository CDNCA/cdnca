package cachecontrol

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
)

// The node's cancel receipt is a node fact (no user) on the cache operation;
// the action is registered in the audit catalog so it renders and passes the
// catalog coverage scan.
func TestCancelReceiptAuditEvent(t *testing.T) {
	scopeID, operationID := uuid.New(), uuid.New()
	settled := time.Date(2026, 10, 26, 8, 30, 0, 0, time.FixedZone("CST", 8*3600))
	receipt := CancelReceipt{
		DeliveryID: uuid.New(), NodeID: uuid.New(), LeaseID: uuid.New(), Attempt: 2, EventID: uuid.New(),
		Outcome: CancelConfirmed, SucceededTargets: 3, FailedTargets: 1, CancelledTargets: 4, SettledAt: settled,
	}
	event := cancelReceiptAuditEvent(scopeID, operationID, receipt)
	if event.Action != "cache.cancel.receipt" || event.ScopeID != scopeID || event.ActorUserID != nil ||
		event.ResourceType != "cache_operation" || event.ResourceID != operationID.String() || event.Result != "success" {
		t.Fatalf("event = %+v", event)
	}
	if event.RequestID != "cache-cancel-receipt:"+receipt.EventID.String() {
		t.Fatalf("request id = %q", event.RequestID)
	}
	if !event.OccurredAt.IsZero() {
		t.Fatalf("occurred_at must be the control-plane clock, got node time %v", event.OccurredAt)
	}
	want := map[string]any{
		"cancel_id": receipt.DeliveryID.String(), "node_id": receipt.NodeID.String(),
		"lease_id": receipt.LeaseID.String(), "attempt": uint32(2), "outcome": "cancelled",
		"succeeded_targets": 3, "failed_targets": 1, "cancelled_targets": 4,
		"settled_at": "2026-10-26T00:30:00Z",
	}
	if len(event.Payload) != len(want) {
		t.Fatalf("payload = %#v", event.Payload)
	}
	for key, value := range want {
		if event.Payload[key] != value {
			t.Fatalf("payload[%s] = %#v, want %#v", key, event.Payload[key], value)
		}
	}
	for _, outcome := range []CancelConfirmation{CancelCompleted, CancelUnresponsive} {
		receipt.Outcome = outcome
		if got := cancelReceiptAuditEvent(scopeID, operationID, receipt).Payload["outcome"]; got != string(outcome) {
			t.Fatalf("outcome %s payload = %#v", outcome, got)
		}
	}
	if _, ok := audit.Lookup("cache.cancel.receipt"); !ok {
		t.Fatal("cache.cancel.receipt is not in the audit catalog")
	}
}
