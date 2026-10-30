package controlupgrade

import (
	"encoding/json"
	"testing"
	"time"
)

func TestHydrateRolloutStatusReceiptProjectsNodeOutcome(t *testing.T) {
	payload := rolloutStatusPayload{Schema: "cdnca.edge.upgrade.status/v1", State: "failed", CurrentVersion: "2.0.0",
		PreviousVersion: "2.0.0", ErrorCode: "HEALTH_FAILED", ObservedAt: time.Unix(1_800_000_000, 0).UTC()}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	receipt := RolloutStatusReceipt{StatusBytes: encoded}
	if !hydrateRolloutStatusReceipt(&receipt) || receipt.ErrorCode != "HEALTH_FAILED" ||
		receipt.CurrentVersion != "2.0.0" || receipt.PreviousVersion != "2.0.0" {
		t.Fatalf("receipt = %+v", receipt)
	}
	// A stored value that no longer passes validation is not projected.
	payload.ErrorCode, payload.CurrentVersion = "bad code with spaces", "not a version"
	encoded, _ = json.Marshal(payload)
	receipt = RolloutStatusReceipt{StatusBytes: encoded}
	if !hydrateRolloutStatusReceipt(&receipt) || receipt.ErrorCode != "" || receipt.CurrentVersion != "" {
		t.Fatalf("invalid outcome projected: %+v", receipt)
	}
}
