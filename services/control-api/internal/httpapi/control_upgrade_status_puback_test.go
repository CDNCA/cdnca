package httpapi

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/controlupgrade"
)

func TestControlUpgradeStatusReceiptExposesExactBrokerIdentity(t *testing.T) {
	receipt := controlupgrade.RolloutStatusReceipt{
		StatusID: "00000000-0000-4000-8000-000000000951", StatusRevision: 3,
		CommandID: "00000000-0000-4000-8000-000000000952", PlanID: "00000000-0000-4000-8000-000000000953",
		PlanRevision: 2, BatchID: "00000000-0000-4000-8000-000000000954",
		InstallationID: "00000000-0000-4000-8000-000000000955", NodeID: "00000000-0000-4000-8000-000000000956",
		Action: "upgrade", StatusSHA256: strings.Repeat("a", 64), State: "installing",
		ObservedAt: time.Date(2026, 8, 6, 1, 2, 3, 0, time.UTC), DeliveryStream: "AGENT_DEPLOYMENT_STATUS",
		DeliveryConsumer: "control_api_upgrade_status", DeliverySequence: 9007199254740993,
	}
	got := controlUpgradeStatusReceipt(receipt)
	if got.StatusID != receipt.StatusID || got.StatusRevision != "3" || got.CommandID != receipt.CommandID ||
		got.StatusSHA256 != receipt.StatusSHA256 || got.DeliveryStream != receipt.DeliveryStream ||
		got.DeliveryConsumer != receipt.DeliveryConsumer ||
		got.DeliverySequence != strconv.FormatUint(receipt.DeliverySequence, 10) {
		t.Fatalf("status receipt response = %#v", got)
	}
}

func TestControlUpgradeStatusReceiptProjectsNodeOutcomeForLogs(t *testing.T) {
	receipt := controlupgrade.RolloutStatusReceipt{StatusID: "00000000-0000-4000-8000-000000000961", State: "failed",
		ErrorCode: "DOWNLOAD_FAILED", CurrentVersion: "2.0.0", PreviousVersion: "2.0.0"}
	got := controlUpgradeStatusReceipt(receipt)
	if got.ErrorCode != "DOWNLOAD_FAILED" || got.CurrentVersion != "2.0.0" || got.PreviousVersion != "2.0.0" {
		t.Fatalf("status receipt response = %#v", got)
	}
	encoded, err := json.Marshal(controlUpgradeStatusReceipt(controlupgrade.RolloutStatusReceipt{State: "healthy"}))
	if err != nil || strings.Contains(string(encoded), "error_code") || strings.Contains(string(encoded), "current_version") {
		t.Fatalf("empty outcome fields must be omitted: %s %v", encoded, err)
	}
}

func TestControlUpgradeOpenAPIRequiresStatusBrokerIdentity(t *testing.T) {
	encoded, err := os.ReadFile("../../../../api/openapi/v1/control.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"ControlUpgradeStatusReceipt:", "status_receipts:",
		"delivery_stream:", "delivery_consumer:", "delivery_sequence:",
		"canary_node_ids:\n          type: array\n          minItems: 1\n          maxItems: 2"} {
		if !strings.Contains(string(encoded), required) {
			t.Errorf("control OpenAPI missing %q", required)
		}
	}
}
