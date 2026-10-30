package httpapi

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/controlupgrade"
)

func TestControlUpgradeStatusReceiptExposesActiveProbeEvidence(t *testing.T) {
	evidence := &controlupgrade.ActiveProbeEvidence{
		Schema:                      controlupgrade.ActiveProbeEvidenceSchema,
		ActiveArtifactSHA256:        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ActiveConfigSHA256:          "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		LastKnownGoodArtifactSHA256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		LastKnownGoodConfigSHA256:   "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		ProbeObservedAt:             time.Date(2026, 8, 6, 2, 0, 0, 0, time.UTC),
		ProbeDeadline:               time.Date(2026, 8, 6, 2, 1, 0, 0, time.UTC),
		EvidenceSHA256:              "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
	}
	response := controlUpgradeStatusReceipt(controlupgrade.RolloutStatusReceipt{
		Schema: controlupgrade.EdgeUpgradeStatusSchemaV2, StatusID: "status-v2", State: "healthy",
		ActiveEvidence: evidence,
	})
	if response.Schema != controlupgrade.EdgeUpgradeStatusSchemaV2 || response.ActiveEvidence == nil ||
		response.ActiveEvidence.EvidenceSHA256 != evidence.EvidenceSHA256 {
		t.Fatalf("status response = %#v", response)
	}
}
