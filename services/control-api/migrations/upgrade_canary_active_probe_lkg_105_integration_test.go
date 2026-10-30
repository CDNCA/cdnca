package migrations

import (
	"os"
	"strings"
	"testing"
)

func TestUpgradeCanaryActiveProbeLKG105StaticContract(t *testing.T) {
	up, err := os.ReadFile("105_upgrade_canary_active_probe_lkg.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("105_upgrade_canary_active_probe_lkg.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	upText, downText := string(up), string(down)
	for _, required := range []string{
		"migration 105 requires the exact verified 104 release head",
		"fac89e12c1c307327e4855a6cde1366026fb2914605723db14acd980519f3a5e",
		"76a85290403d0bddbba56c2245a4391d644b897592d2b2ecb00db8ccf1e8ae12",
		"cdnca.edge.upgrade.status/v2", "cdnca.edge.upgrade.active-probe/v1",
		"active_artifact_sha256", "active_config_sha256", "last_known_good_artifact_sha256",
		"last_known_good_config_sha256", "probe_observed_at", "probe_deadline", "evidence_sha256",
		"control_upgrade_status_validate_105", "control_upgrade_status_semantics_105",
		"(evidence_document->>'probe_observed_at')::timestamptz>NEW.observed_at",
	} {
		if !strings.Contains(upText, required) {
			t.Errorf("105 up missing %q", required)
		}
	}
	if strings.Contains(upText,
		"NEW.observed_at>(evidence_document->>'probe_deadline')::timestamptz") {
		t.Error("105 up rejects a terminal status emitted after its completed probe window")
	}
	for _, required := range []string{
		"migration 105 rollback would discard v2 active probe evidence",
		"control_upgrade_status_validate_093", "control_upgrade_status_semantics_096",
	} {
		if !strings.Contains(downText, required) {
			t.Errorf("105 down missing %q", required)
		}
	}
}
