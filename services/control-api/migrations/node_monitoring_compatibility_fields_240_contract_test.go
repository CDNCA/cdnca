package migrations

import (
	"strings"
	"testing"
)

func TestNodeMonitoringCompatibilityFields240Contract(t *testing.T) {
	up, err := FS.ReadFile("240_node_monitoring_compatibility_fields.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := FS.ReadFile("240_node_monitoring_compatibility_fields.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	upText, downText := string(up), string(down)
	for _, required := range []string{
		"migration 240 requires the exact verified 239 release head",
		"CREATE OR REPLACE FUNCTION system_configuration_v2_node_monitoring_is_valid",
		"monitor_enabled", "monitor_groups", "failure_ratio", "bandwidth_over_limit",
	} {
		if !strings.Contains(upText, required) {
			t.Errorf("migration 240 up is missing %q", required)
		}
	}
	for _, required := range []string{
		"migration 240 rollback requires the exact verified 240 release head",
		"CREATE OR REPLACE FUNCTION system_configuration_v2_node_monitoring_is_valid",
	} {
		if !strings.Contains(downText, required) {
			t.Errorf("migration 240 down is missing %q", required)
		}
	}
}
