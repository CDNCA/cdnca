package migrations_test

import (
	"os"
	"strings"
	"testing"
)

func TestPackageCycleEnforcement146StaticContract(t *testing.T) {
	up := readPackageCycle146(t, "146_package_cycle_enforcement.up.sql")
	down := readPackageCycle146(t, "146_package_cycle_enforcement.down.sql")
	for _, required := range []string{
		"migration 146 requires the exact verified 145 release head",
		"version = 145 AND migration_id = '145_plugin_installations'",
		"c2a8d53baacfd5cf0d0229e70b1cb90238cfedf08b08ccc2118a071d569cf163",
		"f0c80ef2c4fda3e6d7e5812723232959b4864c90331b6c037fc00e9b27343f88",
		"CREATE TABLE package_cycle_enforcement_heads",
		"CREATE TABLE package_cycle_enforcement_claims",
		"CREATE TABLE package_cycle_enforcement_transitions",
		"CREATE TABLE package_cycle_enforcement_overrides",
		"CREATE TABLE package_cycle_usage_adjustments",
		"UNIQUE (tenant_scope_id, subscription_id, evidence_id)",
		"CHECK (status IN ('active','suspended','unknown'))",
		"ARRAY['create','expand']",
		"CHECK (mode IN ('keep_active','force_suspend'))",
		"CHECK (kind IN ('credit','reversal'))",
		"lkg_status",
		"lkg_reason_code",
		"decision_digest",
		"request_digest",
		"response_body",
		"package_cycle_claim_single_winner_146",
		"protect_package_cycle_fact_146",
		"prevent_package_cycle_truncate_146",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("146 up missing %q", required)
		}
	}
	for _, forbidden := range []string{"edge.stop", "edge.disable", "notification_events", "DELETE FROM schema_migrations"} {
		if strings.Contains(up, forbidden) || strings.Contains(down, forbidden) {
			t.Errorf("146 must not contain %q", forbidden)
		}
	}
	for _, required := range []string{
		"migration 146 rollback requires the exact verified 146 head",
		"migration 146 rollback would discard package cycle enforcement facts",
		"DROP TABLE package_cycle_usage_adjustments",
		"DROP TABLE package_cycle_enforcement_overrides",
		"DROP TABLE package_cycle_enforcement_transitions",
		"DROP TABLE package_cycle_enforcement_claims",
		"DROP TABLE package_cycle_enforcement_heads",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("146 down missing %q", required)
		}
	}
}

func readPackageCycle146(t *testing.T, name string) string {
	t.Helper()
	content, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}
