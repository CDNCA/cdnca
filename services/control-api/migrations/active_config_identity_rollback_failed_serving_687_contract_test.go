package migrations

import (
	"strings"
	"testing"
)

// Migration 687: the identity validator's
// no-deployment branch also accepts a rollback_failed apply of the node (the
// release kept serving after its compensation failed), on the exact verified
// 686 head; down restores the 232 function.
func TestActiveConfigIdentityRollbackFailedServing687Contract(t *testing.T) {
	up, err := FS.ReadFile("687_active_config_identity_rollback_failed_serving.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := FS.ReadFile("687_active_config_identity_rollback_failed_serving.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := FS.ReadFile("232_active_config_identity_configuration_scope.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	function := func(sql []byte) string {
		text := string(sql)
		start := strings.Index(text, "CREATE OR REPLACE FUNCTION active_config_identity_artifact_valid_087(")
		if start < 0 {
			t.Fatal("validator definition missing")
		}
		end := strings.Index(text[start:], "$$;")
		return text[start : start+end+3]
	}
	for _, fragment := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 686", "(SELECT max(version) FROM schema_migrations) <> 686",
		"migration_id='686_dns_cleanup_plan_records'", "ERRCODE='P6870'",
		"AND deployment.state IN ('activated', 'healthy', 'rollback_failed')",
		"AND deployment.action = 'apply'", "AND binding.artifact_id = artifact.id",
	} {
		if !strings.Contains(string(up), fragment) {
			t.Errorf("687 up missing %q", fragment)
		}
	}
	// Only the no-deployment branch changes; the reported-deployment branch
	// still takes healthy applies and reverted rollbacks only.
	if got, want := function(up), strings.Replace(function(legacy), "AND deployment.state IN ('activated', 'healthy')\n",
		"AND deployment.state IN ('activated', 'healthy', 'rollback_failed')\n", 1); got != want {
		t.Error("687 up changes more of the validator than its no-deployment states")
	}
	if function(down) != function(legacy) {
		t.Error("687 down does not restore the 232 validator")
	}
	for _, fragment := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 687",
		"migration_id='687_active_config_identity_rollback_failed_serving'", "ERRCODE='P6871'",
	} {
		if !strings.Contains(string(down), fragment) {
			t.Errorf("687 down missing %q", fragment)
		}
	}
	for name, sql := range map[string][]byte{"up": up, "down": down} {
		if strings.Contains(string(sql), "INSERT INTO") || strings.Contains(string(sql), "UPDATE ") ||
			strings.Contains(string(sql), "ALTER TABLE") {
			t.Errorf("687 %s must only replace the validator", name)
		}
	}
}
