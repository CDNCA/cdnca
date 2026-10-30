package migrations

import (
	"strings"
	"testing"
)

func TestOpenRestySecurityConfig217Contract(t *testing.T) {
	up, err := FS.ReadFile("217_openresty_security_config.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := FS.ReadFile("217_openresty_security_config.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"migration_217", "216_identity_user_soft_delete",
		"openresty_security.read", "openresty_security.manage",
		"CREATE TABLE openresty_security_configs",
		"CREATE TABLE openresty_security_config_revisions",
		"CREATE TABLE openresty_security_write_receipts",
		"CREATE TABLE openresty_security_publication_outbox",
		"CREATE TABLE openresty_security_task_outbox",
		"scope_type IN ('global','region','node')", "key_override", "secret_ciphertext",
		"openresty_security_configs_active_target_idx", "prevent_openresty_security_fact_mutation_217",
	} {
		if !strings.Contains(string(up), required) {
			t.Fatalf("migration 217 missing %q", required)
		}
	}
	for _, required := range []string{
		"migration 217 rollback would discard", "DROP TABLE openresty_security_configs",
		"DELETE FROM permissions", "REVOKE SELECT,INSERT,UPDATE",
	} {
		if !strings.Contains(string(down), required) {
			t.Fatalf("migration 217 down missing %q", required)
		}
	}
}
