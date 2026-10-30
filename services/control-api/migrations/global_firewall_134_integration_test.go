//go:build integration

package migrations_test

import (
	"os"
	"strings"
	"testing"
)

func TestGlobalFirewall134MigrationContract(t *testing.T) {
	up := readGlobalFirewall134(t, "134_global_firewall.up.sql")
	down := readGlobalFirewall134(t, "134_global_firewall.down.sql")
	for _, fragment := range []string{
		"migration 134 requires the exact verified 133 release head", "CREATE TABLE global_firewall_policies",
		"CREATE TABLE global_firewall_policy_revisions", "CREATE TABLE global_firewall_write_receipts",
		"CREATE TABLE global_firewall_publication_outbox", "document_sha256", "active_revision",
		"deployment_state", "recovery_of_revision", "idempotency_key", "request_sha256",
		"BEFORE UPDATE OR DELETE", "BEFORE TRUNCATE", "REVOKE ALL", "ERRCODE='P1340'",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("134 up missing %q", fragment)
		}
	}
	for _, fragment := range []string{
		"migration 134 rollback requires the verified 134 head", "rollback would discard global firewall facts",
		"DROP TABLE global_firewall_publication_outbox", "DROP TABLE global_firewall_write_receipts",
		"DROP TABLE global_firewall_policy_revisions", "DROP TABLE global_firewall_policies",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("134 down missing %q", fragment)
		}
	}
}

func TestGlobalFirewall134EmptyRoundTrip(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 133)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 134); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"global_firewall_policies", "global_firewall_policy_revisions", "global_firewall_write_receipts", "global_firewall_publication_outbox"} {
		var exists bool
		if err := pool.QueryRow(t.Context(), `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&exists); err != nil || !exists {
			t.Fatalf("table %s exists=%t err=%v", table, exists, err)
		}
	}
	if err := migrateVersionIsolated(t.Context(), pool, "down", 134); err != nil {
		t.Fatal(err)
	}
}

func readGlobalFirewall134(t *testing.T, name string) string {
	t.Helper()
	content, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}
