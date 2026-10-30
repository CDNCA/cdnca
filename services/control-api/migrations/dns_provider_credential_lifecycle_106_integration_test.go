//go:build integration

package migrations

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestDNSProviderCredentialLifecycle106PredecessorGuard(t *testing.T) {
	up := readMigration106(t, "106_dns_provider_credential_lifecycle.up.sql")
	down := readMigration106(t, "106_dns_provider_credential_lifecycle.down.sql")
	store := readMigration106(t, "../internal/dnsacme/store.go")
	assertMigrationSHA106(t, "105 up", "105_upgrade_canary_active_probe_lkg.up.sql", "aef23962ee9538fbc4724684ec8fc87edc2a2af33f76aa8a76b6992769af0d7b")
	assertMigrationSHA106(t, "105 down", "105_upgrade_canary_active_probe_lkg.down.sql", "f570ec734387701cce422729750234f98365db2e64bf0110f5965076f89ada23")
	for _, expected := range []string{
		"REQUIRED_MIGRATION_105_UP_SHA256=aef23962ee9538fbc4724684ec8fc87edc2a2af33f76aa8a76b6992769af0d7b",
		"REQUIRED_MIGRATION_105_DOWN_SHA256=f570ec734387701cce422729750234f98365db2e64bf0110f5965076f89ada23",
		"checksum_sha256=required_up AND down_checksum_sha256=required_down",
		"ERRCODE='P1060'",
		"migration_id='105_upgrade_canary_active_probe_lkg'",
		"REFERENCES dns_providers(id) ON DELETE CASCADE",
		"UPDATE dns_providers SET credential_revoked=(status='disabled')",
		"NEW.credential_version := OLD.credential_version + 1",
		"event_name := 'rotation'",
		"event_name := 'revocation'",
		"event_name := 'rotation_revocation'",
		"event_name := 'rollback'",
		"provider_status text NOT NULL",
		"prior.provider_status='verified' AND NOT prior.credential_revoked",
		"AFTER INSERT ON dns_providers",
		"AFTER UPDATE ON dns_providers",
	} {
		if !strings.Contains(up, expected) {
			t.Fatalf("106 up guard missing %q", expected)
		}
	}
	if strings.Contains(up, "INTEGRATION_SHA256") || strings.Contains(up, "provisional") ||
		strings.Contains(up, strings.Repeat("0", 64)) {
		t.Fatal("106 up retains an unauthorized or provisional predecessor hash")
	}
	for _, expected := range []string{
		"active.credential_event='rotation'",
		"candidate.credential_version<provider.credential_version",
		"candidate.provider_status='verified' AND NOT candidate.credential_revoked",
		"candidate.credential_version>COALESCE",
		"Action: \"dns.provider.credential.rollback\"",
		"\"restored_from_version\": restoredVersion",
		"\"reason_code\": reasonCode",
	} {
		if !strings.Contains(store, expected) {
			t.Fatalf("production rollback path missing %q", expected)
		}
	}
	if strings.Contains(up, "ON CONFLICT") {
		t.Fatal("106 history silently swallows version conflicts")
	}
	for _, expected := range []string{
		"version=106 AND migration_id='106_dns_provider_credential_lifecycle'",
		"checksum_sha256='097ca7d3fcdf878ff11cc891e8a8b05abe3dfd923b9153fdc15ee616d3415adf'",
		"version=105 AND migration_id='105_upgrade_canary_active_probe_lkg'",
		"checksum_sha256='aef23962ee9538fbc4724684ec8fc87edc2a2af33f76aa8a76b6992769af0d7b'",
		"down_checksum_sha256='f570ec734387701cce422729750234f98365db2e64bf0110f5965076f89ada23'",
		"credential_event <> 'baseline'",
		"rollback would discard credential lifecycle history",
		"DELETE FROM dns_provider_credential_history WHERE credential_event='baseline'",
	} {
		if !strings.Contains(down, expected) {
			t.Fatalf("106 down guard missing %q", expected)
		}
	}
}

func assertMigrationSHA106(t *testing.T, label, path, expected string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	actual := fmt.Sprintf("%x", sha256.Sum256(data))
	if actual != expected {
		t.Fatalf("%s SHA=%s want %s", label, actual, expected)
	}
}

func readMigration106(t *testing.T, name string) string {
	t.Helper()
	path := "106_dns_provider_credential_lifecycle.up.sql"
	if name != path {
		path = name
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
