package migrations_test

import (
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestChallengePublicationFacts138PinsExactReleaseAndDurableContract(t *testing.T) {
	up := readChallengePublication138(t, "138_challenge_publication_facts.up.sql")
	for _, required := range []string{
		"migration 138 requires the exact verified 137 release head",
		"version = 137 AND migration_id = '137_tcp_billing_factor'",
		"checksum_sha256 = '741cabd2ca7d32915d7c2a5e13f42a75ccd9888f3662be8f572cacd3b6d7a4df'",
		"down_checksum_sha256 = 'c6d3329f35c73745eaaef8a9d75aaf4f16ee925aef8d4145211152ea2669923b'",
		"CREATE TABLE challenge_key_facts_138",
		"CREATE TABLE challenge_site_bindings_138",
		"CREATE TABLE challenge_site_binding_revisions_138",
		"role IN ('current','previous','app')",
		"octet_length(ciphertext) BETWEEN 29 AND 4096",
		"octet_length(signature) = 64",
		"UNIQUE (tenant_scope_id, site_id, policy_id, policy_revision, role)",
		"state IN ('candidate','active')",
		"UNIQUE (tenant_scope_id, idempotency_key)",
		"invalid challenge binding revision transition",
		"challenge binding publication identity mismatch",
		"challenge publication facts are immutable",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("138 up missing %q", required)
		}
	}
	if guard, mutation := strings.Index(up, "migration 138 requires the exact verified 137 release head"),
		strings.Index(up, "CREATE TABLE challenge_key_facts_138"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("138 predecessor guard must run before the first schema mutation")
	}
}

func TestChallengePublicationFacts138RollbackFailsClosed(t *testing.T) {
	down := readChallengePublication138(t, "138_challenge_publication_facts.down.sql")
	for _, required := range []string{
		"migration 138 rollback requires the exact verified 138 head",
		"version = 138 AND migration_id = '138_challenge_publication_facts'",
		"checksum_sha256 = '14399e504508dbe31dd78711d22ef2c2f4e5a20aad0fc299ee355553e3a3ae9e'",
		"version = 137 AND migration_id = '137_tcp_billing_factor'",
		"checksum_sha256 = '741cabd2ca7d32915d7c2a5e13f42a75ccd9888f3662be8f572cacd3b6d7a4df'",
		"down_checksum_sha256 = 'c6d3329f35c73745eaaef8a9d75aaf4f16ee925aef8d4145211152ea2669923b'",
		"migration 138 rollback would discard durable challenge publication facts",
		"DROP TABLE challenge_site_binding_revisions_138",
		"DROP TABLE challenge_site_bindings_138",
		"DROP TABLE challenge_key_facts_138",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("138 down missing %q", required)
		}
	}
	if guard, mutation := strings.Index(down, "migration 138 rollback requires the exact verified 138 head"),
		strings.Index(down, "ALTER TABLE challenge_site_bindings_138"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("138 rollback guard must run before the first schema mutation")
	}
	if strings.Contains(down, "DELETE FROM schema_migrations") {
		t.Fatal("138 down must leave migration metadata ownership to the runner")
	}
}

func readChallengePublication138(t *testing.T, name string) string {
	t.Helper()
	content, err := controlmigrations.FS.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}
