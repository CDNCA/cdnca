package migrations

import (
	"strings"
	"testing"
)

// Migration 685: recovery by a registration-verified email joins the consumed
// email proofs on consumed_idempotency_digest; a partial index on the consumed ones keeps that an index lookup
// instead of a scan an anonymous request could repeat. Exact verified 684 head; down drops the index.
func TestRegistrationProofConsumedDigestIndex685Contract(t *testing.T) {
	up, err := FS.ReadFile("685_registration_proof_consumed_digest_index.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := FS.ReadFile("685_registration_proof_consumed_digest_index.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"LOCK TABLE schema_migrations, account_registration_proofs_162 IN ACCESS EXCLUSIVE MODE",
		"(SELECT count(*) FROM schema_migrations) <> 684", "(SELECT max(version) FROM schema_migrations) <> 684",
		"migration_id='684_plugin_installation_license_reports'", "ERRCODE='P6850'",
		"CREATE INDEX account_registration_proofs_consumed_685\n    ON account_registration_proofs_162 (consumed_idempotency_digest)\n    WHERE use_revision = 1;",
	} {
		if !strings.Contains(string(up), fragment) {
			t.Fatalf("685 up lacks %q", fragment)
		}
	}
	for _, fragment := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 685", "migration_id='685_registration_proof_consumed_digest_index'",
		"ERRCODE='P6851'", "DROP INDEX account_registration_proofs_consumed_685;",
	} {
		if !strings.Contains(string(down), fragment) {
			t.Fatalf("685 down lacks %q", fragment)
		}
	}
}
