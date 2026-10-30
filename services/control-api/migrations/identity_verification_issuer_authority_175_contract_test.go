package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestIAM10IdentityVerificationIssuerAuthority175Contract(t *testing.T) {
	upBytes, err := controlmigrations.FS.ReadFile("175_identity_verification_issuer_authority.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	downBytes, err := controlmigrations.FS.ReadFile("175_identity_verification_issuer_authority.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down := string(upBytes), string(downBytes)
	for _, required := range []string{
		"migration 175 requires the exact verified 174 release head",
		"d73f059af5beffa4fe3d76b9ff1a360b02a1a40a0a4be0a3cab085f3900d082a",
		"7b81cf1d669f70ebc8e9696280b3daf3ccc2cad831a86cd27302b4a1be323331",
		"migration 175 cannot infer enterprise settlement facts",
		"ADD COLUMN organization_name", "ADD COLUMN legal_person_fingerprint",
		"ADD COLUMN agent_fingerprint", "ADD COLUMN agent_relationship",
		"CREATE TABLE identity_verification_provider_material_envelopes_v1",
		"CREATE TABLE identity_verification_evidence_issue_bindings_v1",
		"UNIQUE(workload_id,idempotency_digest)",
		"identity_verification_provider_upload_binding_175",
		"identity_verification_evidence_reservation_issue_binding_175",
		"identity_verification_material_envelopes_require_audit_175",
		"prevent_identity_verification_issuer_fact_mutation_175",
		"prevent_identity_verification_issuer_fact_truncate_175",
		"terminal_transition := OLD.status NOT IN",
		"NEW.retention_until<>NEW.terminal_at+configured_retention",
		"NEW.retention_until IS DISTINCT FROM OLD.retention_until",
		"REVOKE ALL ON identity_verification_provider_material_envelopes_v1",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("175 up missing %q", required)
		}
	}
	upSHA := fmt.Sprintf("%x", sha256.Sum256(upBytes))
	for _, required := range []string{
		"migration 175 rollback requires the exact verified 175 head", upSHA,
		"migration 175 rollback refuses to discard identity verification issuer facts",
		"DROP TABLE identity_verification_evidence_issue_bindings_v1",
		"DROP TABLE identity_verification_provider_material_envelopes_v1",
		"DROP COLUMN organization_name", "CREATE OR REPLACE FUNCTION protect_identity_verification_case()",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("175 down missing %q", required)
		}
	}
	for _, forbidden := range []string{"CASCADE", "__UP_SHA256__", "idempotency_key text", "raw_document"} {
		if strings.Contains(up+down, forbidden) {
			t.Errorf("175 migration contains forbidden marker %q", forbidden)
		}
	}
}
