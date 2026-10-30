package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestIAM10IdentityVerificationProviderSessions169Contract(t *testing.T) {
	upBytes, err := controlmigrations.FS.ReadFile("169_identity_verification_provider_sessions.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	downBytes, err := controlmigrations.FS.ReadFile("169_identity_verification_provider_sessions.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down := string(upBytes), string(downBytes)
	for _, required := range []string{
		"migration 169 requires the exact verified 168 release head",
		"afbcb3861d04a9d76933ca497789000dbcfec30cf5bfa2a3f1640775b303ecba",
		"ff328c94456cbbc35006a08c10e671a0196a628e40a4bdc0ec8232703d41dac0",
		"CREATE TABLE identity_verification_provider_sessions_v1",
		"CREATE TABLE identity_verification_provider_attempts_v1",
		"CREATE TABLE identity_verification_provider_uploads_v1",
		"CREATE TABLE identity_verification_provider_callbacks_v1",
		"CREATE TABLE identity_verification_provider_settlements_v1",
		"CREATE TABLE identity_verification_erase_requests_v1",
		"CREATE TABLE identity_verification_erase_receipts_v1",
		"actor_session_id", "idempotency_key", "request_digest_sha256", "object_version",
		"object_sha256", "size_bytes", "content_type", "encryption_key_id",
		"UNIQUE(provider,nonce)", "UNIQUE(provider,event_id)", "pg_advisory_xact_lock",
		"prevent_identity_verification_provider_fact_mutation_169", "clock_timestamp()",
		"REVOKE ALL ON identity_verification_provider_sessions_v1",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("169 up missing %q", required)
		}
	}
	upSHA := fmt.Sprintf("%x", sha256.Sum256(upBytes))
	for _, required := range []string{
		"migration 169 rollback requires the exact verified 169 head", upSHA,
		"migration 169 rollback would discard identity verification provider facts",
		"version=168 AND migration_id='168_recharge_payment_cancellation'",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("169 down missing %q", required)
		}
	}
	for _, forbidden := range []string{"CASCADE", "provider_payload json", "material_body", "__UP_SHA256__"} {
		if strings.Contains(up+down, forbidden) {
			t.Errorf("169 migration contains forbidden marker %q", forbidden)
		}
	}
}
