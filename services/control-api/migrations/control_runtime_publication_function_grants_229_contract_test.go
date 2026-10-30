package migrations

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestControlRuntimePublicationFunctionGrants229Contract(t *testing.T) {
	up, err := FS.ReadFile("229_control_runtime_publication_function_grants.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := FS.ReadFile("229_control_runtime_publication_function_grants.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	upText, downText := string(up), string(down)
	for _, text := range []string{upText, downText} {
		if !strings.Contains(text, "count(*) FROM schema_migrations") ||
			strings.Contains(strings.ToUpper(text), "CASCADE") ||
			strings.Contains(strings.ToUpper(text), "TRUNCATE") {
			t.Fatalf("migration guard contains an unsafe or missing contract: %s", text)
		}
	}
	for _, function := range []string{
		"package_monitor_site_binding_digest_114(uuid,uuid,uuid,uuid,bigint,timestamptz)",
		"record_security_policy_activation_recovery_pending_095(uuid)",
		"record_security_policy_activation_recovery_proofs_095()",
	} {
		if !strings.Contains(upText, "GRANT EXECUTE ON FUNCTION "+function+"\n    TO cdnca_control_runtime;") ||
			!strings.Contains(downText, "REVOKE EXECUTE ON FUNCTION "+function+"\n    FROM cdnca_control_runtime;") {
			t.Errorf("migration 229 is missing symmetric runtime grant for %s", function)
		}
	}
	if !strings.Contains(upText, "migration_id='228_edge_publication_rollback_contract'") ||
		!strings.Contains(downText, "migration_id='228_edge_publication_rollback_contract'") {
		t.Fatal("migration 229 does not pin the exact migration 228 predecessor")
	}
	upDigest := sha256.Sum256(up)
	downDigest := sha256.Sum256(down)
	t.Logf("migration 229 checksums up=%s down=%s", hex.EncodeToString(upDigest[:]), hex.EncodeToString(downDigest[:]))
}
