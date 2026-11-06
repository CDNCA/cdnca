package migrations

import (
	"strings"
	"testing"
)

// Migration 638 (predecessor 637_market_exclusive_nodes): one new table that binds
// a security policy batch Idempotency-Key to the request digest. No existing table, data or permission changes.
func TestSecurityPolicyBatchIdempotency638Contract(t *testing.T) {
	read := func(direction string) string {
		body, err := FS.ReadFile("638_security_policy_batch_idempotency." + direction + ".sql")
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	up, down := read("up"), read("down")
	for _, fragment := range []string{
		"ERRCODE='P6380'", "migration_id='637_market_exclusive_nodes'",
		"to_regclass(current_schema() || '.security_policy_batch_write_requests') IS NOT NULL",
		"CREATE TABLE security_policy_batch_write_requests",
		"PRIMARY KEY (actor_user_id, idempotency_key)",
		"request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32)",
		"CHECK ((completed_at IS NULL) = (response_body IS NULL))",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("638 up missing %q", fragment)
		}
	}
	for _, fragment := range []string{"ERRCODE='P6381'", "migration_id='638_security_policy_batch_idempotency'",
		"DROP TABLE security_policy_batch_write_requests"} {
		if !strings.Contains(down, fragment) {
			t.Errorf("638 down missing %q", fragment)
		}
	}
	for _, forbidden := range []string{"ALTER TABLE", "DELETE FROM", "UPDATE ", "INSERT INTO"} {
		if strings.Contains(up, forbidden) || strings.Contains(down, forbidden) {
			t.Errorf("638 must not contain %q", forbidden)
		}
	}
}
