package migrations

import (
	"strings"
	"testing"
)

// Migration 689: the certificate publication
// actor trigger accepts a session the token refresh replaced, as
// PrincipalForSession does, on the exact verified 688 head; down restores the
// 120 function body.
func TestCertificatePublicationActorRefreshedSession689Contract(t *testing.T) {
	up, err := FS.ReadFile("689_certificate_publication_actor_refreshed_session.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := FS.ReadFile("689_certificate_publication_actor_refreshed_session.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	original, err := FS.ReadFile("120_certificate_publication_results.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 688", "(SELECT max(version) FROM schema_migrations) <> 688",
		"migration_id='688_probe_dnspup_plugin_tenant_idempotency'", "ERRCODE='P6890'",
		"to_regprocedure('validate_certificate_publication_actor_120()') IS NULL",
		"CREATE OR REPLACE FUNCTION validate_certificate_publication_actor_120()",
		"AND session_row.user_id=NEW.actor_user_id AND session_row.revoked_at IS NULL\n          AND session_row.expires_at>transaction_timestamp()",
	} {
		if !strings.Contains(string(up), fragment) {
			t.Errorf("689 up missing %q", fragment)
		}
	}
	upBody := functionBody(t, string(up), "CREATE OR REPLACE FUNCTION validate_certificate_publication_actor_120()")
	if strings.Contains(upBody, "replaced_by_id") {
		t.Error("689 up still requires an unreplaced session")
	}
	for _, fragment := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 689",
		"migration_id='689_certificate_publication_actor_refreshed_session'", "ERRCODE='P6891'",
	} {
		if !strings.Contains(string(down), fragment) {
			t.Errorf("689 down missing %q", fragment)
		}
	}
	downBody := functionBody(t, string(down), "CREATE OR REPLACE FUNCTION validate_certificate_publication_actor_120()")
	originalBody := functionBody(t, string(original), "CREATE FUNCTION validate_certificate_publication_actor_120()")
	if downBody != originalBody {
		t.Errorf("689 down function differs from 120:\n%s\n---\n%s", downBody, originalBody)
	}
	for name, sql := range map[string][]byte{"up": up, "down": down} {
		if strings.Contains(string(sql), "INSERT INTO") || strings.Contains(string(sql), "UPDATE ") ||
			strings.Contains(string(sql), "DELETE FROM") || strings.Contains(string(sql), "ALTER TABLE") ||
			strings.Contains(string(sql), "TRIGGER") {
			t.Errorf("689 %s must only replace the function body", name)
		}
	}
}
