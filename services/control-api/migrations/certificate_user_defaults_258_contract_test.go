package migrations

import (
	"strings"
	"testing"
)

func TestCertificateUserDefaults258Contract(t *testing.T) {
	up, err := FS.ReadFile("258_certificate_user_defaults.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := FS.ReadFile("258_certificate_user_defaults.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	upText, downText := string(up), string(down)
	for _, required := range []string{
		"migration 258 requires the exact verified 257 release head",
		"CREATE TABLE certificate_user_defaults",
		"CREATE TABLE certificate_default_write_requests",
		"FOREIGN KEY (scope_id, user_id) REFERENCES memberships(scope_id, user_id)",
		"FOREIGN KEY (updated_by_user_id) REFERENCES users(id)",
		"UNIQUE (actor_user_id, operation, idempotency_key)",
		"CHECK (certificate_type = 'acme' OR dns_provider_id IS NULL)",
	} {
		if !strings.Contains(upText, required) {
			t.Errorf("migration 258 up is missing %q", required)
		}
	}
	for _, required := range []string{
		"migration 258 rollback requires the exact verified 258 release head",
		"DROP TABLE certificate_default_write_requests",
		"DROP TABLE certificate_user_defaults",
	} {
		if !strings.Contains(downText, required) {
			t.Errorf("migration 258 down is missing %q", required)
		}
	}
}
