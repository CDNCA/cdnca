package migrations

import (
	"strings"
	"testing"
)

func TestCertificateDefaultsRuntimeGrants259Contract(t *testing.T) {
	up, err := FS.ReadFile("259_certificate_defaults_runtime_grants.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := FS.ReadFile("259_certificate_defaults_runtime_grants.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	upText, downText := string(up), string(down)
	for _, required := range []string{
		"migration 259 requires the exact verified 258 release head",
		"checksum_sha256 = '092b366bc037c7d81c4ab24fbff6d54302b7a4cd350193dc0237ba86f365eb92'",
		"down_checksum_sha256 = 'ab91ac6664a5d817a86fb937993880ace5043fdf872e065899a3b1b1f188d584'",
		"to_regrole('cdnca_control_app')",
		"GRANT SELECT, INSERT, UPDATE ON certificate_user_defaults TO cdnca_control_app",
		"GRANT SELECT, INSERT, UPDATE ON certificate_default_write_requests TO cdnca_control_app",
	} {
		if !strings.Contains(upText, required) {
			t.Errorf("migration 259 up is missing %q", required)
		}
	}
	for _, required := range []string{
		"migration 259 rollback requires the exact verified 259 release head",
		"REVOKE SELECT, INSERT, UPDATE ON certificate_user_defaults FROM cdnca_control_app RESTRICT",
		"REVOKE SELECT, INSERT, UPDATE ON certificate_default_write_requests FROM cdnca_control_app RESTRICT",
	} {
		if !strings.Contains(downText, required) {
			t.Errorf("migration 259 down is missing %q", required)
		}
	}
	for _, forbidden := range []string{"GRANT DELETE", "GRANT TRUNCATE", "REVOKE DELETE", "REVOKE TRUNCATE"} {
		if strings.Contains(upText+downText, forbidden) {
			t.Errorf("migration 259 unexpectedly contains %q", forbidden)
		}
	}
}
