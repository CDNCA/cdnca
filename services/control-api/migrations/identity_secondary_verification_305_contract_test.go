package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 305 (FX57 二次实名) placeholder number: on merge the coordinator
// renumbers it after the integration head. Every value that moves with the
// renumber is kept in this block.
const (
	secondaryVerification305Version         = "305"
	secondaryVerification305PreviousCount   = "304"
	secondaryVerification305PreviousID      = "304_announcement_late_join_recipients"
	secondaryVerification305PreviousUpSHA   = "ed7e177bd4e9528f777771652491ee6f341b0aeeba6fdf41887d34946413c7b0"
	secondaryVerification305PreviousDownSHA = "8bd6a2fbff34ea7c3c0dfd1e073c2db18bb3ee032b2c303fe71ff1dec86a92b7"
	secondaryVerification305UpSHA           = "cb591779e5c8b35acff239ac4a5dec44caaaff5e005169d0bfab6ac22184009d"
	secondaryVerification305DownSHA         = "ca8f58f22cf5f18c7b4b3607bb00a70c3d891906a3e0635d1e4d6517925220d3"
)

func TestIdentitySecondaryVerification305Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{secondaryVerification305Version + "_identity_secondary_verification.up.sql", secondaryVerification305UpSHA, []string{
			"(SELECT count(*) FROM schema_migrations) <> " + secondaryVerification305PreviousCount,
			"(SELECT max(version) FROM schema_migrations) <> " + secondaryVerification305PreviousCount,
			secondaryVerification305PreviousID, secondaryVerification305PreviousUpSHA, secondaryVerification305PreviousDownSHA,
			"ERRCODE='P3050'", "CREATE TABLE identity_user_secondary_verification",
			"FOREIGN KEY (scope_id,user_id) REFERENCES memberships(scope_id,user_id)",
			"CHECK (expiry_action = 'none' OR deadline IS NOT NULL)",
			"'identity.user.login_security.update',\n        'identity.user.secondary_verification.update'",
			"UPDATE notification_event_policies SET supported=true, enabled=true, sms_enabled=true, email_enabled=true",
			"('identity_secondary_verification',1,'email'", "('identity_secondary_verification',1,'sms'",
			"GRANT SELECT, INSERT, UPDATE ON identity_user_secondary_verification TO cdnca_control_app, cdnca_control_runtime",
		}},
		{secondaryVerification305Version + "_identity_secondary_verification.down.sql", secondaryVerification305DownSHA, []string{
			"(SELECT count(*) FROM schema_migrations) <> " + secondaryVerification305Version,
			secondaryVerification305Version + "_identity_secondary_verification", "ERRCODE='P3051'",
			"EXISTS (SELECT 1 FROM identity_user_secondary_verification)",
			"DROP TABLE identity_user_secondary_verification",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != script.sha {
			t.Fatalf("%s checksum drift: %s", script.name, got)
		}
		for _, required := range script.required {
			if !strings.Contains(string(raw), required) {
				t.Errorf("%s missing %q", script.name, required)
			}
		}
	}
	for name, sha := range map[string]string{
		secondaryVerification305PreviousID + ".up.sql":   secondaryVerification305PreviousUpSHA,
		secondaryVerification305PreviousID + ".down.sql": secondaryVerification305PreviousDownSHA,
	} {
		raw, err := FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != sha {
			t.Fatalf("predecessor %s is not the pinned head: %s", name, got)
		}
	}
}
