package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 407 (attack alert notifications) is a placeholder
// number: the merge renumbers it after the head it lands on. Everything that
// changes with the renumbering is in this block.
const (
	geWAFMigration407Version         = 407
	geWAFMigration407ID              = "407_attack_alert_notifications"
	geWAFMigration407PreviousID      = geWAFMigration406ID
	geWAFMigration407PreviousUpSHA   = geWAFMigration406UpSHA
	geWAFMigration407PreviousDownSHA = geWAFMigration406DownSHA
	geWAFMigration407UpSHA           = "3699dae3fad2bf7db849a25af7a3409855028d1523e290a82ece978c3bafb99c"
	geWAFMigration407DownSHA         = "9627a9f65b75eab8c8a5102b6ffd6559147473d1706bb12a440ca28334e2f18b"
)

func TestAttackAlertNotifications407Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{geWAFMigration407ID + ".up.sql", geWAFMigration407UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", geWAFMigration407Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", geWAFMigration407Version-1),
			"migration_id='" + geWAFMigration407PreviousID + "'", geWAFMigration407PreviousUpSHA, geWAFMigration407PreviousDownSHA,
			"ERRCODE='P4070'", "'security.attack.detected'", "CREATE TABLE attack_alert_site_states",
		}},
		{geWAFMigration407ID + ".down.sql", geWAFMigration407DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", geWAFMigration407Version),
			"migration_id='" + geWAFMigration407ID + "'", "ERRCODE='P4071'", "ERRCODE='P4072'",
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
}
