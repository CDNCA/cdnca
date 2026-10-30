package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 336 (CC auto switch notifications) is a placeholder
// number: the merge renumbers it after the head it lands on. Everything that
// changes with the renumbering is in this block.
const (
	migration336Version         = 336
	migration336ID              = "336_cc_auto_switch_notifications"
	migration336PreviousID      = "335_site_runtime_observation_revision"
	migration336PreviousUpSHA   = "8efc7dc791cd6b1b104e43c4034fb33cca34586fa753db97c1a2f76d2476e431"
	migration336PreviousDownSHA = "fba9c2b6ff80501081631bdce6b08ff284734bdfe1f1fa38fe7aa16d803394f4"
	migration336UpSHA           = "6e34c6db1ba2d447b357d240e9bfc490b100f61e534062043d6a4fdcaeb7873e"
	migration336DownSHA         = "4796a65eba5dfc3787e7c9e8231f792e6ebbe52592b806af7bf17013b8ef7067"
)

func TestCCAutoSwitchNotifications336Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration336ID + ".up.sql", migration336UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration336Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration336Version-1),
			"migration_id='" + migration336PreviousID + "'", migration336PreviousUpSHA, migration336PreviousDownSHA,
			"ERRCODE='P3360'", "SET supported=true, enabled=true, sms_enabled=true, email_enabled=true, default_email=true",
			"('package.monitor.cc_rule_auto_switch.zh-cn', 1, 'sms'", "('package.monitor.cc_rule_auto_switch.zh-cn', 1, 'email'",
			"CREATE TABLE cc_auto_switch_notification_windows",
			"site_id uuid PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE",
		}},
		{migration336ID + ".down.sql", migration336DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration336Version),
			"migration_id='" + migration336ID + "'", "ERRCODE='P3361'", "ERRCODE='P3362'",
			"DROP TABLE cc_auto_switch_notification_windows",
			"DISABLE TRIGGER notification_templates_immutable", "ENABLE TRIGGER notification_templates_immutable",
			"SET supported=false, enabled=false, sms_enabled=false, email_enabled=false, default_email=false",
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
