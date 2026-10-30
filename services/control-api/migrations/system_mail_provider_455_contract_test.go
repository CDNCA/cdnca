package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 455 is a placeholder number; the merge
// renumbers it after the head it lands on. Everything that changes with the
// renumbering is here.
const (
	migration455Version         = 455
	migration455ID              = "455_system_mail_provider"
	migration455PreviousID      = "454_official_rule_pack_default_on"
	migration455PreviousUpSHA   = "69639d5375f465a4ab62f6152896b12a9fbbc7f7ee6ab43bc7d01b75e1364417"
	migration455PreviousDownSHA = "e70c492069624cabba009b0841025dedd6ca8a3ed304499d29b02c545aecc063"
	migration455UpSHA           = "2059ecff10cd7bac2ef831bf1bee5fb2980ae5ba90242d236949f34d677aab94"
	migration455DownSHA         = "7722d8106b1dbaddce80877208f0198317fc094bc29f2e6231669c9adb1ffd8c"
)

func TestSystemMailProvider455Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration455ID + ".up.sql", migration455UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration455Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration455Version-1),
			"migration_id='" + migration455PreviousID + "'", migration455PreviousUpSHA, migration455PreviousDownSHA,
			"ERRCODE='P4550'", "ADD COLUMN mail_secret_provider text CHECK (mail_secret_provider IS NULL OR mail_secret_provider IN ('aliyun', 'sendgrid'))",
			"platform_system_mail_settings_mail_secret_455", "ARRAY['dns', 'icp', 'mail', 'payment', 'sms']",
		}},
		{migration455ID + ".down.sql", migration455DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration455Version),
			"migration_id='" + migration455ID + "'", "ERRCODE='P4551'", "ERRCODE='P4552'",
			"ARRAY['dns', 'icp', 'payment', 'sms']",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Skipf("%s not embedded under this number (local renumbering): %v", script.name, err)
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
