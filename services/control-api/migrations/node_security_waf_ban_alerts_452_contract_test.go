package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 452 (WAF automatic bans in the notification
// center) is a placeholder number; the merge renumbers it after the head it
// lands on. Everything that changes with the renumbering is here.
const (
	migration452Version         = 452
	migration452ID              = "452_node_security_waf_ban_alerts"
	migration452PreviousID      = "451_security_ip_lists"
	migration452PreviousUpSHA   = "c36630cb599f465559434e1f8b2c0c72c99b7c19b3e591c36c9f76ae0a12fef5"
	migration452PreviousDownSHA = "2d1e3167789dabf7c6ba950e06f82f7b4ebdadd96b7c7043aba818674af40477"
	migration452UpSHA           = "4edf8710fbeb0e36b55fe8790d0929e1075d05e50890871abeb0ccc585599617"
	migration452DownSHA         = "4e4cd71ee8088a8cf4732be4d4494d0efd4df2209396f25399affbff69f30507"
)

func TestNodeSecurityWAFBanAlerts452Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration452ID + ".up.sql", migration452UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration452Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration452Version-1),
			"migration_id='" + migration452PreviousID + "'", migration452PreviousUpSHA, migration452PreviousDownSHA,
			"ERRCODE='P4520'", "'node.security.waf_ban'", "'node.security.waf_ban.zh-cn'",
		}},
		{migration452ID + ".down.sql", migration452DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration452Version),
			"migration_id='" + migration452ID + "'", "ERRCODE='P4521'", "ERRCODE='P4522'",
			"'node.security.waf_ban.zh-cn'",
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
