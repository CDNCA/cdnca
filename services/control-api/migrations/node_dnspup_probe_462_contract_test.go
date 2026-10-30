package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 462 (dnspup checkpoints in node availability
// monitoring) is a placeholder number (reserved 462); the merge renumbers it
// after the head it lands on. Everything that changes with the renumbering
// is here.
const (
	migration462Version         = 462
	migration462ID              = "462_node_dnspup_probe"
	migration462PreviousID      = "461_ban_list_truncation"
	migration462PreviousUpSHA   = "382e5e63754dcd34c767fb8654ac7620ca60e0481a506bf69474562c2863e6a6"
	migration462PreviousDownSHA = "79e1d9f8840b9a0e79f16b11fce133c62b39ddc379beb42b1e172492e7d2380b"
	migration462UpSHA           = "bef82dc2fa73b6da7b1996f5017c5aeb666eedb60993ae9a5c70dfa874904fb3"
	migration462DownSHA         = "c841ad0ddcf7785eda6750e4ebdd81fbbafe1511cc8170c91692404557bc7c93"
)

func TestNodeDNSPupProbe462Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration462ID + ".up.sql", migration462UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration462Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration462Version-1),
			"migration_id='" + migration462PreviousID + "'", migration462PreviousUpSHA, migration462PreviousDownSHA,
			"ERRCODE='P4620'", "'node.dnspup.unreachable'", "'probe.dnspup.balance_exhausted.zh-cn'",
			"CREATE TABLE node_dnspup_probe_settings", "CREATE TABLE node_dnspup_probe_results",
			"CREATE TABLE node_dnspup_probe_states",
		}},
		{migration462ID + ".down.sql", migration462DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration462Version),
			"migration_id='" + migration462ID + "'", "ERRCODE='P4621'", "ERRCODE='P4622'",
			"DROP TABLE node_dnspup_probe_settings",
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
