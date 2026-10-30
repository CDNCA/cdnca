package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 530 (dispatched 536, written 530 for the contiguous
// loader — renumber/repin at merge): notification center event
// installation_ban.rejected (policy plus zh-cn SMS / email templates).
const (
	migration530Version         = 530
	migration530ID              = "530_installation_ban_rejected_notice"
	migration530PreviousID      = "529_installation_ban_node_delivery"
	migration530PreviousUpSHA   = "0c79b3aecee927617617c8e682e867a06bdf3a7bb9f5343a4ea69ef3e0ba1e97"
	migration530PreviousDownSHA = "177625b0ac94bb6dfebfa0b2cfbaacd54ca0b86ef503601a221993332ec14ca0"
	migration530UpSHA           = "018fa04ca61d86e61d93af9d31a1bd59eeff5ec99c49e561e2660d7074373e5b"
	migration530DownSHA         = "f480e877472a5f6dbe432723530b50827d79c1be502bbb8be6e0478babf7658b"
)

func TestInstallationBanRejectedNotice530Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration530ID + ".up.sql", migration530UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration530Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration530Version-1),
			"migration_id='" + migration530PreviousID + "'", migration530PreviousUpSHA, migration530PreviousDownSHA,
			"ERRCODE='P5300'", "VALUES ('installation_ban.rejected', true, true, true, 1, 1, true, true, false, now())",
			"('installation_ban.rejected.zh-cn', 1, 'sms', ''", "('installation_ban.rejected.zh-cn', 1, 'email',",
			"ARRAY['node_name','revision']", "ARRAY['node_name','node_ip','revision','reason','occurred_at']",
		}},
		{migration530ID + ".down.sql", migration530DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration530Version),
			"migration_id='" + migration530ID + "'", "ERRCODE='P5301'", "ERRCODE='P5302'",
			"DELETE FROM notification_event_policies WHERE event_type = 'installation_ban.rejected'",
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
