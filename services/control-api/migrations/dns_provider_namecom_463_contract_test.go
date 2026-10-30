package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 463 (built-in DNS provider name.com) is a
// placeholder number (预留 control 463): the merge renumbers it.
// Everything that changes with the renumbering is here.
const (
	migration463Version         = 463
	migration463ID              = "463_dns_provider_namecom"
	migration463PreviousVersion = 462
	migration463PreviousID      = "462_node_dnspup_probe"
	migration463PreviousUpSHA   = "bef82dc2fa73b6da7b1996f5017c5aeb666eedb60993ae9a5c70dfa874904fb3"
	migration463PreviousDownSHA = "c841ad0ddcf7785eda6750e4ebdd81fbbafe1511cc8170c91692404557bc7c93"
	migration463UpSHA           = "b3bb9cdf50b04f0e4ade41ec6d00550b173f8e20ff8a6b9583e46316403b8434"
	migration463DownSHA         = "079e199db4b99bbb307c2db9a70a3b8e35b0ec442df0c7970d056bbd4a8d4487"
)

func TestDNSProviderNameCom463Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration463ID + ".up.sql", migration463UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration463PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration463PreviousVersion),
			"migration_id='" + migration463PreviousID + "'", migration463PreviousUpSHA, migration463PreviousDownSHA,
			"ERRCODE='P4630'", "DROP CONSTRAINT dns_providers_provider_type_check",
			"'custom_http', 'plugin',\n        'namecom')",
		}},
		{migration463ID + ".down.sql", migration463DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration463Version),
			"migration_id='" + migration463ID + "'", "ERRCODE='P4631'", "ERRCODE='P4632'",
			"WHERE provider_type = 'namecom'", "'dns_la', 'custom_http', 'plugin')",
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
