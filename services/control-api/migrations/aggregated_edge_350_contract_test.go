package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 350 (aggregated edge accounts and
// third-party CDN supplies) is a placeholder number: the merge renumbers it
// after the head it lands on. Everything that changes with the renumbering
// is in this block.
const (
	migration350Version         = 350
	migration350ID              = "350_aggregated_edge"
	migration350PreviousID      = "349_rule_packs"
	migration350PreviousUpSHA   = "ba2acf69a0296766ac6d7538824677d784bf39c536abcca884b041e4a5aab0a8"
	migration350PreviousDownSHA = "cae1167cd408935a65269841290108990acb984ee6e428bb368147ab82fadb75"
	migration350UpSHA           = "f25689a94b20c9f8f6286e2095b0831bbf11c6eb3a17326d1f6674cd3d65f9cf"
	migration350DownSHA         = "0fe195c37967496d268c4d643badab6bea184c61140d650d178e40eced3495d2"
)

func TestAggregatedEdge350Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration350ID + ".up.sql", migration350UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration350Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration350Version-1),
			"migration_id='" + migration350PreviousID + "'", migration350PreviousUpSHA, migration350PreviousDownSHA,
			"ERRCODE='P3500'", "ERRCODE='P3502'", "'edge.aggregated.manage'",
			"CREATE TABLE cdn_provider_accounts", "credential_ciphertext bytea NOT NULL",
			"CREATE TRIGGER cdn_provider_account_credential_fence_350",
			"CREATE TABLE site_supply_cdn_configs", "REFERENCES site_supplies(id)",
			"CREATE TABLE site_supply_cdn_sites", "CREATE TABLE site_supply_cdn_resources",
			"CREATE TABLE aggregated_edge_runtime",
			"REVOKE ALL ON FUNCTION cdn_provider_account_credential_fence_350() FROM PUBLIC",
		}},
		{migration350ID + ".down.sql", migration350DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration350Version),
			"migration_id='" + migration350ID + "'", "ERRCODE='P3501'", "ERRCODE='P3503'",
			"DROP TABLE cdn_provider_accounts", "DELETE FROM permissions WHERE name = 'edge.aggregated.manage'",
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
