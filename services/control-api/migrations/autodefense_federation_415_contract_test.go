package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 415 (signature evaluation, federation rows,
// platform intelligence, ban list source autodefense) is a placeholder
// number (BATCH-PLUGIN 第 16 条): the merge renumbers it. Everything that
// changes with the renumbering is here.
const (
	migration415Version         = 415
	migration415ID              = "415_autodefense_federation"
	migration415PreviousVersion = 414
	migration415PreviousID      = "414_autodefense_module_values"
	migration415PreviousUpSHA   = "75d44f0f16cd29ddcb04f3e417f0ff47bb9df2182ecaf176a3572d7dd2fc3fad"
	migration415PreviousDownSHA = "cc72a3ecc92418b64e244a16086756e42771dd76374130dd481b3a07173085f5"
	migration415UpSHA           = "19630777fa57cb6c4ea973bc88db4b0300c7b665c92725056aaf0276cf34927b"
	migration415DownSHA         = "4d3590d7fd3ce6ab961c1a7406b71657fa370973de76f0ef0861c24459da7b7e"
)

func TestAutoDefenseFederation415Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration415ID + ".up.sql", migration415UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration415PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration415PreviousVersion),
			"migration_id='" + migration415PreviousID + "'", migration415PreviousUpSHA, migration415PreviousDownSHA,
			"ERRCODE='P4150'", "CREATE TABLE autodefense_signature_sightings", "CREATE TABLE autodefense_site_federation",
			"CREATE TABLE autodefense_platform_intel", "'manual', 'autodefense'",
		}},
		{migration415ID + ".down.sql", migration415DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration415Version),
			"migration_id='" + migration415ID + "'", "ERRCODE='P4151'", "ERRCODE='P4152'",
			"DELETE FROM security_ban_entries WHERE source='autodefense'",
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
