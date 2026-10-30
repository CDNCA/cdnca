package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 373 (PA-26 white-label themes) follows 372_market_data_packs.
// Everything that changes with a renumbering is in this block.
const (
	migration373Version         = 373
	migration373ID              = "373_theme_tenant_whitelabel"
	migration373PreviousVersion = 372
	migration373PreviousID      = "372_market_data_packs"
	migration373PreviousUpSHA   = "fb96f7ce4d0ee1f212339007e8ce20359a395959d130c0b02a2cd7cc00170049"
	migration373PreviousDownSHA = "79e46e119c37ce5133e30cd99b3ad7a60d96711f7b97dd10ffcd131112edc941"
	migration373UpSHA           = "bb6678b98976f84ec4c18697bd2cee84f75a604d6809359c7f5731c251c529e7"
	migration373DownSHA         = "d20e3f4d63eb38883d389ee4061746c5846a66a9ee2e30854a679cb1639398a3"
)

func TestThemeTenantWhitelabel373Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration373ID + ".up.sql", migration373UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration373PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration373PreviousVersion),
			"migration_id='" + migration373PreviousID + "'", migration373PreviousUpSHA, migration373PreviousDownSHA,
			"ERRCODE='P3730'", "'tenant_theme.manage'", "CREATE TABLE theme_tenant_policy",
			"CREATE TABLE theme_tenant_settings", "CREATE TABLE theme_tenant_domains",
			"selection_mode IN ('inherit', 'allow', 'deny')", "package_assigned_by IN ('platform', 'tenant')",
			"ERRCODE = 'P3731'", "ERRCODE = 'P3732'", "ERRCODE = 'P3733'", "ERRCODE = 'P3734'", "ERRCODE = 'P3735'",
			"roles_tenant_owner_theme_373", "REVOKE ALL ON theme_tenant_policy", "TO cdnca_control_runtime",
		}},
		{migration373ID + ".down.sql", migration373DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration373Version),
			"migration_id='" + migration373ID + "'", "ERRCODE='P3736'", "ERRCODE='P3737'",
			"DROP TABLE theme_tenant_settings", "DELETE FROM permissions WHERE name = 'tenant_theme.manage'",
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
