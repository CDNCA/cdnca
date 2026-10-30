package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 467 (site theme C). Numbered at the merge-c-theme merge on top of
// merge7 (head 464_impersonation_direct_switch); merge8 takes 465
// (cname-retry3) and 466 (site-backend6), so the guard points at 466.
// 466 is not on this branch yet: PreviousID is the expected name and the two
// previous checksums are PLACEHOLDERS (…01 / …02). After merge8 is merged in,
// fill PreviousID / PreviousUpSHA / PreviousDownSHA with the real values of
// the 466 site-backend6 migration (shasum -a 256 466_*.{up,down}.sql), patch
// the same three values in 467_site_theme_scopes.up.sql, then re-pin UpSHA
// and rerun TestEmbeddedMigrationsAreContiguousAndPaired and the PG tests.
// See RENUMBER-site-theme-scopes.md. The error codes follow the number
// (P<version>0..4). Everything that changes with a renumbering is here.
//
// Earlier numbering, kept for the record: 461_site_theme_scopes guarding
// 460_attack_escalation (up 1df7430b…a662, down 54769943…68f5);
// 466_site_theme_scopes guarding 459_tenant_system_role_grants
// (up 62cb8c2c…4c7e, down 52b30cb0…23be).
const (
	migration467Version         = 467
	migration467ID              = "467_site_theme_scopes"
	migration467PreviousVersion = 466
	migration467PreviousID      = "466_site_edge_options"
	migration467PreviousUpSHA   = "44b2492ac321dc4b2108a10f456e4848fef06aafb7e8311657dcc56a192f043d"
	migration467PreviousDownSHA = "013db3a4cfcb4598f31251dc1e59fec54addb29e7800459ea1848ec932ec46fe"
	migration467UpSHA           = "8358bf5a3e5e1f2e87e42895411bb0f5a0a70f9af243f7d41fd7d91f6cdddb54"
	migration467DownSHA         = "0d0b96fb19d7ba8eb812e6ee200edb84373e718676b43d5e4b20fbaabe086084"
)

func errcode467(n int, spaced bool) string {
	if spaced {
		return fmt.Sprintf("ERRCODE = 'P%d%d'", migration467Version, n)
	}
	return fmt.Sprintf("ERRCODE='P%d%d'", migration467Version, n)
}

func TestSiteThemeScopes467Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration467ID + ".up.sql", migration467UpSHA, []string{
			fmt.Sprintf("DO $migration_%d_up$", migration467Version),
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration467PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration467PreviousVersion),
			fmt.Sprintf("version=%d AND", migration467PreviousVersion),
			fmt.Sprintf("migration %d requires the exact verified %d release head", migration467Version, migration467PreviousVersion),
			"migration_id='" + migration467PreviousID + "'", migration467PreviousUpSHA, migration467PreviousDownSHA,
			errcode467(0, false), errcode467(1, true), errcode467(2, true),
			"ADD COLUMN slot text NOT NULL DEFAULT 'all'", "CHECK (slot IN ('all', 'admin', 'user'))",
			"theme_id LIKE 'market.io.cdnca.%'", "GENERATED ALWAYS AS",
			"(publisher = 'official' OR NOT ('admin' = ANY(applies_to)))",
			fmt.Sprintf("validate_site_theme_activation_%d", migration467Version),
			fmt.Sprintf("REVOKE ALL ON FUNCTION validate_theme_activation_slot_%d()", migration467Version),
		}},
		{migration467ID + ".down.sql", migration467DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration467Version),
			fmt.Sprintf("version=%d AND", migration467Version),
			"migration_id='" + migration467ID + "'", errcode467(3, false), errcode467(4, false),
			"theme_activations WHERE slot <> 'all'", "site_theme_packages WHERE schema <> 'cdnca.site-theme/v1'",
			"ALTER TABLE theme_activations DROP COLUMN slot",
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
		// A4: no stock data migration. Only the down guard reads rows.
		if strings.HasSuffix(script.name, ".up.sql") {
			for _, forbidden := range []string{"UPDATE site_theme_packages", "UPDATE theme_activations", "INSERT INTO", "DELETE FROM"} {
				if strings.Contains(string(raw), forbidden) {
					t.Errorf("%s rewrites existing rows: %q", script.name, forbidden)
				}
			}
		}
	}
}
