package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 339 (CRS rule catalog updates republish
// published scopes, trigger rule_catalog) is a placeholder number: the merge
// renumbers it after the head it lands on. Everything that changes with the
// renumbering is in this block.
const (
	migration339Version         = 339
	migration339ID              = "339_security_rule_catalog_republication"
	migration339PreviousID      = "338_traffic_package_coverage_wake"
	migration339PreviousUpSHA   = "3e612e89e79c7d6e421a2d176ff3c11fe83da6812bdc96fad2c36b23464ad9ed"
	migration339PreviousDownSHA = "361868f603b6970a9ad1069c9f7cce04b57c8fae6da50c52c903f47c1047bd43"
	migration339UpSHA           = "9fa371339d29ea5ec41e6337d0291a8037185c6e0b7c39842753bd337626a310"
	migration339DownSHA         = "31acae1731a07cf53a9dd0a3f20bf32ab212d4616bdb972d78996448abe9ff45"
)

func TestSecurityRuleCatalogRepublication339Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration339ID + ".up.sql", migration339UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration339Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration339Version-1),
			"migration_id='" + migration339PreviousID + "'", migration339PreviousUpSHA, migration339PreviousDownSHA,
			"ERRCODE='P3390'", "'secondary_verification', 'rule_catalog']::text[]", "cardinality(triggers) BETWEEN 1 AND 7",
			"'domain_ownership', 'secondary_verification', 'rule_catalog'));",
			"'node_capability', 'rule_catalog')),", "'security_rule_catalog.updated')),", "'catalog_changed')),",
			"(source_kind = 'rule_catalog' AND permission_name = 'sites.manage' AND reason = 'catalog_changed' AND\n" +
				"         operation = 'security_rule_catalog.updated' AND source_resource_id IS NOT NULL)",
		}},
		{migration339ID + ".down.sql", migration339DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration339Version),
			"migration_id='" + migration339ID + "'", "ERRCODE='P3391'",
			"WHERE source_kind = 'rule_catalog'", "cardinality(triggers) BETWEEN 1 AND 6",
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
