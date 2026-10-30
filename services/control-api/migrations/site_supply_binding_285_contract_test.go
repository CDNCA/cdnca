package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestSiteSupplyBinding285Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
		forbidden []string
	}{
		{"285_site_supply_binding.up.sql", "675876fba0ec984412e09367a456ad6724fc9d10739af07b4d32bbe1a57b776a", []string{
			"(SELECT count(*) FROM schema_migrations) <> 284", "284_node_purge", "ERRCODE='P2850'",
			"CREATE TABLE site_supplies", "CREATE TABLE site_supply_bindings", "CREATE VIEW site_supply_bindings_effective",
		}, []string{
			// Local node groups are derived, never copied: a copy could drift from sites.node_group_id.
			"INSERT INTO site_supply_bindings", "ALTER TABLE sites", "CREATE TRIGGER",
		}},
		{"285_site_supply_binding.down.sql", "1cfbe5ea8bd87748d941fe2f5e713a3583644b6d3471b5dffbefd49557089446", []string{
			"(SELECT count(*) FROM schema_migrations) <> 285", "285_site_supply_binding", "DROP TABLE site_supplies",
		}, []string{"ALTER TABLE sites"}},
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
		for _, forbidden := range script.forbidden {
			if strings.Contains(string(raw), forbidden) {
				t.Errorf("%s must not contain %q", script.name, forbidden)
			}
		}
	}
}
