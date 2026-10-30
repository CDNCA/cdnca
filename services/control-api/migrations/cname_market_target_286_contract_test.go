package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestCNAMEMarketTarget286Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{"286_cname_market_target.up.sql", "29a9ca3e22c23af8882814dc320d6dedd702a1e30191eba0afafd7374e2a51a8", []string{
			"(SELECT count(*) FROM schema_migrations) <> 285", "285_site_supply_binding", "675876fba0ec984412e09367a456ad6724fc9d10739af07b4d32bbe1a57b776a", "ERRCODE='P2860'",
			"ADD COLUMN target_cname", "DROP CONSTRAINT dns_cname_retargets_check",
			"NEW.target_cname", "OLD.target_cname", "DROP FUNCTION protect_dns_cname_retarget_280()",
		}},
		{"286_cname_market_target.down.sql", "2855a70ddbfd1b807f925a2c54d446078344aeff88c3345b38782d7d454e1b23", []string{
			"(SELECT count(*) FROM schema_migrations) <> 286", "286_cname_market_target",
			// Durable retarget facts are never dropped silently.
			"WHERE target_cname IS NOT NULL", "ERRCODE='P2861'", "DROP COLUMN target_cname",
			"CREATE FUNCTION protect_dns_cname_retarget_280()",
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
