package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestMarketBuyer296Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{"296_market_buyer.up.sql", "6a8d7b946285732f64191ffb4c11f8eda5b31f3b40dae0937f8361a347910b65", []string{
			"(SELECT count(*) FROM schema_migrations) <> 295", "295_config_version_telemetry_site_bindings",
			"e58da204e315ca5c377f33e6db12857e74b89b313cd487d42f8a52969c1ca275", "ERRCODE='P2960'",
			"'marketplace.browse'", "'marketplace.purchase'", "'marketplace.sell'",
			"role.name IN ('platform_owner', 'platform_admin')",
			"CREATE TABLE plugin_security_advisories", "CREATE TABLE plugin_security_advisory_acks",
			"PRIMARY KEY (advisory_id, scope_id)", "ERRCODE='P2961'",
		}},
		{"296_market_buyer.down.sql", "8fbc7c1c7a40d8e8b8c7104c396a67043866662ed4158fd3ebeaf7f6f704d52b", []string{
			"(SELECT count(*) FROM schema_migrations) <> 296", "296_market_buyer", "ERRCODE='P2962'",
			// Buyer facts are never dropped silently.
			"EXISTS (SELECT 1 FROM plugin_security_advisory_acks)", "ERRCODE='P2963'",
			"DROP TABLE plugin_security_advisory_acks",
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
