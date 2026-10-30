package migrations

import (
	"strings"
	"testing"
)

// Migration 545: ban list entries may be networks.
// The 544 predecessor is pinned by checksum.
func TestSecurityBanNetworks545Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{"545_security_ban_networks.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 544", "(SELECT max(version) FROM schema_migrations) <> 544",
			"migration_id='544_official_rule_packs_enabled'",
			"checksum_sha256='5ba1918d362a5a27025cfb318084d64de4472dc6340590d0ddc72ce96ac1a997'",
			"down_checksum_sha256='2e09f9793be4ddb97f8b37ca32793d11ccb41fa274146d73cf45349ca50b0ab8'",
			"ERRCODE='P5450'", "DROP CONSTRAINT security_ban_entries_client_ip_check",
			"THEN 8 ELSE 32 END", "THEN 32 ELSE 128 END", "client_ip = network(client_ip)",
		}},
		{"545_security_ban_networks.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 545", "migration_id='545_security_ban_networks'",
			"ERRCODE='P5451'", "ERRCODE='P5452'", "DROP CONSTRAINT security_ban_entries_client_ip_545",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		for _, required := range script.required {
			if !strings.Contains(string(raw), required) {
				t.Errorf("%s missing %q", script.name, required)
			}
		}
	}
}
