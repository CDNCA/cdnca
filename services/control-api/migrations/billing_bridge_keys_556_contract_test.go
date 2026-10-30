package migrations

import (
	"strings"
	"testing"
)

// Migration 556 (bb0102 placeholder, ADR 0019 BB-02): billing bridge keys,
// nonces and call logs, owner guard (P5560–P5566) and billing_bridge.manage
// for the platform owner. The 555 predecessor is pinned by checksum.
func TestBillingBridgeKeys556Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{"556_billing_bridge_keys.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 555", "(SELECT max(version) FROM schema_migrations) <> 555",
			"migration_id='555_subscription_suspension_reseller_change'",
			"checksum_sha256='64e3ad1ac6f92d098cb9ceff562d8f30040ab8e45f4cbd949e961a67bf6fb071'",
			"down_checksum_sha256='f37b4b2e833f40dbb8455514695b4b1b1d20c31c68b5736f86d3c138e4c83ad9'",
			"ERRCODE='P5560'", "ERRCODE='P5561'", "ERRCODE='P5562'", "ERRCODE='P5563'", "ERRCODE='P5564'",
			"CREATE TABLE billing_bridge_keys", "key_id text NOT NULL UNIQUE CHECK (key_id ~ '^cbb_[A-Za-z0-9_-]{22}$')",
			"secret_seed bytea NOT NULL", "ip_allowlist cidr[] NOT NULL", "owner_kind IN ('platform', 'reseller')",
			"reseller_scope_active_480(NEW.owner_scope_id)", "CREATE TABLE billing_bridge_nonces",
			"PRIMARY KEY (key_id, nonce)", "billing_bridge_nonces_seen_556_idx", "CREATE TABLE billing_bridge_logs",
			"'billing_bridge.manage'", "role.name = 'platform_owner'",
		}},
		{"556_billing_bridge_keys.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 556", "migration_id='556_billing_bridge_keys'",
			"ERRCODE='P5565'", "ERRCODE='P5566'", "DROP TABLE billing_bridge_keys", "DELETE FROM permissions WHERE name = 'billing_bridge.manage'",
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
	up, _ := FS.ReadFile("556_billing_bridge_keys.up.sql")
	for _, forbidden := range []string{"secret_digest", "secret text", "secret_plain"} {
		if strings.Contains(string(up), forbidden) {
			t.Errorf("556 stores %q", forbidden)
		}
	}
}
