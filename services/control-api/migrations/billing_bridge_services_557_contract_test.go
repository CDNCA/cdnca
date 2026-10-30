package migrations

import (
	"strings"
	"testing"
)

// Migration 557 (bb0405 placeholder, ADR 0019 BB-04/05): facade service and
// client mappings, write idempotency, single-use SSO tickets (digest only,
// 60 s) and plugin settings; the 556 predecessor is pinned by checksum.
func TestBillingBridgeServices557Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{"557_billing_bridge_services.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 556", "(SELECT max(version) FROM schema_migrations) <> 556",
			"migration_id='556_billing_bridge_keys'",
			"checksum_sha256='851befdf14743018f2b7dc90d28a6017b899fa00b5c4482871d72387820833c2'",
			"down_checksum_sha256='109233918232fd630a8ed6f86eb6dcecbda528507b14d025c69160eb30ec7e99'",
			"ERRCODE='P5570'", "ERRCODE='P5571'", "ERRCODE='P5572'", "ERRCODE='P5573'",
			"CREATE TABLE billing_bridge_clients", "PRIMARY KEY (owner_scope_id, external_system, external_client_id)",
			"CREATE TABLE billing_bridge_services", "UNIQUE (owner_scope_id, external_system, external_service_id)",
			"external_system IN ('whmcs', 'zjmf', 'zjmf_cbap')", "'^[!-~]{1,64}$'",
			"CREATE TABLE billing_bridge_requests", "CREATE TABLE billing_bridge_sso_tickets",
			"token_digest bytea PRIMARY KEY CHECK (octet_length(token_digest) = 32)",
			"expires_at <= created_at + interval '60 seconds'", "DEFERRABLE INITIALLY DEFERRED",
			"CREATE TABLE billing_bridge_settings", "sso_require_mfa boolean NOT NULL",
		}},
		{"557_billing_bridge_services.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 557", "migration_id='557_billing_bridge_services'",
			"ERRCODE='P5574'", "ERRCODE='P5575'", "DROP TABLE billing_bridge_services", "DROP TABLE billing_bridge_sso_tickets",
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
	up, _ := FS.ReadFile("557_billing_bridge_services.up.sql")
	for _, forbidden := range []string{"ticket text", "token text", "raw_token"} {
		if strings.Contains(string(up), forbidden) {
			t.Errorf("557 stores %q", forbidden)
		}
	}
}
