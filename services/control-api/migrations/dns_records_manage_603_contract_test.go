package migrations

import (
	"strings"
	"testing"
)

// Migration 603 (plugapi-S1, scheduler reserved control 603): dns.records.manage
// lets a tenant API key write DNS hub records without the DNS account
// credentials dns.manage also covers. Predecessor 602 is pinned by checksum;
// the backfill and the trigger only add the grant, and down removes it only
// when no custom role or API key still holds it.
func TestDNSRecordsManage603Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{"603_dns_records_manage_permission.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 602", "(SELECT max(version) FROM schema_migrations) <> 602",
			"migration_id='602_url_auth_legacy_marker'",
			"checksum_sha256='4ebaa480871895f61c02b8a6fa4862ef2898184797441403bbc0d37fa513a57b'",
			"down_checksum_sha256='36e4c801af3b722cbbbff8de5e5d7d8171e8731b7337baf606543a25278f4a59'",
			"ERRCODE='P6030'",
			"INSERT INTO permissions(name, description) VALUES\n    ('dns.records.manage'",
			"INSERT INTO custom_rbac_permission_catalog(permission_name, step_up_required) VALUES\n    ('dns.records.manage', false)",
			"held.permission_name = 'dns.manage'",
			"CREATE TRIGGER roles_tenant_dns_records_manage_603",
			"NEW.name <> 'tenant_owner'",
		}},
		{"603_dns_records_manage_permission.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 603", "migration_id='603_dns_records_manage_permission'",
			"ERRCODE='P6031'", "ERRCODE='P6032'", "'dns.records.manage' = ANY(scopes)",
			"DROP TRIGGER roles_tenant_dns_records_manage_603 ON roles",
			"DELETE FROM permissions WHERE name = 'dns.records.manage'",
		}},
	} {
		body, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		for _, fragment := range script.required {
			if !strings.Contains(string(body), fragment) {
				t.Errorf("%s missing %q", script.name, fragment)
			}
		}
	}
}
