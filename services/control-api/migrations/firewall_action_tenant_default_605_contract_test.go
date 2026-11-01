package migrations

import (
	"bytes"
	"testing"
)

func TestFirewallActionTenantDefault605Contract(t *testing.T) {
	up, err := FS.ReadFile("605_firewall_action_tenant_default.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := FS.ReadFile("605_firewall_action_tenant_default.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	guard := bytes.Index(up, []byte("migration 605 requires the exact verified 604 release head"))
	mutation := bytes.Index(up, []byte("CREATE TABLE"))
	if guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("605 guard must precede every mutation")
	}
	for _, required := range [][]byte{
		[]byte("migration_id='604_api_key_plugin_installation'"),
		[]byte("CREATE TABLE firewall_action_tenant_defaults"),
		[]byte("CREATE TABLE firewall_action_tenant_default_revisions"),
		[]byte("CREATE TABLE firewall_action_tenant_default_receipts"),
		[]byte("must advance one revision at a time"),
		[]byte("CHECK(inherited=(document='{}'::jsonb))"),
		[]byte("REFERENCES firewall_action_policy_revisions(tenant_scope_id,site_id,policy_id,revision,inherited)"),
		[]byte("inherited firewall action revisions are not published"),
		[]byte("prevent_firewall_action_fact_mutation_174()"),
	} {
		if !bytes.Contains(up, required) {
			t.Fatalf("up migration missing %q", required)
		}
	}
	for _, required := range [][]byte{
		[]byte("migration 605 down requires the exact verified migration head"),
		[]byte("migration 605 down would discard firewall action default facts"),
		[]byte("DROP TABLE firewall_action_tenant_defaults"),
		[]byte("DROP COLUMN inherited"),
	} {
		if !bytes.Contains(down, required) {
			t.Fatalf("down migration missing %q", required)
		}
	}
	if bytes.Contains(down, []byte("DELETE FROM")) {
		t.Fatal("rollback must refuse instead of deleting facts")
	}
}
