package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 521 (the unread 136 site protocol batch tables
// are dropped; the batch page writes the 515 site columns; the merge also
// drops the site_protocols.read/manage permissions). Branch placeholder 550,
// renumbered to 521 behind 520 at merge.
const (
	migration521Version         = 521
	migration521ID              = "521_site_protocol_batch_drop"
	migration521PreviousVersion = 520
	migration521PreviousID      = "520_site_tls_custom_cipher_suites"
	migration521PreviousUpSHA   = "c4459582720eb002b6c2dd65a3685c6c36e2c090f9b91ab22f07fee22e9a9247"
	migration521PreviousDownSHA = "6f4c66fd0916c0c04c0ed5f8d33552cdea250f52ed5033bbee83e5834abe12c7"
	migration521UpSHA           = "209c85d996838d9659529214b46ad4c66cdc77e9471aa25e3b9131d628ee6a61"
	migration521DownSHA         = "99ccc20dce56fa2e9944e0721bfa41a2653a8f83b91e049686601ca362f942d7"
)

var siteProtocolTables521 = []string{
	"site_protocol_batches", "site_protocol_states", "site_protocol_batch_items", "site_protocol_jobs",
	"site_protocol_node_results", "site_protocol_write_requests", "site_protocol_outbox", "site_protocol_audit_events",
}

func TestSiteProtocolBatchDrop521Contract(t *testing.T) {
	up := readMigration521(t, migration521ID+".up.sql", migration521UpSHA)
	down := readMigration521(t, migration521ID+".down.sql", migration521DownSHA)
	for _, required := range []string{
		fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration521PreviousVersion),
		"migration_id='" + migration521PreviousID + "'", migration521PreviousUpSHA, migration521PreviousDownSHA,
		"ERRCODE='P5210'", "DROP FUNCTION validate_site_protocol_scope_136();",
		"DROP TRIGGER site_protocol_node_results_guard_136_del ON site_protocol_node_results;",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("up missing %q", required)
		}
	}
	for _, required := range []string{
		fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration521Version),
		"migration_id='" + migration521ID + "'", "ERRCODE='P5211'",
		// as left by 284 (node purge) and 319 (per-table scope branches)
		"node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,",
		"WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION guard_site_protocol_node_result_136();",
		"ELSIF TG_TABLE_NAME='site_protocol_node_results' THEN",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("down missing %q", required)
		}
	}
	for _, table := range siteProtocolTables521 {
		if !strings.Contains(up, "DROP TABLE "+table+";") || !strings.Contains(down, "CREATE TABLE "+table+" (") {
			t.Errorf("%s not dropped and restored", table)
		}
	}
	// The site_protocols permissions go too, in
	// order: the system role grants, then the 136 grant trigger and function,
	// then the catalog and the permission rows; custom roles holding them
	// refuse the migration. down restores the 136 rows and trigger.
	upOrder := []string{
		"ERRCODE='P5212'",
		"ALTER TABLE role_permissions DISABLE TRIGGER role_permissions_system_role_guard;",
		"DELETE FROM role_permissions WHERE permission_name IN ('site_protocols.read','site_protocols.manage');",
		"ALTER TABLE role_permissions ENABLE TRIGGER role_permissions_system_role_guard;",
		"DROP TRIGGER roles_site_protocol_permissions_136 ON roles;",
		"DROP FUNCTION grant_site_protocol_permissions_136();",
		"DELETE FROM custom_rbac_permission_catalog WHERE permission_name IN ('site_protocols.read','site_protocols.manage');",
		"DELETE FROM permissions WHERE name IN ('site_protocols.read','site_protocols.manage');",
	}
	last := -1
	for _, step := range upOrder {
		index := strings.Index(up, step)
		if index <= last {
			t.Fatalf("up permission removal step %q missing or out of order", step)
		}
		last = index
	}
	if !strings.Contains(up, "custom_role_revisions") {
		t.Error("up does not check custom role revisions before dropping the permissions")
	}
	for _, required := range []string{
		"('site_protocols.read','Read persisted website protocol batches and node results')",
		"('site_protocols.read',false),('site_protocols.manage',false);",
		"CREATE TRIGGER roles_site_protocol_permissions_136 AFTER INSERT ON roles",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("down missing %q", required)
		}
	}
	for _, script := range []string{up, down} {
		if strings.Contains(script, "CASCADE;") {
			t.Error("521 must not cascade")
		}
	}
}

func readMigration521(t *testing.T, name, sha string) string {
	t.Helper()
	raw, err := FS.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != sha {
		t.Fatalf("%s checksum drift: %s", name, got)
	}
	return string(raw)
}
