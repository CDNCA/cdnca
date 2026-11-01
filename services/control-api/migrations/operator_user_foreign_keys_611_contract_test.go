package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 611: the 12 (tenant_scope_id, operator) →
// memberships keys of 033/043/078/233/254 become operator → users(id); the
// member-or-platform-administrator rule moves to control_operator_on_scope_611.
// The 610 predecessor is pinned by checksum and every dropped key is restored
// by down.
const (
	migration611ID      = "611_operator_user_foreign_keys"
	migration610UpSHA   = "2f7d56ed175e4ec1570078d68a437d303546fb0b10d6c269bbfa1e2502bb6224"
	migration610DownSHA = "cbc597d071c5c4742f3a865a01096708d2b950be77a26f5c3501acc44911a8be"
)

var migration611OldKeys = []string{
	"node_line_groups_tenant_scope_id_created_by_user_id_fkey",
	"node_line_groups_tenant_scope_id_updated_by_user_id_fkey",
	"node_line_groups_deleted_actor_233_fk",
	"node_line_group_revisions_tenant_scope_id_created_by_user__fkey",
	"node_scheduling_write_request_tenant_scope_id_actor_user_i_fkey",
	"announcements_tenant_scope_id_created_by_user_id_fkey",
	"announcement_versions_tenant_scope_id_created_by_user_id_fkey",
	"announcement_write_requests_tenant_scope_id_actor_user_id_fkey",
	"package_monitor_policy_versio_tenant_scope_id_created_by_u_fkey",
	"announcement_archive_254_tenant_scope_id_changed_by_user_i_fkey",
	"announcement_archive_254_tenant_scope_id_archived_by_user__fkey",
	"announcement_lifecycle_facts__tenant_scope_id_actor_user_i_fkey",
}

func TestOperatorUserForeignKeys611Contract(t *testing.T) {
	read := func(name string) string {
		t.Helper()
		raw, err := FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	prevUp, prevDown := read("610_node_ssh_install_language.up.sql"), read("610_node_ssh_install_language.down.sql")
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(prevUp))); got != migration610UpSHA {
		t.Fatalf("610 up checksum drift: %s", got)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(prevDown))); got != migration610DownSHA {
		t.Fatalf("610 down checksum drift: %s", got)
	}
	up, down := read(migration611ID+".up.sql"), read(migration611ID+".down.sql")
	for _, required := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 610", "(SELECT max(version) FROM schema_migrations) <> 610",
		"migration_id='610_node_ssh_install_language'", "checksum_sha256='" + migration610UpSHA + "'",
		"down_checksum_sha256='" + migration610DownSHA + "'", "ERRCODE='P6110'", "ERRCODE = 'P6113'",
		"CREATE FUNCTION control_operator_on_scope_611()", "control_platform_admin_435(operator_id, NULL)",
		"REFERENCES users(id) ON DELETE RESTRICT",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("611 up missing %q", required)
		}
	}
	if strings.Contains(up, "REFERENCES memberships") {
		t.Error("611 up must not add a memberships key")
	}
	if n := strings.Count(up, "REFERENCES users(id) ON DELETE RESTRICT"); n != len(migration611OldKeys) {
		t.Errorf("611 up adds %d users keys, want %d", n, len(migration611OldKeys))
	}
	for _, key := range migration611OldKeys {
		if !strings.Contains(up, "DROP CONSTRAINT "+key) {
			t.Errorf("611 up does not drop %s", key)
		}
		if !strings.Contains(down, "ADD CONSTRAINT "+key+"\n") {
			t.Errorf("611 down does not restore %s", key)
		}
	}
	for _, required := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 611", "migration_id='" + migration611ID + "'",
		"ERRCODE='P6111'", "ERRCODE='P6112'", "DROP FUNCTION control_operator_on_scope_611()",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("611 down missing %q", required)
		}
	}
}
