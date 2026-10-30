package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

const (
	nodeLineGroupPlatformScopeDelete233UpSHA      = "81831602f2f93f107f8b350b1d2178e9231b320dcc1f979b03d265fcb1e50d85"
	nodeLineGroupPlatformScopeDelete233DownSHA    = "45a59232eedd4873336421cc53cc5c393e9258f666a0d9c7569fd1d03547bfce"
	nodeLineGroupPlatformScopeDelete233ParentUp   = "a034c7c7036d2af6be7fd99094d0ea938170339e0dc937db54a1c333973bfa0a"
	nodeLineGroupPlatformScopeDelete233ParentDown = "0e36532308868afb1f7b81f3ca6a0eb720ef8c303f6fb6d728ce7c01d0b703fc"
)

func TestNodeLineGroupPlatformScopeDelete233Contract(t *testing.T) {
	files := map[string]struct {
		name string
		sha  string
	}{
		"up":   {"233_node_line_group_platform_scope_delete.up.sql", nodeLineGroupPlatformScopeDelete233UpSHA},
		"down": {"233_node_line_group_platform_scope_delete.down.sql", nodeLineGroupPlatformScopeDelete233DownSHA},
	}
	contents := make(map[string]string, len(files))
	for label, file := range files {
		payload, err := FS.ReadFile(file.name)
		if err != nil {
			t.Fatalf("read migration 233 %s: %v", label, err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(payload)); got != file.sha {
			t.Fatalf("migration 233 %s checksum = %s, want %s", label, got, file.sha)
		}
		contents[label] = string(payload)
	}

	combined := contents["up"] + contents["down"]
	for _, required := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 232",
		"version = 232 AND migration_id = '232_active_config_identity_configuration_scope'",
		nodeLineGroupPlatformScopeDelete233ParentUp,
		nodeLineGroupPlatformScopeDelete233ParentDown,
		"ADD COLUMN deleted_at timestamptz",
		"ADD COLUMN deleted_by_user_id uuid",
		"FOREIGN KEY (tenant_scope_id, deleted_by_user_id)",
		"actual_kind NOT IN ('tenant', 'platform')",
		"WHERE deleted_at IS NULL",
		"'node_scheduling.group.delete'",
		"deleted node line groups are immutable",
		"node line group tombstone must preserve immutable configuration facts",
		"USING ERRCODE = 'P2330'",
		"version = 233 AND migration_id = '233_node_line_group_platform_scope_delete'",
		nodeLineGroupPlatformScopeDelete233UpSHA,
		"scope.kind <> 'tenant' OR line_group.deleted_at IS NOT NULL",
		"migration 233 rollback cannot represent platform or deleted node line groups",
		"USING ERRCODE = 'P2331'",
		"actual_kind IS DISTINCT FROM 'tenant'",
	} {
		if !strings.Contains(combined, required) {
			t.Errorf("migration 233 is missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"REVOKE ALL", "DELETE FROM schema_migrations", " CASCADE", "__UP_SHA256__", "__DOWN_SHA256__",
	} {
		if strings.Contains(strings.ToUpper(combined), strings.ToUpper(forbidden)) {
			t.Errorf("migration 233 contains forbidden token %q", forbidden)
		}
	}
	if guard, mutation := strings.Index(contents["down"], "migration 233 rollback requires the exact verified 233 head"),
		strings.Index(contents["down"], "CREATE OR REPLACE FUNCTION assert_node_scheduling_tenant_scope"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("migration 233 rollback guards must run before the first rollback mutation")
	}
}
