package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 429（waf_adapt.read/manage 权限码与驳回原因码）是占位号（预留 432）：
// 合入时统一改号，随改号变化的内容都集中在这里。
const (
	wafAdaptPermissionsMigrationVersion         = 429
	wafAdaptPermissionsMigrationID              = "429_waf_adapt_permissions"
	wafAdaptPermissionsMigrationPreviousVersion = 428
	wafAdaptPermissionsMigrationPreviousID      = migration428ID
	wafAdaptPermissionsMigrationPreviousUpSHA   = migration428UpSHA
	wafAdaptPermissionsMigrationPreviousDownSHA = migration428DownSHA
	wafAdaptPermissionsMigrationUpSHA           = "ea7538057b5aab098b210bcbc8917e6e1a06eaa042d1096a096f963467643aa1"
	wafAdaptPermissionsMigrationDownSHA         = "120f1748313304637252bcb01f89bffc147635e0c152d0f3381021cb0a3ccfcb"
)

func TestWAFAdaptPermissionsContract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{wafAdaptPermissionsMigrationID + ".up.sql", wafAdaptPermissionsMigrationUpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", wafAdaptPermissionsMigrationPreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", wafAdaptPermissionsMigrationPreviousVersion),
			"migration_id='" + wafAdaptPermissionsMigrationPreviousID + "'", wafAdaptPermissionsMigrationPreviousUpSHA,
			wafAdaptPermissionsMigrationPreviousDownSHA, "ERRCODE='P4290'",
			"('waf_adapt.manage', true)", "CREATE TRIGGER roles_waf_adapt_permissions_429", "ADD COLUMN reject_reason",
		}},
		{wafAdaptPermissionsMigrationID + ".down.sql", wafAdaptPermissionsMigrationDownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", wafAdaptPermissionsMigrationVersion),
			"migration_id='" + wafAdaptPermissionsMigrationID + "'", "ERRCODE='P4291'", "ERRCODE='P4292'",
			"DROP COLUMN reject_reason",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Skipf("%s not embedded under this number (local renumbering): %v", script.name, err)
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
	// tenant_viewer gets waf_adapt.read through the 094 guard's *.read rule:
	// neither script redefines the system role guard (no per-permission exception).
	for _, name := range []string{wafAdaptPermissionsMigrationID + ".up.sql", wafAdaptPermissionsMigrationID + ".down.sql"} {
		raw, _ := FS.ReadFile(name)
		if strings.Contains(string(raw), "FUNCTION guard_system_role_permission_mutation") {
			t.Fatalf("%s redefines guard_system_role_permission_mutation", name)
		}
	}
}
