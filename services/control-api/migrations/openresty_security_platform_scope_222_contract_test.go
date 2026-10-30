package migrations

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

const (
	migration221UpSHA222   = "f15a1d7c1f22e2dd5e42032d386399791c000d3b7fed63bfcc2359e111d7b51a"
	migration221DownSHA222 = "40c91bbd390cf9d19ccba4dc3c948ea83ca4cc7a2551b67ebf49e7cf76966fc3"
	migration222UpSHA      = "9608c52faf69e6ef329dd57e752727c6e83880b6091c88437c5277bcae16f2fc"
	migration222DownSHA    = "dab33f6c9a728f05872b856f3e6f6788de49fd30dfc2af0ed8976b0915525b13"
)

func TestOpenRestySecurityPlatformScope222Contract(t *testing.T) {
	predecessorUp := readOpenRestySecurityScopeMigration(t, "221_tenant_display_ids.up.sql")
	predecessorDown := readOpenRestySecurityScopeMigration(t, "221_tenant_display_ids.down.sql")
	up := readOpenRestySecurityScopeMigration(t, "222_openresty_security_platform_scope.up.sql")
	down := readOpenRestySecurityScopeMigration(t, "222_openresty_security_platform_scope.down.sql")

	for name, check := range map[string]struct {
		payload []byte
		want    string
	}{
		"221 up": {predecessorUp, migration221UpSHA222}, "221 down": {predecessorDown, migration221DownSHA222},
		"222 up": {up, migration222UpSHA}, "222 down": {down, migration222DownSHA},
	} {
		if got := openRestySecurityScopeMigrationSHA(check.payload); got != check.want {
			t.Fatalf("migration %s checksum = %s, want %s", name, got, check.want)
		}
	}

	for _, required := range []string{
		"LOCK TABLE schema_migrations, permissions, access_scopes, roles, role_permissions IN ACCESS EXCLUSIVE MODE",
		"(SELECT count(*) FROM schema_migrations) <> 221",
		"(SELECT max(version) FROM schema_migrations) <> 221",
		"version = 221 AND migration_id = '221_tenant_display_ids'",
		"checksum_sha256 = '" + migration221UpSHA222 + "'",
		"down_checksum_sha256 = '" + migration221DownSHA222 + "'",
		"DELETE FROM role_permissions assignment",
		"scope.kind = 'tenant'",
		"role.system_role AND role.name = 'tenant_owner'",
		"assignment.permission_name IN ('openresty_security.read', 'openresty_security.manage')",
	} {
		if !strings.Contains(string(up), required) {
			t.Errorf("up migration missing %q", required)
		}
	}
	for _, required := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 222",
		"(SELECT max(version) FROM schema_migrations) <> 222",
		"version = 222 AND migration_id = '222_openresty_security_platform_scope'",
		"checksum_sha256 = '" + migration222UpSHA + "'",
		"INSERT INTO role_permissions(role_id, permission_name)",
		"scope.kind = 'tenant'",
		"role.system_role AND role.name = 'tenant_owner'",
		"ON CONFLICT DO NOTHING",
	} {
		if !strings.Contains(string(down), required) {
			t.Errorf("down migration missing %q", required)
		}
	}

	if guard, mutation := strings.Index(string(up), "migration 222 requires the exact verified 221 release head"),
		strings.Index(string(up), "DELETE FROM role_permissions assignment"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("migration 222 predecessor guard must precede the permission mutation")
	}
	if guard, mutation := strings.Index(string(down), "migration 222 rollback requires the exact verified 222 release head"),
		strings.Index(string(down), "INSERT INTO role_permissions"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("migration 222 rollback guard must precede the permission restoration")
	}

	combined := strings.ToUpper(string(up) + string(down))
	for _, forbidden := range []string{" CASCADE", "TRUNCATE", "DROP SCHEMA", "DELETE FROM SCHEMA_MIGRATIONS", "DELETE FROM PERMISSIONS"} {
		if strings.Contains(combined, forbidden) {
			t.Errorf("migration contains forbidden token %q", forbidden)
		}
	}
}

func readOpenRestySecurityScopeMigration(t *testing.T, name string) []byte {
	t.Helper()
	payload, err := FS.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func openRestySecurityScopeMigrationSHA(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}
