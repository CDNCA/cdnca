package migrations

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

const (
	securityPolicyProjection229UpSHA   = "2f7ba254e3c0599c8160ebe06940a1059a9975965baa2331c2f5d1b5818180a1"
	securityPolicyProjection229DownSHA = "231ed7fa9f14f06b9cb1d029df30791097595c5a7307d5627e039b44e17bc4db"
	securityPolicyProjection230UpSHA   = "5a754062f0248ba9f8138cb3240f58a921968dc1526e551a78d5fcfc8e009551"
	securityPolicyProjection230DownSHA = "5a37942455d54cd6534b987eb5365e8eaddc21410797cfe0eb9bc6651bfad0e6"
)

func TestSecurityPolicySystemRoleProjection230Contract(t *testing.T) {
	files := map[string]struct {
		name string
		sha  string
	}{
		"229 up":   {"229_control_runtime_publication_function_grants.up.sql", securityPolicyProjection229UpSHA},
		"229 down": {"229_control_runtime_publication_function_grants.down.sql", securityPolicyProjection229DownSHA},
		"230 up":   {"230_security_policy_system_role_projection.up.sql", securityPolicyProjection230UpSHA},
		"230 down": {"230_security_policy_system_role_projection.down.sql", securityPolicyProjection230DownSHA},
	}
	contents := make(map[string]string, len(files))
	for label, file := range files {
		payload, err := FS.ReadFile(file.name)
		if err != nil {
			t.Fatalf("read %s: %v", label, err)
		}
		if got := securityPolicyProjection230SHA(payload); got != file.sha {
			t.Fatalf("migration %s checksum = %s, want %s", label, got, file.sha)
		}
		contents[label] = string(payload)
	}

	up, down := contents["230 up"], contents["230 down"]
	for _, required := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 229",
		"version = 229 AND migration_id = '229_control_runtime_publication_function_grants'",
		securityPolicyProjection229UpSHA,
		securityPolicyProjection229DownSHA,
		"security_policy_system_role_grant_additions_230",
		"project_security_policy_system_role_permissions_230()",
		"roles_project_security_policy_permissions_230",
		"role.name IN ('tenant_owner', 'tenant_viewer')",
		"role.name = 'tenant_owner' OR permission.name = 'security_policies.read'",
		"security_policies.manage",
		"source_migration = 230",
		"USING ERRCODE = 'P2300'",
		"USING ERRCODE = 'P2301'",
		"(SELECT count(*) FROM schema_migrations) <> 230",
		"version = 230 AND migration_id = '230_security_policy_system_role_projection'",
		securityPolicyProjection230UpSHA,
		"DISABLE TRIGGER role_permissions_system_role_guard",
		"USING security_policy_system_role_grant_additions_230 addition",
		"USING ERRCODE = 'P2302'",
	} {
		if !strings.Contains(up+down, required) {
			t.Errorf("migration 230 is missing %q", required)
		}
	}
	if !strings.Contains(down, "addition.source_migration = 230") {
		t.Fatal("migration 230 rollback must delete only provenance-recorded grants")
	}
	if strings.Contains(down, "DELETE FROM role_permissions\nWHERE permission_name") {
		t.Fatal("migration 230 rollback contains an unscoped permission deletion")
	}
	for _, forbidden := range []string{
		" CASCADE", "\nTRUNCATE ", "DELETE FROM SCHEMA_MIGRATIONS", "__UP_SHA256__", "__DOWN_SHA256__",
	} {
		if strings.Contains(strings.ToUpper(up+down), forbidden) {
			t.Errorf("migration 230 contains forbidden token %q", forbidden)
		}
	}
}

func securityPolicyProjection230SHA(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}
