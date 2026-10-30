package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

const (
	siteDomainMigration185UpSHA256   = "96832a834af03cb703ba89f4f247d5559d75a17089047a181ed698c8de9bb85f"
	siteDomainMigration185DownSHA256 = "fe98212bbb6fc763a2c2f6efba61aa9007f7de5371271e8ceed64833f6e18ef9"
)

func TestSiteDomainExportRBAC186Contract(t *testing.T) {
	upBytes, err := controlmigrations.FS.ReadFile("186_site_domain_export_rbac.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	downBytes, err := controlmigrations.FS.ReadFile("186_site_domain_export_rbac.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down := string(upBytes), string(downBytes)

	for _, required := range []string{
		"migration 186 requires the exact verified 185 release head",
		"version=185 AND migration_id='185_plugin_webhook_canonical_body_brace_fix'",
		siteDomainMigration185UpSHA256,
		siteDomainMigration185DownSHA256,
		"CREATE OR REPLACE FUNCTION grant_site_domain_permissions_148()",
		"DELETE FROM role_permissions",
		"role.name='tenant_viewer'",
		"migration 186 rollback requires the exact verified 186 and 185 release heads",
		"INSERT INTO role_permissions(role_id,permission_name)",
	} {
		if !strings.Contains(up+down, required) {
			t.Errorf("186 migration missing %q", required)
		}
	}

	upFunction := functionBody(up)
	if !strings.Contains(upFunction, "NEW.name IN ('platform_owner','tenant_owner')") {
		t.Fatal("186 up must grant sites.export only to platform_owner and tenant_owner")
	}
	if strings.Contains(upFunction, "tenant_viewer") {
		t.Fatal("186 up must not grant sites.export to tenant_viewer")
	}
	if !strings.Contains(up, "DELETE FROM role_permissions AS grant_row") ||
		!strings.Contains(up, "role.name='tenant_viewer'") {
		t.Fatal("186 up must remove existing tenant_viewer sites.export grants")
	}

	upSHA := fmt.Sprintf("%x", sha256.Sum256(upBytes))
	if !strings.Contains(down, upSHA) {
		t.Fatalf("186 down must pin its up checksum %s", upSHA)
	}
	downFunction := functionBody(down)
	if !strings.Contains(downFunction, "NEW.name IN ('platform_owner','tenant_owner','tenant_viewer')") {
		t.Fatal("186 down must restore migration 148 trigger semantics")
	}
	if strings.Contains(strings.ToUpper(up+down), "CASCADE") ||
		strings.Contains(up+down, "DELETE FROM schema_migrations") {
		t.Fatal("186 migration must not use destructive migration shortcuts")
	}
	for _, content := range []struct {
		name string
		text string
	}{
		{"up", up},
		{"down", down},
	} {
		guard := strings.Index(content.text, "migration 186")
		mutation := strings.Index(content.text, "CREATE OR REPLACE FUNCTION")
		if guard < 0 || mutation < 0 || guard > mutation {
			t.Fatalf("186 %s predecessor guard must run before mutation", content.name)
		}
	}
}

func functionBody(sql string) string {
	start := strings.Index(sql, "CREATE OR REPLACE FUNCTION grant_site_domain_permissions_148()")
	if start < 0 {
		return ""
	}
	end := strings.Index(sql[start:], "$$;")
	if end < 0 {
		return sql[start:]
	}
	return sql[start : start+end]
}
