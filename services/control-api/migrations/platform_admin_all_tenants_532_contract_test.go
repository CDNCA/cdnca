package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 532: a platform administrator may write any
// tenant's resources; the platform branches of six guards accept platform.admin.
const (
	migration532ID      = "532_platform_admin_all_tenants"
	migration532UpSHA   = "30db4d5210181ea5220c65e495ca0a3e0ac8f5e6938e941ab1e98b4ca958ed0f"
	migration532DownSHA = "46c3d75d37cccb42112e186112ce65be5f653418db06020329cc2f0d106fbe87"
)

func TestPlatformAdminAllTenants532Contract(t *testing.T) {
	functions := []string{
		"CREATE OR REPLACE FUNCTION validate_acme_issuance_operation_snapshot_047()",
		"CREATE OR REPLACE FUNCTION system_configuration_actor_has_permission(",
		"CREATE OR REPLACE FUNCTION error_page_actor_has_permission(",
		"CREATE OR REPLACE FUNCTION http_policy_actor_can_056(",
		"CREATE OR REPLACE FUNCTION validate_plugin_webhook_actor_target_084()",
		"CREATE OR REPLACE FUNCTION validate_package_offer_publication_event_090()",
	}
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration532ID + ".up.sql", migration532UpSHA, append([]string{
			"(SELECT count(*) FROM schema_migrations) <> 531", "ERRCODE='P5320'",
			"OR NOT acme_runtime_actor_is_active_048(NEW.tenant_scope_id, snapshot_actor_id) THEN",
			"permission.permission_name IN (requested_permission, 'platform.admin')",
			") OR control_platform_admin_435(actor_user, actor_scope)",
			"role_permission.permission_name IN (permission, 'platform.admin')",
			"IN ('plugin_webhooks.manage', 'platform.admin')",
			"actor_scope_kind='platform' AND grant_row.permission_name='platform.admin'",
		}, functions...)},
		{migration532ID + ".down.sql", migration532DownSHA, append([]string{
			"(SELECT count(*) FROM schema_migrations) <> 532", "migration_id='" + migration532ID + "'",
			"ERRCODE='P5321'",
		}, functions...)},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != script.sha {
			t.Fatalf("%s checksum drift: %s", script.name, got)
		}
		for _, want := range script.required {
			if !strings.Contains(string(raw), want) {
				t.Fatalf("%s lacks %q", script.name, want)
			}
		}
	}
	down, _ := FS.ReadFile(migration532ID + ".down.sql")
	if strings.Contains(string(down), "platform.admin") || strings.Contains(string(down), "control_platform_admin_435") {
		t.Fatal("532 down must restore the pre-532 bodies")
	}
}
