package migrations

import (
	"strings"
	"testing"
)

// Migration 636 (predecessor 635_market_ban_sync): the controller's platform scope
// holds tenant plugins it confirmed with a target set, coverage decides which tenants use them, the 604/188/368
// tenant-composite keys become authorization keys checked by coverage. Down restores 188/368/585/604 verbatim.
func TestPluginInstallationPlatformTargets636Contract(t *testing.T) {
	up := readPlatformTargets636(t, "up")
	down := readPlatformTargets636(t, "down")
	for _, fragment := range []string{
		"ERRCODE='P6360'", "to_regclass(current_schema() || '.plugin_installation_targets') IS NOT NULL",
		"(scope.kind=NEW.resource_scope OR (scope.kind='platform' AND NEW.resource_scope='tenant'))",
		"CREATE TABLE plugin_installation_targets", "CREATE TABLE plugin_installation_target_tenants",
		"REFERENCES plugin_installation_heads(authorization_id) ON DELETE RESTRICT",
		"CREATE CONSTRAINT TRIGGER plugin_installation_heads_targets_636",
		"DEFERRABLE INITIALLY DEFERRED", "ERRCODE='P6362'",
		"CREATE FUNCTION plugin_installation_covers_tenant_636(checked_authorization_id uuid, checked_tenant_scope_id uuid)",
		"(holder.kind='tenant' AND head.tenant_scope_id=checked_tenant_scope_id)",
		"ADD CONSTRAINT api_keys_plugin_installation_636_fk FOREIGN KEY (plugin_installation_authorization_id)",
		"ADD CONSTRAINT plugin_webhook_subscriptions_installation_binding_636_fk FOREIGN KEY (installation_authorization_id)",
		"ADD CONSTRAINT domain_event_fanout_receipts_installation_636_fk FOREIGN KEY (installation_authorization_id)",
		"plugin_installation_covers_tenant_636(head.authorization_id, NEW.scope_id)",
		"plugin_installation_covers_tenant_636(head.authorization_id, NEW.tenant_scope_id)",
		"plugin_installation_covers_tenant_636(installation.authorization_id, subscription.tenant_scope_id)",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("636 up missing %q", fragment)
		}
	}
	for _, fragment := range []string{
		"ERRCODE='P6364'", "ERRCODE='P6365'", "DROP TABLE plugin_installation_targets",
		"ADD CONSTRAINT api_keys_plugin_installation_604_fk",
		"ADD CONSTRAINT plugin_webhook_subscriptions_installation_binding_188_fk",
		"DROP FUNCTION plugin_installation_covers_tenant_636(uuid, uuid)",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("636 down missing %q", fragment)
		}
	}
	for _, forbidden := range []string{"DELETE FROM", "UPDATE plugin_installation_heads", "INSERT INTO permissions"} {
		if strings.Contains(up, forbidden) || strings.Contains(down, forbidden) {
			t.Errorf("636 must not contain %q", forbidden)
		}
	}
	for file, declaration := range map[string]string{
		"585_plugin_installation_resource_scope.up.sql":  "FUNCTION validate_plugin_installation_resource_scope_585()",
		"188_plugin_webhook_installation_binding.up.sql": "FUNCTION validate_plugin_webhook_installation_binding_188()",
		"368_domain_event_outbox.up.sql":                 "FUNCTION validate_domain_event_delivery_scope_368()",
		"604_api_key_plugin_installation.up.sql":         "FUNCTION validate_api_key_plugin_installation_604()",
	} {
		original, err := FS.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		want := strings.Replace(sqlFunctionBody(t, string(original), "CREATE "+declaration), "CREATE FUNCTION",
			"CREATE OR REPLACE FUNCTION", 1)
		if got := sqlFunctionBody(t, down, "CREATE OR REPLACE "+declaration); got != want {
			t.Errorf("636 down does not restore %s verbatim", declaration)
		}
		if changed := sqlFunctionBody(t, up, "CREATE OR REPLACE "+declaration); changed == want {
			t.Errorf("636 up does not change %s", declaration)
		}
	}
}

// readPlatformTargets636 reads the 636 script.
func readPlatformTargets636(t *testing.T, direction string) string {
	t.Helper()
	for _, name := range []string{"636_plugin_installation_platform_targets."} {
		if body, err := FS.ReadFile(name + direction + ".sql"); err == nil {
			return string(body)
		}
	}
	t.Fatalf("636 %s script not found", direction)
	return ""
}
