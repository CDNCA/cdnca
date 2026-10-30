package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestPluginWebhookInstallationBinding188Contract(t *testing.T) {
	predecessorUp := readPluginWebhookBinding188(t, "187_deployment_domain_event_source_outbox.up.sql")
	predecessorDown := readPluginWebhookBinding188(t, "187_deployment_domain_event_source_outbox.down.sql")
	up := readPluginWebhookBinding188(t, "188_plugin_webhook_installation_binding.up.sql")
	down := readPluginWebhookBinding188(t, "188_plugin_webhook_installation_binding.down.sql")

	for _, required := range []string{
		"migration 188 requires the exact verified 187 release head",
		fmt.Sprintf("%x", sha256.Sum256(predecessorUp)),
		fmt.Sprintf("%x", sha256.Sum256(predecessorDown)),
		"installation_authorization_id uuid",
		"installation_id uuid",
		"plugin_id text",
		"plugin_webhook_subscriptions_installation_binding_shape_188",
		"installation_authorization_id IS NULL AND installation_id IS NULL AND plugin_id IS NULL",
		"installation_authorization_id IS NOT NULL AND installation_id IS NOT NULL AND plugin_id IS NOT NULL",
		"FOREIGN KEY (tenant_scope_id, installation_authorization_id)",
		"REFERENCES plugin_installation_heads(tenant_scope_id, authorization_id)",
		"status IS DISTINCT FROM 'enabled'",
		"installation_id IS DISTINCT FROM NEW.installation_id",
		"plugin_id IS DISTINCT FROM NEW.plugin_id",
		"events.deployment.read", "events.site.read", "events.node.read",
		"events.certificate.read", "events.usage.read", "events.security.read",
		"dns event has no approved installation permission",
		"required_scope = ANY(approved_scopes)",
		"plugin webhook test-only subscription cannot bind an installation",
		"plugin webhook non-test subscription requires an installation binding",
		"plugin webhook installation binding is immutable",
	} {
		if !strings.Contains(string(up), required) {
			t.Errorf("188 up missing %q", required)
		}
	}
	firstMutation := strings.Index(string(up), "ALTER TABLE plugin_webhook_subscriptions")
	guard := strings.Index(string(up), "migration 188 requires the exact verified 187 release head")
	if guard < 0 || firstMutation < 0 || guard > firstMutation {
		t.Fatal("188 predecessor guard must precede the first schema mutation")
	}

	for _, required := range []string{
		"migration 188 rollback requires the exact verified 188 and 187 release heads",
		fmt.Sprintf("%x", sha256.Sum256(up)),
		fmt.Sprintf("%x", sha256.Sum256(predecessorUp)),
		fmt.Sprintf("%x", sha256.Sum256(predecessorDown)),
		"rollback would discard plugin webhook installation bindings",
		"installation_authorization_id IS NOT NULL",
		"DROP COLUMN installation_authorization_id",
		"DROP COLUMN installation_id",
		"DROP COLUMN plugin_id",
	} {
		if !strings.Contains(string(down), required) {
			t.Errorf("188 down missing %q", required)
		}
	}
	combined := strings.ToUpper(string(up) + string(down))
	if strings.Contains(combined, "CASCADE") || strings.Contains(string(up)+string(down), "DELETE FROM schema_migrations") ||
		strings.Contains(string(up)+string(down), "__UP_SHA256__") || strings.Contains(string(up)+string(down), "__DOWN_SHA256__") {
		t.Fatal("188 migration must not use destructive migration shortcuts")
	}
}

func readPluginWebhookBinding188(t *testing.T, name string) []byte {
	t.Helper()
	for _, root := range []string{".", "services/control-api/migrations"} {
		if body, err := os.ReadFile(root + "/" + name); err == nil {
			return body
		}
	}
	t.Fatalf("migration %s not found", name)
	return nil
}
