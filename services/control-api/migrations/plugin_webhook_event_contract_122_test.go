package migrations

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPluginWebhookEventContract122HasPinnedPredecessorAndFailClosedRollback(t *testing.T) {
	up := readMigration122Contract(t, "122_plugin_webhook_event_contract.up.sql")
	down := readMigration122Contract(t, "122_plugin_webhook_event_contract.down.sql")
	for name, content := range map[string]string{"up": up, "down": down} {
		if !strings.Contains(content, "plugin_webhook_event_contracts_122") ||
			!strings.Contains(content, "io.cdnca.webhook.v1.test") {
			t.Fatalf("migration 122 %s is missing the versioned contract registry or legacy test event", name)
		}
	}
	for _, required := range []string{
		"checksum_sha256 = 'b0b22d4317e5e250bee2a9734bab7028d0a0438cc78c54a5b1a0fc7f62633a6f'",
		"down_checksum_sha256 = '37ac1bc284dcd9ef6cd88ee18fb6285cba5a06fa099de6ad284db8d64164a4a5'",
		"plugin_webhook_event_types_shape_122",
		"plugin_webhook_event_type_valid_122",
		"plugin_webhook_data_valid_122",
		"plugin_webhook_canonical_body_084",
		"REVOKE ALL ON TABLE plugin_webhook_event_contracts_122 FROM PUBLIC",
		"GRANT SELECT ON TABLE plugin_webhook_event_contracts_122",
	} {
		if !strings.Contains(up, required) {
			t.Fatalf("migration 122 up missing %q", required)
		}
	}
	if !strings.Contains(down, "P1222") ||
		!strings.Contains(down, "non-test webhook contract data") {
		t.Fatal("migration 122 down does not fail closed for non-test data")
	}
}

func readMigration122Contract(t *testing.T, name string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(".", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}
