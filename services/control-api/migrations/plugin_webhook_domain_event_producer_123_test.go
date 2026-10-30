package migrations_test

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Keep this contract test independent of PostgreSQL. The integration gate
// exercises the deferred trigger path; this test catches a partial migration
// or a changed approved predecessor before a database is started.
func TestPluginWebhookDomainEventProducer123Contract(t *testing.T) {
	up := mustReadPluginWebhookDomainProducer123(t, "123_plugin_webhook_domain_event_producer.up.sql")
	down := mustReadPluginWebhookDomainProducer123(t, "123_plugin_webhook_domain_event_producer.down.sql")
	predecessor084Up := mustReadPluginWebhookDomainProducer123(t, "084_plugin_webhook_control.up.sql")
	predecessor084Down := mustReadPluginWebhookDomainProducer123(t, "084_plugin_webhook_control.down.sql")
	predecessorUp := mustReadPluginWebhookDomainProducer123(t, "122_plugin_webhook_event_contract.up.sql")
	predecessorDown := mustReadPluginWebhookDomainProducer123(t, "122_plugin_webhook_event_contract.down.sql")

	if got := sha256HexPluginWebhook123(predecessor084Up); got != "f51e909422b4254b49204d85cd4adec7ad0fed9da29686fd872651010220a56d" {
		t.Fatalf("084 up changed: %s", got)
	}
	if got := sha256HexPluginWebhook123(predecessor084Down); got != "b914352bc35e24c6bd9d12b90255ab42586dfb9e31438825961c02cb37cbc3be" {
		t.Fatalf("084 down changed: %s", got)
	}
	if got := sha256HexPluginWebhook123(predecessorUp); got != "358b0e639ffa5290cd4146826beb29ac22d114abfb7ae7ce00675cbdc71236cb" {
		t.Fatalf("122 up changed: %s", got)
	}
	if got := sha256HexPluginWebhook123(predecessorDown); got != "cbb00f190518cd10509dc9014e0f35431e02d7c88e5678e5c3182afff959ccea" {
		t.Fatalf("122 down changed: %s", got)
	}
	for _, marker := range []string{
		"migration 123 requires the exact verified 122 release head",
		"checksum_sha256 = '358b0e639ffa5290cd4146826beb29ac22d114abfb7ae7ce00675cbdc71236cb'",
		"down_checksum_sha256 = 'cbb00f190518cd10509dc9014e0f35431e02d7c88e5678e5c3182afff959ccea'",
		"plugin_webhook_domain_contract_123_backup",
		"before_definition := definition",
		"USING ERRCODE = 'P1231'",
		"plugin_webhook.domain_event.publish",
		"checked_event_type",
		"event.event_type <> 'io.cdnca.webhook.v1.test'",
		"plugin_webhook_write_requests_operation_123",
		"plugin_webhook_write_requests_response_status_123",
		"plugin_webhook_write_requests_result_shape_123",
		"plugin_webhook_write_requests_response_body_123",
		"plugin_webhook_rate_events_operation_123",
		"plugin_webhook_write_requests_operation_check",
		"plugin_webhook_write_requests_check",
		"plugin_webhook_write_requests_check2",
		"plugin_webhook_write_requests_check3",
		"plugin_webhook_rate_events_operation_check",
	} {
		if !strings.Contains(up, marker) {
			t.Errorf("123 up missing %q", marker)
		}
	}
	for _, marker := range []string{
		"migration 123 rollback requires the exact verified release head",
		"migration 123 rollback would discard domain webhook facts",
		"USING ERRCODE = 'P1232'",
		"CHECK (",
		"DROP TABLE plugin_webhook_domain_contract_123_backup",
		"plugin_webhook_write_requests_operation_check",
		"plugin_webhook_write_requests_check",
		"plugin_webhook_write_requests_check2",
		"plugin_webhook_write_requests_check3",
	} {
		if !strings.Contains(down, marker) {
			t.Errorf("123 down missing %q", marker)
		}
	}
	if strings.Contains(strings.ToUpper(down), "CASCADE") {
		t.Fatal("123 down must not use CASCADE")
	}
	if strings.Contains(up, "__UP_SHA256__") || strings.Contains(up, "__DOWN_SHA256__") ||
		strings.Contains(down, "__UP_SHA256__") || strings.Contains(down, "__DOWN_SHA256__") {
		t.Fatal("123 migration must not ship checksum placeholders")
	}
}

func mustReadPluginWebhookDomainProducer123(t *testing.T, name string) string {
	t.Helper()
	for _, root := range []string{".", "services/control-api/migrations"} {
		if body, err := os.ReadFile(filepath.Join(root, name)); err == nil {
			return string(body)
		}
	}
	t.Fatalf("migration file %s not found", name)
	return ""
}

func sha256HexPluginWebhook123(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
