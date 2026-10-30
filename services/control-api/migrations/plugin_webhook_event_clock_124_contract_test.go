package migrations_test

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPluginWebhookEventClock124Contract(t *testing.T) {
	up := readPluginWebhookEventClock124(t, "124_plugin_webhook_event_clock.up.sql")
	down := readPluginWebhookEventClock124(t, "124_plugin_webhook_event_clock.down.sql")

	for _, marker := range []string{
		"migration 124 requires the exact verified 123 release head",
		"version = 123",
		"migration_id = '123_plugin_webhook_domain_event_producer'",
		"checksum_sha256 = '1571676e83b10966f0490b7f4ef8064e9e3e19593e8577a726c160dcaff64e0f'",
		"down_checksum_sha256 = '6dc511cc3321279a5434d8d345d8da9ea85ea8432b6cb727b33778ac0c243690'",
		"integrity_state = 'verified'",
		"metadata_recorded_at IS NOT NULL",
		"applied_at IS NOT NULL",
		"plugin_webhook_event_clock_124_backup",
		"pg_get_constraintdef",
		"created_at=event_time",
		"plugin_webhook_events_event_clock_124",
		"date_trunc('microseconds', event_time) = event_time",
		"event_time <= created_at",
		"USING ERRCODE = 'P1241'",
		"USING ERRCODE = 'P1242'",
	} {
		if !strings.Contains(up, marker) {
			t.Errorf("124 up missing %q", marker)
		}
	}
	for _, marker := range []string{
		"migration 124 rollback requires the exact verified release head",
		"version = 124",
		"migration_id = '124_plugin_webhook_event_clock'",
		"plugin_webhook_event_clock_124_backup",
		"event_time IS DISTINCT FROM created_at",
		"migration 124 rollback would discard domain event clock facts",
		"DROP CONSTRAINT plugin_webhook_events_event_clock_124",
		"ADD CONSTRAINT",
		"CHECK (created_at = event_time)",
		"DROP TABLE plugin_webhook_event_clock_124_backup",
		"USING ERRCODE = 'P1241'",
		"USING ERRCODE = 'P1242'",
	} {
		if !strings.Contains(down, marker) {
			t.Errorf("124 down missing %q", marker)
		}
	}
	if strings.Contains(strings.ToUpper(up+down), "CASCADE") {
		t.Fatal("124 migration must not use CASCADE")
	}
	if strings.Contains(up, "plugin_webhook_write_requests") || strings.Contains(up, "plugin_webhook_rate_events") {
		t.Fatal("124 must not relax command-facts or rate-event constraints")
	}
	if strings.Contains(up+down, "__UP_SHA256__") || strings.Contains(up+down, "__DOWN_SHA256__") {
		t.Fatal("124 migration must not ship checksum placeholders")
	}
	t.Logf("124 up sha256=%s down sha256=%s", sha256Hex124(up), sha256Hex124(down))
}

func readPluginWebhookEventClock124(t *testing.T, name string) string {
	t.Helper()
	for _, root := range []string{".", "services/control-api/migrations"} {
		if body, err := os.ReadFile(filepath.Join(root, name)); err == nil {
			return string(body)
		}
	}
	t.Fatalf("migration file %s not found", name)
	return ""
}

func sha256Hex124(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
