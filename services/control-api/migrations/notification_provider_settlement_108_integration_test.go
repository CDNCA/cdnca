//go:build integration

package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestNotificationProviderSettlement108MigrationContract(t *testing.T) {
	up, err := controlmigrations.FS.ReadFile("108_notification_provider_settlement.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := controlmigrations.FS.ReadFile("108_notification_provider_settlement.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	upSQL, downSQL := string(up), string(down)
	for _, required := range []string{
		"migration 108 requires the exact verified 107 release head",
		"migration_id='107_analytics_ingest_watermark_late_revision'",
		"checksum_sha256='5c35e57e9d6ce37af42cf0e3c2241c185017359219728785c952c0e39e8c95c2'",
		"down_checksum_sha256='0e0e31de6e1ae8dac0cec84e219ff90b7caef2533e683bfe25d55ab90f9b7879'",
		"REQUIRED_MIGRATION_107_INTEGRATION_SHA256=7f5dc1a6d88e2ae096564cc29987cc26250cf71748a0cfd51bdcabd2c4ffbfce",
		"USING ERRCODE='P1080'",
		"CREATE TABLE notification_delivery_settlements_108",
		"CREATE TABLE notification_delivery_facts_108",
		"CREATE TABLE notification_delivery_command_receipts_108",
		"dispatching", "accepted", "unknown", "delivered", "cancelled", "retry_wait",
		"provider_event_key", "provider_delivery_id", "replay_of_outbox_id",
		"DEFERRABLE INITIALLY DEFERRED",
		"notification delivery facts are append-only",
		"notification delivery command receipts are immutable",
		"system_configuration.manage",
		"notification.delivery.cancel", "notification.delivery.replay",
		"REVOKE ALL ON notification_delivery_settlements_108 FROM PUBLIC",
		"REVOKE ALL ON notification_delivery_facts_108 FROM PUBLIC",
		"REVOKE ALL ON notification_delivery_command_receipts_108 FROM PUBLIC",
	} {
		if !strings.Contains(upSQL, required) {
			t.Errorf("108 up missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"accepted' THEN 'succeeded", "unknown' THEN 'pending", "provider_response_body",
		"provider_secret", "credential", "authorization_header",
	} {
		if strings.Contains(upSQL, forbidden) {
			t.Errorf("108 up contains unsafe contract %q", forbidden)
		}
	}
	guard := strings.Index(upSQL, "USING ERRCODE='P1080'")
	firstMutation := strings.Index(upSQL, "ALTER TABLE notification_outbox")
	if guard < 0 || firstMutation < 0 || guard > firstMutation {
		t.Errorf("108 up predecessor guard must run before the first schema mutation")
	} else {
		for _, required := range []string{
			"migration_id='107_analytics_ingest_watermark_late_revision'",
			"checksum_sha256='5c35e57e9d6ce37af42cf0e3c2241c185017359219728785c952c0e39e8c95c2'",
			"down_checksum_sha256='0e0e31de6e1ae8dac0cec84e219ff90b7caef2533e683bfe25d55ab90f9b7879'",
			"REQUIRED_MIGRATION_107_INTEGRATION_SHA256=7f5dc1a6d88e2ae096564cc29987cc26250cf71748a0cfd51bdcabd2c4ffbfce",
		} {
			if !strings.Contains(upSQL[:firstMutation], required) {
				t.Errorf("108 predecessor guard missing %q before first schema mutation", required)
			}
		}
	}
	for _, required := range []string{
		"migration 108 rollback requires the exact verified 108 head",
		"USING ERRCODE='P1080'",
		"migration 108 rollback would discard notification settlement facts",
		"DROP TABLE notification_delivery_command_receipts_108",
		"DROP TABLE notification_delivery_facts_108",
		"DROP TABLE notification_delivery_settlements_108",
	} {
		if !strings.Contains(downSQL, required) {
			t.Errorf("108 down missing %q", required)
		}
	}
	downGuard := strings.Index(downSQL, "USING ERRCODE='P1080'")
	firstDrop := strings.Index(downSQL, "DROP TRIGGER notification_outbox_transition_108")
	if downGuard < 0 || firstDrop < 0 || downGuard > firstDrop {
		t.Errorf("108 down release guard must run before the first schema mutation")
	}
	data, err := os.ReadFile("analytics_ingest_watermark_late_revision_107_integration_test.go")
	if err != nil {
		t.Fatal(err)
	}
	actual107IntegrationSHA := fmt.Sprintf("%x", sha256.Sum256(data))
	if actual107IntegrationSHA != "7f5dc1a6d88e2ae096564cc29987cc26250cf71748a0cfd51bdcabd2c4ffbfce" {
		t.Fatalf("107 integration SHA=%s, authoritative SHA drifted", actual107IntegrationSHA)
	}
	if !strings.Contains(upSQL, "REQUIRED_MIGRATION_107_INTEGRATION_SHA256="+actual107IntegrationSHA) {
		t.Fatalf("108 up does not bind computed 107 integration SHA %s", actual107IntegrationSHA)
	}
}
