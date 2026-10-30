//go:build integration

package migrations_test

import (
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestUpgradeStatusPubAckIdentity102Contract(t *testing.T) {
	up, err := controlmigrations.FS.ReadFile("102_upgrade_status_puback_identity.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := controlmigrations.FS.ReadFile("102_upgrade_status_puback_identity.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"migration 102 requires the exact verified 101 release head",
		"delivery_stream", "delivery_consumer", "delivery_sequence",
		"legacy rows remain nullable and are never guessed",
		"UNIQUE (delivery_stream, delivery_sequence)",
		"CREATE FUNCTION validate_control_upgrade_status_puback_identity_102()",
		"new control upgrade status requires exact PubAck delivery facts",
		"control upgrade status PubAck facts are immutable",
		"BEFORE INSERT OR UPDATE ON control_upgrade_status_receipts",
	} {
		if !strings.Contains(string(up), required) {
			t.Errorf("102 up missing %q", required)
		}
	}
	for _, required := range []string{
		"status PubAck delivery facts exist; rollback is unsafe",
		"DROP TRIGGER control_upgrade_status_puback_identity_102",
		"DROP FUNCTION validate_control_upgrade_status_puback_identity_102()",
		"DROP COLUMN delivery_sequence", "DROP COLUMN delivery_consumer", "DROP COLUMN delivery_stream",
	} {
		if !strings.Contains(string(down), required) {
			t.Errorf("102 down missing %q", required)
		}
	}
}
