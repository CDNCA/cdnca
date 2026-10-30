package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

const (
	packageMonitorAlertAcknowledgement120UpSHA256   = "8bad0019496e9f47fa92c66bf1b432d2ded681f9049717ef830cd4364923e9f0"
	packageMonitorAlertAcknowledgement120DownSHA256 = "cfcc4d94770ac3edd44ad0100209c52f45ca4b63af49e88fba2038bca8e85ef5"
	packageMonitorAlertAcknowledgement121UpSHA256   = "b0b22d4317e5e250bee2a9734bab7028d0a0438cc78c54a5b1a0fc7f62633a6f"
	packageMonitorAlertAcknowledgement121DownSHA256 = "37ac1bc284dcd9ef6cd88ee18fb6285cba5a06fa099de6ad284db8d64164a4a5"
)

func TestPackageMonitorAlertAcknowledgement121Contract(t *testing.T) {
	upBytes, err := controlmigrations.FS.ReadFile("121_package_monitor_alert_acknowledgement.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	downBytes, err := controlmigrations.FS.ReadFile("121_package_monitor_alert_acknowledgement.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up := string(upBytes)
	down := string(downBytes)
	if got := fmt.Sprintf("%x", sha256.Sum256(upBytes)); got != packageMonitorAlertAcknowledgement121UpSHA256 {
		t.Fatalf("121 up sha256=%s, want %s", got, packageMonitorAlertAcknowledgement121UpSHA256)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(downBytes)); got != packageMonitorAlertAcknowledgement121DownSHA256 {
		t.Fatalf("121 down sha256=%s, want %s", got, packageMonitorAlertAcknowledgement121DownSHA256)
	}
	for _, marker := range []string{
		packageMonitorAlertAcknowledgement120UpSHA256,
		packageMonitorAlertAcknowledgement121UpSHA256,
	} {
		if !strings.Contains(up+down, marker) {
			t.Fatalf("121 migration hash guard omitted %q", marker)
		}
	}
	if strings.Contains(up, packageMonitorAlertAcknowledgement120DownSHA256) {
		t.Fatalf("121 up unexpectedly pins 120 down checksum %q", packageMonitorAlertAcknowledgement120DownSHA256)
	}
	for _, required := range []string{
		"CREATE TABLE package_monitor_alert_acknowledgement_receipts",
		"CREATE TABLE package_monitor_alert_acknowledgement_facts",
		"CREATE TABLE package_monitor_alert_acknowledgement_heads",
		"request_digest", "idempotency_key", "response_body", "completed_at",
		"acknowledgement_id", "receipt_id", "actor_session_id",
		"REFERENCES auth_sessions(id,scope_id,user_id)",
		"FOREIGN KEY (alert_id,alert_revision)",
		"package_monitor.alert.acknowledge",
		"append-only", "current projection",
	} {
		if !strings.Contains(strings.ToLower(up), strings.ToLower(required)) {
			t.Errorf("121 up missing %q", required)
		}
	}
	for _, forbidden := range []string{"raw_token", "bearer", "refresh_token", "secret", "password"} {
		if strings.Contains(strings.ToLower(up), forbidden) {
			t.Errorf("121 up persists forbidden secret field %q", forbidden)
		}
	}
	if !strings.Contains(down, "rollback would discard package monitor alert acknowledgement facts") ||
		!strings.Contains(down, "DROP TABLE package_monitor_alert_acknowledgement_facts") {
		t.Fatal("121 down must be loss guarded")
	}
	t.Logf("121 up sha256=%x down sha256=%x", sha256.Sum256(upBytes), sha256.Sum256(downBytes))
}
