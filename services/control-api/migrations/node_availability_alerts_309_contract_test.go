package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// G9c-④ 节点告警事件迁移。占位号 309（守卫指向 308 头），合入时如改号，
// 只改这里的常量和两个 SQL 文件头部。
const (
	nodeAvailabilityAlertsVersion    = 309
	nodeAvailabilityAlertsPreviousID = "308_package_auto_renew"
	nodeAvailabilityAlertsPreviousUp = "cf00f85140ed657e76bcff2cbb0db8c5a5f284d82dbd459a2e0fbf2e2ef3a5df"
	nodeAvailabilityAlertsPreviousDn = "3dd8a5febfb33f7676245c9b6f41f44d3d2ad6846456b0d3fe760aa6530d4b4b"
	nodeAvailabilityAlertsUpSHA256   = "c5f68f0fbbe78b414cc9a3bf3693009481466d08cc69d729e2b109d1c1927e74"
	nodeAvailabilityAlertsDownSHA256 = "9e9bb8b369b05d04589e844c80cb4dc0e84b28fc0a70d2876543f936e52e6552"
)

func TestNodeAvailabilityAlertsMigrationContract(t *testing.T) {
	previous := fmt.Sprint(nodeAvailabilityAlertsVersion - 1)
	current := fmt.Sprint(nodeAvailabilityAlertsVersion)
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{current + "_node_availability_alerts.up.sql", nodeAvailabilityAlertsUpSHA256, []string{
			"(SELECT count(*) FROM schema_migrations) <> " + previous,
			"(SELECT max(version) FROM schema_migrations) <> " + previous,
			nodeAvailabilityAlertsPreviousID, nodeAvailabilityAlertsPreviousUp, nodeAvailabilityAlertsPreviousDn,
			"'node.availability.offline'", "'node.availability.recovered'",
			"'node.availability.offline.zh-cn', 1, 'sms'", "'node.availability.recovered.zh-cn', 1, 'email'",
		}},
		{current + "_node_availability_alerts.down.sql", nodeAvailabilityAlertsDownSHA256, []string{
			"(SELECT count(*) FROM schema_migrations) <> " + current, current + "_node_availability_alerts",
			"would discard node alert history",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != script.sha {
			t.Fatalf("%s checksum drift: %s", script.name, got)
		}
		for _, required := range script.required {
			if !strings.Contains(string(raw), required) {
				t.Errorf("%s missing %q", script.name, required)
			}
		}
		if strings.Contains(string(raw), "CASCADE") {
			t.Errorf("%s uses CASCADE", script.name)
		}
	}
}
