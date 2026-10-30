package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// G9c-④ 节点离线告警状态（与 monitor_action 解耦）。占位号 321（守卫指向 320 头），
// 合入时如改号，只改这里的常量和两个 SQL 文件头部。
const (
	nodeAvailabilityAlertStatesVersion    = 321
	nodeAvailabilityAlertStatesPreviousID = "320_retention_cleanup"
	nodeAvailabilityAlertStatesPreviousUp = "95a73b22348a55322f13fa7c0605004c71d102abb5f1977beae57317e5909eb5"
	nodeAvailabilityAlertStatesPreviousDn = "d1c616198a0041b502f01b7ad5f8da0d4c9c09aa0e9b8efa0b971eed00c6231b"
	nodeAvailabilityAlertStatesUpSHA256   = "acd73fe79225092cea6a792821943581292c8c5a566aee452749c0b111546117"
	nodeAvailabilityAlertStatesDownSHA256 = "52135be11ac5e4570e63da1ec438295b29e528df73842915be486982e412f99c"
)

func TestNodeAvailabilityAlertStatesMigrationContract(t *testing.T) {
	previous := fmt.Sprint(nodeAvailabilityAlertStatesVersion - 1)
	current := fmt.Sprint(nodeAvailabilityAlertStatesVersion)
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{current + "_node_availability_alert_states.up.sql", nodeAvailabilityAlertStatesUpSHA256, []string{
			"(SELECT count(*) FROM schema_migrations) <> " + previous,
			nodeAvailabilityAlertStatesPreviousID, nodeAvailabilityAlertStatesPreviousUp, nodeAvailabilityAlertStatesPreviousDn,
			"CREATE TABLE node_availability_alert_states", "CHECK (offline = (offline_since IS NOT NULL))",
		}},
		{current + "_node_availability_alert_states.down.sql", nodeAvailabilityAlertStatesDownSHA256, []string{
			"(SELECT count(*) FROM schema_migrations) <> " + current, current + "_node_availability_alert_states",
			"DROP TABLE node_availability_alert_states",
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
