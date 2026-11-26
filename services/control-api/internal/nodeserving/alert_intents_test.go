package nodeserving

import (
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
)

// 补发保留原事件时间并标“延后通知”；首次入队原样。
func TestAlertIntentContextMarksDelayedNotice(t *testing.T) {
	intent := alertIntent{params: map[string]string{"node_name": "edge-1", "occurred_at": "2026-10-28T01:02:03Z"}}
	if got := intent.values(false)["occurred_at"]; got != "2026-10-28T01:02:03Z" {
		t.Fatalf("first enqueue occurred_at=%q", got)
	}
	delayed := intent.values(true)
	if got := delayed["occurred_at"]; got != "2026-10-28T01:02:03Z"+alertIntentDelayedSuffix {
		t.Fatalf("retry occurred_at=%q", got)
	}
	if got := delayed["node_name"]; got != "edge-1" {
		t.Fatalf("retry node_name=%q", got)
	}
	for eventType := range map[string]bool{EventTypeNodeOffline: true, EventTypeNodeRecovered: true,
		EventTypeNodeBandwidthExceeded: true, EventTypeNodeBandwidthRecovered: true,
		EventTypeLineBackupActivated: true, EventTypeLineBackupRestored: true} {
		if alertIntentGuards[eventType] == nil {
			t.Errorf("%s has no supersession guard", eventType)
		}
	}
}

// The English template gets the English delayed mark and standby
// IP list; the Chinese text is unchanged.
func TestAlertIntentContextEnglish(t *testing.T) {
	intent := alertIntent{params: map[string]string{"occurred_at": "2026-10-28T01:02:03Z",
		"backup_addresses": lineBackupAddressText([]string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5", "192.0.2.6"})}}
	got := intent.context(true)
	if want := notification.LocalizedValue("2026-10-28T01:02:03Z"+alertIntentDelayedSuffix,
		"2026-10-28T01:02:03Z (delayed notice)"); got["occurred_at"] != want {
		t.Fatalf("occurred_at = %+v", got["occurred_at"])
	}
	if want := notification.LocalizedValue(intent.params["backup_addresses"],
		"192.0.2.1, 192.0.2.2, 192.0.2.3, 192.0.2.4, 192.0.2.5 (6 in total)"); got["backup_addresses"] != want {
		t.Fatalf("backup_addresses = %+v", got["backup_addresses"])
	}
}
