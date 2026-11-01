package nodeserving

import "testing"

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
