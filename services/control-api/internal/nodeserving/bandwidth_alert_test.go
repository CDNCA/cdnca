package nodeserving

import (
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
)

var testNodeID = uuid.MustParse("6f1d2c3b-4a59-4e6f-8a7b-9c0d1e2f3a4b")

// NODE-N03：带宽超限自动停用/恢复要通知节点管理员；只认 auto_disable 的
// 带宽转换，其它来源与其它原因（流量超额、禁用时段、改设置）不发。
func TestBandwidthAlertEventOnlyForBandwidthTransitions(t *testing.T) {
	for _, test := range []struct {
		name           string
		source         string
		previousHeld   bool
		previousReason string
		decision       Decision
		want           string
	}{
		{"exceeded", SourceAutoDisable, false, "", Decision{Held: true, Reason: ReasonBandwidthExceeded}, EventTypeNodeBandwidthExceeded},
		{"traffic hold turns bandwidth", SourceAutoDisable, true, ReasonTrafficExceeded, Decision{Held: true, Reason: ReasonBandwidthExceeded}, EventTypeNodeBandwidthExceeded},
		{"still exceeded", SourceAutoDisable, true, ReasonBandwidthExceeded, Decision{Held: true, Reason: ReasonBandwidthExceeded}, ""},
		{"recovered", SourceAutoDisable, true, ReasonBandwidthExceeded, Decision{Reason: ReasonBandwidthRecovered}, EventTypeNodeBandwidthRecovered},
		{"bandwidth hold becomes traffic hold", SourceAutoDisable, true, ReasonBandwidthExceeded, Decision{Held: true, Reason: ReasonTrafficExceeded}, ""},
		{"settings changed release", SourceAutoDisable, true, ReasonBandwidthExceeded, Decision{Reason: ReasonSettingsChanged}, ""},
		{"traffic exceeded", SourceAutoDisable, false, "", Decision{Held: true, Reason: ReasonTrafficExceeded}, ""},
		{"monitor source", SourceAvailabilityMonitor, false, "", Decision{Held: true, Reason: ReasonBandwidthExceeded}, ""},
	} {
		if got := bandwidthAlertEvent(test.source, test.previousHeld, test.previousReason, test.decision); got != test.want {
			t.Errorf("%s: event=%q, want %q", test.name, got, test.want)
		}
	}
	for _, eventType := range []string{EventTypeNodeBandwidthExceeded, EventTypeNodeBandwidthRecovered} {
		if !notification.PlatformEventType(eventType) {
			t.Errorf("%s must be a platform event", eventType)
		}
	}
}

func TestFormatBandwidthMbps(t *testing.T) {
	for value, want := range map[any]string{
		uint64(200_000_000): "200 Mbps", uint64(1_234_567_890): "1234.6 Mbps", uint64(0): "0 Mbps",
		float64(100_500_000): "100.5 Mbps", "bad": "-", nil: "-",
	} {
		if got := formatBandwidthMbps(value); got != want {
			t.Errorf("formatBandwidthMbps(%v)=%q, want %q", value, got, want)
		}
	}
}

func TestBandwidthAlertSourceEventID(t *testing.T) {
	id := bandwidthAlertSourceEventID(testNodeID, 7)
	nodeID, revision, ok := parseBandwidthAlertSourceEventID(id)
	if !ok || nodeID != testNodeID || revision != 7 {
		t.Fatalf("round trip %q -> %v %d %v", id, nodeID, revision, ok)
	}
	for _, bad := range []string{"node-availability/" + testNodeID.String() + "/7", "node-bandwidth/x/7", "node-bandwidth/" + testNodeID.String()} {
		if _, _, ok := parseBandwidthAlertSourceEventID(bad); ok {
			t.Errorf("%q parsed", bad)
		}
	}
}
