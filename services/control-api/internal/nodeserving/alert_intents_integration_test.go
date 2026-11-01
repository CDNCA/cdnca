package nodeserving

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
)

// 状态迁移时通知入队临时失败，保护照常生效；
// 通知意图与状态同事务持久化，通道恢复后补发一次（原事件时间 + 延后通知），再跑不重复；
// 已被后续迁移取代的意图不补发，超过 6 小时的不补发。

func (harness *servingHarness) enableNodeAlerts() {
	harness.t.Helper()
	harness.exec(`INSERT INTO role_permissions(role_id,permission_name)
		SELECT role_id,'nodes.manage' FROM role_assignments WHERE scope_id=$1 AND user_id=$2`, harness.scopeID, harness.userID)
	harness.exec(`UPDATE notification_channel_settings SET sms_enabled=true,email_enabled=true WHERE singleton`)
	notifications, err := notification.NewStore(harness.pool)
	if err != nil {
		harness.t.Fatal(err)
	}
	harness.store.EnableAvailabilityAlerts(notifications)
}

func (harness *servingHarness) breakNotifications() {
	harness.exec(`ALTER TABLE notification_outbox ADD CONSTRAINT reject_all CHECK (false) NOT VALID`)
}

func (harness *servingHarness) repairNotifications() {
	harness.exec(`ALTER TABLE notification_outbox DROP CONSTRAINT reject_all`)
}

func (harness *servingHarness) intentStatuses(eventType string) []string {
	harness.t.Helper()
	rows, err := harness.pool.Query(harness.ctx, `SELECT status FROM node_alert_intents WHERE event_type=$1 ORDER BY occurred_at`, eventType)
	if err != nil {
		harness.t.Fatal(err)
	}
	defer rows.Close()
	var statuses []string
	for rows.Next() {
		var status string
		if err := rows.Scan(&status); err != nil {
			harness.t.Fatal(err)
		}
		statuses = append(statuses, status)
	}
	return statuses
}

// requireDelayedOnce checks one event with both channels, the original event
// time and the delayed-notice mark.
func (harness *servingHarness) requireDelayedOnce(eventType string) {
	harness.t.Helper()
	got := harness.alerts(eventType)
	if len(got) != 1 || got[0].recipient != harness.userID || got[0].outbox != 2 {
		harness.t.Fatalf("%s after recovery=%+v", eventType, got)
	}
	var occurred time.Time
	if err := harness.pool.QueryRow(harness.ctx, `SELECT occurred_at FROM node_alert_intents WHERE event_type=$1`,
		eventType).Scan(&occurred); err != nil {
		harness.t.Fatal(err)
	}
	if !harness.alertBodyContains(got[0].eventID, occurred.UTC().Format(time.RFC3339)+alertIntentDelayedSuffix) {
		harness.t.Fatalf("%s retry lost the original event time or the delayed mark", eventType)
	}
}

func TestAvailabilityAlertEnqueueFailureRetriedOnce(t *testing.T) {
	harness := newServingHarness(t)
	harness.enableNodeAlerts()
	node := harness.addNode()
	harness.activate("pause")
	worker, err := NewWorker(harness.store, time.Second, nil, NewMonitorEvaluator(harness.store), NewAlertIntentEvaluator(harness.store))
	if err != nil {
		t.Fatal(err)
	}
	harness.breakNotifications()
	harness.report(node, false, false, time.Second)
	for range 3 {
		if err := worker.RunOnce(harness.ctx); err != nil {
			t.Fatal(err)
		}
	}
	if held, _, _ := harness.hold(node); !held {
		t.Fatal("notification failure blocked the availability hold")
	}
	if got := harness.alerts(EventTypeNodeOffline); len(got) != 0 {
		t.Fatalf("offline alert enqueued while notifications fail: %+v", got)
	}
	if got := harness.intentStatuses(EventTypeNodeOffline); len(got) != 1 || got[0] != alertIntentPending {
		t.Fatalf("offline intent=%v", got)
	}
	harness.repairNotifications()
	for range 3 { // state unchanged: exactly one late alert
		if err := worker.RunOnce(harness.ctx); err != nil {
			t.Fatal(err)
		}
	}
	harness.requireDelayedOnce(EventTypeNodeOffline)
	if got := harness.intentStatuses(EventTypeNodeOffline); len(got) != 1 || got[0] != alertIntentEnqueued {
		t.Fatalf("offline intent after retry=%v", got)
	}
	// 正常入队不走补发：恢复通知当场入队且不带延后标记。
	harness.report(node, true, true, 0)
	harness.report(node, true, true, 0)
	if err := worker.RunOnce(harness.ctx); err != nil {
		t.Fatal(err)
	}
	recovered := harness.alerts(EventTypeNodeRecovered)
	if len(recovered) != 1 || harness.alertBodyContains(recovered[0].eventID, alertIntentDelayedSuffix) {
		t.Fatalf("recovered alert=%+v", recovered)
	}
}

// 告警与恢复都在故障期间发生：离线意图已被恢复取代，只补恢复一次。
func TestAvailabilityAlertSupersededIntentNotSentLate(t *testing.T) {
	harness := newServingHarness(t)
	harness.enableNodeAlerts()
	node := harness.addNode()
	harness.activate("pause")
	worker, err := NewWorker(harness.store, time.Second, nil, NewMonitorEvaluator(harness.store), NewAlertIntentEvaluator(harness.store))
	if err != nil {
		t.Fatal(err)
	}
	harness.breakNotifications()
	harness.report(node, false, false, time.Second)
	if err := worker.RunOnce(harness.ctx); err != nil {
		t.Fatal(err)
	}
	harness.report(node, true, true, 0)
	harness.report(node, true, true, 0)
	if err := worker.RunOnce(harness.ctx); err != nil {
		t.Fatal(err)
	}
	harness.repairNotifications()
	for range 2 {
		if err := worker.RunOnce(harness.ctx); err != nil {
			t.Fatal(err)
		}
	}
	if got := harness.alerts(EventTypeNodeOffline); len(got) != 0 {
		t.Fatalf("superseded offline alert sent late: %+v", got)
	}
	if got := harness.intentStatuses(EventTypeNodeOffline); len(got) != 1 || got[0] != alertIntentExpired {
		t.Fatalf("superseded offline intent=%v", got)
	}
	harness.requireDelayedOnce(EventTypeNodeRecovered)
}

// 超过补发时效（6 小时）的意图记 expired，不再补发。
func TestAlertIntentOlderThanRetryWindowExpires(t *testing.T) {
	harness := newServingHarness(t)
	harness.enableNodeAlerts()
	node := harness.addNode()
	harness.activate("pause")
	worker, err := NewWorker(harness.store, time.Second, nil, NewMonitorEvaluator(harness.store), NewAlertIntentEvaluator(harness.store))
	if err != nil {
		t.Fatal(err)
	}
	harness.breakNotifications()
	harness.report(node, false, false, time.Second)
	if err := worker.RunOnce(harness.ctx); err != nil {
		t.Fatal(err)
	}
	harness.repairNotifications()
	harness.exec(`UPDATE node_alert_intents SET occurred_at=occurred_at-interval '7 hours'`)
	if err := worker.RunOnce(harness.ctx); err != nil {
		t.Fatal(err)
	}
	if got := harness.alerts(EventTypeNodeOffline); len(got) != 0 {
		t.Fatalf("expired intent sent: %+v", got)
	}
	if got := harness.intentStatuses(EventTypeNodeOffline); len(got) != 1 || got[0] != alertIntentExpired {
		t.Fatalf("old intent=%v", got)
	}
}

func TestBandwidthAlertEnqueueFailureRetriedOnce(t *testing.T) {
	harness := newServingHarness(t)
	harness.enableNodeAlerts()
	node := harness.addNode()
	harness.exec(`UPDATE nodes SET ipv4='192.0.2.20' WHERE id=$1`, node)
	worker, err := NewWorker(harness.store, time.Second, nil, NewAutoDisableEvaluator(harness.store), NewAlertIntentEvaluator(harness.store))
	if err != nil {
		t.Fatal(err)
	}
	harness.autoDisable(node, map[string]any{"bandwidth_limit": 100, "bandwidth_unit": "Mbps", "traffic_types": []string{"outbound"}})
	for range 3 {
		harness.telemetry(node, time.Second, nic("eth0", 0, 200_000_000))
	}
	harness.breakNotifications()
	for range 3 {
		if err := worker.RunOnce(harness.ctx); err != nil {
			t.Fatal(err)
		}
	}
	if held, reason := harness.autoHold(node); !held || reason != ReasonBandwidthExceeded {
		t.Fatalf("bandwidth hold: held=%v reason=%q", held, reason)
	}
	if got := harness.alerts(EventTypeNodeBandwidthExceeded); len(got) != 0 {
		t.Fatalf("bandwidth alert enqueued while notifications fail: %+v", got)
	}
	harness.repairNotifications()
	for range 3 {
		if err := worker.RunOnce(harness.ctx); err != nil {
			t.Fatal(err)
		}
	}
	harness.requireDelayedOnce(EventTypeNodeBandwidthExceeded)
	exceeded := harness.alerts(EventTypeNodeBandwidthExceeded)
	if !harness.alertBodyContains(exceeded[0].eventID, "100 Mbps") {
		t.Fatal("retried bandwidth alert lost the limit captured at transition time")
	}
}

func TestLineBackupAlertEnqueueFailureRetriedOnce(t *testing.T) {
	harness := newServingHarness(t)
	harness.enableNodeAlerts()
	primary, standby := harness.addNode(), harness.addNode()
	groupID, _ := harness.lineGroupWithPriorities(map[uuid.UUID]string{primary: "192.0.2.10", standby: "192.0.2.20"},
		map[uuid.UUID]int{standby: 10})
	harness.activate("pause")
	worker, err := NewWorker(harness.store, time.Second, nil, NewMonitorEvaluator(harness.store),
		NewLineBackupEvaluator(harness.store), NewAlertIntentEvaluator(harness.store))
	if err != nil {
		t.Fatal(err)
	}
	harness.report(primary, true, true, 0)
	harness.report(standby, true, true, 0)
	if err := worker.RunOnce(harness.ctx); err != nil {
		t.Fatal(err)
	}
	harness.report(primary, false, false, 0)
	harness.breakNotifications()
	for range 3 {
		if err := worker.RunOnce(harness.ctx); err != nil {
			t.Fatal(err)
		}
	}
	if state, _ := harness.lineBackup(groupID, 4); state != LineBackupActive {
		t.Fatalf("backup state=%q", state)
	}
	if got := harness.alerts(EventTypeLineBackupActivated); len(got) != 0 {
		t.Fatalf("backup alert enqueued while notifications fail: %+v", got)
	}
	harness.repairNotifications()
	for range 3 {
		if err := worker.RunOnce(harness.ctx); err != nil {
			t.Fatal(err)
		}
	}
	harness.requireDelayedOnce(EventTypeLineBackupActivated)
	activated := harness.alerts(EventTypeLineBackupActivated)
	if !harness.alertBodyContains(activated[0].eventID, "192.0.2.20") {
		t.Fatal("retried backup alert lost the standby address")
	}
	var inbox int
	if err := harness.pool.QueryRow(harness.ctx, `SELECT count(*) FROM admin_inbox_messages
		WHERE recipient_user_id=$1 AND event_type=$2`, harness.userID, EventTypeLineBackupActivated).Scan(&inbox); err != nil || inbox != 1 {
		t.Fatalf("admin inbox copies=%d err=%v", inbox, err)
	}
}
