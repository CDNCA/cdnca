package nodeserving

import (
	"context"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
)

// FX33：节点离线/恢复要按 notification_event_policies 给节点管理员发告警，
// 与 monitor_action 无关（none 也发，但不摘除）。
func TestAvailabilityAlertsFollowProbesWithoutPause(t *testing.T) {
	harness := newServingHarness(t)
	harness.exec(`INSERT INTO role_permissions(role_id,permission_name)
		SELECT role_id,'nodes.manage' FROM role_assignments WHERE scope_id=$1 AND user_id=$2`, harness.scopeID, harness.userID)
	harness.exec(`UPDATE notification_channel_settings SET sms_enabled=true,email_enabled=true WHERE singleton`)
	notifications, err := notification.NewStore(harness.pool)
	if err != nil {
		t.Fatal(err)
	}
	harness.store.EnableAvailabilityAlerts(notifications)
	node := harness.addNode()
	harness.activate("none")
	worker, err := NewWorker(harness.store, time.Second, nil, NewMonitorEvaluator(harness.store))
	if err != nil {
		t.Fatal(err)
	}
	harness.report(node, false, false, time.Second)
	for range 2 { // second run must not alert again
		if err := worker.RunOnce(harness.ctx); err != nil {
			t.Fatal(err)
		}
	}
	if held, _, _ := harness.hold(node); held {
		t.Fatal("action none must not remove the node from serving")
	}
	offline := harness.alerts(EventTypeNodeOffline)
	if len(offline) != 1 || offline[0].outbox != 2 {
		t.Fatalf("offline alerts with action none=%+v", offline)
	}
	// The platform message center gets one copy whatever the channels.
	var inbox int
	var nodeName string
	if err := harness.pool.QueryRow(harness.ctx, `SELECT count(*),max(params->>'node_name') FROM admin_inbox_messages
		WHERE recipient_user_id=$1 AND event_type=$2`, harness.userID, EventTypeNodeOffline).Scan(&inbox, &nodeName); err != nil || inbox != 1 || nodeName == "" {
		t.Fatalf("admin inbox offline copies=%d node_name=%q err=%v", inbox, nodeName, err)
	}
	harness.report(node, true, true, 0)
	harness.report(node, true, true, 0)
	if err := worker.RunOnce(harness.ctx); err != nil {
		t.Fatal(err)
	}
	if recovered := harness.alerts(EventTypeNodeRecovered); len(recovered) != 1 {
		t.Fatalf("recovered alerts with action none=%+v", recovered)
	}
	if harness.guard(offline[0].eventID) {
		t.Fatal("offline repeat still current after recovery")
	}
	// 关闭监控是“不再观察”，不是恢复：只清状态，不发恢复通知。
	harness.report(node, false, false, 0)
	if err := worker.RunOnce(harness.ctx); err != nil {
		t.Fatal(err)
	}
	harness.exec(`INSERT INTO node_monitoring_overrides(node_id,scope_id,revision,monitor_enabled,updated_by_user_id,created_at,updated_at)
		VALUES($1,$2,1,false,$3,now(),now())`, node, harness.scopeID, harness.userID)
	if err := worker.RunOnce(harness.ctx); err != nil {
		t.Fatal(err)
	}
	if got := harness.alerts(EventTypeNodeRecovered); len(got) != 1 {
		t.Fatalf("monitor disabled sent a recovery: %+v", got)
	}
	var offlineNow bool
	if err := harness.pool.QueryRow(harness.ctx, `SELECT offline FROM node_availability_alert_states WHERE node_id=$1`, node).Scan(&offlineNow); err != nil || offlineNow {
		t.Fatalf("alert state not reset: offline=%v err=%v", offlineNow, err)
	}
}

func TestAvailabilityHoldTransitionsEnqueueNodeAlerts(t *testing.T) {
	harness := newServingHarness(t)
	harness.exec(`INSERT INTO role_permissions(role_id,permission_name)
		SELECT role_id,'nodes.manage' FROM role_assignments WHERE scope_id=$1 AND user_id=$2`, harness.scopeID, harness.userID)
	viewer := uuid.New()
	harness.exec(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'serving-viewer','Viewer','test-only')`, viewer)
	harness.exec(`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, harness.scopeID, viewer)
	harness.exec(`UPDATE notification_channel_settings SET sms_enabled=true,email_enabled=true WHERE singleton`)
	notifications, err := notification.NewStore(harness.pool)
	if err != nil {
		t.Fatal(err)
	}
	harness.store.EnableAvailabilityAlerts(notifications)
	node := harness.addNode()
	harness.exec(`UPDATE nodes SET ipv4='192.0.2.10' WHERE id=$1`, node)
	harness.activate("pause")
	worker, err := NewWorker(harness.store, time.Second, nil, NewMonitorEvaluator(harness.store))
	if err != nil {
		t.Fatal(err)
	}

	harness.report(node, false, false, time.Second)
	if err := worker.RunOnce(harness.ctx); err != nil {
		t.Fatal(err)
	}
	offline := harness.alerts(EventTypeNodeOffline)
	if len(offline) != 1 || offline[0].recipient != harness.userID || offline[0].outbox != 2 {
		t.Fatalf("offline alerts=%+v (viewer without nodes.manage must not receive)", offline)
	}
	if !harness.alertBodyContains(offline[0].eventID, "192.0.2.10") {
		t.Fatal("offline alert does not name the node address")
	}
	if !harness.guard(offline[0].eventID) {
		t.Fatal("current offline alert withdrawn")
	}

	harness.report(node, true, true, 0)
	harness.report(node, true, true, 0)
	if err := worker.RunOnce(harness.ctx); err != nil {
		t.Fatal(err)
	}
	recovered := harness.alerts(EventTypeNodeRecovered)
	if len(recovered) != 1 || recovered[0].recipient != harness.userID {
		t.Fatalf("recovered alerts=%+v", recovered)
	}
	if harness.guard(offline[0].eventID) {
		t.Fatal("offline alert repeat still current after recovery")
	}
	if !harness.guard(recovered[0].eventID) {
		t.Fatal("current recovered alert withdrawn")
	}

	// 管理员在通知策略里关掉该事件：状态照常切换，不再入队。
	harness.exec(`UPDATE notification_event_policies SET enabled=false WHERE event_type=$1`, EventTypeNodeOffline)
	harness.report(node, false, false, 0)
	if err := worker.RunOnce(harness.ctx); err != nil {
		t.Fatal(err)
	}
	if held, _, _ := harness.hold(node); !held {
		t.Fatal("node not held again")
	}
	total := 0
	for _, alert := range harness.alerts(EventTypeNodeOffline) {
		total += alert.outbox
	}
	if total != 2 {
		t.Fatalf("disabled event still delivered: outbox=%d", total)
	}
}

func TestAvailabilityAlertFailureDoesNotBlockHold(t *testing.T) {
	harness := newServingHarness(t)
	harness.exec(`INSERT INTO role_permissions(role_id,permission_name)
		SELECT role_id,'nodes.manage' FROM role_assignments WHERE scope_id=$1 AND user_id=$2`, harness.scopeID, harness.userID)
	harness.exec(`UPDATE notification_channel_settings SET sms_enabled=true,email_enabled=true WHERE singleton`)
	notifications, err := notification.NewStore(harness.pool)
	if err != nil {
		t.Fatal(err)
	}
	harness.store.EnableAvailabilityAlerts(notifications)
	// 通知入队失败（这里用约束注入），摘除节点仍必须照常生效。
	harness.exec(`ALTER TABLE notification_outbox ADD CONSTRAINT reject_all CHECK (false) NOT VALID`)
	node := harness.addNode()
	harness.activate("pause")
	harness.report(node, false, false, time.Second)
	worker, err := NewWorker(harness.store, time.Second, nil, NewMonitorEvaluator(harness.store))
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.RunOnce(harness.ctx); err != nil {
		t.Fatal(err)
	}
	if held, _, _ := harness.hold(node); !held {
		t.Fatal("notification failure blocked the availability hold")
	}
}

type nodeAlert struct {
	eventID   uuid.UUID
	recipient uuid.UUID
	outbox    int
}

func (harness *servingHarness) alerts(eventType string) []nodeAlert {
	harness.t.Helper()
	rows, err := harness.pool.Query(harness.ctx, `SELECT event.id,event.recipient_user_id,
		(SELECT count(*) FROM notification_outbox outbox WHERE outbox.event_id=event.id)
		FROM notification_events event WHERE event.event_type=$1 ORDER BY event.created_at`, eventType)
	if err != nil {
		harness.t.Fatal(err)
	}
	defer rows.Close()
	var result []nodeAlert
	for rows.Next() {
		var item nodeAlert
		if err := rows.Scan(&item.eventID, &item.recipient, &item.outbox); err != nil {
			harness.t.Fatal(err)
		}
		result = append(result, item)
	}
	return result
}

func (harness *servingHarness) alertBodyContains(eventID uuid.UUID, text string) bool {
	harness.t.Helper()
	var found bool
	if err := harness.pool.QueryRow(harness.ctx, `SELECT bool_and(position($2 in body)>0)
		FROM notification_outbox WHERE event_id=$1`, eventID, text).Scan(&found); err != nil {
		harness.t.Fatal(err)
	}
	return found
}

func (harness *servingHarness) guard(eventID uuid.UUID) bool {
	harness.t.Helper()
	var candidate notification.ReplayCandidate
	if err := harness.pool.QueryRow(harness.ctx, `SELECT scope_id,id,event_type,source_event_id
		FROM notification_events WHERE id=$1`, eventID).Scan(
		&candidate.ScopeID, &candidate.EventID, &candidate.EventType, &candidate.SourceEventID); err != nil {
		harness.t.Fatal(err)
	}
	candidate.OutboxID, candidate.Generation = uuid.New(), 2
	tx, err := harness.pool.Begin(harness.ctx)
	if err != nil {
		harness.t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	current, err := AvailabilityAlertReplayGuard(harness.ctx, tx, candidate)
	if err != nil {
		harness.t.Fatal(err)
	}
	return current
}

// NODE-N03：带宽超限自动停用与恢复各通知一次节点管理员（nodes.manage），
// 与 hold 同事务；重复提醒在 hold 再变化后撤回；流量超额不发带宽告警；
// 租户（卖方）节点不发。
func TestBandwidthAutoDisableEnqueuesNodeAlerts(t *testing.T) {
	harness := newServingHarness(t)
	harness.exec(`INSERT INTO role_permissions(role_id,permission_name)
		SELECT role_id,'nodes.manage' FROM role_assignments WHERE scope_id=$1 AND user_id=$2`, harness.scopeID, harness.userID)
	viewer := uuid.New()
	harness.exec(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'bandwidth-viewer','Viewer','test-only')`, viewer)
	harness.exec(`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, harness.scopeID, viewer)
	harness.exec(`UPDATE notification_channel_settings SET sms_enabled=true,email_enabled=true WHERE singleton`)
	notifications, err := notification.NewStore(harness.pool)
	if err != nil {
		t.Fatal(err)
	}
	harness.store.EnableAvailabilityAlerts(notifications)
	node := harness.addNode()
	harness.exec(`UPDATE nodes SET ipv4='192.0.2.20' WHERE id=$1`, node)
	worker, err := NewWorker(harness.store, time.Second, nil, NewAutoDisableEvaluator(harness.store))
	if err != nil {
		t.Fatal(err)
	}
	run := func() {
		t.Helper()
		if err := worker.RunOnce(harness.ctx); err != nil {
			t.Fatal(err)
		}
	}
	harness.autoDisable(node, map[string]any{"bandwidth_limit": 100, "bandwidth_unit": "Mbps", "traffic_types": []string{"outbound"}})
	for range 3 {
		harness.telemetry(node, time.Second, nic("eth0", 0, 200_000_000))
	}
	run()
	run() // still held: no second alert
	if held, reason := harness.autoHold(node); !held || reason != ReasonBandwidthExceeded {
		t.Fatalf("bandwidth hold: held=%v reason=%q", held, reason)
	}
	exceeded := harness.alerts(EventTypeNodeBandwidthExceeded)
	if len(exceeded) != 1 || exceeded[0].recipient != harness.userID || exceeded[0].outbox != 2 {
		t.Fatalf("exceeded alerts=%+v (viewer without nodes.manage must not receive)", exceeded)
	}
	if !harness.alertBodyContains(exceeded[0].eventID, "192.0.2.20") || !harness.alertBodyContains(exceeded[0].eventID, "100 Mbps") {
		t.Fatal("exceeded alert does not name the node address and limit")
	}
	if !harness.bandwidthGuard(exceeded[0].eventID) {
		t.Fatal("current exceeded alert withdrawn")
	}
	var inbox int
	if err := harness.pool.QueryRow(harness.ctx, `SELECT count(*) FROM admin_inbox_messages
		WHERE recipient_user_id=$1 AND event_type=$2`, harness.userID, EventTypeNodeBandwidthExceeded).Scan(&inbox); err != nil || inbox != 1 {
		t.Fatalf("admin inbox exceeded copies=%d err=%v", inbox, err)
	}

	for range 3 {
		harness.telemetry(node, time.Second, nic("eth0", 0, 10_000_000))
	}
	harness.exec(`UPDATE node_serving_holds SET held_since=held_since-interval '10 minutes',revision=revision+1,
		changed_at=clock_timestamp(),updated_at=clock_timestamp() WHERE node_id=$1 AND source='auto_disable'`, node)
	run()
	if held, reason := harness.autoHold(node); held || reason != ReasonBandwidthRecovered {
		t.Fatalf("bandwidth recovery: held=%v reason=%q", held, reason)
	}
	recovered := harness.alerts(EventTypeNodeBandwidthRecovered)
	if len(recovered) != 1 || recovered[0].recipient != harness.userID {
		t.Fatalf("recovered alerts=%+v", recovered)
	}
	if harness.bandwidthGuard(exceeded[0].eventID) {
		t.Fatal("exceeded alert repeat still current after recovery")
	}

	// Traffic quota holds are not bandwidth alerts.
	harness.autoDisable(node, map[string]any{"bandwidth_limit": 0, "disabled_periods": "00:00:00-23:59:59"})
	run()
	if held, _ := harness.autoHold(node); !held {
		t.Fatal("disabled window did not hold the node")
	}
	if got := harness.alerts(EventTypeNodeBandwidthExceeded); len(got) != 1 {
		t.Fatalf("non-bandwidth hold sent a bandwidth alert: %+v", got)
	}

	// Tenant-owned nodes are not alerted.
	tenantScope, tenantID := uuid.New(), uuid.New()
	harness.exec(`INSERT INTO tenants(id,display_name) VALUES($1,'Bandwidth seller')`, tenantID)
	harness.exec(`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, tenantScope, tenantID)
	tenantNode := uuid.New()
	harness.exec(`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id) VALUES($1,$2,'tenant-node','active',$3,9999)`,
		tenantNode, tenantScope, harness.userID)
	if _, err := harness.store.Apply(harness.ctx, tenantNode, tenantScope, SourceAutoDisable, 0,
		Decision{Held: true, Reason: ReasonBandwidthExceeded}); err != nil {
		t.Fatal(err)
	}
	if got := harness.alerts(EventTypeNodeBandwidthExceeded); len(got) != 1 {
		t.Fatalf("tenant node alerted: %+v", got)
	}
}

func (harness *servingHarness) bandwidthGuard(eventID uuid.UUID) bool {
	harness.t.Helper()
	var candidate notification.ReplayCandidate
	if err := harness.pool.QueryRow(harness.ctx, `SELECT scope_id,id,event_type,source_event_id
		FROM notification_events WHERE id=$1`, eventID).Scan(
		&candidate.ScopeID, &candidate.EventID, &candidate.EventType, &candidate.SourceEventID); err != nil {
		harness.t.Fatal(err)
	}
	candidate.OutboxID, candidate.Generation = uuid.New(), 2
	tx, err := harness.pool.Begin(harness.ctx)
	if err != nil {
		harness.t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	current, err := BandwidthAlertReplayGuard(harness.ctx, tx, candidate)
	if err != nil {
		harness.t.Fatal(err)
	}
	return current
}
