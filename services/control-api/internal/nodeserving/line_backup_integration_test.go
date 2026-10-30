package nodeserving

import (
	"context"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
)

// fix-backupnotify：线路组主 IP 被监控摘除、开始解析到备用 IP 时给节点管理员发一次“启用备用 IP”，
// 主 IP 恢复后发一次“恢复主 IP”；同一状态多次评估不重复发，旧提醒在状态再迁移后撤回。
func TestLineBackupStateFollowsHoldsAndAlertsOnce(t *testing.T) {
	harness := newServingHarness(t)
	harness.exec(`INSERT INTO role_permissions(role_id,permission_name)
		SELECT role_id,'nodes.manage' FROM role_assignments WHERE scope_id=$1 AND user_id=$2`, harness.scopeID, harness.userID)
	harness.exec(`UPDATE notification_channel_settings SET sms_enabled=true,email_enabled=true WHERE singleton`)
	notifications, err := notification.NewStore(harness.pool)
	if err != nil {
		t.Fatal(err)
	}
	harness.store.EnableAvailabilityAlerts(notifications)
	primary, standby := harness.addNode(), harness.addNode()
	groupID, _ := harness.lineGroup(map[uuid.UUID]string{primary: "192.0.2.10", standby: "192.0.2.20"})
	// 备用端点优先级更低（数值更大）。
	harness.exec(`UPDATE node_line_endpoints SET priority=10 WHERE line_group_id=$1 AND node_id=$2`, groupID, standby)
	harness.activate("pause")
	worker, err := NewWorker(harness.store, time.Second, nil, NewMonitorEvaluator(harness.store), NewLineBackupEvaluator(harness.store))
	if err != nil {
		t.Fatal(err)
	}
	harness.report(primary, true, true, 0)
	harness.report(standby, true, true, 0)
	run := func() {
		t.Helper()
		if err := worker.RunOnce(harness.ctx); err != nil {
			t.Fatal(err)
		}
	}
	run()
	if state, _ := harness.lineBackup(groupID, 4); state != "" {
		t.Fatalf("normal group wrote state %q", state)
	}
	// 主 IP 节点连续失败被摘除 → 备用 IP 发布。
	harness.report(primary, false, false, 0)
	run()
	run()
	state, addresses := harness.lineBackup(groupID, 4)
	if state != LineBackupActive || len(addresses) != 1 || addresses[0] != "192.0.2.20" {
		t.Fatalf("backup state=%q addresses=%v", state, addresses)
	}
	activated := harness.alerts(EventTypeLineBackupActivated)
	if len(activated) != 1 || !harness.alertBodyContains(activated[0].eventID, "192.0.2.20") {
		t.Fatalf("activated alerts=%+v", activated)
	}
	var inbox int
	if err := harness.pool.QueryRow(harness.ctx, `SELECT count(*) FROM admin_inbox_messages
		WHERE recipient_user_id=$1 AND event_type=$2`, harness.userID, EventTypeLineBackupActivated).Scan(&inbox); err != nil || inbox != 1 {
		t.Fatalf("admin inbox copies=%d err=%v", inbox, err)
	}
	// 主 IP 恢复 → 回正常，发恢复，旧提醒撤回。
	harness.report(primary, true, true, 0)
	harness.report(primary, true, true, 0)
	run()
	run()
	if state, addresses := harness.lineBackup(groupID, 4); state != LineBackupNormal || len(addresses) != 0 {
		t.Fatalf("restored state=%q addresses=%v", state, addresses)
	}
	if restored := harness.alerts(EventTypeLineBackupRestored); len(restored) != 1 {
		t.Fatalf("restored alerts=%+v", restored)
	}
	if harness.lineBackupGuard(activated[0].eventID) {
		t.Fatal("activation repeat still current after restore")
	}
	if got := harness.alerts(EventTypeLineBackupActivated); len(got) != 1 {
		t.Fatalf("activation repeated: %+v", got)
	}
	// 全部离线：视图兜底全发布，备用也离线，不算启用备用。
	harness.report(primary, false, false, 0)
	harness.report(standby, false, false, 0)
	run()
	run()
	if state, _ := harness.lineBackup(groupID, 4); state == LineBackupActive {
		t.Fatal("all offline counted as backup active")
	}
}

func (harness *servingHarness) lineBackup(groupID uuid.UUID, family int) (string, []string) {
	harness.t.Helper()
	var state string
	var addresses []string
	err := harness.pool.QueryRow(harness.ctx, `SELECT state,ARRAY(SELECT host(address) FROM unnest(backup_addresses) address)
		FROM node_line_group_backup_states WHERE tenant_scope_id=$1 AND line_group_id=$2 AND address_family=$3`,
		harness.scopeID, groupID, family).Scan(&state, &addresses)
	if err != nil {
		return "", nil
	}
	return state, addresses
}

func (harness *servingHarness) lineBackupGuard(eventID uuid.UUID) bool {
	harness.t.Helper()
	var candidate notification.ReplayCandidate
	if err := harness.pool.QueryRow(harness.ctx, `SELECT scope_id,id,event_type,source_event_id
		FROM notification_events WHERE id=$1`, eventID).Scan(
		&candidate.ScopeID, &candidate.EventID, &candidate.EventType, &candidate.SourceEventID); err != nil {
		harness.t.Fatal(err)
	}
	tx, err := harness.pool.Begin(harness.ctx)
	if err != nil {
		harness.t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	current, err := LineBackupReplayGuard(harness.ctx, tx, candidate)
	if err != nil {
		harness.t.Fatal(err)
	}
	return current
}
