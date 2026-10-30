package notificationcontrol

import (
	"strconv"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
)

// 消息查询的用户/套餐/网站可按名称或展示 ID 过滤。
// PG 用例，按测试规则由合并任务统一跑。
func TestListMessagesMatchesKeywords(t *testing.T) {
	pool := notificationControlPool(t)
	// 消息查询是平台读取（system_configuration.read 不能授给租户角色）；接收人在租户作用域，按 ScopeID 过滤。
	reader := seedControlActor(t, pool, "platform", permissionRead)
	recipient := seedControlActor(t, pool, "tenant")
	control, err := NewStoreWithDependencies(pool, audit.New(pool), func() time.Time { return controlTestNow })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE users SET username='keyword-zhang',display_name='张三' WHERE id=$1`, recipient.UserID); err != nil {
		t.Fatal(err)
	}
	var displayID int64
	if err := pool.QueryRow(t.Context(), `SELECT display_id FROM users WHERE id=$1`, recipient.UserID).Scan(&displayID); err != nil {
		t.Fatal(err)
	}
	siteID := uuid.New()
	event := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO notification_events(
		id,scope_id,recipient_user_id,source_event_id,event_type,delivery_policy,request_digest,created_at,subject_site_id)
		VALUES($1,$2,$3,'keyword/1','security.attack.detected','tenant_subscribed',$4,$5,$6)`,
		event, recipient.ScopeID, recipient.UserID, make([]byte, 32), controlTestNow, siteID); err != nil {
		t.Fatal(err)
	}
	scope := recipient.ScopeID.String()
	for name, query := range map[string]MessageQuery{
		"username": {ScopeID: scope, User: "ZHANG"}, "display name": {ScopeID: scope, User: "张"},
		"display ID": {ScopeID: scope, User: strconv.FormatInt(displayID, 10)},
	} {
		page, err := control.ListMessages(t.Context(), reader, query)
		if err != nil || page.Total != 1 || page.Items[0].ID != event {
			t.Fatalf("%s page=%+v err=%v", name, page, err)
		}
	}
	// 名称不命中、站点已不存在（只剩事件事实）时关键字不匹配，返回空页。
	for name, query := range map[string]MessageQuery{
		"other user": {ScopeID: scope, User: "lisi"}, "deleted site": {ScopeID: scope, Site: "example.test"},
		"no package": {ScopeID: scope, Package: "basic"},
	} {
		page, err := control.ListMessages(t.Context(), reader, query)
		if err != nil || page.Total != 0 || len(page.Items) != 0 {
			t.Fatalf("%s page=%+v err=%v", name, page, err)
		}
	}
	own, err := control.ListOwnMessages(t.Context(), recipient, OwnMessageQuery{Site: "example.test"})
	if err != nil || own.Total != 0 {
		t.Fatalf("own site keyword=%+v err=%v", own, err)
	}
}
