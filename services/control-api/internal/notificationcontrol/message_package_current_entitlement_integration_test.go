//go:build integration

package notificationcontrol

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/packagelinefixture"
	"github.com/google/uuid"
)

// 消息查询的套餐名展示与套餐关键字按当前生效的权益。
// 初购 A、改到 B 后显示 B 的名称、按 B 的名称可搜到、按 A 的名称搜不到（初购快照仍是 A）。
func TestListMessagesPackageNameFollowsCurrentEntitlementPostgres(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	reader := seedControlActor(t, pool, "platform", permissionRead)
	recipient := seedControlActor(t, pool, "tenant")
	lines := packagelinefixture.New(t, pool, packagelinefixture.Options{Scope: recipient.ScopeID, User: recipient.UserID})
	packagelinefixture.Exec(t, pool, `INSERT INTO package_subscription_display_ids(subscription_id) VALUES($1)`, lines.Subscription)
	control, err := NewStoreWithDependencies(pool, audit.New(pool), func() time.Time { return controlTestNow })
	if err != nil {
		t.Fatal(err)
	}
	event := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO notification_events(
		id,scope_id,recipient_user_id,source_event_id,event_type,delivery_policy,request_digest,created_at,subject_package_id)
		VALUES($1,$2,$3,'package-current/1','security.attack.detected','tenant_subscribed',$4,$5,$6)`,
		event, recipient.ScopeID, recipient.UserID, make([]byte, 32), controlTestNow, lines.Subscription); err != nil {
		t.Fatal(err)
	}
	scope := recipient.ScopeID.String()
	name := func(line uuid.UUID) string { return "pkgline-" + line.String()[:8] }
	expect := func(step string, line, other uuid.UUID) {
		t.Helper()
		page, err := control.ListMessages(t.Context(), reader, MessageQuery{ScopeID: scope})
		if err != nil || len(page.Items) != 1 || page.Items[0].PackageName == nil || *page.Items[0].PackageName != name(line) {
			t.Fatalf("%s: page=%+v err=%v, want package %s", step, page, err, name(line))
		}
		if page, err := control.ListMessages(t.Context(), reader, MessageQuery{ScopeID: scope, Package: name(line)}); err != nil || page.Total != 1 {
			t.Fatalf("%s: keyword %s page=%+v err=%v", step, name(line), page, err)
		}
		if page, err := control.ListMessages(t.Context(), reader, MessageQuery{ScopeID: scope, Package: name(other)}); err != nil || page.Total != 0 {
			t.Fatalf("%s: keyword %s page=%+v err=%v", step, name(other), page, err)
		}
	}
	expect("package A", lines.LineA, lines.LineB)
	lines.Change(lines.LineB)
	expect("package B (purchase snapshot still A)", lines.LineB, lines.LineA)
}
