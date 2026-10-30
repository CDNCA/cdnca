package notificationcontrol

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
)

// SEC-ACCOUNT-07（迁移 499）：本人消息只看自己在本作用域收到的可订阅运营事件，
// 站点/套餐 ID 是事件时的事实。PG 用例，按 10-25 测试规则待出包前全量跑。
func TestListOwnMessagesIsSelfScopedAndKeepsSubjectFacts(t *testing.T) {
	pool := notificationControlPool(t)
	owner := seedControlActor(t, pool, "tenant")
	other := seedControlActor(t, pool, "tenant")
	control, err := NewStoreWithDependencies(pool, audit.New(pool), func() time.Time { return controlTestNow })
	if err != nil {
		t.Fatal(err)
	}
	siteID, packageID := uuid.New(), uuid.New()
	insert := func(actor Actor, source, eventType, policy string, site, pkg *uuid.UUID, at time.Time) uuid.UUID {
		t.Helper()
		id := uuid.New()
		if _, err := pool.Exec(t.Context(), `INSERT INTO notification_events(
			id,scope_id,recipient_user_id,source_event_id,event_type,delivery_policy,request_digest,created_at,
			subject_site_id,subject_package_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
			id, actor.ScopeID, actor.UserID, source, eventType, policy, make([]byte, 32), at, site, pkg); err != nil {
			t.Fatal(err)
		}
		return id
	}
	attack := insert(owner, "attack/1", "security.attack.detected", "tenant_subscribed", &siteID, nil, controlTestNow.Add(-time.Minute))
	traffic := insert(owner, "traffic/1", "package.monitor.traffic.triggered", "tenant_subscribed", nil, &packageID, controlTestNow.Add(-2*time.Minute))
	insert(owner, "announcement/1", EventTypeAnnouncementPublished, "tenant_subscribed", nil, nil, controlTestNow)
	insert(owner, "verification/1", "identity.secondary_verification", "system_required", nil, nil, controlTestNow)
	insert(other, "attack/2", "security.attack.detected", "tenant_subscribed", &siteID, nil, controlTestNow)

	page, err := control.ListOwnMessages(t.Context(), owner, OwnMessageQuery{})
	if err != nil || page.Total != 2 || len(page.Items) != 2 || page.Items[0].ID != attack || page.Items[1].ID != traffic ||
		page.Items[0].SiteID == nil || *page.Items[0].SiteID != siteID || page.Items[1].PackageID == nil || *page.Items[1].PackageID != packageID {
		t.Fatalf("own page=%+v err=%v", page, err)
	}
	page, err = control.ListOwnMessages(t.Context(), owner, OwnMessageQuery{SiteID: siteID.String()})
	if err != nil || page.Total != 1 || page.Items[0].ID != attack {
		t.Fatalf("site filter=%+v err=%v", page, err)
	}
	page, err = control.ListOwnMessages(t.Context(), owner, OwnMessageQuery{PackageID: packageID.String(), Limit: "1", Offset: "0"})
	if err != nil || page.Total != 1 || page.Items[0].ID != traffic {
		t.Fatalf("package filter=%+v err=%v", page, err)
	}
	page, err = control.ListOwnMessages(t.Context(), owner, OwnMessageQuery{Limit: "1", Offset: "1"})
	if err != nil || page.Total != 2 || len(page.Items) != 1 || page.Items[0].ID != traffic {
		t.Fatalf("offset page=%+v err=%v", page, err)
	}
	page, err = control.ListOwnMessages(t.Context(), other, OwnMessageQuery{})
	if err != nil || page.Total != 1 || page.Items[0].ID == attack {
		t.Fatalf("other page=%+v err=%v", page, err)
	}
}
