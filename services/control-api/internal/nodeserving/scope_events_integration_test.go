package nodeserving

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// A10/N06：切换日志按作用域分页查询真实 node_serving_events，筛选（来源/事件/节点/IP）生效，
// 其他作用域的事件不可见，0 条与查询失败分开（0 条返回空 items，非法参数返回 ErrInvalidInput）。
func TestScopeEventsListsRealSwitchFactsWithFilters(t *testing.T) {
	harness := newServingHarness(t)
	nodeA, nodeB := harness.addNode(), harness.addNode()
	harness.exec(`UPDATE nodes SET ipv4='192.0.2.10' WHERE id=$1`, nodeA)
	harness.exec(`UPDATE nodes SET ipv6='2001:db8::20' WHERE id=$1`, nodeB)
	other, tenantID := uuid.New(), uuid.New()
	harness.exec(`INSERT INTO tenants(id,display_name) VALUES($1,'foreign-tenant')`, tenantID)
	harness.exec(`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, other, tenantID)
	foreign := uuid.New()
	harness.display++
	harness.exec(`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id) VALUES($1,$2,'foreign','active',$3,$4)`,
		foreign, other, harness.userID, harness.display)

	apply := func(node, scope uuid.UUID, source string, revision int64, held bool, reason string) {
		t.Helper()
		if ok, err := harness.store.Apply(harness.ctx, node, scope, source, revision, Decision{Held: held, Reason: reason}); err != nil || !ok {
			t.Fatalf("apply %s %s rev %d: ok=%v err=%v", node, source, revision, ok, err)
		}
	}
	apply(nodeA, harness.scopeID, SourceAvailabilityMonitor, 0, true, ReasonProbeUnhealthy)
	apply(nodeA, harness.scopeID, SourceAvailabilityMonitor, 1, false, ReasonProbeRecovered)
	apply(nodeB, harness.scopeID, SourceAutoDisable, 0, true, "bandwidth_limit")
	apply(foreign, other, SourceAvailabilityMonitor, 0, true, ReasonProbeUnhealthy)

	window := ScopeEventQuery{From: time.Now().Add(-time.Hour), To: time.Now().Add(time.Hour), Page: 1, Limit: 10}
	all, err := harness.store.ScopeEvents(harness.ctx, harness.scopeID, window)
	if err != nil || all.Total != 3 || len(all.Items) != 3 {
		t.Fatalf("scope events = %+v %v", all, err)
	}
	for _, item := range all.Items {
		if item.NodeID == foreign {
			t.Fatal("foreign scope event leaked")
		}
	}
	if all.Items[0].OccurredAt.Before(all.Items[2].OccurredAt) {
		t.Fatal("events not newest first")
	}

	filtered := window
	filtered.Event = EventReleased
	if page, err := harness.store.ScopeEvents(harness.ctx, harness.scopeID, filtered); err != nil || page.Total != 1 ||
		page.Items[0].NodeID != nodeA || page.Items[0].ReasonCode != ReasonProbeRecovered || page.Items[0].IPv4 != "192.0.2.10" {
		t.Fatalf("event filter = %+v %v", page, err)
	}
	filtered = window
	filtered.Source = SourceAutoDisable
	if page, err := harness.store.ScopeEvents(harness.ctx, harness.scopeID, filtered); err != nil || page.Total != 1 || page.Items[0].NodeID != nodeB {
		t.Fatalf("source filter = %+v %v", page, err)
	}
	filtered = window
	filtered.IP = "2001:db8:0::20"
	if page, err := harness.store.ScopeEvents(harness.ctx, harness.scopeID, filtered); err != nil || page.Total != 1 || page.Items[0].NodeID != nodeB {
		t.Fatalf("ip filter = %+v %v", page, err)
	}
	filtered = window
	filtered.NodeID = nodeA
	filtered.Limit, filtered.Page = 1, 2
	if page, err := harness.store.ScopeEvents(harness.ctx, harness.scopeID, filtered); err != nil || page.Total != 2 || len(page.Items) != 1 ||
		page.Items[0].Event.Event != EventHeld {
		t.Fatalf("node filter page 2 = %+v %v", page, err)
	}
	filtered = window
	filtered.NodeID = foreign
	if page, err := harness.store.ScopeEvents(harness.ctx, harness.scopeID, filtered); err != nil || page.Total != 0 || len(page.Items) != 0 {
		t.Fatalf("foreign node must be empty, not error: %+v %v", page, err)
	}
	for _, bad := range []ScopeEventQuery{
		{From: window.From, To: window.To, Page: 1, Limit: 10, Source: "unknown"},
		{From: window.From, To: window.To, Page: 1, Limit: 10, IP: "not-an-ip"},
		{From: window.To, To: window.From, Page: 1, Limit: 10},
	} {
		if _, err := harness.store.ScopeEvents(harness.ctx, harness.scopeID, bad); err != ErrInvalidInput {
			t.Fatalf("bad query %+v: %v", bad, err)
		}
	}
}
