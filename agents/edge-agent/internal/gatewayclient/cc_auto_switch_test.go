package gatewayclient

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

const (
	ccTestNodeID  = "018f47a2-5b9c-7d31-8a60-104c9c0b7a01"
	ccTestScopeID = "018f47a2-5b9c-7d31-8a60-104c9c0b7a02"
	ccTestSiteID  = "018f47a2-5b9c-7d31-8a60-104c9c0b7a03"
)

// FX65: an engagement is queued as a CC_AUTO_SWITCH report (config revision
// 0, no load metrics, occurred at the engage second); the same engagement
// observed again is queued once, durably.
func TestNodeMonitoringBridgeQueuesCCAutoSwitchOncePerEngagement(t *testing.T) {
	root := t.TempDir()
	bridge, err := NewNodeMonitoringBridge(root, ccTestNodeID)
	if err != nil {
		t.Fatal(err)
	}
	event := CCAutoSwitchEvent{NodeID: ccTestNodeID, TenantScopeID: ccTestScopeID, SiteID: ccTestSiteID,
		PolicyID: ccTestScopeID, PolicyVersion: 7, EngagedAt: time.Unix(1760000000, 400_000_000),
		TriggerQPS: 1200, QPSTotal: 1000, RecoverSeconds: 300}
	if err := bridge.NotifyCCAutoSwitch(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if err := bridge.NotifyCCAutoSwitch(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	pending := bridge.Pending()
	if len(pending) != 1 {
		t.Fatalf("pending = %d, want 1", len(pending))
	}
	report := pending[0]
	if report.Kind != agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_CC_AUTO_SWITCH ||
		report.ConfigRevision != 0 || report.LoadMetricsV1 != nil ||
		!report.Event.OccurredTime.AsTime().Equal(time.Unix(1760000000, 0)) {
		t.Fatalf("report = %+v", report)
	}
	var payload map[string]any
	if err := json.Unmarshal(report.PayloadJson, &payload); err != nil || payload["schema_version"] != float64(1) ||
		payload["site_id"] != ccTestSiteID || payload["engaged_at"] != "2025-10-09T08:53:20Z" || payload["trigger_qps"] != float64(1200) {
		t.Fatalf("payload = %s, %v", report.PayloadJson, err)
	}
	reopened, err := NewNodeMonitoringBridge(root, ccTestNodeID)
	if err != nil || len(reopened.Pending()) != 1 {
		t.Fatalf("reopened outbox = %v, %v", reopened, err)
	}
	if err := reopened.NotifyCCAutoSwitch(context.Background(), event); err != nil || len(reopened.Pending()) != 1 {
		t.Fatalf("re-observed engagement after restart = %v, %d pending", err, len(reopened.Pending()))
	}
	// A later engagement of the same site is a new event.
	event.EngagedAt = event.EngagedAt.Add(10 * time.Minute)
	if err := reopened.NotifyCCAutoSwitch(context.Background(), event); err != nil || len(reopened.Pending()) != 2 {
		t.Fatalf("next engagement = %v, %d pending", err, len(reopened.Pending()))
	}
	for _, invalid := range []CCAutoSwitchEvent{
		{NodeID: "other", TenantScopeID: ccTestScopeID, SiteID: ccTestSiteID, PolicyID: ccTestScopeID, PolicyVersion: 1, EngagedAt: time.Unix(1, 0)},
		{NodeID: ccTestNodeID, TenantScopeID: "x", SiteID: ccTestSiteID, PolicyID: ccTestScopeID, PolicyVersion: 1, EngagedAt: time.Unix(1, 0)},
		{NodeID: ccTestNodeID, TenantScopeID: ccTestScopeID, SiteID: ccTestSiteID, PolicyID: ccTestScopeID, EngagedAt: time.Unix(1, 0)},
		{NodeID: ccTestNodeID, TenantScopeID: ccTestScopeID, SiteID: ccTestSiteID, PolicyID: ccTestScopeID, PolicyVersion: 1},
	} {
		if err := reopened.NotifyCCAutoSwitch(context.Background(), invalid); err == nil {
			t.Errorf("invalid event %+v was queued", invalid)
		}
	}
}
