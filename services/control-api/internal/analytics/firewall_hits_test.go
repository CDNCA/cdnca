package analytics

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/firewallcontrol"
	"github.com/google/uuid"
)

func TestFirewallHitCursorBindsTenantSiteAndSnapshot(t *testing.T) {
	tenantID, siteID := uuid.New(), uuid.New()
	cursor := firewallHitCursor{TenantID: tenantID.String(), SiteID: siteID.String(), SnapshotMS: 20, SnapshotID: "snapshot",
		PositionMS: 10, PositionID: "position"}
	encoded, err := json.Marshal(cursor)
	if err != nil {
		t.Fatal(err)
	}
	filter := firewallcontrol.HitFilter{TargetScopeID: tenantID, SiteID: siteID, Cursor: base64.RawURLEncoding.EncodeToString(encoded)}
	if decoded, err := decodeFirewallHitCursor(filter); err != nil || decoded != cursor {
		t.Fatalf("decoded=%+v err=%v", decoded, err)
	}
	filter.TargetScopeID = uuid.New()
	if _, err := decodeFirewallHitCursor(filter); err == nil {
		t.Fatal("cross-tenant cursor accepted")
	}
}

func TestFirewallHitFromRowRejectsMalformedAuthorityData(t *testing.T) {
	tenantID, siteID, nodeID, ruleID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	row := firewallHitRow{EventID: "event-1", OccurredAtMS: time.Unix(1_800_000_000, 0).UnixMilli(), TenantID: tenantID.String(),
		SiteID: siteID.String(), NodeID: nodeID.String(), RuleID: ruleID.String(), ClientIP: "198.51.100.8",
		Protocol: "tcp", DestinationPort: 443, Action: "block"}
	hit, ok := firewallHitFromRow(row, tenantID, tenantID, siteID)
	if !ok || hit.RuleID != ruleID || hit.ReasonCode != "rule:"+ruleID.String() || hit.ClientIP != row.ClientIP {
		t.Fatalf("hit=%+v ok=%v", hit, ok)
	}
	// security_events.client_ip is IPv6: an IPv4 client reads back mapped.
	row.ClientIP = "::ffff:198.51.100.8"
	if hit, ok := firewallHitFromRow(row, tenantID, tenantID, siteID); !ok || hit.ClientIP != "198.51.100.8" {
		t.Fatalf("IPv4-mapped client: hit=%+v ok=%v", hit, ok)
	}
	row.ClientIP = "not-an-ip"
	if _, ok := firewallHitFromRow(row, tenantID, tenantID, siteID); ok {
		t.Fatal("malformed client IP accepted")
	}
	row.ClientIP, row.TenantID = "198.51.100.8", uuid.NewString()
	if _, ok := firewallHitFromRow(row, tenantID, tenantID, siteID); ok {
		t.Fatal("cross-tenant row accepted")
	}
}
