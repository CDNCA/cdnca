package firewall

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestParseKernelHitHandlesKmsgHeaderAndGlobalScopeOnly(t *testing.T) {
	tenantID, siteID, nodeID, policyID, ruleID := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	rule := Entry{TenantID: tenantID, SiteID: siteID, Action: ActionDeny, Network: "198.51.100.0/24",
		Protocol: ProtocolTCP, PortStart: 443, PortEnd: 443, Source: "global:" + policyID, Reason: "rule:" + ruleID}
	active := activeRecord{Version: FirewallVersion{VersionID: "runtime-v1", Entries: []Entry{rule}}, Scopes: []scopeRecord{{
		TenantID: tenantID, SiteID: siteID, PolicyKind: "global", PolicyID: policyID, Entries: []Entry{rule},
	}}}
	now := time.Unix(1_800_000_000, 0).UTC()
	event, ok := parseKernelHit([]byte("6,42,123456,-;cdnca-fw g1 IN=eth0 SRC=198.51.100.8 PROTO=TCP DPT=443"), active, nodeID, now)
	if !ok {
		t.Fatal("valid kernel hit rejected")
	}
	if uuid.Validate(event.EventID) != nil || event.TenantID != tenantID || event.SiteID != siteID || event.NodeID != nodeID ||
		event.ClientIP != "198.51.100.8" || event.Protocol != "tcp" || event.DestinationPort != 443 ||
		event.SecurityType != "global_firewall" || event.RuleID != ruleID || event.OccurredAt != now {
		t.Fatalf("event=%+v", event)
	}

	active.Scopes[0].PolicyKind = "acl"
	if _, ok := parseKernelHit([]byte("cdnca-fw g1 SRC=198.51.100.8 PROTO=TCP DPT=443"), active, nodeID, now); ok {
		t.Fatal("non-global scope produced a global firewall event")
	}
}

func TestParseKernelHitMapsDefaultDenyWithoutFakeRuleID(t *testing.T) {
	tenantID, siteID, nodeID, policyID := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	entry := Entry{TenantID: tenantID, SiteID: siteID, Action: ActionDeny, Network: "128.0.0.0/1",
		Protocol: ProtocolAny, Source: "global:" + policyID, Reason: "default-deny"}
	active := activeRecord{Version: FirewallVersion{VersionID: "runtime-v2", Entries: []Entry{entry}}, Scopes: []scopeRecord{{
		TenantID: tenantID, SiteID: siteID, PolicyKind: "global", PolicyID: policyID, Entries: []Entry{entry},
	}}}
	event, ok := parseKernelHit([]byte("cdnca-fw ipset SRC=203.0.113.8 PROTO=UDP DPT=53"), active, nodeID, time.Now().UTC())
	if !ok || event.RuleID != "" || event.Protocol != "udp" || event.DestinationPort != 53 {
		t.Fatalf("event=%+v ok=%v", event, ok)
	}
	if _, ok := parseKernelHit([]byte("cdnca-fw ipset SRC=invalid PROTO=UDP DPT=53"), active, nodeID, time.Now().UTC()); ok {
		t.Fatal("malformed source address accepted")
	}
}

func TestParseKernelHitMapsGroupedDropToTheClientsEntry(t *testing.T) {
	tenantID, siteA, siteB, nodeID, policyA, policyB := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	ruleA, ruleB := uuid.NewString(), uuid.NewString()
	first := Entry{TenantID: tenantID, SiteID: siteA, Action: ActionDeny, Network: "198.51.100.0/24",
		Protocol: ProtocolTCP, PortStart: 443, PortEnd: 443, Source: "global:" + policyA, Reason: "rule:" + ruleA}
	second := Entry{TenantID: tenantID, SiteID: siteB, Action: ActionDeny, Network: "203.0.113.0/24",
		Protocol: ProtocolTCP, PortStart: 443, PortEnd: 443, Source: "global:" + policyB, Reason: "rule:" + ruleB}
	active := activeRecord{Version: FirewallVersion{VersionID: "runtime-v3", Entries: []Entry{first, second}}, Scopes: []scopeRecord{
		{TenantID: tenantID, SiteID: siteA, PolicyKind: "global", PolicyID: policyA, Entries: []Entry{first}},
		{TenantID: tenantID, SiteID: siteB, PolicyKind: "global", PolicyID: policyB, Entries: []Entry{second}},
	}}
	if groups := scopedGroups(active.Version.Entries); len(groups) != 1 || len(groups[0].networks) != 2 {
		t.Fatalf("one port, one action, one family must be one set: %+v", groups)
	}
	event, ok := parseKernelHit([]byte("cdnca-fw g1 SRC=203.0.113.7 PROTO=TCP DPT=443"), active, nodeID, time.Now().UTC())
	if !ok || event.SiteID != siteB || event.RuleID != ruleB {
		t.Fatalf("event=%+v ok=%v", event, ok)
	}
	for _, line := range []string{"cdnca-fw g2 SRC=203.0.113.7 PROTO=TCP DPT=443", "cdnca-fw 1 SRC=203.0.113.7 PROTO=TCP DPT=443",
		"cdnca-fw g1 SRC=192.0.2.7 PROTO=TCP DPT=443"} {
		if _, ok := parseKernelHit([]byte(line), active, nodeID, time.Now().UTC()); ok {
			t.Fatalf("%q mapped to an entry", line)
		}
	}
}
