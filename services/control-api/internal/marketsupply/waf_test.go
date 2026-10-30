package marketsupply

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

func wafConfig(t *testing.T, waf siteWAF) siteconf.Config {
	t.Helper()
	cfg := settingsConfig()
	cfg.WAF, _ = json.Marshal(waf)
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func sqliRule() securitypolicy.Rule {
	return securitypolicy.Rule{Name: "sqli", Priority: 1, Enabled: true, Action: securitypolicy.ActionBlock, Flow: securitypolicy.FlowStop,
		Conditions: []securitypolicy.Condition{{Field: "query", Operator: "contains", Values: []string{"union select"}}}}
}

// fix-mktsiteconf2 ②: a waf block becomes a publishable local WAF policy.
func TestWAFFieldsMapTheBlock(t *testing.T) {
	cfg := wafConfig(t, siteWAF{DefaultAction: securitypolicy.ActionAllow, Rules: []securitypolicy.Rule{sqliRule()},
		WAFSettings: &securitypolicy.WAFSettings{Mode: "observe"}})
	waf, err := decodeSiteWAF(cfg)
	if err != nil || waf == nil {
		t.Fatalf("decode %v", err)
	}
	fields, err := wafFields(waf)
	if err != nil || fields.Kind != securitypolicy.KindWAF || len(fields.Rules) != 1 || fields.WAFSettings.Mode != "observe" {
		t.Fatalf("fields = %+v %v", fields, err)
	}
	if blockers := (&Service{}).wafBlockers(t.Context(), cfg, true); len(blockers) != 0 {
		t.Fatalf("blockers %v", blockers)
	}
}

func TestWAFBlockers(t *testing.T) {
	service := &Service{}
	good := wafConfig(t, siteWAF{DefaultAction: securitypolicy.ActionAllow, Rules: []securitypolicy.Rule{sqliRule()}})
	if b := service.wafBlockers(t.Context(), good, false); len(b) != 1 || b[0].Code != "unsupported_waf" || b[0].Detail != activationPending {
		t.Fatalf("unwired: %v", b)
	}
	listedID := "018f47a2-5b9c-7d31-8a60-104c9c0b7101"
	listed := sqliRule()
	listed.Conditions = []securitypolicy.Condition{{Field: "ip_list", Operator: "in_ip_list", Values: []string{listedID}}}
	for name, cfg := range map[string]siteconf.Config{
		"ip list without its list": wafConfig(t, siteWAF{DefaultAction: securitypolicy.ActionAllow, Rules: []securitypolicy.Rule{listed}}),
		"empty list": wafConfig(t, siteWAF{DefaultAction: securitypolicy.ActionAllow, Rules: []securitypolicy.Rule{listed},
			IPLists: map[string]siteIPList{listedID: {Name: "x", CIDRs: []string{}}}}),
		"unknown": func() siteconf.Config { c := settingsConfig(); c.WAF = json.RawMessage(`{"rules":[],"x":1}`); return c }(),
		"action":  wafConfig(t, siteWAF{DefaultAction: "explode", Rules: []securitypolicy.Rule{}}),
	} {
		if b := service.wafBlockers(t.Context(), cfg, true); len(b) != 1 || b[0].Code != "waf_invalid" {
			t.Fatalf("%s: %v", name, b)
		}
	}
}

// fix-mktsiteconf3 ⑥: a rule naming a carried IP list maps onto the leaf's
// own list; CRS application types need the leaf's CRS wiring.
func TestWAFIPListsMapOntoLeafLists(t *testing.T) {
	listedID := "018f47a2-5b9c-7d31-8a60-104c9c0b7101"
	listed := sqliRule()
	listed.Conditions = []securitypolicy.Condition{{Field: "ip_list", Operator: "in_ip_list", Values: []string{listedID}}}
	cfg := wafConfig(t, siteWAF{DefaultAction: securitypolicy.ActionAllow, Rules: []securitypolicy.Rule{listed},
		IPLists: map[string]siteIPList{listedID: {Name: "bad bots", CIDRs: []string{"192.0.2.0/24", "198.51.100.7"}}}})
	waf, err := decodeSiteWAF(cfg)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := wafFields(waf)
	if err != nil {
		t.Fatalf("fields %v", err)
	}
	leaf := uuid.New()
	mapped := withLeafIPLists(fields, map[string]uuid.UUID{listedID: leaf})
	if mapped.Rules[0].Conditions[0].Values[0] != leaf.String() || fields.Rules[0].Conditions[0].Values[0] != listedID {
		t.Fatalf("mapped %+v / sent %+v", mapped.Rules[0].Conditions, fields.Rules[0].Conditions)
	}
	if name := leafIPListName("bad bots", listedID); name != "market 018f47a25b9c7d31 bad bots" || len([]rune(leafIPListName(strings.Repeat("名", 80), listedID))) > 64 {
		t.Fatalf("leaf list name %q", name)
	}
	service := &Service{}
	if b := service.wafBlockers(t.Context(), cfg, true); len(b) != 1 || b[0].Code != "unsupported_waf" || b[0].Detail != activationPending {
		t.Fatalf("lists without the IP list store: %v", b)
	}
	apps := wafConfig(t, siteWAF{DefaultAction: securitypolicy.ActionAllow, Rules: []securitypolicy.Rule{sqliRule()},
		CRSApps: []string{"system/app-wordpress"}})
	if b := service.wafBlockers(t.Context(), apps, true); len(b) != 1 || b[0].Code != "unsupported_waf" || b[0].Detail != activationPending {
		t.Fatalf("apps without site CRS: %v", b)
	}
}
