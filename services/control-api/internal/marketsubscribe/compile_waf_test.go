package marketsubscribe

import (
	"encoding/json"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/cdnca/cdnca/services/control-api/internal/sitecrs"
	"github.com/google/uuid"
)

func wafPolicy() securitypolicy.Policy {
	policyID := uuid.New()
	managed := &securitypolicy.ManagedWAFConfig{Profile: "system/crs-pl1", RequestBodyLimit: 1 << 20}
	return securitypolicy.Policy{ID: policyID, Kind: securitypolicy.KindWAF, Enabled: true, DefaultAction: securitypolicy.ActionAllow,
		WAFSettings: &securitypolicy.WAFSettings{Mode: "observe"},
		QuickBlock:  &securitypolicy.QuickBlock{BlockIDCCN: true},
		Rules: []securitypolicy.Rule{
			{ID: securitypolicy.QuickBlockRuleID(policyID, 1), Name: "quick block", Action: securitypolicy.ActionBlock},
			{ID: uuid.New(), Name: "sqli", Priority: 1, Enabled: true, Action: securitypolicy.ActionBlock, Flow: securitypolicy.FlowStop,
				Conditions: []securitypolicy.Condition{{Field: "query", Operator: "contains", Values: []string{"union select"}}}},
			{ID: uuid.New(), Name: "crs", Priority: 2, Enabled: true, Action: securitypolicy.ActionManagedWAF, Flow: securitypolicy.FlowContinue,
				ActionConfig: securitypolicy.ActionConfig{ManagedWAF: managed}},
		}}
}

// fix-mktsiteconf2 ②: the WAF policy becomes the waf block: rules without
// IDs, quick block switches instead of their system rules, the managed WAF
// with the site's effective profile and exclusions.
func TestCompileWAFCarriesPolicyAndEffectiveCRS(t *testing.T) {
	waf, reason := compileWAF(wafPolicy(), &sitecrs.Library{Profile: "system/crs-pl2", Exclusions: []int{942100}}, nil, nil)
	if reason != "" || waf == nil {
		t.Fatalf("waf = %+v reason %q", waf, reason)
	}
	if len(waf.Rules) != 2 || waf.Rules[0].ID != uuid.Nil || waf.QuickBlock == nil || !waf.QuickBlock.BlockIDCCN ||
		waf.WAFSettings == nil || waf.WAFSettings.Mode != "observe" {
		t.Fatalf("waf = %+v", waf)
	}
	managed := waf.Rules[1].ActionConfig.ManagedWAF
	if managed == nil || managed.Profile != "system/crs-pl2" || len(managed.Exclusions) != 1 || managed.RequestBodyLimit != 1<<20 {
		t.Fatalf("managed = %+v", managed)
	}
	raw, _ := json.Marshal(waf)
	var back WAF
	if err := json.Unmarshal(raw, &back); err != nil || len(back.Rules) != 2 {
		t.Fatalf("round trip %v %+v", err, back)
	}
}

// fix-mktsiteconf3 ⑥: the IP lists the rules name travel expanded, the CRS
// application types travel as pack IDs; a list that cannot be read blocks.
func TestCompileWAFCarriesIPListsAndCRSApps(t *testing.T) {
	p := wafPolicy()
	listID := uuid.New()
	p.Rules[1].Conditions = []securitypolicy.Condition{{Field: "ip_list", Operator: "in_ip_list", Values: []string{listID.String()}}}
	lists := map[uuid.UUID]WAFIPList{listID: {Name: "bad bots", CIDRs: []string{"192.0.2.0/24"}}}
	waf, reason := compileWAF(p, nil, []string{"system/app-wordpress"}, lists)
	if reason != "" || waf == nil || len(waf.IPLists) != 1 || waf.IPLists[listID.String()].CIDRs[0] != "192.0.2.0/24" ||
		len(waf.CRSApps) != 1 || waf.CRSApps[0] != "system/app-wordpress" {
		t.Fatalf("waf = %+v reason %q", waf, reason)
	}
	if waf.Rules[0].Conditions[0].Values[0] != listID.String() {
		t.Fatalf("rule lost its list reference: %+v", waf.Rules[0])
	}
	if _, reason := compileWAF(p, nil, nil, nil); reason != "waf_ip_list" {
		t.Fatalf("unreadable list reason %q", reason)
	}
	p.Enabled = false
	if waf, reason := compileWAF(p, nil, nil, lists); waf != nil || reason != "" {
		t.Fatal("disabled policy carried")
	}
}
