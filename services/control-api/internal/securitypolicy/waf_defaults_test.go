package securitypolicy

import (
	"testing"

	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"github.com/google/uuid"
)

// ge-waf logic 1 / 2: waf_enabled, waf_modules and waf_auto_block of the
// system defaults produce the new site WAF policy: off modules are absent,
// detect logs, on blocks, and the auto block becomes waf_settings.
func TestBuildDefaultWAFPolicyFollowsSystemDefaults(t *testing.T) {
	index := map[string]rulecatalog.Item{}
	for _, item := range rulecatalog.BuiltinWAFSeed() {
		index[item.SystemKey] = item
	}
	defaults := systemconfig.DefaultSecuritySettings{WAFEnabled: true,
		WAFAutoBlock: systemconfig.DefaultWAFAutoBlockSettings{Enabled: true, WindowSeconds: 60, HitThreshold: 20, BlockSeconds: 600},
		WAFModules: systemconfig.DefaultWAFModules{SQLI: "on", XSS: "detect", Upload: "off", FI: "off", CMDI: "off", Java: "off",
			JDeser: "off", PHP: "off", PHPDeser: "off", SSTI: "off"}}
	policy, err := BuildDefaultWAFPolicy(defaults, index)
	if err != nil {
		t.Fatal(err)
	}
	if !policy.Enabled || policy.WAFSettings == nil || policy.WAFSettings.AutoBlock.HitThreshold != 20 || len(policy.Rules) == 0 {
		t.Fatalf("policy = %+v", policy)
	}
	sqli, xss := 0, 0
	for index, rule := range policy.Rules {
		if rule.Priority != index+1 {
			t.Fatalf("priority %d at %d", rule.Priority, index)
		}
		switch {
		case len(rule.Name) >= len("SQL注入") && rule.Name[:len("SQL注入")] == "SQL注入":
			sqli++
			if rule.Action != ActionBlock || rule.Flow != FlowStop {
				t.Fatalf("sqli rule %+v", rule)
			}
		case rule.Name[:3] == "XSS":
			xss++
			if rule.Action != ActionLog || rule.Flow != FlowContinue {
				t.Fatalf("xss rule %+v", rule)
			}
		default:
			t.Fatalf("off module rule %s", rule.Name)
		}
		policy.Rules[index].ID = uuid.New()
	}
	if sqli == 0 || xss == 0 {
		t.Fatalf("sqli=%d xss=%d", sqli, xss)
	}
	fields := PolicyFields{Kind: KindWAF, Name: "default", Enabled: policy.Enabled, DefaultAction: ActionAllow,
		Rules: policy.Rules, WAFSettings: policy.WAFSettings}
	if err := normalizePublishableFields(&fields, false); err != nil {
		t.Fatalf("default WAF is not publishable: %v", err)
	}

	defaults.WAFEnabled, defaults.WAFAutoBlock.Enabled = false, false
	defaults.WAFModules = systemconfig.DefaultWAFModules{SQLI: "off", XSS: "off", Upload: "off", FI: "off", CMDI: "off", Java: "off",
		JDeser: "off", PHP: "off", PHPDeser: "off", SSTI: "off"}
	off, err := BuildDefaultWAFPolicy(defaults, index)
	if err != nil || off.Enabled || off.WAFSettings != nil || len(off.Rules) != 0 {
		t.Fatalf("all off = %+v, %v", off, err)
	}
}
