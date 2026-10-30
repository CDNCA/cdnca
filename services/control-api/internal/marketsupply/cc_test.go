package marketsupply

import (
	"encoding/json"
	"testing"

	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

func ccConfig(t *testing.T, cc siteCC) siteconf.Config {
	t.Helper()
	cfg := settingsConfig()
	cfg.CC, _ = json.Marshal(cc)
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func challengeRule() securitypolicy.Rule {
	return securitypolicy.Rule{Name: "js", Priority: 1, Enabled: true, Action: securitypolicy.ActionChallenge, Flow: securitypolicy.FlowStop,
		Conditions: []securitypolicy.Condition{{Field: "path", Operator: "prefix", Values: []string{"/"}}},
		ActionConfig: securitypolicy.ActionConfig{Challenge: &securitypolicy.ChallengeConfig{Type: "js",
			FailureWindowSeconds: 60, MaxFailures: 5, PassSeconds: 3600, BanSeconds: 600, PowBits: 16, ChallengeSeconds: 120,
			BindIPv4Prefix: 24, BindIPv6Prefix: 64, KeyRotateSeconds: 86400}}}
}

func bucketRule() securitypolicy.Rule {
	return securitypolicy.Rule{Name: "bucket", Priority: 2, Enabled: true, Action: securitypolicy.ActionRateLimit,
		Flow: securitypolicy.FlowContinue, CountBy: []securitypolicy.CountKey{{Key: "uri"}},
		Conditions: []securitypolicy.Condition{{Field: "path", Operator: "prefix", Values: []string{"/api/"}}},
		ActionConfig: securitypolicy.ActionConfig{RateLimit: &securitypolicy.RateLimitConfig{Algorithm: "leaky_bucket",
			RatePerSecond: 5, Burst: 10, ResponseAction: "reject_429"}}}
}

// fix-mktsiteconf3 ①: a cc block with a challenge, a counting key, a leaky
// bucket and the CC settings becomes one publishable local CC policy.
func TestCCFieldsMapTheWholePolicy(t *testing.T) {
	settings := &securitypolicy.CCSettings{
		BanSeconds:  &securitypolicy.CCDuration{Mode: securitypolicy.CCSettingCustom, Seconds: 3600},
		PassSeconds: &securitypolicy.CCDuration{Mode: securitypolicy.CCSettingCustom, Seconds: 900},
		AutoSwitch: &securitypolicy.CCAutoSwitch{Mode: securitypolicy.CCSettingCustom, QPSTotal: 500, RecoverSeconds: 300,
			RuleGroups: []string{"cc_rule:10003"}, Rules: []securitypolicy.Rule{bucketRule()}},
		TrustedCrawlers: []securitypolicy.CCTrustedCrawler{{Name: "googlebot", UserAgentTokens: []string{"Googlebot"},
			RDNSSuffixes: []string{"googlebot.com"}}},
		ChallengeCookieDomain: "example.cn",
	}
	cfg := ccConfig(t, siteCC{DefaultAction: securitypolicy.ActionAllow,
		Rules: []securitypolicy.Rule{challengeRule(), bucketRule()}, CCSettings: settings})
	cc, err := decodeSiteCC(cfg)
	if err != nil || cc == nil {
		t.Fatalf("decode %v", err)
	}
	fields, err := ccFields(cc)
	if err != nil || fields.Kind != securitypolicy.KindCC || len(fields.Rules) != 2 || fields.CCSettings == nil ||
		fields.CCSettings.AutoSwitch == nil || len(fields.CCSettings.TrustedCrawlers) != 1 {
		t.Fatalf("fields = %+v %v", fields, err)
	}
	if blockers := ccBlockers(cfg, true); len(blockers) != 0 {
		t.Fatalf("blockers %v", blockers)
	}
	if b := ccBlockers(cfg, false); len(b) != 1 || b[0].Code != "unsupported_cc" || b[0].Detail != activationPending {
		t.Fatalf("unwired: %v", b)
	}
}

func TestCCBlockersRefuseWhatTheStoreWouldNot(t *testing.T) {
	withID := challengeRule()
	withID.ID = uuid.New()
	for name, cfg := range map[string]siteconf.Config{
		"system mode": ccConfig(t, siteCC{DefaultAction: securitypolicy.ActionAllow, Rules: []securitypolicy.Rule{challengeRule()},
			CCSettings: &securitypolicy.CCSettings{BanSeconds: &securitypolicy.CCDuration{Mode: securitypolicy.CCSettingSystem, Seconds: 60}}}),
		"rule id": ccConfig(t, siteCC{DefaultAction: securitypolicy.ActionAllow, Rules: []securitypolicy.Rule{withID}}),
		"unknown": func() siteconf.Config { c := settingsConfig(); c.CC = json.RawMessage(`{"rules":[],"x":1}`); return c }(),
		"action":  ccConfig(t, siteCC{DefaultAction: "explode", Rules: []securitypolicy.Rule{}}),
	} {
		if b := ccBlockers(cfg, true); len(b) != 1 || b[0].Code != "cc_invalid" {
			t.Fatalf("%s: %v", name, b)
		}
	}
}

// A stored policy whose auto switch rules carry the store's derived IDs is
// the same as the block that sent them without.
func TestSamePolicyFieldsIgnoresAutoSwitchRuleIDs(t *testing.T) {
	sent := &securitypolicy.CCSettings{AutoSwitch: &securitypolicy.CCAutoSwitch{Mode: securitypolicy.CCSettingCustom,
		QPSTotal: 500, RecoverSeconds: 300, RuleGroups: []string{}, Rules: []securitypolicy.Rule{bucketRule()}}}
	stored := *sent.AutoSwitch
	stored.Rules = []securitypolicy.Rule{bucketRule()}
	stored.Rules[0].ID = uuid.New()
	fields := securitypolicy.PolicyFields{Kind: securitypolicy.KindCC, Name: "n", Enabled: true,
		DefaultAction: securitypolicy.ActionAllow, Rules: []securitypolicy.Rule{}, CCSettings: sent}
	current := securitypolicy.Policy{Kind: securitypolicy.KindCC, Name: "n", Enabled: true, DefaultAction: securitypolicy.ActionAllow,
		Rules: []securitypolicy.Rule{}, CCSettings: &securitypolicy.CCSettings{AutoSwitch: &stored}}
	if !samePolicyFields(current, fields) {
		t.Fatal("derived switch rule IDs made the policy differ")
	}
	current.CCSettings.AutoSwitch.QPSTotal = 600
	if samePolicyFields(current, fields) {
		t.Fatal("a changed setting compared equal")
	}
	if stored.Rules[0].ID == uuid.Nil {
		t.Fatal("comparison cleared the stored IDs")
	}
}
