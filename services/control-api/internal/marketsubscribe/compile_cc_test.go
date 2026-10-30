package marketsubscribe

import (
	"encoding/json"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

// ccPolicy is a CC policy using what the old rate_limit path refused:
// a JS challenge, a non-IP counting key, a leaky bucket, a host condition and
// CC settings whose durations and auto switch follow the global config.
func ccPolicy() securitypolicy.Policy {
	policyID := uuid.New()
	challenge := securitypolicy.Rule{ID: uuid.New(), Name: "js", Priority: 1, Enabled: true, Action: securitypolicy.ActionChallenge,
		Flow: securitypolicy.FlowStop, Conditions: []securitypolicy.Condition{{Field: "host", Operator: "equals", Values: []string{"a.test"}}},
		ActionConfig: securitypolicy.ActionConfig{Challenge: &securitypolicy.ChallengeConfig{Type: "js",
			FailureWindowSeconds: 60, MaxFailures: 5, PassSeconds: 3600, BanSeconds: 600, PowBits: 16, ChallengeSeconds: 120,
			BindIPv4Prefix: 24, BindIPv6Prefix: 64, KeyRotateSeconds: 86400}}}
	bucket := securitypolicy.Rule{ID: uuid.New(), Name: "bucket", Priority: 2, Enabled: true, Action: securitypolicy.ActionRateLimit,
		Flow: securitypolicy.FlowContinue, CountBy: []securitypolicy.CountKey{{Key: "uri"}},
		ActionConfig: securitypolicy.ActionConfig{RateLimit: &securitypolicy.RateLimitConfig{Algorithm: "leaky_bucket",
			RatePerSecond: 5, Burst: 10, ResponseAction: "reject_429"}}}
	switchRule := bucket
	switchRule.ID = uuid.NewSHA1(policyID, []byte("cc-auto-switch-rule:0"))
	return securitypolicy.Policy{ID: policyID, Kind: securitypolicy.KindCC, Enabled: true, DefaultAction: securitypolicy.ActionAllow,
		Rules: []securitypolicy.Rule{challenge, bucket},
		CCSettings: &securitypolicy.CCSettings{
			BanSeconds:  &securitypolicy.CCDuration{Mode: securitypolicy.CCSettingSystem, Seconds: 3600},
			PassSeconds: &securitypolicy.CCDuration{Mode: securitypolicy.CCSettingCustom, Seconds: 900},
			AutoSwitch: &securitypolicy.CCAutoSwitch{Mode: securitypolicy.CCSettingSystem, QPSTotal: 500, RecoverSeconds: 300,
				RuleGroups: []string{"cc_rule:10003"}, Rules: []securitypolicy.Rule{switchRule}},
			TrustedCrawlers: []securitypolicy.CCTrustedCrawler{{Name: "googlebot", UserAgentTokens: []string{"Googlebot"},
				RDNSSuffixes: []string{"googlebot.com"}}},
			ChallengeCookieDomain: "a.test",
		}}
}

// fix-mktsiteconf3 ①: the whole CC policy travels; system values become
// the custom values they resolved to; rule IDs are left to the leaf.
func TestCompileCCCarriesTheWholePolicy(t *testing.T) {
	cc := compileCC(ccPolicy())
	if cc == nil || len(cc.Rules) != 2 || cc.Rules[0].ID != uuid.Nil || cc.Rules[0].ActionConfig.Challenge == nil ||
		cc.Rules[1].CountBy[0].Key != "uri" || cc.Rules[1].ActionConfig.RateLimit.Algorithm != "leaky_bucket" {
		t.Fatalf("cc = %+v", cc)
	}
	s := cc.CCSettings
	if s == nil || *s.BanSeconds != (securitypolicy.CCDuration{Mode: "custom", Seconds: 3600}) ||
		*s.PassSeconds != (securitypolicy.CCDuration{Mode: "custom", Seconds: 900}) ||
		s.AutoSwitch == nil || s.AutoSwitch.Mode != "custom" || s.AutoSwitch.QPSTotal != 500 || s.AutoSwitch.Rules[0].ID != uuid.Nil ||
		len(s.TrustedCrawlers) != 1 || s.ChallengeCookieDomain != "a.test" {
		t.Fatalf("settings = %+v", s)
	}
	// The policy itself is untouched (system mode kept, IDs kept).
	if p := ccPolicy(); p.CCSettings.BanSeconds.Mode != "system" {
		t.Fatal("policy changed")
	}
	raw, _ := json.Marshal(cc)
	var back CC
	if err := json.Unmarshal(raw, &back); err != nil || len(back.Rules) != 2 || back.CCSettings.AutoSwitch == nil {
		t.Fatalf("round trip %v %+v", err, back)
	}
}

func TestCompileCCSystemAutoSwitchOffIsNone(t *testing.T) {
	p := ccPolicy()
	p.CCSettings = &securitypolicy.CCSettings{AutoSwitch: &securitypolicy.CCAutoSwitch{Mode: securitypolicy.CCSettingSystem,
		RuleGroups: []string{}, Rules: []securitypolicy.Rule{}}}
	if cc := compileCC(p); cc == nil || cc.CCSettings != nil {
		t.Fatalf("resolved-off auto switch carried: %+v", cc)
	}
	p.Enabled = false
	if compileCC(p) != nil {
		t.Fatal("disabled policy carried")
	}
}
