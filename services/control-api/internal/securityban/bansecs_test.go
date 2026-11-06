package securityban

import (
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

func ccBanRule(seconds int) securitypolicy.Rule {
	return securitypolicy.Rule{ID: uuid.New(), Action: "rate_limit", ActionConfig: securitypolicy.ActionConfig{
		RateLimit: &securitypolicy.RateLimitConfig{ResponseAction: "temporary_ban", BanSeconds: seconds}}}
}

// An automatic ban is listed for the duration the node banned with.
func TestPolicyBanSecondsFindsEverySource(t *testing.T) {
	own, switched, grouped := ccBanRule(120), ccBanRule(60), ccBanRule(90)
	cc := securitypolicy.Policy{Kind: securitypolicy.KindCC, Rules: []securitypolicy.Rule{own},
		CCSettings: &securitypolicy.CCSettings{AutoSwitch: &securitypolicy.CCAutoSwitch{Rules: []securitypolicy.Rule{switched},
			RuleSets: []securitypolicy.CCAutoSwitchRuleSet{{Group: "g2", Rules: []securitypolicy.Rule{grouped}}}}}}
	for name, item := range map[string]struct {
		rule string
		want int
		ok   bool
	}{
		"policy rule":           {own.ID.String(), 120, true},
		"auto switch rule":      {switched.ID.String(), 60, true},
		"auto switch rule set":  {grouped.ID.String(), 90, true},
		"rule the policy lacks": {uuid.NewString(), 0, false},
	} {
		if got, ok := policyBanSeconds(cc, "cc", item.rule); got != item.want || ok != item.ok {
			t.Errorf("cc %s: %d %v, want %d %v", name, got, ok, item.want, item.ok)
		}
	}

	block := securitypolicy.Rule{ID: uuid.New(), Action: "block"}
	ban := securitypolicy.Rule{ID: uuid.New(), Action: securitypolicy.ActionBan,
		ActionConfig: securitypolicy.ActionConfig{WAFBan: &securitypolicy.WAFBanConfig{BanSeconds: 7200}}}
	waf := securitypolicy.Policy{Kind: securitypolicy.KindWAF, Rules: []securitypolicy.Rule{block, ban}}
	// Without the policy's own auto block, a block rule's ban is the auto defense overlay's (node built in 600 s).
	if got, ok := policyBanSeconds(waf, "waf", block.ID.String()); got != OverlayAutoBlockSeconds || !ok {
		t.Errorf("overlay auto block: %d %v", got, ok)
	}
	if got, ok := policyBanSeconds(waf, "waf", ban.ID.String()); got != 7200 || !ok {
		t.Errorf("ban rule: %d %v", got, ok)
	}
	waf.WAFSettings = &securitypolicy.WAFSettings{AutoBlock: &securitypolicy.WAFAutoBlock{BlockSeconds: 300}}
	if got, ok := policyBanSeconds(waf, "waf", block.ID.String()); got != 300 || !ok {
		t.Errorf("policy auto block: %d %v", got, ok)
	}
	if got, ok := policyBanSeconds(waf, "waf", uuid.NewString()); got != 300 || !ok {
		t.Errorf("unknown rule with policy auto block: %d %v", got, ok)
	}
}

func TestPackRuleBanSeconds(t *testing.T) {
	for name, item := range map[string]struct {
		rule rulepack.NodeRule
		want int
	}{
		"cc temporary ban": {rulepack.NodeRule{CC: &edgeconfig.CCV2Rule{Action: edgeconfig.CCV2Action{
			Kind: edgeconfig.CCV2ActionTemporaryBan, BanSeconds: 900}}}, 900},
		"waf ban": {rulepack.NodeRule{WAF: &edgeconfig.WAFRule{Action: edgeconfig.WAFBan,
			ActionConfig: &edgeconfig.WAFActionConfig{BanSeconds: 1800}}}, 1800},
		// a pack's block / challenge rule bans only through the overlay auto block (pack segments carry none)
		"waf block": {rulepack.NodeRule{WAF: &edgeconfig.WAFRule{Action: edgeconfig.WAFBlock}}, OverlayAutoBlockSeconds},
	} {
		if got := packRuleBanSeconds(item.rule); got != item.want {
			t.Errorf("%s: %d, want %d", name, got, item.want)
		}
	}
}
