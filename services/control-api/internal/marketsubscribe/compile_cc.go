package marketsubscribe

import (
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

// The site's CC policy (fix-mktsiteconf3) carried whole as siteconf's cc
// block, like the WAF: rules without IDs (challenges, counting keys, leaky
// bucket and the other algorithms travel in the rule fields) and the CC
// settings. A system-mode value was resolved from this platform's global CC
// config when the policy was saved (ResolveCCSettings); it is sent as the
// custom value it resolved to, so the leaf does not re-resolve it against its
// own global config. A system auto switch resolved to off is sent as none.

// CC is siteconf's cc block.
type CC struct {
	DefaultAction string                     `json:"default_action"`
	Rules         []securitypolicy.Rule      `json:"rules"`
	CCSettings    *securitypolicy.CCSettings `json:"cc_settings,omitempty"`
}

// compileCC is an enabled CC policy as the cc block (nil when disabled).
func compileCC(p securitypolicy.Policy) *CC {
	if !p.Enabled {
		return nil
	}
	cc := &CC{DefaultAction: p.DefaultAction, Rules: make([]securitypolicy.Rule, 0, len(p.Rules)),
		CCSettings: carriedCCSettings(p.CCSettings)}
	for _, r := range p.Rules {
		r.ID = uuid.Nil
		cc.Rules = append(cc.Rules, r)
	}
	return cc
}

// carriedCCSettings is settings with system values made custom and switch
// rule IDs cleared (the leaf derives them from its own policy ID).
func carriedCCSettings(settings *securitypolicy.CCSettings) *securitypolicy.CCSettings {
	if settings == nil {
		return nil
	}
	out := *settings
	if d := settings.BanSeconds; d != nil {
		out.BanSeconds = &securitypolicy.CCDuration{Mode: securitypolicy.CCSettingCustom, Seconds: d.Seconds}
	}
	if d := settings.PassSeconds; d != nil {
		out.PassSeconds = &securitypolicy.CCDuration{Mode: securitypolicy.CCSettingCustom, Seconds: d.Seconds}
	}
	out.AutoSwitch = nil
	if s := settings.AutoSwitch; s.Active() {
		value := *s
		value.Mode = securitypolicy.CCSettingCustom
		value.RuleGroups = append([]string{}, s.RuleGroups...)
		value.Rules = make([]securitypolicy.Rule, len(s.Rules))
		for i, r := range s.Rules {
			r.ID = uuid.Nil
			value.Rules[i] = r
		}
		out.AutoSwitch = &value
	}
	out.TrustedCrawlers = append([]securitypolicy.CCTrustedCrawler(nil), settings.TrustedCrawlers...)
	if out.BanSeconds == nil && out.PassSeconds == nil && out.AutoSwitch == nil && len(out.TrustedCrawlers) == 0 &&
		out.ChallengeCookieDomain == "" {
		return nil
	}
	return &out
}
