package marketsupply

import (
	"bytes"
	"encoding/json"

	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

// siteCC is siteconf's cc block (marketsubscribe.CC): the subscriber's whole
// CC policy without rule IDs, its CC settings all custom.
type siteCC struct {
	DefaultAction string                     `json:"default_action"`
	Rules         []securitypolicy.Rule      `json:"rules"`
	CCSettings    *securitypolicy.CCSettings `json:"cc_settings,omitempty"`
}

func decodeSiteCC(c siteconf.Config) (*siteCC, error) {
	if len(c.CC) == 0 {
		return nil, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(c.CC))
	decoder.DisallowUnknownFields()
	var cc siteCC
	if err := decoder.Decode(&cc); err != nil {
		return nil, err
	}
	return &cc, nil
}

// ccFields maps the block onto a local CC policy, checked as the policy
// store would publish it. A system-mode value is refused: the subscriber
// sends what it resolved to, never "follow the leaf's global config".
func ccFields(cc *siteCC) (securitypolicy.PolicyFields, error) {
	fields := securitypolicy.PolicyFields{Kind: securitypolicy.KindCC, Name: "market cc", Enabled: true,
		DefaultAction: cc.DefaultAction, Rules: cc.Rules, CCSettings: cc.CCSettings}
	if fields.Rules == nil {
		fields.Rules = []securitypolicy.Rule{}
	}
	if securitypolicy.UsesSystemCCSettings(fields.CCSettings) {
		return securitypolicy.PolicyFields{}, siteconf.ErrInvalid
	}
	for _, rule := range fields.Rules {
		if rule.ID != uuid.Nil {
			return securitypolicy.PolicyFields{}, siteconf.ErrInvalid
		}
	}
	policy := securitypolicy.Policy{Kind: fields.Kind, Name: fields.Name, Enabled: true,
		DefaultAction: fields.DefaultAction, Rules: fields.Rules}
	if err := securitypolicy.ValidatePublishablePolicy(policy); err != nil {
		return securitypolicy.PolicyFields{}, err
	}
	if _, err := securitypolicy.CanonicalCCSettings(uuid.New(), fields.CCSettings); err != nil {
		return securitypolicy.PolicyFields{}, err
	}
	return fields, nil
}

// ccBlockers: a malformed cc block (cc_invalid) or one on a leaf without
// security activation (unsupported_cc activation_pending).
func ccBlockers(c siteconf.Config, wired bool) []siteconf.Blocker {
	cc, err := decodeSiteCC(c)
	if err != nil {
		return []siteconf.Blocker{{Code: "cc_invalid"}}
	}
	if cc == nil {
		return nil
	}
	if _, err := ccFields(cc); err != nil {
		return []siteconf.Blocker{{Code: "cc_invalid"}}
	}
	if !wired {
		return []siteconf.Blocker{{Code: "unsupported_cc", Detail: activationPending}}
	}
	return nil
}
