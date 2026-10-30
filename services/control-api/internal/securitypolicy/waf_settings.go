package securitypolicy

import "github.com/cdnca/cdnca/services/control-api/internal/fielderr"

// WAF policy settings and actions (ge-waf S3).
//
//   - Mode "observe" (策略级观察模式): every decision of the policy is
//     recorded as log; nothing is blocked, challenged or banned. Used to try
//     a new rule set on live traffic before enforcing it.
//   - AutoBlock (WAF 命中自动封禁): HitThreshold block / challenge decisions
//     of the policy within WindowSeconds ban the client for BlockSeconds.
//   - Rule actions challenge (人机验证, proof of work, POST answered 307 to
//     keep method and body) and ban (临时封禁 BanSeconds).
//
// They map to edgeconfig.SecurityPolicy Mode / AutoBlock and rule
// ActionConfig, and need CAPABILITY_NAME_WAF v2 on the node.

const (
	ActionBan = "ban"

	WAFModeDefend  = ""
	WAFModeObserve = "observe"
)

// WAFSettings is a WAF policy's policy-level settings (security_policies.
// waf_settings); nil means defend mode without auto block.
type WAFSettings struct {
	Mode      string        `json:"mode,omitempty"`
	AutoBlock *WAFAutoBlock `json:"auto_block,omitempty"`
}

// WAFAutoBlock bans a client after HitThreshold block / challenge decisions
// of the policy within WindowSeconds, for BlockSeconds.
type WAFAutoBlock struct {
	WindowSeconds int `json:"window_seconds"`
	HitThreshold  int `json:"hit_threshold"`
	BlockSeconds  int `json:"block_seconds"`
}

// WAFBanConfig / WAFChallengeAction are the parameters of WAF ban and
// challenge rules (ActionConfig.WAFBan / WAFChallenge).
type WAFBanConfig struct {
	BanSeconds int `json:"ban_seconds"`
}

type WAFChallengeAction struct {
	PassSeconds int `json:"pass_seconds"`
	PowBits     int `json:"pow_bits"`
}

func normalizeWAFSettings(kind string, settings *WAFSettings) (*WAFSettings, error) {
	if settings == nil {
		return nil, nil
	}
	if kind != KindWAF {
		return nil, refuse("waf_settings", fielderr.Invalid)
	}
	if settings.Mode != WAFModeDefend && settings.Mode != WAFModeObserve {
		return nil, refuse("waf_settings.mode", fielderr.Invalid)
	}
	if block := settings.AutoBlock; block != nil {
		if err := outOfRange(bound{"waf_settings.auto_block.window_seconds", within(block.WindowSeconds, 1, 86_400)},
			bound{"waf_settings.auto_block.hit_threshold", within(block.HitThreshold, 1, 1_000_000)},
			bound{"waf_settings.auto_block.block_seconds", within(block.BlockSeconds, 1, 7*86_400)}); err != nil {
			return nil, err
		}
	}
	if settings.Mode == WAFModeDefend && settings.AutoBlock == nil {
		return nil, nil
	}
	copied := *settings
	if settings.AutoBlock != nil {
		block := *settings.AutoBlock
		copied.AutoBlock = &block
	}
	return &copied, nil
}

func validWAFBanConfig(config *WAFBanConfig) bool {
	return config != nil && config.BanSeconds >= 1 && config.BanSeconds <= 7*86_400
}

func validWAFChallengeAction(config *WAFChallengeAction) bool {
	return config != nil && config.PassSeconds >= 60 && config.PassSeconds <= 86_400 &&
		config.PowBits >= 8 && config.PowBits <= 24
}

func cloneWAFSettings(settings *WAFSettings) *WAFSettings {
	if settings == nil {
		return nil
	}
	copied := *settings
	if settings.AutoBlock != nil {
		block := *settings.AutoBlock
		copied.AutoBlock = &block
	}
	return &copied
}

// CloneWAFSettings copies settings (callers rewriting a policy keep them).
func CloneWAFSettings(settings *WAFSettings) *WAFSettings { return cloneWAFSettings(settings) }
