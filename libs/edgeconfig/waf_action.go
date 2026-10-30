package edgeconfig

import (
	"encoding/json"
	"strings"
)

// WAF rule actions beyond allow / block / log (ge-waf S3).
// The rendered state machine and the rule plan interpreter decide exactly as
// before (last matching rule wins until a stop rule); only the segment's
// final verdict is carried out differently:
//
//   - challenge: the client must pass a proof-of-work page (cdnca_waf.act);
//     a request carrying a valid pass cookie for the rule goes on as allow.
//     A POST (or other non-idempotent method) is answered 307 to the same URL
//     after the pass, so the browser repeats it with its method and body
//     (never sends the client to "/" as CC redirect did);
//   - ban: the client address is banned for BanSeconds on this node (every
//     later request of the site's listeners is refused 403 before any rule)
//     and the request is refused.
//
// A policy may also auto ban (WAFAutoBlock): HitThreshold block / challenge
// decisions of the policy within WindowSeconds ban the client for
// BlockSeconds, and a policy in observe mode (WAFModeObserve) records every
// decision as log and never blocks, challenges or bans. Both need
// CAPABILITY_NAME_WAF v2 on the node (WAFActionAPIVersion).
const (
	WAFChallenge WAFAction = "challenge"
	WAFBan       WAFAction = "ban"
)

// WAFMode: "" (defend, the default) or observe.
type WAFMode string

const (
	WAFModeDefend  WAFMode = ""
	WAFModeObserve WAFMode = "observe"
)

// WAFStateDictionary holds WAF v2 bans, auto block counters, challenge
// nonces and the pass secret (cdnca_waf.lua WAF_STATE_DICT).
const WAFStateDictionary = "cdnca_waf_state"

// WAFStateHTTP is its http-level declaration.
const WAFStateHTTP = "  lua_shared_dict " + WAFStateDictionary + " 32m;\n"

// SecurityBanDictionary holds the node's security ban list
// (edge/openresty/lua/cdnca_banlist.lua): the bans and releases the control
// plane's ban list library sends, and the WAF kernel ban queue. WAF v2 gates
// and the CC v2 engine read it.
const SecurityBanDictionary = "cdnca_security_bans"

// SecurityBanHTTP is its http-level declaration.
const SecurityBanHTTP = "  lua_shared_dict " + SecurityBanDictionary + " 16m;\n"

// SecurityBanLuaModule is the ban list module (the security Lua directory).
const SecurityBanLuaModule = "cdnca_banlist"

// WAFActionAPIVersion is CAPABILITY_NAME_WAF v2: challenge / ban actions,
// auto block and observe mode (cdnca_waf.act / gate). v1 agents run the
// allow / block / log state machine only.
const WAFActionAPIVersion uint32 = 2

// WAFAdaptiveAPIVersion is CAPABILITY_NAME_WAF v3 (ADR 0011 RI-03): the
// managed WAF's c3 request context (grey zone challenge, shape signal,
// automatic exclusions and tightening, sampled audit). The node Lua and node
// rules switch to c3 together, so a release with a managed WAF requires it.
const WAFAdaptiveAPIVersion uint32 = 3

// WAFConditionsAPIVersion is CAPABILITY_NAME_WAF v4: the
// content_type and http_version inspect targets and IP list conditions
// (WAFMatch.IPLists). A release using them requires it.
const WAFConditionsAPIVersion uint32 = 4

// WAFMultipartAPIVersion is CAPABILITY_NAME_WAF v5: the
// multipart_field_names / multipart_part_count / multipart_field_max_length
// inspect targets (PHP2Shell and multipart amplification virtual patches). A
// release using them requires it.
const WAFMultipartAPIVersion uint32 = 5

// WAFNodeAPIVersion is the highest WAF API version this node code implements
// (what the agent advertises).
const WAFNodeAPIVersion = WAFMultipartAPIVersion

// ListenerSecurityWAFAPIVersion is the WAF API version a listener's
// security needs: 0 without policies or a managed WAF.
func ListenerSecurityWAFAPIVersion(security *ListenerSecurity) uint32 {
	version := uint32(0)
	if security == nil {
		return version
	}
	if len(security.Policies) > 0 {
		version = 1
	}
	if SecurityPoliciesUseWAFActions(security.Policies) {
		version = WAFActionAPIVersion
	}
	if security.ManagedWAF != nil {
		version = WAFAdaptiveAPIVersion
	}
	if SecurityPoliciesUseWAFConditions(security.Policies) {
		version = WAFConditionsAPIVersion
	}
	if SecurityPoliciesUseWAFMultipart(security.Policies) {
		version = WAFMultipartAPIVersion
	}
	return version
}

// SecurityPoliciesUseWAFConditions reports whether a rule of the policies
// uses a WAF v4 condition (WAFConditionsAPIVersion).
func SecurityPoliciesUseWAFConditions(policies []SecurityPolicy) bool {
	for _, policy := range policies {
		for _, rule := range policy.Rules {
			if WAFMatchUsesV4Conditions(rule.Match) {
				return true
			}
		}
	}
	return false
}

// WAFMatchUsesV4Conditions: the match has a content_type / http_version
// inspect clause or an IP list condition.
func WAFMatchUsesV4Conditions(match WAFMatch) bool {
	if match.IPLists != nil {
		return true
	}
	for _, inspect := range match.Inspect {
		if inspect.Target == "content_type" || inspect.Target == "http_version" {
			return true
		}
	}
	return false
}

// SecurityPoliciesUseWAFMultipart reports whether a rule of the policies
// uses a multipart_* inspect target (WAFMultipartAPIVersion).
func SecurityPoliciesUseWAFMultipart(policies []SecurityPolicy) bool {
	for _, policy := range policies {
		for _, rule := range policy.Rules {
			if WAFMatchUsesMultipart(rule.Match) {
				return true
			}
		}
	}
	return false
}

// WAFMatchUsesMultipart: the match has a multipart_* inspect clause.
func WAFMatchUsesMultipart(match WAFMatch) bool {
	for _, inspect := range match.Inspect {
		if strings.HasPrefix(inspect.Target, "multipart_") {
			return true
		}
	}
	return false
}

const (
	WAFBanSecondsMax          = 7 * 86_400
	WAFChallengePassMax       = 86_400
	WAFChallengePowBitsMin    = 8
	WAFChallengePowBitsMax    = 24
	WAFAutoBlockWindowMax     = 86_400
	WAFAutoBlockThresholdMax  = 1_000_000
	WAFAutoBlockBlockSecMax   = 7 * 86_400
	wafActionPassSecondsMin   = 60
	wafActionChallengeTimeout = 300
)

// WAFActionConfig carries the parameters of a challenge or ban rule.
type WAFActionConfig struct {
	// BanSeconds: ban rules (1..7 days).
	BanSeconds int `json:"ban_seconds,omitempty"`
	// PassSeconds / PowBits: challenge rules; the pass cookie lifetime and
	// the SHA-256 proof-of-work difficulty.
	PassSeconds int `json:"pass_seconds,omitempty"`
	PowBits     int `json:"pow_bits,omitempty"`
}

// WAFAutoBlock bans a client whose requests the policy blocked or challenged
// HitThreshold times within WindowSeconds, for BlockSeconds.
type WAFAutoBlock struct {
	WindowSeconds int `json:"window_seconds"`
	HitThreshold  int `json:"hit_threshold"`
	BlockSeconds  int `json:"block_seconds"`
}

func normalizeWAFAutoBlock(value *WAFAutoBlock) (*WAFAutoBlock, error) {
	if value == nil {
		return nil, nil
	}
	if value.WindowSeconds < 1 || value.WindowSeconds > WAFAutoBlockWindowMax || value.HitThreshold < 1 ||
		value.HitThreshold > WAFAutoBlockThresholdMax || value.BlockSeconds < 1 || value.BlockSeconds > WAFAutoBlockBlockSecMax {
		return nil, ErrInvalidConfig
	}
	copied := *value
	return &copied, nil
}

func normalizeWAFActionConfig(action WAFAction, value *WAFActionConfig) (*WAFActionConfig, error) {
	switch action {
	case WAFBan:
		if value == nil || value.BanSeconds < 1 || value.BanSeconds > WAFBanSecondsMax || value.PassSeconds != 0 || value.PowBits != 0 {
			return nil, ErrInvalidConfig
		}
	case WAFChallenge:
		if value == nil || value.BanSeconds != 0 || value.PassSeconds < wafActionPassSecondsMin ||
			value.PassSeconds > WAFChallengePassMax || value.PowBits < WAFChallengePowBitsMin || value.PowBits > WAFChallengePowBitsMax {
			return nil, ErrInvalidConfig
		}
	default:
		if value != nil {
			return nil, ErrInvalidConfig
		}
		return nil, nil
	}
	copied := *value
	return &copied, nil
}

// SecurityPolicyUsesWAFActions reports whether a bound policy needs
// CAPABILITY_NAME_WAF v2 (challenge / ban rules, auto block, observe mode).
func SecurityPolicyUsesWAFActions(policy SecurityPolicy) bool {
	if policy.Mode != WAFModeDefend || policy.AutoBlock != nil {
		return true
	}
	for _, rule := range policy.Rules {
		if rule.Action == WAFChallenge || rule.Action == WAFBan {
			return true
		}
	}
	return false
}

// SecurityPoliciesUseWAFActions is SecurityPolicyUsesWAFActions over one
// listener's policies.
func SecurityPoliciesUseWAFActions(policies []SecurityPolicy) bool {
	for _, policy := range policies {
		if SecurityPolicyUsesWAFActions(policy) {
			return true
		}
	}
	return false
}

func specUsesWAFActions(sites []Site) bool {
	for _, site := range sites {
		if SecurityPoliciesUseWAFActions(site.SecurityPolicies) {
			return true
		}
	}
	return false
}

// wafActionSpec is the JSON cdnca_waf.act / gate receive (rendered as a Lua
// long string): the ban scope (the site), the segment's kind and policy, its
// mode and auto block, whether decisions set telemetry, and the parameters of
// its challenge / ban rules by rule ID.
type wafActionSpec struct {
	Scope     string                     `json:"scope"`
	Kind      SecurityKind               `json:"kind"`
	PolicyID  string                     `json:"policy_id"`
	Mode      WAFMode                    `json:"mode,omitempty"`
	AutoBlock *WAFAutoBlock              `json:"auto_block,omitempty"`
	Telemetry bool                       `json:"telemetry"`
	Rules     map[string]WAFActionConfig `json:"rules"`
}

// WAFActionSpecJSON is the action spec of one bound policy (the renderer and
// the rule plan embed the same bytes).
func WAFActionSpecJSON(siteID string, policy SecurityPolicy, telemetry bool) string {
	spec := wafActionSpec{Scope: wafBanScope(siteID), Kind: policy.Kind, PolicyID: policy.PolicyID, Mode: policy.Mode,
		AutoBlock: policy.AutoBlock, Telemetry: telemetry, Rules: map[string]WAFActionConfig{}}
	for _, rule := range policy.Rules {
		if rule.ActionConfig != nil {
			spec.Rules[rule.RuleID] = *rule.ActionConfig
		}
	}
	encoded, _ := json.Marshal(spec)
	return string(encoded)
}

func luaLongString(encoded string) string {
	level := 0
	for strings.Contains(encoded, "]"+strings.Repeat("=", level)+"]") {
		level++
	}
	equals := strings.Repeat("=", level)
	return "[" + equals + "[" + encoded + "]" + equals + "]"
}

// wafBanScope is the ban scope of a site (every listener of the site shares
// its bans; another site's bans never apply).
func wafBanScope(siteID string) string {
	if siteID == "" {
		return "site"
	}
	return "site:" + siteID
}
