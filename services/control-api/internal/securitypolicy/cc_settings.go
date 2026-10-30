package securitypolicy

import (
	"slices"
	"sort"
	"strings"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/google/uuid"
)

// CCSettings are a CC policy's site-level protection settings (网站 →
// CC防护 → 展开高级设置 / 自动切换):
//
//   - BanSeconds / PassSeconds (黑名单时间 / 白名单时间, NF30): override the
//     ban of every temporary-ban and challenge rule and the pass lifetime of
//     every challenge rule. Absent keeps each rule's own value. Mode "system"
//     follows the tenant's global CC config (block_time / white_time) and is
//     re-resolved when it changes; "custom" is the given value. Seconds is
//     the resolved value the policy compiles with.
//   - AutoSwitch (自动切换, FX08/FX17): when a node sees the site's requests
//     per second (or its 5xx responses per second) reach the threshold it
//     runs Rules instead of the policy's rules, and switches back once the
//     rate stayed below for RecoverSeconds. Mode "system" follows the global
//     auto_switch (resolved into the same fields; global disabled resolves to
//     no rules, i.e. off); "custom" is the site's own.
//   - TrustedCrawlers (蜘蛛白名单, FX47, CC API v6): a request whose
//     User-Agent carries a crawler's token from one of its networks, or from
//     an address whose reverse DNS forward-confirms under one of its
//     suffixes, skips every CC rule, ban and challenge on the node.
//   - ChallengeCookieDomain (NF28, CC API v6): the pass cookie's Domain, so
//     a pass is shared by the site's subdomains (the node sets it only when
//     the request host is the domain or under it).
type CCSettings struct {
	BanSeconds            *CCDuration        `json:"ban_seconds,omitempty"`
	PassSeconds           *CCDuration        `json:"pass_seconds,omitempty"`
	AutoSwitch            *CCAutoSwitch      `json:"auto_switch,omitempty"`
	TrustedCrawlers       []CCTrustedCrawler `json:"trusted_crawlers,omitempty"`
	ChallengeCookieDomain string             `json:"challenge_cookie_domain,omitempty"`
}

// CCTrustedCrawler mirrors edgeconfig.CCV2TrustedCrawler.
type CCTrustedCrawler struct {
	Name            string   `json:"name"`
	UserAgentTokens []string `json:"user_agent_tokens"`
	Networks        []string `json:"networks,omitempty"`
	RDNSSuffixes    []string `json:"rdns_suffixes,omitempty"`
}

const (
	CCSettingSystem = "system"
	CCSettingCustom = "custom"

	// CCAutoSwitchDefaultRecoverSeconds is the default 5 minutes.
	CCAutoSwitchDefaultRecoverSeconds = 300
	ccAutoSwitchMinRecoverSeconds     = 60
	ccAutoSwitchMaxRecoverSeconds     = 86_400
	ccAutoSwitchMaxQPS                = 1_000_000
	ccAutoSwitchMaxRuleGroups         = MaxCCRuleGroups
)

type CCDuration struct {
	Mode    string `json:"mode"`
	Seconds int    `json:"seconds"`
}

type CCAutoSwitch struct {
	Mode           string `json:"mode"`
	QPSTotal       int    `json:"qps_total"`
	QPS5xx         int    `json:"qps_5xx"`
	RecoverSeconds int    `json:"recover_seconds"`
	// RuleGroups are the system rule groups (catalog cc_rule keys) Rules
	// were expanded from, for display; Rules are what the node switches to.
	RuleGroups []string `json:"rule_groups"`
	Rules      []Rule   `json:"rules"`
	// Overrides (system mode only, fix-fwregion) are the platform nodes whose
	// region / node override differs from the global auto switch, grouped by
	// value; a node not listed runs the fields above. RuleSets are the rules
	// of each overriding rule group other than RuleGroups[0], once per group.
	Overrides []CCAutoSwitchOverride `json:"overrides,omitempty"`
	RuleSets  []CCAutoSwitchRuleSet  `json:"rule_sets,omitempty"`
}

// CCAutoSwitchOverride is what Nodes run instead of the global auto switch.
// RuleGroup "" is off (thresholds and recovery 0); otherwise the rules are
// the global ones when it is RuleGroups[0], else its RuleSets entry.
type CCAutoSwitchOverride struct {
	Nodes          []uuid.UUID `json:"nodes"`
	QPSTotal       int         `json:"qps_total"`
	QPS5xx         int         `json:"qps_5xx"`
	RecoverSeconds int         `json:"recover_seconds"`
	RuleGroup      string      `json:"rule_group"`
}

// CCAutoSwitchRuleSet is a rule group's expansion for overrides.
type CCAutoSwitchRuleSet struct {
	Group string `json:"group"`
	Rules []Rule `json:"rules"`
}

// Active reports an auto switch the node runs (system mode resolved from a
// disabled global auto switch is not).
func (value *CCAutoSwitch) Active() bool {
	return value != nil && len(value.Rules) > 0
}

// Runs reports an auto switch some node runs: the global one or an override.
func (value *CCAutoSwitch) Runs() bool {
	return value.Active() || value != nil && len(value.Overrides) > 0
}

// normalizeCCSettings validates a CC policy's settings (nil for every other
// kind) and canonicalizes the auto switch rules like the policy's own.
// System-mode values must already be resolved (ResolveCCSettings).
func normalizeCCSettings(kind string, settings *CCSettings, create bool) error {
	if settings == nil {
		return nil
	}
	if kind != KindCC {
		return refuse("cc_settings", fielderr.Invalid)
	}
	if err := checkCCDuration(settings.BanSeconds, 1, 86_400, "cc_settings.ban_seconds"); err != nil {
		return err
	}
	if err := checkCCDuration(settings.PassSeconds, 60, 7*86_400, "cc_settings.pass_seconds"); err != nil {
		return err
	}
	if err := normalizeCCTrustedCrawlers(settings); err != nil {
		return fielderr.Within(err, "cc_settings")
	}
	if domain := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(settings.ChallengeCookieDomain), ".")); domain == "" {
		settings.ChallengeCookieDomain = ""
	} else if !edgeconfig.ValidCCV2CookieDomain(domain) {
		return refuse("cc_settings.challenge_cookie_domain", fielderr.InvalidFormat)
	} else {
		settings.ChallengeCookieDomain = domain
	}
	value := settings.AutoSwitch
	if value == nil {
		return nil
	}
	const path = "cc_settings.auto_switch"
	switch {
	case value.Mode != CCSettingSystem && value.Mode != CCSettingCustom:
		return refuse(path+".mode", fielderr.Invalid)
	case value.RuleGroups == nil:
		return refuse(path+".rule_groups", fielderr.Required)
	case len(value.RuleGroups) > ccAutoSwitchMaxRuleGroups:
		return refuse(path+".rule_groups", fielderr.OutOfRange)
	case value.Rules == nil:
		return refuse(path+".rules", fielderr.Required)
	}
	for index, key := range value.RuleGroups {
		if key == "" || len(key) > 128 {
			return refuse(path+"."+indexed("rule_groups", index), fielderr.Invalid)
		}
		if slices.Contains(value.RuleGroups[:index], key) {
			return refuse(path+"."+indexed("rule_groups", index), fielderr.Duplicate)
		}
	}
	if err := normalizeCCAutoSwitchOverrides(value, create); err != nil {
		return err
	}
	if !value.Active() {
		// Only a system switch resolved from a disabled global one is empty.
		if value.Mode != CCSettingSystem || value.QPSTotal != 0 || value.QPS5xx != 0 ||
			value.RecoverSeconds != 0 || len(value.RuleGroups) != 0 {
			return refuse(path, fielderr.Invalid)
		}
		return nil
	}
	if value.QPSTotal == 0 && value.QPS5xx == 0 {
		return refuse(path+".qps_total", fielderr.Required)
	}
	if err := outOfRange(bound{path + ".qps_total", within(value.QPSTotal, 0, ccAutoSwitchMaxQPS)},
		bound{path + ".qps_5xx", within(value.QPS5xx, 0, ccAutoSwitchMaxQPS)},
		bound{path + ".recover_seconds", within(value.RecoverSeconds, ccAutoSwitchMinRecoverSeconds, ccAutoSwitchMaxRecoverSeconds)}); err != nil {
		return err
	}
	fields := PolicyFields{Kind: KindCC, Name: "auto-switch", Enabled: true, DefaultAction: ActionAllow, Rules: value.Rules}
	if err := normalizePublishableFields(&fields, create); err != nil {
		// The switch rules' own fields (rules[n] as sent) under auto_switch.
		// System-mode rules come from the catalog, not the request.
		if located, ok := fielderr.As(err); ok && value.Mode == CCSettingCustom && strings.HasPrefix(located.Field, "rules") {
			return fielderr.Within(err, path)
		}
		return unlocated(err)
	}
	value.Rules = fields.Rules
	return nil
}

// normalizeCCTrustedCrawlers canonicalizes the crawler list the way the
// compiled policy requires it (edgeconfig.validateCCV2TrustedCrawlers):
// names lower-cased and sorted, tokens and suffixes sorted, networks as
// masked CIDRs (netmasks and ranges accepted), empty lists absent. A refusal
// names trusted_crawlers[n] as sent.
func normalizeCCTrustedCrawlers(settings *CCSettings) error {
	if len(settings.TrustedCrawlers) == 0 {
		settings.TrustedCrawlers = nil
		return nil
	}
	if len(settings.TrustedCrawlers) > ccMaxTrustedCrawlers {
		return refuse("trusted_crawlers", fielderr.OutOfRange)
	}
	for index := range settings.TrustedCrawlers {
		path := indexed("trusted_crawlers", index)
		crawler := &settings.TrustedCrawlers[index]
		crawler.Name = strings.ToLower(strings.TrimSpace(crawler.Name))
		if !edgeconfig.ValidCCV2CrawlerName(crawler.Name) {
			return refuse(path+".name", fielderr.InvalidFormat)
		}
		tokens, err := sortedDistinct(crawler.UserAgentTokens, 16, func(value string) (string, bool) {
			value = strings.TrimSpace(value)
			return value, edgeconfig.ValidCCV2CrawlerToken(value)
		})
		if err != nil || tokens == nil {
			return refuse(path+".user_agent_tokens", listReason(err, tokens == nil))
		}
		crawler.UserAgentTokens = tokens
		networks := make([]string, 0, len(crawler.Networks))
		for _, raw := range crawler.Networks {
			prefixes, err := ParseIPNetworks(raw)
			if err != nil {
				return refuse(path+".networks", fielderr.InvalidFormat)
			}
			for _, prefix := range prefixes {
				if prefix.Bits() == 0 {
					return refuse(path+".networks", fielderr.Invalid)
				}
				networks = append(networks, prefix.String())
			}
		}
		if crawler.Networks, err = sortedDistinct(networks, 256, func(value string) (string, bool) { return value, true }); err != nil {
			return refuse(path+".networks", listReason(err, false))
		}
		suffixes, err := sortedDistinct(crawler.RDNSSuffixes, 16, func(value string) (string, bool) {
			value = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(value), "."))
			return value, edgeconfig.ValidCCV2CookieDomain(value)
		})
		if err != nil {
			return refuse(path+".rdns_suffixes", listReason(err, false))
		}
		crawler.RDNSSuffixes = suffixes
		if crawler.Networks == nil && crawler.RDNSSuffixes == nil {
			// A User-Agent alone is never proof of a crawler.
			return refuse(path+".networks", fielderr.Required)
		}
	}
	order := make([]int, len(settings.TrustedCrawlers))
	for index := range order {
		order[index] = index
	}
	sort.SliceStable(order, func(left, right int) bool {
		return settings.TrustedCrawlers[order[left]].Name < settings.TrustedCrawlers[order[right]].Name
	})
	for position := 1; position < len(order); position++ {
		if settings.TrustedCrawlers[order[position]].Name == settings.TrustedCrawlers[order[position-1]].Name {
			return refuse(indexed("trusted_crawlers", max(order[position], order[position-1]))+".name", fielderr.Duplicate)
		}
	}
	sort.Slice(settings.TrustedCrawlers, func(left, right int) bool {
		return settings.TrustedCrawlers[left].Name < settings.TrustedCrawlers[right].Name
	})
	return nil
}

const ccMaxTrustedCrawlers = 32

// sortedDistinct normalizes values, refuses an invalid or duplicate one and
// more than maximum (the reason as a fielderr refusal, no field), and returns
// them sorted (nil when there are none).
func sortedDistinct(values []string, maximum int, normalize func(string) (string, bool)) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	if len(values) > maximum {
		return nil, refuse("", fielderr.OutOfRange)
	}
	result := make([]string, len(values))
	for index, raw := range values {
		value, ok := normalize(raw)
		if !ok {
			return nil, refuse("", fielderr.InvalidFormat)
		}
		result[index] = value
	}
	sort.Strings(result)
	for index := 1; index < len(result); index++ {
		if result[index] == result[index-1] {
			return nil, refuse("", fielderr.Duplicate)
		}
	}
	return result, nil
}

// listReason is the reason of a sortedDistinct refusal (empty: required).
func listReason(err error, empty bool) string {
	if located, ok := fielderr.As(err); ok {
		return located.Reason
	}
	if empty {
		return fielderr.Required
	}
	return fielderr.Invalid
}

// checkCCDuration refuses a site-level duration of a bad mode or out of range.
func checkCCDuration(value *CCDuration, minimum, maximum int, path string) error {
	if value == nil {
		return nil
	}
	if value.Mode != CCSettingSystem && value.Mode != CCSettingCustom {
		return refuse(path+".mode", fielderr.Invalid)
	}
	return outOfRange(bound{path + ".seconds", within(value.Seconds, minimum, maximum)})
}

// validateCCSettingsRuleIDs: the switch rules' IDs are distinct from each
// other and from the policy's (both run under one binding on the node).
func validateCCSettingsRuleIDs(rules []Rule, settings *CCSettings) error {
	if settings == nil || settings.AutoSwitch == nil {
		return nil
	}
	seen := make(map[uuid.UUID]struct{}, len(rules)+len(settings.AutoSwitch.Rules))
	all := append(slices.Clone(rules), settings.AutoSwitch.Rules...)
	for _, set := range settings.AutoSwitch.RuleSets {
		all = append(all, set.Rules...)
	}
	for _, rule := range all {
		if rule.ID == uuid.Nil {
			continue
		}
		if _, duplicate := seen[rule.ID]; duplicate {
			return ErrInvalidInput
		}
		seen[rule.ID] = struct{}{}
	}
	return nil
}

// applyCCDurations rewrites each rule's ban and pass seconds with the
// policy's site-level durations (the rules are already normalized).
func applyCCDurations(rules []Rule, settings *CCSettings) {
	if settings == nil || settings.BanSeconds == nil && settings.PassSeconds == nil {
		return
	}
	for index := range rules {
		rule := &rules[index]
		if limit := rule.ActionConfig.RateLimit; limit != nil && settings.BanSeconds != nil &&
			limit.ResponseAction == "temporary_ban" {
			value := *limit
			value.BanSeconds = settings.BanSeconds.Seconds
			rule.ActionConfig.RateLimit = &value
		}
		challenge := rule.ActionConfig.Challenge
		if challenge == nil {
			continue
		}
		value := *challenge
		if settings.BanSeconds != nil && !value.LogOnly {
			value.BanSeconds = settings.BanSeconds.Seconds
		}
		if settings.PassSeconds != nil {
			value.PassSeconds = settings.PassSeconds.Seconds
			if value.KeyRotateSeconds < value.PassSeconds {
				// The signing key must outlive a pass (checkChallengeConfig).
				value.KeyRotateSeconds = value.PassSeconds
			}
		}
		rule.ActionConfig.Challenge = &value
	}
}

func cloneCCSettings(settings *CCSettings) *CCSettings {
	if settings == nil {
		return nil
	}
	result := &CCSettings{}
	if settings.BanSeconds != nil {
		value := *settings.BanSeconds
		result.BanSeconds = &value
	}
	if settings.PassSeconds != nil {
		value := *settings.PassSeconds
		result.PassSeconds = &value
	}
	if settings.AutoSwitch != nil {
		value := *settings.AutoSwitch
		value.RuleGroups = slices.Clone(settings.AutoSwitch.RuleGroups)
		value.Rules = cloneRules(settings.AutoSwitch.Rules)
		value.Overrides, value.RuleSets = nil, nil
		for _, override := range settings.AutoSwitch.Overrides {
			copied := override
			copied.Nodes = slices.Clone(override.Nodes)
			value.Overrides = append(value.Overrides, copied)
		}
		for _, set := range settings.AutoSwitch.RuleSets {
			value.RuleSets = append(value.RuleSets, CCAutoSwitchRuleSet{Group: set.Group, Rules: cloneRules(set.Rules)})
		}
		result.AutoSwitch = &value
	}
	result.TrustedCrawlers = cloneCCTrustedCrawlers(settings.TrustedCrawlers)
	result.ChallengeCookieDomain = settings.ChallengeCookieDomain
	return result
}

func cloneCCTrustedCrawlers(source []CCTrustedCrawler) []CCTrustedCrawler {
	if source == nil {
		return nil
	}
	result := make([]CCTrustedCrawler, len(source))
	for index, crawler := range source {
		result[index] = CCTrustedCrawler{Name: crawler.Name, UserAgentTokens: slices.Clone(crawler.UserAgentTokens),
			Networks: slices.Clone(crawler.Networks), RDNSSuffixes: slices.Clone(crawler.RDNSSuffixes)}
	}
	return result
}
