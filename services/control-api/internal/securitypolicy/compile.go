package securitypolicy

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"sort"

	"github.com/google/uuid"
)

const RuntimeSnapshotSchemaVersion = "cdnca.security-policy.runtime/v1"

type RuntimeSnapshot struct {
	SchemaVersion string        `json:"schema_version"`
	TenantScopeID uuid.UUID     `json:"tenant_scope_id"`
	SiteID        uuid.UUID     `json:"site_id"`
	PolicyID      uuid.UUID     `json:"policy_id"`
	PolicyVersion int64         `json:"policy_version"`
	Kind          string        `json:"kind"`
	Enabled       bool          `json:"enabled"`
	DefaultAction string        `json:"default_action"`
	Rules         []RuntimeRule `json:"rules"`
	// AutoSwitch (CC only, CC API v5) is the policy's active auto switch.
	AutoSwitch *RuntimeAutoSwitch `json:"auto_switch,omitempty"`
	// TrustedCrawlers / ChallengeCookieDomain (CC only, CC API v6) are the
	// policy's CCSettings values.
	TrustedCrawlers       []CCTrustedCrawler `json:"trusted_crawlers,omitempty"`
	ChallengeCookieDomain string             `json:"challenge_cookie_domain,omitempty"`
	// WAFSettings (WAF only): observe mode and auto block.
	WAFSettings *WAFSettings `json:"waf_settings,omitempty"`
}

// RuntimeAutoSwitch is CCAutoSwitch as the node runs it: the thresholds
// (0 = not used), the recovery time and the rules switched to.
type RuntimeAutoSwitch struct {
	QPSTotal       int           `json:"qps_total"`
	QPS5xx         int           `json:"qps_5xx"`
	RecoverSeconds int           `json:"recover_seconds"`
	Rules          []RuntimeRule `json:"rules"`
	// fix-fwregion (CC API v8): platform nodes running another value. Only
	// with overrides: RuleGroup is the global rule group ("" when global is
	// off, then the fields above are zero and Rules empty).
	RuleGroup string                     `json:"rule_group,omitempty"`
	Overrides []CCAutoSwitchOverride     `json:"overrides,omitempty"`
	RuleSets  []RuntimeAutoSwitchRuleSet `json:"rule_sets,omitempty"`
}

type RuntimeAutoSwitchRuleSet struct {
	Group string        `json:"group"`
	Rules []RuntimeRule `json:"rules"`
}

type RuntimeRule struct {
	ID           uuid.UUID    `json:"id"`
	Priority     int          `json:"priority"`
	Enabled      bool         `json:"enabled"`
	Comment      string       `json:"comment,omitempty"`
	ExpiresAt    string       `json:"expires_at,omitempty"`
	Conditions   []Condition  `json:"conditions"`
	Action       string       `json:"action"`
	Flow         string       `json:"flow"`
	ActionConfig ActionConfig `json:"action_config"`
	CountBy      []CountKey   `json:"count_by,omitempty"`
	ActionTarget string       `json:"action_target,omitempty"`
}

type CompiledRuntimeSnapshot struct {
	Snapshot      RuntimeSnapshot
	CanonicalJSON []byte
	SHA256        [32]byte
}

func CompileRuntimeSnapshot(policy Policy, siteID uuid.UUID) (CompiledRuntimeSnapshot, error) {
	if policy.ID == uuid.Nil || policy.ScopeID == uuid.Nil || siteID == uuid.Nil || policy.Revision < 1 {
		return CompiledRuntimeSnapshot{}, ErrInvalidInput
	}

	fields := PolicyFields{
		Kind:          policy.Kind,
		Name:          policy.Name,
		Description:   policy.Description,
		Enabled:       policy.Enabled,
		DefaultAction: policy.DefaultAction,
		Rules:         cloneRules(policy.Rules),
		CCSettings:    cloneCCSettings(policy.CCSettings),
		WAFSettings:   cloneWAFSettings(policy.WAFSettings),
	}
	if err := normalizeFields(&fields, false); err != nil {
		return CompiledRuntimeSnapshot{}, unlocated(err)
	}
	if err := normalizeCCSettings(fields.Kind, fields.CCSettings, false); err != nil {
		return CompiledRuntimeSnapshot{}, unlocated(err)
	}
	if err := validateCCSettingsRuleIDs(fields.Rules, fields.CCSettings); err != nil {
		return CompiledRuntimeSnapshot{}, err
	}
	// Site-level durations become the rules' own values: the snapshot (and
	// the node) see ordinary rules.
	applyCCDurations(fields.Rules, fields.CCSettings)

	rules, err := runtimeRules(fields.Rules)
	if err != nil {
		return CompiledRuntimeSnapshot{}, err
	}
	var autoSwitch *RuntimeAutoSwitch
	if settings := fields.CCSettings; settings != nil && settings.AutoSwitch.Runs() {
		applyCCDurations(settings.AutoSwitch.Rules, settings)
		switchRules, err := runtimeRules(settings.AutoSwitch.Rules)
		if err != nil {
			return CompiledRuntimeSnapshot{}, err
		}
		autoSwitch = &RuntimeAutoSwitch{QPSTotal: settings.AutoSwitch.QPSTotal, QPS5xx: settings.AutoSwitch.QPS5xx,
			RecoverSeconds: settings.AutoSwitch.RecoverSeconds, Rules: switchRules}
		if len(settings.AutoSwitch.Overrides) != 0 {
			if len(settings.AutoSwitch.RuleGroups) == 1 {
				autoSwitch.RuleGroup = settings.AutoSwitch.RuleGroups[0]
			}
			for _, override := range settings.AutoSwitch.Overrides {
				override.Nodes = slices.Clone(override.Nodes)
				autoSwitch.Overrides = append(autoSwitch.Overrides, override)
			}
			for _, set := range settings.AutoSwitch.RuleSets {
				applyCCDurations(set.Rules, settings)
				rules, err := runtimeRules(set.Rules)
				if err != nil {
					return CompiledRuntimeSnapshot{}, err
				}
				autoSwitch.RuleSets = append(autoSwitch.RuleSets, RuntimeAutoSwitchRuleSet{Group: set.Group, Rules: rules})
			}
		}
	}

	snapshot := RuntimeSnapshot{
		SchemaVersion: RuntimeSnapshotSchemaVersion,
		TenantScopeID: policy.ScopeID,
		SiteID:        siteID,
		PolicyID:      policy.ID,
		PolicyVersion: policy.Revision,
		Kind:          fields.Kind,
		Enabled:       fields.Enabled,
		DefaultAction: fields.DefaultAction,
		Rules:         rules,
		AutoSwitch:    autoSwitch,
		WAFSettings:   fields.WAFSettings,
	}
	if settings := fields.CCSettings; settings != nil {
		snapshot.TrustedCrawlers = cloneCCTrustedCrawlers(settings.TrustedCrawlers)
		snapshot.ChallengeCookieDomain = settings.ChallengeCookieDomain
	}
	canonical, err := json.Marshal(snapshot)
	if err != nil {
		return CompiledRuntimeSnapshot{}, err
	}
	return CompiledRuntimeSnapshot{
		Snapshot: snapshot, CanonicalJSON: canonical, SHA256: sha256.Sum256(canonical),
	}, nil
}

func ValidateRuntimeSnapshot(snapshot RuntimeSnapshot) error {
	if snapshot.SchemaVersion != RuntimeSnapshotSchemaVersion {
		return ErrInvalidInput
	}
	// Durations are already the rules' values; only the auto switch is a
	// setting of its own.
	var settings *CCSettings
	if value := snapshot.AutoSwitch; value != nil {
		settings = &CCSettings{AutoSwitch: &CCAutoSwitch{Mode: CCSettingCustom, QPSTotal: value.QPSTotal,
			QPS5xx: value.QPS5xx, RecoverSeconds: value.RecoverSeconds, RuleGroups: []string{},
			Rules: policyRules(value.Rules)}}
		if len(value.Overrides) != 0 {
			// Only a system switch carries overrides.
			settings.AutoSwitch.Mode = CCSettingSystem
			if value.RuleGroup != "" {
				settings.AutoSwitch.RuleGroups = []string{value.RuleGroup}
			}
			for _, override := range value.Overrides {
				override.Nodes = slices.Clone(override.Nodes)
				settings.AutoSwitch.Overrides = append(settings.AutoSwitch.Overrides, override)
			}
			for _, set := range value.RuleSets {
				settings.AutoSwitch.RuleSets = append(settings.AutoSwitch.RuleSets,
					CCAutoSwitchRuleSet{Group: set.Group, Rules: policyRules(set.Rules)})
			}
		}
	}
	if snapshot.TrustedCrawlers != nil || snapshot.ChallengeCookieDomain != "" {
		if settings == nil {
			settings = &CCSettings{}
		}
		settings.TrustedCrawlers = cloneCCTrustedCrawlers(snapshot.TrustedCrawlers)
		settings.ChallengeCookieDomain = snapshot.ChallengeCookieDomain
	}
	compiled, err := CompileRuntimeSnapshot(Policy{
		ID: snapshot.PolicyID, ScopeID: snapshot.TenantScopeID, Kind: snapshot.Kind,
		Name: "runtime", Enabled: snapshot.Enabled, DefaultAction: snapshot.DefaultAction,
		Rules: policyRules(snapshot.Rules), CCSettings: settings, Revision: snapshot.PolicyVersion,
		WAFSettings: cloneWAFSettings(snapshot.WAFSettings),
	}, snapshot.SiteID)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil || !bytes.Equal(encoded, compiled.CanonicalJSON) {
		return ErrInvalidInput
	}
	return nil
}

func runtimeRules(source []Rule) ([]RuntimeRule, error) {
	rules := make([]RuntimeRule, len(source))
	for index, rule := range source {
		if rule.ID == uuid.Nil {
			return nil, ErrInvalidInput
		}
		sort.Slice(rule.Conditions, func(left, right int) bool {
			return compareConditions(rule.Conditions[left], rule.Conditions[right]) < 0
		})
		rules[index] = RuntimeRule{
			ID: rule.ID, Priority: rule.Priority, Enabled: rule.Enabled,
			Comment: rule.Comment, ExpiresAt: rule.ExpiresAt,
			Conditions: rule.Conditions, Action: rule.Action, Flow: rule.Flow,
			ActionConfig: rule.ActionConfig, CountBy: rule.CountBy, ActionTarget: rule.ActionTarget,
		}
	}
	return rules, nil
}

func policyRules(source []RuntimeRule) []Rule {
	rules := make([]Rule, len(source))
	for index, rule := range source {
		rules[index] = Rule{
			ID: rule.ID, Name: "runtime", Priority: rule.Priority, Enabled: rule.Enabled,
			Comment: rule.Comment, ExpiresAt: rule.ExpiresAt,
			Conditions: rule.Conditions, Action: rule.Action, Flow: rule.Flow,
			ActionConfig: rule.ActionConfig, CountBy: rule.CountBy, ActionTarget: rule.ActionTarget,
		}
	}
	return rules
}

func cloneRules(source []Rule) []Rule {
	rules := make([]Rule, len(source))
	for index, rule := range source {
		rules[index] = rule
		rules[index].Conditions = make([]Condition, len(rule.Conditions))
		for conditionIndex, condition := range rule.Conditions {
			rules[index].Conditions[conditionIndex] = condition
			rules[index].Conditions[conditionIndex].Values = slices.Clone(condition.Values)
			rules[index].Conditions[conditionIndex].Filters = slices.Clone(condition.Filters)
		}
		if rule.ActionConfig.WAFBan != nil {
			value := *rule.ActionConfig.WAFBan
			rules[index].ActionConfig.WAFBan = &value
		}
		if rule.ActionConfig.WAFChallenge != nil {
			value := *rule.ActionConfig.WAFChallenge
			rules[index].ActionConfig.WAFChallenge = &value
		}
		if rule.ActionConfig.RateLimit != nil {
			value := *rule.ActionConfig.RateLimit
			if value.Adaptive != nil {
				adaptive := *value.Adaptive
				value.Adaptive = &adaptive
			}
			rules[index].ActionConfig.RateLimit = &value
		}
		if rule.ActionConfig.Challenge != nil {
			value := *rule.ActionConfig.Challenge
			rules[index].ActionConfig.Challenge = &value
		}
		if rule.CountBy != nil {
			rules[index].CountBy = slices.Clone(rule.CountBy)
		}
	}
	return rules
}

func compareConditions(left, right Condition) int {
	if result := cmp.Compare(left.Field, right.Field); result != 0 {
		return result
	}
	if result := cmp.Compare(left.Operator, right.Operator); result != 0 {
		return result
	}
	if result := cmp.Compare(left.Key, right.Key); result != 0 {
		return result
	}
	if result := slices.Compare(left.Values, right.Values); result != 0 {
		return result
	}
	if result := slices.Compare(left.Filters, right.Filters); result != 0 {
		return result
	}
	return cmp.Compare(left.BodyOverflow, right.BodyOverflow)
}
