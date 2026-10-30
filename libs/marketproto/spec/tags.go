package spec

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Tags are the seller's self-declared features of an offer (ADR 0012 §3.2).
// Pages show them apart from platform-measured facts (node region/carrier,
// benchmark grade), which are not part of this document.
type Tags struct {
	CCProtection       CCProtection `json:"cc_protection"`
	DDoSProtectionGbps int64        `json:"ddos_protection_gbps"` // 0 = none
	ComplaintResistant bool         `json:"complaint_resistant"`
	Tenancy            Tenancy      `json:"tenancy"`
	MobileReachable    bool         `json:"mobile_reachable"`
	RegionBlock        bool         `json:"region_block"`
	LineClass          string       `json:"line_class,omitempty"` // free text such as "BGP", "CN2 GIA"
	// Plugins are the node plugins (licence feature codes module.* / pack.*,
	// or rule_pack:<pack id>)
	// this supply includes. The market only accepts codes every node behind
	// the offer actually has; in a grant they are the
	// ones still available at issue time, so an expired upstream plugin drops
	// out and the buyer falls back to base protection.
	Plugins []string `json:"plugins,omitempty"`
	// Custom are the seller's own feature words:
	// at most MaxCustomTags, each trimmed, unique and at most MaxCustomTagRunes
	// characters without control characters. Display only: a resale does not
	// inherit or check them, and grants drop them (ForGrant).
	Custom []string `json:"custom,omitempty"`
}

type CCProtection string

const (
	CCNone     CCProtection = "none"
	CCBasic    CCProtection = "basic"
	CCAdvanced CCProtection = "advanced"
)

type Tenancy string

const (
	TenancyShared    Tenancy = "shared"
	TenancyDedicated Tenancy = "dedicated"
)

const (
	MaxDDoSProtectionGbps = 100_000
	MaxLineClassRunes     = 32
	MaxPlugins            = 32
	MaxCustomTags         = 10
	MaxCustomTagRunes     = 16
)

// pluginPattern matches licence module and package feature codes
// (entitlement.ModuleFeatureCode, market_plugins.feature_code without theme).
var pluginPattern = regexp.MustCompile(`^(module|pack)\.[a-z0-9]+([._-][a-z0-9]+)*$`)

// rulePackPluginPattern matches "rule_pack:<pack id>" (a rule pack the seller
// bought and every node has applied; pack ids as in
// libs/rulepack: system/<name>, dev/<publisher>/<name>, user/<uuid>/<name>).
var rulePackPluginPattern = regexp.MustCompile(`^rule_pack:(system/[a-z0-9][a-z0-9-]{0,63}|` +
	`dev/[a-z0-9]+(?:[.-][a-z0-9]+)*/[a-z0-9][a-z0-9-]{0,63}|` +
	`user/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/[a-z0-9][a-z0-9-]{0,63})$`)

// ValidPlugin reports whether code is a node plugin: a feature code
// (module.* / pack.*) or a rule pack (rule_pack:<pack id>).
func ValidPlugin(code string) bool {
	if IsRulePackPlugin(code) {
		return len(code) <= 180
	}
	return len(code) <= 96 && pluginPattern.MatchString(code)
}

// IsRulePackPlugin reports whether code is a rule_pack:<pack id> plugin; a
// rule pack is not a licence feature, the node report is its evidence.
func IsRulePackPlugin(code string) bool { return rulePackPluginPattern.MatchString(code) }

// Normalize fills the defaults of an empty declaration (cc none, shared),
// sorts the plugins, and trims the custom tags dropping blanks and repeats
// (first occurrence kept, in the seller's order).
func (t Tags) Normalize() (Tags, error) {
	if t.CCProtection == "" {
		t.CCProtection = CCNone
	}
	if t.Tenancy == "" {
		t.Tenancy = TenancyShared
	}
	if len(t.Plugins) == 0 {
		t.Plugins = nil
	} else {
		t.Plugins = slices.Clone(t.Plugins)
		slices.Sort(t.Plugins)
	}
	var custom []string
	for _, c := range t.Custom {
		if c = strings.TrimSpace(c); c != "" && !slices.Contains(custom, c) {
			custom = append(custom, c)
		}
	}
	t.Custom = custom
	return t, t.Validate()
}

// ForGrant is the tags a grant carries: the custom tags are display only and
// stay out of the signed grant (nodes decode it strictly).
func (t Tags) ForGrant() Tags {
	t.Custom = nil
	return t
}

func (t Tags) Validate() error {
	switch t.CCProtection {
	case CCNone, CCBasic, CCAdvanced:
	default:
		return fmt.Errorf("%w: cc_protection must be none, basic or advanced", ErrInvalid)
	}
	if t.Tenancy != TenancyShared && t.Tenancy != TenancyDedicated {
		return fmt.Errorf("%w: tenancy must be shared or dedicated", ErrInvalid)
	}
	if t.DDoSProtectionGbps < 0 || t.DDoSProtectionGbps > MaxDDoSProtectionGbps {
		return fmt.Errorf("%w: ddos_protection_gbps must be 0..%d", ErrInvalid, MaxDDoSProtectionGbps)
	}
	if !utf8.ValidString(t.LineClass) || utf8.RuneCountInString(t.LineClass) > MaxLineClassRunes {
		return fmt.Errorf("%w: line_class must be at most %d characters", ErrInvalid, MaxLineClassRunes)
	}
	for _, r := range t.LineClass {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: line_class contains control characters", ErrInvalid)
		}
	}
	if len(t.Plugins) > MaxPlugins {
		return fmt.Errorf("%w: at most %d plugins", ErrInvalid, MaxPlugins)
	}
	for i, code := range t.Plugins {
		if !ValidPlugin(code) || (i > 0 && t.Plugins[i-1] >= code) {
			return fmt.Errorf("%w: plugins must be sorted, unique module.*/pack.* feature codes", ErrInvalid)
		}
	}
	if len(t.Custom) > MaxCustomTags {
		return fmt.Errorf("%w: at most %d custom tags", ErrInvalid, MaxCustomTags)
	}
	for i, c := range t.Custom {
		if c == "" || c != strings.TrimSpace(c) || !utf8.ValidString(c) || utf8.RuneCountInString(c) > MaxCustomTagRunes ||
			strings.ContainsFunc(c, unicode.IsControl) || slices.Contains(t.Custom[:i], c) {
			return fmt.Errorf("%w: custom tags must be unique, trimmed, 1..%d characters without control characters", ErrInvalid, MaxCustomTagRunes)
		}
	}
	return nil
}
