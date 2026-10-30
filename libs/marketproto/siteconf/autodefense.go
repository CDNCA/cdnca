package siteconf

import (
	"encoding/json"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/libs/marketproto/spec"
)

// AutoDefense is the site owner's automatic defence setting carried to the
// leaf (Config.AutoDefense, ADR 0012 §19.2). Field names and values follow
// docs/edge/autodefense-contract.md §3.2 and §4; the leaf checks the platform
// ranges of each item (it owns the field registry). Absent fields mean the
// leaf default; an absent block means the subscriber does not manage it.
type AutoDefense struct {
	Mode        string `json:"mode"`                  // off, learning, observe, protect
	Sensitivity string `json:"sensitivity,omitempty"` // low, medium, high
	CrossSite   *bool  `json:"cross_site,omitempty"`
	// MaxLevel locks site.max_level (0 observe .. 5 XDP); nil = automatic.
	MaxLevel *int                `json:"max_level,omitempty"`
	Modules  []AutoDefenseModule `json:"modules,omitempty"`
}

// AutoDefenseModule is one site module overlay (cc, waf, scan, bot).
type AutoDefenseModule struct {
	Name  string            `json:"name"`
	Mode  string            `json:"mode"` // manual, auto, suggest
	Items []AutoDefenseItem `json:"items,omitempty"`
}

// AutoDefenseItem is one overlay field: Value locks it to a manual value,
// Low/High set the automatic range. Values are the contract's integers
// (enum ordinals, booleans 0/1).
type AutoDefenseItem struct {
	Field string `json:"field"`
	Value *int64 `json:"value,omitempty"`
	Low   *int64 `json:"low,omitempty"`
	High  *int64 `json:"high,omitempty"`
}

// Blocker codes a leaf reports for auto_defense and node plugins. They are
// advisory: the leaf applies the rest of the revision (U14).
const (
	BlockerAutoDefenseCapped      = "autodefense_capped"
	BlockerAutoDefenseUnavailable = "autodefense_unavailable"
	BlockerPluginUnavailable      = "plugin_unavailable"
)

const (
	maxAutoDefenseItems = 64
	maxFieldLength      = 96
)

var fieldPattern = regexp.MustCompile(`^[a-z][a-z0-9]*\.[a-z0-9_]+(:[a-z0-9][a-z0-9._-]*)?$`)

// DecodeAutoDefense returns the auto_defense block, or nil when the config
// carries none.
func (c Config) DecodeAutoDefense() (*AutoDefense, error) {
	var ad AutoDefense
	if present, err := decodeStrict(c.AutoDefense, &ad); !present || err != nil {
		return nil, err
	}
	if !slices.Contains([]string{"off", "learning", "observe", "protect"}, ad.Mode) ||
		(ad.Sensitivity != "" && !slices.Contains([]string{"low", "medium", "high"}, ad.Sensitivity)) ||
		(ad.MaxLevel != nil && (*ad.MaxLevel < 0 || *ad.MaxLevel > spec.MaxAutoDefenseLevel)) ||
		len(ad.Modules) > len(spec.AutoDefenseModules) {
		return nil, ErrInvalid
	}
	slices.SortFunc(ad.Modules, func(a, b AutoDefenseModule) int { return strings.Compare(a.Name, b.Name) })
	for i := range ad.Modules {
		m := &ad.Modules[i]
		if !slices.Contains(spec.AutoDefenseModules, m.Name) || (i > 0 && ad.Modules[i-1].Name == m.Name) ||
			!slices.Contains([]string{"manual", "auto", "suggest"}, m.Mode) || len(m.Items) > maxAutoDefenseItems {
			return nil, ErrInvalid
		}
		slices.SortFunc(m.Items, func(a, b AutoDefenseItem) int { return strings.Compare(a.Field, b.Field) })
		for j, it := range m.Items {
			if len(it.Field) > maxFieldLength || !fieldPattern.MatchString(it.Field) ||
				!strings.HasPrefix(it.Field, m.Name+".") || (j > 0 && m.Items[j-1].Field == it.Field) ||
				(it.Value == nil && it.Low == nil && it.High == nil) ||
				(it.Low != nil && it.High != nil && *it.Low > *it.High) {
				return nil, ErrInvalid
			}
		}
		if len(m.Items) == 0 {
			m.Items = nil
		}
	}
	if len(ad.Modules) == 0 {
		ad.Modules = nil
	}
	return &ad, nil
}

// Clamp tightens ad to the supplier caps of the grant (U7): a locked or
// automatic (nil) max_level above the cap is locked to it, and an auto module
// the caps do not allow falls back to manual (suggest only displays, so it
// stays). It returns one autodefense_capped blocker per
// tightened item (Detail = "max_level" or "module:<name>"). nil caps change
// nothing.
func (ad *AutoDefense) Clamp(caps *spec.AutoDefenseCaps) []Blocker {
	if ad == nil || caps == nil {
		return nil
	}
	var out []Blocker
	if caps.MaxLevel < spec.MaxAutoDefenseLevel && (ad.MaxLevel == nil || *ad.MaxLevel > caps.MaxLevel) {
		level := caps.MaxLevel
		ad.MaxLevel = &level
		out = append(out, Blocker{Code: BlockerAutoDefenseCapped, Detail: "max_level:" + strconv.Itoa(level)})
	}
	for i := range ad.Modules {
		m := &ad.Modules[i]
		if m.Mode == "auto" && !caps.Allows(m.Name) {
			m.Mode = "manual"
			out = append(out, Blocker{Code: BlockerAutoDefenseCapped, Detail: "module:" + m.Name})
		}
	}
	return out
}

func (c *Config) normalizeAutoDefense() error {
	ad, err := c.DecodeAutoDefense()
	if err != nil {
		return err
	}
	c.AutoDefense = nil
	if ad != nil {
		if c.AutoDefense, err = json.Marshal(ad); err != nil {
			return ErrInvalid
		}
	}
	return nil
}
