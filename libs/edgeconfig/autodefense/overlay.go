package autodefense

import (
	"sort"
	"strings"
)

// Module auto overlay (ADR 0010 section 7A). Every module (site level: cc,
// waf, scan, bot; node x port group level: l4) is manual, auto or suggest;
// every adjustable field is an Item that is either automatic or locked by a
// person. The overlay never overwrites the manual saved value:
//
//	effective = locked ? manual : clamp(auto, min, max)
//
// and it is the manual value whenever the overlay is inactive (module not in
// auto mode, site not protecting, module.autodefense.auto not licensed,
// circuit open) or the item has no automatic value yet.

// ModuleName names a protection module.
type ModuleName string

const (
	ModuleCC   ModuleName = "cc"
	ModuleWAF  ModuleName = "waf"
	ModuleL4   ModuleName = "l4"
	ModuleScan ModuleName = "scan"
	ModuleBot  ModuleName = "bot"
)

// ModuleMode is the three-way choice of section 7A.1.
type ModuleMode string

const (
	ModuleManual  ModuleMode = "manual"
	ModuleAuto    ModuleMode = "auto"
	ModuleSuggest ModuleMode = "suggest"
)

// ItemState: auto (the defense adjusts within [min, max]) or manual (a
// person locked it; the defense neither reads nor changes it until a person
// chooses "auto" again).
type ItemState string

const (
	ItemAuto   ItemState = "auto"
	ItemManual ItemState = "manual"
)

// Module is one module's overlay. Items are in field order.
type Module struct {
	Name  ModuleName `json:"name"`
	Mode  ModuleMode `json:"mode"`
	Items []Item     `json:"items"`
}

// Item is one adjustable field. Values are integers in the field's unit;
// enum fields carry the ordinal of FieldSpec.Enum, bool fields 0 or 1.
type Item struct {
	Field string    `json:"field"`
	State ItemState `json:"state"`
	// Manual is the person's saved value (the platform default when the
	// person never set one). Locked, it is the value in force.
	Manual int64 `json:"manual"`
	// Auto is the overlay value; absent = no automatic adjustment yet.
	Auto *int64 `json:"auto,omitempty"`
	// Min and Max are the automatic range: the field's platform range
	// narrowed by the user or by the module rules (for example CC's upper
	// bound = the manual value). Auto is clamped into it.
	Min int64 `json:"min"`
	Max int64 `json:"max"`
	// LockedBy / LockedAt: set exactly when State is manual. A person
	// editing the field locks it automatically.
	LockedBy string `json:"locked_by,omitempty"`
	LockedAt int64  `json:"locked_at,omitempty"`
	// ResumedBy / ResumedAt: the person who last chose "auto" again (only
	// in State auto, kept for the page and audit).
	ResumedBy string `json:"resumed_by,omitempty"`
	ResumedAt int64  `json:"resumed_at,omitempty"`
	// FrozenUntil: three reversals within an hour freeze the item for an
	// hour (section 7A.1 rhythm); the node keeps its current value.
	FrozenUntil int64 `json:"frozen_until,omitempty"`
}

// Tighter tells which direction is stricter (adjustment rhythm, section
// 7A.1: tightening applies at once, relaxing one step at a time).
type Tighter string

const (
	TighterLower  Tighter = "lower"
	TighterHigher Tighter = "higher"
)

// FieldKind is the value type of a field.
type FieldKind string

const (
	FieldInt  FieldKind = "int"
	FieldEnum FieldKind = "enum"
	FieldBool FieldKind = "bool"
)

// FieldSpec is the frozen description of one overlay field.
type FieldSpec struct {
	Field   string
	Module  ModuleName // "" = site item
	Kind    FieldKind
	Unit    string
	Enum    []string // ordinal = value, ascending strictness
	Tighter Tighter
	// PlatformMin / PlatformMax: the widest automatic range; users may only
	// narrow it.
	PlatformMin int64
	PlatformMax int64
	// DefaultMin / DefaultMax: the default automatic range (ADR 0010
	// section 7A tables); module rules may narrow it further.
	DefaultMin int64
	DefaultMax int64
	// ManualBound ties the automatic range to the manual value (section 7A
	// tables): "max" = the range may not exceed it (CC threshold, layer 4
	// limits: "upper bound = manual value"), "min" = the range may not go
	// below it (WAF tier: "never below the tier a person chose"), "" = none.
	ManualBound string
	// Suffix: the field name is Field + ":" + slug (one item per rule
	// group, for example waf.group:sqli).
	Suffix bool
	// Section is the ADR 0010 section the field implements.
	Section string
}

// Enum values.
var (
	// LevelNames are the mitigation ladder levels (section 7.1).
	LevelNames = []string{"observe", "challenge", "rate_limit", "ban", "kernel", "xdp"}
	// ChallengeNames: CC challenge strength (section 7A.2: up to PoW).
	ChallengeNames = []string{"off", "js", "five_second", "pow"}
	// WAFTierNames: the four WAF tiers
	// (仅记录 / 标准防护 / 严格防护 / 极严格防护).
	WAFTierNames = []string{"log_only", "standard", "strict", "extra_strict"}
	// WAFGroupNames: a rule group observes (log) or blocks (section 7A.3).
	WAFGroupNames = []string{"log", "block"}
	// SYNTierNames (section 7A.4).
	SYNTierNames = []string{"off", "syncookies", "syncookies_ip_rate", "cidr24_rate"}
	// BotActionNames: what the gate does with a bot class.
	BotActionNames = []string{"log", "challenge", "block"}
)

const (
	waftierStandard = 1
	waftierStrict   = 2
)

var fieldSpecs = []FieldSpec{
	{Field: "site.max_level", Kind: FieldEnum, Enum: LevelNames, Tighter: TighterHigher,
		PlatformMin: 0, PlatformMax: int64(LevelXDP), DefaultMin: 0, DefaultMax: int64(LevelXDP), Section: "7.1 / Q3"},

	{Field: "cc.per_ip_requests", ManualBound: "max", Module: ModuleCC, Kind: FieldInt, Unit: "requests per window", Tighter: TighterLower,
		PlatformMin: 1, PlatformMax: 1000000, DefaultMin: 5, DefaultMax: 1000000, Section: "7A.2"},
	{Field: "cc.challenge", Module: ModuleCC, Kind: FieldEnum, Enum: ChallengeNames, Tighter: TighterHigher,
		PlatformMin: 0, PlatformMax: 3, DefaultMin: 0, DefaultMax: 3, Section: "7A.2"},
	{Field: "cc.ban_seconds", Module: ModuleCC, Kind: FieldInt, Unit: "seconds", Tighter: TighterHigher,
		PlatformMin: 600, PlatformMax: 86400, DefaultMin: 600, DefaultMax: 86400, Section: "7A.2"},
	{Field: "cc.auto_switch_qps", Module: ModuleCC, Kind: FieldInt, Unit: "requests per second", Tighter: TighterLower,
		PlatformMin: 1, PlatformMax: 10000000, DefaultMin: 1, DefaultMax: 10000000, Section: "7A.2"},
	// cc.limit_permille: every CC rate rule of the site
	// (fixed windows of any count_by key, leaky buckets) runs at this share
	// of its own limits, 1000 = unchanged; it only tightens. The automatic
	// value comes from the site baseline (request rate p99 against the
	// attack's rate); the default range stops at a quarter of the limits.
	{Field: "cc.limit_permille", ManualBound: "max", Module: ModuleCC, Kind: FieldInt, Unit: "permille", Tighter: TighterLower,
		PlatformMin: 100, PlatformMax: 1000, DefaultMin: 250, DefaultMax: 1000, Section: "7A.2"},

	{Field: "waf.tier", ManualBound: "min", Module: ModuleWAF, Kind: FieldEnum, Enum: WAFTierNames, Tighter: TighterHigher,
		PlatformMin: 0, PlatformMax: 3, DefaultMin: waftierStandard, DefaultMax: waftierStrict, Section: "7A.3"},
	{Field: "waf.crs_tier", ManualBound: "min", Module: ModuleWAF, Kind: FieldEnum, Enum: WAFTierNames, Tighter: TighterHigher,
		PlatformMin: 0, PlatformMax: 3, DefaultMin: waftierStandard, DefaultMax: waftierStrict, Section: "7A.3"},
	{Field: "waf.auto_block", Module: ModuleWAF, Kind: FieldBool, Tighter: TighterHigher,
		PlatformMin: 0, PlatformMax: 1, DefaultMin: 0, DefaultMax: 1, Section: "7A.3"},
	{Field: "waf.group", Module: ModuleWAF, Kind: FieldEnum, Enum: WAFGroupNames, Tighter: TighterHigher, Suffix: true,
		PlatformMin: 0, PlatformMax: 1, DefaultMin: 0, DefaultMax: 1, Section: "7A.3"},
	// waf.tighten:<set>: the set's weak rules score as strong on the site
	// (ADR 0011 section 3.5, context k=); the node's own overlay, the slug is
	// the set key without "waf_set:" (a set the tier's adaptive list names).
	{Field: "waf.tighten", Module: ModuleWAF, Kind: FieldBool, Tighter: TighterHigher, Suffix: true,
		PlatformMin: 0, PlatformMax: 1, DefaultMin: 0, DefaultMax: 1, Section: "ADR 0011 3.5"},

	{Field: "l4.max_conns_per_ip", ManualBound: "max", Module: ModuleL4, Kind: FieldInt, Unit: "connections", Tighter: TighterLower,
		PlatformMin: 4, PlatformMax: 1000000, DefaultMin: 4, DefaultMax: 1000000, Section: "7A.4"},
	{Field: "l4.new_conns_per_second", ManualBound: "max", Module: ModuleL4, Kind: FieldInt, Unit: "connections per second", Tighter: TighterLower,
		PlatformMin: 5, PlatformMax: 1000000, DefaultMin: 5, DefaultMax: 1000000, Section: "7A.4"},
	{Field: "l4.new_conns_per_minute", ManualBound: "max", Module: ModuleL4, Kind: FieldInt, Unit: "connections per minute", Tighter: TighterLower,
		PlatformMin: 5, PlatformMax: 60000000, DefaultMin: 5, DefaultMax: 60000000, Section: "7A.4"},
	{Field: "l4.syn_tier", Module: ModuleL4, Kind: FieldEnum, Enum: SYNTierNames, Tighter: TighterHigher,
		PlatformMin: 0, PlatformMax: 3, DefaultMin: 0, DefaultMax: 3, Section: "7A.4"},
	{Field: "l4.malformed_drop", Module: ModuleL4, Kind: FieldBool, Tighter: TighterHigher,
		PlatformMin: 0, PlatformMax: 1, DefaultMin: 0, DefaultMax: 1, Section: "7A.4"},
	{Field: "l4.invalid_drop", Module: ModuleL4, Kind: FieldBool, Tighter: TighterHigher,
		PlatformMin: 0, PlatformMax: 1, DefaultMin: 0, DefaultMax: 1, Section: "7A.4"},
	{Field: "l4.idle_seconds", Module: ModuleL4, Kind: FieldInt, Unit: "seconds", Tighter: TighterLower,
		PlatformMin: 3, PlatformMax: 86400, DefaultMin: 3, DefaultMax: 86400, Section: "7A.4"},

	{Field: "scan.not_found_threshold", Module: ModuleScan, Kind: FieldInt, Unit: "404 per 60 seconds", Tighter: TighterLower,
		PlatformMin: 10, PlatformMax: 200, DefaultMin: 10, DefaultMax: 200, Section: "7A.5"},
	{Field: "scan.login_failures_per_minute", Module: ModuleScan, Kind: FieldInt, Unit: "failures per minute per IP", Tighter: TighterLower,
		PlatformMin: 5, PlatformMax: 100000, DefaultMin: 5, DefaultMax: 100000, Section: "7A.5"},
	{Field: "scan.ban_seconds", Module: ModuleScan, Kind: FieldInt, Unit: "seconds", Tighter: TighterHigher,
		PlatformMin: 600, PlatformMax: 86400, DefaultMin: 600, DefaultMax: 86400, Section: "7A.5"},
	{Field: "scan.login_challenge", Module: ModuleScan, Kind: FieldBool, Tighter: TighterHigher,
		PlatformMin: 0, PlatformMax: 1, DefaultMin: 0, DefaultMax: 1, Section: "7A.5"},

	{Field: "bot.mismatch_challenge", Module: ModuleBot, Kind: FieldBool, Tighter: TighterHigher,
		PlatformMin: 0, PlatformMax: 1, DefaultMin: 0, DefaultMax: 1, Section: "7A.6"},
	{Field: "bot.fake_crawler_block", Module: ModuleBot, Kind: FieldBool, Tighter: TighterHigher,
		PlatformMin: 0, PlatformMax: 1, DefaultMin: 0, DefaultMax: 1, Section: "7A.6"},
	// Bot categories: the gate classifies the User-Agent
	// (BotCategories) and acts per the category's level; verified crawlers
	// and whitelisted clients are never acted on.
	{Field: "bot.scanner", Module: ModuleBot, Kind: FieldEnum, Enum: BotActionNames, Tighter: TighterHigher,
		PlatformMin: 0, PlatformMax: 2, DefaultMin: 0, DefaultMax: 2, Section: "7A.6"},
	{Field: "bot.headless", Module: ModuleBot, Kind: FieldEnum, Enum: BotActionNames, Tighter: TighterHigher,
		PlatformMin: 0, PlatformMax: 2, DefaultMin: 0, DefaultMax: 2, Section: "7A.6"},
	{Field: "bot.ai_crawler", Module: ModuleBot, Kind: FieldEnum, Enum: BotActionNames, Tighter: TighterHigher,
		PlatformMin: 0, PlatformMax: 2, DefaultMin: 0, DefaultMax: 2, Section: "7A.6"},
	{Field: "bot.bad_ua", Module: ModuleBot, Kind: FieldEnum, Enum: BotActionNames, Tighter: TighterHigher,
		PlatformMin: 0, PlatformMax: 2, DefaultMin: 0, DefaultMax: 2, Section: "7A.6"},
}

// BotCategories are the User-Agent classes of the gate (cdnca_bot.lua), in
// match order: the first class whose list matches is the request's. The
// overlay field of a class is "bot." + class; frames count hits per class
// (FrameSite.BotHits).
var BotCategories = []string{"scanner", "headless", "ai_crawler", "bad_ua"}

// FieldSpecs returns the frozen field registry in field order.
func FieldSpecs() []FieldSpec {
	out := append([]FieldSpec(nil), fieldSpecs...)
	sort.Slice(out, func(i, j int) bool { return out[i].Field < out[j].Field })
	return out
}

// LookupField resolves an item field name (with its slug for suffix fields).
func LookupField(field string) (FieldSpec, bool) {
	base, slug, suffixed := strings.Cut(field, ":")
	for _, spec := range fieldSpecs {
		if spec.Field != base || spec.Suffix != suffixed {
			continue
		}
		if suffixed && !slugPattern.MatchString(slug) {
			return FieldSpec{}, false
		}
		return spec, true
	}
	return FieldSpec{}, false
}

// Effective is the value in force (section 7A.1). active: the overlay
// applies (module in auto mode, site protecting, auto mitigation licensed,
// circuit closed).
func (item Item) Effective(active bool) int64 {
	if item.State == ItemManual || !active || item.Auto == nil {
		return item.Manual
	}
	return clamp(*item.Auto, item.Min, item.Max)
}

// Suggestion is what a suggest-mode module shows (never in force); ok is
// false when there is no automatic value or the item is locked.
func (item Item) Suggestion() (int64, bool) {
	if item.State == ItemManual || item.Auto == nil {
		return 0, false
	}
	return clamp(*item.Auto, item.Min, item.Max), true
}

// Active reports whether a module's overlay applies on a site.
func Active(snapshot Snapshot, site Site, module Module, now int64) bool {
	return snapshot.AutoMitigation && site.Mode == SiteProtect && site.Circuit.State == CircuitClosed &&
		site.ObserveUntil <= now && module.Mode == ModuleAuto
}

// Item returns the module's item of field.
func (module Module) Item(field string) (Item, bool) {
	index := sort.Search(len(module.Items), func(i int) bool { return module.Items[i].Field >= field })
	if index < len(module.Items) && module.Items[index].Field == field {
		return module.Items[index], true
	}
	return Item{}, false
}

// MaxLevelOf is the site's mitigation ceiling in force: unlocked it is the
// automatic value clamped into [min, max] (no ceiling by default, Q3);
// locked it is the manual level.
func (site Site) MaxLevelOf() Level {
	return Level(site.MaxLevel.Effective(true))
}

// NodeLevel is the level a node executes: L5 runs as L4 until the node has
// XDP (Q9 placeholder).
func NodeLevel(level Level, xdp bool) Level {
	if level == LevelXDP && !xdp {
		return LevelKernel
	}
	return level
}

func clamp(value, low, high int64) int64 {
	if value < low {
		return low
	}
	if value > high {
		return high
	}
	return value
}

func validItem(item Item, module ModuleName) bool {
	spec, ok := LookupField(item.Field)
	if !ok || spec.Module != module {
		return false
	}
	inRange := func(value int64) bool { return value >= spec.PlatformMin && value <= spec.PlatformMax }
	if !inRange(item.Manual) || !inRange(item.Min) || !inRange(item.Max) || item.Min > item.Max ||
		(item.Auto != nil && !inRange(*item.Auto)) || !validTime(item.FrozenUntil, true) ||
		(spec.ManualBound == "max" && item.Max > item.Manual) || (spec.ManualBound == "min" && item.Min < item.Manual) {
		return false
	}
	switch item.State {
	case ItemManual:
		if !actorPattern.MatchString(item.LockedBy) || !validTime(item.LockedAt, false) ||
			item.ResumedBy != "" || item.ResumedAt != 0 {
			return false
		}
	case ItemAuto:
		if item.LockedBy != "" || item.LockedAt != 0 {
			return false
		}
		if (item.ResumedBy == "") != (item.ResumedAt == 0) ||
			(item.ResumedBy != "" && (!actorPattern.MatchString(item.ResumedBy) || !validTime(item.ResumedAt, false))) {
			return false
		}
	default:
		return false
	}
	return true
}

func validModule(module Module, expected ModuleName) bool {
	if module.Name != expected {
		return false
	}
	switch module.Mode {
	case ModuleManual, ModuleAuto, ModuleSuggest:
	default:
		return false
	}
	if module.Items == nil || len(module.Items) > len(fieldSpecs)+64 {
		return false
	}
	for index, item := range module.Items {
		if !validItem(item, module.Name) || (index > 0 && module.Items[index-1].Field >= item.Field) {
			return false
		}
	}
	return true
}
