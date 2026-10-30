package rulepack

import "sort"

// Level is an enablement level (ADR 0007 §5.4): platform -> tenant -> site.
type Level string

const (
	LevelDefault  Level = "default"
	LevelPlatform Level = "platform"
	LevelTenant   Level = "tenant"
	LevelSite     Level = "site"
)

// LevelRef names one level object: the platform (no ID), a tenant scope or
// a site.
type LevelRef struct {
	Level    Level  `json:"level"`
	ObjectID string `json:"object_id,omitempty"`
}

// State is a three-state setting. An absent override row means inherit; a
// row with StateInherit only carries priority / params / allow_lower.
type State string

const (
	StateInherit  State = "inherit"
	StateEnabled  State = "enabled"
	StateDisabled State = "disabled"
)

// Override is one enablement row. RuleID empty = pack level; otherwise a
// rule-level state (enabled / disabled only) of an exported rule.
// AllowLower (pack level) lets the levels below adjust the pack.
type Override struct {
	Level      Level
	ObjectID   string
	PackID     string
	RuleID     string
	State      State
	AllowLower bool
	Priority   *int
	Params     Params
}

// Subject is what the effective set is computed for: the platform alone,
// a tenant (TenantScopeID) or a site of a tenant (both).
type Subject struct {
	TenantScopeID string
	SiteID        string
}

// Effect is the inherited state of one pack for a subject.
type Effect struct {
	Pack    *CompiledPack
	Enabled bool
	// EnabledAt is the level whose row decided Enabled (LevelDefault: no row,
	// a downloaded pack is disabled).
	EnabledAt LevelRef
	// Inherited is Enabled from the levels above the subject's own (what its
	// "inherit" setting follows).
	Inherited bool
	// Adjustable are the subject's levels where the pack can be set now.
	Adjustable []LevelRef
	Priority   int
	Params     Params
	RuleStates map[string]bool
	RuleSource map[string]LevelRef
	// Ignored are rows below a level that does not allow adjustment.
	Ignored []Override
}

// Effective applies the inheritance to every visible pack: a user pack is
// visible only to its tenant; packs are disabled unless a row enables them;
// a level's row applies only when every level above it allows adjustment
// (a user pack starts adjustable by its owner tenant, other packs start
// locked to the platform).
func Effective(packs []*CompiledPack, overrides []Override, subject Subject) []Effect {
	chain := []LevelRef{{Level: LevelPlatform}}
	if subject.TenantScopeID != "" {
		chain = append(chain, LevelRef{Level: LevelTenant, ObjectID: subject.TenantScopeID})
		if subject.SiteID != "" {
			chain = append(chain, LevelRef{Level: LevelSite, ObjectID: subject.SiteID})
		}
	}
	type key struct{ level, object, pack, rule string }
	rows := map[key]Override{}
	ruleIDs := map[string][]string{}
	for _, row := range overrides {
		if row.Level == LevelPlatform {
			row.ObjectID = ""
		}
		rows[key{string(row.Level), row.ObjectID, row.PackID, row.RuleID}] = row
		if row.RuleID != "" {
			ruleIDs[row.PackID] = append(ruleIDs[row.PackID], row.RuleID)
		}
	}
	effects := []Effect{}
	for _, pack := range packs {
		if pack == nil {
			continue
		}
		if pack.Pack.Layer == LayerUser {
			scope, _ := UserPackScope(pack.Pack.PackID)
			if scope != subject.TenantScopeID {
				continue
			}
		}
		effect := Effect{Pack: pack, EnabledAt: LevelRef{Level: LevelDefault}, Adjustable: []LevelRef{},
			Priority: DefaultPriority, Params: Params{}, RuleStates: map[string]bool{}, RuleSource: map[string]LevelRef{},
			Ignored: []Override{}}
		open := pack.Pack.Layer == LayerUser
		permitted := map[Level]bool{}
		for _, ref := range chain {
			effect.Inherited = effect.Enabled
			allowed := ref.Level == LevelPlatform || open
			permitted[ref.Level] = allowed
			if allowed {
				effect.Adjustable = append(effect.Adjustable, ref)
			}
			row, ok := rows[key{string(ref.Level), ref.ObjectID, pack.Pack.PackID, ""}]
			if !ok {
				continue
			}
			if !allowed {
				effect.Ignored = append(effect.Ignored, row)
				continue
			}
			if row.State != StateInherit {
				effect.Enabled, effect.EnabledAt = row.State == StateEnabled, ref
			}
			if row.Priority != nil {
				effect.Priority = *row.Priority
			}
			for name, value := range row.Params {
				effect.Params[name] = value
			}
			open = row.AllowLower
		}
		ids := sortUnique(append([]string{}, ruleIDs[pack.Pack.PackID]...))
		for _, id := range ids {
			for _, ref := range chain {
				row, ok := rows[key{string(ref.Level), ref.ObjectID, pack.Pack.PackID, id}]
				if !ok || row.State == StateInherit {
					continue
				}
				if !permitted[ref.Level] {
					effect.Ignored = append(effect.Ignored, row)
					continue
				}
				effect.RuleStates[id] = row.State == StateEnabled
				effect.RuleSource[id] = ref
			}
		}
		effects = append(effects, effect)
	}
	sort.Slice(effects, func(i, j int) bool { return effects[i].Pack.Pack.PackID < effects[j].Pack.Pack.PackID })
	return effects
}

// MountRequests turns the enabled effects into Resolve input; disabled and
// merely downloaded packs never become mounts.
func MountRequests(effects []Effect) []MountRequest {
	requests := []MountRequest{}
	for _, effect := range effects {
		if !effect.Enabled {
			continue
		}
		requests = append(requests, MountRequest{Pack: effect.Pack, Priority: effect.Priority, Params: effect.Params,
			RuleStates: effect.RuleStates,
			Source:     Source{EnabledAt: effect.EnabledAt, DisableAt: effect.Adjustable, RuleSource: effect.RuleSource}})
	}
	return requests
}
