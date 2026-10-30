package rulepack

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
)

// ResolvedSchema names the document resolved_sha256 is the digest of.
const ResolvedSchema = "cdnca.rule-pack-resolved/v1"

// Mount is one entry of a site object's security.mounts (ADR 0009 §8.4),
// plus the priority it was mounted with. Params are complete and canonical
// (defaults merged, exclusions = the exported rules switched off).
type Mount struct {
	Layer    Layer  `json:"layer"`
	PackID   string `json:"pack_id"`
	Version  string `json:"version"`
	SHA256   string `json:"sha256"`
	Engine   Engine `json:"engine"`
	Priority int    `json:"priority"`
	Params   Params `json:"params"`
}

// Security is the rule-pack part of a site object's security section.
type Security struct {
	Mounts         []Mount `json:"mounts"`
	ResolvedSHA256 string  `json:"resolved_sha256"`
}

// Source says where an effective mount came from: the level whose setting
// enabled it and the levels where it can currently be switched off.
type Source struct {
	EnabledAt  LevelRef            `json:"enabled_at"`
	DisableAt  []LevelRef          `json:"disable_at"`
	RuleSource map[string]LevelRef `json:"rule_source,omitempty"`
}

// MountRequest is one effective (enabled) pack of a site.
type MountRequest struct {
	Pack     *CompiledPack
	Priority int
	// Params overlay the pack defaults (canonical or not).
	Params Params
	// RuleStates are rule-level settings (true = enabled) of exported rules;
	// an unexported ID is a conflict.
	RuleStates map[string]bool
	Source     Source
}

// Target is what the site's nodes run: the lowest engine version among them
// (an engine absent here is not checked; node gating is a separate step).
type Target struct {
	EngineVersions map[Engine]uint32
}

// NodeRule is one rule the node runs, in execution order.
type NodeRule struct {
	Layer    Layer                     `json:"layer"`
	PackID   string                    `json:"pack_id"`
	Version  string                    `json:"version"`
	RuleID   string                    `json:"rule_id"`
	NodeID   string                    `json:"node_id"`
	Engine   Engine                    `json:"engine"`
	Priority int                       `json:"priority"`
	Name     string                    `json:"name"`
	WAF      *edgeconfig.WAFRule       `json:"waf,omitempty"`
	CC       *edgeconfig.CCV2Rule      `json:"cc,omitempty"`
	CRS      *rulecatalog.WAFEngineSet `json:"crs,omitempty"`
}

type resolvedDocument struct {
	Schema string     `json:"schema"`
	Mounts []Mount    `json:"mounts"`
	Rules  []NodeRule `json:"rules"`
}

// Conflict codes (publication is refused while any is present).
const (
	ConflictDuplicatePack   = "duplicate_pack"
	ConflictOppositeAction  = "opposite_action"
	ConflictUnknownExport   = "unknown_export"
	ConflictParamsInvalid   = "params_invalid"
	ConflictEngineVersion   = "engine_version"
	ConflictEngineSingleton = "engine_singleton"
	ConflictBudget          = "budget_exceeded"
	WarningShadowed         = "shadowed"
)

type ConflictSide struct {
	Layer     Layer    `json:"layer"`
	PackID    string   `json:"pack_id"`
	Version   string   `json:"version"`
	RuleID    string   `json:"rule_id,omitempty"`
	EnabledAt LevelRef `json:"enabled_at"`
}

// Remedy is the only kind of fix offered: switch one side off at a level
// (never delete, never reorder automatically).
type Remedy struct {
	Action string   `json:"action"`
	At     LevelRef `json:"at"`
	PackID string   `json:"pack_id"`
	RuleID string   `json:"rule_id,omitempty"`
}

type Conflict struct {
	Code     string         `json:"code"`
	Message  string         `json:"message"`
	Sides    []ConflictSide `json:"sides"`
	Remedies []Remedy       `json:"remedies"`
}

// Resolution is the result of resolving a site's effective mounts. Security
// is set only when Conflicts is empty.
type Resolution struct {
	Security  *Security  `json:"security"`
	Rules     []NodeRule `json:"rules"`
	Conflicts []Conflict `json:"conflicts"`
	Warnings  []Conflict `json:"warnings"`
	Cost      Cost       `json:"cost"`
	Requires  []string   `json:"requires"`
}

// Resolve orders effective mounts by (layer_rank, priority, pack_id) and
// their rules by rule_id, detects conflicts among them only (ADR 0007 §5.2)
// and computes resolved_sha256.
func Resolve(requests []MountRequest, target Target) Resolution {
	resolution := Resolution{Rules: []NodeRule{}, Conflicts: []Conflict{}, Warnings: []Conflict{}, Requires: []string{}}
	byPack := map[string][]MountRequest{}
	mounts := make([]Mount, 0, len(requests))
	sources := map[string]MountRequest{}
	requires := map[string]bool{}
	// modsecurity: one CRS selection pack and one CRS tuning pack at most
	// (ADR 0011 §6.4: the tuning pack only removes targets of the profile)
	singletons := map[string][]MountRequest{}
	for _, request := range requests {
		if request.Pack == nil {
			continue
		}
		pack := request.Pack.Pack
		byPack[pack.PackID] = append(byPack[pack.PackID], request)
	}
	packIDs := make([]string, 0, len(byPack))
	for id := range byPack {
		packIDs = append(packIDs, id)
	}
	sort.Strings(packIDs)
	for _, id := range packIDs {
		group := byPack[id]
		if len(group) > 1 {
			resolution.Conflicts = append(resolution.Conflicts, conflictOf(ConflictDuplicatePack,
				fmt.Sprintf("pack %s is mounted %d times", id, len(group)), group, ""))
			continue
		}
		request := group[0]
		pack := request.Pack.Pack
		priority := request.Priority
		if priority < 0 || priority > MaxPriority {
			resolution.Conflicts = append(resolution.Conflicts, conflictOf(ConflictParamsInvalid,
				fmt.Sprintf("priority %d of %s is outside 0..%d", priority, id, MaxPriority), group, ""))
			continue
		}
		params, err := MergeParams(pack, request.Params, request.RuleStates)
		if err != nil {
			code := ConflictParamsInvalid
			if errors.Is(err, ErrUnknownExport) {
				code = ConflictUnknownExport
			}
			resolution.Conflicts = append(resolution.Conflicts, conflictOf(code, err.Error(), group, ""))
			continue
		}
		if have, ok := target.EngineVersions[pack.Engine]; ok && have < pack.EngineMinVersion {
			resolution.Conflicts = append(resolution.Conflicts, conflictOf(ConflictEngineVersion,
				fmt.Sprintf("%s needs %s v%d, the site's nodes run v%d", id, pack.Engine, pack.EngineMinVersion, have), group, ""))
			continue
		}
		if pack.Engine == EngineModSecurity {
			slot := "modsecurity"
			if IsCRSTuningPack(id) {
				slot = "CRS tuning"
			}
			singletons[slot] = append(singletons[slot], request)
		}
		for _, name := range request.Pack.Requires {
			requires[name] = true
		}
		mounts = append(mounts, Mount{Layer: pack.Layer, PackID: id, Version: pack.Version, SHA256: request.Pack.SHA256,
			Engine: pack.Engine, Priority: priority, Params: params})
		sources[id] = request
	}
	for _, slot := range []string{"modsecurity", "CRS tuning"} {
		if group := singletons[slot]; len(group) > 1 {
			resolution.Conflicts = append(resolution.Conflicts, conflictOf(ConflictEngineSingleton,
				fmt.Sprintf("only one %s pack can run on a site", slot), group, ""))
		}
	}
	sortMounts(mounts)
	packs := map[string]*CompiledPack{}
	for _, mount := range mounts {
		packs[mount.SHA256] = sources[mount.PackID].Pack
	}
	// Sealed packs: the control plane has only their manifest. Their rules
	// are not instantiated, listed or checked rule by rule here; their
	// declared cost counts towards the site budget.
	rules, err := program(mounts, packs, false)
	if err != nil {
		resolution.Conflicts = append(resolution.Conflicts, Conflict{Code: ConflictParamsInvalid, Message: err.Error(),
			Sides: []ConflictSide{}, Remedies: []Remedy{}})
		return resolution
	}
	resolution.Rules = rules
	for _, name := range sortUnique(keys(requires)) {
		resolution.Requires = append(resolution.Requires, name)
	}
	cost := Cost{}
	for _, rule := range rules {
		ruleCost, _ := nodeRuleCost(rule)
		cost = cost.add(ruleCost)
	}
	for _, mount := range mounts {
		if pack := packs[mount.SHA256]; pack.Sealed {
			cost = cost.add(pack.Cost)
		}
	}
	resolution.Cost = cost
	if err := cost.within(siteBudget); err != nil {
		resolution.Conflicts = append(resolution.Conflicts, Conflict{Code: ConflictBudget, Message: err.Error(),
			Sides: []ConflictSide{}, Remedies: []Remedy{}})
	}
	conflicts, warnings := ruleConflicts(rules, sources)
	resolution.Conflicts = append(resolution.Conflicts, conflicts...)
	resolution.Warnings = append(resolution.Warnings, warnings...)
	// The compiled per-request cost of the plan the node will run (ADR 0011
	// §6.5); the node precheck compiles the same plan (MountRulePlan). The
	// control plane sees no rules of sealed packs: the node checks those.
	if len(resolution.Conflicts) == 0 {
		digests := map[string]string{}
		for _, mount := range mounts {
			digests[mount.PackID] = mount.SHA256
		}
		if _, err := MountRulePlan(rules, func(packID string) string { return digests[packID] }, false); err != nil {
			resolution.Conflicts = append(resolution.Conflicts, Conflict{Code: ConflictBudget, Message: err.Error(),
				Sides: []ConflictSide{}, Remedies: []Remedy{}})
		}
	}
	if len(resolution.Conflicts) == 0 {
		digest, err := resolvedDigest(mounts, rules)
		if err != nil {
			resolution.Conflicts = append(resolution.Conflicts, Conflict{Code: ConflictParamsInvalid, Message: err.Error(),
				Sides: []ConflictSide{}, Remedies: []Remedy{}})
			return resolution
		}
		resolution.Security = &Security{Mounts: mounts, ResolvedSHA256: digest}
	}
	return resolution
}

// Verify is the node precheck: it recompiles security.mounts from the pack
// artifacts (by digest) and requires the same order and resolved_sha256.
// The node does not adjudicate conflicts; it only refuses a document it
// cannot reproduce.
func Verify(security Security, packs map[string]*CompiledPack) ([]NodeRule, error) {
	for index, mount := range security.Mounts {
		pack, ok := packs[mount.SHA256]
		if !ok || pack.Pack.PackID != mount.PackID || pack.Pack.Version != mount.Version ||
			pack.Pack.Engine != mount.Engine || pack.Pack.Layer != mount.Layer ||
			mount.Priority < 0 || mount.Priority > MaxPriority {
			return nil, fmt.Errorf("%w: mount %d does not match its pack", ErrInvalidPack, index)
		}
		if index > 0 && !mountLess(security.Mounts[index-1], mount) {
			return nil, fmt.Errorf("%w: mounts are not in execution order", ErrInvalidPack)
		}
	}
	// The digest covers what the control plane could compute (sealed packs:
	// the mount and its sealed object digest, not the rules); the node runs
	// every rule, sealed packs included (opened with their content key).
	public, err := program(security.Mounts, packs, false)
	if err != nil {
		return nil, err
	}
	digest, err := resolvedDigest(security.Mounts, public)
	if err != nil {
		return nil, err
	}
	if digest != security.ResolvedSHA256 {
		return nil, fmt.Errorf("%w: resolved_sha256 mismatch", ErrInvalidPack)
	}
	for _, mount := range security.Mounts {
		if pack := packs[mount.SHA256]; pack.Sealed && len(pack.Pack.Rules) == 0 {
			return nil, fmt.Errorf("%w: sealed pack %s is not opened", ErrInvalidPack, mount.PackID)
		}
	}
	return program(security.Mounts, packs, true)
}

func sortMounts(mounts []Mount) {
	sort.SliceStable(mounts, func(i, j int) bool { return mountLess(mounts[i], mounts[j]) })
}

func mountLess(left, right Mount) bool {
	if left.Layer.Rank() != right.Layer.Rank() {
		return left.Layer.Rank() < right.Layer.Rank()
	}
	if left.Priority != right.Priority {
		return left.Priority < right.Priority
	}
	return left.PackID < right.PackID
}

// program instantiates ordered mounts into node rules. CC-family rules get
// their global 1-based position as priority (the node model needs strictly
// ordered priorities); every rule gets a node UUID derived from
// (pack_id, rule_id) so counters and bans survive pack upgrades.
func program(mounts []Mount, packs map[string]*CompiledPack, withSealed bool) ([]NodeRule, error) {
	rules := []NodeRule{}
	ccPosition := 0
	for _, mount := range mounts {
		compiled := packs[mount.SHA256]
		if compiled.Sealed && !withSealed {
			// Parameters are still checked against the manifest.
			if _, err := parseParams(compiled.Pack, mount.Params); err != nil {
				return nil, fmt.Errorf("pack %s: %w", mount.PackID, err)
			}
			continue
		}
		instances, err := instantiate(compiled.Pack, mount.Params)
		if err != nil {
			return nil, fmt.Errorf("pack %s: %w", mount.PackID, err)
		}
		for _, instance := range instances {
			node := NodeRule{Layer: mount.Layer, PackID: mount.PackID, Version: mount.Version, RuleID: instance.ID,
				NodeID: NodeRuleID(mount.PackID, instance.ID), Engine: mount.Engine, Priority: mount.Priority, Name: instance.Name}
			switch {
			case instance.WAF != nil:
				waf := *instance.WAF
				waf.RuleID = node.NodeID
				node.WAF = &waf
			case instance.CC != nil:
				ccPosition++
				cc := *instance.CC
				cc.RuleID, cc.Priority = node.NodeID, ccPosition
				node.CC = &cc
			default:
				crs := *instance.CRS
				node.CRS = &crs
			}
			rules = append(rules, node)
		}
	}
	return rules, nil
}

func resolvedDigest(mounts []Mount, rules []NodeRule) (string, error) {
	if mounts == nil {
		mounts = []Mount{}
	}
	encoded, err := json.Marshal(resolvedDocument{Schema: ResolvedSchema, Mounts: mounts, Rules: rules})
	if err != nil {
		return "", fmt.Errorf("%w: encode resolved document", ErrInvalidPack)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

// ruleConflicts finds, across different mounts of one engine: opposite
// terminal WAF actions (allow vs block) on the same condition at the same
// layer and priority (no explicit order between them) -> conflict; a rule
// fully covered by an earlier terminal rule -> shadowed warning.
func ruleConflicts(rules []NodeRule, sources map[string]MountRequest) ([]Conflict, []Conflict) {
	conflicts, warnings := []Conflict{}, []Conflict{}
	for later := range rules {
		current := rules[later]
		if current.WAF == nil {
			continue
		}
		currentMatch, _ := json.Marshal(current.WAF.Match)
		for earlier := 0; earlier < later; earlier++ {
			previous := rules[earlier]
			if previous.WAF == nil || previous.Engine != current.Engine || previous.PackID == current.PackID ||
				previous.WAF.Control != edgeconfig.WAFStop {
				continue
			}
			previousMatch, _ := json.Marshal(previous.WAF.Match)
			sameOrder := previous.Layer == current.Layer && previous.Priority == current.Priority
			opposite := current.WAF.Control == edgeconfig.WAFStop && terminalOpposite(previous.WAF.Action, current.WAF.Action)
			if sameOrder && opposite && string(previousMatch) == string(currentMatch) {
				conflicts = append(conflicts, ruleConflict(ConflictOppositeAction,
					fmt.Sprintf("%s/%s (%s) and %s/%s (%s) act oppositely on the same condition with no explicit order",
						previous.PackID, previous.RuleID, previous.WAF.Action, current.PackID, current.RuleID, current.WAF.Action),
					[]NodeRule{previous, current}, sources))
				break
			}
			if edgeconfig.WAFMatchCovers(previous.WAF.Match, current.WAF.Match) {
				warnings = append(warnings, ruleConflict(WarningShadowed,
					fmt.Sprintf("%s/%s never runs: %s/%s (%s) stops every request it matches first",
						current.PackID, current.RuleID, previous.PackID, previous.RuleID, previous.WAF.Action),
					[]NodeRule{previous, current}, sources))
				break
			}
		}
	}
	return conflicts, warnings
}

func terminalOpposite(left, right edgeconfig.WAFAction) bool {
	return left == edgeconfig.WAFAllow && right == edgeconfig.WAFBlock || left == edgeconfig.WAFBlock && right == edgeconfig.WAFAllow
}

func ruleConflict(code, message string, rules []NodeRule, sources map[string]MountRequest) Conflict {
	conflict := Conflict{Code: code, Message: message, Sides: []ConflictSide{}, Remedies: []Remedy{}}
	for _, rule := range rules {
		request := sources[rule.PackID]
		enabledAt := request.Source.EnabledAt
		ruleID := ""
		if request.Pack.Pack.Exported(rule.RuleID) {
			ruleID = rule.RuleID
		}
		conflict.Sides = append(conflict.Sides, ConflictSide{Layer: rule.Layer, PackID: rule.PackID, Version: rule.Version,
			RuleID: rule.RuleID, EnabledAt: enabledAt})
		conflict.Remedies = append(conflict.Remedies, remedies(request.Source, rule.PackID, ruleID)...)
	}
	return conflict
}

func conflictOf(code, message string, requests []MountRequest, ruleID string) Conflict {
	conflict := Conflict{Code: code, Message: message, Sides: []ConflictSide{}, Remedies: []Remedy{}}
	for _, request := range requests {
		pack := request.Pack.Pack
		conflict.Sides = append(conflict.Sides, ConflictSide{Layer: pack.Layer, PackID: pack.PackID, Version: pack.Version,
			RuleID: ruleID, EnabledAt: request.Source.EnabledAt})
		conflict.Remedies = append(conflict.Remedies, remedies(request.Source, pack.PackID, "")...)
	}
	return conflict
}

func remedies(source Source, packID, ruleID string) []Remedy {
	out := []Remedy{}
	for _, at := range source.DisableAt {
		if ruleID != "" {
			out = append(out, Remedy{Action: "disable_rule", At: at, PackID: packID, RuleID: ruleID})
		}
		out = append(out, Remedy{Action: "disable_pack", At: at, PackID: packID})
	}
	return out
}

func nodeRuleCost(rule NodeRule) (Cost, error) {
	return ruleCost(Rule{ID: rule.RuleID, WAF: rule.WAF, CC: rule.CC, CRS: rule.CRS})
}

// NodeRuleID is the UUIDv5 of "<pack_id>/<rule_id>" in the rule pack
// namespace.
func NodeRuleID(packID, ruleID string) string {
	hash := sha1.New()
	hash.Write(nodeRuleNamespace[:])
	hash.Write([]byte(packID + "/" + ruleID))
	sum := hash.Sum(nil)
	sum[6] = sum[6]&0x0f | 0x50
	sum[8] = sum[8]&0x3f | 0x80
	encoded := hex.EncodeToString(sum[:16])
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32]
}

// nodeRuleNamespace is a fixed random UUID (5d0c0a5e-...); changing it would
// renumber every pack rule on every node.
var nodeRuleNamespace = [16]byte{0x5d, 0x0c, 0x0a, 0x5e, 0x7a, 0x31, 0x4b, 0x6e, 0x9d, 0x2f, 0x41, 0x08, 0xc3, 0x6a, 0x90, 0x17}

func keys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	return out
}

// SecurityOf is the security document of already resolved mounts (params
// canonical, as Resolve wrote them) in execution order with their
// resolved_sha256: what Resolve computes for the same mounts. A published
// document with one mount taken out or put back (a suspended mount) is
// rebuilt with it.
func SecurityOf(mounts []Mount, packs map[string]*CompiledPack) (Security, error) {
	ordered := append([]Mount{}, mounts...)
	sortMounts(ordered)
	for _, mount := range ordered {
		if pack := packs[mount.SHA256]; pack == nil || pack.Pack.PackID != mount.PackID || pack.Pack.Version != mount.Version {
			return Security{}, fmt.Errorf("%w: mount %s does not match its pack", ErrInvalidPack, mount.PackID)
		}
	}
	rules, err := program(ordered, packs, false)
	if err != nil {
		return Security{}, err
	}
	digest, err := resolvedDigest(ordered, rules)
	if err != nil {
		return Security{}, err
	}
	return Security{Mounts: ordered, ResolvedSHA256: digest}, nil
}
