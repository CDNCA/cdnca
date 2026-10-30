// Package rulepack is the cdnca.rule-pack/v1 format and its compiler (ADR
// 0007 §5.1, §5.2, §5.4; ADR 0009 §8.4).
//
// A rule pack is data: its rules reuse the node rule models the edge already
// executes (edgeconfig.WAFRule for waf_v2 / acl, edgeconfig.CCV2Rule for
// cc_v2 / challenge) and the signed rule catalog CRS selection
// (rulecatalog.WAFEngineSet for modsecurity). There is no rule DSL.
//
// The control plane and the edge agent import this one package: the control
// plane compiles the effective mounts of a site once at publish time
// (Resolve -> resolved_sha256), the agent recompiles them in its precheck
// (Verify) and both must arrive at the same digest. Canonical bytes are
// encoding/json over the typed structs (declaration field order, sorted map
// keys), the same rule as rulecatalog.CanonicalCatalog.
package rulepack

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"golang.org/x/mod/semver"
)

const Schema = "cdnca.rule-pack/v1"

type Layer string

const (
	LayerSystem    Layer = "system"
	LayerDeveloper Layer = "developer"
	LayerUser      Layer = "user"
)

// Rank is the execution rank of a layer: user exceptions run before
// developer rules, which run before system rules (ADR 0007 §5.2).
func (layer Layer) Rank() int {
	switch layer {
	case LayerUser:
		return 0
	case LayerDeveloper:
		return 1
	case LayerSystem:
		return 2
	}
	return -1
}

type Engine string

const (
	EngineWAFV2       Engine = "waf_v2"
	EngineCCV2        Engine = "cc_v2"
	EngineACL         Engine = "acl"
	EngineChallenge   Engine = "challenge"
	EngineModSecurity Engine = "modsecurity"
)

// EngineMaxVersion is the newest version of each engine this compiler
// understands. cc_v2 / challenge versions are the CC API versions
// (edgeconfig.CCV2PolicyAPIVersion); the others start at 1.
var EngineMaxVersion = map[Engine]uint32{
	EngineWAFV2: 1, EngineACL: 1, EngineCCV2: 6, EngineChallenge: 6, EngineModSecurity: 1, EngineCRSApp: 1,
}

// Capabilities a pack's content needs on a node beyond its engine version.
const (
	RequiresJA4          = "ja4"
	RequiresIPIntel      = "ip_intel"
	RequiresWAFCRSModule = "waf_crs_module"
	// RequiresWAFMultipart: a multipart_* inspect target (CAPABILITY_NAME_WAF
	// v5, edgeconfig.WAFMultipartAPIVersion).
	RequiresWAFMultipart = "waf_multipart"
)

const (
	MaxPackBytes     = 1 << 20
	maxParams        = 32
	maxExports       = 256
	maxCRSExclusions = 256
	// MaxCRSRuleIDs bounds Pack.CRSRuleIDs (CRS 4 has about 600 scoring rules).
	MaxCRSRuleIDs   = 2048
	DefaultPriority = 500
	MaxPriority     = 1000
)

var (
	// ErrInvalidPack: the pack (or a mount's parameters) is not a valid
	// cdnca.rule-pack/v1 document. Errors wrap it with a reason.
	ErrInvalidPack = errors.New("invalid rule pack")
	// ErrBudgetExceeded: the pack is valid but too expensive (rule count,
	// regex backtracking risk or per-request cost). Wraps ErrInvalidPack.
	ErrBudgetExceeded = fmt.Errorf("%w: budget exceeded", ErrInvalidPack)

	systemPackPattern = regexp.MustCompile(`^system/[a-z0-9][a-z0-9-]{0,63}$`)
	// dev/<market publisher id>/<name>: publisher ids are dotted (io.cdnca.examples).
	devPackPattern   = regexp.MustCompile(`^dev/([a-z0-9]+(?:[.-][a-z0-9]+)*)/[a-z0-9][a-z0-9-]{0,63}$`)
	userPackPattern  = regexp.MustCompile(`^user/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/[a-z0-9][a-z0-9-]{0,63}$`)
	ruleIDPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	crsRuleIDPattern = regexp.MustCompile(`^9[0-9]{5}$`)
	paramNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	spdxPattern      = regexp.MustCompile(`^[A-Za-z0-9.+-]{1,64}$`)
)

// Pack is a cdnca.rule-pack/v1 document.
type Pack struct {
	Schema           string               `json:"schema"`
	PackID           string               `json:"pack_id"`
	Version          string               `json:"version"`
	Layer            Layer                `json:"layer"`
	Engine           Engine               `json:"engine"`
	EngineMinVersion uint32               `json:"engine_min_version"`
	Name             string               `json:"name"`
	Description      string               `json:"description"`
	LicenseSPDX      string               `json:"license_spdx,omitempty"`
	ParamsSchema     map[string]ParamSpec `json:"params_schema"`
	Exports          []string             `json:"exports"`
	Rules            []Rule               `json:"rules"`
	Defaults         Params               `json:"defaults"`
}

// Rule is one pack rule: a pack-local ID (rules run in ID order), a display
// name and exactly the body of the pack's engine. RuleID, Priority, Host and
// Port of the node models are assigned per site by the compiler and must be
// empty in the pack.
type Rule struct {
	ID   string                    `json:"id"`
	Name string                    `json:"name"`
	WAF  *edgeconfig.WAFRule       `json:"waf,omitempty"`
	CC   *edgeconfig.CCV2Rule      `json:"cc,omitempty"`
	CRS  *rulecatalog.WAFEngineSet `json:"crs,omitempty"`
	App  *CRSAppRules              `json:"app,omitempty"`
	// Tuning is a system/crs-tuning entry (crstuning.go); the rule ID is
	// the entry number.
	Tuning *edgeconfig.CRSTuning `json:"tuning,omitempty"`
}

// Exported reports whether ruleID may be switched individually.
func (pack Pack) Exported(ruleID string) bool {
	index := sort.SearchStrings(pack.Exports, ruleID)
	return index < len(pack.Exports) && pack.Exports[index] == ruleID
}

// CompiledPack is a validated pack with its canonical bytes and digest.
type CompiledPack struct {
	Pack      Pack
	Canonical []byte
	// SHA256 is the lower-case hex digest of Canonical: the artifact digest
	// mounts and the node object store refer to.
	SHA256 string
	// RequiredEngineVersion is the lowest engine version that can run the
	// rules; Pack.EngineMinVersion is at least this.
	RequiredEngineVersion uint32
	// Requires lists node capabilities beyond the engine (sorted).
	Requires []string
	// Cost is the cost of the rules with default parameters.
	Cost Cost
	// Sealed marks an encrypted pack (seal.go). Canonical / SHA256 are then
	// those of the sealed document. On the control plane (OpenManifest) Pack
	// has no rules; on the node (Open) it has them. Either way its rules are
	// not part of resolved_sha256 and not in Resolution.Rules.
	Sealed bool
	// ExportNames names the exported rules of a sealed pack (nil otherwise).
	ExportNames map[string]string
	// CRSRuleIDs is a sealed modsecurity pack's CRS rule number list from its
	// manifest (nil otherwise). The seller never supplies it (the
	// pack document has no such field): the license service, which
	// holds the plaintext, computes it (PackCRSRuleIDs) when it seals, and the
	// manifest it seals is covered by the catalog it signs. The control plane
	// checks a site's CRS profile by it; the node checks the opened rules
	// evaluate exactly it (CheckCRSRuleIDs).
	CRSRuleIDs []int
}

// ExportName is the display name of an exported rule ("" if unknown).
func (compiled *CompiledPack) ExportName(ruleID string) string {
	if compiled.Sealed {
		return compiled.ExportNames[ruleID]
	}
	if rule, ok := findRule(compiled.Pack, ruleID); ok {
		return rule.Name
	}
	return ""
}

// Compile decodes an authored pack (any valid JSON spelling), validates it
// and returns its canonical form.
func Compile(content []byte) (*CompiledPack, error) {
	if len(content) == 0 || len(content) > MaxPackBytes || edgeconfig.RejectDuplicateJSONKeys(content) != nil {
		return nil, fmt.Errorf("%w: document is empty, too large or has duplicate keys", ErrInvalidPack)
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	var pack Pack
	if err := decoder.Decode(&pack); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPack, err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return nil, fmt.Errorf("%w: trailing data", ErrInvalidPack)
	}
	return CompilePack(pack)
}

// Load accepts only canonical bytes (a stored or delivered artifact) whose
// digest is wantSHA256.
func Load(content []byte, wantSHA256 string) (*CompiledPack, error) {
	sum := sha256.Sum256(content)
	if hex.EncodeToString(sum[:]) != wantSHA256 {
		return nil, fmt.Errorf("%w: digest mismatch", ErrInvalidPack)
	}
	compiled, err := Compile(content)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(compiled.Canonical, content) {
		return nil, fmt.Errorf("%w: not in canonical form", ErrInvalidPack)
	}
	return compiled, nil
}

// CompilePack validates a decoded pack.
func CompilePack(pack Pack) (*CompiledPack, error) {
	normalized, err := normalizePack(pack)
	if err != nil {
		return nil, err
	}
	required, requires, err := packRequirements(normalized)
	if err != nil {
		return nil, err
	}
	if normalized.EngineMinVersion < required || normalized.EngineMinVersion > EngineMaxVersion[normalized.Engine] {
		return nil, fmt.Errorf("%w: engine_min_version must be %d..%d for these rules", ErrInvalidPack,
			required, EngineMaxVersion[normalized.Engine])
	}
	defaults, err := normalizeParams(normalized, normalized.Defaults, true)
	if err != nil {
		return nil, err
	}
	normalized.Defaults = defaults
	rules, err := instantiate(normalized, defaults)
	if err != nil {
		return nil, err
	}
	cost, err := rulesCost(rules)
	if err != nil {
		return nil, err
	}
	if err := cost.within(packBudget); err != nil {
		return nil, err
	}
	if err := probeParams(normalized); err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(normalized)
	if err != nil || len(canonical) > MaxPackBytes {
		return nil, fmt.Errorf("%w: canonical form is too large", ErrInvalidPack)
	}
	sum := sha256.Sum256(canonical)
	return &CompiledPack{Pack: normalized, Canonical: canonical, SHA256: hex.EncodeToString(sum[:]),
		RequiredEngineVersion: required, Requires: requires, Cost: cost}, nil
}

func normalizePack(pack Pack) (Pack, error) {
	invalid := func(format string, args ...any) (Pack, error) {
		return Pack{}, fmt.Errorf("%w: "+format, append([]any{ErrInvalidPack}, args...)...)
	}
	if pack.Schema != Schema {
		return invalid("schema must be %s", Schema)
	}
	if layer, ok := packIDLayer(pack.PackID); !ok || layer != pack.Layer {
		return invalid("pack_id %q does not name a %s pack", pack.PackID, pack.Layer)
	}
	if len(pack.Version) > 64 || !semver.IsValid("v"+pack.Version) || semver.Canonical("v"+pack.Version) != "v"+pack.Version {
		return invalid("version must be canonical semver")
	}
	if _, ok := EngineMaxVersion[pack.Engine]; !ok {
		return invalid("unknown engine %q", pack.Engine)
	}
	if !validText(pack.Name, 1, 128) || !validText(pack.Description, 0, 1000) ||
		pack.LicenseSPDX != "" && !spdxPattern.MatchString(pack.LicenseSPDX) {
		return invalid("name, description or license_spdx is invalid")
	}
	maxRules := packBudget.Rules
	if pack.Engine == EngineCCV2 || pack.Engine == EngineChallenge {
		maxRules = maxCCRules
	}
	if IsCRSTuningPack(pack.PackID) {
		maxRules = maxCRSTuningEntries
	}
	if len(pack.Rules) < 1 || len(pack.Rules) > maxRules {
		return Pack{}, fmt.Errorf("%w: %d rules (1..%d)", ErrBudgetExceeded, len(pack.Rules), maxRules)
	}
	normalized := pack
	normalized.Rules = make([]Rule, len(pack.Rules))
	seen := make(map[string]bool, len(pack.Rules))
	for index, rule := range pack.Rules {
		if !ruleIDPattern.MatchString(rule.ID) || seen[rule.ID] {
			return invalid("rule id %q is invalid or repeated", rule.ID)
		}
		seen[rule.ID] = true
		body, err := normalizeRule(pack, rule)
		if err != nil {
			return invalid("rule %s: %v", rule.ID, err)
		}
		normalized.Rules[index] = body
	}
	sort.Slice(normalized.Rules, func(i, j int) bool { return normalized.Rules[i].ID < normalized.Rules[j].ID })

	exports := append([]string{}, pack.Exports...)
	sort.Strings(exports)
	if len(exports) > maxExports && !(IsCRSTuningPack(pack.PackID) && len(exports) <= maxCRSTuningEntries) {
		return invalid("too many exports")
	}
	for index, id := range exports {
		valid := seen[id]
		if pack.Engine == EngineModSecurity && !IsCRSTuningPack(pack.PackID) {
			valid = crsRuleIDPattern.MatchString(id)
		}
		if !valid || index > 0 && exports[index-1] == id {
			return invalid("export %q is not a rule of the pack or is repeated", id)
		}
	}
	normalized.Exports = exports
	if IsCRSTuningPack(pack.PackID) {
		if err := checkTuningPack(normalized); err != nil {
			return invalid("%v", err)
		}
	}

	if len(pack.ParamsSchema) > maxParams {
		return invalid("too many params")
	}
	normalized.ParamsSchema = make(map[string]ParamSpec, len(pack.ParamsSchema))
	for name, spec := range pack.ParamsSchema {
		if !paramNamePattern.MatchString(name) || name == ParamExclusions {
			return invalid("param name %q is invalid or reserved", name)
		}
		normalizedSpec, err := normalizeParamSpec(normalized, spec)
		if err != nil {
			return invalid("param %s: %v", name, err)
		}
		normalized.ParamsSchema[name] = normalizedSpec
	}
	if err := uniqueBindTargets(normalized.ParamsSchema); err != nil {
		return invalid("%v", err)
	}
	if pack.Defaults == nil {
		normalized.Defaults = Params{}
	}
	return normalized, nil
}

// validCRSRuleIDs: a modsecurity pack's CRS rule ID list is sorted, distinct
// and bounded, every entry a CRS rule number (9xxxxx).
func validCRSRuleIDs(engine Engine, ids []int) error {
	if engine != EngineModSecurity {
		return errors.New("only modsecurity packs list CRS rule IDs")
	}
	if len(ids) > MaxCRSRuleIDs {
		return fmt.Errorf("more than %d IDs", MaxCRSRuleIDs)
	}
	for index, id := range ids {
		if id < 900000 || id > 999999 || index > 0 && ids[index-1] >= id {
			return fmt.Errorf("%d is not a CRS rule number or the list is not sorted and distinct", id)
		}
	}
	return nil
}

// packIDLayer returns the layer a pack ID's namespace belongs to.
func packIDLayer(packID string) (Layer, bool) {
	switch {
	case systemPackPattern.MatchString(packID):
		return LayerSystem, true
	case devPackPattern.MatchString(packID):
		if _, ok := DeveloperPackPublisher(packID); !ok {
			return "", false
		}
		return LayerDeveloper, true
	case userPackPattern.MatchString(packID):
		return LayerUser, true
	}
	return "", false
}

// DeveloperPackPublisher returns the market publisher id a
// dev/<publisher>/<name> pack belongs to.
func DeveloperPackPublisher(packID string) (string, bool) {
	match := devPackPattern.FindStringSubmatch(packID)
	// rule_packs.pack_id is at most 160 characters (control migration 349).
	if match == nil || len(match[1]) > 96 || len(packID) > 160 {
		return "", false
	}
	return match[1], true
}

// UserPackScope returns the tenant scope ID a user/<scope_id>/<name> pack
// belongs to.
func UserPackScope(packID string) (string, bool) {
	if !userPackPattern.MatchString(packID) {
		return "", false
	}
	return strings.Split(packID, "/")[1], true
}

func normalizeRule(pack Pack, rule Rule) (Rule, error) {
	if !validText(rule.Name, 1, 128) {
		return Rule{}, errors.New("name is invalid")
	}
	out := Rule{ID: rule.ID, Name: rule.Name}
	if rule.Tuning != nil && !IsCRSTuningPack(pack.PackID) {
		return Rule{}, errors.New("only system/crs-tuning rules have a tuning body")
	}
	engine := pack.Engine
	switch engine {
	case EngineWAFV2, EngineACL:
		if rule.WAF == nil || rule.CC != nil || rule.CRS != nil || rule.App != nil {
			return Rule{}, errors.New("needs exactly a waf body")
		}
		waf := *rule.WAF
		if waf.RuleID != "" || waf.Comment != "" || waf.ExpiresAt != "" || waf.Match.Host != "" || waf.Match.Port != 0 {
			return Rule{}, errors.New("rule_id, comment, expires_at, host and port are assigned per site")
		}
		match := waf.Match
		if engine == EngineACL && (match.Method != "" || match.Path != nil || match.Header != nil || match.Inspect != nil) {
			return Rule{}, errors.New("acl rules match only source_cidr, ja4 and ip_intel")
		}
		waf.RuleID = placeholderRuleID
		normalized, err := edgeconfig.NormalizeSecurityRule(waf)
		if err != nil {
			return Rule{}, err
		}
		normalized.RuleID = ""
		out.WAF = &normalized
		if IsIntelMarkPack(pack.PackID) {
			if err := checkIntelMarkRule(out); err != nil {
				return Rule{}, err
			}
		}
	case EngineCCV2, EngineChallenge:
		if rule.CC == nil || rule.WAF != nil || rule.CRS != nil || rule.App != nil {
			return Rule{}, errors.New("needs exactly a cc body")
		}
		cc := copyCCRule(*rule.CC)
		if cc.RuleID != "" || cc.Priority != 0 || cc.Match.Host != "" || cc.Match.Port != 0 {
			return Rule{}, errors.New("rule_id, priority, host and port are assigned per site")
		}
		if engine == EngineChallenge && cc.Action.Kind != edgeconfig.CCV2ActionChallenge {
			return Rule{}, errors.New("challenge rules must use the challenge action")
		}
		if err := validateCCRule(cc); err != nil {
			return Rule{}, err
		}
		out.CC = &cc
	case EngineModSecurity:
		if IsCRSTuningPack(pack.PackID) {
			if rule.Tuning == nil || rule.CRS != nil || rule.WAF != nil || rule.CC != nil || rule.App != nil {
				return Rule{}, errors.New("needs exactly a tuning body")
			}
			tuning := copyTuning(*rule.Tuning)
			if err := validateTuningEntry(rule.ID, &tuning); err != nil {
				return Rule{}, err
			}
			out.Tuning = &tuning
			return out, nil
		}
		if rule.CRS == nil || rule.WAF != nil || rule.CC != nil || rule.App != nil {
			return Rule{}, errors.New("needs exactly a crs body")
		}
		crs := copyCRS(*rule.CRS)
		if err := validateCRS(crs); err != nil {
			return Rule{}, err
		}
		out.CRS = &crs
	case EngineCRSApp:
		app, err := normalizeCRSAppRule(rule)
		if err != nil {
			return Rule{}, err
		}
		out.App = app.App
	}
	return out, nil
}

const placeholderRuleID = "00000000-0000-4000-8000-000000000000"

func validateCCRule(rule edgeconfig.CCV2Rule) error {
	rule.RuleID, rule.Priority = placeholderRuleID, 1
	return edgeconfig.ValidateCCV2Rule(rule)
}

// validateCRS checks a CRS selection with the signed catalog's own rules.
func validateCRS(set rulecatalog.WAFEngineSet) error {
	item := rulecatalog.Item{SystemKey: "waf_set:rule-pack", Kind: rulecatalog.KindWAFRuleSet, Name: "rule pack",
		Revision: 1, Body: rulecatalog.ItemBody{WAFRuleSet: &rulecatalog.WAFRuleSetBody{Engine: &set}}}
	return rulecatalog.ValidateItem(item)
}

func validText(value string, minimum, maximum int) bool {
	return utf8.ValidString(value) && strings.TrimSpace(value) == value &&
		utf8.RuneCountInString(value) >= minimum && utf8.RuneCountInString(value) <= maximum &&
		strings.IndexFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) < 0
}

// packRequirements returns the lowest engine version and the node
// capabilities the rules need.
func packRequirements(pack Pack) (uint32, []string, error) {
	needs := map[string]bool{}
	required := uint32(1)
	switch pack.Engine {
	case EngineCCV2, EngineChallenge:
		policy := edgeconfig.CCV2Policy{Rules: make([]edgeconfig.CCV2Rule, 0, len(pack.Rules))}
		for _, rule := range pack.Rules {
			policy.Rules = append(policy.Rules, *rule.CC)
		}
		required = edgeconfig.CCV2PolicyAPIVersion(policy)
	case EngineModSecurity, EngineCRSApp:
		needs[RequiresWAFCRSModule] = true
	default:
		for _, rule := range pack.Rules {
			if rule.WAF.Match.JA4 != nil {
				needs[RequiresJA4] = true
			}
			if rule.WAF.Match.IPIntel != nil {
				needs[RequiresIPIntel] = true
			}
			if edgeconfig.WAFMatchUsesMultipart(rule.WAF.Match) {
				needs[RequiresWAFMultipart] = true
			}
		}
	}
	requires := make([]string, 0, len(needs))
	for name := range needs {
		requires = append(requires, name)
	}
	sort.Strings(requires)
	return required, requires, nil
}

func copyCCRule(rule edgeconfig.CCV2Rule) edgeconfig.CCV2Rule {
	out := rule
	out.CountBy = cloneSlice(rule.CountBy)
	out.Match.PathContains = cloneSlice(rule.Match.PathContains)
	if rule.Match.Path != nil {
		path := *rule.Match.Path
		out.Match.Path = &path
	}
	if rule.Match.ClientIP != nil {
		out.Match.ClientIP = make([]edgeconfig.CCV2IPMatch, len(rule.Match.ClientIP))
		for index, entry := range rule.Match.ClientIP {
			out.Match.ClientIP[index] = edgeconfig.CCV2IPMatch{Negate: entry.Negate, CIDRs: cloneSlice(entry.CIDRs)}
		}
	}
	if rule.Match.Headers != nil {
		out.Match.Headers = make([]edgeconfig.CCV2HeaderMatch, len(rule.Match.Headers))
		for index, entry := range rule.Match.Headers {
			out.Match.Headers[index] = edgeconfig.CCV2HeaderMatch{Name: entry.Name, Kind: entry.Kind, Values: cloneSlice(entry.Values)}
		}
	}
	if challenge := rule.Action.Challenge; challenge != nil {
		copied := *challenge
		if challenge.PassLimit != nil {
			limit := *challenge.PassLimit
			copied.PassLimit = &limit
		}
		out.Action.Challenge = &copied
	}
	return out
}

func copyCRS(set rulecatalog.WAFEngineSet) rulecatalog.WAFEngineSet {
	out := set
	out.Files, out.IncludeIDs, out.ExcludeIDs = cloneSlice(set.Files), cloneSlice(set.IncludeIDs), cloneSlice(set.ExcludeIDs)
	out.StrongRules = cloneSlice(set.StrongRules)
	out.WeakWeights = cloneSlice(set.WeakWeights)
	return out
}

func copyWAFRule(rule edgeconfig.WAFRule) edgeconfig.WAFRule {
	// NormalizeSecurityRule returns fresh slices and pointers.
	normalized, err := edgeconfig.NormalizeSecurityRule(withRuleID(rule, placeholderRuleID))
	if err != nil {
		panic("rulepack: copy of a normalized rule failed: " + err.Error())
	}
	normalized.RuleID = rule.RuleID
	return normalized
}

func withRuleID(rule edgeconfig.WAFRule, id string) edgeconfig.WAFRule {
	rule.RuleID = id
	return rule
}

func cloneSlice[T any](values []T) []T {
	if values == nil {
		return nil
	}
	return append(make([]T, 0, len(values)), values...)
}
