package edgeconfig

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ManagedWAF runs one OWASP CRS profile through libmodsecurity
// (ModSecurity-nginx) for one site (ADR 0007 §5.3, ADR 0009 §9 Q3 方案 a).
//
//   - Profile names a system/crs-<level> rule pack (cdnca.rule-pack/v1,
//     libs/rulepack): its rule sets with their action, paranoia level and
//     anomaly threshold are fixed by the pack, loaded node-wide (CRSProfile);
//     the site only selects it.
//   - Exclusions: CRS rule IDs (from the profile's exports) not evaluated for
//     the site. They take effect per request: the site's gate sets the
//     ModSecurity transaction ID from a Lua variable that lists them and the
//     node-wide configuration removes each listed rule with
//     ctl:ruleRemoveById (RenderWAFEngineGate, renderManagedWAFMain).
//   - AllowCIDRs: client networks the site's ACL/WAF policies allow
//     unconditionally; the engine is off for them so an allow rule keeps
//     precedence over the managed sets.
//   - RequestBody*: bytes buffered for inspection (with and without file
//     parts) and what happens past the limit (reject = 413, partial = inspect
//     the first bytes only); ArgumentsLimit (more arguments -> 400),
//     JSONDepthLimit, PCREMatchLimit.
//   - InspectionLimitAction: what happens when an inspection limit is hit
//     (CRS TX:MSC_*, e.g. the PCRE match limit; more than 100 request headers
//     for header conditions): "log" (default, "" = log) records it and the
//     request goes on (header conditions do not match), "block" returns 403.
type ManagedWAF struct {
	PolicyID                string        `json:"policy_id"`
	PolicyVersion           int64         `json:"policy_version"`
	RequestBodyLimit        int           `json:"request_body_limit"`
	RequestBodyNoFilesLimit int           `json:"request_body_no_files_limit"`
	RequestBodyLimitAction  string        `json:"request_body_limit_action"`
	ArgumentsLimit          int           `json:"arguments_limit"`
	JSONDepthLimit          int           `json:"json_depth_limit"`
	PCREMatchLimit          int           `json:"pcre_match_limit"`
	InspectionLimitAction   string        `json:"inspection_limit_action,omitempty"`
	Profile                 CRSProfileRef `json:"profile"`
	Exclusions              []int         `json:"exclusions,omitempty"`
	AllowCIDRs              []string      `json:"allow_cidrs,omitempty"`
	// Apps are the CRS application exclusion packs (system/app-<key>, the
	// OWASP CRS official rule exclusion plugins) the site selected as its
	// application types, sorted by pack ID. They apply per request like
	// Exclusions: the node loads every app pack of the release node-wide and
	// gates each to the sites that selected it (renderManagedWAFMain).
	Apps []CRSAppRef `json:"apps,omitempty"`
}

// CRSAppRef names one version of an application exclusion pack by digest.
type CRSAppRef struct {
	PackID  string `json:"pack_id"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

// CRSApp is an application exclusion pack as the compiler uses it
// (rulepack.CRSAppOf): the plugin's ModSecurity text of its config and
// before stages (checked by the pack compiler to only narrow CRS), its rule
// ID range and the SecMarker names it defines.
type CRSApp struct {
	Ref     CRSAppRef `json:"ref"`
	Key     string    `json:"key"`
	Name    string    `json:"name"`
	FirstID int       `json:"first_id"`
	LastID  int       `json:"last_id"`
	Config  string    `json:"config"`
	Before  string    `json:"before"`
	Markers []string  `json:"markers"`
}

// MaxManagedWAFApps bounds a site's application types.
const MaxManagedWAFApps = 16

var crsAppPackID = regexp.MustCompile(`^system/app-([a-z0-9][a-z0-9-]{0,47})$`)

func validCRSAppRef(ref CRSAppRef) bool {
	return crsAppPackID.MatchString(ref.PackID) && crsProfileVersion.MatchString(ref.Version) && crsProfileSHA256.MatchString(ref.SHA256)
}

// crsAppKey is the key of system/app-<key>.
func crsAppKey(packID string) string {
	match := crsAppPackID.FindStringSubmatch(packID)
	if match == nil {
		return ""
	}
	return match[1]
}

// CRSProfileRef names one version of a CRS profile pack by its digest (the
// sha256 of the pack's canonical bytes, as the catalog entry and the node
// object store name it).
type CRSProfileRef struct {
	PackID  string `json:"pack_id"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

// CRSProfile is a CRS profile pack as the compiler uses it
// (rulepack.CRSProfileOf): its rule sets and the scoring rule IDs a site may
// exclude (Exports, sorted).
type CRSProfile struct {
	Ref     CRSProfileRef   `json:"ref"`
	Name    string          `json:"name"`
	Sets    []ManagedWAFSet `json:"sets"`
	Exports []int           `json:"exports"`
}

// ManagedWAFSet is one rule set of a profile. Each owns a disjoint group of
// CRS scoring rules (Files prefixes + IncludeIDs - ExcludeIDs) and is scored
// on its own: the request is denied (block) or only recorded (log) when the
// summed anomaly score of the set's rules reaches Threshold. Rules above the
// set's Paranoia level are removed.
//
// Two-level scoring (StrongParanoia > 0): only the rules at or below
// StrongParanoia score toward Threshold; the rules above it (CRS's higher
// paranoia heuristics) score a weak sum, and the request is blocked when
// strong + weak reaches WeakThreshold. A higher tier keeps the lower tier's
// strong rules and threshold, so its decisions contain the lower tier's.
//
// Adaptive WAF fields of a two-level set (rulecatalog.WAFEngineSet, ADR 0011
// RI-02; a one-level set has none): GreyAction allow | challenge (grey zone,
// browser-like request without a challenge cookie), Adaptive (automatic
// exclusions and tightening of the weak rules allowed), StrongRules (rules
// above StrongParanoia scoring strong anyway), WeakWeights (waf-gap6 S1:
// learned offline, a weak rule's score in the weak sum instead of its
// severity, 0 = it only logs; below the severity only, so a weight never
// makes a tier stricter on its own).
type ManagedWAFSet struct {
	Key            string             `json:"key"`
	Name           string             `json:"name"`
	Action         string             `json:"action"`
	Paranoia       int                `json:"paranoia"`
	Threshold      int                `json:"threshold"`
	StrongParanoia int                `json:"strong_paranoia,omitempty"`
	WeakThreshold  int                `json:"weak_threshold,omitempty"`
	Files          []string           `json:"files"`
	IncludeIDs     []int              `json:"include_ids,omitempty"`
	ExcludeIDs     []int              `json:"exclude_ids,omitempty"`
	GreyAction     string             `json:"grey_action,omitempty"`
	Adaptive       bool               `json:"adaptive,omitempty"`
	StrongRules    []int              `json:"strong_rules,omitempty"`
	WeakWeights    []ManagedWAFWeight `json:"weak_weights,omitempty"`
}

// ManagedWAFWeight is one learned weak rule weight (ascending by Rule).
type ManagedWAFWeight struct {
	Rule   int `json:"rule"`
	Weight int `json:"weight"`
}

// managedWAFSeverityScore is CRS's anomaly score of a severity
// (crs-setup: critical 5, error 4, warning 3, notice 2).
var managedWAFSeverityScore = map[string]int{"critical": 5, "error": 4, "warning": 3, "notice": 2}

// weakWeight is a weak rule's learned weight, or -1 (its severity).
func (set ManagedWAFSet) weakWeight(id int) int {
	index := sort.Search(len(set.WeakWeights), func(i int) bool { return set.WeakWeights[i].Rule >= id })
	if index < len(set.WeakWeights) && set.WeakWeights[index].Rule == id {
		return set.WeakWeights[index].Weight
	}
	return -1
}

// ManagedWAFGreyAllow / ManagedWAFGreyChallenge are the grey zone actions.
const (
	ManagedWAFGreyAllow     = "allow"
	ManagedWAFGreyChallenge = "challenge"
	// DynamicWAFChallengeStatus is the status the node rules deny a grey
	// zone request with for the skeleton's error_page to serve the WAF
	// challenge (ADR 0011 PoC-3: non-standard, no origin or module uses it).
	DynamicWAFChallengeStatus = 599
	maxManagedWAFStrongRules  = 256
)

// twoLevel reports whether the set scores in two levels.
func (set ManagedWAFSet) twoLevel() bool { return set.StrongParanoia > 0 }

// weakRule reports whether rule scores toward the set's weak sum: a
// two-level set's rule above StrongParanoia that is not one of StrongRules.
func (set ManagedWAFSet) weakRule(rule CRSRule) bool {
	if !set.twoLevel() || rule.Paranoia <= set.StrongParanoia {
		return false
	}
	index := sort.SearchInts(set.StrongRules, rule.ID)
	return index == len(set.StrongRules) || set.StrongRules[index] != rule.ID
}

const (
	ManagedWAFActionBlock = "block"
	ManagedWAFActionLog   = "log"
	// InspectionLimitAction values.
	ManagedWAFInspectionLog   = "log"
	ManagedWAFInspectionBlock = "block"
	managedWAFMaxSets         = 32
	// MaxManagedWAFExclusions bounds a site's excluded rules (and a
	// profile's exports).
	MaxManagedWAFExclusions = 256
	managedWAFMaxCIDRs      = 256
	managedWAFBodyMax       = 128 << 20
	// managed WAF rule IDs live in the ModSecurity local range (1-99999):
	// node-wide evaluation 10000+ (set evaluation 10100+, request-time
	// exclusion hooks 11000-11999), per-site configuration 20000+.
	managedWAFEvalID      = 10000
	managedWAFExclusionID = 11000
	managedWAFMaxHooks    = 1000
	managedWAFAppID       = 12000
	managedWAFSiteID      = 20000
)

var (
	managedWAFSetKey      = regexp.MustCompile(`^waf_set:[A-Za-z0-9._-]{1,64}$`)
	managedWAFFile        = regexp.MustCompile(`^REQUEST-9[0-9]{2}$`)
	managedWAFSetName     = regexp.MustCompile(`^[^\x00-\x1f'"\\%]{1,128}$`)
	managedWAFTXName      = regexp.MustCompile(`[^a-z0-9]+`)
	managedWAFBodyMode    = []string{"reject", "partial"}
	crsProfilePackID      = regexp.MustCompile(`^system/crs-[a-z0-9][a-z0-9-]{0,59}$`)
	crsProfileVersion     = regexp.MustCompile(`^[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}$`)
	crsProfileSHA256      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	crsProfileDisplayName = regexp.MustCompile(`^[^\x00-\x1f]{1,128}$`)
)

// resolvedManagedSet is a validated set with its concrete scoring rules.
type resolvedManagedSet struct {
	ManagedWAFSet
	Rules []CRSRule
}

func managedSetMembership(set ManagedWAFSet) string {
	return strings.Join(set.Files, ",") + "|" + intsKey(set.IncludeIDs) + "|" + intsKey(set.ExcludeIDs)
}

// weightsKey is a two-level set's split: its reweighted rules and learned
// weights (one sum and one score per rule and set key on a node).
func weightsKey(set ManagedWAFSet) string {
	parts := make([]string, len(set.WeakWeights))
	for index, weight := range set.WeakWeights {
		parts[index] = strconv.Itoa(weight.Rule) + ":" + strconv.Itoa(weight.Weight)
	}
	return intsKey(set.StrongRules) + "|" + strings.Join(parts, ",")
}

func intsKey(values []int) string {
	parts := make([]string, len(values))
	for index, value := range values {
		parts[index] = strconv.Itoa(value)
	}
	return strings.Join(parts, ",")
}

func sortedUniqueInts(values []int) ([]int, bool) {
	result := append([]int(nil), values...)
	sort.Ints(result)
	for index := 1; index < len(result); index++ {
		if result[index] == result[index-1] {
			return nil, false
		}
	}
	return result, true
}

func validCRSRuleID(id int) bool { return id >= 900000 && id <= 999999 }

// resolveManagedSet checks a set against a CRS manifest and returns its
// concrete scoring rules.
func resolveManagedSet(manifest *CRSManifest, set ManagedWAFSet) (resolvedManagedSet, error) {
	if !managedWAFSetKey.MatchString(set.Key) || !managedWAFSetName.MatchString(set.Name) ||
		set.Action != ManagedWAFActionBlock && set.Action != ManagedWAFActionLog ||
		set.Paranoia < 1 || set.Paranoia > 4 || set.Threshold < 1 || set.Threshold > 1000 ||
		!(set.StrongParanoia == 0 && set.WeakThreshold == 0 || set.StrongParanoia >= 1 && set.StrongParanoia < set.Paranoia &&
			set.WeakThreshold > set.Threshold && set.WeakThreshold <= 1000) ||
		len(set.Files)+len(set.IncludeIDs) == 0 || len(set.Files) > 16 || len(set.IncludeIDs) > 256 || len(set.ExcludeIDs) > 256 ||
		!validManagedAdaptive(set) {
		return resolvedManagedSet{}, ErrInvalidConfig
	}
	files := append([]string{}, set.Files...)
	sort.Strings(files)
	for position, file := range files {
		if !managedWAFFile.MatchString(file) || position > 0 && files[position-1] == file {
			return resolvedManagedSet{}, ErrInvalidConfig
		}
	}
	include, okInclude := sortedUniqueInts(set.IncludeIDs)
	exclude, okExclude := sortedUniqueInts(set.ExcludeIDs)
	if !okInclude || !okExclude {
		return resolvedManagedSet{}, ErrInvalidConfig
	}
	members := map[int]CRSRule{}
	for _, rule := range manifest.Rules {
		for _, file := range files {
			if strings.HasPrefix(rule.File, file+"-") {
				members[rule.ID] = rule
			}
		}
	}
	for _, id := range include {
		rule, known := manifest.Rule(id)
		if !known {
			return resolvedManagedSet{}, ErrInvalidConfig
		}
		members[id] = rule
	}
	for _, id := range exclude {
		if _, member := members[id]; !member {
			return resolvedManagedSet{}, ErrInvalidConfig
		}
		delete(members, id)
	}
	if len(members) == 0 {
		return resolvedManagedSet{}, ErrInvalidConfig
	}
	// a reweighted rule is a member the set would otherwise score weak
	for _, id := range set.StrongRules {
		rule, member := members[id]
		if !member || rule.Paranoia <= set.StrongParanoia || rule.Paranoia > set.Paranoia {
			return resolvedManagedSet{}, ErrInvalidConfig
		}
	}
	// a learned weight is a weak member's, below its severity (any paranoia
	// above the split: the two-level tiers of a key share one weight list, a
	// rule above this set's paranoia never runs here)
	for _, weight := range set.WeakWeights {
		rule, member := members[weight.Rule]
		if !member || !set.weakRule(rule) ||
			weight.Weight < 0 || weight.Weight >= managedWAFSeverityScore[rule.Severity] {
			return resolvedManagedSet{}, ErrInvalidConfig
		}
	}
	rules := make([]CRSRule, 0, len(members))
	for _, rule := range members {
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	if len(include) == 0 {
		include = nil
	}
	if len(exclude) == 0 {
		exclude = nil
	}
	set.Files, set.IncludeIDs, set.ExcludeIDs = files, include, exclude
	return resolvedManagedSet{ManagedWAFSet: set, Rules: rules}, nil
}

// validManagedAdaptive: the adaptive fields only on a two-level set, which
// must have a grey action; StrongRules ascending, distinct, bounded.
func validManagedAdaptive(set ManagedWAFSet) bool {
	if !set.twoLevel() {
		return set.GreyAction == "" && !set.Adaptive && set.StrongRules == nil && set.WeakWeights == nil
	}
	if set.GreyAction != ManagedWAFGreyAllow && set.GreyAction != ManagedWAFGreyChallenge || len(set.StrongRules) > maxManagedWAFStrongRules ||
		len(set.WeakWeights) > maxManagedWAFStrongRules {
		return false
	}
	for index, weight := range set.WeakWeights {
		if !validCRSRuleID(weight.Rule) || index > 0 && set.WeakWeights[index-1].Rule >= weight.Rule {
			return false
		}
	}
	for index, id := range set.StrongRules {
		if !validCRSRuleID(id) || index > 0 && set.StrongRules[index-1] >= id {
			return false
		}
	}
	return true
}

func validCRSProfileRef(ref CRSProfileRef) bool {
	return crsProfilePackID.MatchString(ref.PackID) && crsProfileVersion.MatchString(ref.Version) &&
		crsProfileSHA256.MatchString(ref.SHA256)
}

// resolvedCRSProfile is a profile checked against a CRS manifest.
type resolvedCRSProfile struct {
	CRSProfile
	sets []resolvedManagedSet
}

// resolveCRSProfile checks a profile against a CRS manifest: valid disjoint
// sets, and exports that are exactly scoring rules the profile evaluates (a
// set member at or below the set's paranoia level).
func resolveCRSProfile(manifest *CRSManifest, profile CRSProfile) (resolvedCRSProfile, error) {
	if !validCRSProfileRef(profile.Ref) || !crsProfileDisplayName.MatchString(profile.Name) ||
		len(profile.Sets) == 0 || len(profile.Sets) > managedWAFMaxSets || len(profile.Exports) > MaxManagedWAFExclusions {
		return resolvedCRSProfile{}, ErrInvalidConfig
	}
	result := resolvedCRSProfile{CRSProfile: CRSProfile{Ref: profile.Ref, Name: profile.Name}}
	owner := map[int]resolvedManagedSet{}
	keys := map[string]bool{}
	for _, set := range profile.Sets {
		resolved, err := resolveManagedSet(manifest, set)
		if err != nil || keys[set.Key] {
			return resolvedCRSProfile{}, ErrInvalidConfig
		}
		keys[set.Key] = true
		for _, rule := range resolved.Rules {
			if _, taken := owner[rule.ID]; taken {
				return resolvedCRSProfile{}, ErrInvalidConfig // a CRS rule may score for one set only
			}
			owner[rule.ID] = resolved
		}
		result.sets = append(result.sets, resolved)
	}
	sort.Slice(result.sets, func(i, j int) bool { return result.sets[i].Key < result.sets[j].Key })
	result.Sets = make([]ManagedWAFSet, len(result.sets))
	for index, set := range result.sets {
		result.Sets[index] = set.ManagedWAFSet
	}
	exports, ok := sortedUniqueInts(profile.Exports)
	if !ok {
		return resolvedCRSProfile{}, ErrInvalidConfig
	}
	for _, id := range exports {
		set, member := owner[id]
		rule, _ := manifest.Rule(id)
		if !member || rule.Paranoia > set.Paranoia {
			return resolvedCRSProfile{}, ErrInvalidConfig
		}
	}
	result.Exports = exports
	return result, nil
}

// exported reports whether the profile lets a site exclude rule id.
func (profile resolvedCRSProfile) exported(id int) bool {
	index := sort.SearchInts(profile.Exports, id)
	return index < len(profile.Exports) && profile.Exports[index] == id
}

// ResolveCRSProfile checks a profile against a CRS rule text (the control
// plane does it when it lists or selects a profile) and returns it
// normalized (sets and exports sorted).
func ResolveCRSProfile(text *CRSRuleText, profile CRSProfile) (CRSProfile, error) {
	manifest, err := DeriveCRSManifest(text)
	if err != nil {
		return CRSProfile{}, err
	}
	resolved, err := resolveCRSProfile(manifest, profile)
	if err != nil {
		return CRSProfile{}, err
	}
	return resolved.CRSProfile, nil
}

// normalizeManagedWAF checks a site's managed WAF on its own (ranges, the
// profile reference, exclusion syntax). Whether the profile exists, matches
// the CRS rule text and exports the exclusions is a release-level check
// (resolveManagedWAFRelease).
func normalizeManagedWAF(value *ManagedWAF) (*ManagedWAF, error) {
	if value == nil {
		return nil, nil
	}
	result := *value
	if !uuidPattern.MatchString(result.PolicyID) || result.PolicyVersion < 1 || result.PolicyVersion > 1<<53-1 ||
		result.RequestBodyLimit < 1024 || result.RequestBodyLimit > managedWAFBodyMax ||
		result.RequestBodyNoFilesLimit < 1024 || result.RequestBodyNoFilesLimit > result.RequestBodyLimit ||
		!containsString(managedWAFBodyMode, result.RequestBodyLimitAction) ||
		result.ArgumentsLimit < 10 || result.ArgumentsLimit > 100000 || result.JSONDepthLimit < 4 || result.JSONDepthLimit > 10000 ||
		result.PCREMatchLimit < 1000 || result.PCREMatchLimit > 10000000 ||
		!validCRSProfileRef(result.Profile) ||
		len(result.Exclusions) > MaxManagedWAFExclusions || len(result.AllowCIDRs) > managedWAFMaxCIDRs {
		return nil, ErrInvalidConfig
	}
	switch result.InspectionLimitAction {
	case "":
		result.InspectionLimitAction = ManagedWAFInspectionLog
	case ManagedWAFInspectionLog, ManagedWAFInspectionBlock:
	default:
		return nil, ErrInvalidConfig
	}
	exclusions, ok := sortedUniqueInts(value.Exclusions)
	if !ok {
		return nil, ErrInvalidConfig
	}
	for _, id := range exclusions {
		if !validCRSRuleID(id) {
			return nil, ErrInvalidConfig
		}
	}
	if len(exclusions) == 0 {
		exclusions = nil
	}
	result.Exclusions = exclusions
	cidrs := make([]string, 0, len(value.AllowCIDRs))
	for _, raw := range value.AllowCIDRs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || prefix.Masked() != prefix {
			return nil, ErrInvalidConfig
		}
		cidrs = append(cidrs, prefix.String())
	}
	sort.Strings(cidrs)
	if len(cidrs) == 0 {
		cidrs = nil
	}
	result.AllowCIDRs = cidrs
	if len(value.Apps) > MaxManagedWAFApps {
		return nil, ErrInvalidConfig
	}
	apps := append([]CRSAppRef(nil), value.Apps...)
	for index, ref := range apps {
		if !validCRSAppRef(ref) || index > 0 && apps[index-1].PackID >= ref.PackID {
			return nil, ErrInvalidConfig
		}
	}
	if len(apps) == 0 {
		apps = nil
	}
	result.Apps = apps
	return &result, nil
}

// managedWAFRelease is the managed WAF of one release, checked as a whole:
// the CRS manifest of exactly the rule text the release loads, and every
// site's profile resolved against it.
type managedWAFRelease struct {
	manifest *CRSManifest
	text     *CRSRuleText
	profiles map[string]resolvedCRSProfile // by sha256
	apps     []CRSApp                      // the application exclusion packs the sites select, by key
	sites    []Site                        // the sites with a managed WAF, by ID
}

// resolveManagedWAFRelease checks the managed WAF of sites against a CRS
// rule text and the profiles they select:
//   - every site's profile is one of profiles (same digest, pack and
//     version) and exports each of the site's exclusions;
//   - one membership per set key and one set per CRS rule across the
//     release's profiles (they are scored node-wide);
//   - the rule text is restricted to what the release loads: the base files,
//     the rule files of the sets' rules, the data files those read, LICENSE
//     and NOTICE. With exact, the text must be exactly that (a node checks
//     the files a signed release carries); otherwise extra files are
//     dropped (the control plane passes the whole catalog package).
//
// nil without any managed WAF.
func resolveManagedWAFRelease(sites []Site, text *CRSRuleText, profiles []CRSProfile, exact bool, apps ...CRSApp) (*managedWAFRelease, error) {
	var managed []Site
	for _, site := range sites {
		if site.ManagedWAF != nil {
			managed = append(managed, site)
		}
	}
	if len(managed) == 0 {
		return nil, nil
	}
	full, err := DeriveCRSManifest(text)
	if err != nil {
		return nil, ErrInvalidConfig
	}
	available := make(map[string]CRSProfile, len(profiles))
	for _, profile := range profiles {
		if _, duplicate := available[profile.Ref.SHA256]; duplicate {
			return nil, ErrInvalidConfig
		}
		available[profile.Ref.SHA256] = profile
	}
	used := map[string]resolvedCRSProfile{}
	for _, site := range managed {
		ref := site.ManagedWAF.Profile
		profile, ok := available[ref.SHA256]
		if !ok || profile.Ref != ref {
			return nil, ErrInvalidConfig
		}
		resolved, done := used[ref.SHA256]
		if !done {
			if resolved, err = resolveCRSProfile(full, profile); err != nil {
				return nil, ErrInvalidConfig
			}
			used[ref.SHA256] = resolved
		}
		for _, id := range site.ManagedWAF.Exclusions {
			if !resolved.exported(id) {
				return nil, ErrInvalidConfig
			}
		}
	}
	membership, owner := map[string]string{}, map[int]string{}
	files := map[string]bool{CRSLicenseFile: true, CRSNoticeFile: true}
	for _, name := range crsBaseFiles {
		files[name] = true
	}
	// The node scores each rule into one sum per set key: every two-level
	// set of a key splits at the same level, and no one-level set of that
	// key evaluates a rule above it (it would land in a weak sum that tier
	// does not read).
	split, oneLevel, reweighted := map[string]int{}, map[string]int{}, map[string]string{}
	for _, profile := range used {
		for _, set := range profile.sets {
			if set.twoLevel() {
				if previous, seen := split[set.Key]; seen && (previous != set.StrongParanoia || reweighted[set.Key] != weightsKey(set.ManagedWAFSet)) {
					return nil, ErrInvalidConfig
				}
				split[set.Key], reweighted[set.Key] = set.StrongParanoia, weightsKey(set.ManagedWAFSet)
			} else {
				oneLevel[set.Key] = max(oneLevel[set.Key], set.Paranoia)
			}
		}
	}
	for key, level := range split {
		if oneLevel[key] > level {
			return nil, ErrInvalidConfig
		}
	}
	for _, profile := range used {
		for _, set := range profile.sets {
			if previous, seen := membership[set.Key]; seen && previous != managedSetMembership(set.ManagedWAFSet) {
				return nil, ErrInvalidConfig // one CRS rule package per release
			}
			membership[set.Key] = managedSetMembership(set.ManagedWAFSet)
			for _, rule := range set.Rules {
				if previous, taken := owner[rule.ID]; taken && previous != set.Key {
					return nil, ErrInvalidConfig
				}
				owner[rule.ID] = set.Key
				files[rule.File] = true
			}
		}
	}
	for _, file := range full.Files {
		if files[file.Name] {
			for _, data := range file.Uses {
				files[data] = true
			}
		}
	}
	if exact && len(files) != len(text.Files) {
		return nil, ErrInvalidConfig
	}
	restricted := &CRSRuleText{Version: full.Version, Files: make(map[string][]byte, len(files))}
	for name := range files {
		content, ok := text.Files[name]
		if !ok {
			return nil, ErrInvalidConfig
		}
		restricted.Files[name] = append([]byte(nil), content...)
	}
	// The release's own manifest: the same rules a node derives from the
	// files it receives, so the control plane and the node render alike.
	manifest, err := DeriveCRSManifest(restricted)
	if err != nil {
		return nil, ErrInvalidConfig
	}
	release := &managedWAFRelease{manifest: manifest, text: restricted, profiles: map[string]resolvedCRSProfile{}}
	for digest, profile := range used {
		again, err := resolveCRSProfile(manifest, profile.CRSProfile)
		if err != nil {
			return nil, ErrInvalidConfig
		}
		release.profiles[digest] = again
	}
	if release.apps, err = resolveCRSApps(managed, apps); err != nil {
		return nil, err
	}
	sort.Slice(managed, func(i, j int) bool { return managed[i].ID < managed[j].ID })
	for index, site := range managed {
		if index > 0 && managed[index-1].ID == site.ID {
			continue
		}
		release.sites = append(release.sites, site)
	}
	return release, nil
}

// resolveCRSApps checks the sites' application types against the app packs
// the release carries: every selected ref is one of apps (same digest, pack
// and version), app keys and markers are unique across the release and no
// marker uses the node's CDNCA- namespace. It returns the selected apps by
// key.
func resolveCRSApps(sites []Site, apps []CRSApp) ([]CRSApp, error) {
	available := make(map[string]CRSApp, len(apps))
	for _, app := range apps {
		if _, duplicate := available[app.Ref.SHA256]; duplicate || !validCRSAppRef(app.Ref) || crsAppKey(app.Ref.PackID) != app.Key {
			return nil, ErrInvalidConfig
		}
		available[app.Ref.SHA256] = app
	}
	used := map[string]CRSApp{}
	for _, site := range sites {
		for _, ref := range site.ManagedWAF.Apps {
			app, ok := available[ref.SHA256]
			if !ok || app.Ref != ref {
				return nil, ErrInvalidConfig
			}
			if previous, seen := used[app.Key]; seen && previous.Ref != ref {
				return nil, ErrInvalidConfig // one version of an application per release
			}
			used[app.Key] = app
		}
	}
	result := make([]CRSApp, 0, len(used))
	markers := map[string]bool{}
	for _, app := range used {
		for _, marker := range app.Markers {
			if markers[marker] || strings.HasPrefix(marker, "CDNCA") || strings.HasPrefix(marker, "CDNCA") {
				return nil, ErrInvalidConfig
			}
			markers[marker] = true
		}
		result = append(result, app)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Key < result[j].Key })
	return result, nil
}

// fileNames is the release's CRS files, sorted.
func (release *managedWAFRelease) fileNames() []string {
	names := make([]string, 0, len(release.text.Files))
	for name := range release.text.Files {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// setsOf is every set of the profiles by key (one membership per key; the
// scoring split is the set's own: a key's tiers may differ only in mode,
// paranoia and thresholds, and a rule's level is the same in all of them as
// long as StrongParanoia agrees, which resolveManagedWAFRelease checks).
func setsOf(profiles map[string]resolvedCRSProfile) map[string]ManagedWAFSet {
	sets := map[string]ManagedWAFSet{}
	for _, profile := range profiles {
		for _, set := range profile.sets {
			if current, seen := sets[set.Key]; !seen || set.twoLevel() && !current.twoLevel() {
				sets[set.Key] = set.ManagedWAFSet
			}
		}
	}
	return sets
}

// managedSetTX is the ModSecurity TX variable suffix of a set key.
func managedSetTX(key string) string {
	return managedWAFTXName.ReplaceAllString(strings.ToLower(strings.TrimPrefix(key, "waf_set:")), "_")
}

func managedWAFSitePath(siteID string) string { return "security/" + siteID + "/modsecurity.conf" }

const managedWAFMainPath = "security/modsecurity/main.conf"

// renderManagedWAFMain is the node-wide ModSecurity configuration loaded once
// at http level: engine settings, the request-time exclusion hooks of every
// rule the release's profiles export, CRS initialisation, the rule files the
// profiles' sets use, per-set score accounting and evaluation. Per-site
// behaviour is set by the server-level file (renderManagedWAFSite), whose
// rules run before these, and by the site gate's transaction ID
// (RenderWAFEngineGate).
func renderManagedWAFMain(release *managedWAFRelease, stateRoot string) ([]byte, error) {
	sets := map[string]resolvedManagedSet{}
	exports := map[int]bool{}
	for _, profile := range release.profiles {
		for _, set := range profile.sets {
			sets[set.Key] = set
		}
		for _, id := range profile.Exports {
			exports[id] = true
		}
	}
	if len(exports) > managedWAFMaxHooks {
		return nil, ErrInvalidConfig
	}
	keys := make([]string, 0, len(sets))
	files := map[string]bool{}
	owner := map[int]string{}
	for key, set := range sets {
		keys = append(keys, key)
		for _, rule := range set.Rules {
			files[rule.File] = true
			owner[rule.ID] = key
		}
	}
	sort.Strings(keys)
	var output strings.Builder
	output.WriteString("# Generated by edgeconfig: OWASP CRS " + release.manifest.Version + " on libmodsecurity.\n")
	output.WriteString("SecRuleEngine On\nSecRequestBodyAccess On\nSecResponseBodyAccess Off\n")
	output.WriteString("SecArgumentSeparator &\nSecCookieFormat 0\n")
	// SecUnicodeMapFile (%uXXXX best-fit folding for t:urlDecodeUni) ships
	// with the engine extension; the node gate sets it (RenderWAFEngineGate).
	output.WriteString("SecStatusEngine Off\nSecAuditEngine RelevantOnly\nSecAuditLogRelevantStatus \"^(?:5|4(?!04))\"\n")
	output.WriteString("SecAuditLogParts ABHZ\nSecAuditLogType Serial\nSecAuditLogFormat JSON\n")
	fmt.Fprintf(&output, "SecAuditLog %s/shared/modsecurity-audit.log\n", stateRoot)
	output.WriteString("SecDefaultAction \"phase:1,log,auditlog,pass\"\nSecDefaultAction \"phase:2,log,auditlog,pass\"\n")
	fmt.Fprintf(&output, "SecAction \"id:900990,phase:1,pass,t:none,nolog,setvar:tx.crs_setup_version=%s\"\n", release.manifest.SetupVersion())
	renderManagedWAFApps(&output, release.apps)
	// Request-body parsing and parser hardening (libmodsecurity
	// modsecurity.conf-recommended 200000-200007): XML and JSON bodies are
	// parsed so CRS inspects their values; a body that cannot be parsed, an
	// argument flood, a malformed multipart body or an engine error is
	// rejected so a payload cannot hide behind the parser.
	fmt.Fprintf(&output, "SecRule REQUEST_HEADERS:Content-Type \"@rx ^(?:application(?:/soap\\+|/)|text/)xml\" \"id:%d,phase:1,pass,nolog,t:none,t:lowercase,ctl:requestBodyProcessor=XML\"\n", managedWAFEvalID)
	fmt.Fprintf(&output, "SecRule REQUEST_HEADERS:Content-Type \"@rx ^application/(?:[a-z0-9.+-]+\\+)?json\" \"id:%d,phase:1,pass,nolog,t:none,t:lowercase,ctl:requestBodyProcessor=JSON\"\n", managedWAFEvalID+2)
	fmt.Fprintf(&output, "SecRule &ARGS \"@ge %%{tx.cdnca_arguments_limit}\" \"id:%d,phase:2,deny,status:400,log,t:none,msg:'cdnca waf: too many arguments'\"\n", managedWAFEvalID+3)
	fmt.Fprintf(&output, "SecRule REQBODY_ERROR \"!@eq 0\" \"id:%d,phase:2,deny,status:400,log,msg:'cdnca waf: request body could not be parsed',logdata:'%%{reqbody_error_msg}'\"\n", managedWAFEvalID+1)
	fmt.Fprintf(&output, "SecRule MULTIPART_STRICT_ERROR \"!@eq 0\" \"id:%d,phase:2,deny,status:400,log,msg:'cdnca waf: multipart body failed strict validation'\"\n", managedWAFEvalID+4)
	fmt.Fprintf(&output, "SecRule MULTIPART_UNMATCHED_BOUNDARY \"@eq 1\" \"id:%d,phase:2,deny,status:400,log,msg:'cdnca waf: multipart unmatched boundary'\"\n", managedWAFEvalID+5)
	// An inspection limit hit (TX:MSC_*, e.g. the PCRE match limit) is denied
	// only for sites that chose "block"; "log" sites record it and go on.
	fmt.Fprintf(&output, "SecRule TX:cdnca_inspection_limit_mode \"@streq block\" \"id:%d,phase:2,deny,status:403,log,t:none,msg:'cdnca waf: inspection limit hit %%{MATCHED_VAR_NAME}',chain\"\n", managedWAFEvalID+6)
	output.WriteString("  SecRule TX:/^MSC_/ \"!@streq 0\" \"t:none\"\n")
	fmt.Fprintf(&output, "SecRule TX:cdnca_inspection_limit_mode \"@streq log\" \"id:%d,phase:2,pass,log,t:none,msg:'cdnca waf: inspection limit hit (log only) %%{MATCHED_VAR_NAME}',chain\"\n", managedWAFEvalID+7)
	output.WriteString("  SecRule TX:/^MSC_/ \"!@streq 0\" \"t:none\"\n")
	// Request-time site exclusions: the site's gate puts "|x<id>|" for every
	// rule it excludes into the transaction ID (UNIQUE_ID); one phase 1 hook
	// per exportable rule removes it before any CRS rule runs. The hooks do
	// not depend on any site, so excluding a rule changes no node-wide file.
	ids := make([]int, 0, len(exports))
	for id := range exports {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	for position, id := range ids {
		fmt.Fprintf(&output, "SecRule UNIQUE_ID \"@contains |x%d|\" \"id:%d,phase:1,pass,nolog,t:none,ctl:ruleRemoveById=%d\"\n",
			id, managedWAFExclusionID+position, id)
	}
	for _, file := range crsBaseFiles {
		fmt.Fprintf(&output, "Include %s/%s\n", crsRulesDir, file)
	}
	// Relative Includes resolve against this file's directory (the release).
	ordered := make([]string, 0, len(files))
	for file := range files {
		ordered = append(ordered, file)
	}
	sort.Strings(ordered)
	for _, file := range ordered {
		fmt.Fprintf(&output, "Include %s/%s\n", crsRulesDir, file)
	}
	// Scoring rules of the loaded files that belong to no set are removed;
	// every remaining scoring rule credits its set.
	renderManagedSetScoring(&output, release.manifest.Rules, files, owner, setsOf(release.profiles))
	for position, key := range keys {
		renderManagedSetEvaluation(&output, key, managedWAFEvalID+100+position*2, managedWAFEvalID+500+position*3)
	}
	return []byte(output.String()), nil
}

// renderManagedSetScoring is the scoring of the loaded CRS rules: each rule
// of a set adds its severity score to the set's strong sum, or, for a
// two-level set, a heuristic rule above StrongParanoia to its weak sum.
func renderManagedSetScoring(output *strings.Builder, rules []CRSRule, files map[string]bool, owner map[int]string,
	sets map[string]ManagedWAFSet) {
	for _, rule := range rules {
		if !files[rule.File] {
			continue
		}
		key, owned := owner[rule.ID]
		if !owned {
			fmt.Fprintf(output, "SecRuleRemoveById %d\n", rule.ID)
			continue
		}
		sum := "score"
		if sets[key].weakRule(rule) {
			sum = "weak"
			// a learned weight (waf-gap6): its own score, 0 = log only
			// (no setvar: the rule still matches and is audited)
			if weight := sets[key].weakWeight(rule.ID); weight == 0 {
				continue
			} else if weight > 0 {
				fmt.Fprintf(output, "SecRuleUpdateActionById %d \"setvar:'tx.cdnca_%s_weak=+%d'\"\n", rule.ID, managedSetTX(key), weight)
				continue
			}
		}
		fmt.Fprintf(output, "SecRuleUpdateActionById %d \"setvar:'tx.cdnca_%s_%s=+%%{tx.%s_anomaly_score}'\"\n",
			rule.ID, managedSetTX(key), sum, rule.Severity)
	}
}

// renderManagedSetEvaluation is a set's decision (block or log by its mode):
// the strong sum reaches the threshold (ids id / id+1, as before two-level
// scoring), or, for a two-level set, strong + weak reaches the weak
// threshold (ids weakID / weakID+1; tx.cdnca_<set>_weak_threshold is 0 for
// a tier whose set is one-level, so those never fire: the weak sum is then
// never written either).
func renderManagedSetEvaluation(output *strings.Builder, key string, id, weakID int) {
	tx := managedSetTX(key)
	for offset, mode := range []string{"block", "log"} {
		action := "deny,status:403"
		if mode == "log" {
			action = "pass"
		}
		fmt.Fprintf(output, "SecRule TX:cdnca_%s_mode \"@streq %s\" \"id:%d,phase:2,%s,log,auditlog,t:none,msg:'cdnca waf %s %s score %%{tx.cdnca_%s_score}',tag:'cdnca/%s',chain\"\n",
			tx, mode, id+offset, action, mode, key, tx, key)
		fmt.Fprintf(output, "  SecRule TX:cdnca_%s_score \"@ge %%{tx.cdnca_%s_threshold}\" \"t:none\"\n", tx, tx)
	}
	// strong + weak, computed only when the tier's set is two-level
	fmt.Fprintf(output, "SecRule TX:cdnca_%s_weak_threshold \"@gt 0\" \"id:%d,phase:2,pass,nolog,t:none,setvar:'tx.cdnca_%s_total=%%{tx.cdnca_%s_score}',setvar:'tx.cdnca_%s_total=+%%{tx.cdnca_%s_weak}'\"\n",
		tx, weakID, tx, tx, tx, tx)
	for offset, mode := range []string{"block", "log"} {
		action := "deny,status:403"
		if mode == "log" {
			action = "pass"
		}
		fmt.Fprintf(output, "SecRule TX:cdnca_%s_mode \"@streq %s\" \"id:%d,phase:2,%s,log,auditlog,t:none,msg:'cdnca waf %s %s combined score %%{tx.cdnca_%s_total}',tag:'cdnca/%s',chain\"\n",
			tx, mode, weakID+1+offset, action, mode, key, tx, key)
		fmt.Fprintf(output, "  SecRule TX:cdnca_%s_weak_threshold \"@gt 0\" \"t:none,chain\"\n", tx)
		fmt.Fprintf(output, "  SecRule TX:cdnca_%s_total \"@ge %%{tx.cdnca_%s_weak_threshold}\" \"t:none\"\n", tx, tx)
	}
}

// managedSetTierActions are a tier's per-set values set before CRS
// initialises: mode, strong threshold, weak threshold (0: one-level) and the
// sums' start values (unset TX variables would expand to an empty macro).
func managedSetTierActions(set ManagedWAFSet) []string {
	tx := managedSetTX(set.Key)
	return []string{fmt.Sprintf("setvar:tx.cdnca_%s_mode=%s", tx, set.Action),
		fmt.Sprintf("setvar:tx.cdnca_%s_threshold=%d", tx, set.Threshold),
		fmt.Sprintf("setvar:tx.cdnca_%s_weak_threshold=%d", tx, set.WeakThreshold),
		fmt.Sprintf("setvar:tx.cdnca_%s_score=0", tx), fmt.Sprintf("setvar:tx.cdnca_%s_weak=0", tx)}
}

// renderManagedWAFApps writes the application exclusion packs (CRS
// plugins: config then before stage, before CRS initialises, as CRS loads
// plugins) node-wide. Each runs only for requests whose transaction ID
// (RenderWAFEngineGate) carries "|a<key>|": one guard per request phase
// skips to the app's end marker otherwise (skipAfter stays in its phase).
// The pack compiler accepted only text that narrows CRS
// (rulepack.ValidateCRSAppText), so a gated app can never widen another
// site's inspection. IDs: guards 12000+, the plugins' own 95xxxxx.
func renderManagedWAFApps(output *strings.Builder, apps []CRSApp) {
	for index, app := range apps {
		marker := fmt.Sprintf("CDNCA-APP-%s", strings.ToUpper(app.Key))
		fmt.Fprintf(output, "# application type %s: %s %s\n", app.Key, app.Ref.PackID, app.Ref.Version)
		for phase := 1; phase <= 4; phase++ {
			fmt.Fprintf(output, "SecRule UNIQUE_ID \"!@contains |a%s|\" \"id:%d,phase:%d,pass,nolog,t:none,skipAfter:%s\"\n",
				app.Key, managedWAFAppID+index*4+phase-1, phase, marker)
		}
		for _, text := range []string{app.Config, app.Before} {
			if text != "" {
				output.WriteString(strings.TrimRight(text, "\n") + "\n")
			}
		}
		fmt.Fprintf(output, "SecMarker \"%s\"\n", marker)
	}
}

// renderManagedWAFSite is the server-level file of one site: its engine
// limits and the TX values of its profile. Its rules run before the
// node-wide file, so the TX values are in place when CRS initialises (CRS
// keeps paranoia values set earlier). The site's exclusions are not here:
// they apply per request (RenderWAFEngineGate).
func renderManagedWAFSite(release *managedWAFRelease, site Site) []byte {
	value := site.ManagedWAF
	profile := release.profiles[value.Profile.SHA256]
	var output strings.Builder
	fmt.Fprintf(&output, "# site %s policy %s v%d profile %s %s\n", site.ID, value.PolicyID, value.PolicyVersion,
		value.Profile.PackID, value.Profile.Version)
	fmt.Fprintf(&output, "SecRequestBodyLimit %d\nSecRequestBodyNoFilesLimit %d\n", value.RequestBodyLimit, value.RequestBodyNoFilesLimit)
	if value.RequestBodyLimitAction == "partial" {
		output.WriteString("SecRequestBodyLimitAction ProcessPartial\n")
	} else {
		output.WriteString("SecRequestBodyLimitAction Reject\n")
	}
	fmt.Fprintf(&output, "SecArgumentsLimit %d\nSecRequestBodyJsonDepthLimit %d\nSecPcreMatchLimit %d\n",
		value.ArgumentsLimit, value.JSONDepthLimit, value.PCREMatchLimit)
	id := managedWAFSiteID
	next := func() int { id++; return id }
	if len(value.AllowCIDRs) != 0 {
		fmt.Fprintf(&output, "SecRule REMOTE_ADDR \"@ipMatch %s\" \"id:%d,phase:1,pass,nolog,t:none,ctl:ruleEngine=Off\"\n",
			strings.Join(value.AllowCIDRs, ","), next())
	}
	paranoia := 1
	for _, set := range profile.sets {
		if set.Paranoia > paranoia {
			paranoia = set.Paranoia
		}
	}
	actions := []string{
		fmt.Sprintf("setvar:tx.cdnca_arguments_limit=%d", value.ArgumentsLimit),
		"setvar:tx.cdnca_inspection_limit_mode=" + value.InspectionLimitAction,
		fmt.Sprintf("setvar:tx.blocking_paranoia_level=%d", paranoia),
		fmt.Sprintf("setvar:tx.detection_paranoia_level=%d", paranoia),
	}
	for _, set := range profile.sets {
		actions = append(actions, managedSetTierActions(set.ManagedWAFSet)...)
	}
	fmt.Fprintf(&output, "SecAction \"id:%d,phase:1,pass,nolog,t:none,%s\"\n", next(), strings.Join(actions, ","))
	// Sets the profile does not use, and rules above each set's paranoia
	// level, are not evaluated for this site.
	member := map[int]resolvedManagedSet{}
	for _, set := range profile.sets {
		for _, rule := range set.Rules {
			member[rule.ID] = set
		}
	}
	removed := make([]int, 0)
	for _, rule := range release.manifest.Rules {
		set, own := member[rule.ID]
		if !own || rule.Paranoia > set.Paranoia {
			removed = append(removed, rule.ID)
		}
	}
	for start := 0; start < len(removed); start += 32 {
		fmt.Fprintf(&output, "SecRuleRemoveById %s\n", strings.ReplaceAll(intsKey(removed[start:min(start+32, len(removed))]), ",", " "))
	}
	return []byte(output.String())
}

func hasManagedWAF(sites []Site) bool {
	for _, site := range sites {
		if site.ManagedWAF != nil {
			return true
		}
	}
	return false
}

// NormalizeManagedWAF validates a site's managed WAF on its own (ranges,
// profile reference, exclusion syntax) exactly as Build does before the
// release-level checks against the CRS rule text and the profile.
func NormalizeManagedWAF(value ManagedWAF) (*ManagedWAF, error) {
	return normalizeManagedWAF(&value)
}
