package edgeconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Managed WAF on dynamic routing (ADR 0009 §9 Q3 方案 a, PoC section 5,
// task D11). One shared server per port serves every site, so the
// configuration may depend on no site:
//
//   - The node rule file (RenderDynamicWAFRules, http level) loads the CRS
//     rule text once and scores every set of every CRS profile pack the node
//     carries. Per request it reads the site context from the ModSecurity
//     transaction ID (DynamicWAFContext, written by Lua before ModSecurity
//     creates the transaction): engine off for the site's allow CIDRs, the
//     inspection-limit mode and the site's exclusions (one hook per
//     exportable rule, grouped by rule family).
//   - A tier (DynamicWAFTier) is a CRS profile pack plus the values
//     ModSecurity reads only at configuration time (request body limits and
//     action, arguments, JSON depth, PCRE match limit). Every tier the
//     node's sites use is one named location with its own rule file
//     (RenderDynamicWAFTier: the limits, the profile's paranoia and set
//     modes/thresholds, SecRuleRemoveById of what the profile does not
//     evaluate, exactly v7's per-site file without the site), merged before
//     the node rules. A site runs in the tier of its own values, so it gets
//     exactly its profile and limits; tiers change only when a profile pack
//     or a limit combination appears or disappears.
//   - A site's application types (CRS application exclusion packs,
//     waf-apptype) are part of its tier: the tier file carries their text
//     after the profile values, so only the tier's sites run them and no
//     per-request gate is needed (site runtime 8 gated them by the
//     transaction ID).
//
// Rule IDs (ModSecurity local range, disjoint from v7's 10000-20999):
// 30000-30079 context and engine hooks, 30080-30099 detector signals,
// 30100-30999 set evaluation, 31000-31999 adaptive WAF (ADR 0011 RI-03:
// tightening, shape, grey zone, audit sampling), 32000-32123 repeated grey
// zone source (waf-gap6, one per set position), 38000-38031 bucket
// rules, 39000+ tier rules, 40000-49999 exclusion hooks. Automatic
// exclusions (ADR 0011 3.4) are no node rules: the sites with some in force
// are grouped per tier into buckets of at most DynamicWAFBucketSites sites;
// a bucket is one location whose rule file is its tier's plus one rule per
// site (RenderDynamicWAFBucket).

// DynamicWAFContextVariable is the nginx variable (declared by the node
// skeleton, written by Lua in rewrite before the tier location is entered)
// that modsecurity_transaction_id reads.
const DynamicWAFContextVariable = "cdnca_waf_txid"

// DynamicWAFTierPrefix names a tier's named location (@cdnca_waf_<key>).
const DynamicWAFTierPrefix = "@cdnca_waf_"

const (
	dynamicWAFContextID = 30000
	dynamicWAFDetectID  = 30080
	// dynamicWAFDetectorScore is a detector verdict's strong score (CRS
	// critical): on its own it reaches a set's threshold (5).
	dynamicWAFDetectorScore = 5
	dynamicWAFSetID         = 30100
	// adaptive WAF rules: eight per set position (tighten, two shape, two
	// grey zone, two decided), then the challenge and the audit sampling
	dynamicWAFAdaptID     = 31000
	dynamicWAFChallengeID = 31995
	dynamicWAFSampleID    = 31996
	dynamicWAFRepeatID    = 32000
	// dynamicWAFUpgradeID: two per set position (k=, d=repeat), the clamp
	// of an upgraded source's weak sum to the strong threshold (waf-gap10)
	dynamicWAFUpgradeID = 32200
	// dynamicWAFMaxSetKeys bounds the node's set keys (rule ID ranges).
	dynamicWAFMaxSetKeys = 124
	// DynamicWAFSampleDigit: a grey zone transaction is audited when its
	// transaction ID (the request ID) ends in this hex digit: 1/16 (PoC-2).
	DynamicWAFSampleDigit = "0"
	// dynamicWAFShapeScore is the shape signal's weak score (ADR 0011 3.1):
	// alone below a weak threshold (10), with one critical weak hit at it.
	dynamicWAFShapeScore  = 5
	dynamicWAFBucketID    = 38000
	dynamicWAFTierID      = 39000
	dynamicWAFExclusionID = 40000
	// official CRS tuning (ADR 0011 §6.1): guards, batches and per-entry
	// hooks, below the CRS range (900000+)
	dynamicWAFTuningID = 60000
	// DynamicWAFMaxTuningEntries bounds the tuning pack's entries and
	// DynamicWAFMaxTuningTargets one entry's targets.
	DynamicWAFMaxTuningEntries = 16384
	DynamicWAFMaxTuningTargets = 16
	// dynamicWAFTuningBatch bounds the targets of one tuning block (one rule
	// when the site disables none of its entries).
	dynamicWAFTuningBatch = 64
	// DynamicWAFTuningAllOff is the u= item of a site without the tuning
	// pack mounted: no entry applies (entry numbers start at 1).
	DynamicWAFTuningAllOff = 0
	dynamicWAFMaxProfiles  = 64
	// DynamicWAFMaxTiers bounds a node's tiers (named locations).
	DynamicWAFMaxTiers = 256
	// DynamicWAFBucketSites bounds the sites of an exclusion bucket (one
	// location). A location costs about 150-210 KiB per process and 4-5.5
	// ms of reload (RI-03c: its own merged copy of the rules); a site rule
	// of a bucket is evaluated by the bucket's requests up to their site's
	// (about 26 ns each, RI-03d). Measured on real OpenResty (RI-03d, 10 000
	// sites x 32 exclusions, two tiers, 1 worker, 3 rounds): 32 per bucket
	// reload 4.7 s (one round 7.0 s), +152 MiB master; 64: 2.0 s, +131 MiB;
	// 128: 1.8 s, +120 MiB; extra p50 +50 to +120 us at every size (within
	// the rounds' noise). No node-wide bound:
	// cost grows with the sites in force.
	DynamicWAFBucketSites = 128
	// DynamicWAFContextMax bounds the context (ADR 0011 PoC-4: the engine has
	// no limit; cost is about 0.03 ms per KiB and error.log lines end at
	// 4096 bytes). The segment bounds below fit together: nothing is ever
	// dropped from a context.
	DynamicWAFContextMax = 4096
	// Segment bounds (items and bytes, the leading comma included).
	DynamicWAFMaxTighten     = 10
	DynamicWAFMaxTuningOff   = 64
	DynamicWAFMaxIntelBonus  = 100
	dynamicWAFDetectBytes    = 128
	dynamicWAFTightenBytes   = 340
	dynamicWAFTuningOffBytes = 450
	dynamicWAFExcludeBytes   = 1800
	// DynamicWAFMaxTargets is the safety bound of a site's automatic
	// exclusions in force (ADR 0011 3.4): the ctl:ruleRemoveTargetById
	// actions of its bucket rule, only against abnormal input. It is not the
	// business bound: each node takes the
	// first k of a site's ranked exclusions from its own measured per
	// exclusion cost and its latency and memory budgets
	// (agents/edge-agent/internal/wafadapt Plan). They are not in the
	// context (no length bound applies). The cost: libmodsecurity 3.0.17
	// keeps them in a list that every evaluated rule scans per variable and
	// per value (rule_with_operator.cc getFinalVars / evaluate), so only the
	// site's own count matters; memory is about 0.35 KiB a target, node wide
	// (ADR 0011 section 6.5).
	DynamicWAFMaxTargets = 512
	// DynamicWAFMaxGreyFloor bounds f=, the total score at which a set's
	// grey zone starts on the site (0 and 1: every scored request).
	DynamicWAFMaxGreyFloor = 99
)

// DynamicWAFShape is the d= signal of a parameter value that does not fit
// the site's typed parameter (ADR 0011 section 3.3): a weak signal, unlike
// the detectors.
const DynamicWAFShape = "shape"

// DynamicWAFRepeat is the d= signal of a source (site x client address x
// JA4 over TLS; site x client address without a JA4, plain HTTP and HTTP/3:
// waf-gap8, a NAT exit's other clients are not held for one scanner) with
// at least DynamicWAFRepeatThreshold grey zone transactions on the site in
// the current or previous fixed DynamicWAFRepeatWindow seconds (waf-gap6,
// research §3.9: a scanner sends many single weak hit payloads, a person
// seldom one; constants in 1.0.35, a site setting possible in 1.0.36, ADR
// 0011 §3.2a): every two-level set's weak sum scores as strong, as k= does for a
// tightened set. A clean request stays clean (no score, nothing to
// promote). The node's Lua counts a transaction as grey when one of its
// rule messages is a grey zone rule (DynamicWAFGreyRule), read in the log
// phase from $modsecurity_rule_ids (ModSecurity-nginx patch 01).
const (
	DynamicWAFRepeat          = "repeat"
	DynamicWAFRepeatThreshold = 20
	DynamicWAFRepeatWindow    = 60
)

// A site's own repeat threshold / window (defer-small2, capability
// WAF_REPEAT_SITE; waf_adapt_sites.repeat_threshold / repeat_window, NULL =
// the constants above) stays within these bounds.
const (
	DynamicWAFRepeatThresholdMin = 2
	DynamicWAFRepeatThresholdMax = 1000
	DynamicWAFRepeatWindowMin    = 10
	DynamicWAFRepeatWindowMax    = 600
)

// DynamicWAFGreyRule reports whether a node rule ID is a set's grey zone
// rule (31000 + position*8 + 3).
func DynamicWAFGreyRule(id int) bool {
	return id >= dynamicWAFAdaptID && id < dynamicWAFAdaptID+dynamicWAFMaxSetKeys*8 && (id-dynamicWAFAdaptID)%8 == 3
}

// WAFParamNamePattern is a parameter name an automatic exclusion may target:
// ModSecurity's variable name after the collection (JSON leaves are
// json.<path>), case sensitive, inside the ctl:ruleRemoveTargetById
// character set without the context's separators and quoting characters
// (PoC-1). Other names fall back to a site x rule exclusion (x=).
var WAFParamNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.\[\]-]{1,64}$`)

// WAFTargetLocations are the collections a target names, with their context
// letter: args = ARGS (query, form and JSON leaves alike: the audit record
// only says ARGS:<name>), cookie = REQUEST_COOKIES, header = REQUEST_HEADERS.
var WAFTargetLocations = map[string]string{"args": "a", "cookie": "c", "header": "h"}

// dynamicWAFTargetCollections are the ModSecurity collections of the target
// locations.
var dynamicWAFTargetCollections = map[string]string{"args": "ARGS", "cookie": "REQUEST_COOKIES", "header": "REQUEST_HEADERS"}

// DynamicWAFTarget is one automatic exclusion of a site: the rule no longer
// inspects that parameter (ModSecurity target <collection>:<name>).
type DynamicWAFTarget struct {
	Rule     int
	Location string // args | cookie | header
	Name     string
}

func dynamicWAFTargetLess(a, b DynamicWAFTarget) bool {
	if a.Rule != b.Rule {
		return a.Rule < b.Rule
	}
	if a.Location != b.Location {
		return a.Location < b.Location
	}
	return a.Name < b.Name
}

// CRSTuning is one entry of the official CRS tuning pack (ADR 0011 §6.1,
// system/crs-tuning): rule Rule stops inspecting Targets, on tiers whose
// paranoia (tx.blocking_paranoia_level) is at least MinParanoia. Targets are
// exact variable names (no wildcard, no regex: PoC-1, a name is matched byte
// for byte), sorted by (location, name), distinct.
type CRSTuning struct {
	MinParanoia int               `json:"min_paranoia"`
	Rule        int               `json:"rule"`
	Targets     []CRSTuningTarget `json:"targets"`
}

// CRSTuningTarget is one variable an entry removes: Location args | cookie
// | header (ARGS / REQUEST_COOKIES / REQUEST_HEADERS), Name as
// WAFParamNamePattern.
type CRSTuningTarget struct {
	Location string `json:"loc"`
	Name     string `json:"name"`
}

// CRSTuningEntry is an entry with its number (the c3 u= item).
type CRSTuningEntry struct {
	ID int
	CRSTuning
}

// ValidateCRSTuning checks one tuning entry body.
func ValidateCRSTuning(tuning CRSTuning) error {
	if tuning.MinParanoia < 1 || tuning.MinParanoia > 4 || !validCRSRuleID(tuning.Rule) ||
		len(tuning.Targets) < 1 || len(tuning.Targets) > DynamicWAFMaxTuningTargets {
		return fmt.Errorf("%w: tuning entry: min_paranoia 1..4, a CRS rule and 1..%d targets", ErrInvalidConfig,
			DynamicWAFMaxTuningTargets)
	}
	for index, target := range tuning.Targets {
		if _, known := WAFTargetLocations[target.Location]; !known || !WAFParamNamePattern.MatchString(target.Name) {
			return fmt.Errorf("%w: tuning target %s:%s is not an exact parameter name", ErrInvalidConfig, target.Location, target.Name)
		}
		if index > 0 {
			previous := tuning.Targets[index-1]
			if previous.Location > target.Location || previous.Location == target.Location && previous.Name >= target.Name {
				return fmt.Errorf("%w: tuning targets must be sorted and distinct", ErrInvalidConfig)
			}
		}
	}
	return nil
}

// DynamicWAFTier is a site's managed WAF without the site: its CRS profile
// pack and its configuration-time limits.
type DynamicWAFTier struct {
	Profile                 CRSProfileRef `json:"profile"`
	RequestBodyLimit        int           `json:"request_body_limit"`
	RequestBodyNoFilesLimit int           `json:"request_body_no_files_limit"`
	RequestBodyLimitAction  string        `json:"request_body_limit_action"`
	ArgumentsLimit          int           `json:"arguments_limit"`
	JSONDepthLimit          int           `json:"json_depth_limit"`
	PCREMatchLimit          int           `json:"pcre_match_limit"`
	// Apps are the site's application exclusion packs (sorted by pack ID).
	Apps []CRSAppRef `json:"apps,omitempty"`
}

// TierOf is a managed WAF's tier.
func (value ManagedWAF) TierOf() DynamicWAFTier {
	return DynamicWAFTier{Profile: value.Profile, RequestBodyLimit: value.RequestBodyLimit,
		RequestBodyNoFilesLimit: value.RequestBodyNoFilesLimit, RequestBodyLimitAction: value.RequestBodyLimitAction,
		ArgumentsLimit: value.ArgumentsLimit, JSONDepthLimit: value.JSONDepthLimit, PCREMatchLimit: value.PCREMatchLimit,
		Apps: append([]CRSAppRef(nil), value.Apps...)}
}

// Key is the tier's name: the same text the node's Lua builds from a site
// object (edge/openresty/dynroute/cdnca_managed_waf.lua tier_key), so a site
// finds its location without a node-wide map.
func (tier DynamicWAFTier) Key() string {
	action := "r"
	if tier.RequestBodyLimitAction == "partial" {
		action = "p"
	}
	key := fmt.Sprintf("%s_b%d_n%d_%s_a%d_j%d_p%d", dynamicProfileTag(tier.Profile.SHA256), tier.RequestBodyLimit,
		tier.RequestBodyNoFilesLimit, action, tier.ArgumentsLimit, tier.JSONDepthLimit, tier.PCREMatchLimit)
	for _, app := range tier.Apps {
		key += "_x" + dynamicAppTag(app.SHA256)
	}
	return key
}

// Location is the tier's named location.
func (tier DynamicWAFTier) Location() string { return DynamicWAFTierPrefix + tier.Key() }

const managedWAFValidationPolicy = "00000000-0000-4000-8000-000000000000"

func (tier DynamicWAFTier) valid() bool {
	probe := ManagedWAF{PolicyID: managedWAFValidationPolicy, PolicyVersion: 1, RequestBodyLimit: tier.RequestBodyLimit,
		RequestBodyNoFilesLimit: tier.RequestBodyNoFilesLimit, RequestBodyLimitAction: tier.RequestBodyLimitAction,
		ArgumentsLimit: tier.ArgumentsLimit, JSONDepthLimit: tier.JSONDepthLimit, PCREMatchLimit: tier.PCREMatchLimit,
		Profile: tier.Profile, Apps: tier.Apps}
	_, err := normalizeManagedWAF(&probe)
	return err == nil
}

// dynamicProfileTag is a profile pack's short name in tier keys: the first
// 16 hex digits of its digest (a release refuses two that collide).
func dynamicProfileTag(digest string) string {
	if len(digest) < 16 {
		return digest
	}
	return digest[:16]
}

// dynamicAppTag is an application exclusion pack's short name in tier keys:
// the first 8 hex digits of its digest (a release refuses two that collide).
func dynamicAppTag(digest string) string {
	if len(digest) < 8 {
		return digest
	}
	return digest[:8]
}

// DynamicWAFRelease is what a node's managed WAF loads: one CRS rule text,
// the CRS profile packs its sites select (checked against that text) and
// the application exclusion packs they select.
type DynamicWAFRelease struct {
	manifest *CRSManifest
	text     *CRSRuleText
	profiles []resolvedCRSProfile // by digest
	apps     map[string]CRSApp    // by digest, parser rule IDs rewritten
}

// dynamicWAFParserRuleIDs maps the node request body rules an application
// pack may remove, in site runtime 8 numbering (rulepack.CRSAppParserRuleIDs
// targets, renderManagedWAFMain 10000+N), to the same rules of the dynamic
// node rules (RenderDynamicWAFRules 30000+N): parse error, too many
// arguments, multipart strict, multipart unmatched boundary.
var dynamicWAFParserRuleIDs = map[int]int{10001: 30009, 10003: 30008, 10004: 30010, 10005: 30011}

var dynamicWAFRuleRemoveByID = regexp.MustCompile(`ctl:ruleRemoveById=[0-9]+(?: [0-9]+)*`)

// dynamicAppText rewrites the parser rule IDs an application pack removes
// (the pack compiler allows them only as single IDs of ctl:ruleRemoveById).
func dynamicAppText(text string) string {
	return dynamicWAFRuleRemoveByID.ReplaceAllStringFunc(text, func(ctl string) string {
		ids := strings.Fields(strings.TrimPrefix(ctl, "ctl:ruleRemoveById="))
		for index, id := range ids {
			if value, err := strconv.Atoi(id); err == nil {
				if mapped, ok := dynamicWAFParserRuleIDs[value]; ok {
					ids[index] = strconv.Itoa(mapped)
				}
			}
		}
		return "ctl:ruleRemoveById=" + strings.Join(ids, " ")
	})
}

// ResolveDynamicWAFRelease checks a node's CRS rule text, profile packs and
// application exclusion packs: one membership per set key and one set per
// CRS rule across the profiles (they are scored node-wide), the rule text
// restricted to what the profiles load, and the apps checked as site
// runtime 8 checks them (one version per application, markers unique and
// outside the node namespace).
func ResolveDynamicWAFRelease(text *CRSRuleText, profiles []CRSProfile, apps ...CRSApp) (*DynamicWAFRelease, error) {
	if len(profiles) == 0 || len(profiles) > dynamicWAFMaxProfiles {
		return nil, ErrInvalidConfig
	}
	sites := make([]Site, len(profiles))
	for index, profile := range profiles {
		// one synthetic site per profile: resolveManagedWAFRelease checks the
		// profiles together exactly as for a v7 release
		sites[index] = Site{ID: fmt.Sprintf("00000000-0000-4000-8000-%012d", index+1), ManagedWAF: &ManagedWAF{Profile: profile.Ref}}
	}
	release, err := resolveManagedWAFRelease(sites, text, profiles, false)
	if err != nil || release == nil {
		return nil, ErrInvalidConfig
	}
	result := &DynamicWAFRelease{manifest: release.manifest, text: release.text, apps: map[string]CRSApp{}}
	for _, profile := range release.profiles {
		result.profiles = append(result.profiles, profile)
	}
	sort.Slice(result.profiles, func(i, j int) bool { return result.profiles[i].Ref.SHA256 < result.profiles[j].Ref.SHA256 })
	for index := 1; index < len(result.profiles); index++ {
		if dynamicProfileTag(result.profiles[index-1].Ref.SHA256) == dynamicProfileTag(result.profiles[index].Ref.SHA256) {
			return nil, ErrInvalidConfig
		}
	}
	if len(apps) != 0 {
		// one synthetic site selecting every app: resolveCRSApps checks them
		// together exactly as for a site runtime 8 release
		all := &ManagedWAF{}
		for _, app := range apps {
			all.Apps = append(all.Apps, app.Ref)
		}
		resolved, err := resolveCRSApps([]Site{{ManagedWAF: all}}, apps)
		if err != nil || len(resolved) != len(apps) {
			return nil, ErrInvalidConfig
		}
		tags := map[string]bool{}
		for _, app := range resolved {
			if tags[dynamicAppTag(app.Ref.SHA256)] {
				return nil, ErrInvalidConfig
			}
			tags[dynamicAppTag(app.Ref.SHA256)] = true
			app.Config, app.Before = dynamicAppText(app.Config), dynamicAppText(app.Before)
			result.apps[app.Ref.SHA256] = app
		}
	}
	return result, nil
}

func (release *DynamicWAFRelease) profile(ref CRSProfileRef) (resolvedCRSProfile, bool) {
	for _, profile := range release.profiles {
		if profile.Ref == ref {
			return profile, true
		}
	}
	return resolvedCRSProfile{}, false
}

// CheckSite reports whether a site's managed WAF runs on this release: its
// profile and application packs are the release's and it excludes only
// rules that profile exports.
func (release *DynamicWAFRelease) CheckSite(value ManagedWAF) error {
	normalized, err := normalizeManagedWAF(&value)
	if err != nil {
		return err
	}
	profile, ok := release.profile(normalized.Profile)
	if !ok {
		return ErrInvalidConfig
	}
	for _, ref := range normalized.Apps {
		if app, carried := release.apps[ref.SHA256]; !carried || app.Ref != ref {
			return ErrInvalidConfig
		}
	}
	for _, id := range normalized.Exclusions {
		if !profile.exported(id) {
			return ErrInvalidConfig
		}
	}
	return nil
}

// RenderDynamicWAFTier is a tier's rule file, loaded in the tier location
// whose rule set is these rules followed by the http-level node rules
// (ModSecurity-nginx merges a location's rules before its parent's): the
// configuration-time limits, the profile's paranoia, set modes and
// thresholds before CRS initialises (CRS keeps values set earlier), and the
// CRS scoring rules the profile does not evaluate (sets it does not use,
// rules above a set's paranoia) removed. It is v7's per-site file
// (renderManagedWAFSite) without the site's allow CIDRs and exclusions,
// which come per request. The tier's application packs follow (config then
// before stage, as CRS loads plugins), ungated: only the tier's sites run.
func RenderDynamicWAFTier(release *DynamicWAFRelease, tier DynamicWAFTier) ([]byte, error) {
	return renderDynamicWAFTier(release, tier, false)
}

// DynamicWAFCookieSuffix ends the location name of a two-level tier's cookie
// variant (RenderDynamicWAFTierCookies).
const DynamicWAFCookieSuffix = "_c"

// RenderDynamicWAFTierCookies is a two-level tier's cookie variant: the tier
// file whose weak rules also read cookies. The node's Lua sends a request
// there only when one of its cookies is out of the site's learned profile
// (a typed cookie parameter's type, length bucket or charset, ADR 0011 3.3
// shape): on a site whose cookie profile is not mature (no typed cookie) the
// weak rules never read cookies (the strict tiers rely on algorithms and
// adaptive learning). A one-level tier
// has no variant (ErrInvalidConfig).
func RenderDynamicWAFTierCookies(release *DynamicWAFRelease, tier DynamicWAFTier) ([]byte, error) {
	return renderDynamicWAFTier(release, tier, true)
}

// TwoLevel reports whether the tier's profile scores some set in two levels.
func (release *DynamicWAFRelease) TwoLevel(tier DynamicWAFTier) bool {
	profile, ok := release.profile(tier.Profile)
	if !ok {
		return false
	}
	for _, set := range profile.sets {
		if set.twoLevel() {
			return true
		}
	}
	return false
}

func renderDynamicWAFTier(release *DynamicWAFRelease, tier DynamicWAFTier, cookies bool) ([]byte, error) {
	if release == nil || !tier.valid() || cookies && !release.TwoLevel(tier) {
		return nil, ErrInvalidConfig
	}
	profile, ok := release.profile(tier.Profile)
	if !ok {
		return nil, ErrInvalidConfig
	}
	var output strings.Builder
	fmt.Fprintf(&output, "# cdnca managed WAF tier %s: profile %s %s\n", tier.Key(), tier.Profile.PackID, tier.Profile.Version)
	fmt.Fprintf(&output, "SecRequestBodyLimit %d\nSecRequestBodyNoFilesLimit %d\n", tier.RequestBodyLimit, tier.RequestBodyNoFilesLimit)
	if tier.RequestBodyLimitAction == "partial" {
		output.WriteString("SecRequestBodyLimitAction ProcessPartial\n")
	} else {
		output.WriteString("SecRequestBodyLimitAction Reject\n")
	}
	fmt.Fprintf(&output, "SecArgumentsLimit %d\nSecRequestBodyJsonDepthLimit %d\nSecPcreMatchLimit %d\n",
		tier.ArgumentsLimit, tier.JSONDepthLimit, tier.PCREMatchLimit)
	paranoia := 1
	for _, set := range profile.sets {
		paranoia = max(paranoia, set.Paranoia)
	}
	actions := []string{
		fmt.Sprintf("setvar:tx.cdnca_arguments_limit=%d", tier.ArgumentsLimit),
		fmt.Sprintf("setvar:tx.blocking_paranoia_level=%d", paranoia),
		fmt.Sprintf("setvar:tx.detection_paranoia_level=%d", paranoia),
	}
	for _, set := range profile.sets {
		actions = append(actions, managedSetTierActions(set.ManagedWAFSet)...)
		if set.GreyAction == ManagedWAFGreyChallenge {
			// the node rules challenge this set's grey zone (RenderDynamicWAFRules)
			actions = append(actions, fmt.Sprintf("setvar:tx.cdnca_%s_grey=1", managedSetTX(set.Key)))
		}
	}
	fmt.Fprintf(&output, "SecAction \"id:%d,phase:1,pass,nolog,t:none,%s\"\n", dynamicWAFTierID, strings.Join(actions, ","))
	member := map[int]resolvedManagedSet{}
	for _, set := range profile.sets {
		for _, rule := range set.Rules {
			member[rule.ID] = set
		}
	}
	removed := make([]int, 0)
	for _, rule := range release.manifest.Rules {
		if set, own := member[rule.ID]; !own || rule.Paranoia > set.Paranoia {
			removed = append(removed, rule.ID)
		}
	}
	for start := 0; start < len(removed); start += 32 {
		fmt.Fprintf(&output, "SecRuleRemoveById %s\n", strings.ReplaceAll(intsKey(removed[start:min(start+32, len(removed))]), ",", " "))
	}
	for _, ref := range tier.Apps {
		app, ok := release.apps[ref.SHA256]
		if !ok || app.Ref != ref {
			return nil, ErrInvalidConfig
		}
		fmt.Fprintf(&output, "# application type %s: %s %s\n", app.Key, app.Ref.PackID, app.Ref.Version)
		for _, text := range []string{app.Config, app.Before} {
			if text != "" {
				output.WriteString(strings.TrimRight(text, "\n") + "\n")
			}
		}
	}
	if !cookies {
		renderDynamicWAFCookieWeak(&output, release.manifest.Rules, profile.sets)
	}
	return []byte(output.String()), nil
}

// DynamicWAFBucketLocation is a tier's n-th exclusion bucket location
// (@cdnca_waf_<tier key>_x<n>, never a tier key).
func DynamicWAFBucketLocation(tier DynamicWAFTier, n int) string {
	return fmt.Sprintf("%s_x%d", tier.Location(), n)
}

// DynamicWAFBucketSite is one site of an exclusion bucket and its automatic
// exclusions in force.
type DynamicWAFBucketSite struct {
	SiteID  string
	Targets []DynamicWAFTarget
}

var dynamicWAFSiteIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// RenderDynamicWAFBucket is the rule file of an exclusion bucket location:
// its tier's file (included, so every value is the tier's), then per site
// one phase 1 rule that matches the site in the context (the transaction
// ID starts with "c3;s=<site id>;") and removes each excluded target from
// its rule for that transaction (ctl:ruleRemoveTargetById; the location's
// rules run before the node rules), skipping the other sites' rules. A
// request of the bucket evaluates at most DynamicWAFBucketSites such rules;
// a site outside every bucket runs in its tier location and evaluates none.
// sites are ascending by ID, 1 to DynamicWAFBucketSites; each site's
// targets ascending (DynamicWAFTarget order), distinct, 1 to
// DynamicWAFMaxTargets, each rule exported by the tier's profile; tierFile
// is the tier rule file's path.
func RenderDynamicWAFBucket(release *DynamicWAFRelease, tier DynamicWAFTier, tierFile string, sites []DynamicWAFBucketSite) ([]byte, error) {
	if release == nil || !tier.valid() || !gatePathPattern.MatchString(tierFile) || strings.Contains(tierFile, "/../") ||
		len(sites) == 0 || len(sites) > DynamicWAFBucketSites {
		return nil, ErrInvalidConfig
	}
	profile, ok := release.profile(tier.Profile)
	if !ok {
		return nil, ErrInvalidConfig
	}
	var output strings.Builder
	fmt.Fprintf(&output, "# cdnca managed WAF exclusion bucket: tier %s, %d sites\nInclude %s\n", tier.Key(), len(sites), tierFile)
	for index, site := range sites {
		if !dynamicWAFSiteIDPattern.MatchString(site.SiteID) || index > 0 && sites[index-1].SiteID >= site.SiteID ||
			len(site.Targets) == 0 || len(site.Targets) > DynamicWAFMaxTargets {
			return nil, ErrInvalidConfig
		}
		actions := make([]string, len(site.Targets))
		for position, target := range site.Targets {
			if _, known := WAFTargetLocations[target.Location]; !known || !profile.exported(target.Rule) ||
				!WAFParamNamePattern.MatchString(target.Name) || position > 0 && !dynamicWAFTargetLess(site.Targets[position-1], target) {
				return nil, ErrInvalidConfig
			}
			actions[position] = fmt.Sprintf("ctl:ruleRemoveTargetById=%d;%s:%s", target.Rule, dynamicWAFTargetCollections[target.Location], target.Name)
		}
		fmt.Fprintf(&output, "SecRule UNIQUE_ID \"@beginsWith c3;s=%s;\" \"id:%d,phase:1,pass,nolog,t:none,%s,skipAfter:CDNCA-XB\"\n",
			site.SiteID, dynamicWAFBucketID+index, strings.Join(actions, ","))
	}
	output.WriteString("SecMarker \"CDNCA-XB\"\n")
	return []byte(output.String()), nil
}

// TwoLevelProfiles are the digests of the release's profile packs that score
// some set in two levels (严格防护 and above): the node's Lua computes the
// detector verdicts (DynamicWAFContext d=) only for their sites.
func (release *DynamicWAFRelease) TwoLevelProfiles() []string {
	digests := []string{}
	for _, profile := range release.profiles {
		for _, set := range profile.sets {
			if set.twoLevel() {
				digests = append(digests, profile.Ref.SHA256)
				break
			}
		}
	}
	sort.Strings(digests)
	return digests
}

// GreyChallengeProfiles are the digests of the release's profile packs with
// a set whose grey zone challenges (grey_action challenge: 严格防护 and
// 极严格防护): only their sites' browser-like
// requests are marked b=1 in the context.
func (release *DynamicWAFRelease) GreyChallengeProfiles() []string {
	digests := []string{}
	for _, profile := range release.profiles {
		for _, set := range profile.sets {
			if set.GreyAction == ManagedWAFGreyChallenge {
				digests = append(digests, profile.Ref.SHA256)
				break
			}
		}
	}
	sort.Strings(digests)
	return digests
}

// Files is the CRS rule text the node rule file includes, by file name.
func (release *DynamicWAFRelease) Files() map[string][]byte {
	files := make(map[string][]byte, len(release.text.Files))
	for name, content := range release.text.Files {
		files[name] = append([]byte(nil), content...)
	}
	return files
}

// CRSVersion is the release's CRS version.
func (release *DynamicWAFRelease) CRSVersion() string { return release.manifest.Version }

// Exports is the union of the profiles' exportable rules, sorted.
func (release *DynamicWAFRelease) Exports() []int {
	seen := map[int]bool{}
	for _, profile := range release.profiles {
		for _, id := range profile.Exports {
			seen[id] = true
		}
	}
	ids := make([]int, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	return ids
}

// Exported reports whether the profile with digest exports rule id.
func (release *DynamicWAFRelease) Exported(digest string, id int) bool {
	for _, profile := range release.profiles {
		if profile.Ref.SHA256 == digest {
			return profile.exported(id)
		}
	}
	return false
}

// DynamicWAFContext is one request's managed WAF parameters as Lua writes
// them into the transaction ID. Format (cdnca managed WAF context v3, ADR
// 0011 section 3.1 and PoC section 10):
//
//	c3;s=<site id>;i=<l|b>;e=<1|0>;g=<0|1>;b=<0|1>;p=<0-100>;d=,<signal>,;
//	f=<0-99>;k=,<set>,;u=,<entry>,;x=,<id>,;|<request id>
//
// (one line, no space). Every list segment starts and ends with a comma
// ("," when empty). The site's automatic exclusions are not here: a
// site with some in force runs in its tier's
// exclusion bucket location (RenderDynamicWAFBucket), so a request pays only
// for its bucket's sites.
//
//   - i: inspection limit "log"/"block"; e=0: the client is in the site's
//     allow CIDRs (engine off).
//   - g=1: the request carries a valid WAF challenge cookie (grey zone
//     passes); b=1: a browser-like request (the only kind a grey zone
//     challenges, section 3.2).
//   - p: the platform intelligence bonus of the client (ADR 0010 Q7, ad-10:
//     only adds to a score, never decides alone), 0 = none.
//   - d: the structural detectors (DynamicWAFDetectors) that matched an
//     argument value and "shape" (a typed parameter's value out of type);
//     Lua computes them only for a profile pack with two-level scoring.
//   - f: the site's grey zone floor (WAFAdapt grey_floor): a set is in its
//     grey zone from this total score up (0 = the tier's own start, any
//     score above 0). A matured site profile raises it to the p99 of its
//     normal requests' weak scores (GreyFloorFromP99), so fewer of its
//     normal requests are challenged; blocking never changes.
//   - k: the sets tightened on the site (set key without "waf_set:",
//     ascending): their weak rules score as strong (section 3.5).
//   - u: the official tuning entries the site disables (ascending, section
//     6.1); ",0," alone (DynamicWAFTuningAllOff): the site has no tuning
//     pack mounted, no entry applies.
//   - x: the site's rule exclusions (site x rule).
//
// The request ID makes the transaction ID (the audit log unique_id) unique;
// its last hex digit is the audit sampling key (PoC-2). c2 and older are not
// accepted: compatibility baseline 1.0.35 has no node writing them.
type DynamicWAFContext struct {
	SiteID          string
	InspectionBlock bool
	EngineOff       bool
	GreyPassed      bool
	Browser         bool
	IntelBonus      int
	Detectors       []string
	GreyFloor       int
	Tighten         []string
	TuningOff       []int
	Exclusions      []int
	RequestID       string
}

// DynamicWAFDetectors are the node's structural detectors (cdnca_waf.lua
// DETECTORS) whose verdict is a strong signal of a set (waf-strict-algo 2b):
// a request one of them matches adds a critical score (5) to that set's
// strong sum when the request's tier scores the set in two levels (严格防护
// and above), so 标准防护 decides as before. Detector -> set key.
var DynamicWAFDetectors = []struct{ Name, Set string }{
	{"sqli", "waf_set:crs_sqli"},
	{"xss", "waf_set:crs_xss"},
	{"ssti", "waf_set:crs_ssti"},
	{"java_deser", "waf_set:crs_java_deserialization"},
	{"php_deser", "waf_set:crs_php_deserialization"},
	{"ssrf", "waf_set:crs_file_include"},
	{"cmd", "waf_set:crs_cmd_injection"},
	// waf-gap4: classes CRS (as the profile packs include it) misses; each
	// adds to the closest existing set, so no profile pack changes:
	// response splitting to XSS, an open redirect to SSRF's set, printf
	// directives to command injection, NoSQL / LDAP query injection to SQL
	// injection, an executable upload name to file upload, XML external
	// entities to file include.
	{"crlf", "waf_set:crs_xss"},
	{"redirect", "waf_set:crs_file_include"},
	{"format", "waf_set:crs_cmd_injection"},
	{"nosql", "waf_set:crs_sqli"},
	{"ldap", "waf_set:crs_sqli"},
	{"upload", "waf_set:crs_file_upload"},
	// an external entity / XInclude / XSLT extension is a file or URL read
	{"xxe", "waf_set:crs_file_include"},
	// waf-gap5: prototype pollution is CRS 934130's class (crs_generic, 严格防护
	// and above only); path traversal is file include (930)
	{"proto", "waf_set:crs_generic"},
	{"path", "waf_set:crs_file_include"},
}

var dynamicWAFContextPattern = regexp.MustCompile(`^c3;s=([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12});` +
	`i=([lb]);e=([01]);g=([01]);b=([01]);p=(0|[1-9][0-9]?|100);d=(,(?:[a-z_]{1,16},)*);f=(0|[1-9][0-9]?);` +
	`k=(,(?:[A-Za-z0-9._-]{1,64},)*);u=(,(?:0,|(?:[1-9][0-9]{0,5},)*));x=(,(?:[0-9]{6},)*);\|([0-9A-Za-z]{1,64})$`)

// DynamicWAFContextRules are the two PCRE patterns the node rules
// (RenderDynamicWAFRules) parse a c3 context with. The first checks the
// whole context and captures s i e g b p d f (TX.1-TX.8); the second, run
// after it, captures k u x (TX.1-TX.3): each stays within TX.1-TX.9, the
// capture range ModSecurity documents.
// They run under the tier's SecPcreMatchLimit (1000 at least): character
// classes with bounded repeats only, no nesting, so the cost is linear (a
// limit hit reads as a missing context: 500). The node's Lua is the only
// writer; ParseDynamicWAFContext is the strict form (order, known names,
// segment items).
var DynamicWAFContextRules = [2]string{
	`^c3;s=([0-9a-f-]{36});i=([lb]);e=([01]);g=([01]);b=([01]);p=([0-9]{1,3});d=(,[a-z_,]{0,` + strconv.Itoa(dynamicWAFDetectBytes-1) + `});` +
		`f=([0-9]{1,2});` + dynamicWAFContextTail(false) + `$`,
	`;` + dynamicWAFContextTail(true) + `$`,
}

// dynamicWAFContextTail is k= u= x= and the request ID, with or without
// capture groups.
func dynamicWAFContextTail(capture bool) string {
	open, closing := "", ""
	if capture {
		open, closing = "(", ")"
	}
	segment := func(name, class string, bytes int) string {
		return name + "=" + open + "," + class + "{0," + strconv.Itoa(bytes-1) + "}" + closing + ";"
	}
	return segment("k", `[A-Za-z0-9._,-]`, dynamicWAFTightenBytes) + segment("u", `[0-9,]`, dynamicWAFTuningOffBytes) +
		segment("x", `[0-9,]`, dynamicWAFExcludeBytes) + `\|[0-9A-Za-z]{1,64}`
}

func flag(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

func writeList(output *strings.Builder, name string, items []string) {
	output.WriteString(";" + name + "=,")
	for _, item := range items {
		output.WriteString(item + ",")
	}
}

// String is the transaction ID text (it does not check the bounds:
// ParseDynamicWAFContext does).
func (context DynamicWAFContext) String() string {
	var output strings.Builder
	inspection := "l"
	if context.InspectionBlock {
		inspection = "b"
	}
	fmt.Fprintf(&output, "c3;s=%s;i=%s;e=%s;g=%s;b=%s;p=%d", context.SiteID, inspection, flag(!context.EngineOff),
		flag(context.GreyPassed), flag(context.Browser), context.IntelBonus)
	numbers := func(values []int) []string {
		texts := make([]string, len(values))
		for index, value := range values {
			texts[index] = strconv.Itoa(value)
		}
		return texts
	}
	writeList(&output, "d", context.Detectors)
	fmt.Fprintf(&output, ";f=%d", context.GreyFloor)
	writeList(&output, "k", context.Tighten)
	writeList(&output, "u", numbers(context.TuningOff))
	writeList(&output, "x", numbers(context.Exclusions))
	output.WriteString(";|" + context.RequestID)
	return output.String()
}

// dynamicWAFSignalOrder is d='s canonical order: DynamicWAFDetectors, then
// DynamicWAFShape, then DynamicWAFRepeat.
func dynamicWAFSignalOrder() map[string]int {
	order := map[string]int{}
	for position, detector := range DynamicWAFDetectors {
		order[detector.Name] = position
	}
	order[DynamicWAFShape] = len(DynamicWAFDetectors)
	order[DynamicWAFRepeat] = len(DynamicWAFDetectors) + 1
	return order
}

func splitList(segment string) []string {
	trimmed := strings.Trim(segment, ",")
	if trimmed == "" {
		return []string{}
	}
	return strings.Split(trimmed, ",")
}

// ParseDynamicWAFContext reads a transaction ID strictly (tests, the agent's
// audit record reader and log tooling; the node parses it with
// DynamicWAFContextRules). It accepts exactly what String writes for a
// context within bounds: known signals in canonical order, ascending
// distinct lists, each segment within its item and byte bound, the whole
// within DynamicWAFContextMax.
func ParseDynamicWAFContext(value string) (DynamicWAFContext, bool) {
	if len(value) > DynamicWAFContextMax {
		return DynamicWAFContext{}, false
	}
	match := dynamicWAFContextPattern.FindStringSubmatch(value)
	if match == nil {
		return DynamicWAFContext{}, false
	}
	for index, bound := range map[int]int{7: dynamicWAFDetectBytes, 9: dynamicWAFTightenBytes,
		10: dynamicWAFTuningOffBytes, 11: dynamicWAFExcludeBytes} {
		if len(match[index]) > bound {
			return DynamicWAFContext{}, false
		}
	}
	bonus, _ := strconv.Atoi(match[6])
	floor, _ := strconv.Atoi(match[8])
	context := DynamicWAFContext{SiteID: match[1], InspectionBlock: match[2] == "b", EngineOff: match[3] == "0",
		GreyPassed: match[4] == "1", Browser: match[5] == "1", IntelBonus: bonus, Detectors: splitList(match[7]),
		GreyFloor: floor, Tighten: splitList(match[9]), TuningOff: []int{}, Exclusions: []int{}, RequestID: match[12]}
	order := dynamicWAFSignalOrder()
	for index, name := range context.Detectors {
		position, known := order[name]
		if !known || index > 0 && order[context.Detectors[index-1]] >= position {
			return DynamicWAFContext{}, false
		}
	}
	if len(context.Tighten) > DynamicWAFMaxTighten {
		return DynamicWAFContext{}, false
	}
	for index, key := range context.Tighten {
		if !managedWAFSetKey.MatchString("waf_set:"+key) || index > 0 && context.Tighten[index-1] >= key {
			return DynamicWAFContext{}, false
		}
	}
	for _, list := range []struct {
		segment string
		into    *[]int
		max     int
		valid   func(int) bool
	}{
		{match[10], &context.TuningOff, DynamicWAFMaxTuningOff, func(id int) bool { return id >= DynamicWAFTuningAllOff && id <= 999999 }},
		{match[11], &context.Exclusions, MaxManagedWAFExclusions, validCRSRuleID},
	} {
		for _, text := range splitList(list.segment) {
			id, _ := strconv.Atoi(text)
			if !list.valid(id) || len(*list.into) > 0 && (*list.into)[len(*list.into)-1] >= id {
				return DynamicWAFContext{}, false
			}
			*list.into = append(*list.into, id)
		}
		if len(*list.into) > list.max {
			return DynamicWAFContext{}, false
		}
	}
	return context, true
}

// RenderDynamicWAFRules is the node rule file of a dynamic routing node:
// engine settings, the context parser (missing or malformed context: 500),
// engine-off and inspection-limit hooks, the grouped exclusion hooks, CRS
// and the per-set scoring. auditLog is the audit log file (absolute).
func RenderDynamicWAFRules(release *DynamicWAFRelease, auditLog string) ([]byte, error) {
	return RenderDynamicWAFRulesTuned(release, auditLog, nil)
}

// RenderDynamicWAFRulesTuned is RenderDynamicWAFRules with the official CRS
// tuning entries of the node (ADR 0011 §6.1, the system/crs-tuning pack the
// node holds; rulepack.TuningEntries), ascending by entry number. Without
// entries the file is RenderDynamicWAFRules' byte for byte.
func RenderDynamicWAFRulesTuned(release *DynamicWAFRelease, auditLog string, tuning []CRSTuningEntry) ([]byte, error) {
	if release == nil || !gatePathPattern.MatchString(auditLog) || strings.Contains(auditLog, "/../") ||
		len(tuning) > DynamicWAFMaxTuningEntries {
		return nil, ErrInvalidConfig
	}
	for index, entry := range tuning {
		if entry.ID < 1 || entry.ID > 999999 || ValidateCRSTuning(entry.CRSTuning) != nil ||
			index > 0 && tuning[index-1].ID >= entry.ID {
			return nil, ErrInvalidConfig
		}
	}
	sets := map[string]resolvedManagedSet{}
	for _, profile := range release.profiles {
		for _, set := range profile.sets {
			sets[set.Key] = set
		}
	}
	exports := release.Exports()
	if len(exports) > 9999 {
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
	if len(keys) > dynamicWAFMaxSetKeys {
		return nil, ErrInvalidConfig
	}
	var output strings.Builder
	output.WriteString("# Generated by edgeconfig: OWASP CRS " + release.manifest.Version + " on libmodsecurity, cdnca dynamic routing (shared servers).\n")
	output.WriteString("SecRuleEngine On\nSecRequestBodyAccess On\nSecResponseBodyAccess Off\n")
	output.WriteString("SecArgumentSeparator &\nSecCookieFormat 0\n")
	// Audit engine Off: phase 5 turns it on per transaction (ADR 0011 PoC-2).
	output.WriteString("SecStatusEngine Off\nSecAuditEngine Off\n")
	output.WriteString("SecAuditLogParts ABHZ\nSecAuditLogType Serial\nSecAuditLogFormat JSON\n")
	fmt.Fprintf(&output, "SecAuditLog %s\n", auditLog)
	output.WriteString("SecDefaultAction \"phase:1,log,auditlog,pass\"\nSecDefaultAction \"phase:2,log,auditlog,pass\"\n")
	fmt.Fprintf(&output, "SecAction \"id:900990,phase:1,pass,t:none,nolog,setvar:tx.crs_setup_version=%s\"\n", release.manifest.SetupVersion())
	// The site context (DynamicWAFContext). Nothing below reads a request
	// header for it: a client cannot forge it.
	id := dynamicWAFContextID
	next := func() int { id++; return id - 1 }
	// c3, two patterns (DynamicWAFContextRules): the first checks the whole
	// context, the second captures the list segments; a context the first
	// refuses sets nothing and the next rule answers 500.
	fmt.Fprintf(&output, "SecRule UNIQUE_ID \"@rx %s\" \"id:%d,phase:1,pass,nolog,t:none,capture,"+
		"setvar:tx.cdnca_site=%%{TX.1},setvar:tx.cdnca_inspection=%%{TX.2},setvar:tx.cdnca_engine=%%{TX.3},"+
		"setvar:tx.cdnca_grey_passed=%%{TX.4},setvar:tx.cdnca_browser=%%{TX.5},setvar:tx.cdnca_intel=%%{TX.6},"+
		"setvar:tx.cdnca_detect=%%{TX.7},setvar:tx.cdnca_grey_floor=%%{TX.8}\"\n", DynamicWAFContextRules[0], next())
	fmt.Fprintf(&output, "SecRule &TX:cdnca_site \"@eq 1\" \"id:%d,phase:1,pass,nolog,t:none,chain\"\n", next())
	fmt.Fprintf(&output, "  SecRule UNIQUE_ID \"@rx %s\" \"t:none,capture,setvar:tx.cdnca_tighten=%%{TX.1},"+
		"setvar:tx.cdnca_tuning_off=%%{TX.2},setvar:tx.cdnca_exclude=%%{TX.3}\"\n", DynamicWAFContextRules[1])
	fmt.Fprintf(&output, "SecRule &TX:cdnca_exclude \"@eq 0\" \"id:%d,phase:1,deny,status:500,log,t:none,msg:'cdnca waf: missing or malformed site context'\"\n", next())
	// Allow CIDRs: the engine is off for the request (v7 renderManagedWAFSite
	// ctl:ruleEngine=Off).
	fmt.Fprintf(&output, "SecRule TX:cdnca_engine \"@streq 0\" \"id:%d,phase:1,pass,nolog,t:none,ctl:ruleEngine=Off\"\n", next())
	fmt.Fprintf(&output, "SecRule TX:cdnca_inspection \"@streq b\" \"id:%d,phase:1,pass,nolog,t:none,setvar:tx.cdnca_inspection_limit_mode=block\"\n", next())
	fmt.Fprintf(&output, "SecRule TX:cdnca_inspection \"@streq l\" \"id:%d,phase:1,pass,nolog,t:none,setvar:tx.cdnca_inspection_limit_mode=log\"\n", next())
	// Request-body parsing and parser hardening, as v7's node file.
	fmt.Fprintf(&output, "SecRule REQUEST_HEADERS:Content-Type \"@rx ^(?:application(?:/soap\\+|/)|text/)xml\" \"id:%d,phase:1,pass,nolog,t:none,t:lowercase,ctl:requestBodyProcessor=XML\"\n", next())
	fmt.Fprintf(&output, "SecRule REQUEST_HEADERS:Content-Type \"@rx ^application/(?:[a-z0-9.+-]+\\+)?json\" \"id:%d,phase:1,pass,nolog,t:none,t:lowercase,ctl:requestBodyProcessor=JSON\"\n", next())
	fmt.Fprintf(&output, "SecRule &ARGS \"@ge %%{tx.cdnca_arguments_limit}\" \"id:%d,phase:2,deny,status:400,log,t:none,msg:'cdnca waf: too many arguments'\"\n", next())
	fmt.Fprintf(&output, "SecRule REQBODY_ERROR \"!@eq 0\" \"id:%d,phase:2,deny,status:400,log,msg:'cdnca waf: request body could not be parsed',logdata:'%%{reqbody_error_msg}'\"\n", next())
	fmt.Fprintf(&output, "SecRule MULTIPART_STRICT_ERROR \"!@eq 0\" \"id:%d,phase:2,deny,status:400,log,msg:'cdnca waf: multipart body failed strict validation'\"\n", next())
	fmt.Fprintf(&output, "SecRule MULTIPART_UNMATCHED_BOUNDARY \"@eq 1\" \"id:%d,phase:2,deny,status:400,log,msg:'cdnca waf: multipart unmatched boundary'\"\n", next())
	fmt.Fprintf(&output, "SecRule TX:cdnca_inspection_limit_mode \"@streq block\" \"id:%d,phase:2,deny,status:403,log,t:none,msg:'cdnca waf: inspection limit hit %%{MATCHED_VAR_NAME}',chain\"\n", next())
	output.WriteString("  SecRule TX:/^MSC_/ \"!@streq 0\" \"t:none\"\n")
	fmt.Fprintf(&output, "SecRule TX:cdnca_inspection_limit_mode \"@streq log\" \"id:%d,phase:2,pass,log,t:none,msg:'cdnca waf: inspection limit hit (log only) %%{MATCHED_VAR_NAME}',chain\"\n", next())
	output.WriteString("  SecRule TX:/^MSC_/ \"!@streq 0\" \"t:none\"\n")
	// Exclusions, grouped by rule family (PoC section 5: a family guard
	// skips that family's hooks when the site excludes none of its rules).
	id = dynamicWAFExclusionID
	families := map[string][]int{}
	familyOrder := []string{}
	for _, rule := range exports {
		family := strconv.Itoa(rule)[:4]
		if _, seen := families[family]; !seen {
			familyOrder = append(familyOrder, family)
		}
		families[family] = append(families[family], rule)
	}
	for _, family := range familyOrder {
		fmt.Fprintf(&output, "SecRule TX:cdnca_exclude \"!@contains ,%s\" \"id:%d,phase:1,pass,nolog,t:none,skipAfter:CDNCA-EX-%s\"\n", family, next(), family)
		for _, rule := range families[family] {
			fmt.Fprintf(&output, "SecRule TX:cdnca_exclude \"@contains ,%d,\" \"id:%d,phase:1,pass,nolog,t:none,ctl:ruleRemoveById=%d\"\n", rule, next(), rule)
		}
		fmt.Fprintf(&output, "SecMarker \"CDNCA-EX-%s\"\n", family)
	}
	renderDynamicWAFTuning(&output, tuning)
	for _, file := range crsBaseFiles {
		fmt.Fprintf(&output, "Include %s/%s\n", crsRulesDir, file)
	}
	ordered := make([]string, 0, len(files))
	for file := range files {
		ordered = append(ordered, file)
	}
	sort.Strings(ordered)
	for _, file := range ordered {
		fmt.Fprintf(&output, "Include %s/%s\n", crsRulesDir, file)
	}
	byDigest := map[string]resolvedCRSProfile{}
	for _, profile := range release.profiles {
		byDigest[profile.Ref.SHA256] = profile
	}
	renderManagedSetScoring(&output, release.manifest.Rules, files, owner, setsOf(byDigest))
	// Detector signals (DynamicWAFDetectors): only a tier whose set scores
	// in two levels has its weak threshold above 0 (标准防护 never).
	for position, detector := range DynamicWAFDetectors {
		if _, used := sets[detector.Set]; !used {
			continue
		}
		tx := managedSetTX(detector.Set)
		fmt.Fprintf(&output, "SecRule TX:cdnca_detect \"@contains ,%s,\" \"id:%d,phase:2,pass,log,auditlog,t:none,"+
			"msg:'cdnca waf detector %s',tag:'cdnca/%s',chain\"\n", detector.Name, dynamicWAFDetectID+position, detector.Name, detector.Set)
		fmt.Fprintf(&output, "  SecRule TX:cdnca_%s_weak_threshold \"@gt 0\" \"t:none,setvar:'tx.cdnca_%s_score=+%d'\"\n",
			tx, tx, dynamicWAFDetectorScore)
	}
	// Adaptive WAF before the decisions (ADR 0011 3.1), only for a tier
	// whose set scores in two levels (weak threshold above 0; 标准防护 never):
	//   - k=: a tightened set's weak sum scores as strong;
	//   - shape (d=): the shape signal's weak score (5) on every two-level
	//     set: alone below the weak threshold, with one critical weak hit
	//     at it (two independent signals agree);
	//   - grey zone: max(1, f=) <= strong + weak, strong below the threshold
	//     (the total below the weak threshold is what passes the decision).
	for position, key := range keys {
		tx := managedSetTX(key)
		base := dynamicWAFAdaptID + position*8
		// shape first: on a tightened set it then scores strong as well
		fmt.Fprintf(&output, "SecRule TX:cdnca_detect \"@contains ,%s,\" \"id:%d,phase:2,pass,log,auditlog,t:none,msg:'cdnca waf shape %s',tag:'cdnca/%s',chain\"\n",
			DynamicWAFShape, base+1, key, key)
		fmt.Fprintf(&output, "  SecRule TX:cdnca_%s_weak_threshold \"@gt 0\" \"t:none,setvar:'tx.cdnca_%s_weak=+%d'\"\n", tx, tx, dynamicWAFShapeScore)
		renderDynamicWAFUpgradeClamp(&output, "cdnca_tighten", strings.TrimPrefix(key, "waf_set:"), tx, dynamicWAFUpgradeID+position*2)
		fmt.Fprintf(&output, "SecRule TX:cdnca_tighten \"@contains ,%s,\" \"id:%d,phase:2,pass,nolog,t:none,chain\"\n",
			strings.TrimPrefix(key, "waf_set:"), base)
		fmt.Fprintf(&output, "  SecRule TX:cdnca_%s_weak_threshold \"@gt 0\" \"t:none,setvar:'tx.cdnca_%s_score=+%%{tx.cdnca_%s_weak}',"+
			"setvar:tx.cdnca_%s_weak=0\"\n", tx, tx, tx, tx)
	}
	// d=repeat (DynamicWAFRepeat): a repeated grey zone source's weak sums
	// score as strong on every two-level set, after shape and k= (a
	// tightened set's weak sum is 0 by then); like k=, at no less than the
	// strong threshold (renderDynamicWAFUpgradeClamp)
	for position, key := range keys {
		tx := managedSetTX(key)
		renderDynamicWAFUpgradeClamp(&output, "cdnca_detect", DynamicWAFRepeat, tx, dynamicWAFUpgradeID+position*2+1)
		fmt.Fprintf(&output, "SecRule TX:cdnca_detect \"@contains ,%s,\" \"id:%d,phase:2,pass,nolog,t:none,chain\"\n",
			DynamicWAFRepeat, dynamicWAFRepeatID+position)
		fmt.Fprintf(&output, "  SecRule TX:cdnca_%s_weak_threshold \"@gt 0\" \"t:none,setvar:'tx.cdnca_%s_score=+%%{tx.cdnca_%s_weak}',"+
			"setvar:tx.cdnca_%s_weak=0\"\n", tx, tx, tx, tx)
	}
	// Sets a request's profile does not use have no mode: they never fire.
	for position, key := range keys {
		renderManagedSetEvaluation(&output, key, dynamicWAFSetID+position*2, dynamicWAFSetID+500+position*3)
	}
	// After the decisions a request still here passed every set; a set with
	// a score is its grey zone. tx.cdnca_grey counts the request's grey sets,
	// tx.cdnca_grey_challenge those whose tier challenges (grey_action
	// challenge: tx.cdnca_<set>_grey, RenderDynamicWAFTier).
	for position, key := range keys {
		tx := managedSetTX(key)
		base := dynamicWAFAdaptID + position*8
		// (a log mode set passes at any score: only below both lines is grey)
		grey := fmt.Sprintf("  SecRule TX:cdnca_%[1]s_total \"@gt 0\" \"t:none,chain\"\n"+
			"  SecRule TX:cdnca_%[1]s_total \"@ge %%{tx.cdnca_grey_floor}\" \"t:none,chain\"\n"+
			"  SecRule TX:cdnca_%[1]s_total \"@lt %%{tx.cdnca_%[1]s_weak_threshold}\" \"t:none,chain\"\n"+
			"  SecRule TX:cdnca_%[1]s_score \"@lt %%{tx.cdnca_%[1]s_threshold}\" \"t:none,", tx)
		// log (no auditlog): the transaction keeps the message, which
		// $modsecurity_rule_ids names for the source count (DynamicWAFRepeat);
		// the audit sampling below is unchanged
		fmt.Fprintf(&output, "SecRule TX:cdnca_%s_weak_threshold \"@gt 0\" \"id:%d,phase:2,pass,log,t:none,msg:'cdnca waf grey %s',chain\"\n%ssetvar:tx.cdnca_grey=+1\"\n",
			tx, base+3, key, grey)
		fmt.Fprintf(&output, "SecRule TX:cdnca_%s_grey \"@eq 1\" \"id:%d,phase:2,pass,nolog,t:none,chain\"\n%ssetvar:tx.cdnca_grey_challenge=+1\"\n",
			tx, base+4, grey)
		// a log mode set (仅记录) records every scored request in full, as
		// RelevantOnly did before (its messages carry auditlog)
		for offset, sum := range []string{"score", "weak"} {
			fmt.Fprintf(&output, "SecRule TX:cdnca_%[1]s_mode \"@streq log\" \"id:%[2]d,phase:2,pass,nolog,t:none,chain\"\n"+
				"  SecRule TX:cdnca_%[1]s_%[3]s \"@gt 0\" \"t:none,setvar:tx.cdnca_decided=1\"\n", tx, base+5+offset, sum)
		}
	}
	// A set's decision (block, or log at a line) is audited in full: phase 5
	// runs after a denial too (PoC-2), and the sums are still there.
	for position, key := range keys {
		tx := managedSetTX(key)
		fmt.Fprintf(&output, "SecRule TX:cdnca_%[1]s_score \"@ge %%{tx.cdnca_%[1]s_threshold}\" \"id:%[2]d,phase:5,pass,nolog,t:none,chain\"\n"+
			"  SecRule TX:cdnca_%[1]s_threshold \"@gt 0\" \"t:none,setvar:tx.cdnca_decided=1\"\n", tx, dynamicWAFAdaptID+position*8+7)
		fmt.Fprintf(&output, "SecRule TX:cdnca_%[1]s_weak_threshold \"@gt 0\" \"id:%[2]d,phase:5,pass,nolog,t:none,chain\"\n"+
			"  SecRule TX:cdnca_%[1]s_total \"@ge %%{tx.cdnca_%[1]s_weak_threshold}\" \"t:none,setvar:tx.cdnca_decided=1\"\n",
			tx, dynamicWAFAdaptID+position*8+2)
	}
	// Grey zone challenge (PoC-3): a browser-like request without a valid
	// challenge cookie is denied with DynamicWAFChallengeStatus, which the
	// skeleton's error_page serves as the WAF challenge; an API-like one,
	// or one that passed the challenge, goes on. A strong score never
	// reaches here (denied above), so the challenge never relaxes it.
	fmt.Fprintf(&output, "SecRule TX:cdnca_grey_challenge \"@gt 0\" \"id:%d,phase:2,deny,status:%d,log,auditlog,t:none,"+
		"msg:'cdnca waf grey zone challenge',tag:'cdnca/grey_challenge',chain\"\n", dynamicWAFChallengeID, DynamicWAFChallengeStatus)
	output.WriteString("  SecRule TX:cdnca_grey_passed \"@streq 0\" \"t:none,chain\"\n")
	output.WriteString("  SecRule TX:cdnca_browser \"@streq 1\" \"t:none\"\n")
	// Audit (PoC-2): the engine is Off; a denied transaction is written in
	// full, a grey zone one when its ID ends in DynamicWAFSampleDigit (1/16),
	// parts A and H only (rule IDs and variable names; the agent drops the
	// values the messages quote).
	fmt.Fprintf(&output, "SecRule TX:cdnca_grey \"@gt 0\" \"id:%d,phase:5,pass,nolog,t:none,chain\"\n", dynamicWAFSampleID)
	fmt.Fprintf(&output, "  SecRule UNIQUE_ID \"@rx %s$\" \"t:none,ctl:auditEngine=On,ctl:auditLogParts=-B\"\n", DynamicWAFSampleDigit)
	fmt.Fprintf(&output, "SecRule TX:cdnca_decided \"@eq 1\" \"id:%d,phase:5,pass,nolog,t:none,ctl:auditEngine=On\"\n", dynamicWAFSampleID+1)
	// other refusals and origin errors, as RelevantOnly before (a grey zone
	// one, the challenge page included, only when sampled above)
	fmt.Fprintf(&output, "SecRule RESPONSE_STATUS \"@rx ^(?:5|4(?!04))\" \"id:%d,phase:5,pass,nolog,t:none,chain\"\n", dynamicWAFSampleID+2)
	output.WriteString("  SecRule &TX:cdnca_grey \"@eq 0\" \"t:none,ctl:auditEngine=On\"\n")
	return []byte(output.String()), nil
}

// renderDynamicWAFTuning renders the official CRS tuning entries (ADR 0011
// §6.1): each removes literal targets of one CRS rule
// (ctl:ruleRemoveTargetById=<rule>;ARGS|REQUEST_COOKIES|REQUEST_HEADERS:<name>,
// exact names, PoC-1) on tiers whose paranoia is at least the entry's
// min_paranoia (the tier file sets tx.blocking_paranoia_level in phase 1
// before these rules: RenderDynamicWAFTier). Sections by min_paranoia, then
// blocks of at most dynamicWAFTuningBatch targets: a block none of whose
// entries the site disables (context u=, an @pm over the block's entry
// numbers) applies in one rule; otherwise entry by entry.
// DynamicWAFTuningAllOff in u= (the site has no tuning pack mounted) skips
// everything. libmodsecurity scans the transaction's removed-target list
// for every rule and value, so only entries of the request's tier are
// pushed.
func renderDynamicWAFTuning(output *strings.Builder, tuning []CRSTuningEntry) {
	if len(tuning) == 0 {
		return
	}
	id := dynamicWAFTuningID
	next := func() int { id++; return id - 1 }
	ctls := func(entry CRSTuningEntry) []string {
		out := make([]string, 0, len(entry.Targets))
		for _, target := range entry.Targets {
			out = append(out, fmt.Sprintf("ctl:ruleRemoveTargetById=%d;%s:%s", entry.Rule,
				dynamicWAFTargetCollections[target.Location], target.Name))
		}
		return out
	}
	fmt.Fprintf(output, "SecRule TX:cdnca_tuning_off \"@contains ,%d,\" \"id:%d,phase:1,pass,nolog,t:none,skipAfter:CDNCA-TU-END\"\n",
		DynamicWAFTuningAllOff, next())
	block := 0
	for paranoia := 1; paranoia <= 4; paranoia++ {
		var section []CRSTuningEntry
		for _, entry := range tuning {
			if entry.MinParanoia == paranoia {
				section = append(section, entry)
			}
		}
		if len(section) == 0 {
			continue
		}
		// sections ascend: a tier below this one is below every later one
		fmt.Fprintf(output, "SecRule TX:blocking_paranoia_level \"@lt %d\" \"id:%d,phase:1,pass,nolog,t:none,skipAfter:CDNCA-TU-END\"\n",
			paranoia, next())
		for start := 0; start < len(section); {
			end, targets := start, 0
			for end < len(section) && targets+len(section[end].Targets) <= dynamicWAFTuningBatch {
				targets += len(section[end].Targets)
				end++
			}
			numbers, all := make([]string, 0, end-start), []string{}
			for _, entry := range section[start:end] {
				numbers = append(numbers, ","+strconv.Itoa(entry.ID)+",")
				all = append(all, ctls(entry)...)
			}
			block++
			fmt.Fprintf(output, "SecRule TX:cdnca_tuning_off \"!@pm %s\" \"id:%d,phase:1,pass,nolog,t:none,%s,skipAfter:CDNCA-TU-%d\"\n",
				strings.Join(numbers, " "), next(), strings.Join(all, ","), block)
			for _, entry := range section[start:end] {
				fmt.Fprintf(output, "SecRule TX:cdnca_tuning_off \"!@contains ,%d,\" \"id:%d,phase:1,pass,nolog,t:none,%s\"\n",
					entry.ID, next(), strings.Join(ctls(entry), ","))
			}
			fmt.Fprintf(output, "SecMarker \"CDNCA-TU-%d\"\n", block)
			start = end
		}
	}
	output.WriteString("SecMarker \"CDNCA-TU-END\"\n")
}

// renderDynamicWAFCookieWeak: a weak rule (a two-level set's heuristic above
// StrongParanoia) of the tier does not inspect cookies (waf-cookie-fp: on
// real traffic consent, analytics and session cookies, URL-encoded JSON
// mostly, filled the weak sums of 严格防护 and above; 38% false positives,
// 99.7% of those from cookies). Cookies still get every strong rule (PL1,
// the same in 标准防护) and the structural detectors on their decoded values
// (d=, cdnca_waf detect_args); the tier's cookie variant
// (RenderDynamicWAFTierCookies) keeps them for a cookie out of the site's
// profile. A one-level set has no weak rule, so 标准防护 is unchanged. In the
// tier file, not the node rules: ModSecurity merges a location's rule
// exceptions with its parent's and applies them by rule ID.
func renderDynamicWAFCookieWeak(output *strings.Builder, rules []CRSRule, sets []resolvedManagedSet) {
	weak := map[int]bool{}
	for _, set := range sets {
		for _, rule := range set.Rules {
			if rule.Paranoia <= set.Paranoia && set.weakRule(rule) {
				weak[rule.ID] = true
			}
		}
	}
	for _, rule := range rules {
		if weak[rule.ID] {
			fmt.Fprintf(output, "SecRuleUpdateTargetById %d \"!REQUEST_COOKIES|!REQUEST_COOKIES_NAMES\"\n", rule.ID)
		}
	}
}

// DynamicWAFDigest identifies the node's managed WAF configuration (rule
// file, tier files, CRS text): it changes, and nginx reloads, only when the
// CRS text, a profile pack or the set of tiers changes, never for a site.
func DynamicWAFDigest(files map[string][]byte) string {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	hash := sha256.New()
	for _, name := range names {
		sum := sha256.Sum256(files[name])
		fmt.Fprintf(hash, "%s\x00%x\n", name, sum)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// renderDynamicWAFUpgradeClamp raises an upgraded source's (k=, d=repeat)
// nonzero weak sum to the set's strong threshold right before it scores as
// strong: upgraded, a grey zone hit blocks even when its rules' learned
// weights sum below the threshold (941380: 4 < 5; ADR 0011 3.2a, waf-gap10).
// A request not upgraded keeps its learned weak weights.
func renderDynamicWAFUpgradeClamp(output *strings.Builder, variable, item, tx string, id int) {
	fmt.Fprintf(output, "SecRule TX:cdnca_%[1]s_weak \"@gt 0\" \"id:%[2]d,phase:2,pass,nolog,t:none,chain\"\n"+
		"  SecRule TX:%[3]s \"@contains ,%[4]s,\" \"t:none,chain\"\n"+
		"  SecRule TX:cdnca_%[1]s_weak \"@lt %%{tx.cdnca_%[1]s_threshold}\" \"t:none,setvar:'tx.cdnca_%[1]s_weak=%%{tx.cdnca_%[1]s_threshold}'\"\n",
		tx, id, variable, item)
}
