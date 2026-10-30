package autodefense

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"math/bits"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// Adaptive WAF (ADR 0011 section 3, RI-02): the parameter samples of the
// collection frame, the waf_evidence report, the site's waf_adapt snapshot
// item and the tightening overlay field waf.tighten:<set>. A parameter is
// named as ModSecurity names it (location args | cookie | header, JSON
// leaves json.<path>): the audit record only says ARGS:<name>, and an
// exclusion removes exactly that target (ADR 0011 PoC-1).

const (
	// MaxFrameParamSamples bounds the clean requests sampled per site per
	// second (section 3.6), MaxFrameRequestParams their parameters each.
	MaxFrameParamSamples  = 64
	MaxFrameRequestParams = 16
	// MaxWAFEvidenceItems / MaxWAFEvidenceTighten / MaxWAFEvidenceExclusions
	// bound one waf_evidence report (section 4.1), MaxWAFEvidenceBytes its
	// encoded size: 192 KiB, not the ADR's 32 KiB, so the list bounds at
	// their longest always fit (one item is about 250 bytes, 62 KiB for 128;
	// 32 fragments whose bytes all need \u escapes add 54 KiB; 576 exclusion
	// results at their longest about 62 KiB, waf-exclcap2: 184 093 bytes
	// with every list full; the channel takes 256 KiB).
	MaxWAFEvidenceItems   = 128
	MaxWAFEvidenceTighten = 10
	// MaxWAFEvidenceExclusions is MaxWAFAdaptExclusions: every delivered
	// exclusion's result (a pause above all) fits one report.
	MaxWAFEvidenceExclusions = MaxWAFAdaptExclusions
	MaxWAFEvidenceBytes      = 192 << 10
	// MaxWAFAdaptExclusions bounds a site's exclusions in the snapshot: at
	// most edgeconfig.DynamicWAFMaxTargets active (section 3.4, the safety
	// bound; the node decides how many apply) plus MaxWAFAdaptShadow in
	// shadow; MaxWAFTypedParams its typed parameters (section 3.3).
	MaxWAFAdaptShadow     = 64
	MaxWAFAdaptExclusions = edgeconfig.DynamicWAFMaxTargets + MaxWAFAdaptShadow
	MaxWAFTypedParams     = 32
	// MaxWAFCookieNames bounds a site's known cookie names in the snapshot
	// and the cookies of one waf_evidence report (ri-wire Cookie 名集合). A
	// site with more known names is never cookie mature: an incomplete set
	// would make its own cookies look unseen.
	MaxWAFCookieNames = 64
	// MaxWAFHeaderNames bounds the header samples of one waf_evidence report.
	MaxWAFHeaderNames = 32
	// MaxWAFRuleDays is the day bitmap width (section 3.3 days).
	MaxWAFRuleDays = 16
	// WAFLenBuckets: log2 length buckets 0-7 (WAFLenBucket).
	WAFLenBuckets = 8
)

// ReportWAFEvidence is the hourly adaptive WAF evidence of one site
// (section 4.1): site scope, at most one per site per hour.
const ReportWAFEvidence ReportKind = "waf_evidence"

// WAFValueTypes are the value types of a parameter (section 3.3 type_hist
// order). Only number, ident and binary are ever typed (TypedParam).
var WAFValueTypes = []string{"number", "ident", "text", "json", "binary", "url"}

var wafTypedValueTypes = []string{"binary", "ident", "number"}

// WAFCharsetClasses are the charset bitmap bits (bit = index; section 3.3
// charset): characters a value contained.
var WAFCharsetClasses = []string{"quote", "angle", "paren", "semicolon", "pipe", "backtick", "dollar", "brace",
	"percent_encoded", "space", "control", "non_ascii", "backslash"}

// WAFCharsetMask is every charset bit.
const WAFCharsetMask = 1<<13 - 1

// WAFLenBucket is a value length's bucket: 0 for empty, else
// min(7, bit length of n) (1, 2-3, 4-7, ..., 64 and more).
func WAFLenBucket(length int) int64 {
	return int64(min(WAFLenBuckets-1, bits.Len(uint(length))))
}

// WAFParamKey is a parameter's profile key (section 3.3 key): 16 hex digits,
// the CRC-32 (IEEE, Lua ngx.crc32_long) of the path template, then that of
// "<location>:<name>". template "" is the site level key (high half 0: the
// parameter appears on 4 or more templates).
func WAFParamKey(template, location, name string) string {
	high := uint32(0)
	if template != "" {
		high = crc32.ChecksumIEEE([]byte(template))
	}
	return fmt.Sprintf("%08x%08x", high, crc32.ChecksumIEEE([]byte(location+":"+name)))
}

// QueryNamesHash is FrameSample.query_names_hash: the first 16 hex digits of
// SHA-256 over the distinct query argument names, sorted, joined by "\n"
// ("" when the query has none).
func QueryNamesHash(names []string) string {
	if len(names) == 0 {
		return ""
	}
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	unique := sorted[:1]
	for _, name := range sorted[1:] {
		if name != unique[len(unique)-1] {
			unique = append(unique, name)
		}
	}
	sum := sha256.Sum256([]byte(strings.Join(unique, "\n")))
	return hex.EncodeToString(sum[:8])
}

// WAFParam names one parameter.
type WAFParam struct {
	Location string `json:"loc"` // args | cookie | header
	Name     string `json:"name"`
}

func (param WAFParam) valid() bool {
	_, known := edgeconfig.WAFTargetLocations[param.Location]
	return known && edgeconfig.WAFParamNamePattern.MatchString(param.Name)
}

// FrameParamSample is one sampled clean request (no WAF rule hit, not
// mitigated) of the second: its client network and up to
// MaxFrameRequestParams parameters. Values never enter the frame.
type FrameParamSample struct {
	CIDR   string       `json:"cidr"` // DimCIDR form
	Params []FrameParam `json:"params"`
}

// FrameParam is one parameter observation.
type FrameParam struct {
	Key string `json:"key"` // WAFParamKey with the request's path template
	WAFParam
	Type      string `json:"type"` // WAFValueTypes
	LenBucket int64  `json:"len_bucket"`
	Charset   int64  `json:"charset"`
}

func validFrameParams(samples []FrameParamSample) bool {
	if len(samples) > MaxFrameParamSamples {
		return false
	}
	for _, sample := range samples {
		if !ValidCondition(DimCIDR, sample.CIDR) || len(sample.Params) == 0 || len(sample.Params) > MaxFrameRequestParams {
			return false
		}
		seen := map[WAFParam]bool{}
		for _, param := range sample.Params {
			if !param.valid() || !validParamKey(param.Key, param.WAFParam) || seen[param.WAFParam] || !contains(WAFValueTypes, param.Type) ||
				!validLenBucket(param.LenBucket) || !validCharset(param.Charset) {
				return false
			}
			seen[param.WAFParam] = true
		}
	}
	return true
}

// validParamKey: 16 hex digits whose low half is the parameter's (the high
// half is the path template's, which the receiver cannot check).
func validParamKey(key string, param WAFParam) bool {
	return hash16Pattern.MatchString(key) && key[8:] == WAFParamKey("", param.Location, param.Name)[8:]
}

func validLenBucket(bucket int64) bool { return bucket >= 0 && bucket < WAFLenBuckets }

func validCharset(charset int64) bool { return charset >= 0 && charset <= WAFCharsetMask }

// WAFEvidence is the waf_evidence payload: what the node counted on the
// site in Hour since its previous report (section 3.6). Counts add up
// across reports and nodes; Sources and Days merge by OR.
type WAFEvidence struct {
	Hour int64 `json:"hour"` // Unix seconds, multiple of 3600, not after the report
	// Pack is the CRS profile pack the site ran (rule numbers belong to it).
	Pack       WAFPackRef           `json:"pack"`
	Items      []WAFEvidenceItem    `json:"items"`
	Tighten    []WAFTightenState    `json:"tighten"`
	Exclusions []WAFExclusionResult `json:"exclusions"`
	// Fragments are attack fragments (ADR 0011 section 4.4): only when the
	// snapshot's AttackFragments is on, else omitted.
	Fragments []WAFFragment `json:"fragments,omitempty"`
	// Cookies are the site's cookies in the hour's clean frame samples (at
	// most MaxWAFCookieNames, key order); CookieSamples the clean samples
	// that carried a cookie. The control plane learns the known cookie
	// names, the cookie maturity and the cookies' typed parameters from them.
	Cookies       []WAFCookieSample `json:"cookies,omitempty"`
	CookieSamples int64             `json:"cookie_samples,omitempty"`
	// Headers are the site's non-standard request headers in the hour's
	// clean frame samples (ri-gaps2 A4; at most MaxWAFHeaderNames, key
	// order), as Cookies: the site level key "00000000" + CRC-32 of
	// "header:<lower-case name>". CRS weak rules hardly read custom headers,
	// so evidence items never type them; these samples do (typed headers
	// feed the node's shape check, waf-gap4).
	Headers []WAFCookieSample `json:"headers,omitempty"`
	// Limit is how many of the site's delivered active exclusions apply on
	// this node (waf-exclcap2): omitted when none was delivered.
	Limit *WAFExclusionLimit `json:"limit,omitempty"`
	// Dropped counts items left out to stay in bounds.
	Dropped int64 `json:"dropped"`
}

// WAFExclusionLimit is a node's own bound on a site's active exclusions
// (waf-exclcap2): Delivered active, not paused exclusions of the snapshot;
// Applied the first of them by rank the node renders; LatencyTrimmed left
// out by the latency budget (budget / per exclusion cost), MemoryTrimmed by
// the node memory budget (lowest traffic sites first). CostNanos is the
// node's measured cost of one exclusion on one request (0: not measured
// yet, the default cost applies).
type WAFExclusionLimit struct {
	Delivered      int64 `json:"delivered"`
	Applied        int64 `json:"applied"`
	LatencyTrimmed int64 `json:"latency_trimmed"`
	MemoryTrimmed  int64 `json:"memory_trimmed"`
	CostNanos      int64 `json:"cost_ns"`
}

func validWAFExclusionLimit(limit *WAFExclusionLimit) bool {
	return limit == nil || limit.Delivered > 0 && limit.Delivered <= edgeconfig.DynamicWAFMaxTargets && limit.Applied >= 0 &&
		limit.LatencyTrimmed >= 0 && limit.MemoryTrimmed >= 0 && limit.Applied+limit.LatencyTrimmed+limit.MemoryTrimmed == limit.Delivered &&
		limit.CostNanos >= 0 && limit.CostNanos <= MaxWAFExclusionCostNanos
}

// MaxWAFExclusionCostNanos bounds a reported per exclusion cost (1 ms).
const MaxWAFExclusionCostNanos = 1_000_000

// WAFBudget is the platform's budget for the automatic exclusions of a
// node (系统设置 → WAF 自适应, waf-exclcap2): LatencyMicros the extra time
// one request may pay for its site's exclusions (100..5000 us, default
// 500), MemoryPercent the share of node memory all of them may take
// (1..50, default 5). Only part 1 of a snapshot carries it; nil: defaults.
type WAFBudget struct {
	LatencyMicros int64 `json:"latency_us"`
	MemoryPercent int64 `json:"memory_percent"`
}

// WAF budget bounds and defaults.
const (
	MinWAFLatencyMicros     = 100
	MaxWAFLatencyMicros     = 5000
	DefaultWAFLatencyMicros = 500
	MinWAFMemoryPercent     = 1
	MaxWAFMemoryPercent     = 50
	DefaultWAFMemoryPercent = 5
)

// DefaultWAFBudget is the budget of a snapshot without one.
func DefaultWAFBudget() WAFBudget {
	return WAFBudget{LatencyMicros: DefaultWAFLatencyMicros, MemoryPercent: DefaultWAFMemoryPercent}
}

func validWAFBudget(budget *WAFBudget) bool {
	return budget == nil || budget.LatencyMicros >= MinWAFLatencyMicros && budget.LatencyMicros <= MaxWAFLatencyMicros &&
		budget.MemoryPercent >= MinWAFMemoryPercent && budget.MemoryPercent <= MaxWAFMemoryPercent
}

// WAFCookieSample is one cookie name in the hour's clean samples: Key is
// its site level WAFParamKey ("00000000" + CRC-32 of "cookie:<name>", a
// cookie does not depend on the path); Type the hour's value type when
// every value had it, else "text";
// LenBucket / Charset the highest length bucket and the charset union;
// Seen the samples; Sources their /24 (/48) linear counting bitmap.
type WAFCookieSample struct {
	Key       string `json:"key"`
	Type      string `json:"type"`
	LenBucket int64  `json:"len_bucket"`
	Charset   int64  `json:"charset"`
	Seen      int64  `json:"seen"`
	Sources   string `json:"src"`
}

// WAFCookieKey is a cookie name's site level parameter key.
func WAFCookieKey(name string) string { return WAFParamKey("", "cookie", name) }

// WAFHeaderKey is a request header's site level parameter key (the name
// lower-cased, as the node's Lua and ModSecurity's REQUEST_HEADERS:<name>
// targets compare header names case-insensitively).
func WAFHeaderKey(name string) string { return WAFParamKey("", "header", strings.ToLower(name)) }

// Attack fragments (ADR 0011 section 4.4): of a
// request blocked on a strong signal only (the strong score reached its
// threshold, or a structural detector matched, and the request was
// blocked), the part of the value the rule matched, redacted by the agent
// with libs/entitlement/ruleintel/redact (RedactFragment) before it leaves
// the node. Values of other requests are never reported. This package only
// checks the shape; the control plane and the license service re-check the
// redaction (redact.CleanFragment) and refuse what is not redacted.
const (
	// MaxWAFFragments bounds the fragments of one site per hour (one
	// waf_evidence report), MaxWAFFragmentBytes one fragment in its encoding.
	MaxWAFFragments     = 32
	MaxWAFFragmentBytes = 256
	// WAFFragmentStrong: the strong score reached its threshold; any other
	// signal is a DynamicWAFDetectors name.
	WAFFragmentStrong = "strong"
)

// WAFFragmentLocations are where a fragment was found: the three parameter
// locations, plus path and body (a non form body as a whole) without a
// parameter name.
var WAFFragmentLocations = []string{"args", "body", "cookie", "header", "path"}

// WAFFragmentEncodings: text (valid UTF-8 without control characters but
// tab, LF, CR) or percent (bytes below 0x20, from 0x7f, and '%' as %XX in
// upper case hex, the rest as is; used only when text cannot hold it).
var WAFFragmentEncodings = []string{"percent", "text"}

// WAFFragment is one attack fragment.
type WAFFragment struct {
	Rule     int64  `json:"rule_id"`
	Location string `json:"location"`
	// ParamKey is the parameter name normalized by WAFFragmentParamKey; empty
	// for path and body.
	ParamKey string `json:"param_key,omitempty"`
	Fragment string `json:"fragment"`
	Encoding string `json:"encoding"`
	// Signal is why the request was blocked: WAFFragmentStrong or a detector.
	Signal string `json:"signal"`
}

// WAFFragmentParamKey normalizes a parameter name as the license service's
// rule intel normalizer does (ruleintel/cluster NormalizeParamName): lower
// case, trailing "[]" removed, "[<digits>]" as "[*]", all digit dot
// separated segments as "*".
func WAFFragmentParamKey(name string) string {
	name = strings.ToLower(name)
	for strings.HasSuffix(name, "[]") {
		name = strings.TrimSuffix(name, "[]")
	}
	name = fragmentBracketIndex.ReplaceAllString(name, "[*]")
	parts := strings.Split(name, ".")
	for index, part := range parts {
		if part != "" && strings.Trim(part, "0123456789") == "" {
			parts[index] = "*"
		}
	}
	return strings.Join(parts, ".")
}

var (
	fragmentBracketIndex = regexp.MustCompile(`\[[0-9]+\]`)
	fragmentParamKey     = regexp.MustCompile(`^[a-z0-9_.\[\]*-]{1,64}$`)
)

func validWAFFragment(fragment WAFFragment) bool {
	if fragment.Rule < 900000 || fragment.Rule > 999999 || !contains(WAFFragmentLocations, fragment.Location) ||
		!contains(WAFFragmentEncodings, fragment.Encoding) || fragment.Fragment == "" || len(fragment.Fragment) > MaxWAFFragmentBytes {
		return false
	}
	if fragment.Signal != WAFFragmentStrong && !slices.ContainsFunc(edgeconfig.DynamicWAFDetectors,
		func(detector struct{ Name, Set string }) bool { return detector.Name == fragment.Signal }) {
		return false
	}
	if named := fragment.Location != "path" && fragment.Location != "body"; named !=
		(fragmentParamKey.MatchString(fragment.ParamKey) && WAFFragmentParamKey(fragment.ParamKey) == fragment.ParamKey) ||
		!named && fragment.ParamKey != "" {
		return false
	}
	for index := 0; index < len(fragment.Fragment); index++ {
		b := fragment.Fragment[index]
		control := b < 0x20 && b != '\t' && b != '\n' && b != '\r' || b == 0x7f
		if fragment.Encoding == "percent" && (b < 0x20 || b >= 0x7f) || fragment.Encoding == "text" && control {
			return false
		}
	}
	return fragment.Encoding == "percent" || utf8.ValidString(fragment.Fragment)
}

// wafFragmentLess is the canonical order: rule, location, parameter key,
// fragment, encoding (signal is not part of the identity: a duplicate is
// refused).
func wafFragmentLess(a, b WAFFragment) bool {
	return cmp.Or(cmp.Compare(a.Rule, b.Rule), cmp.Compare(a.Location, b.Location), cmp.Compare(a.ParamKey, b.ParamKey),
		cmp.Compare(a.Fragment, b.Fragment), cmp.Compare(a.Encoding, b.Encoding)) < 0
}

type WAFPackRef struct {
	PackID  string `json:"pack_id"`
	Version string `json:"version"`
}

// WAFEvidenceItem is one (parameter key, rule) of the profile with its
// counts (section 4.1 items; no value, body, cookie value, address, user
// agent or path).
type WAFEvidenceItem struct {
	Key   string   `json:"key"` // WAFParamKey (site level: high half 0)
	Param WAFParam `json:"param"`
	// Type, LenBucket, Charset: the parameter's dominant type, highest length
	// bucket and charset union on clean samples.
	Type      string `json:"type"`
	LenBucket int64  `json:"len_bucket"`
	Charset   int64  `json:"charset"`
	Rule      int64  `json:"rule"`
	Hits      int64  `json:"hits"`
	// Sources: the 64 bit linear counting bitmap of the source /24 (/48)
	// hashes of the hits, 16 hex digits.
	Sources string `json:"src"`
	// Days: bit d = the rule hit the parameter d days before Hour's day.
	Days int64 `json:"days"`
	// Challenged / Passed: grey zone hits that were challenged / carried a
	// valid challenge cookie (g=1); FailedSources: challenged sources with no
	// pass within 30 seconds; Clean: hits with no strong score, detector,
	// other rule, mitigation or origin error; AttackAfter: hits whose source
	// had a strong score, detector hit, failed challenge or L2+ verdict
	// within 10 minutes.
	Challenged    int64 `json:"challenged"`
	Passed        int64 `json:"passed"`
	FailedSources int64 `json:"failed_src"`
	Clean         int64 `json:"clean"`
	AttackAfter   int64 `json:"attack_after"`
	// StageHint: candidate = the node's own counts meet the candidate
	// conditions (section 3.4); observe otherwise.
	StageHint string `json:"stage_hint"`
}

// WAFTightenState is a set the node tightened (section 3.5), reason
// attack_ratio (hit rate >= 10x the baseline under attack) or
// challenge_failed (>= 80% failed challenges for 5 minutes).
type WAFTightenState struct {
	Set    string `json:"set"` // set key without "waf_set:"
	Reason string `json:"reason"`
	Since  int64  `json:"since"`
}

// WAFExclusionResult is what a snapshot exclusion did on the node in the
// hour: Flipped requests it let through that the rule would have blocked or
// challenged, AttackAfter of them followed by an attack signal; Paused: the
// node suspended it (automatic revocation, section 3.4) and asks the
// control plane to revoke it.
type WAFExclusionResult struct {
	ID          string `json:"exclusion_id"`
	Flipped     int64  `json:"flipped"`
	AttackAfter int64  `json:"attack_after"`
	Paused      bool   `json:"paused,omitempty"`
}

var wafTightenReasons = []string{"attack_ratio", "challenge_failed"}

// crsPackIDPattern / packVersionPattern are edgeconfig's CRS profile
// reference patterns (crsProfilePackID, crsProfileVersion).
var (
	crsPackIDPattern   = regexp.MustCompile(`^system/crs-[a-z0-9][a-z0-9-]{0,59}$`)
	packVersionPattern = regexp.MustCompile(`^[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}$`)
)

func validWAFSetName(set string) bool {
	return slugPattern.MatchString(set) && len(set) <= 64
}

func validWAFEvidence(evidence WAFEvidence, at int64) bool {
	if !validTime(evidence.Hour, false) || evidence.Hour%3600 != 0 || evidence.Hour > at ||
		!crsPackIDPattern.MatchString(evidence.Pack.PackID) || !packVersionPattern.MatchString(evidence.Pack.Version) ||
		evidence.Items == nil || evidence.Tighten == nil || evidence.Exclusions == nil ||
		len(evidence.Items) > MaxWAFEvidenceItems || len(evidence.Tighten) > MaxWAFEvidenceTighten ||
		len(evidence.Exclusions) > MaxWAFEvidenceExclusions || !validInt(evidence.Dropped) ||
		(len(evidence.Items)+len(evidence.Tighten)+len(evidence.Exclusions)+len(evidence.Fragments)+len(evidence.Cookies)+len(evidence.Headers) == 0 &&
			evidence.Limit == nil) || !validWAFExclusionLimit(evidence.Limit) ||
		(evidence.Fragments != nil && len(evidence.Fragments) == 0) || len(evidence.Fragments) > MaxWAFFragments ||
		(evidence.Cookies != nil && len(evidence.Cookies) == 0) || len(evidence.Cookies) > MaxWAFCookieNames ||
		!validInt(evidence.CookieSamples) || (len(evidence.Cookies) > 0) != (evidence.CookieSamples > 0) {
		return false
	}
	for index, cookie := range evidence.Cookies {
		if !hash16Pattern.MatchString(cookie.Key) || cookie.Key[:8] != "00000000" || !contains(WAFValueTypes, cookie.Type) ||
			!validLenBucket(cookie.LenBucket) || !validCharset(cookie.Charset) || cookie.Seen <= 0 || cookie.Seen > evidence.CookieSamples ||
			!hash16Pattern.MatchString(cookie.Sources) || (index > 0 && evidence.Cookies[index-1].Key >= cookie.Key) {
			return false
		}
	}
	if (evidence.Headers != nil && len(evidence.Headers) == 0) || len(evidence.Headers) > MaxWAFHeaderNames {
		return false
	}
	for index, header := range evidence.Headers {
		if !hash16Pattern.MatchString(header.Key) || header.Key[:8] != "00000000" || !contains(WAFValueTypes, header.Type) ||
			!validLenBucket(header.LenBucket) || !validCharset(header.Charset) || header.Seen <= 0 || !validInt(header.Seen) ||
			!hash16Pattern.MatchString(header.Sources) || (index > 0 && evidence.Headers[index-1].Key >= header.Key) {
			return false
		}
	}
	for index, fragment := range evidence.Fragments {
		if !validWAFFragment(fragment) || (index > 0 && !wafFragmentLess(evidence.Fragments[index-1], fragment)) {
			return false
		}
	}
	for index, item := range evidence.Items {
		if !item.Param.valid() || !validParamKey(item.Key, item.Param) ||
			!contains(WAFValueTypes, item.Type) || !validLenBucket(item.LenBucket) || !validCharset(item.Charset) ||
			item.Rule < 900000 || item.Rule > 999999 || item.Hits <= 0 || !validInt(item.Hits) || !hash16Pattern.MatchString(item.Sources) ||
			item.Days <= 0 || item.Days >= 1<<MaxWAFRuleDays ||
			(item.StageHint != "observe" && item.StageHint != "candidate") {
			return false
		}
		for _, count := range []int64{item.Challenged, item.Passed, item.FailedSources, item.Clean, item.AttackAfter} {
			if !validInt(count) || count > item.Hits {
				return false
			}
		}
		if item.FailedSources > item.Challenged {
			return false
		}
		if index > 0 {
			previous := evidence.Items[index-1]
			if previous.Key > item.Key || previous.Key == item.Key && previous.Rule >= item.Rule {
				return false
			}
		}
	}
	for index, state := range evidence.Tighten {
		if !validWAFSetName(state.Set) || !contains(wafTightenReasons, state.Reason) || !validTime(state.Since, false) ||
			state.Since > at || (index > 0 && evidence.Tighten[index-1].Set >= state.Set) {
			return false
		}
	}
	for index, result := range evidence.Exclusions {
		if !hash16Pattern.MatchString(result.ID) || !validInt(result.Flipped) || !validInt(result.AttackAfter) ||
			result.AttackAfter > result.Flipped || (index > 0 && evidence.Exclusions[index-1].ID >= result.ID) {
			return false
		}
	}
	return true
}

// WAFAdapt is a site's adaptive WAF state from the control plane (section
// 3.10): the grey zone challenge switch, the automatic exclusions and the
// typed parameters. Tightening is the node's own (overlay items
// waf.tighten:<set> of the waf module), never here.
type WAFAdapt struct {
	// GreyChallenge: the site's grey zone challenge (inherit / on / off
	// resolved by the control plane); only a 严格防护 or 极严格防护 tier
	// challenges, whatever this says.
	GreyChallenge bool `json:"grey_challenge"`
	// GreyFloor is the site's grey zone floor (context f=, 0 = none): a set
	// is in its grey zone only from this total score up. The control plane
	// sets it from a matured site profile (GreyFloorFromP99); blocking is
	// never affected.
	GreyFloor   int             `json:"grey_floor,omitempty"`
	Exclusions  []WAFExclusion  `json:"exclusions,omitempty"`
	TypedParams []WAFTypedParam `json:"typed_params,omitempty"`
	// CookieMature: the site's cookie profile is mature (enough clean
	// samples over enough days, every known name fits in CookieNames); then
	// a request carrying a cookie name out of CookieNames enters the tier's
	// cookie variant (its weak rules read cookies), as a typed cookie out of
	// shape does. CookieNames: the low halves (8 hex, CRC-32 of
	// "cookie:<name>") of the known cookie names, ascending; only when
	// mature.
	CookieMature bool     `json:"cookie_mature,omitempty"`
	CookieNames  []string `json:"cookie_names,omitempty"`
	// RepeatThreshold / RepeatWindow: the site's repeated grey zone source
	// threshold and window seconds (both set or both 0 = the node constants
	// edgeconfig.DynamicWAFRepeatThreshold / Window). The control plane sets
	// them only for a node that declares CAPABILITY_NAME_WAF_REPEAT_SITE
	// (earlier agents refuse unknown fields).
	RepeatThreshold int `json:"repeat_threshold,omitempty"`
	RepeatWindow    int `json:"repeat_window,omitempty"`
}

// GreyFloorProfile is what a site profile says about its normal requests'
// grey zone scores (RI-04 supplies it): how many normal requests (no rule
// hit decided, not mitigated) it has seen, whether it is mature (ADR 0011
// 3.3), and the p99 of their highest per set weak score (strong + weak of
// the set with the largest total, 0 when none scored).
type GreyFloorProfile struct {
	Mature   bool
	Requests int64
	WeakP99  int
}

// MinGreyFloorRequests is the fewest normal requests a profile's p99 is
// taken from (below it a few odd requests decide the tail).
const MinGreyFloorRequests = 10000

// GreyFloorFromP99 is a site's grey zone floor (WAFAdapt.GreyFloor): one
// above the p99 of its normal requests' weak scores once the profile is
// mature, so 99 % of them are not challenged, capped at weakThreshold-1
// (the floor never reaches the block line; at most a set's whole grey zone
// is skipped) and at edgeconfig.DynamicWAFMaxGreyFloor. 0 (the tier's own
// grey zone) while the profile is not mature, has too few requests or its
// p99 is 0. weakThreshold is the tier's (10 for 严格防护 and 极严格防护).
func GreyFloorFromP99(profile GreyFloorProfile, weakThreshold int) int {
	if !profile.Mature || profile.Requests < MinGreyFloorRequests || profile.WeakP99 <= 0 || weakThreshold <= 1 {
		return 0
	}
	return min(profile.WeakP99+1, weakThreshold-1, edgeconfig.DynamicWAFMaxGreyFloor)
}

// WAFExclusion stages (section 3.4).
const (
	WAFExclusionShadow = "shadow"
	WAFExclusionActive = "active"
)

// WAFExclusion is one site x parameter x rule exclusion. An active one is
// in the site's exclusion bucket (edgeconfig.RenderDynamicWAFBucket) from Since
// to Until (the agent renders ActiveTargets at each reload and reloads
// when the set changes, section 3.9); a shadow one only counts what it
// would flip.
type WAFExclusion struct {
	ID    string   `json:"id"` // WAFExclusionID
	Rule  int64    `json:"rule"`
	Param WAFParam `json:"param"`
	Stage string   `json:"stage"`
	Since int64    `json:"since"`
	Until int64    `json:"until"`
	// Rank orders the site's active exclusions (waf-exclcap2): 1 is the
	// most valuable; the active ones of a site are ranked 1..n, each once,
	// shadow ones 0. A node applies the first k by rank (its own bound) and
	// leaves the rest checked by their rules (stricter, never looser).
	Rank int `json:"rank,omitempty"`
}

// WAFExclusionID is an exclusion's identity: the first 16 hex digits of
// SHA-256 over "<rule>:<location>:<name>".
func WAFExclusionID(rule int64, param WAFParam) string {
	sum := sha256.Sum256([]byte(strconv.FormatInt(rule, 10) + ":" + param.Location + ":" + param.Name))
	return hex.EncodeToString(sum[:8])
}

// Target is the exclusion's rule and parameter (edgeconfig.DynamicWAFTarget).
func (exclusion WAFExclusion) Target() edgeconfig.DynamicWAFTarget {
	return edgeconfig.DynamicWAFTarget{Rule: int(exclusion.Rule), Location: exclusion.Param.Location, Name: exclusion.Param.Name}
}

// WAFTypedParam is a parameter the site's traffic fixed to one type
// (section 3.3 "确定类型"): a value of another type, a longer one or one
// with a charset class outside Charset is the shape signal.
type WAFTypedParam struct {
	Key          string `json:"key"` // WAFParamKey
	Type         string `json:"type"`
	MaxLenBucket int64  `json:"max_len_bucket"`
	Charset      int64  `json:"charset"`
}

// maxWAFExclusionSeconds bounds an exclusion's span (shadow 72 hours, active
// 30 days by default; platform settings may lengthen them).
const maxWAFExclusionSeconds = 90 * 24 * 3600

func validWAFAdapt(adapt WAFAdapt) bool {
	if len(adapt.Exclusions) > MaxWAFAdaptExclusions || len(adapt.TypedParams) > MaxWAFTypedParams ||
		adapt.GreyFloor < 0 || adapt.GreyFloor > edgeconfig.DynamicWAFMaxGreyFloor ||
		(adapt.RepeatThreshold == 0) != (adapt.RepeatWindow == 0) || adapt.RepeatThreshold != 0 &&
		(adapt.RepeatThreshold < edgeconfig.DynamicWAFRepeatThresholdMin || adapt.RepeatThreshold > edgeconfig.DynamicWAFRepeatThresholdMax ||
			adapt.RepeatWindow < edgeconfig.DynamicWAFRepeatWindowMin || adapt.RepeatWindow > edgeconfig.DynamicWAFRepeatWindowMax) {
		return false
	}
	active := 0
	ranks := make([]bool, len(adapt.Exclusions)+1)
	for index, exclusion := range adapt.Exclusions {
		if exclusion.Rule < 900000 || exclusion.Rule > 999999 || !exclusion.Param.valid() ||
			exclusion.ID != WAFExclusionID(exclusion.Rule, exclusion.Param) ||
			(exclusion.Stage != WAFExclusionShadow && exclusion.Stage != WAFExclusionActive) || !validTime(exclusion.Since, false) ||
			exclusion.Until <= exclusion.Since || exclusion.Until-exclusion.Since > maxWAFExclusionSeconds ||
			(index > 0 && !wafExclusionLess(adapt.Exclusions[index-1], exclusion)) {
			return false
		}
		if exclusion.Stage == WAFExclusionActive {
			active++
			if exclusion.Rank < 1 || exclusion.Rank > len(adapt.Exclusions) || ranks[exclusion.Rank] {
				return false
			}
			ranks[exclusion.Rank] = true
		} else if exclusion.Rank != 0 {
			return false
		}
	}
	for rank := 1; rank <= active; rank++ { // 1..active, each once
		if !ranks[rank] {
			return false
		}
	}
	if active > edgeconfig.DynamicWAFMaxTargets || adapt.CookieMature != (len(adapt.CookieNames) > 0) ||
		len(adapt.CookieNames) > MaxWAFCookieNames {
		return false
	}
	for index, name := range adapt.CookieNames {
		if !hash8Pattern.MatchString(name) || (index > 0 && adapt.CookieNames[index-1] >= name) {
			return false
		}
	}
	for index, typed := range adapt.TypedParams {
		if !hash16Pattern.MatchString(typed.Key) || !contains(wafTypedValueTypes, typed.Type) || !validLenBucket(typed.MaxLenBucket) ||
			!validCharset(typed.Charset) || (index > 0 && adapt.TypedParams[index-1].Key >= typed.Key) {
			return false
		}
	}
	return true
}

// wafExclusionLess is the canonical order (rule, location letter, name),
// which makes ActiveTargets sorted as RenderDynamicWAFBucket takes them.
func wafExclusionLess(a, b WAFExclusion) bool {
	if a.Rule != b.Rule {
		return a.Rule < b.Rule
	}
	la, lb := edgeconfig.WAFTargetLocations[a.Param.Location], edgeconfig.WAFTargetLocations[b.Param.Location]
	if la != lb {
		return la < lb
	}
	return a.Param.Name < b.Param.Name
}

// SortWAFExclusions puts exclusions in the canonical order.
func SortWAFExclusions(exclusions []WAFExclusion) {
	sort.Slice(exclusions, func(i, j int) bool { return wafExclusionLess(exclusions[i], exclusions[j]) })
}

func (adapt *WAFAdapt) canonical() {
	sort.Slice(adapt.Exclusions, func(i, j int) bool { return wafExclusionLess(adapt.Exclusions[i], adapt.Exclusions[j]) })
	sort.Slice(adapt.TypedParams, func(i, j int) bool { return adapt.TypedParams[i].Key < adapt.TypedParams[j].Key })
	sort.Strings(adapt.CookieNames)
}

// ActiveTargets are the site's active exclusions at now (canonical order),
// all of them (a node applies its own first k by rank).
func (adapt WAFAdapt) ActiveTargets(now int64) []edgeconfig.DynamicWAFTarget {
	targets := []edgeconfig.DynamicWAFTarget{}
	for _, exclusion := range adapt.Exclusions {
		if exclusion.Stage == WAFExclusionActive && exclusion.Since <= now && now < exclusion.Until {
			targets = append(targets, exclusion.Target())
		}
	}
	return targets
}
