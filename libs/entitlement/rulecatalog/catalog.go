// Package rulecatalog defines the signed CC/WAF system rule catalog that the
// license service delivers to each control installation
// (cdnca.security-rule-catalog/v1) and the custom rule report that control
// installations upload back (cdnca.security-custom-rule-report/v2).
//
// Both services import this package so canonical encoding, digests, proof
// messages and verification cannot drift between the producer and consumer.
package rulecatalog

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"golang.org/x/mod/semver"
)

const (
	CatalogSchema = "cdnca.security-rule-catalog/v1"

	KindCCRuleGroup = "cc_rule_group"
	KindCCMatcher   = "cc_matcher"
	KindCCFilter    = "cc_filter"
	KindWAFRuleSet  = "waf_rule_set"

	MaxCatalogItems        = 1024
	MaxCatalogBytes        = 1 << 20
	maxRuleGroupEntries    = 32
	maxMatcherConditions   = 16
	maxConditionValues     = 256
	maxWAFRules            = 100
	maxWAFMatcherGroups    = 8
	maxWAFMatchersPerGroup = 8
	maxTextValueBytes      = 4096
)

var (
	ErrInvalidCatalog = errors.New("invalid security rule catalog")

	systemKeyPattern = regexp.MustCompile(`^(cc_rule|cc_matcher|cc_filter|waf_set):[A-Za-z0-9._-]{1,64}$`)
	legacyIDPattern  = regexp.MustCompile(`^[0-9]{0,32}$`)
	wafRuleIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	headerKeyPattern = regexp.MustCompile(`^[!#$%&'*+.^_` + "`" + `|~0-9A-Za-z-]{1,128}$`)
)

// KindPrefix maps an item kind to its system_key namespace. Competitor IDs
// collide across kinds (rule group 1 and filter 1), so keys are namespaced.
var KindPrefix = map[string]string{
	KindCCRuleGroup: "cc_rule", KindCCMatcher: "cc_matcher", KindCCFilter: "cc_filter", KindWAFRuleSet: "waf_set",
}

// FilterTypes lists the competitor's ten CC filter types. The node filter
// pipeline (separate task) compiles each of these; the catalog only carries
// their parameters.
var FilterTypes = []string{
	"req_rate", "browser_verify_auto", "delay_jump_filter", "click_filter", "easy_click_filter",
	"slide_filter", "easy_slide_filter", "captcha_filter", "rotate_filter", "302_challenge",
}

var (
	matcherFields   = []string{"ip", "host", "uri", "req_uri", "query", "method", "referer", "user_agent", "header", "cookie", "country"}
	matcherOps      = []string{"contain", "not_contain", "equal", "not_equal", "prefix", "suffix", "regex", "ip_in", "ip_not_in"}
	ruleActions     = []string{"block", "allow", "log"}
	ruleModes       = []string{"break", "continue"}
	wafFields       = []string{"ip", "host", "uri", "req_uri", "query", "args", "method", "referer", "user_agent", "header", "cookie", "body", "upload_extension", "upload_filename"}
	wafOps          = []string{"contain", "not_contain", "equal", "not_equal", "prefix", "suffix", "regex", "not_regex", "ip_in", "ip_not_in"}
	wafTransforms   = []string{"none", "lowercase", "urldecode", "base64decode", "trim"}
	wafRuleActions  = []string{"allow", "block", "log"}
	keyedFields     = map[string]bool{"header": true, "cookie": true}
	maxFilterNumber = 1_000_000
)

// Catalog is the per-installation set of system rules. Items are sorted by
// system_key; withdrawn or untargeted items are simply absent.
type Catalog struct {
	Schema string `json:"schema"`
	Items  []Item `json:"items"`
}

type Item struct {
	SystemKey   string   `json:"system_key"`
	Kind        string   `json:"kind"`
	LegacyID    string   `json:"legacy_id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Sort        int      `json:"sort"`
	Hidden      bool     `json:"hidden"`
	Revision    uint64   `json:"revision"`
	Body        ItemBody `json:"body"`
}

// ItemBody holds exactly one body matching Item.Kind.
type ItemBody struct {
	CCRuleGroup *CCRuleGroupBody `json:"cc_rule_group,omitempty"`
	CCMatcher   *CCMatcherBody   `json:"cc_matcher,omitempty"`
	CCFilter    *CCFilterBody    `json:"cc_filter,omitempty"`
	WAFRuleSet  *WAFRuleSetBody  `json:"waf_rule_set,omitempty"`
}

// CCRuleGroupBody is an ordered list of matcher -> filter1 [-> filter2]
// chains. A matching entry with mode=break stops evaluation of the group.
type CCRuleGroupBody struct {
	Entries []CCRuleGroupEntry `json:"entries"`
}

type CCRuleGroupEntry struct {
	MatcherKey string `json:"matcher_key"`
	Filter1Key string `json:"filter1_key"`
	Filter2Key string `json:"filter2_key"`
	Action     string `json:"action"`
	Mode       string `json:"mode"`
	Enabled    bool   `json:"enabled"`
}

// CCMatcherBody matches when every condition matches; no conditions matches
// every request ("匹配所有资源"). A condition matches when any value matches.
type CCMatcherBody struct {
	Conditions []CCMatcherCondition `json:"conditions"`
}

type CCMatcherCondition struct {
	Field    string   `json:"field"`
	Operator string   `json:"operator"`
	Key      string   `json:"key"`
	Values   []string `json:"values"`
}

// CCFilterBody mirrors the competitor filter: a request counter per client
// over within_second; max_req is the challenge/request budget and
// max_req_per_uri (0 = off) the per-URI budget.
type CCFilterBody struct {
	Type         string            `json:"type"`
	WithinSecond int               `json:"within_second"`
	MaxReq       int               `json:"max_req"`
	MaxReqPerURI int               `json:"max_req_per_uri"`
	Extra        map[string]string `json:"extra"`
	Params       *CCFilterParams   `json:"params,omitempty"`
}

// CCFilterParams are the enforcement parameters of a filter (competitor
// "CC参数配置"). req_rate filters set only BanSeconds (blacklist time after
// the rate is exceeded). Verification filters set every field:
//   - BanSeconds: blacklist time after more than max_req failed/unpassed
//     verifications within within_second;
//   - PassSeconds: lifetime of the pass cookie (whitelist validity);
//   - PowBits: SHA-256 proof-of-work difficulty in leading zero bits that the
//     browser must solve before the page can be submitted (each bit doubles
//     the work; 0 for 302_challenge, which serves no page); DelaySeconds: minimum wait of the 5-second shield (others 0);
//   - ChallengeSeconds: lifetime of one verification page;
//   - BindIPv4Prefix / BindIPv6Prefix: the pass cookie is valid only from the
//     same client network (32 / 128 = exact address);
//   - KeyRotateSeconds: pass signing keys rotate this often (current and
//     previous key accepted; must be >= PassSeconds).
type CCFilterParams struct {
	BanSeconds       int `json:"ban_seconds"`
	PassSeconds      int `json:"pass_seconds,omitempty"`
	PowBits          int `json:"pow_bits,omitempty"`
	DelaySeconds     int `json:"delay_seconds,omitempty"`
	ChallengeSeconds int `json:"challenge_seconds,omitempty"`
	BindIPv4Prefix   int `json:"bind_ipv4_prefix,omitempty"`
	BindIPv6Prefix   int `json:"bind_ipv6_prefix,omitempty"`
	KeyRotateSeconds int `json:"key_rotate_seconds,omitempty"`
}

// ValidCCFilterParams reports whether params fit a filter of filterType.
func ValidCCFilterParams(filterType string, params CCFilterParams) bool {
	if params.BanSeconds < 1 || params.BanSeconds > 86400 {
		return false
	}
	if filterType == "req_rate" {
		return params == CCFilterParams{BanSeconds: params.BanSeconds}
	}
	// 302_challenge only proves cookie support (no page, no proof of work).
	powOK := filterType == "302_challenge" && params.PowBits == 0 || filterType != "302_challenge" &&
		params.PowBits >= 8 && params.PowBits <= 26
	return params.PassSeconds >= 60 && params.PassSeconds <= 7*86400 && powOK &&
		params.DelaySeconds >= 0 && params.DelaySeconds <= 30 && (filterType == "delay_jump_filter") == (params.DelaySeconds > 0) &&
		params.ChallengeSeconds >= 30 && params.ChallengeSeconds <= 3600 &&
		params.BindIPv4Prefix >= 8 && params.BindIPv4Prefix <= 32 && params.BindIPv6Prefix >= 32 && params.BindIPv6Prefix <= 128 &&
		params.KeyRotateSeconds >= params.PassSeconds && params.KeyRotateSeconds <= 30*86400
}

// WAFRuleSetBody is exactly one of:
//   - Rules: self-developed detection (signature matcher groups; the node
//     adds its semantic SQL injection / XSS detectors to waf_set:sqli/xss);
//   - Engine: an OWASP CRS rule set run by libmodsecurity (the optional
//     node engine extension), with the site defaults (action / paranoia /
//     threshold) operators may tune;
//   - Settings: CRS engine-wide defaults shared by every CRS set (hidden);
//   - Bundle: the CRS rule text itself (hidden, waf_set:crs_rules). Rule text
//     is catalog data delivered license service -> control -> node with the
//     catalog signature; nodes do not ship it.
type WAFRuleSetBody struct {
	Rules    []WAFRule          `json:"rules,omitempty"`
	Engine   *WAFEngineSet      `json:"engine,omitempty"`
	Settings *WAFEngineSettings `json:"settings,omitempty"`
	Bundle   *WAFEngineBundle   `json:"bundle,omitempty"`
}

// WAFEngineBundle carries rule files of one CRS release: each file's
// content is gzip+base64 (RawStdEncoding) and SHA256 is the hex digest of
// the decompressed bytes. Consumers decode with DecodeWAFEngineBundle.
type WAFEngineBundle struct {
	Engine  string          `json:"engine"`
	Version string          `json:"version"`
	Files   []WAFEngineFile `json:"files"`
}

type WAFEngineFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Gzip   string `json:"gzip"`
}

const (
	maxEngineFiles     = 64
	maxEngineFileBytes = 512 << 10
	maxEngineBytes     = 2 << 20
)

var (
	engineFilePattern    = regexp.MustCompile(`^(REQUEST-9[0-9]{2}-[A-Z0-9-]{1,64}\.conf|[a-z0-9][a-z0-9-]{0,63}\.data|LICENSE|NOTICE)$`)
	engineVersionPattern = regexp.MustCompile(`^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$`)
	sha256HexPattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// DecodeWAFEngineBundle validates a rule-text bundle and returns its files
// by name (decompressed, digest-checked).
func DecodeWAFEngineBundle(bundle WAFEngineBundle) (map[string][]byte, error) {
	if bundle.Engine != WAFEngineCRS || !engineVersionPattern.MatchString(bundle.Version) ||
		len(bundle.Files) == 0 || len(bundle.Files) > maxEngineFiles {
		return nil, ErrInvalidCatalog
	}
	files := make(map[string][]byte, len(bundle.Files))
	total := 0
	for index, file := range bundle.Files {
		if !engineFilePattern.MatchString(file.Name) || !sha256HexPattern.MatchString(file.SHA256) ||
			index > 0 && bundle.Files[index-1].Name >= file.Name {
			return nil, ErrInvalidCatalog
		}
		compressed, err := base64.RawStdEncoding.DecodeString(file.Gzip)
		if err != nil {
			return nil, ErrInvalidCatalog
		}
		reader, err := gzip.NewReader(bytes.NewReader(compressed))
		if err != nil {
			return nil, ErrInvalidCatalog
		}
		content, err := io.ReadAll(io.LimitReader(reader, maxEngineFileBytes+1))
		if err != nil || len(content) == 0 || len(content) > maxEngineFileBytes || total+len(content) > maxEngineBytes {
			return nil, ErrInvalidCatalog
		}
		total += len(content)
		sum := sha256.Sum256(content)
		if hex.EncodeToString(sum[:]) != file.SHA256 {
			return nil, ErrInvalidCatalog
		}
		files[file.Name] = content
	}
	return files, nil
}

// WAFEngineSet selects CRS scoring rules: every rule of the Files (CRS file
// prefixes such as "REQUEST-942"), plus IncludeIDs, minus ExcludeIDs. The
// request is blocked (action block) or recorded (log) when the summed anomaly
// score of the selected rules reaches Threshold; rules above Paranoia are off.
//
// Two-level scoring (waf-strict-algo; StrongParanoia 0 = off, every rule
// scores toward Threshold): rules at or below StrongParanoia score toward
// Threshold (one strong signal blocks); the heuristic rules above it score a
// separate weak sum, and the request is blocked only when strong + weak
// reaches WeakThreshold (several signals agreeing, not one heuristic).
//
// Adaptive WAF (ADR 0011 sections 3.2-3.5, two-level sets only):
// GreyAction is what the grey zone (0 < strong + weak < WeakThreshold,
// strong below Threshold) does to a browser-like request without a valid
// challenge cookie: allow, or challenge (only
// 严格防护 and 极严格防护, the only tiers with two-level sets). Adaptive: the
// set's weak rules may be excluded per parameter or tightened per site
// automatically. StrongRules: rules above StrongParanoia that still score
// strong (official reweighting, section 6.1 waf_reweight; it only makes the
// tier stricter). WeakWeights (waf-gap6): learned offline per weak rule, its
// score in the weak sum instead of its severity (0-4, below critical; the
// node compiler checks each is a weak member below its own severity).
type WAFEngineSet struct {
	Engine         string      `json:"engine"`
	Files          []string    `json:"files"`
	IncludeIDs     []int       `json:"include_ids"`
	ExcludeIDs     []int       `json:"exclude_ids"`
	Action         string      `json:"action"`
	Paranoia       int         `json:"paranoia"`
	Threshold      int         `json:"threshold"`
	StrongParanoia int         `json:"strong_paranoia,omitempty"`
	WeakThreshold  int         `json:"weak_threshold,omitempty"`
	GreyAction     string      `json:"grey_action,omitempty"`
	Adaptive       bool        `json:"adaptive,omitempty"`
	StrongRules    []int       `json:"strong_rules,omitempty"`
	WeakWeights    []WAFWeight `json:"weak_weights,omitempty"`
}

// WAFWeight is one learned weak rule weight.
type WAFWeight struct {
	Rule   int `json:"rule"`
	Weight int `json:"weight"`
}

// WAFGreyActions are the grey zone actions of a two-level set.
const (
	WAFGreyAllow     = "allow"
	WAFGreyChallenge = "challenge"
)

// MaxWAFStrongRules bounds a set's reweighted rules.
const MaxWAFStrongRules = 256

// validAdaptiveScoring: a one-level set has none of the adaptive fields; a
// two-level set has a grey action and at most MaxWAFStrongRules ascending
// distinct CRS rule IDs (their membership and paranoia are checked against
// the rule text by the node compiler, edgeconfig).
func validAdaptiveScoring(strong int, grey string, adaptive bool, rules []int, weights []WAFWeight) bool {
	if strong == 0 {
		return grey == "" && !adaptive && rules == nil && weights == nil
	}
	if grey != WAFGreyAllow && grey != WAFGreyChallenge || len(rules) > MaxWAFStrongRules || len(weights) > MaxWAFStrongRules {
		return false
	}
	for index, weight := range weights {
		if weight.Rule < 900000 || weight.Rule > 999999 || weight.Weight < 0 || weight.Weight > 4 ||
			index > 0 && weights[index-1].Rule >= weight.Rule {
			return false
		}
	}
	for index, id := range rules {
		if id < 900000 || id > 999999 || index > 0 && rules[index-1] >= id {
			return false
		}
	}
	return true
}

// WAFEngineSettings are request inspection defaults: bytes buffered for
// inspection with and without file parts, the action past the limit
// (reject = 413, partial = inspect only the first bytes), the most arguments
// parsed (more are rejected: 400), the deepest JSON nesting parsed and the
// PCRE match limit per regex (ReDoS bound; a hit fails the request closed).
type WAFEngineSettings struct {
	Engine                  string `json:"engine"`
	RequestBodyLimit        int    `json:"request_body_limit"`
	RequestBodyNoFilesLimit int    `json:"request_body_no_files_limit"`
	RequestBodyLimitAction  string `json:"request_body_limit_action"`
	ArgumentsLimit          int    `json:"arguments_limit"`
	JSONDepthLimit          int    `json:"json_depth_limit"`
	PCREMatchLimit          int    `json:"pcre_match_limit"`
}

// WAFEngineCRS names the OWASP CRS on libmodsecurity engine.
const WAFEngineCRS = "owasp_crs"

type WAFRule struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Enabled       bool              `json:"enabled"`
	Action        string            `json:"action"`
	MatcherGroups []WAFMatcherGroup `json:"matcher_groups"`
}

// WAFMatcherGroup matches when all matchers match; a rule matches when any
// group matches (competitor matcher_groups semantics).
type WAFMatcherGroup struct {
	ID       string       `json:"id"`
	Matchers []WAFMatcher `json:"matchers"`
}

type WAFMatcher struct {
	Field     string `json:"field"`
	Operator  string `json:"operator"`
	Key       string `json:"key"`
	Transform string `json:"transform"`
	Value     string `json:"value"`
}

// CanonicalCatalog validates the catalog and returns its canonical bytes and
// SHA-256 digest. The canonical form is encoding/json over the typed structs:
// field order is fixed by declaration and maps are key-sorted.
func CanonicalCatalog(catalog Catalog) ([]byte, [32]byte, error) {
	if err := ValidateCatalog(catalog); err != nil {
		return nil, [32]byte{}, err
	}
	encoded, err := json.Marshal(catalog)
	if err != nil || len(encoded) > MaxCatalogBytes {
		return nil, [32]byte{}, ErrInvalidCatalog
	}
	return encoded, sha256.Sum256(encoded), nil
}

func DigestString(digest [32]byte) string { return base64.RawURLEncoding.EncodeToString(digest[:]) }

// SortItems orders items by system_key, the canonical catalog order.
func SortItems(items []Item) { sortItems(items) }

func sortItems(items []Item) {
	sort.Slice(items, func(i, j int) bool { return items[i].SystemKey < items[j].SystemKey })
}

func ValidateCatalog(catalog Catalog) error {
	if catalog.Schema != CatalogSchema || catalog.Items == nil || len(catalog.Items) > MaxCatalogItems {
		return ErrInvalidCatalog
	}
	kinds := make(map[string]string, len(catalog.Items))
	for index, item := range catalog.Items {
		if index > 0 && catalog.Items[index-1].SystemKey >= item.SystemKey {
			return ErrInvalidCatalog
		}
		if err := ValidateItem(item); err != nil {
			return err
		}
		kinds[item.SystemKey] = item.Kind
	}
	// Rule groups may only reference matchers/filters delivered in the same
	// catalog, so a consumer never sees a dangling reference.
	for _, item := range catalog.Items {
		if item.Kind != KindCCRuleGroup {
			continue
		}
		for _, entry := range item.Body.CCRuleGroup.Entries {
			if kinds[entry.MatcherKey] != KindCCMatcher || kinds[entry.Filter1Key] != KindCCFilter ||
				entry.Filter2Key != "" && kinds[entry.Filter2Key] != KindCCFilter {
				return ErrInvalidCatalog
			}
		}
	}
	return nil
}

// ValidateItem checks one item in isolation (references are checked by
// ValidateCatalog).
func ValidateItem(item Item) error {
	prefix, ok := KindPrefix[item.Kind]
	if !ok || !systemKeyPattern.MatchString(item.SystemKey) || !strings.HasPrefix(item.SystemKey, prefix+":") ||
		!legacyIDPattern.MatchString(item.LegacyID) || !validText(item.Name, 1, 128) ||
		!validText(item.Description, 0, 1000) || item.Sort < 0 || item.Sort > 100000 ||
		item.Revision < 1 || item.Revision > 1<<53-1 {
		return ErrInvalidCatalog
	}
	body := item.Body
	count := 0
	for _, present := range []bool{body.CCRuleGroup != nil, body.CCMatcher != nil, body.CCFilter != nil, body.WAFRuleSet != nil} {
		if present {
			count++
		}
	}
	if count != 1 {
		return ErrInvalidCatalog
	}
	var valid bool
	switch item.Kind {
	case KindCCRuleGroup:
		valid = body.CCRuleGroup != nil && validRuleGroup(*body.CCRuleGroup)
	case KindCCMatcher:
		valid = body.CCMatcher != nil && validMatcher(*body.CCMatcher)
	case KindCCFilter:
		valid = body.CCFilter != nil && validFilter(*body.CCFilter)
	case KindWAFRuleSet:
		valid = body.WAFRuleSet != nil && validWAFRuleSet(*body.WAFRuleSet)
	}
	if !valid {
		return ErrInvalidCatalog
	}
	return nil
}

func validRuleGroup(body CCRuleGroupBody) bool {
	if body.Entries == nil || len(body.Entries) > maxRuleGroupEntries {
		return false
	}
	for _, entry := range body.Entries {
		if !strings.HasPrefix(entry.MatcherKey, "cc_matcher:") || !systemKeyPattern.MatchString(entry.MatcherKey) ||
			!strings.HasPrefix(entry.Filter1Key, "cc_filter:") || !systemKeyPattern.MatchString(entry.Filter1Key) ||
			entry.Filter2Key != "" && (!strings.HasPrefix(entry.Filter2Key, "cc_filter:") ||
				!systemKeyPattern.MatchString(entry.Filter2Key) || entry.Filter2Key == entry.Filter1Key) ||
			!contains(ruleActions, entry.Action) || !contains(ruleModes, entry.Mode) {
			return false
		}
	}
	return true
}

func validMatcher(body CCMatcherBody) bool {
	if body.Conditions == nil || len(body.Conditions) > maxMatcherConditions {
		return false
	}
	for _, condition := range body.Conditions {
		if !contains(matcherFields, condition.Field) || !contains(matcherOps, condition.Operator) ||
			keyedFields[condition.Field] != headerKeyPattern.MatchString(condition.Key) ||
			!keyedFields[condition.Field] && condition.Key != "" || !validValues(condition.Values) {
			return false
		}
	}
	return true
}

func validFilter(body CCFilterBody) bool {
	if !contains(FilterTypes, body.Type) || body.WithinSecond < 1 || body.WithinSecond > 86400 ||
		body.MaxReq < 0 || body.MaxReq > maxFilterNumber || body.MaxReqPerURI < 0 ||
		body.MaxReqPerURI > maxFilterNumber || body.Extra == nil || len(body.Extra) > 16 {
		return false
	}
	for key, value := range body.Extra {
		if !wafRuleIDPattern.MatchString(key) || !validText(value, 0, 1024) {
			return false
		}
	}
	return body.Params == nil || body.Type != "url_auth" && ValidCCFilterParams(body.Type, *body.Params)
}

var crsFilePattern = regexp.MustCompile(`^REQUEST-9[0-9]{2}$`)

// validTwoLevelScoring: both fields unset, or a strong level below the
// set's paranoia and a weak threshold above the strong one (weak signals
// alone never reach Threshold's single-signal meaning).
func validTwoLevelScoring(paranoia, threshold, strong, weak int) bool {
	if strong == 0 && weak == 0 {
		return true
	}
	return strong >= 1 && strong < paranoia && weak > threshold && weak <= 1000
}

func validWAFEngineSet(body WAFEngineSet) bool {
	if body.Engine != WAFEngineCRS || body.Files == nil || body.IncludeIDs == nil || body.ExcludeIDs == nil ||
		len(body.Files)+len(body.IncludeIDs) == 0 || len(body.Files) > 16 || len(body.IncludeIDs) > 256 ||
		len(body.ExcludeIDs) > 256 || body.Action != "block" && body.Action != "log" ||
		body.Paranoia < 1 || body.Paranoia > 4 || body.Threshold < 1 || body.Threshold > 1000 ||
		!validTwoLevelScoring(body.Paranoia, body.Threshold, body.StrongParanoia, body.WeakThreshold) ||
		!validAdaptiveScoring(body.StrongParanoia, body.GreyAction, body.Adaptive, body.StrongRules, body.WeakWeights) {
		return false
	}
	for _, file := range body.Files {
		if !crsFilePattern.MatchString(file) {
			return false
		}
	}
	for _, ids := range [][]int{body.IncludeIDs, body.ExcludeIDs} {
		for _, id := range ids {
			if id < 900000 || id > 999999 {
				return false
			}
		}
	}
	return true
}

func validWAFEngineSettings(body WAFEngineSettings) bool {
	return body.Engine == WAFEngineCRS && body.RequestBodyLimit >= 1024 && body.RequestBodyLimit <= 128<<20 &&
		body.RequestBodyNoFilesLimit >= 1024 && body.RequestBodyNoFilesLimit <= body.RequestBodyLimit &&
		(body.RequestBodyLimitAction == "reject" || body.RequestBodyLimitAction == "partial") &&
		body.ArgumentsLimit >= 10 && body.ArgumentsLimit <= 100000 && body.JSONDepthLimit >= 4 && body.JSONDepthLimit <= 10000 &&
		body.PCREMatchLimit >= 1000 && body.PCREMatchLimit <= 10000000
}

func validWAFRuleSet(body WAFRuleSetBody) bool {
	switch {
	case body.Engine != nil:
		return body.Rules == nil && body.Settings == nil && body.Bundle == nil && validWAFEngineSet(*body.Engine)
	case body.Settings != nil:
		return body.Rules == nil && body.Bundle == nil && validWAFEngineSettings(*body.Settings)
	case body.Bundle != nil:
		_, err := DecodeWAFEngineBundle(*body.Bundle)
		return body.Rules == nil && err == nil
	}
	if body.Rules == nil || len(body.Rules) < 1 || len(body.Rules) > maxWAFRules {
		return false
	}
	seen := map[string]bool{}
	for _, rule := range body.Rules {
		if !wafRuleIDPattern.MatchString(rule.ID) || seen[rule.ID] || !validText(rule.Name, 1, 128) ||
			!contains(wafRuleActions, rule.Action) || rule.MatcherGroups == nil || len(rule.MatcherGroups) < 1 ||
			len(rule.MatcherGroups) > maxWAFMatcherGroups {
			return false
		}
		seen[rule.ID] = true
		for _, group := range rule.MatcherGroups {
			if !wafRuleIDPattern.MatchString(group.ID) || group.Matchers == nil || len(group.Matchers) < 1 ||
				len(group.Matchers) > maxWAFMatchersPerGroup {
				return false
			}
			for _, matcher := range group.Matchers {
				if !contains(wafFields, matcher.Field) || !contains(wafOps, matcher.Operator) ||
					!contains(wafTransforms, matcher.Transform) ||
					keyedFields[matcher.Field] != headerKeyPattern.MatchString(matcher.Key) ||
					!keyedFields[matcher.Field] && matcher.Key != "" || !validText(matcher.Value, 1, maxTextValueBytes) {
					return false
				}
			}
		}
	}
	return true
}

func validValues(values []string) bool {
	if values == nil || len(values) < 1 || len(values) > maxConditionValues {
		return false
	}
	for _, value := range values {
		if !validText(value, 1, maxTextValueBytes) || strings.ContainsAny(value, "\r\n") {
			return false
		}
	}
	return true
}

func validText(value string, minimum, maximum int) bool {
	return utf8.ValidString(value) && strings.TrimSpace(value) == value &&
		utf8.RuneCountInString(value) >= minimum && utf8.RuneCountInString(value) <= maximum
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

// EngineCatalogControlVersion is the first control release that understands
// the catalog bodies added for OWASP CRS (waf_rule_set engine / settings /
// bundle) and CC filter enforcement parameters. Older control releases
// reject a catalog containing them as a whole, so the license service serves
// them the newest revision of each item without these bodies (or omits the
// item when it has none).
const EngineCatalogControlVersion = "1.0.35"

// RequiresEngineCatalog reports whether an item uses a body that control
// releases before EngineCatalogControlVersion cannot decode.
func RequiresEngineCatalog(item Item) bool {
	body := item.Body
	if body.WAFRuleSet != nil && (body.WAFRuleSet.Engine != nil || body.WAFRuleSet.Settings != nil || body.WAFRuleSet.Bundle != nil) {
		return true
	}
	return body.CCFilter != nil && body.CCFilter.Params != nil
}

// ControlSupportsEngineCatalog reports whether a control release (semver,
// with or without a leading v) accepts engine catalog bodies.
func ControlSupportsEngineCatalog(controlVersion string) bool {
	version := controlVersion
	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}
	return semver.IsValid(version) && semver.Compare(version, "v"+EngineCatalogControlVersion) >= 0
}
