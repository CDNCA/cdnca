package edgeconfig

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	CCV2SchemaVersion         = "cdnca.edge.cc/v2"
	CCV2RegistrySchemaVersion = "cdnca.edge.cc-registry/v1"
	CCV2RegistryBeginMarker   = "# cdnca-cc-v2-registry-begin"
	CCV2RegistryEndMarker     = "# cdnca-cc-v2-registry-end"
	CCV2LuaPackagePath        = "/usr/local/share/cdnca/security/?.lua"
	CCV2LuaModule             = "cc"
	CCV2StateDictionary       = "cdnca_cc_v2_state"

	ccV2RegistryOpen  = "[==["
	ccV2RegistryClose = "]==]"
	ccV2MaxRules      = 128
	// ccV2RegistryChunkBytes keeps every Lua long string of the inlined
	// registry well under nginx's 4096-byte configuration token limit.
	ccV2RegistryChunkBytes = 2048
)

// ccV2RegistryLua renders the registry JSON as the init block's registry_json
// expression: one long string, or table.concat of long strings when the
// registry would not fit one nginx configuration token.
func ccV2RegistryLua(content []byte) string {
	if len(content) <= ccV2RegistryChunkBytes {
		return ccV2RegistryOpen + string(content) + ccV2RegistryClose
	}
	var output strings.Builder
	output.WriteString("table.concat({ ")
	for offset := 0; offset < len(content); offset += ccV2RegistryChunkBytes {
		if offset > 0 {
			output.WriteString(", ")
		}
		output.WriteString(ccV2RegistryOpen)
		output.Write(content[offset:min(offset+ccV2RegistryChunkBytes, len(content))])
		output.WriteString(ccV2RegistryClose)
	}
	output.WriteString(" })")
	return output.String()
}

type CCV2Algorithm string
type CCV2Flow string
type CCV2Dimension string
type CCV2ActionKind string
type CCV2PathKind string
type CCV2CountKeyName string
type CCV2ActionTarget string

const (
	CCV2AlgorithmFixedWindow CCV2Algorithm = "fixed_window"
	CCV2AlgorithmLeakyBucket CCV2Algorithm = "leaky_bucket"
	// CCV2AlgorithmAlways marks every matching request as over the limit; it
	// only pairs with the challenge action ("challenge until passed").
	CCV2AlgorithmAlways CCV2Algorithm = "always"

	CCV2FlowContinue CCV2Flow = "continue"
	CCV2FlowStop     CCV2Flow = "stop"

	CCV2DimensionClientIP CCV2Dimension = "client_ip"

	// Counting keys (CC API v4, securitypolicy.CountKey). A rule without
	// CountBy counts by client IP.
	CCV2CountClientIP   CCV2CountKeyName = "client_ip"
	CCV2CountClientCIDR CCV2CountKeyName = "client_cidr"
	CCV2CountHost       CCV2CountKeyName = "host"
	CCV2CountURI        CCV2CountKeyName = "uri"
	CCV2CountURIPath    CCV2CountKeyName = "uri_path"
	CCV2CountJA4        CCV2CountKeyName = "ja4"
	// fix-ja4rule (CC API v7, CAPABILITY_NAME_CC_MATCH_KEYS): the request's
	// User-Agent / Referer, and one named header / cookie / query argument
	// (CCV2CountKey.Name). A request without the value is not counted.
	CCV2CountUserAgent CCV2CountKeyName = "user_agent"
	CCV2CountReferer   CCV2CountKeyName = "referer"
	CCV2CountHeader    CCV2CountKeyName = "header"
	CCV2CountCookie    CCV2CountKeyName = "cookie"
	CCV2CountQuery     CCV2CountKeyName = "query"

	// CCV2ActionTargetCountKey bans the counted bucket instead of the client.
	CCV2ActionTargetCountKey CCV2ActionTarget = "count_key"

	CCV2ActionLog          CCV2ActionKind = "log"
	CCV2ActionReject429    CCV2ActionKind = "reject_429"
	CCV2ActionTemporaryBan CCV2ActionKind = "temporary_ban"
	CCV2ActionChallenge    CCV2ActionKind = "challenge"

	CCV2PathExact  CCV2PathKind = "exact"
	CCV2PathPrefix CCV2PathKind = "prefix"
)

var ccV2MethodPattern = regexp.MustCompile(`^[A-Z][A-Z0-9!#$%&'*+.^_` + "`" + `|~-]{0,31}$`)

type CCV2Policy struct {
	SchemaVersion   string     `json:"schema_version"`
	TenantScopeID   string     `json:"tenant_scope_id"`
	SiteID          string     `json:"site_id"`
	PolicyID        string     `json:"policy_id"`
	PolicyVersion   int64      `json:"policy_version"`
	BindingID       string     `json:"binding_id"`
	BindingRevision int64      `json:"binding_revision"`
	PublicationID   string     `json:"publication_id"`
	Enabled         bool       `json:"enabled"`
	TrustedProxies  []string   `json:"trusted_proxies"`
	Allowlist       []string   `json:"allowlist"`
	Rules           []CCV2Rule `json:"rules"`
	// AutoSwitch (CC API v5) is present only on an enabled policy with an
	// active auto switch (securitypolicy.CCSettings).
	AutoSwitch *CCV2AutoSwitch `json:"auto_switch,omitempty"`
	// TrustedCrawlers (CC API v6, FX47): a verified search engine crawler
	// skips every CC rule, ban and challenge (ccv2/engine.lua). Only on an
	// enabled policy.
	TrustedCrawlers []CCV2TrustedCrawler `json:"trusted_crawlers,omitempty"`
	// ChallengeCookieDomain (CC API v6, NF28) is the pass cookie's Domain
	// when the request host is it or under it; absent keeps it host-only.
	ChallengeCookieDomain string `json:"challenge_cookie_domain,omitempty"`
}

// CCV2TrustedCrawler: a request whose User-Agent contains one of
// UserAgentTokens is the crawler when the client is in Networks or its
// address forward-confirms (PTR, then A/AAAA back to it) to a hostname equal
// to or under one of RDNSSuffixes. The User-Agent alone never trusts.
type CCV2TrustedCrawler struct {
	Name            string   `json:"name"`
	UserAgentTokens []string `json:"user_agent_tokens"`
	Networks        []string `json:"networks,omitempty"`
	RDNSSuffixes    []string `json:"rdns_suffixes,omitempty"`
}

const (
	ccV2MaxTrustedCrawlers = 32
	ccV2MaxCrawlerTokens   = 16
	ccV2MaxCrawlerNetworks = 256
	ccV2MaxCrawlerSuffixes = 16
	ccV2MaxIPMatches       = 16
	ccV2MaxIPMatchCIDRs    = 256
	ccV2MaxHeaderMatches   = 16
	ccV2MaxHeaderValues    = 64
)

// CCV2AutoSwitch: once the node's requests per second for the site reach
// QPSTotal, or its 5xx responses per second reach QPS5xx (0 = threshold not
// used), the node runs Rules instead of the policy's rules until both stayed
// below for RecoverSeconds (ccv2/engine.lua).
type CCV2AutoSwitch struct {
	QPSTotal       uint32     `json:"qps_total"`
	QPS5xx         uint32     `json:"qps_5xx"`
	RecoverSeconds uint32     `json:"recover_seconds"`
	Rules          []CCV2Rule `json:"rules"`
	// Overrides / RuleSets (CC API v8, fix-fwregion): the platform nodes that
	// run another value than the fields above (区域/节点覆盖). With overrides
	// the global value may be off (thresholds 0, no rules). An override with
	// both thresholds 0 is off on its nodes; RuleSet "" runs Rules, otherwise
	// the named RuleSets entry.
	Overrides []CCV2AutoSwitchOverride `json:"overrides,omitempty"`
	RuleSets  []CCV2AutoSwitchRuleSet  `json:"rule_sets,omitempty"`
}

type CCV2AutoSwitchOverride struct {
	Nodes          []string `json:"nodes"`
	QPSTotal       uint32   `json:"qps_total"`
	QPS5xx         uint32   `json:"qps_5xx"`
	RecoverSeconds uint32   `json:"recover_seconds"`
	RuleSet        string   `json:"rule_set,omitempty"`
}

type CCV2AutoSwitchRuleSet struct {
	Name  string     `json:"name"`
	Rules []CCV2Rule `json:"rules"`
}

// CCAutoSwitchOverridesAPIVersion is the CC API of per-node auto switch
// overrides.
const CCAutoSwitchOverridesAPIVersion uint32 = 8

// CCV2PolicyRules is every rule a policy may run: its own and its auto
// switch's.
func CCV2PolicyRules(policy CCV2Policy) []CCV2Rule {
	if policy.AutoSwitch == nil {
		return policy.Rules
	}
	rules := make([]CCV2Rule, 0, len(policy.Rules)+len(policy.AutoSwitch.Rules))
	rules = append(append(rules, policy.Rules...), policy.AutoSwitch.Rules...)
	for _, set := range policy.AutoSwitch.RuleSets {
		rules = append(rules, set.Rules...)
	}
	return rules
}

type CCV2Rule struct {
	RuleID    string        `json:"rule_id"`
	Priority  int           `json:"priority"`
	Flow      CCV2Flow      `json:"flow"`
	Match     CCV2Match     `json:"match"`
	Dimension CCV2Dimension `json:"dimension"`
	// CountBy is absent for the default (client IP) and otherwise one or two
	// keys in ccV2CountKeyOrder; a policy with it needs CC API v4.
	CountBy []CCV2CountKey `json:"count_by,omitempty"`
	Limit   CCV2Limit      `json:"limit"`
	Action  CCV2Action     `json:"action"`
}

type CCV2CountKey struct {
	Key        CCV2CountKeyName `json:"key"`
	IPv4Prefix uint32           `json:"ipv4_prefix,omitempty"`
	IPv6Prefix uint32           `json:"ipv6_prefix,omitempty"`
	// Name: the header (lower case) / cookie / query argument of key header /
	// cookie / query (CC API v7); absent for every other key.
	Name string `json:"name,omitempty"`
}

var ccV2CountKeyOrder = []CCV2CountKeyName{CCV2CountClientIP, CCV2CountClientCIDR, CCV2CountHost, CCV2CountURI,
	CCV2CountURIPath, CCV2CountJA4, CCV2CountUserAgent, CCV2CountReferer, CCV2CountHeader, CCV2CountCookie, CCV2CountQuery}

// CCV2CountKeyNamePattern: a counting key's header (lower case) / cookie /
// query argument name.
var (
	ccV2CountHeaderNamePattern = regexp.MustCompile(`^[a-z0-9!#$%&'*+.^_` + "`" + `|~-]{1,64}$`)
	ccV2CountParamNamePattern  = regexp.MustCompile(`^[A-Za-z0-9_.:\[\]-]{1,128}$`)
)

// ccV2MatchKeysCountKey: a counting key of CC API v7.
func ccV2MatchKeysCountKey(key CCV2CountKeyName) bool {
	return key == CCV2CountUserAgent || key == CCV2CountReferer || key == CCV2CountHeader || key == CCV2CountCookie || key == CCV2CountQuery
}

type CCV2Match struct {
	Host               string         `json:"host,omitempty"`
	Port               uint16         `json:"port,omitempty"`
	Method             string         `json:"method,omitempty"`
	Path               *CCV2PathMatch `json:"path,omitempty"`
	SourceCIDR         string         `json:"source_cidr,omitempty"`
	DistinctUserAgents uint32         `json:"distinct_user_agents,omitempty"`
	Status404Count     uint32         `json:"status_404_count,omitempty"`
	PathContains       []string       `json:"path_contains,omitempty"`
	// ClientIP (CC API v6, NF27): every entry must hold (AND); an entry holds
	// when the client is in one of its CIDRs (Negate: in none). A rule with a
	// single plain CIDR uses SourceCIDR instead.
	ClientIP []CCV2IPMatch `json:"client_ip,omitempty"`
	// Headers (CC API v6, NF32): every entry must hold (AND); an entry holds
	// when one of the request's Name headers matches one of its values.
	Headers []CCV2HeaderMatch `json:"headers,omitempty"`
	// JA4 (CC API v7, fix-ja4rule): the request's TLS fingerprint
	// ($cdnca_ja4) is one of the values (sorted, unique); a request without
	// one never matches. Needs CAPABILITY_NAME_JA4 and CC_MATCH_KEYS.
	JA4 []string `json:"ja4,omitempty"`
}

type CCV2IPMatch struct {
	Negate bool     `json:"negate,omitempty"`
	CIDRs  []string `json:"cidrs"`
}

type CCV2HeaderKind string

const (
	CCV2HeaderExact    CCV2HeaderKind = "exact"
	CCV2HeaderPrefix   CCV2HeaderKind = "prefix"
	CCV2HeaderContains CCV2HeaderKind = "contains"
	// CCV2HeaderRegex values are RE2 patterns the node runs with PCRE
	// (ngx.re, jo); the common syntax of both.
	CCV2HeaderRegex CCV2HeaderKind = "regex"
)

// CCV2HeaderMatch: Name is a lower-case header field name (user-agent,
// referer or any other).
type CCV2HeaderMatch struct {
	Name   string         `json:"name"`
	Kind   CCV2HeaderKind `json:"kind"`
	Values []string       `json:"values"`
}

type CCV2PathMatch struct {
	Kind  CCV2PathKind `json:"kind"`
	Value string       `json:"value"`
}

type CCV2Limit struct {
	Algorithm     CCV2Algorithm `json:"algorithm"`
	Requests      uint32        `json:"requests,omitempty"`
	PerURI        uint32        `json:"requests_per_uri,omitempty"`
	WindowSeconds uint32        `json:"window_seconds,omitempty"`
	RatePerSecond uint32        `json:"rate_per_second,omitempty"`
	Burst         uint32        `json:"burst,omitempty"`
}

type CCV2Action struct {
	Kind       CCV2ActionKind `json:"kind"`
	BanSeconds uint32         `json:"ban_seconds,omitempty"`
	Challenge  *CCV2Challenge `json:"challenge,omitempty"`
	// Target is CCV2ActionTargetCountKey or absent (the client).
	Target CCV2ActionTarget `json:"target,omitempty"`
}

// CCV2ChallengeModes are the verification pages cc.lua renders.
var CCV2ChallengeModes = []string{"delay", "js", "redirect", "click", "easy_click", "slider", "easy_slider", "captcha", "rotate"}

// CCV2Challenge: a client without a valid pass gets the page; more than
// MaxFailures unpassed pages within FailureWindowSeconds bans it for the
// action's BanSeconds (or only logs when LogOnly). A pass lasts PassSeconds
// and is revoked when PassLimit is exceeded.
// CCV2Challenge is a verification page (ccv2/engine.lua). PowBits is the
// SHA-256 proof-of-work difficulty the page must solve (0 only for redirect),
// DelaySeconds the 5-second-shield wait, ChallengeSeconds the page lifetime;
// the pass cookie lives PassSeconds, is bound to the client's BindIPv4Prefix /
// BindIPv6Prefix network and is signed with a key rotated every
// KeyRotateSeconds (>= PassSeconds; the previous key is still accepted).
type CCV2Challenge struct {
	Mode                 string     `json:"mode"`
	DelaySeconds         uint32     `json:"delay_seconds,omitempty"`
	FailureWindowSeconds uint32     `json:"failure_window_seconds"`
	MaxFailures          uint32     `json:"max_failures"`
	PassSeconds          uint32     `json:"pass_seconds"`
	LogOnly              bool       `json:"log_only,omitempty"`
	PassLimit            *CCV2Limit `json:"pass_limit,omitempty"`
	PowBits              uint32     `json:"pow_bits"`
	ChallengeSeconds     uint32     `json:"challenge_seconds"`
	BindIPv4Prefix       uint32     `json:"bind_ipv4_prefix"`
	BindIPv6Prefix       uint32     `json:"bind_ipv6_prefix"`
	KeyRotateSeconds     uint32     `json:"key_rotate_seconds"`
}

// CCV2PolicyNeedsProofOfWork reports whether a compiled policy has a
// challenge (proof of work, bound and rotated pass): agents need CC API v3.
func CCV2PolicyNeedsProofOfWork(policy CCV2Policy) bool {
	for _, rule := range CCV2PolicyRules(policy) {
		if rule.Action.Challenge != nil {
			return true
		}
	}
	return false
}

// CCV2PolicyCountsByKey reports a compiled policy with counting keys: agents
// need CC API v4 (older agents accept dimension client_ip only and refuse
// the whole policy, which takes the site down with 503).
func CCV2PolicyCountsByKey(policy CCV2Policy) bool {
	for _, rule := range CCV2PolicyRules(policy) {
		if len(rule.CountBy) != 0 {
			return true
		}
	}
	return false
}

// CCV2PolicyNeedsV6 reports a compiled policy with trusted crawlers, a pass
// cookie domain, IP lists or header matches: agents need CC API v6 (older
// ones decode policies strictly and refuse them).
func CCV2PolicyNeedsV6(policy CCV2Policy) bool {
	if policy.TrustedCrawlers != nil || policy.ChallengeCookieDomain != "" {
		return true
	}
	for _, rule := range CCV2PolicyRules(policy) {
		if rule.Match.ClientIP != nil || rule.Match.Headers != nil {
			return true
		}
	}
	return false
}

// CCV2PolicyNeedsMatchKeys reports a compiled policy counting by User-Agent,
// Referer, a header, cookie or query argument, or matching on JA4: agents
// need CC API v7 (CAPABILITY_NAME_CC_MATCH_KEYS v1; older ones decode
// policies strictly and refuse them).
func CCV2PolicyNeedsMatchKeys(policy CCV2Policy) bool {
	for _, rule := range CCV2PolicyRules(policy) {
		if rule.Match.JA4 != nil {
			return true
		}
		for _, key := range rule.CountBy {
			if ccV2MatchKeysCountKey(key.Key) {
				return true
			}
		}
	}
	return false
}

// CCMatchKeysAPIVersion is CAPABILITY_NAME_CC_MATCH_KEYS v1; such a policy
// is CC API v7 (CCMatchKeysCCAPIVersion).
const (
	CCMatchKeysAPIVersion   uint32 = 1
	CCMatchKeysCCAPIVersion uint32 = 7
)

// ListenerSecurityUsesCCMatchKeys reports a site runtime v2 listener whose
// CC policy needs CAPABILITY_NAME_CC_MATCH_KEYS.
func ListenerSecurityUsesCCMatchKeys(security *ListenerSecurity) bool {
	return security != nil && security.CC != nil && CCV2PolicyNeedsMatchKeys(security.CC.Policy)
}

// CCV2PolicyAPIVersion is the CC API version a compiled policy needs.
// v5: auto switch (older agents decode policies strictly and refuse it).
// v6: trusted crawlers, pass cookie domain, IP lists, header matches.
// v7: count keys user_agent / referer / header / cookie / query, JA4 match.
func CCV2PolicyAPIVersion(policy CCV2Policy) uint32 {
	switch {
	case policy.AutoSwitch != nil && len(policy.AutoSwitch.Overrides) != 0:
		return CCAutoSwitchOverridesAPIVersion
	case CCV2PolicyNeedsMatchKeys(policy):
		return CCMatchKeysCCAPIVersion
	case CCV2PolicyNeedsV6(policy):
		return 6
	case policy.AutoSwitch != nil:
		return 5
	case CCV2PolicyCountsByKey(policy):
		return 4
	case CCV2PolicyNeedsProofOfWork(policy):
		return 3
	}
	return 2
}

type CCV2SiteBinding struct {
	SourceSHA256   string
	CompiledSHA256 string
	Policy         CCV2Policy
}

type CCV2Registry struct {
	SchemaVersion   string              `json:"schema_version"`
	ConfigVersionID string              `json:"config_version_id"`
	Entries         []CCV2RegistryEntry `json:"entries"`
}

type CCV2RegistryEntry struct {
	EntryID         string   `json:"entry_id"`
	TenantScopeID   string   `json:"tenant_scope_id"`
	SiteID          string   `json:"site_id"`
	Hostname        string   `json:"hostname"`
	ListenPort      uint16   `json:"listen_port"`
	Protocol        Protocol `json:"protocol"`
	PolicyID        string   `json:"policy_id"`
	PolicyVersion   int64    `json:"policy_version"`
	BindingID       string   `json:"binding_id"`
	BindingRevision int64    `json:"binding_revision"`
	PublicationID   string   `json:"publication_id"`
	SourceSHA256    string   `json:"source_sha256"`
	CompiledPath    string   `json:"compiled_path"`
	CompiledSHA256  string   `json:"compiled_sha256"`
}

func CanonicalCCV2Policy(policy CCV2Policy) ([]byte, error) {
	if err := validateCCV2Policy(policy); err != nil {
		return nil, err
	}
	return json.Marshal(policy)
}

func DecodeCCV2Policy(content []byte) (CCV2Policy, error) {
	if len(content) == 0 || len(content) > MaxConfigurationBundleFileBytes || RejectDuplicateJSONKeys(content) != nil {
		return CCV2Policy{}, ErrInvalidConfig
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var policy CCV2Policy
	if decoder.Decode(&policy) != nil || decoder.Decode(&struct{}{}) != io.EOF || validateCCV2Policy(policy) != nil {
		return CCV2Policy{}, ErrInvalidConfig
	}
	canonical, err := json.Marshal(policy)
	if err != nil || !bytes.Equal(canonical, content) {
		return CCV2Policy{}, ErrInvalidConfig
	}
	return policy, nil
}

func CanonicalCCV2Registry(registry CCV2Registry) ([]byte, error) {
	if err := validateCCV2Registry(registry); err != nil {
		return nil, err
	}
	return json.Marshal(registry)
}

func DecodeCCV2RegistryFromNginx(nginx []byte) (CCV2Registry, error) {
	document, ok := parseNginxDirectives(string(nginx))
	if !ok || document.hasInclude {
		return CCV2Registry{}, ErrInvalidConfig
	}
	httpBlocks := document.blockIDs(0, []string{"http"})
	if len(httpBlocks) != 1 {
		return CCV2Registry{}, ErrInvalidConfig
	}
	initBlocks := document.blockNamed(httpBlocks[0], "init_by_lua_block")
	if len(initBlocks) != 1 {
		return CCV2Registry{}, ErrInvalidConfig
	}
	// A JS challenge site appends its engine init to the same block
	// (renderChallengeInit); the registry contract is the head.
	initBody, challengeTail, split := splitChallengeInitTail(strings.TrimSpace(document.opaqueBodies[initBlocks[0].blockID]))
	if !split {
		return CCV2Registry{}, ErrInvalidConfig
	}

	begin := bytes.Index(nginx, []byte(CCV2RegistryBeginMarker))
	end := bytes.Index(nginx, []byte(CCV2RegistryEndMarker))
	if begin < 0 || end <= begin || bytes.Index(nginx[begin+len(CCV2RegistryBeginMarker):], []byte(CCV2RegistryBeginMarker)) >= 0 ||
		bytes.Index(nginx[end+len(CCV2RegistryEndMarker):], []byte(CCV2RegistryEndMarker)) >= 0 {
		return CCV2Registry{}, ErrInvalidConfig
	}
	block := nginx[begin:end]
	open := bytes.Index(block, []byte(ccV2RegistryOpen))
	close := bytes.LastIndex(block, []byte(ccV2RegistryClose))
	if open < 0 || close <= open+len(ccV2RegistryOpen) {
		return CCV2Registry{}, ErrInvalidConfig
	}
	// A chunked registry is long strings joined by ", "; the exact rendering
	// is re-checked against ccV2RegistryLua below.
	content := bytes.ReplaceAll(block[open+len(ccV2RegistryOpen):close], []byte(ccV2RegistryClose+", "+ccV2RegistryOpen), nil)
	if bytes.Contains(content, []byte(ccV2RegistryOpen)) || bytes.Contains(content, []byte(ccV2RegistryClose)) {
		return CCV2Registry{}, ErrInvalidConfig
	}
	if RejectDuplicateJSONKeys(content) != nil {
		return CCV2Registry{}, ErrInvalidConfig
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var registry CCV2Registry
	if decoder.Decode(&registry) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return CCV2Registry{}, ErrInvalidConfig
	}
	canonical, err := CanonicalCCV2Registry(registry)
	if err != nil || !bytes.Equal(canonical, content) {
		return CCV2Registry{}, ErrInvalidConfig
	}
	expectedBody := "require(\"" + CCV2LuaModule +
		"\").init({ state_dict = \"" + CCV2StateDictionary +
		"\", release_root = ngx.config.prefix(), registry_json = " + ccV2RegistryLua(canonical) + " })"
	expectedBodyWithFreshness := expectedBody + `; require("cachefreshness.guard")`
	if challengeTail != "" {
		challengeTail += "\n"
	}
	wrappedBody := initBody + challengeTail
	expected := []byte(CCV2RegistryBeginMarker + "\n  init_by_lua_block { " + expectedBody + challengeTail + " }\n  ")
	expectedWithFreshness := []byte(CCV2RegistryBeginMarker + "\n  init_by_lua_block { " + expectedBodyWithFreshness + challengeTail + " }\n  ")
	if initBody != expectedBody && initBody != expectedBodyWithFreshness ||
		!bytes.Equal(block, expected) && !bytes.Equal(block, expectedWithFreshness) {
		return CCV2Registry{}, ErrInvalidConfig
	}
	expectedInit := []byte("  init_by_lua_block { " + wrappedBody + " }\n")
	initOffset := bytes.Index(block, expectedInit)
	if initOffset < 0 {
		return CCV2Registry{}, ErrInvalidConfig
	}
	withoutWrappedInit := make([]byte, 0, len(nginx)-len(expectedInit))
	withoutWrappedInit = append(withoutWrappedInit, nginx[:begin+initOffset]...)
	withoutWrappedInit = append(withoutWrappedInit, nginx[begin+initOffset+len(expectedInit):]...)
	withoutDocument, withoutOK := parseNginxDirectives(string(withoutWrappedInit))
	withoutHTTP := []int(nil)
	if withoutOK && !withoutDocument.hasInclude {
		withoutHTTP = withoutDocument.blockIDs(0, []string{"http"})
	}
	if !withoutOK || len(withoutHTTP) != 1 ||
		len(withoutDocument.blockNamed(withoutHTTP[0], "init_by_lua_block")) != 0 {
		return CCV2Registry{}, ErrInvalidConfig
	}
	if validateCCV2NginxBindings(nginx, registry) != nil {
		return CCV2Registry{}, ErrInvalidConfig
	}
	return registry, nil
}

func ValidateCCV2Bundle(bundle Bundle) error {
	nginx := bundle.Files["nginx.conf"]
	hasLuaArtifact, validDetection := ccV2NginxHasArtifact(nginx)
	if !validDetection {
		return fmt.Errorf("%w: invalid CC v2 Lua", ErrInvalidBundle)
	}
	hasArtifact := hasLuaArtifact || bytes.Contains(nginx, []byte(CCV2RegistryBeginMarker)) ||
		bytes.Contains(nginx, []byte(CCV2RegistryEndMarker))
	for path := range bundle.Files {
		if ccV2CompiledBundlePath(path) {
			hasArtifact = true
			break
		}
	}
	if !hasArtifact {
		return nil
	}

	registry, err := DecodeCCV2RegistryFromNginx(nginx)
	if err != nil {
		return fmt.Errorf("%w: invalid CC v2 registry", ErrInvalidBundle)
	}
	referenced := make(map[string]struct{}, len(registry.Entries))
	for _, entry := range registry.Entries {
		content, ok := bundle.Files[entry.CompiledPath]
		if !ok {
			return fmt.Errorf("%w: CC v2 compiled policy is missing", ErrInvalidBundle)
		}
		digest := sha256.Sum256(content)
		if hex.EncodeToString(digest[:]) != entry.CompiledSHA256 {
			return fmt.Errorf("%w: CC v2 compiled policy digest mismatch", ErrInvalidBundle)
		}
		policy, decodeErr := DecodeCCV2Policy(content)
		if decodeErr != nil {
			return fmt.Errorf("%w: invalid CC v2 compiled policy", ErrInvalidBundle)
		}
		if policy.TenantScopeID != entry.TenantScopeID || policy.SiteID != entry.SiteID ||
			policy.PolicyID != entry.PolicyID || policy.PolicyVersion != entry.PolicyVersion ||
			policy.BindingID != entry.BindingID || policy.BindingRevision != entry.BindingRevision ||
			policy.PublicationID != entry.PublicationID {
			return fmt.Errorf("%w: CC v2 compiled policy identity mismatch", ErrInvalidBundle)
		}
		referenced[entry.CompiledPath] = struct{}{}
	}
	for path := range bundle.Files {
		if ccV2CompiledBundlePath(path) {
			if _, ok := referenced[path]; !ok {
				return fmt.Errorf("%w: unreferenced CC v2 compiled policy", ErrInvalidBundle)
			}
		}
	}
	return nil
}

func ccV2NginxHasArtifact(nginx []byte) (bool, bool) {
	document, ok := parseNginxDirectives(string(nginx))
	if !ok {
		return false, !ccV2PlausibleModuleReference(string(nginx))
	}
	for _, body := range document.opaqueBodies {
		tokens, tokenized := cacheFreshnessLuaTokens(body)
		if !tokenized || !cacheFreshnessLuaWithinBudget(tokens) {
			if ccV2PlausibleModuleReference(body) {
				return false, false
			}
			continue
		}
		for index := range tokens {
			if !cacheFreshnessLuaTokenIs(tokens, index, cacheFreshnessLuaName, "require") {
				continue
			}
			previous := cacheFreshnessLuaPrevious(tokens, index-1)
			if cacheFreshnessLuaTokenIs(tokens, previous, cacheFreshnessLuaSymbol, ".") ||
				cacheFreshnessLuaTokenIs(tokens, previous, cacheFreshnessLuaSymbol, ":") {
				continue
			}
			opening := cacheFreshnessLuaNext(tokens, index+1)
			module := cacheFreshnessLuaNext(tokens, opening+1)
			closing := cacheFreshnessLuaNext(tokens, module+1)
			if cacheFreshnessLuaTokenIs(tokens, opening, cacheFreshnessLuaSymbol, "(") &&
				cacheFreshnessLuaTokenIs(tokens, module, cacheFreshnessLuaString, CCV2LuaModule) &&
				!tokens[module].escaped &&
				cacheFreshnessLuaTokenIs(tokens, closing, cacheFreshnessLuaSymbol, ")") {
				return true, true
			}
		}
	}
	return false, true
}

func ccV2PlausibleModuleReference(content string) bool {
	return strings.Contains(content, "require") && strings.Contains(content, CCV2LuaModule)
}

func ccV2CompiledBundlePath(path string) bool {
	const prefix = "security/"
	const suffix = "/cc.compiled.json"
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return false
	}
	siteID := strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix)
	return siteID != "" && !strings.Contains(siteID, "/")
}

var ccV2SetDirectiveLine = regexp.MustCompile(`(?m)^[\t ]*set[\t ]+`)

func validateCCV2NginxBindings(nginx []byte, registry CCV2Registry) error {
	document, ok := parseNginxDirectives(string(nginx))
	httpBlocks := []int(nil)
	if ok {
		httpBlocks = document.blockIDs(0, []string{"http"})
	}
	if !ok || document.hasInclude || len(httpBlocks) != 1 || !validNginxListenerPlacement(document, httpBlocks[0]) {
		return ErrInvalidConfig
	}
	httpBlock := httpBlocks[0]
	servers := make(map[string]int)
	for _, directive := range document.blockNamed(httpBlock, "server") {
		server := directive.blockID
		domains := make(map[string]struct{})
		for _, serverName := range document.directNamed(server, "server_name") {
			if serverName.nameQuoted {
				continue
			}
			for _, domain := range serverName.fields[1:] {
				domains[strings.ToLower(domain)] = struct{}{}
			}
		}
		ports := make(map[uint16]struct{})
		for _, listen := range document.directNamed(server, "listen") {
			if port, valid := nginxListenPort(listen); valid {
				ports[port] = struct{}{}
			}
		}
		for domain := range domains {
			for port := range ports {
				key := ccV2ListenerKey(domain, port)
				if previous, exists := servers[key]; exists && previous != server {
					servers[key] = 0
				} else if !exists {
					servers[key] = server
				}
			}
		}
	}
	canonicalHooks := canonicalCCV2ServerHookOrderIndex(nginx)
	usedHooks := make(map[int]struct{}, len(registry.Entries))
	usedLogHooks := make(map[int]struct{}, len(registry.Entries))
	for _, entry := range registry.Entries {
		server := servers[ccV2ListenerKey(entry.Hostname, entry.ListenPort)]
		if server == 0 {
			return ErrInvalidConfig
		}
		hooks := document.blockNamed(server, "server_rewrite_by_lua_block")
		if len(hooks) != 1 {
			return ErrInvalidConfig
		}
		hook := hooks[0]
		// The hook may first assign the server's own telemetry identity
		// (ccV2IdentityPrelude), exactly as its `set`s do.
		call := fmt.Sprintf("return require(%q).access(%q)", CCV2LuaModule, entry.EntryID)
		prelude, preludeOK := ccV2ServerIdentityPrelude(document, server)
		body := strings.TrimSpace(document.opaqueBodies[hook.blockID])
		if _, duplicate := usedHooks[hook.blockID]; duplicate || !preludeOK ||
			body != call && (prelude == "" || body != prelude+"\n      "+call) ||
			canonicalHooks[ccV2CanonicalListenerKey(entry)] != entry.EntryID {
			return ErrInvalidConfig
		}
		logHooks := document.blockNamed(server, "log_by_lua_block")
		if len(logHooks) != 1 || strings.TrimSpace(document.opaqueBodies[logHooks[0].blockID]) !=
			`require("cc").log()` {
			return ErrInvalidConfig
		}
		usedHooks[hook.blockID] = struct{}{}
		usedLogHooks[logHooks[0].blockID] = struct{}{}
	}
	for _, names := range document.blockNames {
		for _, hook := range names["server_rewrite_by_lua_block"] {
			if _, used := usedHooks[hook.blockID]; !used {
				return ErrInvalidConfig
			}
		}
	}
	for _, names := range document.blockNames {
		for _, hook := range names["log_by_lua_block"] {
			if strings.TrimSpace(document.opaqueBodies[hook.blockID]) != `require("cc").log()` {
				continue
			}
			if _, used := usedLogHooks[hook.blockID]; !used {
				return ErrInvalidConfig
			}
		}
	}
	if len(usedHooks) != len(registry.Entries) || len(usedLogHooks) != len(registry.Entries) {
		return ErrInvalidConfig
	}
	return nil
}

func ccV2ListenerKey(host string, port uint16) string {
	return strings.ToLower(host) + "\x00" + strconv.Itoa(int(port))
}

// HasLegacyNginxACL reports real allow/deny directives outside opaque Lua blocks.
// The generated baseline allow-all directive is the sole non-legacy exception.
func HasLegacyNginxACL(nginx []byte) bool {
	document, ok := parseNginxDirectives(string(nginx))
	if !ok {
		return true
	}
	for _, directives := range document.direct {
		if len(directives["deny"]) != 0 {
			return true
		}
		for _, directive := range directives["allow"] {
			if len(directive.fields) != 2 || directive.fields[1] != "all" {
				return true
			}
		}
	}
	return false
}

func canonicalCCV2ServerHookOrderIndex(nginx []byte) map[string]string {
	result := make(map[string]string)
	for _, tail := range strings.Split(string(nginx), "\n  server {\n")[1:] {
		closing := strings.Index(tail, "\n  }")
		if closing < 0 {
			continue
		}
		lines := strings.Split(tail[:closing], "\n")
		host, port, protocol, valid := canonicalCCV2ServerIdentity(lines)
		if !valid {
			continue
		}
		entryID := ""
		for index := 3; index < len(lines); index++ {
			if ccV2SetDirectiveLine.MatchString(lines[index]) && entryID == "" {
				valid = false
			}
			if lines[index] != "    server_rewrite_by_lua_block {" {
				continue
			}
			// An identity prelude line (ccV2IdentityPrelude) may precede the
			// call; validateCCV2NginxBindings checks it against the `set`s.
			if index+1 < len(lines) && strings.HasPrefix(lines[index+1], "      ngx.var.cdnca_tenant_id = ") {
				index++
			}
			if entryID != "" || index+2 >= len(lines) || lines[index+2] != "    }" {
				valid = false
				break
			}
			const hookPrefix = `      return require("cc").access("`
			const hookSuffix = `")`
			body := lines[index+1]
			if !strings.HasPrefix(body, hookPrefix) || !strings.HasSuffix(body, hookSuffix) {
				valid = false
				break
			}
			entryID = strings.TrimSuffix(strings.TrimPrefix(body, hookPrefix), hookSuffix)
			if index+3 >= len(lines) || lines[index+3] != `    log_by_lua_block { require("cc").log() }` {
				valid = false
				break
			}
			index += 2
		}
		if !valid || entryID == "" {
			continue
		}
		key := host + "\x00" + strconv.Itoa(int(port)) + "\x00" + string(protocol)
		if _, duplicate := result[key]; duplicate {
			result[key] = ""
		} else {
			result[key] = entryID
		}
	}
	return result
}

func canonicalCCV2ServerIdentity(lines []string) (string, uint16, Protocol, bool) {
	if len(lines) < 3 {
		return "", 0, "", false
	}
	const ipv4Prefix = "    listen 0.0.0.0:"
	if !strings.HasPrefix(lines[0], ipv4Prefix) || !strings.HasSuffix(lines[0], ";") {
		return "", 0, "", false
	}
	listen := strings.TrimSuffix(strings.TrimPrefix(lines[0], ipv4Prefix), ";")
	protocol := ProtocolHTTP
	if strings.HasSuffix(listen, " ssl") {
		protocol = ProtocolHTTPS
		listen = strings.TrimSuffix(listen, " ssl")
	}
	parsed, err := strconv.ParseUint(listen, 10, 16)
	if err != nil || parsed == 0 || listen != strconv.FormatUint(parsed, 10) {
		return "", 0, "", false
	}
	port := uint16(parsed)
	options := ""
	if protocol == ProtocolHTTPS {
		options = " ssl"
	}
	if lines[1] != fmt.Sprintf("    listen [::]:%d%s;", port, options) ||
		!strings.HasPrefix(lines[2], "    server_name ") || !strings.HasSuffix(lines[2], ";") {
		return "", 0, "", false
	}
	host := strings.TrimSuffix(strings.TrimPrefix(lines[2], "    server_name "), ";")
	if host == "" || strings.ContainsAny(host, " \t") {
		return "", 0, "", false
	}
	return host, port, protocol, true
}

func ccV2CanonicalListenerKey(entry CCV2RegistryEntry) string {
	return entry.Hostname + "\x00" + strconv.Itoa(int(entry.ListenPort)) + "\x00" + string(entry.Protocol)
}

func CCV2RegistryEntrySHA256(entry CCV2RegistryEntry) (string, error) {
	if err := validateCCV2RegistryEntry(entry); err != nil {
		return "", err
	}
	content, err := json.Marshal(entry)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:]), nil
}

func ccV2RegistryForSpec(spec normalizedSpec) (CCV2Registry, error) {
	registry := CCV2Registry{SchemaVersion: CCV2RegistrySchemaVersion, ConfigVersionID: spec.ConfigVersionID,
		Entries: make([]CCV2RegistryEntry, 0)}
	for _, site := range spec.Sites {
		if site.CCV2 == nil {
			continue
		}
		policy := site.CCV2.Policy
		entry := CCV2RegistryEntry{TenantScopeID: policy.TenantScopeID, SiteID: policy.SiteID,
			Hostname: site.Domain, ListenPort: site.ListenPort, Protocol: site.Protocol,
			PolicyID: policy.PolicyID, PolicyVersion: policy.PolicyVersion, BindingID: policy.BindingID,
			BindingRevision: policy.BindingRevision, PublicationID: policy.PublicationID,
			SourceSHA256: site.CCV2.SourceSHA256, CompiledPath: ccV2CompiledPath(policy.SiteID),
			CompiledSHA256: site.CCV2.CompiledSHA256}
		entry.EntryID = ccV2RegistryEntryID(entry)
		registry.Entries = append(registry.Entries, entry)
	}
	// Sites and listeners arrive in site order; the registry is canonical in
	// (port, hostname, protocol, entry) order.
	registry = sortedCCV2Registry(registry)
	if err := validateCCV2Registry(registry); err != nil {
		return CCV2Registry{}, err
	}
	return registry, nil
}

func normalizeCCV2SiteBinding(tenantID string, site Site) (*CCV2SiteBinding, error) {
	if site.CCV2 == nil {
		return nil, nil
	}
	value := *site.CCV2
	value.Policy.TrustedProxies = make([]string, len(site.CCV2.Policy.TrustedProxies))
	copy(value.Policy.TrustedProxies, site.CCV2.Policy.TrustedProxies)
	value.Policy.Allowlist = make([]string, len(site.CCV2.Policy.Allowlist))
	copy(value.Policy.Allowlist, site.CCV2.Policy.Allowlist)
	value.Policy.Rules = cloneCCV2Rules(site.CCV2.Policy.Rules)
	value.Policy.TrustedCrawlers = cloneCCV2TrustedCrawlers(site.CCV2.Policy.TrustedCrawlers)
	if site.CCV2.Policy.AutoSwitch != nil {
		autoSwitch := *site.CCV2.Policy.AutoSwitch
		autoSwitch.Rules = cloneCCV2Rules(autoSwitch.Rules)
		autoSwitch.Overrides = nil
		for _, override := range site.CCV2.Policy.AutoSwitch.Overrides {
			override.Nodes = append([]string(nil), override.Nodes...)
			autoSwitch.Overrides = append(autoSwitch.Overrides, override)
		}
		autoSwitch.RuleSets = nil
		for _, set := range site.CCV2.Policy.AutoSwitch.RuleSets {
			autoSwitch.RuleSets = append(autoSwitch.RuleSets, CCV2AutoSwitchRuleSet{Name: set.Name, Rules: cloneCCV2Rules(set.Rules)})
		}
		value.Policy.AutoSwitch = &autoSwitch
	}
	if value.Policy.TenantScopeID != tenantID || value.Policy.SiteID != site.ID ||
		!canonicalSHA256Text(value.SourceSHA256) || !canonicalSHA256Text(value.CompiledSHA256) {
		return nil, ErrInvalidConfig
	}
	canonical, err := CanonicalCCV2Policy(value.Policy)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(canonical)
	if hex.EncodeToString(digest[:]) != value.CompiledSHA256 {
		return nil, ErrInvalidConfig
	}
	return &value, nil
}

func cloneCCV2Rules(source []CCV2Rule) []CCV2Rule {
	if source == nil {
		return nil
	}
	rules := make([]CCV2Rule, len(source))
	copy(rules, source)
	for index := range rules {
		rule := &rules[index]
		if path := rule.Match.Path; path != nil {
			copy := *path
			rule.Match.Path = &copy
		}
		if rule.Match.PathContains != nil {
			rule.Match.PathContains = append([]string(nil), rule.Match.PathContains...)
		}
		if rule.Match.ClientIP != nil {
			entries := make([]CCV2IPMatch, len(rule.Match.ClientIP))
			for entry, value := range rule.Match.ClientIP {
				entries[entry] = CCV2IPMatch{Negate: value.Negate, CIDRs: append([]string(nil), value.CIDRs...)}
			}
			rule.Match.ClientIP = entries
		}
		if rule.Match.Headers != nil {
			entries := make([]CCV2HeaderMatch, len(rule.Match.Headers))
			for entry, value := range rule.Match.Headers {
				entries[entry] = CCV2HeaderMatch{Name: value.Name, Kind: value.Kind, Values: append([]string(nil), value.Values...)}
			}
			rule.Match.Headers = entries
		}
		if rule.CountBy != nil {
			rule.CountBy = append([]CCV2CountKey(nil), rule.CountBy...)
		}
		if challenge := rule.Action.Challenge; challenge != nil {
			copy := *challenge
			if challenge.PassLimit != nil {
				limit := *challenge.PassLimit
				copy.PassLimit = &limit
			}
			rule.Action.Challenge = &copy
		}
	}
	return rules
}

func validateCCV2Policy(policy CCV2Policy) error {
	if policy.SchemaVersion != CCV2SchemaVersion || !uuidPattern.MatchString(policy.TenantScopeID) ||
		!uuidPattern.MatchString(policy.SiteID) || !uuidPattern.MatchString(policy.PolicyID) ||
		!uuidPattern.MatchString(policy.BindingID) || !uuidPattern.MatchString(policy.PublicationID) ||
		policy.PolicyVersion < 1 || policy.PolicyVersion > 1<<53-1 || policy.BindingRevision < 1 ||
		policy.BindingRevision > 1<<53-1 || policy.TrustedProxies == nil || len(policy.TrustedProxies) != 0 ||
		policy.Allowlist == nil || len(policy.Allowlist) != 0 || policy.Rules == nil || len(policy.Rules) > ccV2MaxRules {
		return ErrInvalidConfig
	}
	seen := make(map[string]struct{}, len(policy.Rules))
	if err := validateCCV2Rules(policy.Rules, seen); err != nil {
		return err
	}
	if (policy.TrustedCrawlers != nil || policy.ChallengeCookieDomain != "") && !policy.Enabled ||
		validateCCV2TrustedCrawlers(policy.TrustedCrawlers) != nil ||
		policy.ChallengeCookieDomain != "" && !ValidCCV2CookieDomain(policy.ChallengeCookieDomain) {
		return ErrInvalidConfig
	}
	if value := policy.AutoSwitch; value != nil {
		// Rule IDs are distinct across both sets (one binding's state keys).
		if !policy.Enabled || len(value.Overrides) == 0 && len(value.RuleSets) != 0 {
			return ErrInvalidConfig
		}
		globalOff := len(value.Overrides) != 0 && value.QPSTotal == 0 && value.QPS5xx == 0 &&
			value.RecoverSeconds == 0 && value.Rules != nil && len(value.Rules) == 0
		if !globalOff && (value.QPSTotal > 1_000_000 || value.QPS5xx > 1_000_000 ||
			value.QPSTotal == 0 && value.QPS5xx == 0 || value.RecoverSeconds < 60 || value.RecoverSeconds > 86_400 ||
			len(value.Rules) < 1 || len(value.Rules) > ccV2MaxRules) {
			return ErrInvalidConfig
		}
		if err := validateCCV2Rules(value.Rules, seen); err != nil {
			return err
		}
		return validateCCV2AutoSwitchOverrides(value, globalOff, seen)
	}
	return nil
}

// validateCCV2Rules checks one ordered rule set; seen collects rule IDs.
func validateCCV2Rules(rules []CCV2Rule, seen map[string]struct{}) error {
	previousPriority := -1
	previousID := ""
	for _, rule := range rules {
		if !uuidPattern.MatchString(rule.RuleID) || rule.Priority < 1 || rule.Priority > 1_000_000 ||
			rule.Dimension != CCV2DimensionClientIP || validateCCV2Match(rule.Match) != nil ||
			validateCCV2Limit(rule.Limit) != nil || validateCCV2Action(rule.Action, rule.Flow) != nil ||
			validateCCV2CountBy(rule) != nil ||
			rule.Limit.Algorithm == CCV2AlgorithmAlways && rule.Action.Kind != CCV2ActionChallenge ||
			(rule.Match.DistinctUserAgents != 0 || rule.Match.Status404Count != 0) &&
				rule.Limit.Algorithm != CCV2AlgorithmFixedWindow {
			return ErrInvalidConfig
		}
		if _, duplicate := seen[rule.RuleID]; duplicate || rule.Priority < previousPriority ||
			rule.Priority == previousPriority && rule.RuleID <= previousID {
			return ErrInvalidConfig
		}
		seen[rule.RuleID] = struct{}{}
		previousPriority, previousID = rule.Priority, rule.RuleID
	}
	return nil
}

// validateCCV2CountBy accepts the canonical form securitypolicy stores:
// one or two distinct keys in ccV2CountKeyOrder, never client_ip alone,
// client_cidr with both prefixes, no client_ip+client_cidr or uri+uri_path,
// no per-client statistics conditions, a challenge only through its
// fixed-window trigger. Target count_key only with a temporary ban.
func validateCCV2CountBy(rule CCV2Rule) error {
	if rule.Action.Target != "" && (rule.Action.Target != CCV2ActionTargetCountKey ||
		rule.Action.Kind != CCV2ActionTemporaryBan || rule.CountBy == nil) {
		return ErrInvalidConfig
	}
	if rule.CountBy == nil {
		return nil
	}
	if len(rule.CountBy) < 1 || len(rule.CountBy) > 2 ||
		len(rule.CountBy) == 1 && rule.CountBy[0].Key == CCV2CountClientIP ||
		rule.Match.DistinctUserAgents != 0 || rule.Match.Status404Count != 0 ||
		rule.Action.Kind == CCV2ActionChallenge && rule.Limit.Algorithm != CCV2AlgorithmFixedWindow {
		return ErrInvalidConfig
	}
	seen := map[CCV2CountKeyName]bool{}
	previous := -1
	for _, key := range rule.CountBy {
		position := -1
		for index, name := range ccV2CountKeyOrder {
			if name == key.Key {
				position = index
			}
		}
		if position <= previous {
			return ErrInvalidConfig
		}
		previous = position
		seen[key.Key] = true
		if key.Key == CCV2CountClientCIDR {
			if key.IPv4Prefix < 8 || key.IPv4Prefix > 32 || key.IPv6Prefix < 32 || key.IPv6Prefix > 128 {
				return ErrInvalidConfig
			}
		} else if key.IPv4Prefix != 0 || key.IPv6Prefix != 0 {
			return ErrInvalidConfig
		}
		switch key.Key {
		case CCV2CountHeader:
			if !ccV2CountHeaderNamePattern.MatchString(key.Name) {
				return ErrInvalidConfig
			}
		case CCV2CountCookie, CCV2CountQuery:
			if !ccV2CountParamNamePattern.MatchString(key.Name) {
				return ErrInvalidConfig
			}
		default:
			if key.Name != "" {
				return ErrInvalidConfig
			}
		}
	}
	if seen[CCV2CountClientIP] && seen[CCV2CountClientCIDR] || seen[CCV2CountURI] && seen[CCV2CountURIPath] {
		return ErrInvalidConfig
	}
	return nil
}

func validateCCV2Match(match CCV2Match) error {
	if match.DistinctUserAgents > 1024 || match.Status404Count > 1024 {
		return ErrInvalidConfig
	}
	if match.Host != "" {
		// An exact host or a wildcard site domain ("*.x.example": a wildcard
		// alias of a site runtime v2 server, matched as server_name does).
		normalized, err := normalizeSiteDomainName(match.Host)
		if err != nil || normalized != match.Host {
			return ErrInvalidConfig
		}
	}
	if match.Method != "" && !ccV2MethodPattern.MatchString(match.Method) {
		return ErrInvalidConfig
	}
	if match.Path != nil {
		if match.Path.Kind != CCV2PathExact && match.Path.Kind != CCV2PathPrefix ||
			len(match.Path.Value) == 0 || len(match.Path.Value) > 1024 || !utf8.ValidString(match.Path.Value) || match.Path.Value[0] != '/' ||
			strings.ContainsAny(match.Path.Value, "\\%?#") || strings.Contains(match.Path.Value, "//") {
			return ErrInvalidConfig
		}
		for _, segment := range strings.Split(match.Path.Value, "/") {
			if segment == "." || segment == ".." {
				return ErrInvalidConfig
			}
			for _, character := range segment {
				if unicode.IsControl(character) {
					return ErrInvalidConfig
				}
			}
		}
	}
	if match.PathContains != nil {
		if len(match.PathContains) == 0 || len(match.PathContains) > 64 || match.Path != nil {
			return ErrInvalidConfig
		}
		for index, value := range match.PathContains {
			if len(value) == 0 || len(value) > 256 || !utf8.ValidString(value) || strings.IndexFunc(value, unicode.IsControl) >= 0 ||
				index > 0 && match.PathContains[index-1] >= value {
				return ErrInvalidConfig
			}
		}
	}
	if match.SourceCIDR != "" && !canonicalCCV2CIDR(match.SourceCIDR) {
		return ErrInvalidConfig
	}
	if match.JA4 != nil {
		normalized, err := normalizeWAFJA4(match.JA4)
		if err != nil || !slices.Equal(normalized, match.JA4) {
			return ErrInvalidConfig
		}
	}
	if match.ClientIP != nil {
		// A single plain CIDR is SourceCIDR (the pre-v6 bytes); the two never mix.
		if len(match.ClientIP) == 0 || len(match.ClientIP) > ccV2MaxIPMatches || match.SourceCIDR != "" ||
			len(match.ClientIP) == 1 && !match.ClientIP[0].Negate && len(match.ClientIP[0].CIDRs) == 1 {
			return ErrInvalidConfig
		}
		for _, entry := range match.ClientIP {
			if !sortedCCV2CIDRs(entry.CIDRs, 1, ccV2MaxIPMatchCIDRs) {
				return ErrInvalidConfig
			}
		}
	}
	if match.Headers != nil {
		if len(match.Headers) == 0 || len(match.Headers) > ccV2MaxHeaderMatches {
			return ErrInvalidConfig
		}
		for _, entry := range match.Headers {
			if validateCCV2HeaderMatch(entry) != nil {
				return ErrInvalidConfig
			}
		}
	}
	return nil
}

func canonicalCCV2CIDR(value string) bool {
	prefix, err := netip.ParsePrefix(value)
	return err == nil && !prefix.Addr().Is4In6() && prefix.Masked().String() == value
}

// sortedCCV2CIDRs: minimum..maximum canonical CIDRs in strictly ascending
// text order.
func sortedCCV2CIDRs(values []string, minimum, maximum int) bool {
	if len(values) < minimum || len(values) > maximum {
		return false
	}
	for index, value := range values {
		if !canonicalCCV2CIDR(value) || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}

var ccV2HeaderNamePattern = regexp.MustCompile(`^[!#$%&'*+.^_` + "`" + `|~0-9a-z-]{1,128}$`)

func validateCCV2HeaderMatch(entry CCV2HeaderMatch) error {
	if !ccV2HeaderNamePattern.MatchString(entry.Name) || len(entry.Values) < 1 || len(entry.Values) > ccV2MaxHeaderValues {
		return ErrInvalidConfig
	}
	switch entry.Kind {
	case CCV2HeaderExact, CCV2HeaderPrefix, CCV2HeaderContains, CCV2HeaderRegex:
	default:
		return ErrInvalidConfig
	}
	for index, value := range entry.Values {
		if len(value) == 0 || len(value) > 1024 || !utf8.ValidString(value) || strings.IndexFunc(value, unicode.IsControl) >= 0 ||
			index > 0 && entry.Values[index-1] >= value {
			return ErrInvalidConfig
		}
		if entry.Kind == CCV2HeaderRegex {
			if _, err := regexp.Compile(value); err != nil {
				return ErrInvalidConfig
			}
		}
	}
	return nil
}

// validateCCV2TrustedCrawlers: nil, or 1..32 crawlers sorted by distinct
// name, each with sorted distinct printable User-Agent tokens and at least
// one verification (networks or rDNS suffixes of two labels or more).
func validateCCV2TrustedCrawlers(crawlers []CCV2TrustedCrawler) error {
	if crawlers == nil {
		return nil
	}
	if len(crawlers) == 0 || len(crawlers) > ccV2MaxTrustedCrawlers {
		return ErrInvalidConfig
	}
	for index, crawler := range crawlers {
		if !ValidCCV2CrawlerName(crawler.Name) || index > 0 && crawlers[index-1].Name >= crawler.Name ||
			len(crawler.UserAgentTokens) < 1 || len(crawler.UserAgentTokens) > ccV2MaxCrawlerTokens ||
			crawler.Networks == nil && crawler.RDNSSuffixes == nil ||
			crawler.Networks != nil && !sortedCCV2CIDRs(crawler.Networks, 1, ccV2MaxCrawlerNetworks) ||
			crawler.RDNSSuffixes != nil && (len(crawler.RDNSSuffixes) < 1 || len(crawler.RDNSSuffixes) > ccV2MaxCrawlerSuffixes) {
			return ErrInvalidConfig
		}
		for position, token := range crawler.UserAgentTokens {
			if !ValidCCV2CrawlerToken(token) || position > 0 && crawler.UserAgentTokens[position-1] >= token {
				return ErrInvalidConfig
			}
		}
		for _, network := range crawler.Networks {
			if prefix, _ := netip.ParsePrefix(network); prefix.Bits() == 0 {
				return ErrInvalidConfig
			}
		}
		for position, suffix := range crawler.RDNSSuffixes {
			if !ValidCCV2CookieDomain(suffix) || position > 0 && crawler.RDNSSuffixes[position-1] >= suffix {
				return ErrInvalidConfig
			}
		}
	}
	return nil
}

// ValidCCV2CrawlerName: 1..64 bytes of [a-z0-9_.-].
func ValidCCV2CrawlerName(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			character == '-' || character == '_' || character == '.') {
			return false
		}
	}
	return true
}

// ValidCCV2CrawlerToken: 3..128 printable ASCII bytes without spaces (a
// User-Agent product token such as "Googlebot" or "Baiduspider").
func ValidCCV2CrawlerToken(value string) bool {
	if len(value) < 3 || len(value) > 128 {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] <= ' ' || value[index] > '~' {
			return false
		}
	}
	return true
}

// ValidCCV2CookieDomain: a lower-case DNS name of two labels or more, no
// leading dot or wildcard (the pass cookie Domain, a crawler rDNS suffix).
func ValidCCV2CookieDomain(value string) bool {
	normalized, err := normalizeDNSName(value, true)
	return err == nil && normalized == value && !strings.Contains(value, "*")
}

func cloneCCV2TrustedCrawlers(source []CCV2TrustedCrawler) []CCV2TrustedCrawler {
	if source == nil {
		return nil
	}
	result := make([]CCV2TrustedCrawler, len(source))
	for index, crawler := range source {
		result[index] = CCV2TrustedCrawler{Name: crawler.Name,
			UserAgentTokens: append([]string(nil), crawler.UserAgentTokens...)}
		if crawler.Networks != nil {
			result[index].Networks = append([]string(nil), crawler.Networks...)
		}
		if crawler.RDNSSuffixes != nil {
			result[index].RDNSSuffixes = append([]string(nil), crawler.RDNSSuffixes...)
		}
	}
	return result
}

func validateCCV2Limit(limit CCV2Limit) error {
	switch limit.Algorithm {
	case CCV2AlgorithmFixedWindow:
		if limit.Requests < 1 || limit.Requests > 1_000_000 || limit.WindowSeconds < 1 || limit.WindowSeconds > 3600 ||
			limit.PerURI > 1_000_000 || limit.RatePerSecond != 0 || limit.Burst != 0 {
			return ErrInvalidConfig
		}
	case CCV2AlgorithmLeakyBucket:
		if limit.RatePerSecond < 1 || limit.RatePerSecond > 1_000_000 || limit.Burst < 1 || limit.Burst > 1_000_000 ||
			limit.Requests != 0 || limit.WindowSeconds != 0 || limit.PerURI != 0 {
			return ErrInvalidConfig
		}
	case CCV2AlgorithmAlways:
		if limit != (CCV2Limit{Algorithm: CCV2AlgorithmAlways}) {
			return ErrInvalidConfig
		}
	default:
		return ErrInvalidConfig
	}
	return nil
}

func validateCCV2Action(action CCV2Action, flow CCV2Flow) error {
	switch action.Kind {
	case CCV2ActionLog:
		if action.BanSeconds != 0 || action.Challenge != nil || flow != CCV2FlowContinue && flow != CCV2FlowStop {
			return ErrInvalidConfig
		}
	case CCV2ActionReject429:
		if action.BanSeconds != 0 || action.Challenge != nil || flow != CCV2FlowStop {
			return ErrInvalidConfig
		}
	case CCV2ActionTemporaryBan:
		if action.BanSeconds < 1 || action.BanSeconds > 86_400 || flow != CCV2FlowStop || action.Challenge != nil {
			return ErrInvalidConfig
		}
	case CCV2ActionChallenge:
		return validateCCV2Challenge(action, flow)
	default:
		return ErrInvalidConfig
	}
	return nil
}

func validateCCV2Challenge(action CCV2Action, flow CCV2Flow) error {
	challenge := action.Challenge
	if challenge == nil || flow != CCV2FlowStop || !containsString(CCV2ChallengeModes, challenge.Mode) ||
		challenge.FailureWindowSeconds < 1 || challenge.FailureWindowSeconds > 86_400 ||
		challenge.MaxFailures < 1 || challenge.MaxFailures > 1000 ||
		challenge.PassSeconds < 60 || challenge.PassSeconds > 7*86_400 ||
		challenge.LogOnly != (action.BanSeconds == 0) || action.BanSeconds > 86_400 ||
		(challenge.Mode == "delay") != (challenge.DelaySeconds != 0) || challenge.DelaySeconds > 30 {
		return ErrInvalidConfig
	}
	if (challenge.Mode == "redirect") != (challenge.PowBits == 0) ||
		challenge.PowBits != 0 && (challenge.PowBits < 8 || challenge.PowBits > 26) ||
		challenge.ChallengeSeconds < 30 || challenge.ChallengeSeconds > 3600 ||
		challenge.BindIPv4Prefix < 8 || challenge.BindIPv4Prefix > 32 || challenge.BindIPv6Prefix < 32 || challenge.BindIPv6Prefix > 128 ||
		challenge.KeyRotateSeconds < challenge.PassSeconds || challenge.KeyRotateSeconds > 30*86_400 {
		return ErrInvalidConfig
	}
	if challenge.PassLimit != nil && (challenge.PassLimit.Algorithm != CCV2AlgorithmFixedWindow ||
		validateCCV2Limit(*challenge.PassLimit) != nil) {
		return ErrInvalidConfig
	}
	return nil
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func validateCCV2Registry(registry CCV2Registry) error {
	if registry.SchemaVersion != CCV2RegistrySchemaVersion || !versionPattern.MatchString(registry.ConfigVersionID) ||
		registry.Entries == nil || len(registry.Entries) == 0 || len(registry.Entries) > 1000 {
		return ErrInvalidConfig
	}
	seenIDs := make(map[string]struct{}, len(registry.Entries))
	seenListeners := make(map[string]struct{}, len(registry.Entries))
	for index, entry := range registry.Entries {
		if validateCCV2RegistryEntry(entry) != nil || entry.EntryID != ccV2RegistryEntryID(entry) {
			return ErrInvalidConfig
		}
		listener := entry.TenantScopeID + "\x00" + entry.SiteID + "\x00" + entry.Hostname + "\x00" +
			strconv.Itoa(int(entry.ListenPort)) + "\x00" + string(entry.Protocol)
		if _, duplicate := seenIDs[entry.EntryID]; duplicate {
			return ErrInvalidConfig
		}
		if _, duplicate := seenListeners[listener]; duplicate {
			return ErrInvalidConfig
		}
		seenIDs[entry.EntryID] = struct{}{}
		seenListeners[listener] = struct{}{}
		if index > 0 && compareCCV2RegistryEntries(registry.Entries[index-1], entry) >= 0 {
			return ErrInvalidConfig
		}
	}
	return nil
}

func validateCCV2RegistryEntry(entry CCV2RegistryEntry) error {
	if len(entry.EntryID) != 32 || !validHex(entry.EntryID) || !uuidPattern.MatchString(entry.TenantScopeID) ||
		!uuidPattern.MatchString(entry.SiteID) || !uuidPattern.MatchString(entry.PolicyID) ||
		!uuidPattern.MatchString(entry.BindingID) || !uuidPattern.MatchString(entry.PublicationID) ||
		entry.PolicyVersion < 1 || entry.BindingRevision < 1 || entry.ListenPort == 0 ||
		(entry.Protocol != ProtocolHTTP && entry.Protocol != ProtocolHTTPS) ||
		!canonicalSHA256Text(entry.SourceSHA256) || !canonicalSHA256Text(entry.CompiledSHA256) ||
		entry.CompiledPath != ccV2CompiledPath(entry.SiteID) {
		return ErrInvalidConfig
	}
	host, err := normalizeSiteDomainName(entry.Hostname)
	if err != nil || host != entry.Hostname {
		return ErrInvalidConfig
	}
	return nil
}

func ccV2RegistryEntryID(entry CCV2RegistryEntry) string {
	key := entry.TenantScopeID + "\x00" + entry.SiteID + "\x00" + entry.Hostname + "\x00" +
		strconv.Itoa(int(entry.ListenPort)) + "\x00" + string(entry.Protocol)
	digest := sha256.Sum256([]byte(key))
	return hex.EncodeToString(digest[:16])
}

func compareCCV2RegistryEntries(left, right CCV2RegistryEntry) int {
	leftKey := fmt.Sprintf("%05d\x00%s\x00%s\x00%s", left.ListenPort, left.Hostname, left.Protocol, left.EntryID)
	rightKey := fmt.Sprintf("%05d\x00%s\x00%s\x00%s", right.ListenPort, right.Hostname, right.Protocol, right.EntryID)
	return strings.Compare(leftKey, rightKey)
}

func ccV2CompiledPath(siteID string) string {
	return "security/" + siteID + "/cc.compiled.json"
}

func canonicalSHA256Text(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func hasCCV2(sites []Site) bool {
	for _, site := range sites {
		if site.CCV2 != nil {
			return true
		}
	}
	return false
}

func sortedCCV2Registry(registry CCV2Registry) CCV2Registry {
	result := registry
	result.Entries = append([]CCV2RegistryEntry(nil), registry.Entries...)
	sort.Slice(result.Entries, func(left, right int) bool {
		return compareCCV2RegistryEntries(result.Entries[left], result.Entries[right]) < 0
	})
	return result
}

// validateCCV2AutoSwitchOverrides: distinct canonical node IDs, sorted rule
// sets each used, an override's thresholds / recovery like the global value
// (or both thresholds and recovery 0: off), a rule set the switch has (""
// only while the global value is on), rule IDs distinct across every set.
func validateCCV2AutoSwitchOverrides(value *CCV2AutoSwitch, globalOff bool, seen map[string]struct{}) error {
	if len(value.Overrides) > 64 || len(value.RuleSets) > 64 {
		return ErrInvalidConfig
	}
	sets := make(map[string]int, len(value.RuleSets))
	for index, set := range value.RuleSets {
		if set.Name == "" || len(set.Name) > 128 || index > 0 && value.RuleSets[index-1].Name >= set.Name ||
			len(set.Rules) < 1 || len(set.Rules) > ccV2MaxRules {
			return ErrInvalidConfig
		}
		if err := validateCCV2Rules(set.Rules, seen); err != nil {
			return err
		}
		sets[set.Name] = 0
	}
	nodes := map[string]struct{}{}
	for _, override := range value.Overrides {
		if len(override.Nodes) < 1 || len(override.Nodes) > 10_000 {
			return ErrInvalidConfig
		}
		for index, node := range override.Nodes {
			if _, duplicate := nodes[node]; duplicate || !uuidPattern.MatchString(node) ||
				index > 0 && override.Nodes[index-1] >= node {
				return ErrInvalidConfig
			}
			nodes[node] = struct{}{}
		}
		if override.QPSTotal == 0 && override.QPS5xx == 0 {
			if override.RecoverSeconds != 0 || override.RuleSet != "" {
				return ErrInvalidConfig
			}
			continue
		}
		if override.QPSTotal > 1_000_000 || override.QPS5xx > 1_000_000 ||
			override.RecoverSeconds < 60 || override.RecoverSeconds > 86_400 {
			return ErrInvalidConfig
		}
		if override.RuleSet == "" {
			if globalOff {
				return ErrInvalidConfig
			}
			continue
		}
		if _, ok := sets[override.RuleSet]; !ok {
			return ErrInvalidConfig
		}
		sets[override.RuleSet]++
	}
	for _, used := range sets {
		if used == 0 {
			return ErrInvalidConfig
		}
	}
	return nil
}
