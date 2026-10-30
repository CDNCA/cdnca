package edgeconfig

import (
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
)

// Cache rule path regular expressions and response Content-Type conditions.
// Site runtime v2 only: the dynamic
// routing node matches path_regex with ngx.re (PCRE2) on the normalized
// $uri and content_types in the header filter (edge/openresty/dynroute/
// cdnca_cache.lua); both need CACHE_RULE_MATCH.

// CacheRuleMatchCapability is the site object capability name of
// CAPABILITY_NAME_CACHE_RULE_MATCH and the API version a node with this
// code executes (2: per-rule settings, CacheRuleMatchExtrasAPIVersion).
// A policy with path_regex/content_types needs 1.
const (
	CacheRuleMatchCapability        = "cache_rule_match"
	CacheRuleMatchAPIVersion uint32 = CacheRuleMatchExtrasAPIVersion
	MaxCachePathRegexBytes          = 256
	MaxCacheContentTypes            = 16
	// MaxCacheConditionalRules bounds the rules with a path_regex or
	// content_types: the node's plan enumerates the subsets of those a
	// request can match (edgecache candidate sets).
	MaxCacheConditionalRules = 8
	// CachePathRegexMatchLimit is the node's lua_regex_match_limit: a match
	// that needs more backtracking steps fails (the rule does not match).
	CachePathRegexMatchLimit = 100000
)

// cacheContentTypePattern: type "/" subtype, or a prefix of one ending in "*".
var cacheContentTypePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9!#$&^_.+-]{0,63}(?:/[a-z0-9!#$&^_.+-]{0,64})?\*?$`)

// ValidateCachePathRegex accepts a regular expression both RE2 (the control
// plane) and PCRE2 (the node) read the same way, with a bounded cost:
// at most MaxCachePathRegexBytes, valid UTF-8 without NUL or control
// characters, Perl syntax without \C, \Q..\E, (?U), \z or named groups, no
// repetition count above 100, and no unbounded repetition (*, +, {n,})
// inside another (catastrophic backtracking under PCRE).
func ValidateCachePathRegex(value string) error {
	if value == "" || len(value) > MaxCachePathRegexBytes || strings.ContainsFunc(value, func(r rune) bool {
		return r < 0x20 || r == 0x7f || r == 0xfffd
	}) || strings.Contains(value, `\C`) || strings.Contains(value, `\Q`) || strings.Contains(value, `(?U`) ||
		strings.Contains(value, `(?P<`) || strings.Contains(value, `(?<`) || strings.Contains(value, `\z`) {
		return ErrInvalidConfig
	}
	parsed, err := syntax.Parse(value, syntax.Perl)
	if err != nil || !boundedCacheRegex(parsed, false) {
		return ErrInvalidConfig
	}
	return nil
}

// boundedCacheRegex: no repeat over 100 and no unbounded repeat inside an
// unbounded repeat.
func boundedCacheRegex(node *syntax.Regexp, insideUnbounded bool) bool {
	unbounded := false
	switch node.Op {
	case syntax.OpStar, syntax.OpPlus:
		unbounded = true
	case syntax.OpRepeat:
		if node.Max > 100 || node.Min > 100 {
			return false
		}
		unbounded = node.Max == -1
	}
	if unbounded && insideUnbounded {
		return false
	}
	for _, sub := range node.Sub {
		if !boundedCacheRegex(sub, insideUnbounded || unbounded) {
			return false
		}
	}
	return true
}

// CompileCachePathRegex is the control plane's matcher of a validated
// path_regex (the dynamic routing node uses PCRE2 on the same text).
func CompileCachePathRegex(value string) (*regexp.Regexp, error) {
	if err := ValidateCachePathRegex(value); err != nil {
		return nil, err
	}
	return regexp.Compile(value)
}

// validateCacheContentTypes: 1..MaxCacheContentTypes sorted unique lower case
// media types, each exact ("text/html") or a prefix ending in "*"
// ("image/*", "text/*", "application/vnd.*").
func validateCacheContentTypes(values []string) error {
	if len(values) == 0 || len(values) > MaxCacheContentTypes {
		return ErrInvalidConfig
	}
	for index, value := range values {
		exact := !strings.HasSuffix(value, "*")
		if !cacheContentTypePattern.MatchString(value) || exact && (!strings.Contains(value, "/") || strings.HasSuffix(value, "/")) ||
			index > 0 && values[index-1] >= value {
			return ErrInvalidConfig
		}
	}
	return nil
}

// NormalizeCacheContentTypes lower-cases, trims, sorts and validates a
// content_types list (control plane input).
func NormalizeCacheContentTypes(values []string) ([]string, error) {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if slices.Contains(result, value) {
			return nil, ErrInvalidConfig
		}
		result = append(result, value)
	}
	slices.Sort(result)
	if err := validateCacheContentTypes(result); err != nil {
		return nil, err
	}
	return result, nil
}

// CacheMediaType is the media type a Content-Type header names: lower case,
// parameters and spaces removed ("" when absent).
func CacheMediaType(header string) string {
	if index := strings.IndexByte(header, ';'); index >= 0 {
		header = header[:index]
	}
	return strings.ToLower(strings.TrimSpace(header))
}

// CacheContentTypeMatches reports whether a response's media type
// (CacheMediaType) satisfies a rule's content_types; an empty list always
// does.
func CacheContentTypeMatches(types []string, mediaType string) bool {
	if len(types) == 0 {
		return true
	}
	for _, value := range types {
		if prefix, ok := strings.CutSuffix(value, "*"); ok {
			if strings.HasPrefix(mediaType, prefix) && mediaType != "" {
				return true
			}
		} else if mediaType == value {
			return true
		}
	}
	return false
}

// CacheRuleConditional reports whether a rule matches on more than its path
// prefix and extensions (path_regex or content_types).
func CacheRuleConditional(rule CacheRuleDocument) bool {
	return rule.PathRegex != "" || len(rule.ContentTypes) != 0
}

func cacheConditionalRules(rules []CacheRuleDocument) int {
	count := 0
	for _, rule := range rules {
		if CacheRuleConditional(rule) {
			count++
		}
	}
	return count
}

// CachePolicyUsesRuleMatch reports whether a policy needs CACHE_RULE_MATCH.
func CachePolicyUsesRuleMatch(policy CachePolicyDocument) bool {
	return cacheConditionalRules(policy.Rules) != 0
}

// OriginFollowRedirectCapability is the site object capability name of
// CAPABILITY_NAME_ORIGIN_FOLLOW_REDIRECT (site origin.follow_redirect, ge36).
const (
	OriginFollowRedirectCapability        = "origin_follow_redirect"
	OriginFollowRedirectAPIVersion uint32 = 1
)

// OriginTLSNoVerifyCapability is the site object capability name of
// CAPABILITY_NAME_ORIGIN_TLS_NO_VERIFY: an HTTPS origin
// with trust anchor "none" (回源 HTTPS 不校验源站证书, native patch 29).
const (
	OriginTLSNoVerifyCapability        = "origin_tls_no_verify"
	OriginTLSNoVerifyAPIVersion uint32 = 1
)

// SiteEdgeOptionsCapability is the site object capability name of
// CAPABILITY_NAME_SITE_EDGE_OPTIONS: the default site,
// search engine origin, ACME pass-through and unbuffered proxying.
const (
	SiteEdgeOptionsCapability        = "site_edge_options"
	SiteEdgeOptionsAPIVersion uint32 = 1
)

// L2RoutingCapability is the site object capability name of
// CAPABILITY_NAME_L2_ROUTING (A19-b): an L2 configuration's cache mode
// (origin.l2.cache_only) and L2 conditions (origin.l2.conditions). v2:
// pass-through L2 (origin.l2.passthrough: the L1 reaches the
// L2 on the visitor's protocol and port), a node that is an endpoint of the
// site's L2 pool goes straight to the origin, and an L2 hop carries
// X-Cdnca-L2-Hop so the L2 never forwards it to another L2.
const (
	L2RoutingCapability        = "l2_routing"
	L2RoutingAPIVersion uint32 = 2
)
