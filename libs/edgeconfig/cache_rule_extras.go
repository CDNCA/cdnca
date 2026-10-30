package edgeconfig

import (
	"regexp"
	"strings"
)

// Per-rule cache settings:
// 单个路径, 忽略 URL 参数, 分片回源, 强制 CDN 缓存, 忽略 Vary and 不缓存条件.
// Site runtime v2 only (the dynamic routing node, cdnca_cache.lua and
// edgecache); a policy that uses any needs CACHE_RULE_MATCH v2.
//
// The rule that decides a request is the first (lowest order) of the rules
// that match it; its settings apply to the whole request. Unset (nil)
// settings inherit the site's policy.

// CacheRuleMatchExtrasAPIVersion is the CACHE_RULE_MATCH version that
// executes CacheRuleExtras.
const CacheRuleMatchExtrasAPIVersion uint32 = 2

// MaxCacheNoCacheConditions bounds a rule's 不缓存条件.
const MaxCacheNoCacheConditions = 8

// No-cache condition sources: what the pattern is matched on.
const (
	CacheConditionURI      = "uri"       // 请求URI: path and query ($request_uri)
	CacheConditionPath     = "path"      // 请求URI(不带参数): normalized path ($uri)
	CacheConditionClientIP = "client_ip" // 客户IP地址
	CacheConditionScheme   = "scheme"    // 请求协议: http | https
	CacheConditionArgs     = "args"      // 请求参数: the raw query
	CacheConditionHost     = "host"      // 域名
	CacheConditionHeader   = "header"    // 自定义: one request header (Name), e.g. cookie
)

// CacheNoCacheCondition: the request is neither read from nor stored in the
// cache when Pattern (ValidateCachePathRegex) matches the source's value.
// An absent header is the empty string.
type CacheNoCacheCondition struct {
	Source  string `json:"source"`
	Name    string `json:"name,omitempty"`
	Pattern string `json:"pattern"`
}

// CacheRuleExtras are a rule's own settings.
//   - PathExact: the request path ($uri) must equal it (单个路径; 首页 is "/");
//     exclusive with PathPrefix.
//   - IgnoreQuery true: the query is not part of the key (the site's
//     query_mode otherwise).
//   - SliceBytes: the slice size of the rule's requests (0 = whole objects;
//     nil = the site's slice_bytes); the same bounds as the site's.
//   - ForceCache true: the rule's TTL wins over the origin's Cache-Control,
//     Expires and X-Accel-Expires (the override variant); false: they are
//     honoured, the rule TTL is the fallback (follow); nil: the site's mode.
//     A response the origin marks private/no-store/no-cache or that sets a
//     cookie is still never stored (another visitor must not get it).
//   - IgnoreVary: the origin's Vary does not split the cached object.
//   - NoCache: 不缓存条件.
type CacheRuleExtras struct {
	PathExact   string                  `json:"path_exact,omitempty"`
	IgnoreQuery bool                    `json:"ignore_query,omitempty"`
	SliceBytes  *int64                  `json:"slice_bytes,omitempty"`
	ForceCache  *bool                   `json:"force_cache,omitempty"`
	IgnoreVary  bool                    `json:"ignore_vary,omitempty"`
	NoCache     []CacheNoCacheCondition `json:"no_cache,omitempty"`
}

// Used reports whether any setting is set.
func (extras CacheRuleExtras) Used() bool {
	return extras.PathExact != "" || extras.IgnoreQuery || extras.SliceBytes != nil || extras.ForceCache != nil ||
		extras.IgnoreVary || len(extras.NoCache) != 0
}

// Clone deep-copies the settings.
func (extras CacheRuleExtras) Clone() CacheRuleExtras {
	result := extras
	if extras.SliceBytes != nil {
		value := *extras.SliceBytes
		result.SliceBytes = &value
	}
	if extras.ForceCache != nil {
		value := *extras.ForceCache
		result.ForceCache = &value
	}
	if extras.NoCache != nil {
		result.NoCache = append([]CacheNoCacheCondition(nil), extras.NoCache...)
	}
	return result
}

var (
	cacheConditionHeaderPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	cacheConditionSources       = map[string]bool{CacheConditionURI: true, CacheConditionPath: true,
		CacheConditionClientIP: true, CacheConditionScheme: true, CacheConditionArgs: true,
		CacheConditionHost: true, CacheConditionHeader: true}
)

// ValidCacheExactPath: an absolute normalized path ("/" or "/a/b.html"),
// printable ASCII without query, fragment, "//", "." or ".." segments.
func ValidCacheExactPath(value string) bool {
	if value == "" || len(value) > 2048 || value[0] != '/' || strings.ContainsAny(value, "?#\\%") ||
		strings.Contains(value, "//") {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] <= 0x20 || value[index] >= 0x7f {
			return false
		}
	}
	for _, segment := range strings.Split(value[1:], "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

// ValidateCacheRuleExtras checks a rule's settings (control plane and node
// alike). pathPrefix is the rule's directory prefix.
func ValidateCacheRuleExtras(extras CacheRuleExtras, pathPrefix string, action CacheRuleAction) error {
	if extras.PathExact != "" && (pathPrefix != "" || !ValidCacheExactPath(extras.PathExact)) ||
		extras.SliceBytes != nil && *extras.SliceBytes != 0 && (*extras.SliceBytes < CacheMinSliceBytes ||
			*extras.SliceBytes > CacheMaxSliceBytes || *extras.SliceBytes%(64<<10) != 0) ||
		*nonNilInt64(extras.SliceBytes) < 0 || len(extras.NoCache) > MaxCacheNoCacheConditions ||
		extras.NoCache != nil && len(extras.NoCache) == 0 {
		return ErrInvalidConfig
	}
	// a no_cache rule stores nothing: only its match conditions mean anything
	if action == CacheRuleActionNoCache && (extras.IgnoreQuery || extras.SliceBytes != nil || extras.ForceCache != nil ||
		extras.IgnoreVary || len(extras.NoCache) != 0) {
		return ErrInvalidConfig
	}
	for _, condition := range extras.NoCache {
		if !cacheConditionSources[condition.Source] || ValidateCachePathRegex(condition.Pattern) != nil ||
			(condition.Source == CacheConditionHeader) != (condition.Name != "") ||
			condition.Name != "" && !cacheConditionHeaderPattern.MatchString(condition.Name) {
			return ErrInvalidConfig
		}
	}
	return nil
}

func nonNilInt64(value *int64) *int64 {
	if value == nil {
		var zero int64
		return &zero
	}
	return value
}

// CachePolicyUsesRuleExtras reports whether a policy needs
// CACHE_RULE_MATCH v2.
func CachePolicyUsesRuleExtras(policy CachePolicyDocument) bool {
	for _, rule := range policy.Rules {
		if rule.CacheRuleExtras.Used() {
			return true
		}
	}
	return false
}
