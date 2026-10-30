package siteconf

import (
	"bytes"
	"encoding/json"
	"slices"
)

// Cache is the controller-neutral cache policy of a site (Config.Cache).
// Absent means the subscriber does not manage caching: the leaf leaves its
// own policy for the site as it is. To return to defaults, send
// {"mode":"follow_origin"}.
type Cache struct {
	Mode        string      `json:"mode"` // disabled, follow_origin, override
	Rules       []CacheRule `json:"rules,omitempty"`
	QueryMode   string      `json:"query_mode,omitempty"` // preserve (default), ignore, include, exclude
	QueryNames  []string    `json:"query_names,omitempty"`
	VaryHeaders []string    `json:"vary_headers,omitempty"`
	// Policy extensions (stale-if-error, background update, stored object
	// size bounds, slice size; the leaf's cache policy extensions).
	StaleIfError     bool  `json:"stale_if_error,omitempty"`
	BackgroundUpdate bool  `json:"background_update,omitempty"`
	MinObjectBytes   int64 `json:"min_object_bytes,omitempty"`
	MaxObjectBytes   int64 `json:"max_object_bytes,omitempty"`
	SliceBytes       int64 `json:"slice_bytes,omitempty"`
}

// CacheRule matches by extension, path prefix and status; rules apply in order.
type CacheRule struct {
	Extensions        []string `json:"extensions,omitempty"`
	PathPrefix        string   `json:"path_prefix,omitempty"`
	StatusCodes       []int    `json:"status_codes,omitempty"`
	Action            string   `json:"action"` // cache, no_cache
	TTLSeconds        int64    `json:"ttl_seconds,omitempty"`
	BrowserTTLSeconds int64    `json:"browser_ttl_seconds,omitempty"`
	// Matches and per-rule settings beyond extension/prefix/status (the
	// leaf needs its nodes to support cache rule matching for these).
	PathRegex    string             `json:"path_regex,omitempty"`
	ContentTypes []string           `json:"content_types,omitempty"`
	PathExact    string             `json:"path_exact,omitempty"`
	IgnoreQuery  bool               `json:"ignore_query,omitempty"`
	SliceBytes   *int64             `json:"slice_bytes,omitempty"`
	ForceCache   *bool              `json:"force_cache,omitempty"`
	IgnoreVary   bool               `json:"ignore_vary,omitempty"`
	NoCache      []CacheNoCacheRule `json:"no_cache,omitempty"`
}

// CacheNoCacheRule: the response is not cached when the request's Source
// (cookie, header, arg) Name matches Pattern.
type CacheNoCacheRule struct {
	Source  string `json:"source"`
	Name    string `json:"name,omitempty"`
	Pattern string `json:"pattern"`
}

// UsesMatch reports whether the rule uses a match or setting beyond
// extensions, path prefix and status codes.
func (r CacheRule) UsesMatch() bool {
	return r.PathRegex != "" || len(r.ContentTypes) > 0 || r.PathExact != "" || r.IgnoreQuery || r.SliceBytes != nil ||
		r.ForceCache != nil || r.IgnoreVary || len(r.NoCache) > 0
}

const (
	maxCacheRules = 64
	maxCacheNames = 32
	maxCacheTTL   = 10 * 365 * 24 * 3600
)

// DecodeCache returns the cache block, or nil when the config carries none.
// It checks the shape only; each leaf validates what it can honour.
func (c Config) DecodeCache() (*Cache, error) {
	if len(c.Cache) == 0 || bytes.Equal(bytes.TrimSpace(c.Cache), []byte("null")) {
		return nil, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(c.Cache))
	decoder.DisallowUnknownFields()
	var cache Cache
	if err := decoder.Decode(&cache); err != nil || decoder.More() {
		return nil, ErrInvalid
	}
	if !slices.Contains([]string{"disabled", "follow_origin", "override"}, cache.Mode) ||
		!slices.Contains([]string{"", "preserve", "ignore", "include", "exclude"}, cache.QueryMode) ||
		len(cache.Rules) > maxCacheRules || len(cache.QueryNames) > maxCacheNames || len(cache.VaryHeaders) > maxCacheNames ||
		cache.MinObjectBytes < 0 || cache.MaxObjectBytes < 0 || cache.SliceBytes < 0 {
		return nil, ErrInvalid
	}
	for _, rule := range cache.Rules {
		if (rule.Action != "cache" && rule.Action != "no_cache") || rule.TTLSeconds < 0 || rule.TTLSeconds > maxCacheTTL ||
			rule.BrowserTTLSeconds < 0 || rule.BrowserTTLSeconds > maxCacheTTL ||
			len(rule.Extensions) > maxCacheNames || len(rule.StatusCodes) > maxCacheNames || len(rule.PathPrefix) > 512 ||
			len(rule.PathRegex) > 512 || len(rule.PathExact) > 512 || len(rule.ContentTypes) > maxCacheNames ||
			len(rule.NoCache) > maxCacheNames || rule.SliceBytes != nil && *rule.SliceBytes < 0 {
			return nil, ErrInvalid
		}
	}
	if cache.QueryMode == "" {
		cache.QueryMode = "preserve"
	}
	return &cache, nil
}

// normalizeCache rewrites the cache block canonically so that equal intent
// gives an equal digest.
func (c *Config) normalizeCache() error {
	cache, err := c.DecodeCache()
	if err != nil {
		return err
	}
	if cache == nil {
		c.Cache = nil
		return nil
	}
	raw, err := json.Marshal(cache)
	if err != nil {
		return ErrInvalid
	}
	c.Cache = raw
	return nil
}
