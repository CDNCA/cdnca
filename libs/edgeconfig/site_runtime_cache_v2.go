package edgeconfig

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Site runtime v2 cache rendering (ge-cache). v1 signed releases keep
// renderCacheRuntime and its nginx contract; a site runtime v2 release is
// compiled on the node and renders the cache with these directives instead:
//
//   - the zone is the site's stable namespace and the key names its cache
//     generation (CacheGeneration), so a publication that changes nothing about
//     caching keeps every object (A);
//   - keys_zone grows with the quota (B);
//   - a request Cookie bypasses only requests no cache rule names (C);
//   - a Range request reads the cached full object (D);
//   - inactive covers the longest rule TTL and the stale window (G);
//   - X-CDN-Cache names STALE/UPDATING/REVALIDATED and X-CDN-Cache-Reason
//     says why a request bypassed (H);
//   - stale-if-error, background update, cache lock, revalidation, object
//     size bounds and slices.

const (
	// cacheAverageObjectBytes sizes keys_zone: nginx keeps about 8000 keys
	// per MiB, so one MiB per 8000 objects of this average size.
	cacheAverageObjectBytes int64 = 32 << 10
	cacheKeysPerZoneMiB     int64 = 8000
	// cacheMinInactive: an object nobody reads for this long is removed
	// even when its TTL is longer than nothing at all.
	cacheMinInactive = time.Hour
	// cacheStaleInactive: with stale-if-error an expired object stays on
	// disk at least this long after its last read, to be served while the
	// origin fails.
	cacheStaleInactive = 24 * time.Hour
	// cacheLockTimeout / cacheLockAge: concurrent misses of one key wait
	// for the first fill (no thundering herd on the origin), at most this
	// long, then go to the origin themselves without storing.
	cacheLockTimeout = 5 * time.Second
	cacheLockAge     = 5 * time.Second
)

// CacheZoneBytesForQuota is the keys_zone a site's disk quota needs: one
// key per cacheAverageObjectBytes of quota, rounded up to whole MiB, within
// 1 MiB and maxCacheZoneSize.
func CacheZoneBytesForQuota(quota int64) int64 {
	if quota <= 0 {
		return minCacheZoneSize
	}
	objects := (quota + cacheAverageObjectBytes - 1) / cacheAverageObjectBytes
	mib := (objects + cacheKeysPerZoneMiB - 1) / cacheKeysPerZoneMiB
	return min(max(mib*cacheSizeUnit, minCacheZoneSize), int64(maxCacheZoneSize))
}

// cacheInactiveV2 is how long an unread object stays on disk: the longest
// TTL the policy can give (default, status and rule TTLs), at least an hour,
// and with stale-if-error at least cacheStaleInactive.
func cacheInactiveV2(policy CachePolicy) time.Duration {
	maximum := maximumCacheTTL(policy)
	for _, rule := range policy.Rules {
		maximum = max(maximum, rule.TTL)
	}
	maximum = max(maximum, cacheMinInactive)
	if policy.StaleIfError {
		maximum = max(maximum, cacheStaleInactive)
	}
	return maximum
}

// CacheNodeBudget is the node-wide cache capacity the platform's system
// configuration sets (proxy_cache_max_size, proxy_cache_zone_bytes,
// proxy_cache_min_free): when the sites of a node together ask for more disk
// or key zone than the budget, every site's share is scaled down in
// proportion, so the budget is never exceeded. Zero values set no limit.
type CacheNodeBudget struct {
	MaxBytes     int64
	ZoneBytes    int64
	MinFreeBytes int64
}

// CacheNodeBudgetFromSystem is the budget of a site runtime system block
// (nil: no limits).
func CacheNodeBudgetFromSystem(system *SiteRuntimeSystem) CacheNodeBudget {
	if system == nil {
		return CacheNodeBudget{}
	}
	return CacheNodeBudget{
		MaxBytes: system.Nginx.ProxyCacheMaxBytes, ZoneBytes: system.Nginx.ProxyCacheZoneBytes,
		MinFreeBytes: system.Nginx.ProxyCacheMinFreeBytes,
	}
}

// ApplyCacheNodeBudget scales the renderers' disk and key zone sizes so their
// sums fit the budget, and sets min_free on each. Each renderer keeps at
// least 1 MiB of zone and of disk.
func ApplyCacheNodeBudget(renderers []*SiteCacheRenderer, budget CacheNodeBudget) {
	var disk, zones int64
	for _, renderer := range renderers {
		if renderer.Enabled() {
			disk += renderer.maxSize
			zones += renderer.zoneSize
		}
	}
	for _, renderer := range renderers {
		if !renderer.Enabled() {
			continue
		}
		if budget.MaxBytes > 0 && disk > budget.MaxBytes {
			renderer.maxSize = scaleCacheSize(renderer.maxSize, budget.MaxBytes, disk)
		}
		if budget.ZoneBytes > 0 && zones > budget.ZoneBytes {
			renderer.zoneSize = scaleCacheSize(renderer.zoneSize, budget.ZoneBytes, zones)
		}
		renderer.minFree = budget.MinFreeBytes
	}
}

// scaleCacheSize is value*limit/total rounded down to whole MiB, at least 1 MiB.
func scaleCacheSize(value, limit, total int64) int64 {
	scaled := int64(float64(value) * float64(limit) / float64(total))
	return max(scaled/cacheSizeUnit*cacheSizeUnit, cacheSizeUnit)
}

// SiteRuntimeCacheV2HTTPMaps are the http{} level maps of the v2 cache: the
// per-request bypass inputs, the bypass reason and the X-CDN-Cache value.
// A rule route sets $cdnca_cache_rule_matched 1 (its request names a cache
// rule): such requests ignore the request Cookie (C). The Range request
// header no longer bypasses (D).
func SiteRuntimeCacheV2HTTPMaps() string {
	var output strings.Builder
	output.WriteString("  map $request_method $cdnca_cache_method_bypass { default 1; GET 0; HEAD 0; }\n")
	output.WriteString("  map $http_authorization $cdnca_cache_authorization_bypass { default 1; '' 0; }\n")
	output.WriteString("  map \"$cdnca_cache_rule_matched:$http_cookie\" $cdnca_cache_cookie_bypass { volatile; default 1; ~^1: 0; \"0:\" 0; }\n")
	output.WriteString("  map $http_upgrade $cdnca_cache_upgrade_bypass { default 1; '' 0; }\n")
	output.WriteString("  map $upstream_http_set_cookie $cdnca_cache_response_cookie_bypass { default 1; '' 0; }\n")
	output.WriteString("  map $upstream_http_cache_control $cdnca_cache_response_control_bypass { default 0; ~*(^|[,[:space:]])(private|no-store|no-cache)([=,[:space:]]|$) 1; }\n")
	output.WriteString("  map \"$cdnca_cache_method_bypass:$cdnca_cache_authorization_bypass:$cdnca_cache_cookie_bypass:$cdnca_cache_upgrade_bypass\" $cdnca_cache_request_bypass { volatile; default 1; \"0:0:0:0\" 0; }\n")
	// Why a request was not served from (or stored in) the cache, first
	// cause first; empty when it was not bypassed.
	output.WriteString("  map \"$cdnca_cache_method_bypass$cdnca_cache_authorization_bypass$cdnca_cache_cookie_bypass$cdnca_cache_upgrade_bypass$cdnca_cache_policy_bypass$cdnca_cache_response_cookie_bypass$cdnca_cache_response_control_bypass$cdnca_cache_size_bypass\" $cdnca_cache_bypass_reason {\n")
	output.WriteString("    volatile;\n    default \"\";\n")
	for index, reason := range []string{"method", "authorization", "cookie", "upgrade", "no_cache_rule", "set_cookie", "origin_no_store", "object_size"} {
		fmt.Fprintf(&output, "    ~^%s1 %s;\n", strings.Repeat(".", index), reason)
	}
	output.WriteString("  }\n")
	output.WriteString("  map \"$cdnca_cache_bypass_reason:$upstream_cache_status\" $cdnca_cache_header {\n")
	output.WriteString("    volatile;\n    default BYPASS;\n")
	for _, status := range []string{"HIT", "STALE", "UPDATING", "REVALIDATED", "MISS", "EXPIRED"} {
		fmt.Fprintf(&output, "    \":%s\" %s;\n", status, status)
	}
	output.WriteString("  }\n")
	output.WriteString("  map $cdnca_cache_header $cdnca_cache_reason_header { volatile; default \"\"; BYPASS $cdnca_cache_bypass_reason; }\n")
	output.WriteString("  map $cdnca_cache_request_bypass $cdnca_cache_origin_range { volatile; default \"\"; 1 $http_range; }\n")
	output.WriteString("  map $cdnca_cache_request_bypass $cdnca_cache_origin_if_range { volatile; default \"\"; 1 $http_if_range; }\n")
	return output.String()
}

// v2Directives renders the cache directives of a proxying location (public,
// rule route or prewarm). route is nil for a simple policy; the bypass route
// renders nothing (the request is not cached).
func (renderer *SiteCacheRenderer) v2Directives(output *strings.Builder, port uint16, route *cachePolicyRoute, prewarm, headerFilter bool) {
	policy := renderer.policy
	if policy.Mode == CacheDisabled {
		return
	}
	fmt.Fprintf(output, "      proxy_cache %s;\n", renderer.zoneName())
	key := "$cdnca_cache_policy_key"
	if route == nil {
		key = renderer.simpleKey(port) + "$uri$is_args$args"
	}
	if policy.SliceBytes > 0 {
		// One object per slice: the slice's range is part of its key.
		key += "|slice=$slice_range"
	}
	fmt.Fprintf(output, "      proxy_cache_key %s;\n", strconv.Quote(key))
	output.WriteString("      proxy_cache_methods GET HEAD;\n      proxy_cache_convert_head on;\n")
	if route != nil && route.V2 && route.NoCacheDefault && len(route.NoCacheStatuses) == 0 {
		// A no-cache rule for every status: the request neither reads nor
		// stores, and its bypass reason is the rule.
		output.WriteString("      set $cdnca_cache_policy_bypass 1;\n")
	}
	output.WriteString("      proxy_cache_bypass $cdnca_cache_request_bypass $cdnca_cache_policy_bypass;\n")
	output.WriteString("      proxy_no_cache $cdnca_cache_request_bypass $cdnca_cache_policy_bypass $cdnca_cache_response_cookie_bypass $cdnca_cache_response_control_bypass $cdnca_cache_size_bypass")
	if route != nil && route.V2 {
		fmt.Fprintf(output, " %s", route.noCacheVariable)
	}
	output.WriteString(";\n")
	if route != nil && route.V2 {
		fmt.Fprintf(output, "      expires %s;\n", route.browserVariable)
	}
	if policy.Mode == CacheOverride {
		output.WriteString("      proxy_ignore_headers X-Accel-Expires Expires Cache-Control;\n")
	}
	fmt.Fprintf(output, "      proxy_cache_lock on;\n      proxy_cache_lock_timeout %s;\n      proxy_cache_lock_age %s;\n",
		nginxCacheDuration(cacheLockTimeout), nginxCacheDuration(cacheLockAge))
	output.WriteString("      proxy_cache_revalidate on;\n")
	if policy.StaleIfError {
		output.WriteString("      proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;\n")
		fmt.Fprintf(output, "      proxy_cache_background_update %s;\n", nginxBoolean(policy.BackgroundUpdate))
	}
	if headerFilter && (policy.MinObjectBytes > 0 || policy.MaxObjectBytes > 0) {
		fmt.Fprintf(output, "      header_filter_by_lua_block { %s }\n", cacheSizeFilterLua(policy))
	}
	renderer.v2Validity(output, route)
	renderer.v2Range(output, prewarm)
}

// cacheSizeFilterLua sets $cdnca_cache_size_bypass from the object's size
// on a fill (MISS/EXPIRED): the origin's Content-Length, or for a slice (206)
// the total length of its Content-Range. A response of unknown size is not
// stored when a maximum is set. Slice subrequests share the request's
// variables, so one oversized slice stops the whole object.
func cacheSizeFilterLua(policy CachePolicy) string {
	return fmt.Sprintf("do local status = ngx.var.upstream_cache_status; "+
		"if status == \"MISS\" or status == \"EXPIRED\" then "+
		"local length = tonumber(string.match(ngx.var.upstream_http_content_range or \"\", \"/(%%d+)$\") or ngx.var.upstream_http_content_length or \"\"); "+
		"if (length == nil and %d > 0) or (length ~= nil and (length < %d or (%d > 0 and length > %d))) then ngx.var.cdnca_cache_size_bypass = \"1\" end end end ",
		policy.MaxObjectBytes, policy.MinObjectBytes, policy.MaxObjectBytes, policy.MaxObjectBytes)
}

// v2Validity is the TTL per status: a rule route's groups, else the
// default/status TTLs (v1 semantics); with slices 206 is cached like 200.
func (renderer *SiteCacheRenderer) v2Validity(output *strings.Builder, route *cachePolicyRoute) {
	policy := renderer.policy
	slice := policy.SliceBytes > 0
	if route != nil && len(policy.Rules) != 0 {
		for _, group := range route.TTLGroups {
			statuses := make([]string, 0, len(group.Statuses)+1)
			for _, status := range group.Statuses {
				statuses = append(statuses, strconv.Itoa(status))
				if slice && status == 200 {
					statuses = append(statuses, "206")
				}
			}
			fmt.Fprintf(output, "      proxy_cache_valid %s %s;\n", strings.Join(statuses, " "), nginxCacheDuration(group.TTL))
		}
		if route.WildcardTTL != 0 {
			fmt.Fprintf(output, "      proxy_cache_valid any %s;\n", nginxCacheDuration(route.WildcardTTL))
		} else {
			output.WriteString("      proxy_cache_valid any 0s;\n")
		}
		return
	}
	custom := make(map[int]struct{}, len(policy.StatusTTLs))
	for _, status := range policy.StatusTTLs {
		custom[status.Status] = struct{}{}
	}
	remaining := make([]string, 0, 4)
	for _, status := range []int{200, 301, 302} {
		if _, exists := custom[status]; !exists {
			remaining = append(remaining, strconv.Itoa(status))
			if slice && status == 200 {
				remaining = append(remaining, "206")
			}
		}
	}
	if len(remaining) > 0 {
		fmt.Fprintf(output, "      proxy_cache_valid %s %s;\n", strings.Join(remaining, " "), nginxCacheDuration(policy.DefaultTTL))
	}
	for _, status := range policy.StatusTTLs {
		statuses := strconv.Itoa(status.Status)
		if slice && status.Status == 200 {
			statuses += " 206"
		}
		fmt.Fprintf(output, "      proxy_cache_valid %s %s;\n", statuses, nginxCacheDuration(status.TTL))
	}
}

// v2Range decides what the origin sees of a client Range (D). With slices,
// every origin request asks for one aligned slice and the client's range is
// cut from the slices (a prewarm fills every slice of the object). Without slices the origin is asked for the full
// object (no Range forwarded), which is cached and the client's range cut
// from it, for a cached site regardless of the site's Range setting: the
// Range setting only decides whether a non-cacheable request forwards Range,
// which the bypass route (writeRange) keeps. A prewarm fills full objects.
func (renderer *SiteCacheRenderer) v2Range(output *strings.Builder, prewarm bool) {
	if renderer.policy.SliceBytes > 0 {
		fmt.Fprintf(output, "      slice %d;\n", renderer.policy.SliceBytes)
		output.WriteString("      proxy_set_header Range $slice_range;\n")
		output.WriteString("      proxy_set_header If-Range \"\";\n")
		output.WriteString("      proxy_force_ranges on;\n")
		return
	}
	if renderer.rangeEnabled && !prewarm {
		// A bypassed request (not read from or stored in the cache)
		// forwards the client's Range as the site asks.
		output.WriteString("      proxy_set_header Range $cdnca_cache_origin_range;\n")
		output.WriteString("      proxy_set_header If-Range $cdnca_cache_origin_if_range;\n")
	} else {
		output.WriteString("      proxy_set_header Range \"\";\n")
		output.WriteString("      proxy_set_header If-Range \"\";\n")
	}
	output.WriteString("      proxy_force_ranges on;\n")
}

// simpleKey is the key prefix of a simple (non-advanced) policy's key.
func (renderer *SiteCacheRenderer) simpleKey(port uint16) string {
	domain := renderer.domain
	if renderer.keyByHost {
		domain = "$" + CacheKeyHostVariable
	}
	return CacheKeyPrefix(renderer.tenantID, renderer.siteID, renderer.generation, domain, port)
}

// zoneName names the site's keys_zone after its stable namespace.
func (renderer *SiteCacheRenderer) zoneName() string {
	return "cdnca_cache_" + renderer.NamespaceID()[:32]
}

// cacheHTTPFileDirectives are the http{} level file serving directives of a
// node that caches: cache hits are sent with sendfile from the page cache and
// read with thread-pool aio so a slow disk does not block the worker.
// open_file_cache is deliberately absent: proxy_cache opens cache files
// through it, so a purged (unlinked) object would keep being served from the
// cached descriptor until open_file_cache_valid expires.
func cacheHTTPFileDirectives() string {
	return "  sendfile on;\n  tcp_nopush on;\n  aio threads;\n  aio_write on;\n"
}
