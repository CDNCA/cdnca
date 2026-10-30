package edgecache

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Variables the cache module writes (declared by the skeleton in its
// never-executed variables location, dynroute contract section 1.4).
var Variables = []string{
	"cdnca_cache_zone",        // pool zone or "" (not cached)
	"cdnca_cache_key",         // proxy_cache_key
	"cdnca_cache_ttls",        // per-status TTL table (patch 24 via map)
	"cdnca_cache_browsers",    // per-status browser expiry table
	"cdnca_cache_reason",      // bypass reason ("" when cached)
	"cdnca_cache_enabled",     // "1" when the site has a cache plan
	"cdnca_cache_range",       // Range sent to the origin on a bypassed request
	"cdnca_cache_if_range",    // If-Range sent with it
	"cdnca_cache_prewarm",     // "1" for an authenticated agent prewarm
	"cdnca_cache_show",        // "1": answer X-CDN-Cache/-Reason (site cache_status_header or a prewarm)
	"cdnca_cache_dispatched",  // access ran (a named variant re-enters it)
	"cdnca_cache_size_bypass", // "1": outside the object size bounds, "2": no content_types rule caches it (header filter)
	"cdnca_cache_rule_bypass", // "1": a site response rule replaced the response (cdnca_filters; "" = 0)
	"cdnca_cache_signature",   // the request's rule candidate set when a content_types rule is in it
	"cdnca_cache_follow",      // "1": a redirect is being followed, the cache is not read (ge36)
	"cdnca_follow_hops",       // origin redirects followed so far ("" = not entered, ge36)
}

// FollowLocation is the named location of a request whose site follows
// origin redirects and that the cache does not serve (ge36): the origin's
// 301/302/303/307/308 comes back here (error_page), cdnca_origin.follow
// rewrites the request to the Location or returns the redirect.
const FollowLocation = "@cdnca_origin_follow"

// followDirectives intercept the origin's redirects of a follow location or
// cache variant (only there: location /, the tier locations, the bypass and
// the plain variants keep the origin's redirect; the site's error pages are
// the header filter's and the conditional origin fallback is the
// balancer's). name is the location itself: a redirect re-enters it.
func followDirectives(output *strings.Builder, indent, name string) {
	fmt.Fprintf(output, "%sproxy_intercept_errors on;\n%srecursive_error_pages on;\n", indent, indent)
	fmt.Fprintf(output, "%serror_page 301 302 303 307 308 = %s;\n", indent, name)
}

// FollowLocationBlock renders FollowLocation (every shared server): a
// request of a following site the cache does not serve. cache: the node has
// cache zones (the cache status headers and the Range the module allows,
// as location / with PublicLocation).
func FollowLocationBlock(indent, proxy string, cache bool) string {
	var output strings.Builder
	inner := indent + "  "
	fmt.Fprintf(&output, "%slocation %s {\n", indent, FollowLocation)
	output.WriteString(proxy)
	if cache {
		output.WriteString(PublicLocation(inner))
	}
	followDirectives(&output, inner, FollowLocation)
	fmt.Fprintf(&output, "%s}\n", indent)
	return output.String()
}

// Module is the Lua module (edge/openresty/dynroute/cdnca_cache.lua).
const Module = "cdnca_cache"

// PurgeDictionary holds every caching site's purge generation (one key per
// site) and the agent's prewarm token.
const PurgeDictionary = "cdnca_cache_purge"

// PurgeDictionaryBytes sizes the generation dictionary: one 128-byte slab
// slot per site with 25% headroom, at least 1 MiB.
func PurgeDictionaryBytes(sites int) int64 {
	value := int64(sites) * 128 * 5 / 4
	return max(1<<20, (value+1<<20-1)>>20<<20)
}

// BypassVariant is the named location of a request with no cache rule on a
// range site (v7's bypass route: not cached, the client's Range forwarded,
// proxy_force_ranges).
const BypassVariant = "@cdnca_cache_bypass"

// Stale modes of a variant: none, stale-if-error, stale-if-error with
// background update (background update needs stale-if-error).
const (
	staleNone       = ""
	staleOnError    = "_stale"
	staleBackground = "_stalebg"
)

func staleOf(staleIfError, backgroundUpdate bool) string {
	switch {
	case staleIfError && backgroundUpdate:
		return staleBackground
	case staleIfError:
		return staleOnError
	}
	return staleNone
}

// IgnoreVarySuffix names a variant that does not split objects by the
// origin's Vary (a cache rule's ignore_vary).
const IgnoreVarySuffix = "_nv"

// variantName: @cdnca_cache_<override|follow>[_stale|_stalebg][_nv][_s<KiB>].
func variantName(override bool, stale string, ignoreVary bool, sliceBytes int64) string {
	name := "@cdnca_cache_follow"
	if override {
		name = "@cdnca_cache_override"
	}
	name += stale
	if ignoreVary {
		name += IgnoreVarySuffix
	}
	if sliceBytes > 0 {
		name += "_s" + strconv.FormatInt(sliceBytes>>10, 10)
	}
	return name
}

type variant struct {
	name       string
	override   bool
	stale      string
	sliceBytes int64
	follow     bool
	ignoreVary bool
}

// FollowSuffix names the variant of a site that follows origin redirects
// (ge36): <variant>_f, without slices (a slice subrequest cannot be
// redirected; a sliced site's cached requests do not follow).
const FollowSuffix = "_f"

// variants is every cacheable request variant: mode x stale mode x Vary
// handling x slice size (0 and SliceVariantSizes), and mode x stale mode x
// Vary handling following redirects.
func variants() []variant {
	var result []variant
	for _, override := range []bool{true, false} {
		for _, stale := range []string{staleNone, staleOnError, staleBackground} {
			for _, ignoreVary := range []bool{false, true} {
				for _, size := range append([]int64{0}, sliceVariantSizes...) {
					result = append(result, variant{variantName(override, stale, ignoreVary, size), override, stale, size, false, ignoreVary})
				}
				result = append(result, variant{variantName(override, stale, ignoreVary, 0) + FollowSuffix, override, stale, 0, true, ignoreVary})
			}
		}
	}
	return result
}

// VariantNames are the named locations the cache module dispatches to.
func VariantNames() []string {
	names := []string{BypassVariant}
	for _, variant := range variants() {
		names = append(names, variant.name)
	}
	return names
}

// HTTP renders the http{} level cache: the zone pool, the generation
// dictionary and the maps that turn the per-request tables into the values
// nginx reads after the response header (patch 24 proxy_cache_valid,
// expires) and the cache status headers. cacheRoot holds the zone
// directories cdnca-<index> (the node's cache directory, NODE_STORAGE);
// zoneSuffix is ZoneSuffix of cacheRoot (the cache module's zone_suffix).
func HTTP(pool Pool, cacheRoot, zoneSuffix string, sites int) string {
	var output strings.Builder
	fmt.Fprintf(&output, "  lua_shared_dict %s %dm;\n", PurgeDictionary, PurgeDictionaryBytes(sites)>>20)
	for index := range pool.Zones {
		fmt.Fprintf(&output, "  proxy_cache_path %q levels=1:2 keys_zone=%s:%dm max_size=%dm",
			filepath.Join(cacheRoot, "cdnca-"+strconv.Itoa(index)), ZoneName(index, zoneSuffix), pool.KeysZoneBytes>>20, pool.MaxBytes>>20)
		if pool.MinFreeBytes > 0 {
			fmt.Fprintf(&output, " min_free=%dm", pool.MinFreeBytes>>20)
		}
		fmt.Fprintf(&output, " inactive=%ds use_temp_path=off;\n", int64(pool.Inactive/time.Second))
	}
	// The last upstream status (retries: "502, 200") picks its entry of
	// " 200=60 404=0 any=60 ", else "any", else "" (patch 24: not cached).
	output.WriteString("  map \"$upstream_status|$cdnca_cache_ttls\" $cdnca_cache_valid {\n    volatile;\n" +
		"    \"~^(?:[^|]*, )?(?<cdnca_cache_s>[0-9]{3})\\|.* \\k<cdnca_cache_s>=(?<cdnca_cache_t>[0-9]+) \" $cdnca_cache_t;\n" +
		"    \"~^[^|]*\\|.* any=(?<cdnca_cache_t>[0-9]+) \" $cdnca_cache_t;\n    default \"\";\n  }\n")
	output.WriteString("  map \"$status|$cdnca_cache_browsers\" $cdnca_cache_expires {\n    volatile;\n" +
		"    \"~^(?<cdnca_cache_s>[0-9]{3})\\|.* \\k<cdnca_cache_s>=(?<cdnca_cache_b>[a-z0-9]+) \" $cdnca_cache_b;\n" +
		"    \"~^[0-9]{3}\\|.* any=(?<cdnca_cache_b>[a-z0-9]+) \" $cdnca_cache_b;\n    default \"\";\n  }\n")
	// v7: a response with Set-Cookie or private/no-store/no-cache, or outside
	// the policy's object size bounds ($cdnca_cache_size_bypass 1), or one a
	// site response rule replaced ($cdnca_cache_rule_bypass), is not stored;
	// nor one no content_types rule caches ($cdnca_cache_size_bypass 2, ge36).
	output.WriteString("  map $upstream_http_set_cookie $cdnca_cache_response_cookie { default 1; '' 0; }\n")
	output.WriteString("  map $upstream_http_cache_control $cdnca_cache_response_control { default 0; ~*(^|[,[:space:]])(private|no-store|no-cache)([=,[:space:]]|$) 1; }\n")
	// X-CDN-Cache (ge-cache H, v7 SiteRuntimeCacheV2HTTPMaps): only for a
	// caching site; HIT, STALE, UPDATING, REVALIDATED, MISS and EXPIRED are
	// nginx's own; anything not cached is BYPASS with X-CDN-Cache-Reason:
	// the request's (cache module, v7 names and order) or the response's
	// (set_cookie, origin_no_store, object_size, response_rule).
	// the pool's zone names (ZoneName; the suffix is hex, no regex escape)
	zone := "cdnca_cache_[0-9]+" + zoneSuffix
	output.WriteString("  map \"$cdnca_cache_enabled|$cdnca_cache_zone|$cdnca_cache_response_cookie$cdnca_cache_response_control$cdnca_cache_size_bypass$cdnca_cache_rule_bypass|$upstream_cache_status\" $cdnca_cache_status {\n" +
		"    volatile;\n    \"~^\\|\" \"\";\n")
	for _, status := range []string{"HIT", "STALE", "UPDATING", "REVALIDATED", "MISS", "EXPIRED"} {
		fmt.Fprintf(&output, "    \"~^1\\|%s\\|0000\\|%s$\" %s;\n", zone, status, status)
	}
	// a followed redirect's final response (ge36): fetched with the lookup
	// skipped (proxy_cache_bypass, only in the follow variants) and stored
	output.WriteString("    \"~^1\\|" + zone + "\\|0000\\|BYPASS$\" MISS;\n")
	output.WriteString("    default BYPASS;\n  }\n")
	output.WriteString("  map \"$cdnca_cache_zone|$cdnca_cache_reason|$cdnca_cache_response_cookie$cdnca_cache_response_control$cdnca_cache_size_bypass$cdnca_cache_rule_bypass|$upstream_cache_status\" $cdnca_cache_reason_header {\n" +
		"    volatile;\n    \"~^\\|(?<cdnca_cache_r>[a-z_]+)\\|\" $cdnca_cache_r;\n" +
		"    \"~^" + zone + "\\|\\|1\" " + ReasonSetCookie + ";\n" +
		"    \"~^" + zone + "\\|\\|01\" " + ReasonOriginNoStore + ";\n" +
		"    \"~^" + zone + "\\|\\|001\" " + ReasonObjectSize + ";\n" +
		"    \"~^" + zone + "\\|\\|002\" " + ReasonContentType + ";\n" +
		"    \"~^" + zone + "\\|\\|0001\" " + ReasonResponseRule + ";\n    default \"\";\n  }\n")
	// 响应头显示缓存状态: both headers only when
	// the cache module set $cdnca_cache_show (the site object's
	// cache_status_header, published off at attack escalation B and above,
	// or the agent's prewarm, which reads them); empty: nginx adds neither.
	output.WriteString("  map $cdnca_cache_show $cdnca_cache_status_header { volatile; 1 $cdnca_cache_status; default \"\"; }\n")
	output.WriteString("  map $cdnca_cache_show $cdnca_cache_reason_shown { volatile; 1 $cdnca_cache_reason_header; default \"\"; }\n")
	return output.String()
}

// InitLua is the cache module's configuration call (init_by_lua).
func InitLua(pool Pool, siteLRU int) string {
	return fmt.Sprintf("require(%q).configure({ zones = %d, lru_items = %d })", Module, pool.Zones, max(siteLRU, 1))
}

// responseHeaders strips internal and cache headers from the origin and
// adds the cache status (every location that proxies a site request; empty
// unless $cdnca_cache_show, see HTTP).
func responseHeaders(output *strings.Builder, indent string) {
	for _, header := range []string{"X-CDN-Cache", "X-CDN-Cache-Reason", "X-Cdnca-Cache-Key", "X-Cdnca-Site"} {
		fmt.Fprintf(output, "%sproxy_hide_header %s;\n", indent, header)
	}
	fmt.Fprintf(output, "%sproxy_set_header X-Cdnca-Cache-Task \"\";\n", indent)
	fmt.Fprintf(output, "%sadd_header X-CDN-Cache $cdnca_cache_status_header always;\n", indent)
	fmt.Fprintf(output, "%sadd_header X-CDN-Cache-Reason $cdnca_cache_reason_shown always;\n", indent)
}

// PublicLocation are the cache directives of the skeleton's location /: a
// request the cache module bypassed (or a site without cache) is proxied
// with the Range the module allows (v7: a caching site forwards Range only
// when range is on).
func PublicLocation(indent string) string {
	var output strings.Builder
	fmt.Fprintf(&output, "%sproxy_set_header Range $cdnca_cache_range;\n", indent)
	fmt.Fprintf(&output, "%sproxy_set_header If-Range $cdnca_cache_if_range;\n", indent)
	responseHeaders(&output, indent)
	return output.String()
}

// Variants are the named locations the cache module dispatches to. proxy is
// the skeleton's proxy body (origin Host, TLS, proxy_pass), written into
// each. Configuration-time differences only (v7 v2Directives): override
// ignores origin expiry headers, stale-if-error serves the stale object on
// origin errors (optionally refreshing it in the background), a slice size
// caches one object per slice; every variant locks concurrent fills,
// revalidates, and answers Range from the cached object (proxy_force_ranges,
// v7 every cached location). A request the module bypasses for a request
// reason or a no-cache rule runs in its rule's variant with an empty zone
// (not read, not stored; v7 proxy_cache_bypass in the rule location).
func Variants(indent, proxy string) string {
	var output strings.Builder
	inner := indent + "  "
	fmt.Fprintf(&output, "%slocation %s {\n", indent, BypassVariant)
	output.WriteString(proxy)
	responseHeaders(&output, inner)
	fmt.Fprintf(&output, "%sproxy_set_header Range $cdnca_cache_range;\n%sproxy_set_header If-Range $cdnca_cache_if_range;\n", inner, inner)
	fmt.Fprintf(&output, "%sproxy_force_ranges on;\n%s}\n", inner, indent)
	for _, variant := range variants() {
		fmt.Fprintf(&output, "%slocation %s {\n", indent, variant.name)
		output.WriteString(proxy)
		responseHeaders(&output, inner)
		fmt.Fprintf(&output, "%sproxy_cache $cdnca_cache_zone;\n", inner)
		if variant.follow {
			// a redirect followed: not read (a stored 30x of the original key
			// would answer again), the final response stored under the key
			fmt.Fprintf(&output, "%sproxy_cache_bypass $cdnca_cache_follow;\n", inner)
			// an intercepted redirect is not stored (before the rule TTLs;
			// an origin max-age still stores one: a HIT on it re-enters and
			// is fetched again with the lookup skipped)
			fmt.Fprintf(&output, "%sproxy_cache_valid 301 302 303 307 308 0;\n", inner)
			followDirectives(&output, inner, variant.name)
		}
		if variant.sliceBytes > 0 {
			// one object per slice: the slice's range is part of its key (v7)
			fmt.Fprintf(&output, "%sproxy_cache_key $cdnca_cache_key|slice=$slice_range;\n", inner)
		} else {
			fmt.Fprintf(&output, "%sproxy_cache_key $cdnca_cache_key;\n", inner)
		}
		fmt.Fprintf(&output, "%sproxy_cache_valid any $cdnca_cache_valid;\n", inner)
		fmt.Fprintf(&output, "%sproxy_no_cache $cdnca_cache_response_cookie $cdnca_cache_response_control $cdnca_cache_size_bypass $cdnca_cache_rule_bypass;\n", inner)
		fmt.Fprintf(&output, "%sexpires $cdnca_cache_expires;\n", inner)
		switch {
		case variant.override && variant.ignoreVary:
			fmt.Fprintf(&output, "%sproxy_ignore_headers X-Accel-Expires Expires Cache-Control Vary;\n", inner)
		case variant.override:
			fmt.Fprintf(&output, "%sproxy_ignore_headers X-Accel-Expires Expires Cache-Control;\n", inner)
		case variant.ignoreVary:
			fmt.Fprintf(&output, "%sproxy_ignore_headers Vary;\n", inner)
		}
		fmt.Fprintf(&output, "%sproxy_cache_lock on;\n%sproxy_cache_lock_timeout %ds;\n%sproxy_cache_lock_age %ds;\n",
			inner, inner, int64(LockTimeout/time.Second), inner, int64(LockTimeout/time.Second))
		fmt.Fprintf(&output, "%sproxy_cache_revalidate on;\n", inner)
		if variant.stale != staleNone {
			fmt.Fprintf(&output, "%sproxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;\n", inner)
			fmt.Fprintf(&output, "%sproxy_cache_background_update %s;\n", inner, map[bool]string{true: "on", false: "off"}[variant.stale == staleBackground])
		}
		if variant.sliceBytes > 0 {
			fmt.Fprintf(&output, "%sslice %d;\n%sproxy_set_header Range $slice_range;\n%sproxy_set_header If-Range \"\";\n",
				inner, variant.sliceBytes, inner, inner)
		} else {
			// cached: "" (the origin sends the whole object); bypassed: the
			// client's Range when the site enables it (cache module)
			fmt.Fprintf(&output, "%sproxy_set_header Range $cdnca_cache_range;\n%sproxy_set_header If-Range $cdnca_cache_if_range;\n", inner, inner)
		}
		fmt.Fprintf(&output, "%sproxy_force_ranges on;\n", inner)
		fmt.Fprintf(&output, "%s}\n", indent)
	}
	return output.String()
}

// LockTimeout bounds how long concurrent misses of one key wait for the
// first fill (v7 cacheLockTimeout / cacheLockAge).
const LockTimeout = 5 * time.Second

// AdminLocation routes /cache/ on the dynamic routing control socket server
// (dynroute contract section 5.4) to the cache module.
func AdminLocation(indent string) string {
	return fmt.Sprintf("%slocation /cache/ { content_by_lua_block { require(%q).admin() } }\n", indent, Module)
}
