package edgeconfig

import (
	"strings"
	"testing"
	"time"
)

func geCacheRenderer(t *testing.T, document CachePolicyDocument, rangeEnabled bool) *SiteCacheRenderer {
	t.Helper()
	renderer, err := NewSiteCacheRenderer("cv-1", "/var/lib/cdnca/shared", "33333333-3333-4333-8333-333333333333", 0,
		[]string{"cache.example.test"}, rangeEnabled, SiteRuntimeCache{
			TenantID: "11111111-1111-4111-8111-111111111111", Domain: "cache.example.test", Policy: document,
		})
	if err != nil {
		t.Fatal(err)
	}
	return renderer
}

func geSimplePolicy() CachePolicyDocument {
	return CachePolicyDocument{Revision: 3, Mode: CacheFollowOrigin, QueryMode: CacheQueryPreserve, DiskQuotaBytes: 64 << 20,
		Rules: []CacheRuleDocument{}, QueryNames: []string{}, VaryHeaders: []string{}}
}

func geRulePolicy() CachePolicyDocument {
	return CachePolicyDocument{SchemaVersion: CachePolicyDocumentSchemaV2, Revision: 5, Mode: CacheOverride,
		QueryMode: CacheQueryPreserve, DiskQuotaBytes: 64 << 20, QueryNames: []string{}, VaryHeaders: []string{},
		Rules: []CacheRuleDocument{
			{Order: 1, Extensions: []string{".css"}, Action: CacheRuleActionCache, TTLSeconds: 7 * 24 * 3600},
			{Order: 2, PathPrefix: "/api/", Action: CacheRuleActionNoCache},
		}}
}

// A: the namespace and key do not name the config version; they change only
// with what decides which object a request reads.
func TestCacheGenerationIsStableAcrossPublications(t *testing.T) {
	first := geCacheRenderer(t, geSimplePolicy(), false)
	second, err := NewSiteCacheRenderer("cv-2", "/var/lib/cdnca/shared", "33333333-3333-4333-8333-333333333333", 0,
		[]string{"cache.example.test"}, false, SiteRuntimeCache{TenantID: "11111111-1111-4111-8111-111111111111",
			Domain: "cache.example.test", Policy: geSimplePolicy()})
	if err != nil {
		t.Fatal(err)
	}
	if first.NamespaceID() != second.NamespaceID() || first.Generation() != second.Generation() ||
		proxyCacheKeys(first.PublicDirectives(80))[0] != proxyCacheKeys(second.PublicDirectives(80))[0] {
		t.Fatal("another config version changed the cache identity")
	}
	if strings.Contains(first.PublicDirectives(80), "cv-1") || strings.Contains(first.HTTPDefinitions(map[string]struct{}{}), "cv-1") {
		t.Fatal("cache key or zone names the config version")
	}
	quota := geSimplePolicy()
	quota.Revision, quota.DiskQuotaBytes, quota.StaleIfError = 9, 128<<20, true
	if geCacheRenderer(t, quota, false).Generation() != first.Generation() {
		t.Fatal("revision/quota/stale changed the generation")
	}
	query := geSimplePolicy()
	query.QueryMode = CacheQueryIgnore
	if geCacheRenderer(t, query, false).Generation() == first.Generation() {
		t.Fatal("a key projection change kept the generation")
	}
}

// B: keys_zone grows with the quota (8000 keys per MiB, 32 KiB objects).
func TestCacheZoneBytesForQuota(t *testing.T) {
	for _, item := range []struct{ quota, want int64 }{
		{64 << 20, 1 << 20}, {1 << 30, 5 << 20}, {10 << 30, 41 << 20}, {100 << 30, 256 << 20}, {16 << 40, maxCacheZoneSize},
	} {
		if got := CacheZoneBytesForQuota(item.quota); got != item.want {
			t.Errorf("quota %d: zone %d, want %d", item.quota, got, item.want)
		}
	}
	policy := geSimplePolicy()
	policy.DiskQuotaBytes = 10 << 30
	if zone := geCacheRenderer(t, policy, false).HTTPDefinitions(map[string]struct{}{}); !strings.Contains(zone, ":41m max_size=10240m") {
		t.Fatalf("10 GiB quota zone:\n%s", zone)
	}
}

// C: a request Cookie bypasses only requests no cache rule names.
func TestCacheCookieBypassesOnlyUnmatchedRequests(t *testing.T) {
	maps := SiteRuntimeCacheHTTPMaps()
	if !strings.Contains(maps, `map "$cdnca_cache_rule_matched:$http_cookie" $cdnca_cache_cookie_bypass { volatile; default 1; ~^1: 0; "0:" 0; }`) {
		t.Fatalf("cookie map:\n%s", maps)
	}
	renderer := geCacheRenderer(t, geRulePolicy(), false)
	routes := renderer.NamedRoutes(false, "      proxy_pass http://site;\n")
	bypass, _ := nginxNamedBlock(routes, "    location "+cachePolicyRouteName(0, false, 0)+" {")
	if strings.Contains(bypass, "cdnca_cache_rule_matched 1") || strings.Contains(bypass, "proxy_cache ") {
		t.Fatalf("bypass route:\n%s", bypass)
	}
	for index := 1; index <= len(renderer.plan.Routes); index++ {
		block, ok := nginxNamedBlock(routes, "    location "+cachePolicyRouteName(0, false, index)+" {")
		if !ok || !strings.Contains(block, "set $cdnca_cache_rule_matched 1;") {
			t.Fatalf("rule route %d does not mark the rule match:\n%s", index, block)
		}
	}
	if headers := renderer.ServerHeaders(); !strings.Contains(headers, "set $cdnca_cache_rule_matched 0;") {
		t.Fatalf("server does not default the rule match:\n%s", headers)
	}
}

// D: the Range request header no longer bypasses; a cached site asks the
// origin for the full object (or one slice) and cuts the client's range.
func TestCacheRangeReadsCachedObject(t *testing.T) {
	if maps := SiteRuntimeCacheHTTPMaps(); strings.Contains(maps, "$cdnca_cache_range_bypass") {
		t.Fatalf("Range still bypasses:\n%s", maps)
	}
	plain := geCacheRenderer(t, geSimplePolicy(), true).PublicDirectives(80)
	for _, line := range []string{"proxy_set_header Range $cdnca_cache_origin_range;", "proxy_force_ranges on;",
		"proxy_cache_bypass $cdnca_cache_request_bypass $cdnca_cache_policy_bypass;"} {
		if !strings.Contains(plain, line) {
			t.Fatalf("range-enabled cached site lacks %q:\n%s", line, plain)
		}
	}
	if off := geCacheRenderer(t, geSimplePolicy(), false).PublicDirectives(80); !strings.Contains(off, `proxy_set_header Range "";`) {
		t.Fatalf("range-disabled site forwards Range:\n%s", off)
	}
	sliced := geSimplePolicy()
	sliced.SliceBytes = 1 << 20
	directives := geCacheRenderer(t, sliced, true).PublicDirectives(80)
	for _, line := range []string{"slice 1048576;", "proxy_set_header Range $slice_range;", "|slice=$slice_range\";",
		"proxy_cache_valid 200 206 301 302 60s;"} {
		if !strings.Contains(directives, line) {
			t.Fatalf("slice cache lacks %q:\n%s", line, directives)
		}
	}
}

// G: inactive covers the longest rule TTL (7 days), and the stale window.
func TestCacheInactiveCoversRuleTTL(t *testing.T) {
	if zone := geCacheRenderer(t, geRulePolicy(), false).HTTPDefinitions(map[string]struct{}{}); !strings.Contains(zone, "inactive=604800s") {
		t.Fatalf("rule TTL inactive:\n%s", zone)
	}
	stale := geSimplePolicy()
	stale.StaleIfError = true
	if zone := geCacheRenderer(t, stale, false).HTTPDefinitions(map[string]struct{}{}); !strings.Contains(zone, "inactive=86400s") {
		t.Fatalf("stale inactive:\n%s", zone)
	}
	policy, _ := CachePolicyFromDocument(geRulePolicy())
	if cacheInactiveV2(policy) != 7*24*time.Hour {
		t.Fatal(cacheInactiveV2(policy))
	}
}

// H: STALE/UPDATING/REVALIDATED keep their names; BYPASS carries a reason.
func TestCacheStatusHeaderNamesStaleAndReason(t *testing.T) {
	maps := SiteRuntimeCacheHTTPMaps()
	for _, line := range []string{`":STALE" STALE;`, `":UPDATING" UPDATING;`, `":REVALIDATED" REVALIDATED;`,
		"~^..1 cookie;", "~^....1 no_cache_rule;", "~^.......1 object_size;",
		"$cdnca_cache_reason_header { volatile; default \"\"; BYPASS $cdnca_cache_bypass_reason; }"} {
		if !strings.Contains(maps, line) {
			t.Fatalf("maps lack %q:\n%s", line, maps)
		}
	}
	if headers := geCacheRenderer(t, geSimplePolicy(), false).ServerHeaders(); !strings.Contains(headers,
		"add_header X-CDN-Cache-Reason $cdnca_cache_reason_header always;") {
		t.Fatalf("server headers:\n%s", headers)
	}
}

// Missing 1/7/9: stale-if-error, background update, lock, revalidation,
// object size bounds, sendfile/aio (no open_file_cache: purge unlinks files).
func TestCacheV2Extensions(t *testing.T) {
	policy := geSimplePolicy()
	policy.StaleIfError, policy.BackgroundUpdate, policy.MinObjectBytes, policy.MaxObjectBytes = true, true, 1024, 512<<20
	directives := geCacheRenderer(t, policy, false).PublicDirectives(80)
	for _, line := range []string{"proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;",
		"proxy_cache_background_update on;", "proxy_cache_lock on;", "proxy_cache_revalidate on;",
		"header_filter_by_lua_block {", "length < 1024", "length > 536870912", "$cdnca_cache_size_bypass;"} {
		if !strings.Contains(directives, line) {
			t.Fatalf("extensions lack %q:\n%s", line, directives)
		}
	}
	if plain := geCacheRenderer(t, geSimplePolicy(), false).PublicDirectives(80); strings.Contains(plain, "use_stale") ||
		strings.Contains(plain, "header_filter_by_lua") {
		t.Fatalf("stale/size without the policy asking:\n%s", plain)
	}
	if maps := SiteRuntimeCacheHTTPMaps(); !strings.Contains(maps, "sendfile on;") || !strings.Contains(maps, "aio threads;") ||
		strings.Contains(maps, "open_file_cache") {
		t.Fatalf("file directives:\n%s", maps)
	}
	for name, invalid := range map[string]func(*CachePolicyDocument){
		"background without stale": func(p *CachePolicyDocument) { p.BackgroundUpdate = true },
		"min >= max":               func(p *CachePolicyDocument) { p.MinObjectBytes, p.MaxObjectBytes = 10, 10 },
		"slice too small":          func(p *CachePolicyDocument) { p.SliceBytes = 64 << 10 },
		"slice unaligned":          func(p *CachePolicyDocument) { p.SliceBytes = 1<<20 + 1 },
	} {
		document := geSimplePolicy()
		invalid(&document)
		if _, err := CachePolicyFromDocument(document); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	disabled := CachePolicyDocument{Mode: CacheDisabled, QueryMode: CacheQueryIgnore, StaleIfError: true}
	if _, err := CachePolicyFromDocument(disabled); err == nil {
		t.Error("disabled policy with stale accepted")
	}
}

// E: the node budget (system settings) scales every site's disk and zone so
// their sums fit, and sets min_free.
func TestCacheNodeBudgetScalesSites(t *testing.T) {
	big := geSimplePolicy()
	big.DiskQuotaBytes = 300 << 30
	small := geSimplePolicy()
	small.DiskQuotaBytes = 100 << 30
	first, second := geCacheRenderer(t, big, false), geCacheRenderer(t, small, false)
	ApplyCacheNodeBudget([]*SiteCacheRenderer{first, second},
		CacheNodeBudget{MaxBytes: 200 << 30, ZoneBytes: 256 << 20, MinFreeBytes: 5 << 30})
	if first.maxSize != 150<<30 || second.maxSize != 50<<30 || first.zoneSize+second.zoneSize > 256<<20 {
		t.Fatalf("scaled disk %d/%d zone %d/%d", first.maxSize, second.maxSize, first.zoneSize, second.zoneSize)
	}
	if zone := first.HTTPDefinitions(map[string]struct{}{}); !strings.Contains(zone, " min_free=5120m ") {
		t.Fatalf("min_free:\n%s", zone)
	}
	untouched := geCacheRenderer(t, small, false)
	ApplyCacheNodeBudget([]*SiteCacheRenderer{untouched}, CacheNodeBudget{})
	if untouched.maxSize != 100<<30 || strings.Contains(untouched.HTTPDefinitions(map[string]struct{}{}), "min_free") {
		t.Fatal("empty budget changed the site")
	}
}
