package edgecache

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

const (
	testTenant = "0a1b9999-0000-4000-8000-000000000001"
	testSite   = "0a1b2005-0000-4000-8000-000000000103"
)

func keyPrefixFor(index int) string {
	sum := sha256.Sum256([]byte(fmt.Sprint(index)))
	return hex.EncodeToString(sum[:16])
}

func siteWith(t *testing.T, policy edgeconfig.CachePolicyDocument, keyByHost, rangeOn bool) edgesite.Site {
	t.Helper()
	if policy.Rules == nil {
		policy.Rules = []edgeconfig.CacheRuleDocument{}
	}
	policy.QueryNames, policy.VaryHeaders = nonNil(policy.QueryNames), nonNil(policy.VaryHeaders)
	cache := &edgesite.Cache{KeyPrefix: edgesite.CacheKeyPrefix(testTenant, testSite), Domain: "rules.example.test", KeyByHost: keyByHost, Policy: policy}
	token, err := edgesite.CacheGeneration(*cache)
	if err != nil {
		t.Fatal(err)
	}
	cache.Generation = token
	return edgesite.Site{TenantID: testTenant, SiteID: testSite, Range: rangeOn, Cache: cache}
}

// The golden "cache" scenario's rules site: .css cached 60s, /api/ no cache,
// anything else no rule (BYPASS).
func TestBuildRulesSiteMatchesV7Golden(t *testing.T) {
	site := siteWith(t, edgeconfig.CachePolicyDocument{SchemaVersion: 2, Revision: 4, Mode: edgeconfig.CacheOverride,
		Rules: []edgeconfig.CacheRuleDocument{
			{Order: 1, Extensions: []string{".css"}, Action: edgeconfig.CacheRuleActionCache, TTLSeconds: 60},
			{Order: 2, PathPrefix: "/api/", Action: edgeconfig.CacheRuleActionNoCache},
		}, QueryMode: edgeconfig.CacheQueryPreserve, DiskQuotaBytes: 64 << 20}, true, false)
	plan, err := Build(site)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Routes) != 3 {
		t.Fatalf("routes %v", plan.Routes)
	}
	css, api, both := plan.Routes["1"], plan.Routes["2"], plan.Routes["1,2"]
	if !css.Cache || css.TTLs != " any=60 " || css.BrowserAny != "off" {
		t.Errorf("css %+v", css)
	}
	if api.Cache || api.TTLs != " any=0 " || api.BrowserAny != "epoch" {
		t.Errorf("api %+v", api)
	}
	// /api/x.css: rule 1 is the first candidate without statuses
	if !both.Cache || both.TTLs != " any=60 " {
		t.Errorf("api css %+v", both)
	}
	if _, exists := plan.Routes[""]; exists {
		t.Error("a request matching no rule must not have a route (v7 BYPASS)")
	}
	if plan.Projected || plan.MaxTTL() != time.Minute || plan.QuotaBytes != 64<<20 {
		t.Errorf("%+v", plan)
	}
}

func TestBuildStatusRules(t *testing.T) {
	site := siteWith(t, edgeconfig.CachePolicyDocument{SchemaVersion: 2, Revision: 1, Mode: edgeconfig.CacheOverride,
		Rules: []edgeconfig.CacheRuleDocument{
			{Order: 1, PathPrefix: "/img/", StatusCodes: []int{404}, Action: edgeconfig.CacheRuleActionCache, TTLSeconds: 30, BrowserTTLSeconds: 10},
			{Order: 2, StatusCodes: []int{500}, Action: edgeconfig.CacheRuleActionNoCache},
			{Order: 3, Action: edgeconfig.CacheRuleActionCache, TTLSeconds: 3600},
		}, QueryMode: edgeconfig.CacheQueryIgnore, DiskQuotaBytes: 64 << 20, SliceBytes: 1 << 20}, false, true)
	plan, err := Build(site)
	if err != nil {
		t.Fatal(err)
	}
	img := plan.Routes["1,2,3"]
	if img.TTLs != " 404=30 500=0 any=3600 " || img.Browser["404"] != "10s" || img.Browser["500"] != "epoch" || img.BrowserAny != "off" {
		t.Errorf("img %+v", img)
	}
	other := plan.Routes["2,3"]
	if other.TTLs != " 500=0 any=3600 " {
		t.Errorf("other %+v", other)
	}
	if !plan.Projected || plan.SliceBytes != 1<<20 || plan.KeyByHost || plan.MaxTTL() != time.Hour {
		t.Errorf("%+v", plan)
	}
}

func TestBuildSimpleAndDisabled(t *testing.T) {
	plan, err := Build(siteWith(t, edgeconfig.CachePolicyDocument{Revision: 3, Mode: edgeconfig.CacheOverride,
		QueryMode: edgeconfig.CacheQueryPreserve, DiskQuotaBytes: 64 << 20}, true, false))
	if err != nil {
		t.Fatal(err)
	}
	if plan.Routes[""].TTLs != " 200=60 301=60 302=60 any=0 " || plan.SliceBytes != 0 {
		t.Errorf("%+v", plan)
	}
	disabled := siteWith(t, edgeconfig.CachePolicyDocument{Revision: 1, Mode: edgeconfig.CacheDisabled, QueryMode: edgeconfig.CacheQueryIgnore}, true, false)
	if plan, err := Build(disabled); plan != nil || err != nil {
		t.Fatalf("disabled: %v %v", plan, err)
	}
	if _, err := Build(siteWith(t, edgeconfig.CachePolicyDocument{Revision: 3, Mode: edgeconfig.CacheOverride,
		QueryMode: edgeconfig.CacheQueryPreserve, DiskQuotaBytes: 64 << 20, SliceBytes: 1000}, true, true)); err == nil {
		t.Fatal("bad slice size accepted")
	}
}

func TestKeyStableAcrossPublicationsAndIsolated(t *testing.T) {
	policy := edgeconfig.CachePolicyDocument{Revision: 3, Mode: edgeconfig.CacheOverride, QueryMode: edgeconfig.CacheQueryPreserve, DiskQuotaBytes: 64 << 20}
	plan, _ := Build(siteWith(t, policy, true, false))
	key := Key(plan, 0, "alias.example.test", 443, "/a.css")
	if !strings.HasPrefix(key, plan.KeyPrefix+"|"+plan.Generation+"|0|alias.example.test|443|/a.css") {
		t.Fatal(key)
	}
	// a republication (new revision) or a new quota keeps the key (D8 revision)
	policy.Revision, policy.DiskQuotaBytes = 9, 128<<20
	again, _ := Build(siteWith(t, policy, true, false))
	if Key(again, 0, "alias.example.test", 443, "/a.css") != key {
		t.Fatal("republication changed the key")
	}
	// a purge generation is a new key space for this site only
	if Key(plan, 1, "alias.example.test", 443, "/a.css") == key {
		t.Fatal("purge generation ignored")
	}
	shared, _ := Build(siteWith(t, policy, false, false))
	if !strings.Contains(Key(shared, 0, "alias.example.test", 443, "/a"), "|rules.example.test|") {
		t.Fatal("shared domain key")
	}
}

// ge-cache policy extensions: the variant a plan dispatches to, slices
// cache 206 like 200 (v7 v2Validity), stale keeps objects 24h.
func TestBuildPolicyExtensions(t *testing.T) {
	base := edgeconfig.CachePolicyDocument{Revision: 3, Mode: edgeconfig.CacheOverride, QueryMode: edgeconfig.CacheQueryPreserve, DiskQuotaBytes: 64 << 20}
	plan, err := Build(siteWith(t, base, true, false))
	if err != nil || plan.Variant() != "@cdnca_cache_override" || plan.SliceBytes != 0 || plan.Inactive() != time.Minute {
		t.Fatalf("plain %+v %v variant %s", plan, err, plan.Variant())
	}
	extended := base
	extended.StaleIfError, extended.BackgroundUpdate, extended.MinObjectBytes, extended.MaxObjectBytes = true, true, 10, 1<<20
	extended.SliceBytes = 3 << 20 // runs in the 1 MiB slice variant
	plan, err = Build(siteWith(t, extended, true, false))
	if err != nil || plan.Variant() != "@cdnca_cache_override_stalebg_s1024" || plan.SliceBytes != 1<<20 ||
		plan.MinObjectBytes != 10 || plan.MaxObjectBytes != 1<<20 || plan.Inactive() != StaleInactive {
		t.Fatalf("extended %+v %v variant %s", plan, err, plan.Variant())
	}
	if plan.Routes[""].TTLs != " 200=60 206=60 301=60 302=60 any=0 " {
		t.Fatalf("slice TTLs %q", plan.Routes[""].TTLs)
	}
	follow := base
	follow.Mode, follow.StaleIfError = edgeconfig.CacheFollowOrigin, true
	if plan, _ := Build(siteWith(t, follow, true, false)); plan.Variant() != "@cdnca_cache_follow_stale" {
		t.Fatalf("follow variant %s", plan.Variant())
	}
	names := map[string]bool{}
	for _, name := range VariantNames() {
		names[name] = true
	}
	for _, size := range []int64{256 << 10, 512 << 10, 1 << 20, 5 << 20, 64 << 20} {
		document := base
		document.SliceBytes = size
		plan, err := Build(siteWith(t, document, false, false))
		if err != nil || !names[plan.Variant()] || plan.SliceBytes > size || plan.SliceBytes == 0 {
			t.Fatalf("slice %d: %v %s", size, err, plan.Variant())
		}
	}
	invalid := base
	invalid.BackgroundUpdate = true
	if _, err := Build(siteWith(t, invalid, true, false)); err == nil {
		t.Fatal("background update without stale-if-error accepted")
	}
}

func TestVariantsRenderTheV7CacheDirectives(t *testing.T) {
	rendered := Variants("    ", "      proxy_pass http://x;\n")
	for _, name := range VariantNames() {
		if !strings.Contains(rendered, "location "+name+" {") {
			t.Fatalf("variant %s not rendered", name)
		}
	}
	block := func(name string) string {
		start := strings.Index(rendered, "location "+name+" {")
		end := strings.Index(rendered[start:], "\n    }\n")
		return rendered[start : start+end]
	}
	stale := block("@cdnca_cache_follow_stalebg_s256")
	for _, want := range []string{"proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;",
		"proxy_cache_background_update on;", "slice 262144;", "proxy_set_header Range $slice_range;",
		"proxy_cache_key $cdnca_cache_key|slice=$slice_range;", "proxy_cache_lock on;", "proxy_cache_revalidate on;",
		"proxy_force_ranges on;", "proxy_no_cache $cdnca_cache_response_cookie $cdnca_cache_response_control $cdnca_cache_size_bypass $cdnca_cache_rule_bypass;"} {
		if !strings.Contains(stale, want) {
			t.Fatalf("missing %q in\n%s", want, stale)
		}
	}
	plain := block("@cdnca_cache_override")
	if strings.Contains(plain, "use_stale") || strings.Contains(plain, "slice ") || !strings.Contains(plain, "proxy_force_ranges on;") ||
		!strings.Contains(plain, "proxy_ignore_headers X-Accel-Expires Expires Cache-Control;") {
		t.Fatalf("plain variant\n%s", plain)
	}
	if bypass := block(BypassVariant); strings.Contains(bypass, "proxy_cache ") || !strings.Contains(bypass, "proxy_force_ranges on;") {
		t.Fatalf("bypass variant\n%s", bypass)
	}
}

// ge36: a path_regex rule may or may not match each request, a
// content_types rule may be dropped once the response is known.
func TestBuildConditionalRules(t *testing.T) {
	site := siteWith(t, edgeconfig.CachePolicyDocument{SchemaVersion: 2, Revision: 5, Mode: edgeconfig.CacheOverride,
		Rules: []edgeconfig.CacheRuleDocument{
			{Order: 1, PathRegex: `^/v[0-9]+/`, Action: edgeconfig.CacheRuleActionCache, TTLSeconds: 300},
			{Order: 2, ContentTypes: []string{"image/*"}, Action: edgeconfig.CacheRuleActionCache, TTLSeconds: 600},
			{Order: 3, Extensions: []string{".html"}, Action: edgeconfig.CacheRuleActionNoCache},
		}, QueryMode: edgeconfig.CacheQueryPreserve, DiskQuotaBytes: 64 << 20}, false, false)
	plan, err := Build(site)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Rules[0].PathRegex != `^/v[0-9]+/` || len(plan.Rules[1].ContentTypes) != 1 {
		t.Fatalf("rules %+v", plan.Rules)
	}
	for _, signature := range []string{"1", "2", "1,2", "3", "1,3", "2,3", "1,2,3"} {
		if _, ok := plan.Routes[signature]; !ok {
			t.Errorf("route %q missing: %v", signature, plan.Routes)
		}
	}
	if len(plan.Routes) != 7 {
		t.Errorf("routes %v", plan.Routes)
	}
	// /x.html with an image: "2,3" -> rule 2 (first) caches 600s
	if route := plan.Routes["2,3"]; !route.Cache || route.TTLs != " any=600 " || !route.MayCache {
		t.Errorf("2,3 %+v", route)
	}
	// /x.html, not an image: rule 2 dropped -> "3" no cache
	if route := plan.Routes["3"]; route.Cache || route.MayCache {
		t.Errorf("3 %+v", route)
	}
	// only a content_types rule: may cache (an image), the request is looked up
	if route := plan.Routes["2"]; !route.Cache || !route.MayCache {
		t.Errorf("2 %+v", route)
	}
}

// ge36 schema v1 (the console's document): conditional rules plan like v2,
// every matching v1 rule caches at its TTL.
func TestBuildConditionalRulesSchemaV1(t *testing.T) {
	site := siteWith(t, edgeconfig.CachePolicyDocument{Revision: 2, Mode: edgeconfig.CacheOverride,
		Rules: []edgeconfig.CacheRuleDocument{
			{Order: 1, PathRegex: `^/v[0-9]+/`, TTLSeconds: 300},
			{Order: 2, ContentTypes: []string{"image/*"}, TTLSeconds: 600},
			{Order: 3, PathPrefix: "/", TTLSeconds: 30},
		}, QueryMode: edgeconfig.CacheQueryPreserve, DiskQuotaBytes: 64 << 20}, false, false)
	plan, err := Build(site)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Rules[0].PathRegex != `^/v[0-9]+/` || len(plan.Rules[1].ContentTypes) != 1 {
		t.Fatalf("rules %+v", plan.Rules)
	}
	if route := plan.Routes["1,2,3"]; !route.Cache || route.TTLs != " any=300 " {
		t.Errorf("1,2,3 %+v", route)
	}
	if route := plan.Routes["2,3"]; !route.Cache || route.TTLs != " any=600 " {
		t.Errorf("2,3 %+v", route)
	}
	if route := plan.Routes["3"]; !route.Cache || route.TTLs != " any=30 " {
		t.Errorf("3 %+v", route)
	}
}

func TestBuildConditionalRulesBound(t *testing.T) {
	rules := make([]edgeconfig.CacheRuleDocument, edgeconfig.MaxCacheConditionalRules)
	for index := range rules {
		rules[index] = edgeconfig.CacheRuleDocument{Order: index + 1, PathRegex: fmt.Sprintf("^/r%d/", index),
			Extensions: []string{fmt.Sprintf(".e%d", index)}, Action: edgeconfig.CacheRuleActionCache, TTLSeconds: 60}
	}
	site := siteWith(t, edgeconfig.CachePolicyDocument{SchemaVersion: 2, Revision: 1, Mode: edgeconfig.CacheOverride,
		Rules: rules, QueryMode: edgeconfig.CacheQueryPreserve, DiskQuotaBytes: 64 << 20}, false, false)
	plan, err := Build(site)
	if err != nil || len(plan.Routes) != edgeconfig.MaxCacheConditionalRules {
		t.Fatalf("plan %v, %v", plan, err)
	}
}
