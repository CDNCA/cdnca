package edgecache

import (
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

func extrasSite(rules []edgeconfig.CacheRuleDocument) edgesite.Site {
	policy := edgeconfig.CachePolicyDocument{SchemaVersion: 2, Revision: 1, Mode: edgeconfig.CacheOverride,
		Rules: rules, QueryMode: edgeconfig.CacheQueryPreserve, QueryNames: []string{}, VaryHeaders: []string{}, DiskQuotaBytes: 64 << 20}
	return edgesite.Site{Cache: &edgesite.Cache{KeyPrefix: strings.Repeat("a", 32), Generation: strings.Repeat("b", 16), Domain: "x.test", Policy: policy}}
}

func TestRuleExtrasPlan(t *testing.T) {
	no, slice := false, int64(1<<20)
	home := edgeconfig.CacheRuleDocument{Order: 1, Action: edgeconfig.CacheRuleActionCache, TTLSeconds: 86400,
		CacheRuleExtras: edgeconfig.CacheRuleExtras{PathExact: "/", ForceCache: &no}}
	video := edgeconfig.CacheRuleDocument{Order: 2, Extensions: []string{".mp4"}, Action: edgeconfig.CacheRuleActionCache, TTLSeconds: 600,
		CacheRuleExtras: edgeconfig.CacheRuleExtras{SliceBytes: &slice, IgnoreQuery: true, IgnoreVary: true}}
	wp := edgeconfig.CacheRuleDocument{Order: 3, PathPrefix: "/", Action: edgeconfig.CacheRuleActionCache, TTLSeconds: 300,
		CacheRuleExtras: edgeconfig.CacheRuleExtras{NoCache: []edgeconfig.CacheNoCacheCondition{{Source: "header", Name: "cookie", Pattern: "wordpress_logged_in"}}}}
	plan, err := Build(extrasSite([]edgeconfig.CacheRuleDocument{home, video, wp}))
	if err != nil {
		t.Fatal(err)
	}
	// "/" exact: rules 1 and 3; "/a.mp4": 2 and 3; any other path: 3
	for signature, want := range map[string]string{"1,3": "@cdnca_cache_follow", "2,3": "@cdnca_cache_override_nv_s1024", "3": ""} {
		route, ok := plan.Routes[signature]
		if !ok || route.Variant != want {
			t.Fatalf("route %q = %+v (present %v), want variant %q; routes %v", signature, route, ok, want, plan.Routes)
		}
	}
	if !plan.Routes["2,3"].IgnoreQuery || len(plan.Routes["3"].NoCache) != 1 || len(plan.Routes["1,3"].NoCache) != 0 {
		t.Fatalf("per-rule settings: %+v", plan.Routes)
	}
	if plan.Routes["2,3"].TTLs != " any=600 " {
		t.Fatalf("sliced TTLs %q", plan.Routes["2,3"].TTLs)
	}
	for _, name := range []string{"@cdnca_cache_follow", "@cdnca_cache_override_nv_s1024", "@cdnca_cache_override_stalebg_nv_f"} {
		if !strings.Contains(Variants("", ""), "location "+name+" {") {
			t.Fatalf("variant %s not rendered", name)
		}
	}
	if !strings.Contains(Variants("", ""), "proxy_ignore_headers X-Accel-Expires Expires Cache-Control Vary;") ||
		!strings.Contains(Variants("", ""), "proxy_ignore_headers Vary;") {
		t.Fatal("ignore Vary variants missing")
	}
}

func TestRuleExtrasValidation(t *testing.T) {
	zero, bad := int64(0), int64(100)
	cases := map[string]struct {
		extras edgeconfig.CacheRuleExtras
		prefix string
		action edgeconfig.CacheRuleAction
		ok     bool
	}{
		"exact":                {edgeconfig.CacheRuleExtras{PathExact: "/index.html"}, "", "cache", true},
		"exact with prefix":    {edgeconfig.CacheRuleExtras{PathExact: "/"}, "/a/", "cache", false},
		"exact dot segment":    {edgeconfig.CacheRuleExtras{PathExact: "/a/../b"}, "", "cache", false},
		"exact query":          {edgeconfig.CacheRuleExtras{PathExact: "/a?b"}, "", "cache", false},
		"slice off":            {edgeconfig.CacheRuleExtras{SliceBytes: &zero}, "", "cache", true},
		"slice out of bounds":  {edgeconfig.CacheRuleExtras{SliceBytes: &bad}, "", "cache", false},
		"no cache on no_cache": {edgeconfig.CacheRuleExtras{IgnoreVary: true}, "", "no_cache", false},
		"exact on no_cache":    {edgeconfig.CacheRuleExtras{PathExact: "/x"}, "", "no_cache", true},
		"header without name":  {edgeconfig.CacheRuleExtras{NoCache: []edgeconfig.CacheNoCacheCondition{{Source: "header", Pattern: "x"}}}, "", "cache", false},
		"name on uri":          {edgeconfig.CacheRuleExtras{NoCache: []edgeconfig.CacheNoCacheCondition{{Source: "uri", Name: "x", Pattern: "x"}}}, "", "cache", false},
		"nested repeat":        {edgeconfig.CacheRuleExtras{NoCache: []edgeconfig.CacheNoCacheCondition{{Source: "uri", Pattern: "(a+)+"}}}, "", "cache", false},
		"unknown source":       {edgeconfig.CacheRuleExtras{NoCache: []edgeconfig.CacheNoCacheCondition{{Source: "body", Pattern: "x"}}}, "", "cache", false},
		"empty list":           {edgeconfig.CacheRuleExtras{NoCache: []edgeconfig.CacheNoCacheCondition{}}, "", "cache", false},
	}
	for name, item := range cases {
		if err := edgeconfig.ValidateCacheRuleExtras(item.extras, item.prefix, item.action); (err == nil) != item.ok {
			t.Errorf("%s: err %v, want ok %v", name, err, item.ok)
		}
	}
}
