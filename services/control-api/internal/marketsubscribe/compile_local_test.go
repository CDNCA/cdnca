package marketsubscribe

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/regioncatalog"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
)

func codesOf(in []Unsupported) []string {
	out := []string{}
	for _, u := range in {
		out = append(out, u.Code)
	}
	return out
}

// The site's own cache rules become the revision's cache block and read
// back the same through siteconf.
func TestCompileCacheRoundTrip(t *testing.T) {
	slice, force := int64(1<<20), true
	doc := cachecontrol.PolicyDocument{SchemaVersion: cachecontrol.PolicySchemaV2, Mode: cachecontrol.PolicyOverride,
		QueryMode: cachecontrol.QueryInclude, QueryNames: []string{"v"}, VaryHeaders: []string{"accept-encoding"},
		DiskQuotaBytes: 5 << 30, Extensions: cachecontrol.PolicyExtensions{StaleIfError: true, MaxObjectBytes: 1 << 20},
		Rules: []cachecontrol.Rule{
			{Order: 1, Extensions: []string{".png"}, Action: cachecontrol.RuleActionCache, TTLSeconds: 3600, BrowserTTLSeconds: 60},
			{Order: 2, PathRegex: "^/api/", Action: cachecontrol.RuleActionNoCache},
			{Order: 3, PathPrefix: "/v/", Action: cachecontrol.RuleActionCache, TTLSeconds: 60,
				CacheRuleExtras: edgeconfig.CacheRuleExtras{IgnoreQuery: true, SliceBytes: &slice, ForceCache: &force,
					NoCache: []edgeconfig.CacheNoCacheCondition{{Source: "header", Name: "cookie", Pattern: "sid="}}}},
		}}
	raw, err := compileCache(doc)
	if err != nil {
		t.Fatal(err)
	}
	cfg := siteconf.Config{Cache: raw}
	cache, err := cfg.DecodeCache()
	if err != nil || cache == nil {
		t.Fatalf("decode: %v", err)
	}
	if cache.Mode != "override" || cache.QueryMode != "include" || !slices.Equal(cache.QueryNames, []string{"v"}) ||
		!cache.StaleIfError || cache.MaxObjectBytes != 1<<20 || len(cache.Rules) != 3 ||
		cache.Rules[0].Extensions[0] != ".png" || cache.Rules[0].BrowserTTLSeconds != 60 ||
		cache.Rules[1].PathRegex != "^/api/" || cache.Rules[1].Action != "no_cache" ||
		!cache.Rules[2].IgnoreQuery || *cache.Rules[2].SliceBytes != slice || len(cache.Rules[2].NoCache) != 1 {
		t.Fatalf("cache = %+v", cache)
	}
}

// v1 rules (no action) are cache rules.
func TestCompileCacheV1RulesAreCache(t *testing.T) {
	doc := cachecontrol.PolicyDocument{SchemaVersion: cachecontrol.PolicySchemaV1, Mode: cachecontrol.PolicyOverride,
		QueryMode: cachecontrol.QueryPreserve, Rules: []cachecontrol.Rule{{Order: 1, PathPrefix: "/s/", TTLSeconds: 30}}}
	raw, err := compileCache(doc)
	if err != nil {
		t.Fatal(err)
	}
	var cache siteconf.Cache
	if err := json.Unmarshal(raw, &cache); err != nil || cache.Rules[0].Action != "cache" || cache.Rules[0].TTLSeconds != 30 {
		t.Fatalf("cache = %+v %v", cache, err)
	}
}

func aclPolicy(rules ...securitypolicy.Rule) securitypolicy.Policy {
	return securitypolicy.Policy{Kind: securitypolicy.KindACL, Enabled: true, DefaultAction: securitypolicy.ActionAllow, Rules: rules}
}

func cidrRule(action, cidr string, priority int) securitypolicy.Rule {
	return securitypolicy.Rule{Priority: priority, Enabled: true, Action: action, Flow: securitypolicy.FlowStop,
		Conditions: []securitypolicy.Condition{{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{cidr}}}}
}

// The local ACL lets every allow win over any block; the access list keeps
// that by listing allows first.
func TestCompileACLAllowsFirst(t *testing.T) {
	access, blocked := compileACL(aclPolicy(cidrRule("block", "198.51.100.0/24", 1), cidrRule("allow", "198.51.100.7/32", 2),
		securitypolicy.Rule{Enabled: false, Action: "block", Conditions: []securitypolicy.Condition{{Field: "client_ip",
			Operator: "ip_in_cidr", Values: []string{"203.0.113.0/24"}}}}))
	if blocked != "" || access == nil || access.Default != "allow" || len(access.Rules) != 2 ||
		access.Rules[0] != (siteconf.AccessRule{CIDR: "198.51.100.7/32", Action: "allow"}) ||
		access.Rules[1] != (siteconf.AccessRule{CIDR: "198.51.100.0/24", Action: "block"}) {
		t.Fatalf("access = %+v %q", access, blocked)
	}
	if access, blocked := compileACL(securitypolicy.Policy{Kind: securitypolicy.KindACL, Enabled: false}); access != nil || blocked != "" {
		t.Fatalf("disabled policy = %+v %q", access, blocked)
	}
}

func TestCompileOriginRoutes(t *testing.T) {
	doc := site.ConditionalOriginDocument{Schema: site.ConditionalOriginSchemaV1, DefaultPoolID: "default",
		Pools: []site.ConditionalOriginPool{{ID: "default", BalanceMethod: "round_robin",
			Endpoints: []site.ConditionalOriginEndpoint{{ID: "origin-00", Host: "203.0.113.10", Port: 8080, Weight: 3}}},
			{ID: "api", Endpoints: []site.ConditionalOriginEndpoint{{ID: "a", Host: "203.0.113.30", Port: 80, Weight: 1}}}},
		Routes: []site.ConditionalOriginRoute{{ID: "r1", Priority: 1, PathPrefix: "/api/", PoolID: "api"}},
		Retry:  site.ConditionalOriginRetry{Methods: []string{"GET", "HEAD"}, MaxAttempts: 1, ConnectTimeoutMS: 3000, ReadTimeoutMS: 30000, TotalBudgetMS: 33000}}
	routes, blocked := compileOriginRoutes(doc, nil)
	if blocked != "" || routes == nil || len(routes.Pools) != 2 || routes.Routes[0].PoolID != "api" || routes.Retry.MaxAttempts != 1 {
		t.Fatalf("routes = %+v %q", routes, blocked)
	}
	// Node regions are carried as their standard geography; a region
	// without a country (or not in the catalog) refuses.
	geos := map[string]regioncatalog.CodeGeo{
		"cn-south": {Code: "cn-south", CountryCode: "CN", ProvinceCode: "440000"},
		"us":       {Code: "us", CountryCode: "US"},
		"hk-dup":   {Code: "hk-dup", CountryCode: "US"},
		"bare":     {Code: "bare"},
	}
	doc.Routes[0].NodeRegions = []string{"us", "cn-south", "hk-dup"}
	routes, blocked = compileOriginRoutes(doc, geos)
	if want := []siteconf.NodeGeo{{Country: "CN", Province: "440000"}, {Country: "US"}}; blocked != "" ||
		!reflect.DeepEqual(routes.Routes[0].NodeGeos, want) {
		t.Fatalf("geos = %+v %q", routes, blocked)
	}
	for _, regions := range [][]string{{"bare"}, {"us", "gone"}} {
		doc.Routes[0].NodeRegions = regions
		if _, blocked := compileOriginRoutes(doc, geos); blocked != "node_region_geo" {
			t.Fatalf("%v = %q", regions, blocked)
		}
	}
	doc.Routes[0].NodeRegions, doc.IngressSourceEnabled = nil, true
	if _, blocked := compileOriginRoutes(doc, geos); blocked != "ingress_source" {
		t.Fatalf("ingress source = %q", blocked)
	}
}
