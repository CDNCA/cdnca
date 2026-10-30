package marketsupply

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/services/control-api/internal/regioncatalog"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
)

func optionsConfig() siteconf.Config {
	off := false
	return siteconf.Config{Schema: siteconf.SchemaV1, Domains: []string{"www.example.test"},
		HTTPPorts: []int{80}, HTTPSPorts: []int{443}, OriginScheme: "https", BalanceMethod: "sticky",
		WebSocket: true, HTTP3: true, ForceHTTPS: true, HTTPSRedirectPort: 443,
		ClientAuth: &siteconf.ClientAuth{Mode: "required", CAPEM: "ca"},
		Origins: []siteconf.Origin{{Host: "203.0.113.9", Port: 8443, Weight: 2, MaxConns: 30},
			{Host: "203.0.113.10", Port: 443, Weight: 1, Level: 1}},
		Forwarding: &siteconf.Forwarding{RequestHost: "custom", RequestHostValue: "origin.example.test", HTTPSPort: 8443,
			TLSSNI: "origin.example.test", TLSCAPEM: "pem", Sticky: &siteconf.Sticky{Source: "cookie", Name: "uid"},
			FollowRedirect: &siteconf.FollowRedirect{MaxHops: 2}, TrustedProxyCIDRs: []string{"192.0.2.0/24"},
			SearchEngineOrigin: "203.0.113.20", WebSocketOrigins: []string{"https://a.example.test"},
			ResponseBuffering: &off, ACMEPassthrough: true, KeepaliveDisabled: true, FailbackManual: true,
			HealthCheckPath: "/healthz"},
	}
}

// The leaf writes every option the subscriber's site sets onto its own
// site: none is dropped on the way.
func TestSiteFieldsCarrySiteOptions(t *testing.T) {
	cfg := optionsConfig()
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	fields, pool := siteFields(cfg, true)
	if fields.ForceHTTPS == nil || !*fields.ForceHTTPS || *fields.HTTPSRedirectPort != 443 ||
		*fields.TLSClientAuth != "required" || *fields.TLSClientCAPEM != "ca" || !*fields.HTTP3Enabled {
		t.Fatalf("fields = %+v", fields)
	}
	// Backup levels ride on the pool's origins (site create pairs pool and
	// basic origins by index, so BackupOrigins is not used).
	if !slices.Equal(fields.Origins, []string{"203.0.113.10:443", "203.0.113.9:8443"}) || len(pool.Origins) != 2 ||
		pool.Origins[0].Level != 1 || pool.Origins[1].MaxConns != 30 || pool.Origins[1].Level != 0 || pool.BackupOrigins != nil {
		t.Fatalf("origins = %v pool = %+v", fields.Origins, pool.Origins)
	}
	if pool.Scheme != site.OriginSchemeHTTPS || pool.BalanceMethod != site.BalanceSticky ||
		pool.Sticky == nil || pool.Sticky.Name != "uid" || pool.RequestHost.Mode != site.OriginRequestHostCustom ||
		pool.RequestHost.Value != "origin.example.test" || pool.HTTPSPort != 8443 || pool.HTTPPort != 0 ||
		pool.TLS.Trust != site.OriginTrustCustom || pool.TLS.CAPEM != "pem" || pool.TLS.SNI != "origin.example.test" ||
		pool.FollowRedirect == nil || !pool.FollowRedirect.Enabled || pool.FollowRedirect.MaxHops != 2 ||
		!slices.Equal(pool.TrustedProxyCIDRs, []string{"192.0.2.0/24"}) || pool.SearchEngineOrigin != "203.0.113.20" ||
		pool.WebSocket == nil || !pool.WebSocket.Enabled || !slices.Equal(pool.WebSocket.AllowedOrigins, []string{"https://a.example.test"}) ||
		pool.ResponseBuffering == nil || *pool.ResponseBuffering || pool.RequestBuffering != nil || !pool.ACMEPassthrough ||
		pool.KeepaliveEnabled == nil || *pool.KeepaliveEnabled || pool.FailbackMode != site.FailbackManual ||
		pool.HealthCheckPath != "/healthz" {
		t.Fatalf("pool = %+v", pool)
	}
	// Without SITE_QUIC on the supply's nodes the site serves HTTP/2 only.
	if fields, _ = siteFields(cfg, false); *fields.HTTP3Enabled {
		t.Fatal("http3 without SITE_QUIC")
	}
}

func TestSiteFieldsDefaults(t *testing.T) {
	cfg := siteconf.Config{Schema: siteconf.SchemaV1, Domains: []string{"a.example.test"}, HTTPPorts: []int{80},
		Origins: []siteconf.Origin{{Host: "203.0.113.9", Port: 80}}}
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	fields, pool := siteFields(cfg, true)
	if *fields.ForceHTTPS || *fields.TLSClientAuth != "off" || *fields.HTTP3Enabled || pool.WebSocket == nil ||
		pool.WebSocket.Enabled || pool.RequestHost.Mode != site.OriginRequestHostVisitor || pool.TLS.Trust != site.OriginTrustSystem ||
		*pool.KeepaliveEnabled != true || pool.FailbackMode != site.FailbackAuto || pool.BackupOrigins != nil {
		t.Fatalf("fields = %+v pool = %+v", fields, pool)
	}
}

// WebSocket, HTTPS / follow origins, backup levels and the other site
// options no longer refuse the revision.
func TestProtocolOptionsAreNotBlockers(t *testing.T) {
	cfg := optionsConfig()
	cfg.OriginScheme = "follow"
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	for _, b := range protocolBlockers(cfg, nil) {
		t.Errorf("blocker %+v", b)
	}
}

func TestOriginRouteDocumentMapsSiteconf(t *testing.T) {
	cfg := optionsConfig()
	cfg.OriginRoutes = &siteconf.OriginRoutes{
		Pools: []siteconf.RoutePool{{ID: "default", Endpoints: []siteconf.RouteEndpoint{{ID: "o1", Host: "203.0.113.9", Port: 8443, Weight: 2}}},
			{ID: "api", BalanceMethod: "ip_hash", Endpoints: []siteconf.RouteEndpoint{{ID: "a", Host: "203.0.113.30", Port: 8080, Weight: 1}}}},
		DefaultPoolID: "default",
		Routes:        []siteconf.Route{{ID: "r1", Priority: 5, PathPrefix: "/api/", Hosts: []string{"www.example.test"}, PoolID: "api"}},
		Retry:         siteconf.RouteRetry{Methods: []string{"GET"}, MaxAttempts: 1, ConnectTimeoutMS: 3000, ReadTimeoutMS: 30000, TotalBudgetMS: 33000},
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	doc, unmatched, err := originRouteDocument(cfg.OriginRoutes, nil)
	if err != nil || len(unmatched) > 0 {
		t.Fatalf("document: %v", err)
	}
	if len(doc.Pools) != 2 || doc.Pools[0].ID != "api" || doc.Pools[0].BalanceMethod != "ip_hash" || len(doc.Routes) != 1 ||
		doc.Routes[0].PathPrefix != "/api/" || doc.Routes[0].PoolID != "api" || doc.Retry.MaxAttempts != 1 {
		t.Fatalf("document = %+v", doc)
	}
	raw, _ := json.Marshal(doc)
	if len(raw) == 0 {
		t.Fatal("empty")
	}
	// A route the local model refuses (no condition) is invalid, not dropped.
	cfg.OriginRoutes.Routes[0].PathPrefix, cfg.OriginRoutes.Routes[0].Hosts = "", nil
	if _, _, err := originRouteDocument(cfg.OriginRoutes, nil); err == nil {
		t.Fatal("route without condition accepted")
	}
}

// Node geographies map onto the leaf's own regions with that geography: a
// country matches every region in it, a province only regions with that
// province; a route no leaf region matches never applies on the leaf and is
// left out, reported as unmatched.
func TestOriginRouteDocumentMapsNodeGeos(t *testing.T) {
	cfg := optionsConfig()
	cfg.OriginRoutes = &siteconf.OriginRoutes{
		Pools:         []siteconf.RoutePool{{ID: "default", Endpoints: []siteconf.RouteEndpoint{{ID: "o1", Host: "203.0.113.9", Port: 80, Weight: 1}}}},
		DefaultPoolID: "default",
		Routes: []siteconf.Route{
			{ID: "cn", Priority: 1, NodeGeos: []siteconf.NodeGeo{{Country: "CN"}}, PoolID: "default"},
			{ID: "gd", Priority: 2, PathPrefix: "/a/", NodeGeos: []siteconf.NodeGeo{{Country: "CN", Province: "440000"}}, PoolID: "default"},
			{ID: "us", Priority: 3, NodeGeos: []siteconf.NodeGeo{{Country: "US"}}, PoolID: "default"},
		},
		Retry: siteconf.RouteRetry{Methods: []string{"GET"}, MaxAttempts: 1, ConnectTimeoutMS: 3000, ReadTimeoutMS: 30000, TotalBudgetMS: 33000},
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	leaf := map[string]regioncatalog.CodeGeo{
		"south": {Code: "south", CountryCode: "CN", ProvinceCode: "440000"},
		"north": {Code: "north", CountryCode: "CN", ProvinceCode: "110000"},
		"cn":    {Code: "cn", CountryCode: "CN"},
		"bare":  {Code: "bare"},
	}
	doc, unmatched, err := originRouteDocument(cfg.OriginRoutes, leaf)
	if err != nil {
		t.Fatal(err)
	}
	regions := map[string][]string{}
	for _, r := range doc.Routes {
		regions[r.ID] = r.NodeRegions
	}
	if !slices.Equal(regions["cn"], []string{"cn", "north", "south"}) || !slices.Equal(regions["gd"], []string{"south"}) ||
		len(doc.Routes) != 2 || !slices.Equal(unmatched, []string{"us"}) {
		t.Fatalf("routes = %+v unmatched = %v", doc.Routes, unmatched)
	}
	if b := originRouteAdvisory(cfg, leaf); len(b) != 1 || b[0].Code != BlockerOriginRouteGeoUnmatched || b[0].Detail != "us" {
		t.Fatalf("blockers = %+v", b)
	}
}

func TestCacheDocumentCarriesMatchesAndExtensions(t *testing.T) {
	cfg := optionsConfig()
	cfg.Cache = json.RawMessage(`{"mode":"override","stale_if_error":true,"rules":[
		{"path_regex":"^/img/","content_types":["image/png"],"action":"cache","ttl_seconds":60,"browser_ttl_seconds":0,
		 "ignore_query":true,"no_cache":[{"source":"header","name":"cookie","pattern":"sid="}]}]}`)
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	cache, err := cfg.DecodeCache()
	if err != nil {
		t.Fatal(err)
	}
	doc, err := cacheDocument(cache)
	if err != nil {
		t.Fatalf("document: %v", err)
	}
	r := doc.Rules[0]
	if !doc.Extensions.StaleIfError || r.PathRegex != "^/img/" || !slices.Equal(r.ContentTypes, []string{"image/png"}) ||
		!r.IgnoreQuery || len(r.NoCache) != 1 || r.NoCache[0].Name != "cookie" {
		t.Fatalf("document = %+v rule = %+v", doc, r)
	}
}

// The production site writer also writes conditional origins (applyOriginRoutes).
var _ ConditionalOrigins = (*site.Service)(nil)
