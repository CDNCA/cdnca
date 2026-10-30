package siteconf

import (
	"encoding/json"
	"reflect"
	"testing"
)

func withOptions() Config {
	c := sample()
	on, off := true, false
	c.OriginScheme, c.BalanceMethod, c.WebSocket = "https", "sticky", true
	c.Origins[0].MaxConns, c.Origins[1].Level = 50, 1
	c.ForceHTTPS, c.HTTPSRedirectPort = true, 443
	c.ClientAuth = &ClientAuth{Mode: "required", CAPEM: "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"}
	c.Forwarding = &Forwarding{
		RequestHost: "custom", RequestHostValue: "origin.example.net", HTTPPort: 80, HTTPSPort: 8443,
		TLSSNI: "origin.example.net", Sticky: &Sticky{Source: "cookie", Name: "uid"},
		FollowRedirect:    &FollowRedirect{MaxHops: 2, CrossOrigin: true},
		TrustedProxyCIDRs: []string{"198.51.100.0/24", "192.0.2.0/24"}, SearchEngineOrigin: "203.0.113.20",
		WebSocketOrigins:  []string{"https://b.example.com", "https://a.example.com"},
		ResponseBuffering: &off, RequestBuffering: &on, ACMEPassthrough: true,
	}
	c.OriginRoutes = &OriginRoutes{
		Pools: []RoutePool{
			{ID: "default", BalanceMethod: "round_robin", Endpoints: []RouteEndpoint{{ID: "origin-00", Host: "203.0.113.9", Port: 80, Weight: 1}}},
			{ID: "api", Endpoints: []RouteEndpoint{{ID: "a", Host: "203.0.113.30", Port: 8080, Weight: 2}}},
		},
		DefaultPoolID: "default",
		Routes:        []Route{{ID: "r1", Priority: 10, PathPrefix: "/api/", ClientCIDRs: []string{"192.0.2.0/24"}, PoolID: "api"}},
		Retry:         RouteRetry{Methods: []string{"GET", "HEAD"}, MaxAttempts: 2, ConnectTimeoutMS: 3000, ReadTimeoutMS: 30000, TotalBudgetMS: 33000},
	}
	return c
}

// Every option survives JSON (the relay) and normalizes to the same digest
// on both sides.
func TestSiteOptionsRoundTrip(t *testing.T) {
	c := withOptions()
	if err := c.Normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var back Config
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if err := back.Normalize(); err != nil {
		t.Fatalf("normalize again: %v", err)
	}
	if back.Digest() != c.Digest() || !reflect.DeepEqual(back, c) {
		t.Fatalf("round trip differs:\n%+v\n%+v", back, c)
	}
	f := back.Forwarding
	if f.TrustedProxyCIDRs[0] != "192.0.2.0/24" || f.WebSocketOrigins[0] != "https://a.example.com" ||
		back.Origins[0].MaxConns != 50 || back.Origins[1].Level != 1 || back.OriginRoutes.Pools[1].BalanceMethod != "round_robin" {
		t.Fatalf("not canonical: %+v %+v", f, back.Origins)
	}
}

// Node geographies are sorted and deduplicated.
func TestRouteNodeGeosCanonical(t *testing.T) {
	c := withOptions()
	c.OriginRoutes.Routes[0].NodeGeos = []NodeGeo{{Country: "US"}, {Country: "CN", Province: "440000"}, {Country: "US"}, {Country: "CN"}}
	if err := c.Normalize(); err != nil {
		t.Fatal(err)
	}
	want := []NodeGeo{{Country: "CN"}, {Country: "CN", Province: "440000"}, {Country: "US"}}
	if got := c.OriginRoutes.Routes[0].NodeGeos; !reflect.DeepEqual(got, want) {
		t.Fatalf("geos = %+v", got)
	}
}

// An all-default forwarding block is the same revision as none.
func TestEmptyForwardingIsNone(t *testing.T) {
	a, b := sample(), sample()
	b.Forwarding = &Forwarding{RequestHost: "visitor"}
	if err := a.Normalize(); err != nil {
		t.Fatal(err)
	}
	if err := b.Normalize(); err != nil {
		t.Fatal(err)
	}
	if b.Forwarding != nil || a.Digest() != b.Digest() {
		t.Fatalf("forwarding = %+v", b.Forwarding)
	}
}

func TestSiteOptionsRejects(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"balance":            func(c *Config) { c.BalanceMethod = "fastest" },
		"max conns":          func(c *Config) { c.Origins[0].MaxConns = -1 },
		"level":              func(c *Config) { c.Origins[0].Level = 16 },
		"force https no tls": func(c *Config) { c.HTTPSPorts = nil },
		"redirect port":      func(c *Config) { c.HTTPSRedirectPort = 8443 },
		"client auth mode":   func(c *Config) { c.ClientAuth.Mode = "off" },
		"client auth no ca":  func(c *Config) { c.ClientAuth.CAPEM = "" },
		"request host":       func(c *Config) { c.Forwarding.RequestHost = "cdn" },
		"https port":         func(c *Config) { c.Forwarding.HTTPSPort = 70000 },
		"hops":               func(c *Config) { c.Forwarding.FollowRedirect.MaxHops = 6 },
		"sticky source":      func(c *Config) { c.Forwarding.Sticky.Source = "ip" },
		"routes no pool":     func(c *Config) { c.OriginRoutes.Pools = nil },
		"routes too many":    func(c *Config) { c.OriginRoutes.Routes = make([]Route, 257) },
		"geo country case":   func(c *Config) { c.OriginRoutes.Routes[0].NodeGeos = []NodeGeo{{Country: "cn"}} },
		"geo province us":    func(c *Config) { c.OriginRoutes.Routes[0].NodeGeos = []NodeGeo{{Country: "US", Province: "440000"}} },
		"geo city":           func(c *Config) { c.OriginRoutes.Routes[0].NodeGeos = []NodeGeo{{Country: "CN", Province: "440300"}} },
		"geo too many":       func(c *Config) { c.OriginRoutes.Routes[0].NodeGeos = make([]NodeGeo, 33) },
	} {
		c := withOptions()
		mutate(&c)
		if err := c.Normalize(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Cache rule matches and per-rule settings, and the policy extensions,
// are part of the cache block.
func TestCacheExtrasRoundTrip(t *testing.T) {
	c := sample()
	force := true
	slice := int64(1 << 20)
	c.Cache = json.RawMessage(`{"mode":"override","stale_if_error":true,"max_object_bytes":1048576,"rules":[
		{"path_regex":"^/img/","content_types":["image/png"],"action":"cache","ttl_seconds":60,
		 "path_exact":"","ignore_query":true,"slice_bytes":1048576,"force_cache":true,"ignore_vary":true,
		 "no_cache":[{"source":"header","name":"cookie","pattern":"sid="}]}]}`)
	if err := c.Normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	cache, err := c.DecodeCache()
	if err != nil || cache == nil {
		t.Fatalf("decode: %v", err)
	}
	r := cache.Rules[0]
	if !cache.StaleIfError || cache.MaxObjectBytes != 1<<20 || r.PathRegex != "^/img/" || r.ContentTypes[0] != "image/png" ||
		!r.IgnoreQuery || r.SliceBytes == nil || *r.SliceBytes != slice || r.ForceCache == nil || *r.ForceCache != force ||
		!r.IgnoreVary || len(r.NoCache) != 1 || r.NoCache[0].Name != "cookie" || !r.UsesMatch() {
		t.Fatalf("cache = %+v rule = %+v", cache, r)
	}
}
