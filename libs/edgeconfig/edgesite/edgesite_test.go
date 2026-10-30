package edgesite

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
)

const (
	testScope  = "018f47a2-5b9c-7d31-8a60-104c9c0b7101"
	testTenant = "018f47a2-5b9c-7d31-8a60-104c9c0b7d01"
	testSite   = "018f47a2-5b9c-7d31-8a60-104c9c0b7103"
	testNode   = "018f47a2-5b9c-7d31-8a60-104c9c0b7105"
	testUUID   = "11111111-1111-4111-8111-111111111111"
	testUUID2  = "22222222-2222-4222-8222-222222222222"
)

var digestA, digestB = strings.Repeat("a", 64), strings.Repeat("b", 64)

// testStyleHash is a well-formed errorpagestyle.SourceHash.
const testStyleHash = "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="

func int64Pointer(value int64) *int64 { return &value }

// fullSite has every optional part present.
func fullSite(t *testing.T) Site {
	t.Helper()
	site := Site{
		Schema: Schema, ConfigurationScopeID: testScope, TenantID: testTenant, SiteID: testSite, Revision: 7,
		Hosts: Hosts{Primary: "cdn.example.test", Aliases: []string{"*.img.example.test", "www.example.test"}},
		Listeners: []Listener{
			{Port: 80, AddressFamily: FamilyDualStack},
			{Port: 443, AddressFamily: FamilyDualStack, HTTP2: true, HTTP3: true,
				TLS: &TLS{CertificateVersionID: testUUID, Protocols: []string{"TLSv1.2", "TLSv1.3"}}},
		},
		ForceHTTPS: &ForceHTTPS{RedirectPort: 443},
		HSTS:       &HSTS{MaxAgeSeconds: HSTSPreloadMinAge, IncludeSubdomains: true, Preload: true},
		WebSocket:  true, Range: true,
		Origin: Origin{
			DefaultPoolID: "l2-topology", DefaultFallbackPoolID: "primary",
			Pools: []Pool{
				{ID: "l2-topology", Kind: PoolL2, Algorithm: "round_robin",
					Endpoints: []Endpoint{{ID: testUUID2, Scheme: "http", Host: "2001:db8::10", Port: 8080, Weight: 100,
						NodeID: testNode, MTLSIdentitySHA256: "sha256:" + digestA, TopologyRevision: 3}},
					Retry: Retry{Methods: []string{"GET", "HEAD"}, MaxAttempts: 3, ConnectTimeoutMS: 3000, ReadTimeoutMS: 30000, TotalBudgetMS: 60000}},
				{ID: "primary", Kind: PoolOrigin, Algorithm: "least_conn", KeepaliveIdleTimeoutMS: int64Pointer(60000),
					Endpoints: []Endpoint{
						{ID: "origin-0", Scheme: "https", Host: "192.0.2.10", Port: 443, Weight: 100, SNI: "origin.example.test", TrustAnchor: "sha256:" + digestB},
						{ID: "origin-1", Scheme: "http", Host: "origin2.example.test", Port: 80, Weight: 50},
					},
					Retry: Retry{Methods: []string{"GET", "HEAD"}, MaxAttempts: 3, ConnectTimeoutMS: 3000, ReadTimeoutMS: 30000, TotalBudgetMS: 60000}},
			},
			Routes: []Route{{ID: "api", Priority: 10, PathPrefix: "/api", ClientCIDRs: []string{"198.51.100.0/24"},
				NodeRegions: []string{"cn-east"}, PoolID: "primary"}},
			L2:            &L2{DirectFallbackPoolID: "primary", ProbeIntervalMS: 10000, FailureThreshold: 3, RecoveryThreshold: 3},
			IngressSource: true,
			Auth: []OriginAuth{{PoolID: "primary", Endpoint: "https://bucket.cos.example.test",
				Secret: Ref{Kind: RefOriginAuthSecret, ID: testUUID, Revision: 2}}},
		},
		Cache: &Cache{Domain: "cdn.example.test", KeyByHost: true, Policy: edgeconfig.CachePolicyDocument{
			Revision: 4, Mode: edgeconfig.CacheOverride, QueryMode: edgeconfig.CacheQueryPreserve, DiskQuotaBytes: 128 << 20,
			Rules:      []edgeconfig.CacheRuleDocument{{Order: 1, Extensions: []string{".css", ".js"}, TTLSeconds: 3600}},
			QueryNames: []string{}, VaryHeaders: []string{},
		}},
		Security: Security{
			Rules: RulePlan{HeaderOverflow: HeaderOverflowNoMatch, Policies: []RulePolicy{{
				Kind: edgeconfig.SecurityACL, PolicyID: testUUID, PolicyVersion: 2, BindingRevision: 1, RuntimeSHA256: digestA,
				Enabled: true, DefaultAction: edgeconfig.WAFAllow,
				Rules: []edgeconfig.WAFRule{{RuleID: testUUID2, Match: edgeconfig.WAFMatch{Port: 443, SourceCIDR: "203.0.113.0/24"},
					Action: edgeconfig.WAFBlock, Control: edgeconfig.WAFStop}},
			}}},
			CC: []CCBinding{{Ports: []int{80, 443}, Policy: Ref{Kind: RefCCPolicy, ID: testUUID, Revision: 3, SHA256: digestA}, SourceSHA256: digestB}},
			ManagedWAF: &ManagedWAF{
				PolicyID: testUUID2, PolicyVersion: 3,
				Profile: ManagedWAFProfile{RequestBodyLimit: 1 << 20, RequestBodyNoFilesLimit: 128 << 10, RequestBodyLimitAction: "reject",
					ArgumentsLimit: 1000, JSONDepthLimit: 512, PCREMatchLimit: 100000, InspectionLimitAction: "log"},
				CRSProfile: edgeconfig.CRSProfileRef{PackID: "system/crs-pl1", Version: "1.0.0", SHA256: digestA},
				Exclusions: []int{941100, 942100},
				AllowCIDRs: []string{"192.0.2.0/24"},
			},
			Challenge:      &Ref{Kind: RefChallenge, ID: testUUID, Revision: 5},
			FirewallAction: &Ref{Kind: RefFirewallAction, ID: testUUID2, Revision: 7, SHA256: digestB},
		},
		HTTP: &Ref{Kind: RefHTTPPolicy, ID: testUUID, Revision: 3, SHA256: digestA},
		Errors: []ErrorPage{
			{Category: ErrorEdgeConnect, Status: 502, RuleID: testUUID, MIMEType: "text/html", StyleHash: testStyleHash,
				Asset: Ref{Kind: RefErrorPageAsset, ID: testUUID, Revision: 1, SHA256: digestA}},
			{Category: ErrorOriginResponse, Status: 404, RuleID: testUUID2, MIMEType: "text/html",
				Asset: Ref{Kind: RefErrorPageAsset, ID: testUUID2, Revision: 1, SHA256: digestB}},
		},
		Limits: Limits{MaxBodyBytes: 64 << 20, Connections: &Connections{SubscriptionID: testUUID, Max: 200}},
		Telemetry: &Telemetry{PackageSubscriptionID: testUUID, Capture: siteobject.TelemetryCapture{
			Enabled: true, Methods: []string{"GET"}, URIPrefixes: []string{"/api/"},
			RequestHeaderAllowlist: []string{}, ResponseHeaderAllowlist: []string{},
			RequestBodyFieldAllowlist: []string{}, ResponseBodyFieldAllowlist: []string{},
			MaxValueBytes: 4096, MaxBodyBytes: 64 << 10, MaxEventBytes: 1 << 20,
		}},
	}
	site.Cache.KeyPrefix = CacheKeyPrefix(site.TenantID, site.SiteID)
	token, err := CacheGeneration(*site.Cache)
	if err != nil {
		t.Fatal(err)
	}
	site.Cache.Generation = token
	return site
}

// minimalSite has only what every site carries.
func minimalSite() Site {
	return Site{
		Schema: Schema, ConfigurationScopeID: testScope, TenantID: testTenant, SiteID: testSite, Revision: 1,
		Hosts:     Hosts{Primary: "plain.example.test", Aliases: []string{}},
		Listeners: []Listener{{Port: 80, AddressFamily: FamilyIPv4}},
		Origin: Origin{DefaultPoolID: "primary", Routes: []Route{}, Auth: []OriginAuth{},
			Pools: []Pool{{ID: "primary", Kind: PoolOrigin, Algorithm: "round_robin",
				Endpoints: []Endpoint{{ID: "origin-0", Scheme: "http", Host: "192.0.2.1", Port: 80, Weight: 1}},
				Retry:     Retry{Methods: []string{"GET", "HEAD"}, MaxAttempts: 1, ConnectTimeoutMS: 10, ReadTimeoutMS: 10, TotalBudgetMS: 10}}}},
		Security: Security{Rules: RulePlan{HeaderOverflow: HeaderOverflowNoMatch, Policies: []RulePolicy{}}, CC: []CCBinding{}},
		Errors:   []ErrorPage{},
		Limits:   Limits{MaxBodyBytes: 0},
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	for name, site := range map[string]Site{"full": fullSite(t), "minimal": minimalSite()} {
		t.Run(name, func(t *testing.T) {
			raw, err := Encode(site)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := Decode(raw)
			if err != nil {
				t.Fatal(err)
			}
			again, err := Encode(decoded)
			if err != nil || !bytes.Equal(again, raw) {
				t.Fatalf("round trip changed the encoding: %v", err)
			}
			if !strings.HasPrefix(string(raw), `{"schema":"cdnca.edge.site/v2",`) || bytes.HasSuffix(raw, []byte("\n")) {
				t.Fatalf("unexpected encoding head/tail: %.60s", raw)
			}
			t.Logf("%s: %d bytes, digest %s", name, len(raw), Digest(raw))
		})
	}
}

// Same site, same bytes, same digest; any field change changes the digest.
func TestDigestIsDeterministic(t *testing.T) {
	first, err := Encode(fullSite(t))
	if err != nil {
		t.Fatal(err)
	}
	for range 20 {
		again, err := Encode(fullSite(t))
		if err != nil || Digest(again) != Digest(first) {
			t.Fatal("digest differs for the same site")
		}
	}
	changed := fullSite(t)
	changed.Revision++
	raw, err := Encode(changed)
	if err != nil || Digest(raw) == Digest(first) {
		t.Fatal("digest did not change with the revision")
	}
	// HTML-sensitive characters are not escaped (object encoding of v1).
	html := fullSite(t)
	html.Telemetry.Capture.URIPrefixes = []string{"/a&b"}
	raw, err = Encode(html)
	if err != nil || !bytes.Contains(raw, []byte(`"/a&b"`)) {
		t.Fatalf("HTML escaping in the encoding: %v", err)
	}
}

func TestDecodeRejectsOtherEncodings(t *testing.T) {
	raw, err := Encode(minimalSite())
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	cases := map[string]string{
		"unknown top field":    strings.Replace(text, `"revision":1,`, `"revision":1,"extra":1,`, 1),
		"unknown nested field": strings.Replace(text, `"aliases":[]`, `"aliases":[],"wildcard":true`, 1),
		"trailing newline":     text + "\n",
		"trailing value":       text + "{}",
		"whitespace":           strings.Replace(text, `,"tenant_id"`, `, "tenant_id"`, 1),
		"field order":          strings.Replace(text, `"websocket":false,"range":false`, `"range":false,"websocket":false`, 1),
		"null list":            strings.Replace(text, `"aliases":[]`, `"aliases":null`, 1),
		"schema v1":            strings.Replace(text, Schema, "cdnca.edge.site/v1", 1),
		"empty":                "",
		"too large":            text + strings.Repeat(" ", MaxObjectBytes),
	}
	for name, input := range cases {
		if input == text {
			t.Fatalf("%s: the case does not change the input", name)
		}
		if _, err := Decode([]byte(input)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: decoded (%v)", name, err)
		}
	}
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]func(*Site){
		"schema":            func(s *Site) { s.Schema = "cdnca.edge.site/v1" },
		"site id":           func(s *Site) { s.SiteID = "not-a-uuid" },
		"upper case uuid":   func(s *Site) { s.TenantID = strings.ToUpper(testTenant) },
		"revision 0":        func(s *Site) { s.Revision = 0 },
		"revision unsafe":   func(s *Site) { s.Revision = MaxSafeInteger + 1 },
		"upper case name":   func(s *Site) { s.Hosts.Primary = "CDN.example.test" },
		"bare wildcard":     func(s *Site) { s.Hosts.Primary = "*" },
		"inner wildcard":    func(s *Site) { s.Hosts.Aliases = []string{"a.*.example.test"} },
		"unsorted aliases":  func(s *Site) { s.Hosts.Aliases = []string{"www.example.test", "*.img.example.test"} },
		"alias is primary":  func(s *Site) { s.Hosts.Aliases = []string{"cdn.example.test"} },
		"too many names":    func(s *Site) { s.Hosts.Aliases = manyNames(MaxNames) },
		"no listeners":      func(s *Site) { s.Listeners = []Listener{} },
		"duplicate port":    func(s *Site) { s.Listeners[1].Port = 80 },
		"unsorted ports":    func(s *Site) { s.Listeners[0], s.Listeners[1] = s.Listeners[1], s.Listeners[0] },
		"port 0":            func(s *Site) { s.Listeners[0].Port = 0 },
		"port 65536":        func(s *Site) { s.Listeners[1].Port = 65536 },
		"family":            func(s *Site) { s.Listeners[0].AddressFamily = "ipv5" },
		"h2 without tls":    func(s *Site) { s.Listeners[0].HTTP2 = true },
		"h3 without tls":    func(s *Site) { s.Listeners[0].HTTP3 = true },
		"h3 with tls 1.2":   func(s *Site) { s.Listeners[1].TLS.Protocols = []string{"TLSv1.2"} },
		"tls 1.1":           func(s *Site) { s.Listeners[1].TLS.Protocols = []string{"TLSv1.1", "TLSv1.3"} },
		"no tls protocols":  func(s *Site) { s.Listeners[1].TLS.Protocols = []string{} },
		"force https plain": func(s *Site) { s.ForceHTTPS.RedirectPort = 80 },
		"no pools":          func(s *Site) { s.Origin.Pools = []Pool{} },
		"unsorted pools":    func(s *Site) { s.Origin.Pools[0], s.Origin.Pools[1] = s.Origin.Pools[1], s.Origin.Pools[0] },
		"default pool":      func(s *Site) { s.Origin.DefaultPoolID = "missing" },
		"l2 default no l2":  func(s *Site) { s.Origin.L2 = nil },
		"l2 fallback is l2": func(s *Site) { s.Origin.L2.DirectFallbackPoolID = "l2-topology" },
		"l2 probe":          func(s *Site) { s.Origin.L2.ProbeIntervalMS = 99 },
		"algorithm":         func(s *Site) { s.Origin.Pools[1].Algorithm = "fastest" },
		"retry attempts":    func(s *Site) { s.Origin.Pools[1].Retry.MaxAttempts = 9 },
		"retry method":      func(s *Site) { s.Origin.Pools[1].Retry.Methods = []string{"POST"} },
		"keepalive":         func(s *Site) { s.Origin.Pools[1].KeepaliveIdleTimeoutMS = int64Pointer(500) },
		"keepalive on l2":   func(s *Site) { s.Origin.Pools[0].KeepaliveIdleTimeoutMS = int64Pointer(60000) },
		"https no anchor":   func(s *Site) { s.Origin.Pools[1].Endpoints[0].TrustAnchor = "" },
		"https bad sni":     func(s *Site) { s.Origin.Pools[1].Endpoints[0].SNI = "*.x.test" },
		"sni mode unknown":  func(s *Site) { s.Origin.Pools[1].Endpoints[0].SNIMode = "fixed" },
		"custom sni empty": func(s *Site) {
			s.Origin.Pools[1].Endpoints[0].SNIMode, s.Origin.Pools[1].Endpoints[0].SNI = SNICustom, ""
		},
		"visitor sni with sni": func(s *Site) { s.Origin.Pools[1].Endpoints[0].SNIMode = SNIVisitorHost },
		"origin sni with sni":  func(s *Site) { s.Origin.Pools[1].Endpoints[0].SNIMode = SNIOriginHost },
		"http sni mode":        func(s *Site) { s.Origin.Pools[1].Endpoints[1].SNIMode = SNIVisitorHost },
		"hash no key":          func(s *Site) { s.Origin.Pools[1].Algorithm = "hash" },
		"hash bad key":         func(s *Site) { s.Origin.Pools[1].Algorithm, s.Origin.Pools[1].HashKey = "hash", "$request_body" },
		"key without hash":     func(s *Site) { s.Origin.Pools[1].HashKey = "$uri" },
		"sticky no settings":   func(s *Site) { s.Origin.Pools[1].Algorithm = "sticky" },
		"sticky bad source": func(s *Site) {
			s.Origin.Pools[1].Algorithm, s.Origin.Pools[1].Sticky = "sticky", &Sticky{Source: "body", Name: "r"}
		},
		"request host mode":  func(s *Site) { s.Origin.Pools[1].RequestHost = &RequestHost{Mode: "visitor"} },
		"request host value": func(s *Site) { s.Origin.Pools[1].RequestHost = &RequestHost{Mode: RequestHostCustom, Value: "a b"} },
		"origin host value": func(s *Site) {
			s.Origin.Pools[1].RequestHost = &RequestHost{Mode: RequestHostOrigin, Value: "x.test"}
		},
		"l2 request host": func(s *Site) { s.Origin.Pools[0].RequestHost = &RequestHost{Mode: RequestHostCustom, Value: "x.test"} },
		"follow + origin": func(s *Site) {
			s.Origin.Pools[1].FollowPort, s.Origin.Pools[1].RequestHost = true, &RequestHost{Mode: RequestHostOrigin}
		},
		"only backups": func(s *Site) {
			s.Origin.Pools[1].Endpoints[0].Level, s.Origin.Pools[1].Endpoints[1].Level = 1, 2
		},
		"level out of range": func(s *Site) { s.Origin.Pools[1].Endpoints[1].Level = MaxLevel + 1 },
		"active level range": func(s *Site) { s.Origin.Pools[1].ActiveLevel = MaxLevel + 1 },
		"max conns":          func(s *Site) { s.Origin.Pools[1].Endpoints[1].MaxConns = MaxEndpointConns + 1 },
		"trusted /0":         func(s *Site) { s.Origin.TrustedProxyCIDRs = []string{"0.0.0.0/0"} },
		"trusted unmasked":   func(s *Site) { s.Origin.TrustedProxyCIDRs = []string{"10.0.0.1/8"} },
		"trusted order":      func(s *Site) { s.Origin.TrustedProxyCIDRs = []string{"10.0.0.0/8", "10.0.0.0/8"} },
		"ws origins off":     func(s *Site) { s.WebSocket, s.WebSocketOrigins = false, []string{"https://a.test"} },
		"ws origin form":     func(s *Site) { s.WebSocketOrigins = []string{"a.test"} },
		"https pool plain":   func(s *Site) { s.Origin.HTTPSPoolID = "primary" },
		"route host":         func(s *Site) { s.Origin.Routes[0].Hosts = []string{"Bad Host"} },
		"http with anchor":   func(s *Site) { s.Origin.Pools[1].Endpoints[1].TrustAnchor = "sha256:" + digestA },
		"l2 no identity":     func(s *Site) { s.Origin.Pools[0].Endpoints[0].MTLSIdentitySHA256 = "" },
		"origin with node":   func(s *Site) { s.Origin.Pools[1].Endpoints[1].NodeID = testNode },
		"weight 0":           func(s *Site) { s.Origin.Pools[1].Endpoints[1].Weight = 0 },
		"weight 101":         func(s *Site) { s.Origin.Pools[1].Endpoints[1].Weight = 101 },
		"duplicate endpoint": func(s *Site) { s.Origin.Pools[1].Endpoints[1].ID = "origin-0" },
		"mapped address":     func(s *Site) { s.Origin.Pools[1].Endpoints[0].Host = "::ffff:192.0.2.1" },
		"route pool":         func(s *Site) { s.Origin.Routes[0].PoolID = "missing" },
		"route no condition": func(s *Site) { s.Origin.Routes[0] = Route{ID: "x", PoolID: "primary"} },
		"route path":         func(s *Site) { s.Origin.Routes[0].PathPrefix = "/a/../b" },
		"route path //":      func(s *Site) { s.Origin.Routes[0].PathPrefix = "/a//b" },
		"route cidr":         func(s *Site) { s.Origin.Routes[0].ClientCIDRs = []string{"198.51.100.1/24"} },
		"route priority":     func(s *Site) { s.Origin.Routes[0].Priority = 1001 },
		"auth pool":          func(s *Site) { s.Origin.Auth[0].PoolID = "l2-topology" },
		"auth endpoint":      func(s *Site) { s.Origin.Auth[0].Endpoint = "http://bucket.example.test" },
		"auth secret kind":   func(s *Site) { s.Origin.Auth[0].Secret.Kind = RefCCPolicy },
		"cache prefix":       func(s *Site) { s.Cache.KeyPrefix = strings.Repeat("0", 32) },
		"cache token":        func(s *Site) { s.Cache.Policy.Rules[0].TTLSeconds++ },
		"cache domain":       func(s *Site) { s.Cache.Domain = "other.example.test" },
		"cache null list":    func(s *Site) { s.Cache.Policy.QueryNames = nil },
		"cache policy":       func(s *Site) { s.Cache.Policy.DiskQuotaBytes = 1; refreshToken(s) },
		"rule plan overflow": func(s *Site) { s.Security.Rules.HeaderOverflow = "drop" },
		"two acl policies": func(s *Site) {
			s.Security.Rules.Policies = append(s.Security.Rules.Policies, s.Security.Rules.Policies[0])
		},
		"policy default log":  func(s *Site) { s.Security.Rules.Policies[0].DefaultAction = edgeconfig.WAFLog },
		"rule id":             func(s *Site) { s.Security.Rules.Policies[0].Rules[0].RuleID = "r1" },
		"rule cidr":           func(s *Site) { s.Security.Rules.Policies[0].Rules[0].Match.SourceCIDR = "203.0.113.1/24" },
		"rule port":           func(s *Site) { s.Security.Rules.Policies[0].Rules[0].Match.Port = 8443 },
		"rule action":         func(s *Site) { s.Security.Rules.Policies[0].Rules[0].Action = "drop" },
		"cc port":             func(s *Site) { s.Security.CC[0].Ports = []int{8080} },
		"cc ports unsorted":   func(s *Site) { s.Security.CC[0].Ports = []int{443, 80} },
		"cc port twice":       func(s *Site) { s.Security.CC = append(s.Security.CC, s.Security.CC[0]) },
		"cc no digest":        func(s *Site) { s.Security.CC[0].Policy.SHA256 = "" },
		"challenge kind":      func(s *Site) { s.Security.Challenge.Kind = RefHTTPPolicy },
		"firewall digest":     func(s *Site) { s.Security.FirewallAction.SHA256 = "" },
		"waf not normalized":  func(s *Site) { s.Security.ManagedWAF.AllowCIDRs = []string{"192.0.2.1/24"} },
		"waf exclusion order": func(s *Site) { ids := s.Security.ManagedWAF.Exclusions; ids[0], ids[1] = ids[1], ids[0] },
		"waf profile ref":     func(s *Site) { s.Security.ManagedWAF.CRSProfile.SHA256 = "x" },
		"waf body":            func(s *Site) { s.Security.ManagedWAF.Profile.RequestBodyLimit = 10 },
		"waf null exclusions": func(s *Site) { s.Security.ManagedWAF.Exclusions = nil },
		"http policy digest":  func(s *Site) { s.HTTP.SHA256 = "x" },
		"error page order":    func(s *Site) { s.Errors[0], s.Errors[1] = s.Errors[1], s.Errors[0] },
		"error page status":   func(s *Site) { s.Errors[0].Status = 302 },
		"error page category": func(s *Site) { s.Errors[0].Category = "no_host" },
		"error page mime":     func(s *Site) { s.Errors[0].MIMEType = "text/html\r\nx: y" },
		"error page charset":  func(s *Site) { s.Errors[0].MIMEType = "text/html; charset=utf-8" },
		"error page connect":  func(s *Site) { s.Errors[0].Status = 500 },
		"error page rule id":  func(s *Site) { s.Errors[0].RuleID = "" },
		"error page style":    func(s *Site) { s.Errors[0].StyleHash = "sha256-x" },
		"style on text":       func(s *Site) { s.Errors[1].MIMEType, s.Errors[1].StyleHash = "text/plain", testStyleHash },
		"error page asset":    func(s *Site) { s.Errors[0].Asset.SHA256 = "" },
		"hsts negative":       func(s *Site) { s.HSTS.MaxAgeSeconds = -1 },
		"hsts too long":       func(s *Site) { s.HSTS.MaxAgeSeconds = MaxHSTSMaxAge + 1 },
		"hsts preload short":  func(s *Site) { s.HSTS.MaxAgeSeconds = HSTSPreloadMinAge - 1 },
		"hsts preload subs":   func(s *Site) { s.HSTS.IncludeSubdomains = false },
		"hsts no tls": func(s *Site) {
			s.Listeners[1].TLS, s.Listeners[1].HTTP2, s.Listeners[1].HTTP3, s.ForceHTTPS = nil, false, false, nil
		},
		"body negative":       func(s *Site) { s.Limits.MaxBodyBytes = -1 },
		"body too large":      func(s *Site) { s.Limits.MaxBodyBytes = MaxBodyBytes + 1 },
		"connections -2":      func(s *Site) { s.Limits.Connections.Max = -2 },
		"connections max":     func(s *Site) { s.Limits.Connections.Max = MaxConnections + 1 },
		"tcp connections -1":  func(s *Site) { s.Limits.Connections.MaxConnections = -1 },
		"tcp connections max": func(s *Site) { s.Limits.Connections.MaxConnections = MaxSubscriptionCount + 1 },
		"new per second -1":   func(s *Site) { s.Limits.Connections.NewPerSecond = -1 },
		"qps max":             func(s *Site) { s.Limits.Connections.QPS = MaxSubscriptionCount + 1 },
		"subscription":        func(s *Site) { s.Telemetry.PackageSubscriptionID = "x" },
		"capture method":      func(s *Site) { s.Telemetry.Capture.Methods = []string{"get"} },
		"capture nil":         func(s *Site) { s.Telemetry.Capture.Methods = nil },
	}
	for name, mutate := range cases {
		site := fullSite(t)
		mutate(&site)
		if err := Validate(site); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: accepted (%v)", name, err)
		} else if testing.Verbose() {
			t.Logf("%s: %v", name, err)
		}
	}
	if err := Validate(fullSite(t)); err != nil {
		t.Fatalf("the fixture is invalid: %v", err)
	}
}

// A trailing slash in a route path prefix is meaningful ("/api/" matches
// "/api/..." only), so it is valid, as is "/" (every path).
// The forwarding fields ge-origin added (v7 site runtime document) are all
// representable.
func TestValidateAcceptsForwarding(t *testing.T) {
	cases := map[string]func(*Site){
		"sni from host": func(s *Site) { s.Origin.Pools[1].Endpoints[0].SNI = "" },
		"sni custom":    func(s *Site) { s.Origin.Pools[1].Endpoints[0].SNIMode = SNICustom },
		"sni visitor": func(s *Site) {
			s.Origin.Pools[1].Endpoints[0].SNIMode, s.Origin.Pools[1].Endpoints[0].SNI = SNIVisitorHost, ""
		},
		"sni origin": func(s *Site) {
			s.Origin.Pools[1].Endpoints[0].SNIMode, s.Origin.Pools[1].Endpoints[0].SNI = SNIOriginHost, ""
		},
		"system trust": func(s *Site) { s.Origin.Pools[1].Endpoints[0].TrustAnchor = TrustSystem },
		"hash": func(s *Site) {
			s.Origin.Pools[1].Algorithm, s.Origin.Pools[1].HashKey = "hash", "$host$uri:$cookie_sid"
		},
		"sticky": func(s *Site) {
			s.Origin.Pools[1].Algorithm, s.Origin.Pools[1].Sticky = "sticky", &Sticky{Source: "cookie", Name: "cdnca_route"}
		},
		"custom host": func(s *Site) {
			s.Origin.Pools[1].RequestHost = &RequestHost{Mode: RequestHostCustom, Value: "bucket.test:8080"}
		},
		"origin host": func(s *Site) { s.Origin.Pools[1].RequestHost = &RequestHost{Mode: RequestHostOrigin} },
		"follow port": func(s *Site) { s.Origin.Pools[1].FollowPort = true },
		"backup": func(s *Site) {
			s.Origin.Pools[1].Endpoints[1].Level, s.Origin.Pools[1].Endpoints[1].MaxConns = 1, 10
			s.Origin.Pools[1].ActiveLevel = 1
		},
		"trusted":     func(s *Site) { s.Origin.TrustedProxyCIDRs = []string{"10.0.0.0/8", "2001:db8::/32"} },
		"ws origins":  func(s *Site) { s.WebSocketOrigins = []string{"https://a.test", "https://b.test:8443"} },
		"route hosts": func(s *Site) { s.Origin.Routes[0].Hosts = []string{"*.example.test", "a.example.test"} },
	}
	for name, mutate := range cases {
		site := fullSite(t)
		mutate(&site)
		if _, err := Encode(site); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestStickyTokenMatchesV7(t *testing.T) {
	// siteruntimev2.stickyToken of the origin-forwarding golden's sticky site,
	// pool primary, endpoint b: the token the golden sends to pin b.
	if got := StickyToken("0a1b2019-0000-4000-8000-000000000103", "primary", "b"); got != "b06dd6cb99f615b375088cc5" {
		t.Fatalf("token %s", got)
	}
}

func TestValidateAcceptsRoutePathPrefixes(t *testing.T) {
	for _, prefix := range []string{"/", "/api", "/api/", "/a/b/"} {
		site := fullSite(t)
		site.Origin.Routes[0].PathPrefix = prefix
		if _, err := Encode(site); err != nil {
			t.Errorf("%q: %v", prefix, err)
		}
	}
}

func refreshToken(site *Site) {
	site.Cache.Generation, _ = CacheGeneration(*site.Cache)
}

func manyNames(count int) []string {
	names := make([]string, count)
	for index := range names {
		names[index] = fmt.Sprintf("a%04d.example.test", index)
	}
	return names
}

func TestPortProfiles(t *testing.T) {
	a := fullSite(t)
	b := minimalSite()
	b.SiteID = testUUID2
	b.Listeners = []Listener{{Port: 80, AddressFamily: FamilyIPv4}, {Port: 443, AddressFamily: FamilyIPv6, HTTP2: true,
		TLS: &TLS{CertificateVersionID: testUUID2, Protocols: []string{"TLSv1.3"}}}}
	profiles, err := PortProfiles([]Site{a, b})
	if err != nil {
		t.Fatal(err)
	}
	want := []PortProfile{
		{Port: 80, IPv4: true, IPv6: true, SiteCount: 2},
		{Port: 443, TLS: true, HTTP2: true, HTTP3: true, IPv4: true, IPv6: true, SiteCount: 2},
	}
	if fmt.Sprint(profiles) != fmt.Sprint(want) {
		t.Fatalf("profiles %+v, want %+v", profiles, want)
	}

	// HTTP/2 is per site (native patch 27): the port's server has it when
	// any site does.
	noH2 := b
	noH2.Listeners = []Listener{b.Listeners[0], b.Listeners[1]}
	noH2.Listeners[1].HTTP2 = false
	profiles, err = PortProfiles([]Site{a, noH2})
	if err != nil || !profiles[1].HTTP2 {
		t.Fatalf("HTTP/2 off for one site of a port: %+v %v", profiles, err)
	}
	if profiles, err = PortProfiles([]Site{noH2}); err != nil || profiles[1].HTTP2 {
		t.Fatalf("HTTP/2 off for every site of a port: %+v %v", profiles, err)
	}
	if a.UsesTLSOptions() || !noH2.UsesTLSOptions() {
		t.Fatal("UsesTLSOptions for HTTP/2 off")
	}
	prefer := b
	prefer.Listeners = []Listener{b.Listeners[0], b.Listeners[1]}
	on := true
	tls := *b.Listeners[1].TLS
	tls.PreferServerCiphers = &on
	prefer.Listeners[1].TLS = &tls
	if !prefer.UsesTLSOptions() {
		t.Fatal("UsesTLSOptions for an explicit prefer_server_ciphers")
	}
	if err := Validate(prefer); err != nil {
		t.Fatalf("modern preset with prefer_server_ciphers on: %v", err)
	}
	off := false
	tls.PreferServerCiphers = &off // equal to the modern preset: not canonical
	if err := Validate(prefer); !errors.Is(err, ErrInvalid) {
		t.Fatalf("prefer_server_ciphers equal to the preset accepted: %v", err)
	}
	plain := b
	plain.Listeners = []Listener{{Port: 443, AddressFamily: FamilyIPv4}}
	if _, err := PortProfiles([]Site{a, plain}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("TLS and plain on one port accepted: %v", err)
	}
	same := b
	same.Hosts = Hosts{Primary: "www.example.test", Aliases: []string{}}
	if _, err := PortProfiles([]Site{a, same}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("one name on one port for two sites accepted: %v", err)
	}
	if _, err := PortProfiles([]Site{a, a}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a site twice accepted: %v", err)
	}
}

func TestIndexEntries(t *testing.T) {
	site := fullSite(t)
	entries := site.IndexEntries()
	if len(entries) != 6 {
		t.Fatalf("%d entries, want 2 ports x 3 names", len(entries))
	}
	if entries[0].Port != 80 || entries[0].Name != "*.img.example.test" || entries[5].Port != 443 || entries[5].Name != "www.example.test" {
		t.Fatalf("entries are not sorted by port then name: %+v", entries)
	}
	// The key is md5("443\x00cdn.example.test"): the node computes the same.
	key := IndexKey(443, "cdn.example.test")
	if want := md5.Sum([]byte("443\x00cdn.example.test")); key != want {
		t.Fatalf("index key %s", hex.EncodeToString(key[:]))
	}
	if IndexKey(443, "cdn.example.test") == IndexKey(4430, "cdn.example.test") || IndexKey(44, "3cdn.example.test") == key {
		t.Fatal("index keys are ambiguous")
	}
}

func TestCacheIdentity(t *testing.T) {
	site := fullSite(t)
	edited := fullSite(t)
	edited.Revision++
	edited.Hosts.Aliases = []string{"www.example.test"}
	if edited.Cache.KeyPrefix != site.Cache.KeyPrefix || edited.Cache.Generation != site.Cache.Generation {
		t.Fatal("a site edit outside the cache changed the cache identity")
	}
	// D8 revision (ge-cache epoch): a new policy revision or soft quota keeps
	// the key space; only what shapes cached responses changes it.
	edited.Cache.Policy.Revision++
	edited.Cache.Policy.DiskQuotaBytes *= 2
	refreshToken(&edited)
	if edited.Cache.Generation != site.Cache.Generation {
		t.Fatal("a policy revision or disk quota change started a new key space")
	}
	edited.Cache.Policy.Rules[0].TTLSeconds = 60
	refreshToken(&edited)
	if edited.Cache.KeyPrefix != site.Cache.KeyPrefix || edited.Cache.Generation == site.Cache.Generation {
		t.Fatal("a cache policy change did not start a new key space")
	}
	edited.Cache.KeyByHost = false
	before := edited.Cache.Generation
	refreshToken(&edited)
	if edited.Cache.Generation == before {
		t.Fatal("host keying did not change the freshness token")
	}
	if CacheKeyPrefix(testTenant, testSite) == CacheKeyPrefix(testTenant, testUUID) {
		t.Fatal("two sites share a cache key prefix")
	}
}

// The largest site the bounds allow still fits MaxObjectBytes: every name,
// every listener, every pool full, MaxPlanRules rules.
func TestSizeBounds(t *testing.T) {
	site := fullSite(t)
	site.Hosts.Aliases = manyNames(MaxNames - 1)
	site.Listeners = nil
	for index := range MaxListeners {
		site.Listeners = append(site.Listeners, Listener{Port: 8000 + index, AddressFamily: FamilyDualStack, HTTP2: true, HTTP3: true,
			TLS: &TLS{CertificateVersionID: testUUID, Protocols: []string{"TLSv1.2", "TLSv1.3"}}})
	}
	site.ForceHTTPS = &ForceHTTPS{RedirectPort: 8000}
	site.Security.CC[0].Ports = []int{8000}
	pool := site.Origin.Pools[1]
	pool.Endpoints = nil
	for index := range MaxEndpoints {
		pool.Endpoints = append(pool.Endpoints, Endpoint{ID: fmt.Sprintf("origin-%02d", index), Scheme: "https",
			Host: fmt.Sprintf("origin%02d.example.test", index), Port: 443, Weight: 100, SNI: "origin.example.test", TrustAnchor: "sha256:" + digestB})
	}
	site.Origin.Pools = []Pool{site.Origin.Pools[0]}
	for index := range MaxPools - 1 {
		copy := pool
		copy.ID = fmt.Sprintf("pool-%02d", index)
		site.Origin.Pools = append(site.Origin.Pools, copy)
	}
	site.Origin.DefaultFallbackPoolID, site.Origin.L2.DirectFallbackPoolID = "pool-00", "pool-00"
	site.Origin.Routes = []Route{}
	site.Origin.Auth = []OriginAuth{}
	policy := site.Security.Rules.Policies[0]
	policy.Rules = nil
	for index := range MaxPlanRules {
		policy.Rules = append(policy.Rules, edgeconfig.WAFRule{RuleID: fmt.Sprintf("11111111-1111-4111-8111-%012d", index),
			Match:  edgeconfig.WAFMatch{Port: 8000, Method: "POST", Path: &edgeconfig.WAFPathMatch{Kind: edgeconfig.WAFPathPrefix, Value: "/api/v1/upload"}, SourceCIDR: "203.0.113.0/24"},
			Action: edgeconfig.WAFBlock, Control: edgeconfig.WAFContinue})
	}
	site.Security.Rules.Policies = []RulePolicy{policy}
	// Every (category, status) a site can carry, each its own UUID rule.
	site.Errors = nil
	for _, category := range []string{ErrorEdgeConnect, ErrorEdgeRoute, ErrorOriginResponse} {
		for status := 400; status <= 599; status++ {
			if ErrorCategoryAllows(category, status) {
				site.Errors = append(site.Errors, ErrorPage{Category: category, Status: status,
					RuleID: fmt.Sprintf("33333333-3333-4333-8333-%012d", len(site.Errors)), MIMEType: "text/html", StyleHash: testStyleHash,
					Asset: Ref{Kind: RefErrorPageAsset, ID: testUUID, Revision: 1, SHA256: digestA}})
			}
		}
	}
	if len(site.Errors) != MaxErrorPages {
		t.Fatalf("%d error pages, MaxErrorPages %d", len(site.Errors), MaxErrorPages)
	}
	raw, err := Encode(site)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("largest site: %d bytes (%.0f%% of MaxObjectBytes)", len(raw), 100*float64(len(raw))/MaxObjectBytes)

	policy.Rules = append(policy.Rules, policy.Rules[0])
	site.Security.Rules.Policies = []RulePolicy{policy}
	if _, err := Encode(site); !errors.Is(err, ErrInvalid) {
		t.Fatalf("%d rules accepted", len(policy.Rules))
	}
}

// Every digest a site references is listed once (the node keeps them with
// the site object).
func TestReferencedDigests(t *testing.T) {
	site := fullSite(t)
	got := site.ReferencedDigests()
	if len(got) != 2 || got[0] != digestA || got[1] != digestB {
		t.Fatalf("full site references %v", got)
	}
	site.Listeners[1].TLS.ClientAuth = edgeconfig.ClientAuthRequired
	site.Listeners[1].TLS.ClientCA = &Ref{Kind: RefClientCA, ID: testUUID, Revision: 1, SHA256: strings.Repeat("c", 64)}
	if got := site.ReferencedDigests(); len(got) != 3 || got[2] != strings.Repeat("c", 64) {
		t.Fatalf("client CA not referenced: %v", got)
	}
	if got := minimalSite().ReferencedDigests(); len(got) != 0 {
		t.Fatalf("minimal site references %v", got)
	}
}

// WAF v2 (ge-waf): a WAF policy carries observe mode, auto block and
// challenge / ban rules with their action_config; ACL policies take none of
// them, and auto block must be in its normalized form.
func TestRulePlanCarriesWAFActions(t *testing.T) {
	waf := RulePolicy{Kind: edgeconfig.SecurityWAF, PolicyID: testUUID2, PolicyVersion: 1, BindingRevision: 1, RuntimeSHA256: digestB,
		Enabled: true, DefaultAction: edgeconfig.WAFAllow, Mode: edgeconfig.WAFModeObserve,
		AutoBlock: &edgeconfig.WAFAutoBlock{WindowSeconds: 60, HitThreshold: 5, BlockSeconds: 600},
		Rules: []edgeconfig.WAFRule{
			{RuleID: "11111111-1111-4111-8111-000000000001", Match: edgeconfig.WAFMatch{Method: "POST"}, Action: edgeconfig.WAFChallenge,
				Control: edgeconfig.WAFStop, ActionConfig: &edgeconfig.WAFActionConfig{PassSeconds: 600, PowBits: 10}},
			{RuleID: "11111111-1111-4111-8111-000000000002", Match: edgeconfig.WAFMatch{Method: "PUT"}, Action: edgeconfig.WAFBan,
				Control: edgeconfig.WAFStop, ActionConfig: &edgeconfig.WAFActionConfig{BanSeconds: 300}},
		}}
	withPolicies := func(policies ...RulePolicy) Site {
		site := fullSite(t)
		site.Security.Rules.Policies = append([]RulePolicy{site.Security.Rules.Policies[0]}, policies...)
		return site
	}
	raw, err := Encode(withPolicies(waf))
	if err != nil {
		t.Fatalf("WAF v2 policy rejected: %v", err)
	}
	decoded, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	got := decoded.Security.Rules.Policies[1]
	if got.Mode != edgeconfig.WAFModeObserve || got.AutoBlock == nil || *got.AutoBlock != *waf.AutoBlock ||
		got.Rules[0].ActionConfig == nil || got.Rules[1].ActionConfig.BanSeconds != 300 {
		t.Fatalf("WAF v2 fields lost: %+v", got)
	}
	for name, mutate := range map[string]func(*RulePolicy){
		"ACL observe":        func(p *RulePolicy) { p.Kind = edgeconfig.SecurityACL; p.AutoBlock = nil; p.Rules = p.Rules[:0] },
		"unknown mode":       func(p *RulePolicy) { p.Mode = "learn" },
		"zero auto block":    func(p *RulePolicy) { p.AutoBlock = &edgeconfig.WAFAutoBlock{} },
		"ban without config": func(p *RulePolicy) { p.Rules[1].ActionConfig = nil },
		"challenge pow 30": func(p *RulePolicy) {
			p.Rules[0].ActionConfig = &edgeconfig.WAFActionConfig{PassSeconds: 600, PowBits: 30}
		},
	} {
		policy := waf
		policy.Rules = append([]edgeconfig.WAFRule(nil), waf.Rules...)
		mutate(&policy)
		if policy.Kind == edgeconfig.SecurityACL {
			policy.Mode = edgeconfig.WAFModeObserve
			site := fullSite(t)
			site.Security.Rules.Policies = []RulePolicy{policy}
			if _, err := Encode(site); !errors.Is(err, ErrInvalid) {
				t.Errorf("%s accepted", name)
			}
			continue
		}
		if _, err := Encode(withPolicies(policy)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s accepted", name)
		}
	}
	acl := fullSite(t)
	acl.Security.Rules.Policies[0].Rules[0].Action = edgeconfig.WAFBan
	acl.Security.Rules.Policies[0].Rules[0].ActionConfig = &edgeconfig.WAFActionConfig{BanSeconds: 60}
	if _, err := Encode(acl); !errors.Is(err, ErrInvalid) {
		t.Error("ACL ban rule accepted")
	}
}
