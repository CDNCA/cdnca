package l4forward

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestL403DomainUpstreamCanonicalizationAndSafety(t *testing.T) {
	fields := validFields()
	fields.UpstreamAddress = ""
	fields.UpstreamHost = "B\u00dcCHER.Example."
	fields.DNS = DNSPolicy{
		PositiveMinTTLSeconds: 5, PositiveMaxTTLSeconds: 300,
		NegativeTTLSeconds: 30, StaleIfErrorSeconds: 900,
	}
	if err := normalizeFields(&fields); err != nil {
		t.Fatalf("normalize domain fields: %v", err)
	}
	if fields.UpstreamHost != "xn--bcher-kva.example" {
		t.Fatalf("canonical host=%q", fields.UpstreamHost)
	}

	for name, mutate := range map[string]func(*Fields){
		"both address and host":    func(value *Fields) { value.UpstreamAddress = "192.0.2.10" },
		"neither address nor host": func(value *Fields) { value.UpstreamHost = "" },
		"localhost":                func(value *Fields) { value.UpstreamHost = "localhost" },
		"localhost child":          func(value *Fields) { value.UpstreamHost = "origin.localhost" },
		"reverse IPv4":             func(value *Fields) { value.UpstreamHost = "1.0.0.127.in-addr.arpa" },
		"reverse IPv6":             func(value *Fields) { value.UpstreamHost = "1.0.0.0.ip6.arpa" },
		"leading whitespace":       func(value *Fields) { value.UpstreamHost = " origin.example" },
		"control character":        func(value *Fields) { value.UpstreamHost = "origin\n.example" },
		"IP in host field":         func(value *Fields) { value.UpstreamHost = "192.0.2.10" },
		"single label":             func(value *Fields) { value.UpstreamHost = "origin" },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := fields
			mutate(&invalid)
			if err := normalizeFields(&invalid); err == nil {
				t.Fatalf("normalizeFields accepted %+v", invalid)
			}
		})
	}
}

func TestL403DNSAndGeoPolicyFailSafe(t *testing.T) {
	base := validFields()
	base.UpstreamAddress = ""
	base.UpstreamHost = "origin.example"
	base.DNS = DNSPolicy{
		PositiveMinTTLSeconds: 5, PositiveMaxTTLSeconds: 300,
		NegativeTTLSeconds: 30, StaleIfErrorSeconds: 900,
	}
	base.Geo = GeoPolicy{
		Enabled: true, UnknownRegionAction: GeoActionBlock,
		TrustedProxyCIDRs: []string{"2001:db8::1/64", "192.0.2.19/24"},
		BlockedRegions:    []string{" CN-BJ ", "us-ca", "cn-bj"},
		RegionCIDRs: []GeoRegionCIDRs{
			{Region: "us-ca", CIDRs: []string{"2001:db8:1::/48"}},
			{Region: "cn-bj", CIDRs: []string{"198.51.100.9/24"}},
		},
	}
	base.ProxyProtocolInbound = true
	if err := normalizeFields(&base); err != nil {
		t.Fatalf("normalize v2 fields: %v", err)
	}
	if got := strings.Join(base.Geo.TrustedProxyCIDRs, ","); got != "192.0.2.0/24,2001:db8::/64" {
		t.Fatalf("trusted proxy CIDRs=%q", got)
	}
	if got := strings.Join(base.Geo.BlockedRegions, ","); got != "cn-bj,us-ca" {
		t.Fatalf("blocked regions=%q", got)
	}

	for name, mutate := range map[string]func(*Fields){
		"positive minimum zero":            func(value *Fields) { value.DNS.PositiveMinTTLSeconds = 0 },
		"positive maximum below minimum":   func(value *Fields) { value.DNS.PositiveMaxTTLSeconds = 4 },
		"positive maximum unbounded":       func(value *Fields) { value.DNS.PositiveMaxTTLSeconds = 86401 },
		"negative TTL zero":                func(value *Fields) { value.DNS.NegativeTTLSeconds = 0 },
		"negative TTL unbounded":           func(value *Fields) { value.DNS.NegativeTTLSeconds = 3601 },
		"stale bound zero":                 func(value *Fields) { value.DNS.StaleIfErrorSeconds = 0 },
		"private without explicit opt-in":  func(value *Fields) { value.DNS.AllowPrivateAddresses = true },
		"unknown action implicit":          func(value *Fields) { value.Geo.UnknownRegionAction = "" },
		"unknown action invalid":           func(value *Fields) { value.Geo.UnknownRegionAction = "challenge" },
		"proxy is not CIDR":                func(value *Fields) { value.Geo.TrustedProxyCIDRs = []string{"proxy.example"} },
		"trusted proxy without inbound":    func(value *Fields) { value.ProxyProtocolInbound = false },
		"inbound proxy with UDP":           func(value *Fields) { value.Protocol = ProtocolUDP },
		"region invalid":                   func(value *Fields) { value.Geo.BlockedRegions = []string{"../../CN"} },
		"blocked region without authority": func(value *Fields) { value.Geo.BlockedRegions = []string{"eu-de"} },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := base
			invalid.Geo.TrustedProxyCIDRs = append([]string(nil), base.Geo.TrustedProxyCIDRs...)
			invalid.Geo.BlockedRegions = append([]string(nil), base.Geo.BlockedRegions...)
			invalid.Geo.RegionCIDRs = append([]GeoRegionCIDRs(nil), base.Geo.RegionCIDRs...)
			mutate(&invalid)
			if err := normalizeFields(&invalid); err == nil {
				t.Fatalf("normalizeFields accepted %+v", invalid)
			}
		})
	}
}

// Migration 506: a stream belongs to no website; the v2 runtime and its geo
// bind tenant and stream only (tcp/udp v12).
func TestL403RuntimeV2BindsTenantStreamListenerEndpointDNSAndGeo(t *testing.T) {
	item := Forward{
		ID:       uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7101"),
		ScopeID:  uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7102"),
		Revision: 7, Protocol: ProtocolTCP, ListenAddress: "*", ListenPort: 18080,
		UpstreamHost: "origin.example", UpstreamPort: 8080,
		DNS:                  DNSPolicy{PositiveMinTTLSeconds: 5, PositiveMaxTTLSeconds: 300, NegativeTTLSeconds: 30, StaleIfErrorSeconds: 900},
		Geo:                  GeoPolicy{Enabled: true, UnknownRegionAction: GeoActionBlock, TrustedProxyCIDRs: []string{"192.0.2.0/24"}, BlockedRegions: []string{"cn-bj"}, RegionCIDRs: []GeoRegionCIDRs{{Region: "cn-bj", CIDRs: []string{"198.51.100.0/24"}}}},
		ProxyProtocolInbound: true,
		ConnectTimeoutMS:     1000, ResponseTimeoutMS: 30000, MaxConnectionsPerClient: 100,
	}
	encoded, err := json.Marshal(runtimeSpec(item))
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		`"schema_version":"cdnca.edge.l4/v2"`, `"tenant_id":"018f47a2-5b9c-7d31-8a60-104c9c0b7102"`,
		`"stream_id":"018f47a2-5b9c-7d31-8a60-104c9c0b7101"`,
		`"revision":7`, `"listener":{"protocol":"tcp","address":"*","port":18080}`,
		`"endpoint":{"host":"origin.example","port":8080}`, `"unknown_region_action":"block"`,
		`"proxy_protocol_inbound":true`,
		`"geo":{"enabled":true,"tenant_id":"018f47a2-5b9c-7d31-8a60-104c9c0b7102","stream_id":"018f47a2-5b9c-7d31-8a60-104c9c0b7101","revision":7`,
	} {
		if !strings.Contains(string(encoded), fragment) {
			t.Fatalf("runtime JSON %s does not contain %s", encoded, fragment)
		}
	}
	if strings.Contains(string(encoded), `"site_id"`) {
		t.Fatalf("runtime JSON still names a website: %s", encoded)
	}
}

func TestL403StoreUsesMigration151FactsWithoutMemoryFallback(t *testing.T) {
	source := readThisFile(t, "store.go")
	for _, fragment := range []string{
		"remark", "upstream_host", "dns_policy", "geo_policy", "proxy_protocol_inbound",
		"COALESCE(host(f.upstream_address), '')", "f.upstream_host",
	} {
		if !strings.Contains(source, fragment) {
			t.Fatalf("store.go missing migration151 fact %q", fragment)
		}
	}
	if strings.Contains(source, "memoryStore") || strings.Contains(source, "map[uuid.UUID]Forward") {
		t.Fatal("store.go contains an in-memory L4-03 authority")
	}
}

func readThisFile(t *testing.T, name string) string {
	t.Helper()
	payload, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}
