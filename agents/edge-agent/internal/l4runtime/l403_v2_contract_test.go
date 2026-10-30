package l4runtime

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

const (
	l403Tenant = "11111111-1111-4111-8111-111111111111"
	l403Stream = "33333333-3333-4333-8333-333333333333"
)

func l403StreamSpec() StreamRuntimeSpecV2 {
	return StreamRuntimeSpecV2{
		SchemaVersion: SchemaVersionV2,
		TenantID:      l403Tenant, StreamID: l403Stream, Revision: 7,
		Listener: ListenerSocketV2{Protocol: ProtocolTCP, Address: "0.0.0.0", Port: 9443},
		Endpoint: EndpointV2{Host: "B\u00dcCHER.example.", Port: 443},
		DNS:      DNSPolicyV2{PositiveMinTTLSeconds: 5, PositiveMaxTTLSeconds: 300, NegativeTTLSeconds: 10, StaleIfErrorSeconds: 900},
		Geo: GeoPolicyV2{
			Enabled: true, TenantID: l403Tenant, StreamID: l403Stream, Revision: 7,
			UnknownRegionAction: GeoActionBlock,
			TrustedProxyCIDRs:   []string{"2001:db8:abcd::/48", "203.0.113.0/24"},
			BlockedRegions:      []string{"US", "CN"},
			RegionCIDRs: []RegionCIDRsV2{
				{Region: "CN", CIDRs: []string{"1.0.1.0/24", "2001:250::/32"}},
				{Region: "US", CIDRs: []string{"8.8.8.0/24"}},
			},
		},
		ConnectTimeoutMS: 1000, ResponseTimeoutMS: 30000, MaxConnectionsPerClient: 100, DrainTimeoutMS: 30000,
		ProxyProtocolInbound: true, ProxyProtocolOutbound: true,
	}
}

func TestL403V2TranslationIsExplicitCanonicalAndScoped(t *testing.T) {
	config, err := AggregateStreamRuntimeSpecsV2("l403-revision-7", 7, []StreamRuntimeSpecV2{l403StreamSpec()})
	if err != nil {
		t.Fatal(err)
	}
	if config.SchemaVersion != SchemaVersionV2 || len(config.Listeners) != 1 {
		t.Fatalf("translated config = %+v", config)
	}
	listener := config.Listeners[0]
	if listener.ID != l403Stream || listener.StreamID != l403Stream || listener.Endpoint.Host != "xn--bcher-kva.example" {
		t.Fatalf("listener identity/IDNA host = %+v", listener)
	}
	if listener.Geo.TenantID != listener.TenantID || listener.Geo.SiteID != listener.SiteID ||
		listener.Geo.StreamID != listener.StreamID || listener.Geo.Revision != config.Revision {
		t.Fatalf("geo scope escaped listener = %+v", listener.Geo)
	}
	canonical, err := CanonicalV2(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"schema_version":"cdnca.edge.l4/v2"`, `"revision":7`, `"host":"xn--bcher-kva.example"`,
		`"blocked_regions":["cn","us"]`, `"region":"cn"`, `"connect_timeout_ms":1000`,
	} {
		if !strings.Contains(string(canonical), want) {
			t.Fatalf("canonical config missing %q: %s", want, canonical)
		}
	}
	var decoded map[string]any
	if err := json.Unmarshal(canonical, &decoded); err != nil {
		t.Fatal(err)
	}
	if _, leaked := decoded["tenant_id"]; leaked {
		t.Fatal("Agent aggregated config silently reused the control single-stream shape")
	}
}

func TestL403V2RejectsCrossScopeUnsafeAndAmbiguousInputs(t *testing.T) {
	tests := map[string]func(*StreamRuntimeSpecV2){
		"address and host":               func(v *StreamRuntimeSpecV2) { v.Endpoint.Address = "8.8.8.8" },
		"missing endpoint":               func(v *StreamRuntimeSpecV2) { v.Endpoint.Host = "" },
		"bad IDNA":                       func(v *StreamRuntimeSpecV2) { v.Endpoint.Host = "bad host.example" },
		"private DNS opt in unsupported": func(v *StreamRuntimeSpecV2) { v.DNS.AllowPrivateAddresses = true },
		"cross tenant geo":               func(v *StreamRuntimeSpecV2) { v.Geo.TenantID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" },
		"cross listener geo":             func(v *StreamRuntimeSpecV2) { v.Geo.StreamID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" },
		"stale revision geo":             func(v *StreamRuntimeSpecV2) { v.Geo.Revision = 6 },
		"unknown action":                 func(v *StreamRuntimeSpecV2) { v.Geo.UnknownRegionAction = "challenge" },
		"trusted all":                    func(v *StreamRuntimeSpecV2) { v.Geo.TrustedProxyCIDRs = []string{"0.0.0.0/0"} },
		"blocked without authority":      func(v *StreamRuntimeSpecV2) { v.Geo.RegionCIDRs = v.Geo.RegionCIDRs[:1] },
		"ttl inverted":                   func(v *StreamRuntimeSpecV2) { v.DNS.PositiveMaxTTLSeconds = 4 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			spec := l403StreamSpec()
			mutate(&spec)
			if _, err := AggregateStreamRuntimeSpecsV2("l403-revision-7", 7, []StreamRuntimeSpecV2{spec}); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestL403V2StaticAddressRetainsV1IPCompatibility(t *testing.T) {
	for _, raw := range []string{"10.0.0.1", "192.0.2.1"} {
		t.Run(raw, func(t *testing.T) {
			spec := l403StreamSpec()
			spec.Endpoint = EndpointV2{Address: raw, Port: 443}
			spec.DNS = DNSPolicyV2{}
			config, err := AggregateStreamRuntimeSpecsV2("l403-static", 7, []StreamRuntimeSpecV2{spec})
			if err != nil {
				t.Fatalf("static v1-compatible address rejected: %v", err)
			}
			if got := config.Listeners[0].Endpoint.Address; got != raw {
				t.Fatalf("static address = %q, want %q", got, raw)
			}
		})
	}
}

func TestL403V2CompilerUsesResolvedSetAndGeoPrereadWithoutV1Drift(t *testing.T) {
	before, err := Compile(validConfig("l403-v1-baseline"))
	if err != nil {
		t.Fatal(err)
	}
	config, err := AggregateStreamRuntimeSpecsV2("l403-revision-7", 7, []StreamRuntimeSpecV2{l403StreamSpec()})
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := CompileV2(config, map[string][]netip.Addr{
		l403Stream: {netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("2001:4860:4860::8888")},
	})
	if err != nil {
		t.Fatal(err)
	}
	nginx := string(compiled.NginxConfig)
	for _, want := range []string{
		"stream {\n    lua_package_path '/opt/cdnca/l4geo/?.lua;/opt/cdnca/?.lua;;';",
		`geo.enforce("` + l403Stream + `")`,
		"server 8.8.8.8:443", "server [2001:4860:4860::8888]:443",
	} {
		if !strings.Contains(nginx, want) {
			t.Fatalf("v2 nginx missing %q:\n%s", want, nginx)
		}
	}
	for _, want := range []string{`"id":"` + l403Stream + `"`, `"geo":{"enabled":true,"tenant_id":"` + l403Tenant + `"`} {
		if !strings.Contains(string(compiled.GeoJSON), want) {
			t.Fatalf("geo config missing %q: %s", want, compiled.GeoJSON)
		}
	}
	after, err := Compile(validConfig("l403-v1-baseline"))
	if err != nil || string(before.CanonicalJSON) != string(after.CanonicalJSON) || before.Digest != after.Digest || string(before.NginxConfig) != string(after.NginxConfig) {
		t.Fatalf("v1 artifact drifted after v2 compile: error=%v", err)
	}
}
