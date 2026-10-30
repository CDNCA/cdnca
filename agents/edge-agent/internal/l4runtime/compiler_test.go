package l4runtime

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func validConfig(versionID string) Config {
	return Config{
		SchemaVersion: SchemaVersionV1,
		VersionID:     versionID,
		UpstreamPools: []UpstreamPool{
			{ID: "pool-v6", Endpoints: []Endpoint{{Address: "2001:0db8::2", Port: 9443, Weight: 1, MaxFails: 2, FailTimeoutMS: 2_000}}},
			{ID: "pool-v4", Endpoints: []Endpoint{
				{Address: "192.0.2.20", Port: 9000, Weight: 1, MaxFails: 1, FailTimeoutMS: 1_000},
				{Address: "192.0.2.10", Port: 9000, Weight: 3, MaxFails: 2, FailTimeoutMS: 2_000},
			}},
		},
		Listeners: []Listener{
			{ID: "udp-public", Protocol: ProtocolUDP, Address: "0.0.0.0", Port: 5353, UpstreamPoolID: "pool-v4", ConnectTimeoutMS: 500, IdleTimeoutMS: 5_000, MaxConnectionsPerClient: 20},
			{ID: "tcp-v6", Protocol: ProtocolTCP, Address: "2001:0db8::1", Port: 443, UpstreamPoolID: "pool-v6", ConnectTimeoutMS: 1_000, IdleTimeoutMS: 60_000, ProxyProtocolOutbound: true, ProxyProtocolV1: true, MaxConnectionsPerClient: 100},
		},
	}
}

func TestCompileIsDeterministicAndAuditable(t *testing.T) {
	first, err := Compile(validConfig("l4-v1"))
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	reordered := validConfig("l4-v1")
	reordered.Listeners[0], reordered.Listeners[1] = reordered.Listeners[1], reordered.Listeners[0]
	reordered.UpstreamPools[0], reordered.UpstreamPools[1] = reordered.UpstreamPools[1], reordered.UpstreamPools[0]
	reordered.UpstreamPools[0].Endpoints[0], reordered.UpstreamPools[0].Endpoints[1] = reordered.UpstreamPools[0].Endpoints[1], reordered.UpstreamPools[0].Endpoints[0]
	second, err := Compile(reordered)
	if err != nil {
		t.Fatalf("Compile(reordered) error = %v", err)
	}
	if first.Digest != second.Digest || !reflect.DeepEqual(first.Config, second.Config) || string(first.NginxConfig) != string(second.NginxConfig) || string(first.CanonicalJSON) != string(second.CanonicalJSON) {
		t.Fatal("equivalent L4 input produced different normalized output")
	}

	text := string(first.NginxConfig)
	for _, expected := range []string{
		"schema=cdnca.edge.l4/v1 version=l4-v1 digest=" + first.Digest,
		"upstream l4_upstream_",
		"server 192.0.2.10:9000 weight=3 max_fails=2 fail_timeout=2s",
		"listen [2001:db8::1]:443 ipv6only=on",
		"listen 0.0.0.0:5353 udp",
		"proxy_connect_timeout 1000ms",
		"proxy_timeout 60000ms",
		"proxy_protocol on",
		"proxy_responses 1",
		`limit_conn_zone "$server_addr:$server_port:$protocol:$binary_remote_addr" zone=l4_limit_clients:16m`,
		"limit_conn l4_limit_clients",
		"log_format l4_audit escape=json",
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("generated configuration missing %q:\n%s", expected, text)
		}
	}
	if strings.Contains(text, "2001:0db8") {
		t.Fatalf("IPv6 address was not canonicalized:\n%s", text)
	}
	for _, absent := range []string{"trusted_proxy_cidrs", `"priority"`, `"backup"`} {
		if strings.Contains(string(first.CanonicalJSON), absent) {
			t.Fatalf("disabled enhancement %q changed baseline canonical JSON: %s", absent, first.CanonicalJSON)
		}
	}
}

func TestCompileBoundsSharedClientConnectionZoneAcrossMaximumListeners(t *testing.T) {
	config := validConfig("l4-max-listeners")
	config.Listeners = make([]Listener, 0, maxListeners)
	for index := 0; index < maxListeners; index++ {
		config.Listeners = append(config.Listeners, Listener{
			ID: fmt.Sprintf("listener-%03d", index), Protocol: ProtocolTCP, Address: "0.0.0.0",
			Port: 20_000 + index, UpstreamPoolID: "pool-v4", ConnectTimeoutMS: 100,
			IdleTimeoutMS: 1_000, MaxConnectionsPerClient: index + 1,
		})
	}
	compiled, err := Compile(config)
	if err != nil {
		t.Fatal(err)
	}
	text := string(compiled.NginxConfig)
	if count := strings.Count(text, "limit_conn_zone "); count != 1 {
		t.Fatalf("limit_conn_zone count = %d, want 1", count)
	}
	if count := strings.Count(text, "limit_conn l4_limit_clients "); count != maxListeners {
		t.Fatalf("limit_conn count = %d, want %d", count, maxListeners)
	}
	for _, expected := range []string{
		`limit_conn_zone "$server_addr:$server_port:$protocol:$binary_remote_addr" zone=l4_limit_clients:16m;`,
		"limit_conn l4_limit_clients 1;", "limit_conn l4_limit_clients 256;",
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("maximum-listener configuration missing %q", expected)
		}
	}
	reversed := config
	reversed.Listeners = append([]Listener(nil), config.Listeners...)
	for left, right := 0, len(reversed.Listeners)-1; left < right; left, right = left+1, right-1 {
		reversed.Listeners[left], reversed.Listeners[right] = reversed.Listeners[right], reversed.Listeners[left]
	}
	second, err := Compile(reversed)
	if err != nil || second.Digest != compiled.Digest || !reflect.DeepEqual(second.NginxConfig, compiled.NginxConfig) {
		t.Fatalf("reordered maximum listeners changed output: digest=%q error=%v", second.Digest, err)
	}
}

func TestCompileEnforcesProxyProtocolV1Contract(t *testing.T) {
	tests := []struct {
		name                   string
		listener               Listener
		wantErr                error
		wantInbound            bool
		wantOutboundDirectives int
	}{
		{name: "disabled TCP", listener: Listener{Protocol: ProtocolTCP}},
		{name: "TCP outbound v1", listener: Listener{Protocol: ProtocolTCP, ProxyProtocolOutbound: true, ProxyProtocolV1: true}, wantOutboundDirectives: 1},
		{name: "inbound without trusted proxy", listener: Listener{Protocol: ProtocolTCP, ProxyProtocolInbound: true}, wantErr: ErrInvalidConfig},
		{name: "trusted proxy without inbound", listener: Listener{Protocol: ProtocolTCP, TrustedProxyCIDRs: []string{"192.0.2.0/24"}}, wantErr: ErrInvalidConfig},
		{name: "trusted inbound v1 and v2", listener: Listener{Protocol: ProtocolTCP, ProxyProtocolInbound: true,
			TrustedProxyCIDRs: []string{"2001:0db8:2:1::/48", "192.0.2.7/24"}}, wantInbound: true},
		{name: "UDP inbound", listener: Listener{Protocol: ProtocolUDP, ProxyProtocolInbound: true,
			TrustedProxyCIDRs: []string{"192.0.2.0/24"}}, wantErr: ErrUnsupported},
		{name: "outbound without v1", listener: Listener{Protocol: ProtocolTCP, ProxyProtocolOutbound: true}, wantErr: ErrInvalidConfig},
		{name: "v1 without outbound", listener: Listener{Protocol: ProtocolTCP, ProxyProtocolV1: true}, wantErr: ErrInvalidConfig},
		{name: "UDP outbound v1", listener: Listener{Protocol: ProtocolUDP, ProxyProtocolOutbound: true, ProxyProtocolV1: true}, wantErr: ErrUnsupported},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := validConfig("proxy-contract")
			config.Listeners[1].ProxyProtocolInbound = test.listener.ProxyProtocolInbound
			config.Listeners[1].ProxyProtocolOutbound = test.listener.ProxyProtocolOutbound
			config.Listeners[1].ProxyProtocolV1 = test.listener.ProxyProtocolV1
			config.Listeners[1].TrustedProxyCIDRs = test.listener.TrustedProxyCIDRs
			config.Listeners[1].Protocol = test.listener.Protocol
			compiled, err := Compile(config)
			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) {
					t.Fatalf("Compile() error = %v, want %v", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			text := string(compiled.NginxConfig)
			if got := strings.Count(text, "proxy_protocol on;"); got != test.wantOutboundDirectives {
				t.Fatalf("outbound proxy_protocol directives = %d", got)
			}
			inbound := strings.Contains(text, "listen [2001:db8::1]:443 ipv6only=on proxy_protocol")
			if inbound != test.wantInbound {
				t.Fatalf("inbound Proxy Protocol generated=%t, want %t:\n%s", inbound, test.wantInbound, text)
			}
			if test.wantInbound {
				for _, trusted := range []string{"set_real_ip_from 192.0.2.0/24;", "set_real_ip_from 2001:db8:2::/48;"} {
					if !strings.Contains(text, trusted) {
						t.Fatalf("trusted inbound configuration missing %q:\n%s", trusted, text)
					}
				}
			}
		})
	}
}

func TestCompileRejectsInvalidConfiguration(t *testing.T) {
	tests := map[string]func(*Config){
		"unknown schema":             func(c *Config) { c.SchemaVersion = "cdnca.edge.l4/v2" },
		"version control character":  func(c *Config) { c.VersionID = "l4-v1\nworker_processes 8" },
		"empty listeners":            func(c *Config) { c.Listeners = nil },
		"empty pools":                func(c *Config) { c.UpstreamPools = nil },
		"duplicate listener id":      func(c *Config) { c.Listeners[1].ID = c.Listeners[0].ID },
		"listener id injection":      func(c *Config) { c.Listeners[0].ID = "udp; return 1" },
		"unknown protocol":           func(c *Config) { c.Listeners[0].Protocol = "sctp" },
		"invalid listener address":   func(c *Config) { c.Listeners[0].Address = "127.0.0.1; deny all" },
		"mapped listener address":    func(c *Config) { c.Listeners[0].Address = "::ffff:192.0.2.1" },
		"listener address zone":      func(c *Config) { c.Listeners[1].Address = "fe80::1%eth0" },
		"listener multicast":         func(c *Config) { c.Listeners[0].Address = "224.0.0.1" },
		"listener port zero":         func(c *Config) { c.Listeners[0].Port = 0 },
		"listener port overflow":     func(c *Config) { c.Listeners[0].Port = 65536 },
		"missing upstream reference": func(c *Config) { c.Listeners[0].UpstreamPoolID = "missing" },
		"connect timeout low":        func(c *Config) { c.Listeners[0].ConnectTimeoutMS = 9 },
		"connect timeout high":       func(c *Config) { c.Listeners[0].ConnectTimeoutMS = 60_001 },
		"idle timeout low":           func(c *Config) { c.Listeners[0].IdleTimeoutMS = 99 },
		"idle timeout high":          func(c *Config) { c.Listeners[0].IdleTimeoutMS = 86_400_001 },
		"connection limit zero":      func(c *Config) { c.Listeners[0].MaxConnectionsPerClient = 0 },
		"connection limit high":      func(c *Config) { c.Listeners[0].MaxConnectionsPerClient = 10_001 },
		"trusted proxy without inbound": func(c *Config) {
			c.Listeners[1].TrustedProxyCIDRs = []string{"192.0.2.0/24"}
		},
		"trusted proxy all IPv4": func(c *Config) {
			c.Listeners[1].ProxyProtocolInbound = true
			c.Listeners[1].TrustedProxyCIDRs = []string{"0.0.0.0/0"}
		},
		"trusted proxy mapped IPv6": func(c *Config) {
			c.Listeners[1].ProxyProtocolInbound = true
			c.Listeners[1].TrustedProxyCIDRs = []string{"::ffff:192.0.2.0/120"}
		},
		"trusted proxy duplicate": func(c *Config) {
			c.Listeners[1].ProxyProtocolInbound = true
			c.Listeners[1].TrustedProxyCIDRs = []string{"192.0.2.0/24", "192.0.2.1/24"}
		},
		"trusted proxy overlap": func(c *Config) {
			c.Listeners[1].ProxyProtocolInbound = true
			c.Listeners[1].TrustedProxyCIDRs = []string{"192.0.2.0/24", "192.0.2.128/25"}
		},
		"duplicate pool id":         func(c *Config) { c.UpstreamPools[1].ID = c.UpstreamPools[0].ID },
		"pool id injection":         func(c *Config) { c.UpstreamPools[0].ID = "pool\rinclude" },
		"empty upstream":            func(c *Config) { c.UpstreamPools[0].Endpoints = nil },
		"invalid upstream address":  func(c *Config) { c.UpstreamPools[0].Endpoints[0].Address = "origin.example" },
		"unspecified upstream":      func(c *Config) { c.UpstreamPools[0].Endpoints[0].Address = "::" },
		"multicast upstream":        func(c *Config) { c.UpstreamPools[0].Endpoints[0].Address = "ff02::1" },
		"upstream port zero":        func(c *Config) { c.UpstreamPools[0].Endpoints[0].Port = 0 },
		"weight zero":               func(c *Config) { c.UpstreamPools[0].Endpoints[0].Weight = 0 },
		"weight high":               func(c *Config) { c.UpstreamPools[0].Endpoints[0].Weight = 257 },
		"max fails zero":            func(c *Config) { c.UpstreamPools[0].Endpoints[0].MaxFails = 0 },
		"max fails high":            func(c *Config) { c.UpstreamPools[0].Endpoints[0].MaxFails = 101 },
		"fail timeout low":          func(c *Config) { c.UpstreamPools[0].Endpoints[0].FailTimeoutMS = 999 },
		"fail timeout fractional":   func(c *Config) { c.UpstreamPools[0].Endpoints[0].FailTimeoutMS = 1_500 },
		"fail timeout high":         func(c *Config) { c.UpstreamPools[0].Endpoints[0].FailTimeoutMS = 300_001 },
		"backup without priority":   func(c *Config) { c.UpstreamPools[1].Endpoints[0].Backup = true },
		"partial endpoint priority": func(c *Config) { c.UpstreamPools[1].Endpoints[0].Priority = 1 },
		"duplicate endpoint priority": func(c *Config) {
			c.UpstreamPools[1].Endpoints[0].Priority = 1
			c.UpstreamPools[1].Endpoints[1].Priority = 1
		},
		"endpoint priority gap": func(c *Config) {
			c.UpstreamPools[1].Endpoints[0].Priority = 1
			c.UpstreamPools[1].Endpoints[1].Priority = 3
		},
		"primary after backup": func(c *Config) {
			c.UpstreamPools[1].Endpoints[0].Priority = 1
			c.UpstreamPools[1].Endpoints[0].Backup = true
			c.UpstreamPools[1].Endpoints[1].Priority = 2
		},
		"all endpoints backup": func(c *Config) {
			c.UpstreamPools[1].Endpoints[0].Priority = 1
			c.UpstreamPools[1].Endpoints[0].Backup = true
			c.UpstreamPools[1].Endpoints[1].Priority = 2
			c.UpstreamPools[1].Endpoints[1].Backup = true
		},
		"duplicate endpoint": func(c *Config) {
			c.UpstreamPools[1].Endpoints[1] = c.UpstreamPools[1].Endpoints[0]
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			config := validConfig("l4-v1")
			mutate(&config)
			if _, err := Compile(config); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("Compile() error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestCompilePreservesExplicitPrimaryAndBackupOrder(t *testing.T) {
	config := validConfig("ordered-backup")
	config.UpstreamPools[1].Endpoints = []Endpoint{
		{Address: "192.0.2.30", Port: 9000, Weight: 1, MaxFails: 3, FailTimeoutMS: 10_000, Priority: 3, Backup: true},
		{Address: "192.0.2.20", Port: 9000, Weight: 2, MaxFails: 2, FailTimeoutMS: 5_000, Priority: 1},
		{Address: "192.0.2.10", Port: 9000, Weight: 1, MaxFails: 1, FailTimeoutMS: 2_000, Priority: 2},
	}
	first, err := Compile(config)
	if err != nil {
		t.Fatal(err)
	}
	got := first.Config.UpstreamPools[0].Endpoints
	if len(got) != 3 || got[0].Priority != 1 || got[1].Priority != 2 || got[2].Priority != 3 || !got[2].Backup {
		t.Fatalf("normalized endpoint order = %+v", got)
	}
	text := string(first.NginxConfig)
	primaryOne := strings.Index(text, "server 192.0.2.20:9000 weight=2 max_fails=2 fail_timeout=5s;")
	primaryTwo := strings.Index(text, "server 192.0.2.10:9000 weight=1 max_fails=1 fail_timeout=2s;")
	backup := strings.Index(text, "server 192.0.2.30:9000 weight=1 max_fails=3 fail_timeout=10s backup;")
	if primaryOne < 0 || primaryTwo <= primaryOne || backup <= primaryTwo {
		t.Fatalf("primary/backup order was not rendered exactly:\n%s", text)
	}
	reversed := config
	reversed.UpstreamPools = append([]UpstreamPool(nil), config.UpstreamPools...)
	reversed.UpstreamPools[1].Endpoints = append([]Endpoint(nil), config.UpstreamPools[1].Endpoints...)
	reversed.UpstreamPools[1].Endpoints[0], reversed.UpstreamPools[1].Endpoints[2] =
		reversed.UpstreamPools[1].Endpoints[2], reversed.UpstreamPools[1].Endpoints[0]
	second, err := Compile(reversed)
	if err != nil || second.Digest != first.Digest || !reflect.DeepEqual(second.NginxConfig, first.NginxConfig) {
		t.Fatalf("reordered explicit endpoints changed output: digest=%q error=%v", second.Digest, err)
	}
}

func TestCompileRejectsOverlappingBindsButAllowsTCPAndUDPToSharePort(t *testing.T) {
	listener := func(id string, protocol Protocol, address string, port int) Listener {
		return Listener{
			ID: id, Protocol: protocol, Address: address, Port: port, UpstreamPoolID: "pool-v4",
			ConnectTimeoutMS: 100, IdleTimeoutMS: 1_000, MaxConnectionsPerClient: 10,
		}
	}
	for _, test := range []struct {
		name      string
		listeners []Listener
	}{
		{
			name: "exact duplicate concrete bind",
			listeners: []Listener{
				listener("tcp-specific-first", ProtocolTCP, "127.0.0.1", 443),
				listener("tcp-specific-second", ProtocolTCP, "127.0.0.1", 443),
			},
		},
		{
			name: "IPv4 interleaved wildcard then specific",
			listeners: []Listener{
				listener("tcp-v4-any-443", ProtocolTCP, "0.0.0.0", 443),
				listener("tcp-v4-any-8443", ProtocolTCP, "0.0.0.0", 8443),
				listener("tcp-v4-specific-443", ProtocolTCP, "127.0.0.1", 443),
			},
		},
		{
			name: "IPv4 interleaved reverse input",
			listeners: []Listener{
				listener("tcp-v4-specific-443", ProtocolTCP, "127.0.0.1", 443),
				listener("tcp-v4-any-8443", ProtocolTCP, "0.0.0.0", 8443),
				listener("tcp-v4-any-443", ProtocolTCP, "0.0.0.0", 443),
			},
		},
		{
			name: "IPv6 interleaved wildcard then specific",
			listeners: []Listener{
				listener("tcp-v6-any-443", ProtocolTCP, "::", 443),
				listener("tcp-v6-any-8443", ProtocolTCP, "::", 8443),
				listener("tcp-v6-specific-443", ProtocolTCP, "::1", 443),
			},
		},
		{
			name: "IPv6 interleaved reverse input",
			listeners: []Listener{
				listener("tcp-v6-specific-443", ProtocolTCP, "::1", 443),
				listener("tcp-v6-any-8443", ProtocolTCP, "::", 8443),
				listener("tcp-v6-any-443", ProtocolTCP, "::", 443),
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := validConfig("l4-v1")
			config.Listeners = test.listeners
			if _, err := Compile(config); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("Compile(overlap) error = %v, want ErrInvalidConfig", err)
			}
		})
	}

	for _, test := range []struct {
		name      string
		listeners []Listener
	}{
		{
			name: "TCP and UDP same port",
			listeners: []Listener{
				listener("tcp-v4", ProtocolTCP, "0.0.0.0", 443),
				listener("udp-v4", ProtocolUDP, "0.0.0.0", 443),
			},
		},
		{
			name: "IPv4 and IPv6 same port",
			listeners: []Listener{
				listener("tcp-v4", ProtocolTCP, "0.0.0.0", 443),
				listener("tcp-v6", ProtocolTCP, "::", 443),
			},
		},
		{
			name: "same protocol different ports",
			listeners: []Listener{
				listener("tcp-443", ProtocolTCP, "0.0.0.0", 443),
				listener("tcp-8443", ProtocolTCP, "0.0.0.0", 8443),
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := validConfig("l4-v1")
			config.Listeners = test.listeners
			if _, err := Compile(config); err != nil {
				t.Fatalf("Compile(non-overlap) error = %v", err)
			}
		})
	}
}

func TestCompilePreservesCanonicalListenerOrderingAcrossOverlapValidation(t *testing.T) {
	specific := Listener{ID: "tcp-specific-443", Protocol: ProtocolTCP, Address: "127.0.0.1", Port: 443, UpstreamPoolID: "pool-v4", ConnectTimeoutMS: 100, IdleTimeoutMS: 1_000, MaxConnectionsPerClient: 10}
	wildcard := Listener{ID: "tcp-wildcard-8443", Protocol: ProtocolTCP, Address: "0.0.0.0", Port: 8443, UpstreamPoolID: "pool-v4", ConnectTimeoutMS: 100, IdleTimeoutMS: 1_000, MaxConnectionsPerClient: 10}
	for _, listeners := range [][]Listener{{specific, wildcard}, {wildcard, specific}} {
		config := validConfig("l4-v1")
		config.Listeners = listeners
		compiled, err := Compile(config)
		if err != nil {
			t.Fatalf("Compile() error = %v", err)
		}
		got := compiled.Config.Listeners
		if len(got) != 2 || got[0].ID != wildcard.ID || got[1].ID != specific.ID {
			t.Fatalf("canonical listener order = %+v, want wildcard-8443 then specific-443", got)
		}
	}
}

func TestInternalNamesAreStableAcrossConfigurationOrdering(t *testing.T) {
	poolName := internalName("l4_upstream", "pool-v4")
	if poolName != internalName("l4_upstream", "pool-v4") {
		t.Fatal("internal names are not deterministic")
	}
	if poolName == internalName("l4_upstream", "pool-v6") || strings.Contains(poolName, "pool-v4") {
		t.Fatalf("internal names expose IDs or collide: pool=%q", poolName)
	}
	compiled, err := Compile(validConfig("l4-v1"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(compiled.NginxConfig)
	if !strings.Contains(text, "upstream "+poolName) || !strings.Contains(text, "zone "+poolName+" 64k") ||
		!strings.Contains(text, "zone=l4_limit_clients:16m") {
		t.Fatalf("generated configuration does not use stable internal names:\n%s", text)
	}
}
