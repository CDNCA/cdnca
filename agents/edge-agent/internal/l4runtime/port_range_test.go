package l4runtime

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// portRangeSpec is a plain TCP stream on 20000-20999 that follows the client's
// port to an address origin.
func portRangeSpec() StreamRuntimeSpecV2 {
	spec := l403StreamSpec()
	spec.ProxyProtocolInbound, spec.ProxyProtocolOutbound = false, false
	spec.Geo = GeoPolicyV2{TenantID: l403Tenant, StreamID: l403Stream, Revision: 7, UnknownRegionAction: GeoActionAllow}
	spec.Listener = ListenerSocketV2{Protocol: ProtocolTCP, Address: "0.0.0.0", Port: 20000, PortEnd: 20999}
	spec.Endpoint, spec.DNS = EndpointV2{Address: "8.8.8.8", Port: 20000, FollowPort: true}, DNSPolicyV2{}
	return spec
}

// port_end / follow_port (tcp/udp v9) ride from the stream spec through the
// aggregate; unset they leave the canonical bytes and nginx.conf unchanged.
func TestPortRangeIsOptionalAndCarried(t *testing.T) {
	base, err := AggregateStreamRuntimeSpecsV2("l403-revision-7", 7, []StreamRuntimeSpecV2{l403StreamSpec()})
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := CanonicalV2(base)
	if err != nil {
		t.Fatal(err)
	}
	plain := mustCompileV2(t, base)
	if bytes.Contains(canonical, []byte("port_end")) || bytes.Contains(canonical, []byte("follow_port")) ||
		bytes.Contains(plain.NginxConfig, []byte("balancer_by_lua")) {
		t.Fatalf("unset range changed the release:\n%s\n%s", canonical, plain.NginxConfig)
	}
	config, err := AggregateStreamRuntimeSpecsV2("l403-revision-7", 7, []StreamRuntimeSpecV2{portRangeSpec()})
	if err != nil {
		t.Fatal(err)
	}
	canonical, err = CanonicalV2(config)
	if err != nil || !bytes.Contains(canonical, []byte(`"port":20000,"port_end":20999,`)) ||
		!bytes.Contains(canonical, []byte(`"port":20000,"follow_port":true}`)) {
		t.Fatalf("range not carried: %s %v", canonical, err)
	}
}

func TestPortRangeRejectsInvalidStreams(t *testing.T) {
	for name, change := range map[string]func(*StreamRuntimeSpecV2){
		"end equals start": func(s *StreamRuntimeSpecV2) { s.Listener.PortEnd = s.Listener.Port },
		"over 1000 ports":  func(s *StreamRuntimeSpecV2) { s.Listener.PortEnd = 21000 },
		"covers 443":       func(s *StreamRuntimeSpecV2) { s.Listener.Port, s.Listener.PortEnd, s.Endpoint.Port = 400, 500, 400 },
		"follow mismatch":  func(s *StreamRuntimeSpecV2) { s.Endpoint.Port = 9000 },
		"extra over 1000": func(s *StreamRuntimeSpecV2) {
			s.AdditionalListeners = []AdditionalListenerV2{{ID: "44444444-4444-4444-8444-444444444444", Protocol: ProtocolUDP, Address: "*", Port: 1000, PortEnd: 2000}}
		},
		"extra overlaps range": func(s *StreamRuntimeSpecV2) {
			s.AdditionalListeners = []AdditionalListenerV2{{ID: "44444444-4444-4444-8444-444444444444", Protocol: ProtocolTCP, Address: "*", Port: 20500}}
		},
		"passthrough range": func(s *StreamRuntimeSpecV2) { s.TLSPassthrough, s.ServerNames = true, []string{"a.example.com"} },
	} {
		spec := portRangeSpec()
		change(&spec)
		if _, err := AggregateStreamRuntimeSpecsV2("l403-revision-7", 7, []StreamRuntimeSpecV2{spec}); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("%s accepted: %v", name, err)
		}
	}
	// Another stream inside the range, and a website hand-over inside it.
	other := l403StreamSpec()
	other.StreamID, other.Geo.StreamID = "66666666-6666-4666-8666-666666666666", "66666666-6666-4666-8666-666666666666"
	other.Listener.Port = 20999
	if _, err := AggregateStreamRuntimeSpecsV2("l403-revision-7", 7, []StreamRuntimeSpecV2{portRangeSpec(), other}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("stream inside a range accepted: %v", err)
	}
	other.Listener.Protocol = ProtocolUDP
	other.ProxyProtocolInbound, other.ProxyProtocolOutbound = false, false
	other.Geo = GeoPolicyV2{TenantID: l403Tenant, StreamID: other.StreamID, Revision: 7, UnknownRegionAction: GeoActionAllow}
	if _, err := AggregateStreamRuntimeSpecsV2("l403-revision-7", 7, []StreamRuntimeSpecV2{portRangeSpec(), other}); err != nil {
		t.Fatalf("UDP stream inside a TCP range refused: %v", err)
	}
	site := SiteSocketsV2{Port: 20100, PlainSocket: "/var/lib/cdnca-edge/shared/l4mux/site-plain.sock"}
	if _, err := AggregateStreamRuntimeSpecsV2("l403-revision-7", 7, []StreamRuntimeSpecV2{portRangeSpec()}, site); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("website hand-over inside a range accepted: %v", err)
	}
}

// A range listens on every port with one directive; follow_port connects to
// the resolved origin addresses on the client's port through a balancer, and
// the telemetry directory is the range's first port.
func TestPortRangeRendersListenAndFollowPortBalancer(t *testing.T) {
	spec := portRangeSpec()
	spec.Endpoint = EndpointV2{Host: "origin.example.com", Port: 20000, FollowPort: true}
	spec.DNS = DNSPolicyV2{PositiveMinTTLSeconds: 5, PositiveMaxTTLSeconds: 300, NegativeTTLSeconds: 10, StaleIfErrorSeconds: 900}
	spec.AdditionalListeners = []AdditionalListenerV2{{ID: "44444444-4444-4444-8444-444444444444", Protocol: ProtocolUDP, Address: "*", Port: 30000, PortEnd: 30009}}
	config, err := AggregateStreamRuntimeSpecsV2("l403-revision-7", 7, []StreamRuntimeSpecV2{spec})
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := CompileV2(config, map[string][]netip.Addr{l403Stream: {netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("2606:4700::1111")}})
	if err != nil {
		t.Fatal(err)
	}
	nginx := string(compiled.NginxConfig)
	for _, want := range []string{
		"        listen 0.0.0.0:20000-20999;\n",
		"        listen 0.0.0.0:30000-30009 udp;\n",
		"        server 0.0.0.1:1;\n",
		`local peers = {"8.8.8.8", "[2606:4700::1111]"}`,
		"tonumber(ngx.var.server_port) or tonumber(ngx.var.proxy_protocol_server_port)",
		"balancer.set_more_tries(#peers - 1)",
		"        proxy_next_upstream_tries 2;\n",
		// v12: the stream is its own telemetry partition (no website).
		"/" + l403Stream + "/20000/stream-" + l403Stream + "--listener-" + l403Stream + "--tcp--",
		"/" + l403Stream + "/30000/stream-" + l403Stream + "--listener-44444444-4444-4444-8444-444444444444--udp--",
	} {
		if !strings.Contains(nginx, want) {
			t.Fatalf("missing %q:\n%s", want, nginx)
		}
	}
	if strings.Contains(nginx, "server 8.8.8.8:20000;") || strings.Contains(nginx, "zone l4_v2_upstream") {
		t.Fatalf("follow_port upstream still lists fixed-port servers:\n%s", nginx)
	}
	// Without follow_port a range still connects to the one origin port.
	spec.Endpoint.FollowPort = false
	config, err = AggregateStreamRuntimeSpecsV2("l403-revision-7", 7, []StreamRuntimeSpecV2{spec})
	if err != nil {
		t.Fatal(err)
	}
	nginx = string(mustCompileV2(t, config).NginxConfig)
	if !strings.Contains(nginx, "        server 8.8.8.8:20000;\n") || strings.Contains(nginx, "balancer_by_lua") {
		t.Fatalf("fixed-port range upstream:\n%s", nginx)
	}
}

// Every port of a range is probed; a busy port inside it fails the listener.
func TestPrecheckProbesEveryPortOfARange(t *testing.T) {
	holder, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	busy := holder.Addr().(*net.TCPAddr).Port
	start := max(busy-3, 1024)
	listener := Listener{ID: "range", Protocol: ProtocolTCP, Address: "127.0.0.1", Port: start, PortEnd: busy + 3}
	controller, candidate := testPortPrecheck(t, Config{Listeners: []Listener{listener}}, nil)
	assertListenerPrecheckFailure(t, controller.Precheck(context.Background(), candidate), "range", "LISTENER_PORT_CONFLICT")
	// The active runtime owning the busy port is not a conflict.
	active := Listener{ID: "active", Protocol: ProtocolTCP, Address: "127.0.0.1", Port: busy}
	controller, candidate = testPortPrecheck(t, Config{Listeners: []Listener{listener}}, &Config{Listeners: []Listener{active}})
	if err := controller.Precheck(context.Background(), candidate); err != nil && !strings.Contains(err.Error(), "LISTENER_PORT") {
		t.Fatalf("Precheck() error = %v", err)
	} else if err != nil {
		// Another process may hold a neighbouring port; only the busy one is ours.
		t.Skipf("neighbouring port busy: %v", err)
	}
}

func TestLiveSocketsCarryRanges(t *testing.T) {
	config, err := AggregateStreamRuntimeSpecsV2("l403-revision-7", 7, []StreamRuntimeSpecV2{portRangeSpec()})
	if err != nil {
		t.Fatal(err)
	}
	sockets, stream, err := LiveSocketsV2(config, l403Stream)
	if err != nil || stream == nil || len(sockets) != 1 || sockets[0].Port != 20000 || sockets[0].PortEnd != 20999 || sockets[0].Shared {
		t.Fatalf("live sockets %+v %v", sockets, err)
	}
}

// L4F-E01：跟随端口 + 定源（ip_hash）首个目标必须由客户端地址决定，不能按连接号轮换；
// 轮询仍按连接号。
func TestFollowPortBalancerKeepsIPHash(t *testing.T) {
	addresses := map[string][]netip.Addr{l403Stream: {netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("9.9.9.9")}}
	render := func(balance string) string {
		spec := portRangeSpec()
		spec.Endpoint = EndpointV2{Host: "origin.example.com", Port: 20000, FollowPort: true, Balance: balance}
		spec.DNS = DNSPolicyV2{PositiveMinTTLSeconds: 5, PositiveMaxTTLSeconds: 300, NegativeTTLSeconds: 10, StaleIfErrorSeconds: 900}
		config, err := AggregateStreamRuntimeSpecsV2("l403-revision-7", 7, []StreamRuntimeSpecV2{spec})
		if err != nil {
			t.Fatal(err)
		}
		compiled, err := CompileV2(config, addresses)
		if err != nil {
			t.Fatal(err)
		}
		return string(compiled.NginxConfig)
	}
	hashed := render(edgeconfig.L4BalanceIPHash)
	if !strings.Contains(hashed, "local first = ngx.crc32_long(ngx.var.remote_addr)") ||
		strings.Contains(hashed, "local first = tonumber(ngx.var.connection)") ||
		!strings.Contains(hashed, "local peer = peers[(first + try - 1) % #peers + 1]") {
		t.Fatalf("follow_port ip_hash balancer:\n%s", hashed)
	}
	roundRobin := render("")
	if !strings.Contains(roundRobin, "local first = tonumber(ngx.var.connection)") || strings.Contains(roundRobin, "crc32_long") {
		t.Fatalf("follow_port round robin balancer:\n%s", roundRobin)
	}
}
