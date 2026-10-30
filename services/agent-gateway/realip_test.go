package gateway

import (
	"crypto/tls"
	"net/http"
	"net/netip"
	"testing"
	"time"
)

// Ported from tests/gateway-cdn-poc/realip_test.go (ADR 0013 §4.4, 7 cases).
func TestClientIPRules(t *testing.T) {
	ranges, err := ParseTrustedProxyRanges("173.245.48.0/20=CF-Connecting-IP, 10.0.0.0/8=X-Forwarded-For\n# comment\n127.0.0.1/32")
	if err != nil {
		t.Fatal(err)
	}
	trusted := NewTrustedProxies(ranges)
	for _, tc := range []struct {
		name, remote string
		header       http.Header
		ip, source   string
	}{
		{"direct peer ignores forged header", "203.0.113.7:5000", http.Header{"X-Forwarded-For": {"198.51.100.1"}}, "203.0.113.7", PeerIPSourceTCP},
		{"cloudflare header", "173.245.48.10:443", http.Header{"Cf-Connecting-Ip": {"198.51.100.2"}}, "198.51.100.2", PeerIPSourceTrustedProxy},
		{"cloudflare ignores xff", "173.245.48.10:443", http.Header{"X-Forwarded-For": {"198.51.100.3"}}, "173.245.48.10", PeerIPSourceTCP},
		{"xff rightmost untrusted", "10.1.2.3:443", http.Header{"X-Forwarded-For": {"203.0.113.9, 198.51.100.4, 10.9.9.9"}}, "198.51.100.4", PeerIPSourceTrustedProxy},
		{"xff malformed hop stops", "10.1.2.3:443", http.Header{"X-Forwarded-For": {"198.51.100.5, garbage"}}, "10.1.2.3", PeerIPSourceTCP},
		{"xff all trusted", "10.1.2.3:443", http.Header{"X-Forwarded-For": {"10.4.4.4"}}, "10.1.2.3", PeerIPSourceTCP},
		{"bare cidr binds xff", "127.0.0.1:443", http.Header{"X-Forwarded-For": {"203.0.113.9, 172.17.0.1"}}, "172.17.0.1", PeerIPSourceTrustedProxy},
	} {
		ip, source, err := trusted.ClientIP(tc.remote, tc.header)
		if err != nil || ip.String() != tc.ip || source != tc.source {
			t.Errorf("%s: got %v %s %v, want %s %s", tc.name, ip, source, err, tc.ip, tc.source)
		}
	}
	if _, err := ParseTrustedProxyRanges("not-a-cidr=X-Forwarded-For"); err == nil {
		t.Fatal("invalid range accepted")
	}
	var empty TrustedProxies
	if ip, source, _ := empty.ClientIP("173.245.48.10:1", http.Header{"Cf-Connecting-Ip": {"198.51.100.2"}}); ip.String() != "173.245.48.10" || source != PeerIPSourceTCP {
		t.Fatal("zero TrustedProxies trusted a header")
	}
}

func TestDefaultTrustedProxiesAreCloudflareOnly(t *testing.T) {
	ranges, err := ParseTrustedProxyRanges(DefaultTrustedProxies)
	if err != nil {
		t.Fatal(err)
	}
	if len(ranges) < 20 {
		t.Fatalf("default list has %d ranges", len(ranges))
	}
	for _, r := range ranges {
		if r.Header != "Cf-Connecting-Ip" {
			t.Fatalf("default range %s bound to %s", r.Prefix, r.Header)
		}
	}
	if _, ok := trustedRangeFor(netip.MustParseAddr("2606:4700::1"), ranges); !ok {
		t.Fatal("Cloudflare IPv6 range missing")
	}
}

// A tunnel through a trusted proxy hands gRPC the forwarded address and
// source; GatewayHello echoes it (ADR 0013 §4.4 point 3).
func TestTunnelPeerAddressCarriesTrustedProxySource(t *testing.T) {
	ranges, _ := ParseTrustedProxyRanges("127.0.0.1/32=X-Forwarded-For")
	g := startSharedTestServers(t, NewTrustedProxies(ranges).RealIP)
	header := g.node.token(testTunnelAudience, TunnelPath, time.Now(), randomNonce(t))
	header.Set("X-Forwarded-For", "203.0.113.9, 198.51.100.77")
	inner := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "localhost", RootCAs: g.pki.rootPool, Certificates: []tls.Certificate{g.node.certificate}}
	connection, _, err := g.tunnelConnection(t, g.agent, TunnelPath, header, inner)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	hello := connectHello(t, connection)
	if hello.GetObservedPeerIp() != "198.51.100.77" {
		t.Fatalf("observed peer = %q", hello.GetObservedPeerIp())
	}
	// Direct sessions echo the TCP peer and never read headers.
	direct := dialGateway(t, g.agent, g.pki.rootPool, g.node.certificate)
	defer direct.Close()
	directHello := connectHello(t, direct)
	if got := directHello.GetObservedPeerIp(); got != "127.0.0.1" {
		t.Fatalf("direct observed peer = %q", got)
	}
	// A08: the node owner from the control plane's authorization reaches the
	// Agent, which gates tenant host firewall rules on it.
	if got := directHello.GetNodeOwnerScopeId(); got != testNodeOwnerScopeID {
		t.Fatalf("hello node owner = %q, want %q", got, testNodeOwnerScopeID)
	}
}
