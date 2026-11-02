package gatewayregistry

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const pin = "upgrade_trust_sha256=" + "c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00"

func TestNodeGatewayDefaultsPrefersTheWebSocketEntry(t *testing.T) {
	local := Entrypoint{Address: "gw.example:20407", ServerName: "gw.example", Transport: TransportGRPC, EnrollmentAddress: "gw.example:29402"}
	ws := Entrypoint{Address: "gw.example:443", ServerName: "gw.example", Transport: TransportWS, TunnelHost: "gw.example"}
	d, ok := NodeGatewayDefaultsFor([]Entrypoint{local, ws}, local)
	if !ok {
		t.Fatal("no defaults")
	}
	lines, err := d.Lines()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"gateway_enrollment_address=gw.example:443", "gateway_address=gw.example:443", "gateway_server_name=gw.example",
		"gateway_transport=ws", "gateway_tunnel_host=gw.example", "gateway_endpoints=gw.example:20407|gw.example|grpc"}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("lines =\n%s", strings.Join(lines, "\n"))
	}
}

func TestNodeGatewayDefaultsDirectOnly(t *testing.T) {
	local := Entrypoint{Address: "203.0.113.20:20407", ServerName: "203.0.113.20", Transport: TransportGRPC, EnrollmentAddress: "203.0.113.20:29402"}
	d, _ := NodeGatewayDefaultsFor([]Entrypoint{local}, local)
	lines, _ := d.Lines()
	if strings.Join(lines, "\n") != "gateway_enrollment_address=203.0.113.20:29402\ngateway_address=203.0.113.20:20407\ngateway_server_name=203.0.113.20" {
		t.Fatalf("lines = %q", lines)
	}
	if _, ok := NodeGatewayDefaultsFor(nil, Entrypoint{}); ok {
		t.Fatal("an empty list must not publish defaults")
	}
}

func TestWriteNodeGatewayDefaultsReplacesOnlyTheGatewayLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node-install-defaults")
	old := pin + "\ngateway_enrollment_address=a:1\ngateway_address=a:2\ngateway_server_name=a\ngateway_transport=ws\ngateway_tunnel_host=a\ndownload_fallback_origin=https://auth.example\n"
	if err := os.WriteFile(path, []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	d := NodeGatewayDefaults{EnrollmentAddress: "b:9", Address: "b:8", ServerName: "b", Transport: TransportGRPC}
	changed, err := WriteNodeGatewayDefaults(path, d)
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	got, _ := os.ReadFile(path)
	want := pin + "\ngateway_enrollment_address=b:9\ngateway_address=b:8\ngateway_server_name=b\ndownload_fallback_origin=https://auth.example\n"
	if string(got) != want {
		t.Fatalf("file =\n%s", got)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v", info.Mode())
	}
	if changed, err := WriteNodeGatewayDefaults(path, d); err != nil || changed {
		t.Fatalf("second write changed=%v err=%v", changed, err)
	}
	if changed, err := WriteNodeGatewayDefaults(filepath.Join(t.TempDir(), "missing"), d); err != nil || changed {
		t.Fatalf("missing file changed=%v err=%v", changed, err)
	}
	if _, err := WriteNodeGatewayDefaults(path, NodeGatewayDefaults{Address: "bad", ServerName: "b", Transport: "x"}); err == nil {
		t.Fatal("invalid defaults must be refused")
	}
	if parsed := ParseNodeGatewayDefaults([]byte(old)); parsed.Transport != TransportWS || parsed.TunnelHost != "a" || parsed.EnrollmentAddress != "a:1" {
		t.Fatalf("parsed = %+v", parsed)
	}
}

func TestDirectNodeInstallGatewayMatchesTheDefaultsAndSkipsWebSocket(t *testing.T) {
	local := Entrypoint{Address: "203.0.113.20:20407", ServerName: "203.0.113.20", Transport: TransportGRPC, EnrollmentAddress: "203.0.113.20:29402"}
	d, ok := DirectNodeInstallGateway([]Entrypoint{local}, local)
	if !ok || d.EnrollmentAddress != "203.0.113.20:29402" || d.Address != "203.0.113.20:20407" || d.ServerName != "203.0.113.20" {
		t.Fatalf("direct = %+v ok=%v", d, ok)
	}
	ws := Entrypoint{Address: "cdn.example:443", ServerName: "gw.example", Transport: TransportWS, TunnelHost: "cdn.example"}
	if _, ok := DirectNodeInstallGateway([]Entrypoint{local, ws}, local); ok {
		t.Fatal("a ws console keeps the command without gateway arguments")
	}
	if _, ok := DirectNodeInstallGateway(nil, local); ok {
		t.Fatal("nothing published")
	}
	if _, ok := DirectNodeInstallGateway([]Entrypoint{{Address: "bad host:1", ServerName: "x"}}, Entrypoint{}); ok {
		t.Fatal("invalid entry accepted")
	}
	var none *Service
	if _, ok, err := none.NodeInstallGateway(t.Context()); ok || err != nil {
		t.Fatal("nil service")
	}
}

func TestMoveLocalGatewayKeepsTheCDNEntry(t *testing.T) {
	old := Entrypoint{Address: "203.0.113.20:20407", ServerName: "203.0.113.20", EnrollmentAddress: "203.0.113.20:29402"}
	updated := Entrypoint{Address: "gw.example:20407", ServerName: "gw.example", EnrollmentAddress: "gw.example:29402"}
	direct := NodeGatewayDefaults{EnrollmentAddress: old.EnrollmentAddress, Address: old.Address, ServerName: old.ServerName, Transport: TransportGRPC}
	if got := direct.MoveLocalGateway(old, updated); got.Address != updated.Address || got.EnrollmentAddress != updated.EnrollmentAddress || got.ServerName != "gw.example" {
		t.Fatalf("direct = %+v", got)
	}
	ws := NodeGatewayDefaults{EnrollmentAddress: "cdn.example:443", Address: "cdn.example:443", ServerName: "cdn.example", Transport: TransportWS,
		Endpoints: []Entrypoint{{Address: old.Address, ServerName: old.ServerName, Transport: TransportGRPC}}}
	got := ws.MoveLocalGateway(old, updated)
	if got.Address != "cdn.example:443" || got.Endpoints[0].Address != updated.Address || got.Endpoints[0].ServerName != "gw.example" {
		t.Fatalf("ws = %+v", got)
	}
}

// 11-02 (73): gateway.cdnca.com resolves into Cloudflare, which forwards
// neither 29402 nor 20407; nodes are told the 443 tunnel first, exactly the
// lines install-control.sh writes for a ws install.
func TestWithCDNTunnelPutsTheWebSocketTunnelFirst(t *testing.T) {
	local := Entrypoint{Address: "gateway.cdnca.com:20407", ServerName: "gateway.cdnca.com", Transport: TransportGRPC,
		EnrollmentAddress: "gateway.cdnca.com:29402"}
	endpoints := WithCDNTunnel([]Entrypoint{local}, local, true)
	d, ok := NodeGatewayDefaultsFor(endpoints, local)
	lines, err := d.Lines()
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	want := []string{"gateway_enrollment_address=gateway.cdnca.com:443", "gateway_address=gateway.cdnca.com:443",
		"gateway_server_name=gateway.cdnca.com", "gateway_transport=ws", "gateway_tunnel_host=gateway.cdnca.com",
		"gateway_endpoints=gateway.cdnca.com:20407|gateway.cdnca.com|grpc"}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("lines =\n%s", strings.Join(lines, "\n"))
	}
	// The copied / SSH command then passes no direct entry (node-install-defaults decides).
	if _, ok := DirectNodeInstallGateway(endpoints, local); ok {
		t.Fatal("a CDN Gateway must not hand out the direct entry")
	}
	// Not behind a CDN, or a ws entry already published: unchanged.
	if got := WithCDNTunnel([]Entrypoint{local}, local, false); len(got) != 1 || got[0] != local {
		t.Fatalf("direct = %+v", got)
	}
	page := Entrypoint{Address: "edge.example.com:443", ServerName: "gateway.cdnca.com", Transport: TransportWS, TunnelHost: "edge.example.com"}
	if got := WithCDNTunnel([]Entrypoint{local, page}, local, true); len(got) != 2 || got[1] != page {
		t.Fatalf("published ws = %+v", got)
	}
	if got := WithCDNTunnel(nil, local, true); got != nil {
		t.Fatalf("empty = %+v", got)
	}
}
