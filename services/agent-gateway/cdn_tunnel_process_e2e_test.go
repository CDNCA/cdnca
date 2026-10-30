package gateway

// Gateway half of tests/gateway-cdn-e2e/run.sh (GW-03, ADR 0013 §4.2): the
// production Connect service behind the production shared-port TunnelRouter
// and TrustedProxies, with an OpenResty container in front acting as a CDN
// (own edge certificate, WebSocket back to this port). The node half dials
// the CDN only. Writes gateway.json for the node half and sessions.json
// (sessions, heartbeats, last observed peer address and its source).

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/grpc"
)

type cdnE2ESink struct {
	mu         sync.Mutex
	heartbeats int
}

func (s *cdnE2ESink) PersistHeartbeat(context.Context, string, *agentv1.Heartbeat) error {
	s.mu.Lock()
	s.heartbeats++
	s.mu.Unlock()
	return nil
}

type cdnE2EGatewayFixture struct {
	e2eGatewayFixture
	TunnelAudience string `json:"tunnel_audience"`
	// GatewayPort is the shared port the CDN pulls from.
	GatewayPort int `json:"gateway_port"`
}

type cdnE2ESessions struct {
	Sessions   int    `json:"sessions"`
	Heartbeats int    `json:"heartbeats"`
	PeerIP     string `json:"peer_ip"`
	PeerSource string `json:"peer_source"`
}

func TestGatewayCDNProcess(t *testing.T) {
	directory, trusted := os.Getenv("GATEWAY_CDN_E2E_DIR"), os.Getenv("GATEWAY_CDN_E2E_TRUSTED")
	if directory == "" || trusted == "" {
		t.Skip("GATEWAY_CDN_E2E_DIR and GATEWAY_CDN_E2E_TRUSTED are not set; run tests/gateway-cdn-e2e/run.sh")
	}
	ranges, err := ParseTrustedProxyRanges(trusted)
	if err != nil {
		t.Fatal(err)
	}
	proxies := NewTrustedProxies(ranges)
	pki := newTestPKI(t)
	now := time.Now()
	node := pki.ed25519Node(t, 71, testNodeID, now.Add(-time.Hour), now.Add(2*time.Hour))
	sink := &cdnE2ESink{}
	config := DefaultConfig()
	config.GatewayInstanceID, config.GatewayVersion = "gateway-cdn-e2e", "e2e"
	config.HeartbeatInterval = time.Second
	service, err := NewWithDurableMessaging(config, defaultFakeControl(), NewMemorySessionCoordinator(), &fakeCommandBus{}, sink)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	report := cdnE2ESessions{}
	write := func() {
		sink.mu.Lock()
		report.Heartbeats = sink.heartbeats
		sink.mu.Unlock()
		encoded, _ := json.Marshal(report)
		_ = os.WriteFile(filepath.Join(directory, "sessions.json.tmp"), encoded, 0o600)
		_ = os.Rename(filepath.Join(directory, "sessions.json.tmp"), filepath.Join(directory, "sessions.json"))
	}
	servers, err := NewServers(service, &tls.Config{Certificates: []tls.Certificate{pki.server}},
		&tls.Config{Certificates: []tls.Certificate{pki.server}, ClientCAs: pki.rootPool},
		grpc.ChainStreamInterceptor(func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
			if info.FullMethod == agentv1.AgentGatewayService_Connect_FullMethodName {
				addr, source, _ := peerAddress(stream.Context())
				mu.Lock()
				report.Sessions++
				report.PeerIP, report.PeerSource = addr.String(), source
				write()
				mu.Unlock()
			}
			return handler(srv, stream)
		}))
	if err != nil {
		t.Fatal(err)
	}
	router, err := NewTunnelRouter(TunnelRouterConfig{Certificate: pki.server, NodeCAs: pki.rootPool,
		Audience: testTunnelAudience, Nonces: NewMemoryTunnelNonceStore(), RealIP: proxies.RealIP, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	// All interfaces: the CDN container reaches the host through Docker.
	raw, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = servers.MTLS.Serve(router.Listen(raw, SharedListenerAgent)) }()
	defer func() { servers.MTLS.Stop(); _ = router.Close() }()

	identity := filepath.Join(directory, "gateway-identity")
	if err := os.Mkdir(identity, 0o700); err != nil {
		t.Fatal(err)
	}
	writePEM := func(name, kind string, der []byte, mode os.FileMode) string {
		path := filepath.Join(identity, name)
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	key, err := x509.MarshalPKCS8PrivateKey(node.key)
	if err != nil {
		t.Fatal(err)
	}
	fixture := cdnE2EGatewayFixture{e2eGatewayFixture: e2eGatewayFixture{ServerName: "localhost",
		RootCAFile:            writePEM("ca.pem", "CERTIFICATE", pki.caCertificate.Raw, 0o600),
		ClientCertificateFile: writePEM("client.pem", "CERTIFICATE", node.leaf.Raw, 0o600),
		ClientPrivateKeyFile:  writePEM("client-key.pem", "PRIVATE KEY", key, 0o600),
		NodeID:                testNodeID, ArtifactKeyID: "artifact-key"},
		TunnelAudience: testTunnelAudience, GatewayPort: raw.Addr().(*net.TCPAddr).Port}
	// The CDN verifies the origin against the same root (proxy_ssl_verify)
	// and presents its own edge certificate (cdn.e2e.test); the node trusts
	// it through the installation root it adds to the system roots.
	edge := pki.issue(t, 72, "cdn.e2e.test", nil, now.Add(-time.Hour), now.Add(2*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	edgeKey, err := x509.MarshalPKCS8PrivateKey(edge.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	cdn := filepath.Join(directory, "cdn")
	for name, block := range map[string]*pem.Block{"origin-ca.pem": {Type: "CERTIFICATE", Bytes: pki.caCertificate.Raw},
		"edge.pem": {Type: "CERTIFICATE", Bytes: edge.Certificate[0]}, "edge-key.pem": {Type: "PRIVATE KEY", Bytes: edgeKey}} {
		if err := os.WriteFile(filepath.Join(cdn, name), pem.EncodeToMemory(block), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	encoded, _ := json.Marshal(fixture)
	if err := os.WriteFile(filepath.Join(directory, "gateway.json.tmp"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(directory, "gateway.json.tmp"), filepath.Join(directory, "gateway.json")); err != nil {
		t.Fatal(err)
	}
	t.Logf("gateway shared port %d behind the CDN; trusted %s", fixture.GatewayPort, trusted)
	deadline := time.Now().Add(10 * time.Minute)
	for {
		mu.Lock()
		write()
		mu.Unlock()
		if _, err := os.Stat(filepath.Join(directory, "finished")); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("node half did not finish")
		}
		time.Sleep(200 * time.Millisecond)
	}
}
