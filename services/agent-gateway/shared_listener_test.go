package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/gorilla/websocket"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

const testTunnelAudience = "6f1c2a4e-8d3b-4c5a-9e7f-0a1b2c3d4e5f"

// Same vector as edge-agent internal/gatewaytunnel TestSignedTextVector.
func TestTunnelSignedTextVector(t *testing.T) {
	got := tunnelSignedText("aud", TunnelPath, testNodeID, "1a", 1700000000, "00112233445566778899aabbccddeeff")
	want := "cdnca-gw-auth-v1\naud\n/agent/v1/tunnel\n" + testNodeID + "\n1a\n1700000000\n00112233445566778899aabbccddeeff"
	if string(got) != want {
		t.Fatalf("signed text = %q", got)
	}
}

type ed25519Node struct {
	leaf        *x509.Certificate
	key         ed25519.PrivateKey
	certificate tls.Certificate
}

func (p *testPKI) ed25519Node(t *testing.T, serial int64, nodeID string, notBefore, notAfter time.Time) ed25519Node {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, _ := url.Parse(nodeSPIFFEPrefix + nodeID)
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "node"},
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{uri}}
	der, err := x509.CreateCertificate(rand.Reader, template, p.caCertificate, public, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return ed25519Node{leaf: leaf, key: private, certificate: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private, Leaf: leaf}}
}

func (n ed25519Node) token(audience, path string, iat time.Time, nonce string) http.Header {
	nodeID := strings.TrimPrefix(n.leaf.URIs[0].String(), nodeSPIFFEPrefix)
	signature := ed25519.Sign(n.key, tunnelSignedText(audience, path, nodeID, n.leaf.SerialNumber.Text(16), iat.Unix(), nonce))
	header := http.Header{}
	header.Set(TunnelNodeCertificateHeader, base64.StdEncoding.EncodeToString(n.leaf.Raw))
	header.Set(TunnelNodeAuthHeader, fmt.Sprintf("v1.%d.%s.%s", iat.Unix(), nonce, base64.StdEncoding.EncodeToString(signature)))
	return header
}

func randomNonce(t *testing.T) string {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(raw)
}

func TestTunnelTokenRejections(t *testing.T) {
	pki := newTestPKI(t)
	now := time.Now()
	node := pki.ed25519Node(t, 41, testNodeID, now.Add(-time.Hour), now.Add(time.Hour))
	expired := pki.ed25519Node(t, 42, testNodeID, now.Add(-2*time.Hour), now.Add(-time.Hour))
	other := newTestPKI(t).ed25519Node(t, 43, testNodeID, now.Add(-time.Hour), now.Add(time.Hour))
	verifier := &tunnelTokenVerifier{audience: testTunnelAudience, nodeCAs: pki.rootPool, nonces: NewMemoryTunnelNonceStore(), now: time.Now}
	verify := func(h http.Header, path string) error {
		_, err := verifier.verify(context.Background(), h.Get(TunnelNodeCertificateHeader), h.Get(TunnelNodeAuthHeader), path)
		return err
	}
	good := node.token(testTunnelAudience, TunnelPath, now, randomNonce(t))
	if err := verify(good, TunnelPath); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	tampered := node.token(testTunnelAudience, TunnelPath, now, randomNonce(t))
	auth := tampered.Get(TunnelNodeAuthHeader)
	tampered.Set(TunnelNodeAuthHeader, auth[:len(auth)-4]+"AAA=")
	cases := map[string]struct {
		header http.Header
		path   string
	}{
		"replay":          {good, TunnelPath},
		"other path":      {node.token(testTunnelAudience, EnrollmentTunnelPath, now, randomNonce(t)), TunnelPath},
		"other audience":  {node.token("other-installation", TunnelPath, now, randomNonce(t)), TunnelPath},
		"stale iat":       {node.token(testTunnelAudience, TunnelPath, now.Add(-2*time.Minute), randomNonce(t)), TunnelPath},
		"tampered":        {tampered, TunnelPath},
		"foreign CA":      {other.token(testTunnelAudience, TunnelPath, now, randomNonce(t)), TunnelPath},
		"expired cert":    {expired.token(testTunnelAudience, TunnelPath, now, randomNonce(t)), TunnelPath},
		"missing headers": {http.Header{}, TunnelPath},
	}
	for name, tc := range cases {
		if err := verify(tc.header, tc.path); err == nil {
			t.Errorf("%s: token accepted", name)
		}
	}
}

type sharedTestGateway struct {
	pki        *testPKI
	node       ed25519Node
	enrollment string
	agent      string
	seen       chan string
}

// startSharedTestServers wires the production NewServers through the tunnel
// router, as cmd/agent-gateway does.
func startSharedTestServers(t *testing.T, realIP ...func(*http.Request) (net.Addr, string)) sharedTestGateway {
	t.Helper()
	return startSharedTestServersWith(t, nil, realIP...)
}

func startSharedTestServersWith(t *testing.T, configure func(*Gateway), realIP ...func(*http.Request) (net.Addr, string)) sharedTestGateway {
	t.Helper()
	pki := newTestPKI(t)
	now := time.Now()
	node := pki.ed25519Node(t, 51, testNodeID, now.Add(-time.Hour), now.Add(time.Hour))
	config := DefaultConfig()
	config.GatewayInstanceID, config.GatewayVersion = "gateway-test", "test"
	gateway, err := New(config, defaultFakeControl(), NewMemorySessionCoordinator())
	if err != nil {
		t.Fatal(err)
	}
	if configure != nil {
		configure(gateway)
	}
	seen := make(chan string, 8)
	servers, err := NewServers(gateway, &tls.Config{Certificates: []tls.Certificate{pki.server}},
		&tls.Config{Certificates: []tls.Certificate{pki.server}, ClientCAs: pki.rootPool},
		grpc.ChainStreamInterceptor(func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
			if identity, err := authenticatedNode(stream.Context()); err == nil {
				p, _ := peer.FromContext(stream.Context())
				seen <- identity.NodeID + "|" + identity.SerialNumber + "|" + p.Addr.String()
			}
			return handler(srv, stream)
		}))
	if err != nil {
		t.Fatal(err)
	}
	router, err := NewTunnelRouter(TunnelRouterConfig{Certificate: pki.server, NodeCAs: pki.rootPool,
		Audience: testTunnelAudience, Nonces: NewMemoryTunnelNonceStore(), EnrollmentRate: 2,
		Logf: func(string, ...any) {}})
	if err == nil && len(realIP) > 0 {
		router.config.RealIP = realIP[0]
	}
	if err != nil {
		t.Fatal(err)
	}
	rawEnrollment, _ := net.Listen("tcp", "127.0.0.1:0")
	rawAgent, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() { _ = servers.Enrollment.Serve(router.Listen(rawEnrollment, SharedListenerEnrollment)) }()
	go func() { _ = servers.MTLS.Serve(router.Listen(rawAgent, SharedListenerAgent)) }()
	t.Cleanup(func() { servers.Enrollment.Stop(); servers.MTLS.Stop(); _ = router.Close() })
	return sharedTestGateway{pki: pki, node: node, enrollment: rawEnrollment.Addr().String(), agent: rawAgent.Addr().String(), seen: seen}
}

func (g sharedTestGateway) tunnelConnection(t *testing.T, address, path string, header http.Header, inner *tls.Config) (*grpc.ClientConn, *http.Response, error) {
	t.Helper()
	var response *http.Response
	dial := func(ctx context.Context, _ string) (net.Conn, error) {
		dialer := websocket.Dialer{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "localhost", RootCAs: g.pki.rootPool},
			HandshakeTimeout: 5 * time.Second}
		ws, resp, err := dialer.DialContext(ctx, "wss://"+address+path, header)
		response = resp
		if err != nil {
			return nil, err
		}
		return &wsConn{ws: ws, remote: ws.RemoteAddr()}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	connection, err := grpc.DialContext(ctx, "passthrough:///gateway", grpc.WithTransportCredentials(credentials.NewTLS(inner)),
		grpc.WithContextDialer(dial), grpc.WithBlock(), grpc.WithReturnConnectionError())
	return connection, response, err
}

func connectHello(t *testing.T, connection *grpc.ClientConn) *agentv1.GatewayHello {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	stream, err := agentv1.NewAgentGatewayServiceClient(connection).Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(validHello(testNodeID, versionRange(1, 0), 1)); err != nil {
		t.Fatal(err)
	}
	response, err := stream.Recv()
	if err != nil {
		t.Fatalf("Connect hello: %v", err)
	}
	return response.GetHello()
}

func TestSharedPortDirectAndTunnelYieldSameIdentity(t *testing.T) {
	g := startSharedTestServers(t)
	direct := dialGateway(t, g.agent, g.pki.rootPool, g.node.certificate)
	defer direct.Close()
	if connectHello(t, direct) == nil {
		t.Fatal("direct Connect returned no hello")
	}
	directSeen := <-g.seen
	inner := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "localhost", RootCAs: g.pki.rootPool, Certificates: []tls.Certificate{g.node.certificate}}
	// Both ports serve the tunnel (a CDN forwards one origin port).
	for _, address := range []string{g.agent, g.enrollment} {
		tunnel, _, err := g.tunnelConnection(t, address, TunnelPath, g.node.token(testTunnelAudience, TunnelPath, time.Now(), randomNonce(t)), inner)
		if err != nil {
			t.Fatalf("tunnel via %s: %v", address, err)
		}
		if connectHello(t, tunnel) == nil {
			t.Fatal("tunnel Connect returned no hello")
		}
		tunnelSeen := <-g.seen
		_ = tunnel.Close()
		identity := func(v string) string { return v[:strings.LastIndex(v, "|")] }
		if identity(directSeen) != identity(tunnelSeen) || !strings.HasPrefix(identity(tunnelSeen), testNodeID+"|33") {
			t.Fatalf("direct %q tunnel %q", directSeen, tunnelSeen)
		}
		if !strings.HasPrefix(tunnelSeen[strings.LastIndex(tunnelSeen, "|")+1:], "127.0.0.1:") {
			t.Fatalf("tunnel peer address = %q", tunnelSeen)
		}
	}
}

func TestSharedPortRejectsUnauthenticatedTunnelAndCertificatelessH2(t *testing.T) {
	g := startSharedTestServers(t)
	inner := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "localhost", RootCAs: g.pki.rootPool, Certificates: []tls.Certificate{g.node.certificate}}
	_, response, err := g.tunnelConnection(t, g.agent, TunnelPath, http.Header{}, inner)
	if err == nil || response == nil || response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("tokenless tunnel err=%v response=%v, want 401", err, response)
	}
	// h2 without a client certificate on the agent port never reaches gRPC.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	anonymous, err := grpc.DialContext(ctx, g.agent, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS13, ServerName: "localhost", RootCAs: g.pki.rootPool})), grpc.WithBlock(), grpc.WithReturnConnectionError())
	if err == nil {
		_ = anonymous.Close()
		t.Fatal("certificateless h2 connected to the agent port")
	}
	select {
	case seen := <-g.seen:
		t.Fatalf("unauthenticated connection reached a handler: %s", seen)
	default:
	}
}

func TestSharedPortEnrollmentTunnelReachesEnrollmentServerAndIsRateLimited(t *testing.T) {
	g := startSharedTestServers(t)
	inner := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "localhost", RootCAs: g.pki.rootPool}
	for _, address := range []string{g.enrollment, g.agent} {
		connection, _, err := g.tunnelConnection(t, address, EnrollmentTunnelPath, nil, inner)
		if err != nil {
			t.Fatalf("enrollment tunnel via %s: %v", address, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		response, err := agentv1.NewAgentGatewayServiceClient(connection).Enroll(ctx, validEnrollment())
		cancel()
		_ = connection.Close()
		if err != nil || response.GetNodeId() != testNodeID {
			t.Fatalf("Enroll via tunnel = %v, %v", response, err)
		}
	}
	_, response, err := g.tunnelConnection(t, g.enrollment, EnrollmentTunnelPath, nil, inner)
	if err == nil || response == nil || response.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("third enrollment tunnel err=%v response=%v, want 429", err, response)
	}
}
