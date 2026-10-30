package gatewayclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewaytunnel"
	"github.com/gorilla/websocket"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/peer"
)

const tunnelTestAudience = "6f1c2a4e-8d3b-4c5a-9e7f-0a1b2c3d4e5f"

type tunnelListener struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func (l *tunnelListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *tunnelListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *tunnelListener) Addr() net.Addr { return &net.TCPAddr{} }

type serverWS struct {
	*websocket.Conn
	buf []byte
}

func (c *serverWS) Read(p []byte) (int, error) {
	for len(c.buf) == 0 {
		_, data, err := c.ReadMessage()
		if err != nil {
			return 0, err
		}
		c.buf = data
	}
	n := copy(p, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}
func (c *serverWS) Write(p []byte) (int, error) {
	return len(p), c.WriteMessage(websocket.BinaryMessage, p)
}
func (c *serverWS) SetDeadline(t time.Time) error { return c.NetConn().SetDeadline(t) }

// TestMTLSDialerWSTransportTunnelsInnerMTLS: the ws transport upgrades at
// /agent/v1/tunnel with a token signed by the node key, and the inner TLS
// presents the same client certificate as a direct dial.
func TestMTLSDialerWSTransportTunnelsInnerMTLS(t *testing.T) {
	directory := filepath.Join(secureTempDir(t), "pki")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	root, _ := x509.ParseCertificate(rootDER)
	serverDER, serverKey := issueTestCertificate(t, root, rootKey, "gateway.test", []string{"gateway.test"}, x509.ExtKeyUsageServerAuth, 2)
	nodePublic, nodePrivate, _ := ed25519.GenerateKey(rand.Reader)
	uri, _ := url.Parse("spiffe://cdn-platform/node/018f47a2-5b9c-7d31-8a60-104c9c0b717f")
	nodeDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(0x3a), Subject: pkix.Name{CommonName: "node"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{uri}}, root, nodePublic, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootPath := writePEM(t, directory, "root.pem", "CERTIFICATE", rootDER)
	clientCertPath := writePEM(t, directory, "client.pem", "CERTIFICATE", nodeDER)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(nodePrivate)
	clientKeyPath := writePEM(t, directory, "client-key.pem", "PRIVATE KEY", pkcs8)
	serverPair := tls.Certificate{Certificate: [][]byte{serverDER}, PrivateKey: serverKey}
	pool := x509.NewCertPool()
	pool.AddCert(root)

	inner := &tunnelListener{conns: make(chan net.Conn), done: make(chan struct{})}
	seen := make(chan string, 1)
	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{serverPair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool})),
		grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			p, _ := peer.FromContext(ctx)
			seen <- p.AuthInfo.(credentials.TLSInfo).State.VerifiedChains[0][0].URIs[0].String()
			return handler(ctx, req)
		}))
	healthv1.RegisterHealthServer(grpcServer, health.NewServer())
	go func() { _ = grpcServer.Serve(inner) }()
	t.Cleanup(grpcServer.Stop)

	var gotHost string
	upgrader := websocket.Upgrader{}
	mux := http.NewServeMux()
	mux.HandleFunc(gatewaytunnel.TunnelPath, func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		parts := strings.Split(r.Header.Get("Cdnca-Node-Auth"), ".")
		signature, _ := base64.StdEncoding.DecodeString(parts[len(parts)-1])
		if len(parts) != 4 || r.Header.Get("Cdnca-Node-Cert") != base64.StdEncoding.EncodeToString(nodeDER) ||
			!ed25519.Verify(nodePublic, gatewaytunnel.SignedText(tunnelTestAudience, gatewaytunnel.TunnelPath,
				"018f47a2-5b9c-7d31-8a60-104c9c0b717f", "3a", mustInt(parts[1]), parts[2]), signature) {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		inner.conns <- &serverWS{Conn: ws}
	})
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	httpServer := &http.Server{Handler: mux}
	go func() {
		_ = httpServer.Serve(tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{serverPair}, NextProtos: []string{"http/1.1"}}))
	}()
	t.Cleanup(func() { _ = httpServer.Close() })

	// The outer name is the CDN name (here the same certificate), the inner
	// ServerName the gateway name.
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	dialer, err := NewMTLSDialer(MTLSDialerConfig{Address: listener.Addr().String(), ServerName: "gateway.test",
		RootCAFile: rootPath, ClientCertificateFile: clientCertPath, ClientPrivateKeyFile: clientKeyPath,
		MaximumReceiveBytes: 1 << 20, MaximumSendBytes: 1 << 20,
		Transport: gatewaytunnel.TransportWS, TunnelHost: "gateway.test", TunnelAudience: tunnelTestAudience})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, err := dialer.Dial(ctx)
	if err != nil {
		t.Fatalf("ws Dial: %v", err)
	}
	defer connection.Close()
	if _, err := healthv1.NewHealthClient(connection.(*grpcConnection).connection).Check(ctx, &healthv1.HealthCheckRequest{}); err != nil {
		t.Fatalf("inner gRPC over tunnel: %v", err)
	}
	if got := <-seen; got != uri.String() {
		t.Fatalf("inner identity = %q", got)
	}
	if gotHost != "gateway.test:"+port {
		t.Fatalf("outer Host = %q", gotHost)
	}

	if _, err := NewMTLSDialer(MTLSDialerConfig{Address: listener.Addr().String(), ServerName: "gateway.test",
		RootCAFile: rootPath, ClientCertificateFile: clientCertPath, ClientPrivateKeyFile: clientKeyPath,
		MaximumReceiveBytes: 1 << 20, MaximumSendBytes: 1 << 20, Transport: "quic"}); err == nil {
		t.Fatal("unknown transport accepted")
	}
	if _, err := NewMTLSDialer(MTLSDialerConfig{Address: listener.Addr().String(), ServerName: "gateway.test",
		RootCAFile: rootPath, ClientCertificateFile: clientCertPath, ClientPrivateKeyFile: clientKeyPath,
		MaximumReceiveBytes: 1 << 20, MaximumSendBytes: 1 << 20, Transport: gatewaytunnel.TransportWS}); err == nil {
		t.Fatal("ws transport without audience accepted")
	}
}

func mustInt(value string) int64 {
	var n int64
	for _, c := range value {
		n = n*10 + int64(c-'0')
	}
	return n
}
