package gatewayclient

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewaytunnel"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/test/bufconn"
)

type rejectionPKI struct {
	directory string
	rootPath  string
	server    tls.Certificate
	pool      *x509.CertPool
}

func newTestRoot(t *testing.T, name string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(der)
	return root, key
}

// newRejectionPKI writes the gateway root and a node certificate issued by a
// foreign root (an orphan node of a rebuilt control plane) for the dialer.
func newRejectionPKI(t *testing.T) (rejectionPKI, MTLSDialerConfig) {
	t.Helper()
	directory := filepath.Join(secureTempDir(t), "pki")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	root, rootKey := newTestRoot(t, "CDNCA node CA")
	foreign, foreignKey := newTestRoot(t, "CDNCA node CA")
	serverDER, serverKey := issueTestCertificate(t, root, rootKey, "gateway.test", []string{"gateway.test"}, x509.ExtKeyUsageServerAuth, 2)
	nodePublic, nodePrivate, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	nodeDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(0x3b), Subject: pkix.Name{CommonName: "node"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: mustNodeURI(t)}, foreign, nodePublic, foreignKey)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(nodePrivate)
	pki := rejectionPKI{directory: directory, server: tls.Certificate{Certificate: [][]byte{serverDER}, PrivateKey: serverKey}, pool: x509.NewCertPool()}
	pki.pool.AddCert(root)
	pki.rootPath = writePEM(t, directory, "root.pem", "CERTIFICATE", root.Raw)
	config := MTLSDialerConfig{ServerName: "gateway.test", RootCAFile: pki.rootPath,
		ClientCertificateFile: writePEM(t, directory, "client.pem", "CERTIFICATE", nodeDER),
		ClientPrivateKeyFile:  writePEM(t, directory, "client-key.pem", "PRIVATE KEY", pkcs8),
		MaximumReceiveBytes:   1 << 20, MaximumSendBytes: 1 << 20}
	return pki, config
}

func dialWithin(t *testing.T, config MTLSDialerConfig, within time.Duration) error {
	t.Helper()
	dialer, err := NewMTLSDialer(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	started := time.Now()
	connection, err := dialer.Dial(ctx)
	if err == nil {
		_ = connection.Close()
		t.Fatal("dial with a foreign node certificate succeeded")
	}
	if elapsed := time.Since(started); elapsed > within {
		t.Fatalf("dial took %v (error %v), want it to end at the rejection", elapsed, err)
	}
	return err
}

// Direct gRPC: the gateway's TLS server refuses the foreign node certificate
// with an alert; the dial ends at once and is an identity rejection.
func TestMTLSDialerDirectForeignCertificateIsIdentityRejection(t *testing.T) {
	pki, config := newRejectionPKI(t)
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{pki.server}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pki.pool})))
	healthv1.RegisterHealthServer(server, health.NewServer())
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	config.Address = listener.Addr().String()
	if err := dialWithin(t, config, 3*time.Second); !gatewaytunnel.IdentityRejected(err) {
		t.Fatalf("direct dial error = %v, want an identity rejection", err)
	}
	// Nothing listening: a network error, not a rejection.
	_ = listener.Close()
	server.Stop()
	closed := config
	dialer, _ := NewMTLSDialer(closed)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := dialer.Dial(ctx); err == nil || gatewaytunnel.IdentityRejected(err) {
		t.Fatalf("closed port error = %v, want a non-identity failure", err)
	}
}

// ws tunnel: 401 on the upgrade is an identity rejection, 503 is not.
func TestMTLSDialerTunnelStatusClassification(t *testing.T) {
	pki, config := newRejectionPKI(t)
	var status int
	var mu sync.Mutex
	mux := http.NewServeMux()
	mux.HandleFunc(gatewaytunnel.TunnelPath, func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		code := status
		mu.Unlock()
		http.Error(w, "unauthenticated", code)
	})
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	httpServer := &http.Server{Handler: mux}
	go func() {
		_ = httpServer.Serve(tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{pki.server}, NextProtos: []string{"http/1.1"}}))
	}()
	t.Cleanup(func() { _ = httpServer.Close() })
	config.Address, config.Transport, config.TunnelHost, config.TunnelAudience = listener.Addr().String(), gatewaytunnel.TransportWS, "gateway.test", tunnelTestAudience
	set := func(code int) { mu.Lock(); status = code; mu.Unlock() }
	set(http.StatusUnauthorized)
	if err := dialWithin(t, config, 3*time.Second); !errors.Is(err, gatewaytunnel.ErrNodeIdentityRejected) {
		t.Fatalf("tunnel 401 error = %v, want ErrNodeIdentityRejected", err)
	}
	set(http.StatusServiceUnavailable)
	dialer, _ := NewMTLSDialer(config)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if _, err := dialer.Dial(ctx); err == nil || gatewaytunnel.IdentityRejected(err) {
		t.Fatalf("tunnel 503 error = %v, want a non-identity failure", err)
	}
}
func mustNodeURI(t *testing.T) []*url.URL {
	t.Helper()
	uri, err := url.Parse("spiffe://cdn-platform/node/a1d3cce1-5b9c-4d31-8a60-104c9c0b717f")
	if err != nil {
		t.Fatal(err)
	}
	return []*url.URL{uri}
}

// scriptedDialer plays one step per Dial: "rejected", "network" or
// "session" (a real session on the bufconn gateway); then stays rejected.
type scriptedDialer struct {
	steps   []string
	session *bufDialer
	mu      sync.Mutex
	dialed  int
	done    chan struct{}
}

func (d *scriptedDialer) last() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dialed - 1
}

func (d *scriptedDialer) Dial(ctx context.Context) (Connection, error) {
	d.mu.Lock()
	index := d.dialed
	d.dialed++
	d.mu.Unlock()
	if index == len(d.steps) {
		close(d.done)
	}
	step := "rejected"
	if index < len(d.steps) {
		step = d.steps[index]
	}
	switch step {
	case "session":
		return d.session.Dial(ctx)
	case "network":
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
	default:
		return nil, fmt.Errorf("gateway tunnel upgrade 401 Unauthorized: %w", gatewaytunnel.ErrNodeIdentityRejected)
	}
}

// A rejected node backs off 30s, 1m, 2m, ... (network errors in between keep
// the normal backoff and do not reset it); an established session restores
// the normal rhythm, so the next rejection starts at 30s again.
func TestRunBacksOffIdentityRejectionAndResetsAfterSession(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	command, artifact := signedTestCommand(t, privateKey)
	gateway := &fakeGateway{command: command, artifact: artifact, statusEvents: make(chan *agentv1.DeploymentStatus, 128),
		suppressHeartbeatAck: true, offlineAfter: 60 * time.Millisecond}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	agentv1.RegisterAgentGatewayServiceServer(server, gateway)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })
	root := secureTempDir(t)
	t.Cleanup(func() { makeTestTreeWritable(root) })
	manager, err := deployment.NewManager(filepath.Join(root, "deployment"), testPrechecker{}, &testRuntime{})
	if err != nil {
		t.Fatal(err)
	}
	trust, err := NewTrustStore(map[string]crypto.PublicKey{"test-signing-key": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	dialer := &scriptedDialer{steps: []string{"rejected", "rejected", "rejected", "network", "rejected", "session", "rejected", "rejected"},
		session: &bufDialer{listener: listener}, done: make(chan struct{})}
	client, err := New(testClientConfig(filepath.Join(root, "gateway-journal")), dialer, manager, trust)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	waits := map[int][]time.Duration{}
	client.jitter = func(base time.Duration) time.Duration {
		mu.Lock()
		waits[dialer.last()] = append(waits[dialer.last()], base)
		mu.Unlock()
		return time.Millisecond
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	select {
	case <-dialer.done:
	case <-time.After(5 * time.Second):
		t.Fatalf("Run stopped after %d dials", dialer.last()+1)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() = %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	want := map[int]time.Duration{0: 30 * time.Second, 1: time.Minute, 2: 2 * time.Minute, 4: 4 * time.Minute, 6: 30 * time.Second, 7: time.Minute}
	for step, delay := range want {
		if got := waits[step]; len(got) != 1 || got[0] != delay {
			t.Errorf("step %d (%s) waits %v, want [%v]", step, dialer.steps[step], got, delay)
		}
	}
	// The network error keeps the normal reconnect backoff (10ms maximum).
	if got := waits[3]; len(got) != 1 || got[0] > 10*time.Millisecond {
		t.Errorf("network error waits %v, want the normal backoff", got)
	}
	if gateway.connects.Load() < 1 {
		t.Fatal("scripted session never reached the gateway")
	}
}
