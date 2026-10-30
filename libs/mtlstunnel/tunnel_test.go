package mtlstunnel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

type authority struct {
	cert *x509.Certificate
	key  ed25519.PrivateKey
	pool *x509.CertPool
}

func newAuthority(t *testing.T, name string) authority {
	t.Helper()
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return authority{cert: cert, key: private, pool: pool}
}

func (a authority) issue(t *testing.T, usage x509.ExtKeyUsage, dns string, ip net.IP) tls.Certificate {
	t.Helper()
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{usage}, KeyUsage: x509.KeyUsageDigitalSignature}
	if dns != "" {
		template.DNSNames = []string{dns}
	}
	if ip != nil {
		template.IPAddresses = []net.IP{ip}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, public, a.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private}
}

// fixture: a TLS 1.3 mTLS backend (the 9448 stand-in, auth.cdnca.test) behind
// an outer TLS tunnel server (the CDN/front stand-in on 127.0.0.1).
type fixture struct {
	inner      authority
	outerRoots *x509.CertPool
	tunnelURL  string
	backend    *httptest.Server
	server     *Server
}

func newFixture(t *testing.T, handler http.HandlerFunc) fixture {
	t.Helper()
	inner := newAuthority(t, "license installation CA")
	backend := httptest.NewUnstartedServer(handler)
	backend.EnableHTTP2 = true
	backend.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: inner.pool,
		Certificates: []tls.Certificate{inner.issue(t, x509.ExtKeyUsageServerAuth, "auth.cdnca.test", nil)}}
	backend.StartTLS()
	t.Cleanup(backend.Close)

	outer := newAuthority(t, "public CDN CA")
	server := &Server{Targets: map[string]string{TargetPluginRuntime: backend.Listener.Addr().String()}}
	front := httptest.NewUnstartedServer(server)
	front.TLS = &tls.Config{Certificates: []tls.Certificate{outer.issue(t, x509.ExtKeyUsageServerAuth, "", net.ParseIP("127.0.0.1"))}}
	front.StartTLS()
	t.Cleanup(front.Close)
	return fixture{inner: inner, outerRoots: outer.pool, tunnelURL: front.URL, backend: backend, server: server}
}

func (f fixture) httpClient(t *testing.T, clientCert tls.Certificate) *http.Client {
	t.Helper()
	tunnel, err := NewClient("https://auth.cdnca.test:9448", f.tunnelURL, TargetPluginRuntime)
	if err != nil {
		t.Fatal(err)
	}
	tunnel.Roots = f.outerRoots
	transport := Apply(&http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13,
		RootCAs: f.inner.pool, Certificates: []tls.Certificate{clientCert}}}, tunnel.DialContext)
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}
}

func TestTunnelCarriesInnerMTLSEndToEnd(t *testing.T) {
	var sawClientCert, sawHTTP2 bool
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		sawClientCert = r.TLS != nil && len(r.TLS.PeerCertificates) == 1 && r.TLS.ServerName == "auth.cdnca.test"
		sawHTTP2 = r.ProtoMajor == 2
		body, _ := io.ReadAll(r.Body)
		_, _ = w.Write(body)
	})
	client := f.httpClient(t, f.inner.issue(t, x509.ExtKeyUsageClientAuth, "", nil))
	// Larger than a frame: the stream is split and reassembled byte exact.
	payload := bytes.Repeat([]byte("0123456789abcdef"), 3*MaxFrameBytes/16+7)
	response, err := client.Post("https://auth.cdnca.test:9448/v1/echo", "application/octet-stream", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	echoed, _ := io.ReadAll(response.Body)
	if response.StatusCode != 200 || !bytes.Equal(echoed, payload) {
		t.Fatalf("status %d, echoed %d bytes of %d", response.StatusCode, len(echoed), len(payload))
	}
	if !sawClientCert || !sawHTTP2 {
		t.Fatalf("backend saw client cert=%v (SNI auth.cdnca.test) http2=%v", sawClientCert, sawHTTP2)
	}
}

// HTTP/1.1 keep-alive over one tunnel: net/http aborts its background read
// between requests with a past deadline and expects the connection to survive.
func TestTunnelHTTP11KeepAlive(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_, _ = w.Write(append([]byte("echo:"), body...))
	})
	client := f.httpClient(t, f.inner.issue(t, x509.ExtKeyUsageClientAuth, "", nil))
	transport := client.Transport.(*http.Transport)
	transport.ForceAttemptHTTP2 = false
	transport.TLSClientConfig.NextProtos = []string{"http/1.1"}
	for i := 0; i < 5; i++ {
		response, err := client.Post("https://auth.cdnca.test:9448/v1/x", "text/plain", bytes.NewReader([]byte("ping")))
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if string(body) != "echo:ping" || response.ProtoMajor != 1 {
			t.Fatalf("request %d: %s %q", i, response.Proto, body)
		}
	}
}

func TestTunnelKeepsInnerCertificateChecks(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	// A client certificate from another CA is refused by the backend itself.
	stranger := newAuthority(t, "other CA")
	if _, err := f.httpClient(t, stranger.issue(t, x509.ExtKeyUsageClientAuth, "", nil)).Get("https://auth.cdnca.test:9448/"); err == nil {
		t.Fatal("backend accepted a client certificate from an unknown CA through the tunnel")
	}
	// The inner server name is still verified against the original host.
	tunnel, _ := NewClient("https://other.cdnca.test:9448", f.tunnelURL, TargetPluginRuntime)
	tunnel.Roots = f.outerRoots
	transport := Apply(&http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: f.inner.pool,
		Certificates: []tls.Certificate{f.inner.issue(t, x509.ExtKeyUsageClientAuth, "", nil)}}}, tunnel.DialContext)
	defer transport.CloseIdleConnections()
	if _, err := (&http.Client{Transport: transport}).Get("https://other.cdnca.test:9448/"); err == nil ||
		!strings.Contains(err.Error(), "certificate") {
		t.Fatalf("inner SAN mismatch not refused: %v", err)
	}
}

func TestTunnelRefusesOtherOrigins(t *testing.T) {
	tunnel, err := NewClient("https://auth.cdnca.test:9448", "", TargetPluginRuntime)
	if err != nil {
		t.Fatal(err)
	}
	if tunnel.Entrance != "auth.cdnca.test:443" || tunnel.Host != "auth.cdnca.test" {
		t.Fatalf("default entrance %s host %s", tunnel.Entrance, tunnel.Host)
	}
	if _, err := tunnel.DialContext(context.Background(), "tcp", "evil.test:443"); err == nil {
		t.Fatal("tunnel dialed an address other than its origin")
	}
}

func TestServerRejectsUnknownTargetAndMissingSubprotocol(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, _ *http.Request) {})
	dial := func(path string, protocols []string) int {
		dialer := websocket.Dialer{TLSClientConfig: &tls.Config{RootCAs: f.outerRoots}, Subprotocols: protocols}
		ws, response, err := dialer.Dial("wss"+strings.TrimPrefix(f.tunnelURL, "https")+path, nil)
		if err == nil {
			ws.Close()
			return 101
		}
		if response == nil {
			t.Fatal(err)
		}
		return response.StatusCode
	}
	if got := dial(PathPrefix+"nope", []string{Subprotocol}); got != 404 {
		t.Fatalf("unknown target = %d, want 404", got)
	}
	if got := dial(PathPrefix+TargetPluginRuntime, nil); got != 400 {
		t.Fatalf("missing subprotocol = %d, want 400", got)
	}
	if got := dial(PathPrefix+TargetPluginRuntime, []string{"other"}); got != 400 {
		t.Fatalf("wrong subprotocol = %d, want 400", got)
	}
	if got := dial(PathPrefix+TargetPluginRuntime, []string{Subprotocol}); got != 101 {
		t.Fatalf("valid upgrade = %d, want 101", got)
	}
}

func TestServerLimits(t *testing.T) {
	server := &Server{TotalLimit: 2}
	if !server.acquire("a") || !server.acquire("b") || server.acquire("c") {
		t.Fatal("total limit not enforced")
	}
	server.release("a")
	server.release("b")
	server = &Server{}
	for range PerSourceLimit {
		if !server.acquire("a") {
			t.Fatal("per-source limit too small")
		}
	}
	if server.acquire("a") || !server.acquire("b") {
		t.Fatal("per-source limit not enforced per source")
	}
}

func TestBridgeClosesIdleTunnel(t *testing.T) {
	f := newFixture(t, func(w http.ResponseWriter, _ *http.Request) {})
	f.server.IdleTimeout = 200 * time.Millisecond
	tunnel, _ := NewClient("https://auth.cdnca.test:9448", f.tunnelURL, TargetPluginRuntime)
	tunnel.Roots = f.outerRoots
	conn, err := tunnel.DialContext(context.Background(), "tcp", "auth.cdnca.test:9448")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("idle tunnel stayed open")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("idle tunnel was not closed by the server within 5s")
	}
}

func TestDialerModes(t *testing.T) {
	if dial, err := Dialer(ModeDirect, "https://auth.cdnca.test:9448", "", TargetPluginRuntime); err != nil || dial != nil {
		t.Fatalf("direct = %v %v, want nil dialer", dial != nil, err)
	}
	for _, mode := range []string{"", ModeTunnel} {
		if dial, err := Dialer(mode, "https://auth.cdnca.test:9448", "", TargetPluginRuntime); err != nil || dial == nil {
			t.Fatalf("mode %q = %v %v, want tunnel", mode, dial != nil, err)
		}
	}
	if _, err := Dialer("websocket", "https://auth.cdnca.test:9448", "", TargetPluginRuntime); err == nil {
		t.Fatal("unknown mode accepted")
	}
	for _, bad := range []string{"http://cdn.test", "https://cdn.test/path", "https://user@cdn.test"} {
		if _, err := NewClient("https://auth.cdnca.test:9448", bad, TargetPluginRuntime); err == nil {
			t.Fatalf("tunnel URL %q accepted", bad)
		}
	}
	if c, err := NewClient("https://auth.cdnca.test:9448", "https://edge.cdnca.test:8443", TargetPluginRuntime); err != nil ||
		c.Entrance != "edge.cdnca.test:8443" || c.Host != "edge.cdnca.test" || c.Origin != "auth.cdnca.test:9448" {
		t.Fatalf("override = %+v %v", c, err)
	}
}
