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
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// Handoff tests (moved from services/market-service/internal/mtlstunnel).

const memberHost = "my.cdnca.com"

// harness: outer TLS tunnel listener (httptest, stands in for the CDN-facing
// listener) handing tunnels to a real mTLS http.Server (inner).
type harness struct {
	outer      *httptest.Server
	tunnel     *HandoffServer
	innerCA    authority
	outerCA    authority
	clientCert tls.Certificate
	seen       chan string // inner handler: RemoteAddr + client URI
}

// issueURI is a client certificate with one URI SAN (the installation identity).
func (a authority) issueURI(t *testing.T, uri string) tls.Certificate {
	t.Helper()
	parsed, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "client"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), URIs: []*url.URL{parsed},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, public, a.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private}
}

func newHarness(t *testing.T, limit int, auth OriginAuth) *harness {
	t.Helper()
	serverCA := newAuthority(t, "market server CA")
	clientCA := newAuthority(t, "installation CA")
	serverCert := serverCA.issue(t, x509.ExtKeyUsageServerAuth, memberHost, nil)
	clientCert := clientCA.issueURI(t, "spiffe://cdn-platform/installation/00000000-0000-4000-8000-000000000001")
	h := &harness{innerCA: serverCA, clientCert: clientCert, seen: make(chan string, 16)}
	handoff := NewHandoff("member")
	inner := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			uri := ""
			if len(r.TLS.VerifiedChains) > 0 && len(r.TLS.VerifiedChains[0][0].URIs) == 1 {
				uri = r.TLS.VerifiedChains[0][0].URIs[0].String()
			}
			h.seen <- r.RemoteAddr + " " + uri
			body, _ := io.ReadAll(r.Body)
			_, _ = w.Write(append([]byte("echo:"), body...))
		}),
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert},
			ClientCAs: clientCA.pool, ClientAuth: tls.RequireAndVerifyClientCert},
	}
	go func() { _ = inner.ServeTLS(handoff, "", "") }()
	t.Cleanup(func() { _ = inner.Close(); _ = handoff.Close() })

	h.tunnel = &HandoffServer{Targets: map[string]*Handoff{TargetMarketMember: handoff}, TotalLimit: limit, Auth: auth}
	h.outer = httptest.NewUnstartedServer(h.tunnel)
	outerCA := newAuthority(t, "public CDN CA")
	outerCert := outerCA.issue(t, x509.ExtKeyUsageServerAuth, memberHost, nil)
	h.outerCA = outerCA
	h.outer.TLS = &tls.Config{NextProtos: []string{"http/1.1"}, Certificates: []tls.Certificate{outerCert}}
	h.outer.StartTLS()
	t.Cleanup(h.outer.Close)
	return h
}

func (h *harness) tunnelClient(t *testing.T, target string) *Client {
	t.Helper()
	client, err := NewClient("https://"+memberHost, "", target)
	if err != nil {
		t.Fatal(err)
	}
	// Outer: SNI my.cdnca.com, the "CDN" certificate; only the TCP entrance is local.
	client.Entrance = h.outer.Listener.Addr().String()
	client.Roots = h.outerCA.pool
	return client
}

func (h *harness) httpClient(t *testing.T, target string, cert *tls.Certificate) *http.Client {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: h.innerCA.pool}
	if cert != nil {
		tlsConfig.Certificates = []tls.Certificate{*cert}
	}
	dial := h.tunnelClient(t, target).DialContext
	return &http.Client{Timeout: 10 * time.Second, Transport: Apply(&http.Transport{TLSClientConfig: tlsConfig, ForceAttemptHTTP2: true}, dial)}
}

func TestHandoffCarriesInnerMTLS(t *testing.T) {
	h := newHarness(t, 0, OriginAuth{})
	client := h.httpClient(t, TargetMarketMember, &h.clientCert)
	// > 64 KiB body: split into several frames both ways.
	payload := make([]byte, 200<<10)
	_, _ = rand.Read(payload)
	response, err := client.Post("https://"+memberHost+"/v1/x", "application/octet-stream", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != 200 || !bytes.Equal(body, append([]byte("echo:"), payload...)) {
		t.Fatalf("status %d, body %d bytes", response.StatusCode, len(body))
	}
	if response.TLS == nil || response.TLS.Version != tls.VersionTLS13 || response.TLS.ServerName != memberHost {
		t.Fatalf("inner TLS %+v", response.TLS)
	}
	seen := <-h.seen
	if !strings.HasPrefix(seen, "127.0.0.1:0 ") || !strings.HasSuffix(seen, "/installation/00000000-0000-4000-8000-000000000001") {
		t.Fatalf("inner saw %q", seen)
	}
}

func TestHandoffInnerRequiresClientCertificate(t *testing.T) {
	h := newHarness(t, 0, OriginAuth{})
	if _, err := h.httpClient(t, TargetMarketMember, nil).Get("https://" + memberHost + "/"); err == nil {
		t.Fatal("inner mTLS accepted a client without certificate")
	}
}

func TestHandoffInnerPinsServerCA(t *testing.T) {
	h := newHarness(t, 0, OriginAuth{})
	client := h.httpClient(t, TargetMarketMember, &h.clientCert)
	other := newAuthority(t, "other CA")
	client.Transport.(*http.Transport).TLSClientConfig.RootCAs = other.pool
	if _, err := client.Get("https://" + memberHost + "/"); err == nil {
		t.Fatal("inner TLS accepted a server outside the pinned CA")
	}
}

func (h *harness) outerHTTP() *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: h.outerCA.pool, ServerName: memberHost}}}
}

func outerRequest(t *testing.T, h *harness, path string, subprotocol bool) int {
	t.Helper()
	request, _ := http.NewRequest(http.MethodGet, h.outer.URL+path, nil)
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "websocket")
	request.Header.Set("Sec-WebSocket-Version", "13")
	request.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	if subprotocol {
		request.Header.Set("Sec-WebSocket-Protocol", Subprotocol)
	}
	response, err := h.outerHTTP().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode == http.StatusSwitchingProtocols && response.Header.Get("Sec-WebSocket-Protocol") != Subprotocol {
		t.Fatalf("server answered subprotocol %q", response.Header.Get("Sec-WebSocket-Protocol"))
	}
	return response.StatusCode
}

func TestHandoffRefusals(t *testing.T) {
	h := newHarness(t, 0, OriginAuth{})
	if got := outerRequest(t, h, PathPrefix+"plugin-runtime", true); got != http.StatusNotFound {
		t.Fatalf("unknown target: %d", got)
	}
	if got := outerRequest(t, h, "/other", true); got != http.StatusNotFound {
		t.Fatalf("outside prefix: %d", got)
	}
	if got := outerRequest(t, h, PathPrefix+TargetMarketMember, false); got != http.StatusBadRequest {
		t.Fatalf("missing subprotocol: %d", got)
	}
	if got := outerRequest(t, h, PathPrefix+TargetMarketMember, true); got != http.StatusSwitchingProtocols {
		t.Fatalf("valid upgrade: %d", got)
	}
}

func TestHandoffClientDialRefusesOtherOriginAndChecksSubprotocol(t *testing.T) {
	h := newHarness(t, 0, OriginAuth{})
	client := h.tunnelClient(t, TargetMarketMember)
	if _, err := client.DialContext(context.Background(), "tcp", "evil.example:443"); err == nil {
		t.Fatal("dial for another origin accepted")
	}
	// Unknown target over the real client: upgrade fails with the status.
	client.Target = "nope"
	if _, err := client.DialContext(context.Background(), "tcp", client.Origin); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatal("unknown target accepted")
	}
}

func TestHandoffLimits(t *testing.T) {
	h := newHarness(t, 2, OriginAuth{})
	open := func() *websocket.Conn {
		d := websocket.Dialer{TLSClientConfig: &tls.Config{RootCAs: h.outerCA.pool, ServerName: memberHost}, Subprotocols: []string{Subprotocol}}
		ws, response, err := d.Dial("wss://"+h.outer.Listener.Addr().String()+PathPrefix+TargetMarketMember, nil)
		if err != nil {
			if response != nil && response.StatusCode == http.StatusServiceUnavailable {
				return nil
			}
			t.Fatal(err)
		}
		return ws
	}
	a, b := open(), open()
	if a == nil || b == nil {
		t.Fatal("first two tunnels refused")
	}
	if c := open(); c != nil {
		t.Fatal("third tunnel above the total limit accepted")
	}
	_ = a.Close()
	deadline := time.Now().Add(5 * time.Second)
	for h.tunnel.Active() > 1 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	// The inner server closes its side once the tunnel ends; the slot is free again.
	if c := open(); c == nil {
		t.Fatalf("slot not released (active %d)", h.tunnel.Active())
	}
	_ = b.Close()
}

func TestHandoffPerSourceLimit(t *testing.T) {
	s := &HandoffServer{}
	ip := "203.0.113.9"
	for i := 0; i < PerSourceLimit; i++ {
		if !s.take(s.TotalLimit, ip) {
			t.Fatalf("refused at %d", i)
		}
	}
	if s.take(s.TotalLimit, ip) {
		t.Fatal("source above PerSourceLimit accepted")
	}
	if !s.take(s.TotalLimit, "2001:db8::1") {
		t.Fatal("another source refused")
	}
	s.give(ip)
	if !s.take(s.TotalLimit, ip) {
		t.Fatal("released slot not reusable")
	}
}

func TestOriginAuthSource(t *testing.T) {
	auth := OriginAuth{Header: "X-Cdnca-Origin-Key", Secret: []byte("0123456789abcdef0123456789abcdef"), RealIPHeader: "X-Forwarded-For"}
	request := func(headers ...string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "198.51.100.7:4433"
		for i := 0; i+1 < len(headers); i += 2 {
			r.Header.Add(headers[i], headers[i+1])
		}
		return r
	}
	cases := []struct {
		name    string
		auth    OriginAuth
		r       *http.Request
		want    string
		fromCDN bool
	}{
		{"no secret configured", OriginAuth{}, request("X-Forwarded-For", "203.0.113.1"), "198.51.100.7", false},
		{"no key header", auth, request("X-Forwarded-For", "203.0.113.1"), "198.51.100.7", false},
		{"wrong key", auth, request("X-Cdnca-Origin-Key", "wrong", "X-Forwarded-For", "203.0.113.1"), "198.51.100.7", false},
		// Right-most hop, as services/management-web client_ip.go (A3e).
		{"xff rightmost hop", auth, request("X-Cdnca-Origin-Key", string(auth.Secret), "X-Forwarded-For", "10.0.0.1, 203.0.113.1"), "203.0.113.1", true},
		{"xff spoofed left hop ignored", auth, request("X-Cdnca-Origin-Key", string(auth.Secret), "X-Forwarded-For", "192.0.2.66,203.0.113.4"), "203.0.113.4", true},
		{"xff header lines joined", auth, request("X-Cdnca-Origin-Key", string(auth.Secret), "X-Forwarded-For", "192.0.2.66", "X-Forwarded-For", "203.0.113.5"), "203.0.113.5", true},
		{"xff rightmost garbage", auth, request("X-Cdnca-Origin-Key", string(auth.Secret), "X-Forwarded-For", "203.0.113.1, nope"), "198.51.100.7", false},
		{"xff too long", auth, request("X-Cdnca-Origin-Key", string(auth.Secret), "X-Forwarded-For", strings.Repeat("192.0.2.1,", 103)+"203.0.113.1"), "198.51.100.7", false},
		{"key header twice", auth, request("X-Cdnca-Origin-Key", string(auth.Secret), "X-Cdnca-Origin-Key", string(auth.Secret), "X-Forwarded-For", "203.0.113.1"), "198.51.100.7", false},
		{"xff ipv6", auth, request("X-Cdnca-Origin-Key", string(auth.Secret), "X-Forwarded-For", "2001:db8::5"), "2001:db8::5", true},
		{"xff garbage", auth, request("X-Cdnca-Origin-Key", string(auth.Secret), "X-Forwarded-For", "nope"), "198.51.100.7", false},
		{"single-ip header twice", OriginAuth{Header: auth.Header, Secret: auth.Secret, RealIPHeader: "CF-Connecting-IP"},
			request("X-Cdnca-Origin-Key", string(auth.Secret), "CF-Connecting-IP", "203.0.113.1", "CF-Connecting-IP", "203.0.113.2"), "198.51.100.7", false},
		{"single-ip header", OriginAuth{Header: auth.Header, Secret: auth.Secret, RealIPHeader: "CF-Connecting-IP"},
			request("X-Cdnca-Origin-Key", string(auth.Secret), "CF-Connecting-IP", "203.0.113.3"), "203.0.113.3", true},
	}
	for _, c := range cases {
		got, fromCDN := c.auth.Source(c.r)
		if got.String() != c.want || fromCDN != c.fromCDN {
			t.Errorf("%s: %s %v, want %s %v", c.name, got, fromCDN, c.want, c.fromCDN)
		}
	}
}

func TestHandoffParseModeAndNewClient(t *testing.T) {
	for in, want := range map[string]string{"": ModeTunnel, "tunnel": ModeTunnel, "direct": ModeDirect, " direct\n": ModeDirect} {
		if got, err := ParseMode(in); err != nil || got != want {
			t.Errorf("ParseMode(%q) = %q %v", in, got, err)
		}
	}
	if _, err := ParseMode("grpc"); err == nil {
		t.Error("ParseMode accepted grpc")
	}
	c, err := NewClient("https://auth.cdnca.com:9447", "", TargetMarketLicense)
	if err != nil || c.Entrance != "auth.cdnca.com:443" || c.Host != "auth.cdnca.com" || c.Origin != "auth.cdnca.com:9447" {
		t.Fatalf("%+v %v", c, err)
	}
	c, err = NewClient("https://auth.cdnca.com:9447/service/v1", "https://edge.cdnca.com:8443", TargetMarketLicense)
	if err != nil || c.Entrance != "edge.cdnca.com:8443" || c.Host != "edge.cdnca.com" {
		t.Fatalf("override %+v %v", c, err)
	}
	for _, bad := range []string{"http://x", "https://x/path", "https://u@x"} {
		if _, err := NewClient("https://auth.cdnca.com:9447", bad, TargetMarketLicense); err == nil {
			t.Errorf("tunnel URL %q accepted", bad)
		}
	}
	if dial, err := Dialer("direct", "https://auth.cdnca.com:9447", "", TargetMarketLicense); dial != nil || err != nil {
		t.Fatal("direct mode must leave the transport dialer")
	}
	if dial, err := Dialer("", "https://auth.cdnca.com:9447", "", TargetMarketLicense); dial == nil || err != nil {
		t.Fatal("default mode must tunnel")
	}
}

func TestHandoffIdleTimeout(t *testing.T) {
	h := newHarness(t, 0, OriginAuth{})
	h.tunnel.IdleTimeout = 200 * time.Millisecond
	d := websocket.Dialer{TLSClientConfig: &tls.Config{RootCAs: h.outerCA.pool, ServerName: memberHost}, Subprotocols: []string{Subprotocol}}
	ws, _, err := d.Dial("wss://"+h.outer.Listener.Addr().String()+PathPrefix+TargetMarketMember, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	_ = ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	if _, _, err := ws.ReadMessage(); err == nil {
		t.Fatal("idle tunnel delivered a message")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("idle tunnel closed after %s", elapsed)
	}
	for deadline := time.Now().Add(2 * time.Second); h.tunnel.Active() != 0; {
		if time.Now().After(deadline) {
			t.Fatalf("active %d after idle close", h.tunnel.Active())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// http.Server interrupts its background read with a past read deadline
// between HTTP/1.1 requests; the tunnel must treat that as a timeout, not end
// the connection.
func TestHandoffHTTP11KeepAlive(t *testing.T) {
	h := newHarness(t, 0, OriginAuth{})
	client := h.httpClient(t, TargetMarketMember, &h.clientCert)
	transport := client.Transport.(*http.Transport)
	transport.ForceAttemptHTTP2 = false
	transport.TLSClientConfig.NextProtos = []string{"http/1.1"}
	for i := 0; i < 5; i++ {
		response, err := client.Post("https://"+memberHost+"/v1/x", "text/plain", strings.NewReader("ping"))
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if string(body) != "echo:ping" || response.ProtoMajor != 1 {
			t.Fatalf("request %d: %s %q", i, response.Proto, body)
		}
		<-h.seen
	}
	if h.tunnel.Active() != 1 {
		t.Fatalf("keep-alive used %d tunnels, want 1", h.tunnel.Active())
	}
}
