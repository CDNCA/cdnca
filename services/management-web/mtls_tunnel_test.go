package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/mtlstunnel"
	"github.com/gorilla/websocket"
)

// wsConn adapts a client websocket to net.Conn the way the T1 client does
// (gatewaytunnel conn): binary frames in both directions.
type wsConn struct {
	*websocket.Conn
	reader io.Reader
	wmu    sync.Mutex
}

func (c *wsConn) Read(p []byte) (int, error) {
	for {
		if c.reader == nil {
			kind, reader, err := c.NextReader()
			if err != nil {
				return 0, err
			}
			if kind != websocket.BinaryMessage {
				continue
			}
			c.reader = reader
		}
		n, err := c.reader.Read(p)
		if errors.Is(err, io.EOF) {
			c.reader = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

func (c *wsConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	for start := 0; start < len(p); start += mtlstunnel.MaxFrameBytes {
		end := min(start+mtlstunnel.MaxFrameBytes, len(p))
		if err := c.WriteMessage(websocket.BinaryMessage, p[start:end]); err != nil {
			return start, err
		}
	}
	return len(p), nil
}

func (c *wsConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

// tunnelFront serves the front handler with only the given tunnel targets.
func tunnelFront(t *testing.T, targets map[string]string, configure func(*mtlsTunnel)) *httptest.Server {
	t.Helper()
	return tunnelFrontWith(t, targets, configure, clientIPResolver{authHeader: defaultOriginAuthHeader})
}

func tunnelFrontWith(t *testing.T, targets map[string]string, configure func(*mtlsTunnel), resolver clientIPResolver) *httptest.Server {
	t.Helper()
	tunnel := newMTLSTunnel(targets, 0)
	if configure != nil {
		configure(tunnel)
	}
	upstream, _ := url.Parse("http://127.0.0.1:1")
	handler, err := newHandlerWithOptions(testStaticRoot(t), upstream, handlerOptions{
		ClientIP: resolver, Tunnel: tunnel})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

func dialTunnel(t *testing.T, server *httptest.Server, target string, subprotocols []string) (*wsConn, *http.Response, error) {
	t.Helper()
	return dialTunnelWith(t, server, target, subprotocols, nil)
}

func dialTunnelWith(t *testing.T, server *httptest.Server, target string, subprotocols []string, header http.Header) (*wsConn, *http.Response, error) {
	t.Helper()
	dialer := websocket.Dialer{Subprotocols: subprotocols, HandshakeTimeout: 5 * time.Second}
	address := "ws" + strings.TrimPrefix(server.URL, "http") + mtlstunnel.PathPrefix + target
	ws, response, err := dialer.Dial(address, header)
	if err != nil {
		return nil, response, err
	}
	t.Cleanup(func() { _ = ws.Close() })
	return &wsConn{Conn: ws}, response, nil
}

// echoBackend accepts TCP connections and echoes them, reporting each
// connection's received byte count when it closes.
func echoBackend(t *testing.T) (string, chan int64) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	received := make(chan int64, 16)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				n, _ := io.Copy(conn, conn)
				received <- n
			}()
		}
	}()
	return listener.Addr().String(), received
}

func TestTunnelUnknownTargetIs404(t *testing.T) {
	address, _ := echoBackend(t)
	server := tunnelFront(t, map[string]string{"plugin-runtime": address}, nil)
	_, response, err := dialTunnel(t, server, "license-db", []string{mtlstunnel.Subprotocol})
	if err == nil || response == nil || response.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown target: err=%v response=%v", err, response)
	}
	// The tunnel prefix never falls through to the SPA index.
	plain, err := http.Get(server.URL + mtlstunnel.PathPrefix + "license-db")
	if err != nil {
		t.Fatal(err)
	}
	_ = plain.Body.Close()
	if plain.StatusCode != http.StatusNotFound {
		t.Fatalf("plain GET status=%d", plain.StatusCode)
	}
}

func TestTunnelRequiresSubprotocol(t *testing.T) {
	address, _ := echoBackend(t)
	server := tunnelFront(t, map[string]string{"plugin-runtime": address}, nil)
	for _, offered := range [][]string{nil, {"chat"}} {
		_, response, err := dialTunnel(t, server, "plugin-runtime", offered)
		if err == nil || response == nil || response.StatusCode != http.StatusBadRequest {
			t.Fatalf("subprotocols %v: err=%v response=%v", offered, err, response)
		}
	}
	plain, err := http.Get(server.URL + mtlstunnel.PathPrefix + "plugin-runtime")
	if err != nil {
		t.Fatal(err)
	}
	_ = plain.Body.Close()
	if plain.StatusCode != http.StatusBadRequest {
		t.Fatalf("non-upgrade status=%d", plain.StatusCode)
	}
}

func TestTunnelBridgesBytesBothWays(t *testing.T) {
	address, received := echoBackend(t)
	server := tunnelFront(t, map[string]string{"plugin-runtime": address}, nil)
	conn, response, err := dialTunnel(t, server, "plugin-runtime", []string{"other", mtlstunnel.Subprotocol})
	if err != nil {
		t.Fatal(err)
	}
	if got := response.Header.Get("Sec-WebSocket-Protocol"); got != mtlstunnel.Subprotocol {
		t.Fatalf("subprotocol answered %q", got)
	}
	payload := make([]byte, 300<<10) // spans several 64 KiB frames each way
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	go func() { _, _ = conn.Write(payload) }()
	echoed := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, echoed); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(echoed, payload) {
		t.Fatal("echoed bytes differ")
	}
	_ = conn.Close()
	select {
	case n := <-received:
		if n != int64(len(payload)) {
			t.Fatalf("backend received %d bytes, want %d", n, len(payload))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("backend connection not closed after client close")
	}
}

func TestTunnelRejectsOversizedFrame(t *testing.T) {
	address, _ := echoBackend(t)
	server := tunnelFront(t, map[string]string{"plugin-runtime": address}, nil)
	conn, _, err := dialTunnel(t, server, "plugin-runtime", []string{mtlstunnel.Subprotocol})
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := conn.WriteMessage(websocket.BinaryMessage, make([]byte, mtlstunnel.MaxFrameBytes+1)); err != nil {
		t.Fatal(err)
	}
	// gorilla fragments the message, so leading fragments may be bridged and
	// echoed before the limit trips; the tunnel must close before all of it.
	echoed := 0
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			if !websocket.IsCloseError(err, websocket.CloseMessageTooBig) {
				t.Fatalf("closed with %v, want 1009 message too big", err)
			}
			break
		}
		echoed += len(message)
	}
	if echoed > mtlstunnel.MaxFrameBytes {
		t.Fatalf("echoed %d bytes of an oversized message", echoed)
	}
}

// Behind a CDN every tunnel arrives from the CDN's egress address (here all
// from 127.0.0.1). The per-source limit must count the T2 client, so one
// client stops at mtlstunnel.PerSourceLimit while another still gets in.
func TestTunnelPerSourceLimitCountsT2Client(t *testing.T) {
	address, _ := echoBackend(t)
	server := tunnelFrontWith(t, map[string]string{"plugin-runtime": address}, nil, cdnResolver("CF-Connecting-IP"))
	client := func(ip string) http.Header {
		return http.Header{defaultOriginAuthHeader: {testOriginSecret}, "Cf-Connecting-Ip": {ip}}
	}
	for i := 0; i < mtlstunnel.PerSourceLimit; i++ {
		if _, _, err := dialTunnelWith(t, server, "plugin-runtime", []string{mtlstunnel.Subprotocol}, client("198.51.100.7")); err != nil {
			t.Fatalf("tunnel %d: %v", i, err)
		}
	}
	_, response, err := dialTunnelWith(t, server, "plugin-runtime", []string{mtlstunnel.Subprotocol}, client("198.51.100.7"))
	if err == nil || response == nil || response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("over per-source limit: err=%v response=%v", err, response)
	}
	if _, _, err := dialTunnelWith(t, server, "plugin-runtime", []string{mtlstunnel.Subprotocol}, client("2001:db8::7")); err != nil {
		t.Fatalf("another client behind the same CDN address was refused: %v", err)
	}
}

func TestTunnelSourceIPIsT2Client(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, mtlstunnel.PathPrefix+"plugin-runtime", nil)
	request.RemoteAddr = "203.0.113.9:4000"
	request.Header.Set(defaultOriginAuthHeader, testOriginSecret)
	request.Header.Set("X-Forwarded-For", "192.0.2.66, 2001:db8::7")
	cdnResolver("X-Forwarded-For").apply(request)
	if got := tunnelSourceIP(request); got != "2001:db8::7" {
		t.Fatalf("SourceIP = %q, want the T2 client", got)
	}
	plain := httptest.NewRequest(http.MethodGet, mtlstunnel.PathPrefix+"plugin-runtime", nil)
	plain.RemoteAddr = "203.0.113.9:4000"
	plain.Header.Set("X-Forwarded-For", "2001:db8::7")
	cdnResolver("X-Forwarded-For").apply(plain)
	if got := tunnelSourceIP(plain); got != "203.0.113.9" {
		t.Fatalf("unauthenticated SourceIP = %q, want the TCP peer", got)
	}
}

func TestTunnelTotalLimitAndRelease(t *testing.T) {
	address, _ := echoBackend(t)
	server := tunnelFront(t, map[string]string{"plugin-runtime": address}, func(tunnel *mtlsTunnel) { tunnel.server.TotalLimit = 1 })
	first, _, err := dialTunnel(t, server, "plugin-runtime", []string{mtlstunnel.Subprotocol})
	if err != nil {
		t.Fatal(err)
	}
	if _, response, err := dialTunnel(t, server, "plugin-runtime", []string{mtlstunnel.Subprotocol}); err == nil ||
		response == nil || response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("over total: err=%v response=%v", err, response)
	}
	_ = first.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, _, err := dialTunnel(t, server, "plugin-runtime", []string{mtlstunnel.Subprotocol}); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("slot not released after close")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestTunnelIdleTimeout(t *testing.T) {
	address, received := echoBackend(t)
	server := tunnelFront(t, map[string]string{"plugin-runtime": address}, func(tunnel *mtlsTunnel) { tunnel.server.IdleTimeout = 200 * time.Millisecond })
	conn, _, err := dialTunnel(t, server, "plugin-runtime", []string{mtlstunnel.Subprotocol})
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := conn.ReadMessage(); err == nil {
		t.Fatal("idle tunnel still open")
	}
	select {
	case <-received:
	case <-time.After(5 * time.Second):
		t.Fatal("backend not closed on idle")
	}
}

// The inner layer is the original mTLS: TLS 1.3, client certificate required,
// ServerName is the public host. The front only moves bytes.
func TestTunnelCarriesInnerMutualTLS(t *testing.T) {
	ca, caKey := testCA(t)
	serverCert := testLeaf(t, ca, caKey, "auth.cdnca.com", x509.ExtKeyUsageServerAuth)
	clientCert := testLeaf(t, ca, caKey, "installation", x509.ExtKeyUsageClientAuth)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(response, "peer="+request.TLS.PeerCertificates[0].Subject.CommonName)
	}))
	backend.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	backend.StartTLS()
	t.Cleanup(backend.Close)
	server := tunnelFront(t, map[string]string{"plugin-runtime": backend.Listener.Addr().String()}, nil)

	client := func(certificates []tls.Certificate) *http.Client {
		return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "auth.cdnca.com", RootCAs: pool, Certificates: certificates},
			DialContext: func(context.Context, string, string) (net.Conn, error) {
				conn, _, err := dialTunnel(t, server, "plugin-runtime", []string{mtlstunnel.Subprotocol})
				if err != nil {
					return nil, err
				}
				return conn, nil
			},
		}}
	}
	response, err := client([]tls.Certificate{clientCert}).Get("https://auth.cdnca.com:9448/plugin-runtime/v1/ping")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || string(body) != "peer=installation" {
		t.Fatalf("inner response %d %q", response.StatusCode, body)
	}
	if response.TLS == nil || response.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("inner TLS = %+v", response.TLS)
	}
	// Without a client certificate the inner handshake is refused end to end.
	if response, err := client(nil).Get("https://auth.cdnca.com:9448/plugin-runtime/v1/ping"); err == nil {
		_ = response.Body.Close()
		t.Fatalf("no client certificate: status %d", response.StatusCode)
	}
}

// End to end with the shared client: libs/mtlstunnel.NewClient + Apply (what
// control-api uses) → this front over outer TLS → inner
// TLS 1.3 mTLS backends for both default targets. Unknown targets and a client
// without a certificate are still refused.
func TestSharedClientThroughFront(t *testing.T) {
	ca, caKey := testCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	backend := func(name string) string {
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			_, _ = io.WriteString(response, name+" peer="+request.TLS.PeerCertificates[0].Subject.CommonName)
		}))
		server.TLS = &tls.Config{MinVersion: tls.VersionTLS13,
			Certificates: []tls.Certificate{testLeaf(t, ca, caKey, "auth.cdnca.com", x509.ExtKeyUsageServerAuth)},
			ClientAuth:   tls.RequireAndVerifyClientCert, ClientCAs: pool}
		server.StartTLS()
		t.Cleanup(server.Close)
		return server.Listener.Addr().String()
	}
	tunnel := newMTLSTunnel(map[string]string{
		mtlstunnel.TargetPluginRuntime: backend("9448"), mtlstunnel.TargetMarketLicense: backend("9447")}, 0)
	upstream, _ := url.Parse("http://127.0.0.1:1")
	handler, err := newHandlerWithOptions(testStaticRoot(t), upstream, handlerOptions{
		ClientIP: clientIPResolver{authHeader: defaultOriginAuthHeader}, Tunnel: tunnel})
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewTLSServer(handler) // the CDN 443 stand-in (outer TLS)
	t.Cleanup(front.Close)
	frontRoots := x509.NewCertPool()
	frontRoots.AddCert(front.Certificate())

	clientCert := testLeaf(t, ca, caKey, "installation", x509.ExtKeyUsageClientAuth)
	get := func(originURL, target string, certificates []tls.Certificate) (string, error) {
		client, err := mtlstunnel.NewClient(originURL, front.URL, target)
		if err != nil {
			t.Fatal(err)
		}
		client.Roots = frontRoots
		transport := mtlstunnel.Apply(&http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: certificates}}, client.DialContext)
		defer transport.CloseIdleConnections()
		response, err := (&http.Client{Timeout: 10 * time.Second, Transport: transport}).Get(originURL + "/v1/ping")
		if err != nil {
			return "", err
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		if response.TLS == nil || response.TLS.Version != tls.VersionTLS13 || response.TLS.ServerName != "auth.cdnca.com" {
			t.Fatalf("inner TLS = %+v", response.TLS)
		}
		return string(body), nil
	}
	for target, want := range map[string]string{
		mtlstunnel.TargetPluginRuntime: "9448 peer=installation", mtlstunnel.TargetMarketLicense: "9447 peer=installation"} {
		port := map[string]string{mtlstunnel.TargetPluginRuntime: "9448", mtlstunnel.TargetMarketLicense: "9447"}[target]
		body, err := get("https://auth.cdnca.com:"+port, target, []tls.Certificate{clientCert})
		if err != nil || body != want {
			t.Fatalf("%s: body=%q err=%v", target, body, err)
		}
	}
	if _, err := get("https://auth.cdnca.com:9448", mtlstunnel.TargetMarketMember, []tls.Certificate{clientCert}); err == nil ||
		!strings.Contains(err.Error(), "404") {
		t.Fatalf("target not served here: err=%v, want 404 upgrade failure", err)
	}
	if _, err := get("https://auth.cdnca.com:9448", mtlstunnel.TargetPluginRuntime, nil); err == nil {
		t.Fatal("inner mTLS accepted a client without a certificate")
	}
}

func TestParseTunnelTargets(t *testing.T) {
	targets, err := parseTunnelTargets(defaultTunnelTargets)
	if err != nil || len(targets) != 2 || targets["plugin-runtime"] != "127.0.0.1:9448" || targets["market-license"] != "127.0.0.1:9447" {
		t.Fatalf("defaults = %v %v", targets, err)
	}
	if targets, err := parseTunnelTargets(""); err != nil || len(targets) != 0 {
		t.Fatalf("empty = %v %v", targets, err)
	}
	for _, bad := range []string{"plugin-runtime", "a=localhost:1", "a/b=127.0.0.1:1", "a=127.0.0.1:1,a=127.0.0.1:2"} {
		if _, err := parseTunnelTargets(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func testCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return ca, key
}

func testLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, name string, usage x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
