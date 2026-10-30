package gateway

// Same-port dual transport (ADR 0013 §4.2, GW-03). Each gateway port keeps its
// gRPC server and TLS policy unchanged and additionally serves two WebSocket
// tunnel paths, so one port works for direct nodes and for CDN back-to-origin:
//
//   ClientHello ALPN offers only h2 (gRPC clients) -> the port's own
//       grpc.Server, which performs today's TLS handshake itself
//       (enrollment: server auth; agent: RequireAndVerifyClientCert)
//   anything else (http/1.1, no ALPN, CDN origin) -> TLS + HTTP/1.1:
//       /agent/v1/tunnel  signed upgrade token, then the inner TLS 1.3 mTLS
//                         gRPC connection goes to the agent grpc.Server
//       /agent/v1/enroll  no token, rate limited by source address, inner
//                         TLS goes to the enrollment grpc.Server
//
// Both paths exist on both ports because a CDN usually forwards one origin
// port. Tunnels are merged into the Accept stream of every shared listener of
// the matching kind, so grpc.Server.Serve, readiness and port transitions keep
// working on a plain net.Listener.

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type SharedListenerKind int

const (
	SharedListenerEnrollment SharedListenerKind = iota
	SharedListenerAgent
)

type TunnelRouterConfig struct {
	// Certificate is the gateway server certificate presented on the outer
	// HTTP/1.1 TLS (direct tunnel or CDN back-to-origin).
	Certificate tls.Certificate
	// GetCertificate, when set, replaces Certificate (renewable certificate).
	GetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	// NodeCAs verifies the node certificate carried in the upgrade token.
	NodeCAs *x509.CertPool
	// Audience is the installation ID signed into every upgrade token.
	Audience string
	Nonces   TunnelNonceStore
	// RealIP resolves the node address of an upgrade request (GW-05). Nil
	// means the TCP peer.
	RealIP func(*http.Request) (net.Addr, string)
	// EnrollmentRate is the number of enrollment tunnel upgrades accepted per
	// source address per minute.
	EnrollmentRate int
	Now            func() time.Time
	Logf           func(string, ...any)
}

type TunnelRouter struct {
	config     TunnelRouterConfig
	verifier   *tunnelTokenVerifier
	httpTLS    *tls.Config
	upgrader   websocket.Upgrader
	httpConns  *chanListener
	httpServer *http.Server
	tunnels    map[SharedListenerKind]chan net.Conn
	done       chan struct{}
	closeOnce  sync.Once
	limiter    *sourceRateLimiter
}

const (
	sharedPeekTimeout    = 10 * time.Second
	tunnelDeliverTimeout = 10 * time.Second
)

func outerTLS(config TunnelRouterConfig) *tls.Config {
	outer := &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}, ClientAuth: tls.NoClientCert}
	if config.GetCertificate != nil {
		outer.GetCertificate = config.GetCertificate
	} else {
		outer.Certificates = []tls.Certificate{config.Certificate}
	}
	return outer
}

func NewTunnelRouter(config TunnelRouterConfig) (*TunnelRouter, error) {
	if (len(config.Certificate.Certificate) == 0 && config.GetCertificate == nil) || config.NodeCAs == nil || config.Audience == "" || config.Nonces == nil {
		return nil, fmt.Errorf("tunnel router requires a certificate, node CA pool, audience and nonce store")
	}
	if config.EnrollmentRate <= 0 {
		config.EnrollmentRate = 30
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Logf == nil {
		config.Logf = log.Printf
	}
	router := &TunnelRouter{
		config:    config,
		verifier:  &tunnelTokenVerifier{audience: config.Audience, nodeCAs: config.NodeCAs, nonces: config.Nonces, now: config.Now},
		httpTLS:   outerTLS(config),
		upgrader:  websocket.Upgrader{ReadBufferSize: 32 << 10, WriteBufferSize: 32 << 10, CheckOrigin: func(*http.Request) bool { return true }},
		httpConns: newChanListener(&net.TCPAddr{IP: net.IPv4zero}, nil),
		tunnels:   map[SharedListenerKind]chan net.Conn{SharedListenerEnrollment: make(chan net.Conn), SharedListenerAgent: make(chan net.Conn)},
		done:      make(chan struct{}),
		limiter:   newSourceRateLimiter(config.EnrollmentRate, time.Minute, config.Now),
	}
	mux := http.NewServeMux()
	mux.HandleFunc(TunnelPath, router.serveTunnel)
	mux.HandleFunc(EnrollmentTunnelPath, router.serveEnrollmentTunnel)
	router.httpServer = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second, MaxHeaderBytes: 32 << 10}
	go func() { _ = router.httpServer.Serve(router.httpConns) }()
	return router, nil
}

func (r *TunnelRouter) Close() error {
	r.closeOnce.Do(func() {
		close(r.done)
		_ = r.httpServer.Close()
	})
	return nil
}

// Listen wraps raw so that direct gRPC connections and tunnels of kind share
// one Accept stream. Closing the returned listener closes raw.
func (r *TunnelRouter) Listen(raw net.Listener, kind SharedListenerKind) net.Listener {
	listener := &sharedListener{raw: raw, router: r, tunnels: r.tunnels[kind]}
	listener.direct = newChanListener(raw.Addr(), func() { _ = raw.Close() })
	go listener.acceptLoop()
	return listener
}

type sharedListener struct {
	raw     net.Listener
	router  *TunnelRouter
	direct  *chanListener
	tunnels chan net.Conn
}

func (l *sharedListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.direct.conns:
		return conn, nil
	case conn := <-l.tunnels:
		return conn, nil
	case <-l.direct.done:
		return nil, l.direct.err
	}
}

func (l *sharedListener) Close() error   { return l.direct.Close() }
func (l *sharedListener) Addr() net.Addr { return l.raw.Addr() }

func (l *sharedListener) acceptLoop() {
	for {
		raw, err := l.raw.Accept()
		if err != nil {
			var temporary interface{ Temporary() bool }
			if errors.As(err, &temporary) && temporary.Temporary() {
				time.Sleep(5 * time.Millisecond)
				continue
			}
			l.direct.fail(err)
			return
		}
		go l.route(raw)
	}
}

func (l *sharedListener) route(raw net.Conn) {
	_ = raw.SetDeadline(time.Now().Add(sharedPeekTimeout))
	protocols, prefix, err := peekClientHelloALPN(raw)
	_ = raw.SetDeadline(time.Time{})
	if err != nil {
		_ = raw.Close()
		return
	}
	conn := &prefixConn{Conn: raw, prefix: prefix}
	if grpcOnlyALPN(protocols) {
		l.direct.deliver(conn)
		return
	}
	l.router.httpConns.deliver(tls.Server(conn, l.router.httpTLS))
}

// grpcOnlyALPN is true for gRPC clients (they offer exactly h2). A CDN or
// tunnel client that also offers http/1.1 is served by HTTP/1.1.
func grpcOnlyALPN(protocols []string) bool {
	return slices.Contains(protocols, "h2") && !slices.Contains(protocols, "http/1.1")
}

type peekConn struct {
	net.Conn
	read bytes.Buffer
}

func (c *peekConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.read.Write(p[:n])
	return n, err
}

// Write discards the alert the aborted handshake sends.
func (c *peekConn) Write(p []byte) (int, error) { return len(p), nil }

var errClientHelloPeeked = errors.New("client hello peeked")

// peekClientHelloALPN reads one TLS ClientHello and returns its ALPN list and
// the bytes consumed, which the caller replays to the real handshake.
func peekClientHelloALPN(conn net.Conn) ([]string, []byte, error) {
	peek := &peekConn{Conn: conn}
	var protocols []string
	seen := false
	_ = tls.Server(peek, &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		protocols, seen = slices.Clone(hello.SupportedProtos), true
		return nil, errClientHelloPeeked
	}}).Handshake()
	if !seen {
		return nil, nil, errors.New("connection did not start with a TLS ClientHello")
	}
	return protocols, peek.read.Bytes(), nil
}

func (r *TunnelRouter) remote(request *http.Request) net.Addr {
	if r.config.RealIP != nil {
		addr, _ := r.config.RealIP(request)
		if addr != nil {
			return addr
		}
	}
	if addr, err := net.ResolveTCPAddr("tcp", request.RemoteAddr); err == nil {
		return addr
	}
	return &net.TCPAddr{IP: net.IPv4zero}
}

func (r *TunnelRouter) serveTunnel(w http.ResponseWriter, request *http.Request) {
	if _, err := r.verifier.verify(request.Context(), request.Header.Get(TunnelNodeCertificateHeader), request.Header.Get(TunnelNodeAuthHeader), TunnelPath); err != nil {
		r.config.Logf("agent-gateway tunnel rejected peer=%s error=%q", request.RemoteAddr, err.Error())
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	r.upgrade(w, request, SharedListenerAgent)
}

func (r *TunnelRouter) serveEnrollmentTunnel(w http.ResponseWriter, request *http.Request) {
	remote := r.remote(request)
	host, _, err := net.SplitHostPort(remote.String())
	if err != nil {
		host = remote.String()
	}
	if !r.limiter.allow(host) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	r.upgrade(w, request, SharedListenerEnrollment)
}

func (r *TunnelRouter) upgrade(w http.ResponseWriter, request *http.Request, kind SharedListenerKind) {
	if !websocket.IsWebSocketUpgrade(request) {
		http.Error(w, "websocket upgrade required", http.StatusBadRequest)
		return
	}
	remote := r.remote(request)
	ws, err := r.upgrader.Upgrade(w, request, nil)
	if err != nil {
		return
	}
	conn := &wsConn{ws: ws, remote: remote}
	timer := time.NewTimer(tunnelDeliverTimeout)
	defer timer.Stop()
	select {
	case r.tunnels[kind] <- conn:
	case <-r.done:
		_ = conn.Close()
	case <-timer.C:
		_ = conn.Close()
	case <-request.Context().Done():
		_ = conn.Close()
	}
}

type sourceRateLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	now    func() time.Time
	start  time.Time
	counts map[string]int
}

func newSourceRateLimiter(limit int, window time.Duration, now func() time.Time) *sourceRateLimiter {
	return &sourceRateLimiter{limit: limit, window: window, now: now, start: now(), counts: map[string]int{}}
}

func (l *sourceRateLimiter) allow(source string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now := l.now(); now.Sub(l.start) >= l.window {
		l.start, l.counts = now, map[string]int{}
	}
	if l.counts[source] >= l.limit {
		return false
	}
	l.counts[source]++
	return true
}
