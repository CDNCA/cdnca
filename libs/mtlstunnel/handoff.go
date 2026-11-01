package mtlstunnel

import (
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// Handoff is a net.Listener fed by HandoffServer: each upgraded tunnel
// becomes one accepted connection of the original mTLS http.Server, so its
// TLS config (client CA, RequireAndVerifyClientCert), handler and timeouts
// apply unchanged. Unlike a TCP bridge to the local port, the inner server
// sees the tunnel's source address (not loopback, which an operator source
// guard may always admit) and needs no PROXY header.
type Handoff struct {
	addr  net.Addr
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

// NewHandoff names the listener after the listener it stands in for.
func NewHandoff(name string) *Handoff {
	return &Handoff{addr: handoffAddr(name), conns: make(chan net.Conn), done: make(chan struct{})}
}

type handoffAddr string

func (a handoffAddr) Network() string { return "mtls-tunnel" }
func (a handoffAddr) String() string  { return string(a) }

func (h *Handoff) Accept() (net.Conn, error) {
	select {
	case c := <-h.conns:
		return c, nil
	case <-h.done:
		return nil, net.ErrClosed
	}
}

func (h *Handoff) Close() error {
	h.once.Do(func() { close(h.done) })
	return nil
}

func (h *Handoff) Addr() net.Addr { return h.addr }

func (h *Handoff) deliver(c net.Conn) bool {
	select {
	case h.conns <- c:
		return true
	case <-h.done:
		return false
	}
}

// MaxForwardedForBytes bounds the X-Forwarded-For value OriginAuth reads.
const MaxForwardedForBytes = 1024

// OriginAuth is 协议 T2 on a tunnel listener: a request carrying Header
// equal to Secret came through the CDN, which put the client in RealIPHeader.
// Same rules as services/management-web client_ip.go. Zero value: the TCP
// peer is the source.
type OriginAuth struct {
	Header       string
	Secret       []byte
	RealIPHeader string
}

// Source returns the client address of r and whether it came from the CDN header.
func (a OriginAuth) Source(r *http.Request) (netip.Addr, bool) {
	peer, _ := netip.ParseAddrPort(r.RemoteAddr)
	tcp := peer.Addr().Unmap()
	if len(a.Secret) == 0 || a.Header == "" || a.RealIPHeader == "" {
		return tcp, false
	}
	key := r.Header.Values(a.Header)
	if len(key) != 1 || subtle.ConstantTimeCompare([]byte(key[0]), a.Secret) != 1 {
		return tcp, false
	}
	values := r.Header.Values(a.RealIPHeader)
	if len(values) == 0 {
		return tcp, false
	}
	raw := values[0]
	if strings.EqualFold(a.RealIPHeader, "X-Forwarded-For") {
		// Right-most hop (A3e): the CDN appends the address it accepted the
		// connection from; whatever the client sent sits to its left.
		joined := strings.Join(values, ",")
		if len(joined) > MaxForwardedForBytes {
			return tcp, false
		}
		raw = joined[strings.LastIndexByte(joined, ',')+1:]
	} else if len(values) != 1 {
		return tcp, false
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil || ip.Zone() != "" {
		return tcp, false
	}
	return ip.Unmap(), true
}

// HandoffServer answers PathPrefix+<target> and hands each tunnel to
// Targets[target] (in-process, no TCP bridge).
type HandoffServer struct {
	Targets map[string]*Handoff
	// TotalLimit caps concurrent tunnels; 0 = DefaultTotalLimit.
	TotalLimit int
	Auth       OriginAuth
	// IdleTimeout closes a tunnel with no bytes either way; 0 = IdleTimeout.
	// The inner server's own deadlines cannot do it: it resets them per request.
	IdleTimeout time.Duration

	limiter
}

func (s *HandoffServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name, ok := strings.CutPrefix(r.URL.Path, PathPrefix)
	target, known := s.Targets[name]
	if !ok || !known {
		http.NotFound(w, r)
		return
	}
	if !slices.Contains(websocket.Subprotocols(r), Subprotocol) || !websocket.IsWebSocketUpgrade(r) {
		http.Error(w, "mTLS tunnel requires the "+Subprotocol+" WebSocket subprotocol", http.StatusBadRequest)
		return
	}
	source, _ := s.Auth.Source(r)
	key := source.String()
	if !s.take(s.TotalLimit, key) {
		http.Error(w, "too many tunnels", http.StatusServiceUnavailable)
		return
	}
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.give(key) // the upgrader has answered
		return
	}
	conn := &handedConn{wsConn: newWSConn(ws), remote: net.TCPAddrFromAddrPort(netip.AddrPortFrom(source, 0)), closed: make(chan struct{})}
	conn.onClose = func() { s.give(key) }
	conn.touch()
	idle := s.IdleTimeout
	if idle <= 0 {
		idle = IdleTimeout
	}
	go conn.watchIdle(idle)
	if !target.deliver(conn) {
		_ = conn.Close()
	}
}

// handedConn reports the tunnel source as RemoteAddr, closes after idle and
// frees its slot once.
type handedConn struct {
	*wsConn
	remote  net.Addr
	last    atomic.Int64
	closed  chan struct{}
	once    sync.Once
	onClose func()
}

func (c *handedConn) RemoteAddr() net.Addr { return c.remote }

func (c *handedConn) touch() { c.last.Store(time.Now().UnixNano()) }

func (c *handedConn) Read(p []byte) (int, error) {
	n, err := c.wsConn.Read(p)
	if n > 0 {
		c.touch()
	}
	return n, err
}

func (c *handedConn) Write(p []byte) (int, error) {
	n, err := c.wsConn.Write(p)
	if n > 0 {
		c.touch()
	}
	return n, err
}

func (c *handedConn) watchIdle(idle time.Duration) {
	ticker := time.NewTicker(min(idle/4, 5*time.Second))
	defer ticker.Stop()
	for {
		select {
		case <-c.closed:
			return
		case <-ticker.C:
			if time.Since(time.Unix(0, c.last.Load())) >= idle {
				_ = c.Close()
				return
			}
		}
	}
}

func (c *handedConn) Close() error {
	err := c.wsConn.Close()
	c.once.Do(func() { close(c.closed); c.onClose() })
	if errors.Is(err, net.ErrClosed) {
		return nil // already closed
	}
	return err
}
