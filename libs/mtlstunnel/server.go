package mtlstunnel

import (
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// Server answers PathPrefix+<target> and bridges each tunnel to Targets[target].
type Server struct {
	// Targets maps the whitelisted target name to a local host:port.
	Targets map[string]string
	// TotalLimit caps concurrent tunnels; 0 = DefaultTotalLimit.
	TotalLimit int
	// SourceIP is the client IP the per-source limit counts (协议 T2 real IP);
	// nil = host of RemoteAddr.
	SourceIP func(*http.Request) string
	// IdleTimeout closes a tunnel with no bytes either way; 0 = IdleTimeout.
	IdleTimeout time.Duration

	mu      sync.Mutex
	total   int
	sources map[string]int
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name, ok := strings.CutPrefix(r.URL.Path, PathPrefix)
	address, known := s.Targets[name]
	if !ok || !known {
		http.NotFound(w, r)
		return
	}
	source := remoteHost(r)
	if s.SourceIP != nil {
		source = s.SourceIP(r)
	}
	if !s.acquire(source) {
		http.Error(w, "too many tunnels", http.StatusServiceUnavailable)
		return
	}
	defer s.release(source)
	_ = bridge(w, r, address, s.IdleTimeout)
}

func (s *Server) acquire(source string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	limit := s.TotalLimit
	if limit <= 0 {
		limit = DefaultTotalLimit
	}
	if s.sources == nil {
		s.sources = map[string]int{}
	}
	if s.total >= limit || s.sources[source] >= PerSourceLimit {
		return false
	}
	s.total++
	s.sources[source]++
	return true
}

func (s *Server) release(source string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.total--
	if s.sources[source]--; s.sources[source] <= 0 {
		delete(s.sources, source)
	}
}

func remoteHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

var upgrader = websocket.Upgrader{
	ReadBufferSize: 32 << 10, WriteBufferSize: 32 << 10,
	Subprotocols: []string{Subprotocol},
	// The outer layer carries no identity (the inner mTLS does) and non-browser
	// clients send no Origin.
	CheckOrigin: func(*http.Request) bool { return true },
}

// Bridge upgrades r (it must offer Subprotocol, else 400) and copies raw
// bytes both ways between the WebSocket and a TCP connection to target
// (host:port), without looking at them. The tunnel closes when either side
// closes or nothing moved for IdleTimeout. Limits are the caller's (Server).
func Bridge(w http.ResponseWriter, r *http.Request, target string) error {
	return bridge(w, r, target, IdleTimeout)
}

func bridge(w http.ResponseWriter, r *http.Request, target string, idle time.Duration) error {
	if idle <= 0 {
		idle = IdleTimeout
	}
	if !slices.Contains(websocket.Subprotocols(r), Subprotocol) || !websocket.IsWebSocketUpgrade(r) {
		http.Error(w, "mTLS tunnel requires the "+Subprotocol+" WebSocket subprotocol", http.StatusBadRequest)
		return errSubprotocol
	}
	backend, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(r.Context(), "tcp", target)
	if err != nil {
		http.Error(w, "mTLS tunnel target unavailable", http.StatusBadGateway)
		return err
	}
	defer backend.Close()
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return err // the upgrader has answered
	}
	tunnel := newWSConn(ws)
	defer tunnel.Close()

	var last atomic.Int64
	touch := func() { last.Store(time.Now().UnixNano()) }
	touch()
	done := make(chan struct{}, 2)
	copyTouching := func(dst io.Writer, src io.Reader) {
		buffer := make([]byte, 32<<10)
		for {
			n, err := src.Read(buffer)
			if n > 0 {
				touch()
				if _, werr := dst.Write(buffer[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}
	go copyTouching(backend, tunnel)
	go copyTouching(tunnel, backend)
	ticker := time.NewTicker(min(idle/4, 5*time.Second))
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return nil
		case <-ticker.C:
			if time.Since(time.Unix(0, last.Load())) >= idle {
				return nil
			}
		}
	}
}

type tunnelError string

func (e tunnelError) Error() string { return string(e) }

const errSubprotocol = tunnelError("mTLS tunnel subprotocol missing")
