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

	limiter
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
	if !s.take(s.TotalLimit, source) {
		http.Error(w, "too many tunnels", http.StatusServiceUnavailable)
		return
	}
	defer s.give(source)
	_ = bridge(w, r, address, s.IdleTimeout)
}

// limiter counts open tunnels in total and per source (client IP).
type limiter struct {
	mu      sync.Mutex
	total   int
	sources map[string]int
}

func (l *limiter) take(totalLimit int, source string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if totalLimit <= 0 {
		totalLimit = DefaultTotalLimit
	}
	if l.sources == nil {
		l.sources = map[string]int{}
	}
	if l.total >= totalLimit || l.sources[source] >= PerSourceLimit {
		return false
	}
	l.total++
	l.sources[source]++
	return true
}

func (l *limiter) give(source string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.total--
	if l.sources[source]--; l.sources[source] <= 0 {
		delete(l.sources, source)
	}
}

// Active reports the open tunnels (tests, logs).
func (l *limiter) Active() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.total
}

func remoteHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// writeBuffers lends the 32 KiB WebSocket write buffer only while a message
// is written; an idle tunnel holds none. ReadBufferSize 0 reuses
// the HTTP server's read buffer (the dialer gets gorilla's 4 KiB default).
var writeBuffers = &sync.Pool{}

var upgrader = websocket.Upgrader{
	WriteBufferSize: 32 << 10, WriteBufferPool: writeBuffers,
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
