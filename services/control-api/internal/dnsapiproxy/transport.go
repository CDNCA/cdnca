package dnsapiproxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

// ErrProxyUnavailable: the request never reached the DNS provider because the
// proxy could not be used (unreachable or timed out, TLS to the proxy failed,
// CONNECT refused or proxy authentication failed). Nothing was sent to the
// provider. The error names neither the proxy nor its credentials.
var ErrProxyUnavailable = errors.New("dns api http proxy unavailable")

// Setting is the live proxy: read again at most every ttl, and replaced at
// once by Store when this process saves it, so a save applies without a
// restart. One request at a time reads; the others keep the last value
// meanwhile. A failed read keeps the last value (direct before the first).
type Setting struct {
	load       func(context.Context) (string, error)
	ttl        time.Duration
	now        func() time.Time
	state      atomic.Pointer[settingState]
	refreshing atomic.Bool
}

type settingState struct {
	proxy    *url.URL
	loadedAt time.Time
}

// settingReadTimeout bounds the read a request waits for.
const settingReadTimeout = 2 * time.Second

// NewSetting reads the stored setting with load.
func NewSetting(load func(context.Context) (string, error), ttl time.Duration) *Setting {
	return &Setting{load: load, ttl: ttl, now: time.Now}
}

// Current is the proxy in force; nil means direct.
func (s *Setting) Current(ctx context.Context) *url.URL {
	if s == nil || s.load == nil {
		return nil
	}
	state := s.state.Load()
	now := s.now()
	if state != nil && !now.Before(state.loadedAt) && now.Sub(state.loadedAt) < s.ttl {
		return copyURL(state.proxy)
	}
	if !s.refreshing.CompareAndSwap(false, true) {
		if state == nil {
			return nil
		}
		return copyURL(state.proxy)
	}
	defer s.refreshing.Store(false)
	readCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), settingReadTimeout)
	defer cancel()
	raw, err := s.load(readCtx)
	var proxy *url.URL
	switch {
	case err != nil && state != nil:
		proxy = state.proxy
	case err == nil:
		proxy, _ = Parse(raw)
	}
	s.state.Store(&settingState{proxy: proxy, loadedAt: now})
	return copyURL(proxy)
}

// Store puts a value this process just saved in force.
func (s *Setting) Store(raw string) {
	if s == nil {
		return
	}
	proxy, _ := Parse(raw)
	s.state.Store(&settingState{proxy: proxy, loadedAt: s.now()})
}

func copyURL(value *url.URL) *url.URL {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}

var live atomic.Pointer[Setting]

// Use makes setting the proxy of every Transport (nil: direct).
func Use(setting *Setting) { live.Store(setting) }

// Store puts a value this process just saved in force for every Transport.
func Store(raw string) { live.Load().Store(raw) }

type recorderKey struct{}

// WithFailureRecorder returns ctx in which a request failing with
// ErrProxyUnavailable is recorded; failed reports whether one did. Callers
// that map transport errors to their own sentinels use it to tell proxy
// failures apart.
func WithFailureRecorder(ctx context.Context) (traced context.Context, failed func() bool) {
	flag := new(atomic.Bool)
	return context.WithValue(ctx, recorderKey{}, flag), flag.Load
}

// Transport sends requests through the live proxy (direct when none is set).
// Each proxy value has its own connection pool: net/http reuses an HTTP/2
// connection by target host alone, whatever proxy opened it, so one shared
// pool kept sending over the direct connection (or the old tunnel) after the
// setting changed (CONTROL-SOURCE-IP-HTTP-PROXY-RESTORE).
type Transport struct {
	base  *http.Transport // template, never used for requests
	mu    sync.Mutex
	key   string
	route *http.Transport
}

// NewTransport is a clone of base routed through the live proxy; nil base is
// http.DefaultTransport.
func NewTransport(base *http.Transport) *Transport {
	if base == nil {
		base = http.DefaultTransport.(*http.Transport)
	}
	cloned := base.Clone()
	cloned.Proxy = nil
	return &Transport{base: cloned}
}

// Proxy is the proxy request goes through (nil: direct).
func (t *Transport) Proxy(request *http.Request) (*url.URL, error) {
	return live.Load().Current(request.Context()), nil
}

func (t *Transport) CloseIdleConnections() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.route != nil {
		t.route.CloseIdleConnections()
	}
}

// routeFor is the pool of proxy; switching value closes the idle connections
// of the previous one (requests in flight on it finish there).
func (t *Transport) routeFor(proxy *url.URL) *http.Transport {
	key := ""
	if proxy != nil {
		key = proxy.String()
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.route != nil && t.key == key {
		return t.route
	}
	if t.route != nil {
		t.route.CloseIdleConnections()
	}
	route := t.base.Clone()
	if proxy != nil {
		route.Proxy = http.ProxyURL(proxy)
	}
	t.key, t.route = key, route
	return route
}

// RoundTrip fixes the proxy once per request and turns a failure before the
// provider's TLS handshake began (nothing reached the provider) into
// ErrProxyUnavailable.
func (t *Transport) RoundTrip(request *http.Request) (*http.Response, error) {
	ctx := request.Context()
	proxy := live.Load().Current(ctx)
	route := t.routeFor(proxy)
	if proxy == nil {
		return route.RoundTrip(request)
	}
	// TLS handshakes before the provider's: one with an https proxy.
	proxyHandshakes := int32(0)
	if proxy.Scheme == "https" {
		proxyHandshakes = 1
	}
	var handshakes atomic.Int32
	var connected atomic.Bool
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		TLSHandshakeStart: func() { handshakes.Add(1) },
		GotConn:           func(httptrace.GotConnInfo) { connected.Store(true) },
	})
	response, err := route.RoundTrip(request.WithContext(ctx))
	if err == nil || connected.Load() || handshakes.Load() > proxyHandshakes ||
		errors.Is(request.Context().Err(), context.Canceled) {
		return response, err
	}
	if flag, ok := request.Context().Value(recorderKey{}).(*atomic.Bool); ok {
		flag.Store(true)
	}
	return nil, ErrProxyUnavailable
}
