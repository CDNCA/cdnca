// Package clientip decides the visitor address of a console request from
// the platform setting 源IP请求头 (system other settings source_ip_header,
// user): behind a CDN the TCP peer is the
// CDN node, and the administrator names the header the CDN writes the
// visitor address into. Empty keeps the direct connection's address.
//
// The console nginx overwrites X-Real-IP and X-Forwarded-For with its TCP
// peer for control-api (whose trusted-proxy resolver reads them), so the
// client's own values of those two arrive in ForwardedXRealIP and
// ForwardedXForwardedFor (scripts/install-control.sh write_nginx_config,
// converge-management-web-nginx.py). nginx sets both on every proxied
// location, which also drops any header of those names the client sent.
// CF-Connecting-IP and True-Client-IP pass through nginx unchanged.
package clientip

import (
	"context"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"
)

const (
	HeaderCFConnectingIP = "CF-Connecting-IP"
	HeaderTrueClientIP   = "True-Client-IP"
	// HeaderXForwardedFor takes the leftmost address of the client's X-Forwarded-For.
	HeaderXForwardedFor = "X-Forwarded-For"
	HeaderXRealIP       = "X-Real-IP"

	ForwardedXRealIP       = "X-Cdnca-Client-X-Real-IP"
	ForwardedXForwardedFor = "X-Cdnca-Client-X-Forwarded-For"
)

// Headers are the values source_ip_header takes besides "" (direct).
var Headers = []string{HeaderCFConnectingIP, HeaderTrueClientIP, HeaderXForwardedFor, HeaderXRealIP}

// ValidSetting reports whether value is "" or one of Headers.
func ValidSetting(value string) bool {
	if value == "" {
		return true
	}
	for _, header := range Headers {
		if value == header {
			return true
		}
	}
	return false
}

// FromHeader is the visitor address setting names in header; false when the
// setting is empty or the header holds no single valid address (the caller
// keeps the connection's address then).
func FromHeader(header http.Header, setting string) (netip.Addr, bool) {
	switch setting {
	case HeaderCFConnectingIP, HeaderTrueClientIP:
		return single(header.Values(setting))
	case HeaderXRealIP:
		return single(header.Values(ForwardedXRealIP))
	case HeaderXForwardedFor:
		values := header.Values(ForwardedXForwardedFor)
		if len(values) == 0 {
			return netip.Addr{}, false
		}
		first, _, _ := strings.Cut(values[0], ",")
		return parse(first)
	}
	return netip.Addr{}, false
}

func single(values []string) (netip.Addr, bool) {
	if len(values) != 1 {
		return netip.Addr{}, false
	}
	return parse(values[0])
}

// parse accepts one IPv4 or IPv6 address (no port or zone; an IPv4-mapped
// address is returned as IPv4). Unspecified, loopback and multicast
// addresses are no visitor.
func parse(raw string) (netip.Addr, bool) {
	address, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil || address.Zone() != "" {
		return netip.Addr{}, false
	}
	address = address.Unmap()
	if address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() {
		return netip.Addr{}, false
	}
	return address, true
}

type visitorKey struct{}

// WithVisitor records the visitor address FromHeader gave for this request.
func WithVisitor(ctx context.Context, address netip.Addr) context.Context {
	if !address.IsValid() {
		return ctx
	}
	return context.WithValue(ctx, visitorKey{}, address)
}

// Visitor is the address WithVisitor recorded; the source IP resolvers
// return it before their trusted-proxy rules.
func Visitor(ctx context.Context) (netip.Addr, bool) {
	if ctx == nil {
		return netip.Addr{}, false
	}
	address, ok := ctx.Value(visitorKey{}).(netip.Addr)
	return address, ok && address.IsValid()
}

// Setting is the live source_ip_header: read again at most every ttl, and
// replaced at once by Store when this process saves it, so a save applies
// without a restart. One request at a time reads; the others keep the last
// value meanwhile. A failed read keeps the last value ("" before the first).
type Setting struct {
	load       func(context.Context) (string, error)
	ttl        time.Duration
	now        func() time.Time
	state      atomic.Pointer[settingState]
	refreshing atomic.Bool
}

type settingState struct {
	value    string
	loadedAt time.Time
}

// settingReadTimeout bounds the read a request waits for.
const settingReadTimeout = 2 * time.Second

// NewSetting reads the setting with load (nil: always "").
func NewSetting(load func(context.Context) (string, error), ttl time.Duration) *Setting {
	return &Setting{load: load, ttl: ttl, now: time.Now}
}

// Current is the setting in force; an invalid stored value counts as "".
func (s *Setting) Current(ctx context.Context) string {
	if s == nil || s.load == nil {
		return ""
	}
	state := s.state.Load()
	now := s.now()
	if state != nil && !now.Before(state.loadedAt) && now.Sub(state.loadedAt) < s.ttl {
		return state.value
	}
	if !s.refreshing.CompareAndSwap(false, true) {
		if state == nil {
			return ""
		}
		return state.value
	}
	defer s.refreshing.Store(false)
	readCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), settingReadTimeout)
	defer cancel()
	value, err := s.load(readCtx)
	switch {
	case err != nil && state != nil:
		value = state.value
	case err != nil || !ValidSetting(value):
		value = ""
	}
	s.state.Store(&settingState{value: value, loadedAt: now})
	return value
}

// Store puts a value this process just saved in force.
func (s *Setting) Store(value string) {
	if s == nil {
		return
	}
	if !ValidSetting(value) {
		value = ""
	}
	s.state.Store(&settingState{value: value, loadedAt: s.now()})
}
