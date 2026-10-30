package controlgrpc

import (
	"context"
	"net"
	"sync/atomic"
	"time"
)

// AllowedSourcesFunc lists the addresses allowed on the remote listener
// (bound standalone Gateways, ADR 0013 §3.3 / GW-09).
type AllowedSourcesFunc func(context.Context) ([]net.IP, error)

// RemoteConfig opens a second ControlInternal listener for standalone
// Gateways. The TLS policy is the same as the loopback listener (TLS 1.3,
// verified Gateway client certificate); connections from any address that is
// not a bound Gateway are closed before the TLS handshake.
type RemoteConfig struct {
	ListenAddress   string
	AllowedSources  AllowedSourcesFunc
	RefreshInterval time.Duration
}

// sourceFilter is the current allow set, swapped atomically on refresh.
type sourceFilter struct {
	allowed atomic.Pointer[map[string]bool]
}

func (f *sourceFilter) set(ips []net.IP) {
	next := make(map[string]bool, len(ips))
	for _, ip := range ips {
		next[ip.String()] = true
	}
	f.allowed.Store(&next)
}

func (f *sourceFilter) allows(addr net.Addr) bool {
	tcp, ok := addr.(*net.TCPAddr)
	if !ok || tcp.IP == nil {
		return false
	}
	if tcp.IP.IsLoopback() {
		return true
	}
	ip := tcp.IP
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	allowed := f.allowed.Load()
	return allowed != nil && (*allowed)[ip.String()]
}

// filteredListener drops connections from addresses outside the filter.
type filteredListener struct {
	net.Listener
	filter *sourceFilter
}

func (l *filteredListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.filter.allows(conn.RemoteAddr()) {
			return conn, nil
		}
		_ = conn.Close()
	}
}

// refresh keeps the filter current until ctx ends. A failed refresh keeps
// the previous set (a database blip must not cut connected Gateways).
func (f *sourceFilter) refresh(ctx context.Context, list AllowedSourcesFunc, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			ips, err := list(callCtx)
			cancel()
			if err == nil {
				f.set(ips)
			}
		}
	}
}

// validateRemoteListenAddress accepts "host:port" with an IP host, including
// the unspecified address (0.0.0.0 / [::]) the remote listener binds to.
func validateRemoteListenAddress(address string) error {
	if err := validateListenAddress(address); err != nil {
		return err
	}
	host, _, _ := net.SplitHostPort(address)
	if net.ParseIP(host) == nil {
		return invalidConfig("remote listen host must be an IP address")
	}
	return nil
}
