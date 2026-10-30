package gateway

// Node real IP on a tunnel upgrade (ADR 0013 §4.4, GW-05). A forwarded
// header is read only when the TCP peer is inside a trusted CDN
// back-to-origin range, and only the header bound to that range (Cloudflare:
// CF-Connecting-IP, other CDNs: X-Forwarded-For by default). X-Forwarded-For
// is walked from the right skipping trusted hops; the first untrusted address
// wins and a malformed hop stops the walk (fall back to the TCP peer). Direct
// gRPC sessions never read headers.

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"

	"google.golang.org/grpc/peer"
)

const (
	PeerIPSourceTCP          = "tcp"
	PeerIPSourceTrustedProxy = "trusted_proxy"
)

// DefaultTrustedProxies is the Cloudflare list shipped with the release (the
// only preset).
//
//go:embed trusted_proxies_cloudflare.txt
var DefaultTrustedProxies string

type TrustedProxyRange struct {
	Prefix netip.Prefix
	Header string
}

// ParseTrustedProxyRanges reads "cidr=Header,cidr=Header"; a bare cidr binds
// X-Forwarded-For.
func ParseTrustedProxyRanges(value string) ([]TrustedProxyRange, error) {
	var result []TrustedProxyRange
	var kept []string
	for _, line := range strings.Split(value, "\n") {
		if line, _, _ = strings.Cut(line, "#"); strings.TrimSpace(line) != "" {
			kept = append(kept, line)
		}
	}
	for _, item := range strings.FieldsFunc(strings.Join(kept, ","), func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\r' }) {
		cidr, header, found := strings.Cut(item, "=")
		if !found {
			header = "X-Forwarded-For"
		}
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil || header == "" || strings.ContainsAny(header, " :\r\n") {
			return nil, fmt.Errorf("invalid trusted proxy range %q", item)
		}
		result = append(result, TrustedProxyRange{Prefix: prefix.Masked(), Header: http.CanonicalHeaderKey(header)})
	}
	return result, nil
}

// TrustedProxies is swapped atomically when the control plane publishes a
// new set (GW-06 page); the zero value trusts nothing.
type TrustedProxies struct {
	ranges atomic.Pointer[[]TrustedProxyRange]
}

func NewTrustedProxies(ranges []TrustedProxyRange) *TrustedProxies {
	t := &TrustedProxies{}
	t.Set(ranges)
	return t
}

func (t *TrustedProxies) Set(ranges []TrustedProxyRange) {
	copied := append([]TrustedProxyRange(nil), ranges...)
	t.ranges.Store(&copied)
}

func (t *TrustedProxies) list() []TrustedProxyRange {
	if t == nil {
		return nil
	}
	if ranges := t.ranges.Load(); ranges != nil {
		return *ranges
	}
	return nil
}

func trustedRangeFor(addr netip.Addr, ranges []TrustedProxyRange) (TrustedProxyRange, bool) {
	for _, r := range ranges {
		if r.Prefix.Contains(addr.Unmap()) {
			return r, true
		}
	}
	return TrustedProxyRange{}, false
}

// ClientIP returns the node address of an upgrade request and its source.
func (t *TrustedProxies) ClientIP(remoteAddr string, header http.Header) (netip.Addr, string, error) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	peerAddr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, "", errors.New("request peer address is not an IP")
	}
	peerAddr = peerAddr.Unmap().WithZone("")
	ranges := t.list()
	bound, ok := trustedRangeFor(peerAddr, ranges)
	if !ok {
		return peerAddr, PeerIPSourceTCP, nil
	}
	values := header.Values(bound.Header)
	if bound.Header != "X-Forwarded-For" {
		if len(values) == 1 {
			if addr, err := netip.ParseAddr(strings.TrimSpace(values[0])); err == nil {
				return addr.Unmap().WithZone(""), PeerIPSourceTrustedProxy, nil
			}
		}
		return peerAddr, PeerIPSourceTCP, nil
	}
	hops := strings.Split(strings.Join(values, ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		addr, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		if _, trusted := trustedRangeFor(addr, ranges); !trusted {
			return addr.Unmap().WithZone(""), PeerIPSourceTrustedProxy, nil
		}
	}
	return peerAddr, PeerIPSourceTCP, nil
}

// RealIP adapts ClientIP to TunnelRouterConfig.RealIP.
func (t *TrustedProxies) RealIP(request *http.Request) (net.Addr, string) {
	addr, source, err := t.ClientIP(request.RemoteAddr, request.Header)
	if err != nil {
		return nil, ""
	}
	return &tunnelPeerAddr{TCPAddr: net.TCPAddrFromAddrPort(netip.AddrPortFrom(addr, 0)), source: source}, source
}

// tunnelPeerAddr is the RemoteAddr of a tunnel connection; gRPC exposes it
// as peer.Addr, so handlers learn both the resolved address and its source.
type tunnelPeerAddr struct {
	*net.TCPAddr
	source string
}

// peerAddress returns the node address and its source for a gRPC context.
func peerAddress(ctx context.Context) (netip.Addr, string, bool) {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return netip.Addr{}, "", false
	}
	source := PeerIPSourceTCP
	if tunnel, ok := p.Addr.(*tunnelPeerAddr); ok {
		source = tunnel.source
	}
	host, _, err := net.SplitHostPort(p.Addr.String())
	if err != nil {
		return netip.Addr{}, "", false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || addr.Zone() != "" {
		return netip.Addr{}, "", false
	}
	return addr.Unmap(), source, true
}
