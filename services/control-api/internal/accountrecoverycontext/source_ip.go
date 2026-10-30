package accountrecoverycontext

import (
	"errors"
	"net/http"
	"net/netip"
)

var (
	ErrSourceIPMissing = errors.New("source IP is missing")
	ErrSourceIPInvalid = errors.New("source IP is invalid")
	ErrSourceIPSpoofed = errors.New("source IP forwarding headers are untrusted")
)

type SourceIPResolver struct {
	trustedProxies []netip.Prefix
	maxProxyHops   int
}

func NewSourceIPResolver(trustedProxyCIDRs []string, maxProxyHops int) (*SourceIPResolver, error) {
	if maxProxyHops < 0 || maxProxyHops > maximumProxyHops {
		return nil, ErrInvalidConfig
	}
	if maxProxyHops == 0 {
		maxProxyHops = defaultMaxProxyHops
	}
	trusted := make([]netip.Prefix, 0, len(trustedProxyCIDRs))
	for _, raw := range trustedProxyCIDRs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || prefix != prefix.Masked() || prefix.String() != raw || prefix.Bits() == 0 ||
			prefix.Addr().Zone() != "" || prefix.Addr() != prefix.Addr().Unmap() {
			return nil, ErrInvalidConfig
		}
		for _, existing := range trusted {
			if existing.Contains(prefix.Addr()) || prefix.Contains(existing.Addr()) {
				return nil, ErrInvalidConfig
			}
		}
		trusted = append(trusted, prefix)
	}
	return &SourceIPResolver{trustedProxies: trusted, maxProxyHops: maxProxyHops}, nil
}

func (resolver *SourceIPResolver) ResolveSourceIP(request *http.Request) (netip.Addr, error) {
	if resolver == nil || request == nil {
		return netip.Addr{}, ErrSourceIPInvalid
	}
	peer, err := remotePeer(request.RemoteAddr)
	if err != nil {
		return netip.Addr{}, ErrSourceIPInvalid
	}
	forwardedPresent := len(request.Header.Values("Forwarded")) != 0
	xffPresent := len(request.Header.Values("X-Forwarded-For")) != 0
	if !resolver.isTrustedProxy(peer) {
		if forwardedPresent || xffPresent {
			return netip.Addr{}, ErrSourceIPSpoofed
		}
		return peer, nil
	}
	if !forwardedPresent && !xffPresent {
		return netip.Addr{}, ErrSourceIPMissing
	}
	if forwardedPresent && xffPresent {
		return netip.Addr{}, ErrSourceIPInvalid
	}

	var chain []netip.Addr
	if forwardedPresent {
		raw, _, err := singleHeader(request, "Forwarded")
		if err != nil {
			return netip.Addr{}, ErrSourceIPInvalid
		}
		values, err := parseForwarded(raw, resolver.maxProxyHops)
		if err != nil || !values.hasFor {
			return netip.Addr{}, ErrSourceIPInvalid
		}
		chain = values.forChain
	} else {
		raw, _, err := singleHeader(request, "X-Forwarded-For")
		if err != nil {
			return netip.Addr{}, ErrSourceIPInvalid
		}
		chain, err = parseXForwardedFor(raw, resolver.maxProxyHops)
		if err != nil {
			return netip.Addr{}, ErrSourceIPInvalid
		}
	}
	for index := len(chain) - 1; index >= 0; index-- {
		if !resolver.isTrustedProxy(chain[index]) {
			return chain[index].Unmap(), nil
		}
	}
	return netip.Addr{}, ErrSourceIPInvalid
}

func (resolver *SourceIPResolver) isTrustedProxy(address netip.Addr) bool {
	for _, prefix := range resolver.trustedProxies {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}
