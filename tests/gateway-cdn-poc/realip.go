package main

// Node real IP on the tunnel upgrade (ADR 0013 §4.4). Forwarded headers are
// read only when the TCP peer is inside a trusted CDN back-to-origin range,
// and only the header bound to that range (Cloudflare: CF-Connecting-IP,
// generic CDN: X-Forwarded-For). For X-Forwarded-For the list is walked from
// the right, skipping trusted hops; the first untrusted address wins. Any
// other header the client sent is ignored.

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

type trustedRange struct {
	prefix netip.Prefix
	header string
}

// parseTrusted reads "cidr=Header,cidr=Header".
func parseTrusted(value string) ([]trustedRange, error) {
	var result []trustedRange
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		cidr, header, ok := strings.Cut(item, "=")
		prefix, err := netip.ParsePrefix(cidr)
		if !ok || err != nil || header == "" {
			return nil, errors.New("invalid trusted range " + item)
		}
		result = append(result, trustedRange{prefix: prefix.Masked(), header: http.CanonicalHeaderKey(header)})
	}
	return result, nil
}

func trustedFor(addr netip.Addr, ranges []trustedRange) (trustedRange, bool) {
	for _, r := range ranges {
		if r.prefix.Contains(addr.Unmap()) {
			return r, true
		}
	}
	return trustedRange{}, false
}

// clientIP returns the node address and where it came from ("tcp" or
// "trusted_proxy").
func clientIP(remoteAddr string, header http.Header, ranges []trustedRange) (string, string) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return host, "tcp"
	}
	peer = peer.Unmap()
	bound, ok := trustedFor(peer, ranges)
	if !ok {
		return peer.String(), "tcp"
	}
	values := header.Values(bound.header)
	if bound.header != "X-Forwarded-For" {
		if len(values) == 1 {
			if addr, err := netip.ParseAddr(strings.TrimSpace(values[0])); err == nil {
				return addr.Unmap().String(), "trusted_proxy"
			}
		}
		return peer.String(), "tcp"
	}
	hops := strings.Split(strings.Join(values, ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		addr, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break // malformed hop: stop, do not look further left
		}
		if _, trusted := trustedFor(addr, ranges); !trusted {
			return addr.Unmap().String(), "trusted_proxy"
		}
	}
	return peer.String(), "tcp"
}
