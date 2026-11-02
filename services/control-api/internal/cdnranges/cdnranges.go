// Package cdnranges holds the CDN edge address ranges control-api recognises
// without configuration: Cloudflare's published IPv4/IPv6 ranges, the same
// list agent-gateway ships as trusted_proxies_cloudflare.txt and migration
// 448 seeds into the Gateway trusted proxies (a test keeps the three equal).
//
// Uses: a node registration whose source address is a CDN edge keeps the
// installer-reported public IP (the console is behind the CDN without
// real-ip), and a Gateway host that resolves into these ranges is reached
// through the 443 WebSocket tunnel (the CDN forwards no Gateway port).
package cdnranges

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"time"
)

// Cloudflare: https://www.cloudflare.com/ips-v4 and /ips-v6 (fetched 2026-10-22,
// services/agent-gateway/trusted_proxies_cloudflare.txt).
var Cloudflare = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
	"108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
	"162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
	"2a06:98c0::/29", "2c0f:f248::/32",
}

var prefixes = func() []netip.Prefix {
	out := make([]netip.Prefix, 0, len(Cloudflare))
	for _, cidr := range Cloudflare {
		out = append(out, netip.MustParsePrefix(cidr))
	}
	return out
}()

// Contains reports whether address (an IP literal, IPv4-mapped IPv6 included)
// is a known CDN edge address.
func Contains(address string) bool {
	ip, err := netip.ParseAddr(strings.Trim(strings.TrimSpace(address), "[]"))
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	for _, prefix := range prefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// LookupFunc resolves a host name to its addresses (net.Resolver.LookupHost).
type LookupFunc func(ctx context.Context, host string) ([]string, error)

// HostBehindCDN reports whether host (a name or IP literal) resolves only to
// known CDN edge addresses. A lookup failure or an empty answer is false: the
// caller keeps its direct configuration.
func HostBehindCDN(ctx context.Context, lookup LookupFunc, host string) bool {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return Contains(host)
	}
	if lookup == nil {
		lookup = net.DefaultResolver.LookupHost
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	addresses, err := lookup(ctx, host)
	if err != nil || len(addresses) == 0 {
		return false
	}
	for _, address := range addresses {
		if !Contains(address) {
			return false
		}
	}
	return true
}
