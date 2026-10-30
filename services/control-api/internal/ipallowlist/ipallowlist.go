// Package ipallowlist normalizes and matches source-address allowlists made of
// single IP addresses and CIDR prefixes. It backs the per-user login allowlist
// and the platform administration access allowlist.
package ipallowlist

import (
	"errors"
	"net/netip"
	"sort"
	"strings"
)

var ErrInvalidEntry = errors.New("invalid allowlist entry")

// Normalize canonicalizes entries: a bare address stays an address, a prefix is
// masked to its network ("10.1.2.3/8" becomes "10.0.0.0/8"), IPv4-mapped IPv6
// becomes IPv4, a full-length prefix collapses to the address. Duplicates are
// removed and the result is sorted. Zones are rejected.
func Normalize(values []string, maxEntries int) ([]string, error) {
	if values == nil || len(values) > maxEntries {
		return nil, ErrInvalidEntry
	}
	result := make([]string, 0, len(values))
	seen := make(map[string]bool, len(values))
	for _, raw := range values {
		canonical, err := Canonical(raw)
		if err != nil {
			return nil, err
		}
		if !seen[canonical] {
			result = append(result, canonical)
			seen[canonical] = true
		}
	}
	sort.Strings(result)
	return result, nil
}

// Canonical returns the canonical form of one address or prefix.
func Canonical(raw string) (string, error) {
	if raw == "" || raw != strings.TrimSpace(raw) || len(raw) > 64 {
		return "", ErrInvalidEntry
	}
	if !strings.Contains(raw, "/") {
		address, err := netip.ParseAddr(raw)
		if err != nil || address.Zone() != "" {
			return "", ErrInvalidEntry
		}
		return address.Unmap().String(), nil
	}
	prefix, err := netip.ParsePrefix(raw)
	if err != nil || prefix.Addr().Zone() != "" {
		return "", ErrInvalidEntry
	}
	address, bits := prefix.Addr(), prefix.Bits()
	if address.Is4In6() {
		if bits < 96 {
			return "", ErrInvalidEntry
		}
		address, bits = address.Unmap(), bits-96
	}
	prefix = netip.PrefixFrom(address, bits).Masked()
	if bits == address.BitLen() {
		return prefix.Addr().String(), nil
	}
	return prefix.String(), nil
}

// Contains reports whether source matches one of the canonical entries. An
// unparsable source never matches.
func Contains(entries []string, source string) bool {
	address, err := netip.ParseAddr(source)
	if err != nil || address.Zone() != "" {
		return false
	}
	address = address.Unmap()
	for _, entry := range entries {
		if strings.Contains(entry, "/") {
			prefix, err := netip.ParsePrefix(entry)
			if err == nil && prefix.Contains(address) {
				return true
			}
			continue
		}
		allowed, err := netip.ParseAddr(entry)
		if err == nil && allowed.Unmap() == address {
			return true
		}
	}
	return false
}
