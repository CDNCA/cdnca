package securitypolicy

import (
	"net/netip"
	"strings"
)

// maxIPConditionValues bounds a client_ip CIDR condition after ranges are
// expanded (a range a-b becomes up to 2*bits CIDRs).
const maxIPConditionValues = 256

// ParseIPNetworks reads one client network value (NF27): a CIDR (host bits
// are cleared), an address (/32 or /128), an IPv4 address with a dotted
// netmask ("10.0.0.1/255.255.255.0") or a range "a-b" of one family, which
// becomes the fewest CIDRs covering exactly a..b. IPv4-mapped IPv6 and zoned
// addresses are refused.
func ParseIPNetworks(raw string) ([]netip.Prefix, error) {
	value := strings.TrimSpace(raw)
	if first, last, isRange := strings.Cut(value, "-"); isRange {
		start, startErr := parsePlainAddr(first)
		end, endErr := parsePlainAddr(last)
		if startErr != nil || endErr != nil || start.BitLen() != end.BitLen() || end.Less(start) {
			return nil, ErrInvalidInput
		}
		return rangeToPrefixes(start, end, maxIPConditionValues)
	}
	if address, mask, hasMask := strings.Cut(value, "/"); hasMask && strings.Contains(mask, ".") {
		start, err := parsePlainAddr(address)
		netmask, maskErr := parsePlainAddr(mask)
		if err != nil || maskErr != nil || !start.Is4() || !netmask.Is4() {
			return nil, ErrInvalidInput
		}
		bits, ok := netmaskBits(netmask.As4())
		if !ok {
			return nil, ErrInvalidInput
		}
		return []netip.Prefix{netip.PrefixFrom(start, bits).Masked()}, nil
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		address, addressErr := parsePlainAddr(value)
		if addressErr != nil {
			return nil, ErrInvalidInput
		}
		prefix = netip.PrefixFrom(address, address.BitLen())
	}
	if prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
		return nil, ErrInvalidInput
	}
	return []netip.Prefix{prefix.Masked()}, nil
}

func parsePlainAddr(raw string) (netip.Addr, error) {
	address, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil || address.Is4In6() || address.Zone() != "" {
		return netip.Addr{}, ErrInvalidInput
	}
	return address, nil
}

// netmaskBits is the prefix length of a contiguous IPv4 netmask.
func netmaskBits(mask [4]byte) (int, bool) {
	value := uint32(mask[0])<<24 | uint32(mask[1])<<16 | uint32(mask[2])<<8 | uint32(mask[3])
	bits := 0
	for bits < 32 && value&(1<<(31-bits)) != 0 {
		bits++
	}
	if bits < 32 && value<<bits != 0 {
		return 0, false
	}
	return bits, true
}

// rangeToPrefixes covers start..end with the fewest aligned CIDRs.
func rangeToPrefixes(start, end netip.Addr, limit int) ([]netip.Prefix, error) {
	result := []netip.Prefix{}
	width := start.BitLen()
	for current := start; ; {
		// The shortest prefix that starts at current and stays within end.
		bits := width
		for bits > 0 {
			candidate := netip.PrefixFrom(current, bits-1)
			if candidate.Masked().Addr() != current || lastAddr(candidate).Compare(end) > 0 {
				break
			}
			bits--
		}
		prefix := netip.PrefixFrom(current, bits)
		if result = append(result, prefix); len(result) > limit {
			return nil, ErrInvalidInput
		}
		last := lastAddr(prefix)
		if last.Compare(end) >= 0 {
			return result, nil
		}
		current = last.Next()
	}
}

func lastAddr(prefix netip.Prefix) netip.Addr {
	bytes := prefix.Masked().Addr().AsSlice()
	for bit := prefix.Bits(); bit < len(bytes)*8; bit++ {
		bytes[bit/8] |= 0x80 >> (bit % 8)
	}
	address, _ := netip.AddrFromSlice(bytes)
	return address
}
