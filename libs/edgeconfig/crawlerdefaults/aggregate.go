package crawlerdefaults

import (
	"fmt"
	"net/netip"
	"sort"
)

// Minimum prefix lengths aggregation may produce: a crawler list that only
// fits into a wider network is refused instead of trusting that network.
const (
	minAggregateBits4 = 12
	minAggregateBits6 = 24
)

// Aggregate returns the prefixes as canonical CIDR strings in string order, without
// duplicates or prefixes another one contains, sibling halves merged. Over
// maximum, the two neighbouring prefixes (same family) with the longest
// common supernet are replaced by that supernet until it fits: the result
// covers every input address and as few others as this greedy merge finds.
func Aggregate(prefixes []netip.Prefix, maximum int) ([]string, error) {
	list := normalize(prefixes)
	for len(list) > maximum {
		best, bestBits := -1, -1
		for index := 0; index+1 < len(list); index++ {
			left, right := list[index], list[index+1]
			if left.Addr().Is4() != right.Addr().Is4() {
				continue
			}
			if bits := commonBits(left, right); bits > bestBits {
				best, bestBits = index, bits
			}
		}
		if best < 0 {
			return nil, fmt.Errorf("%w: cannot aggregate %d networks", ErrInvalid, len(list))
		}
		minimum := minAggregateBits6
		if list[best].Addr().Is4() {
			minimum = minAggregateBits4
		}
		if bestBits < minimum {
			return nil, fmt.Errorf("%w: %d networks only fit in /%d networks", ErrInvalid, len(list), bestBits)
		}
		supernet, _ := list[best].Addr().Prefix(bestBits)
		list = normalize(append(append(append([]netip.Prefix(nil), list[:best]...), supernet), list[best+2:]...))
	}
	result := make([]string, len(list))
	for index, prefix := range list {
		result[index] = prefix.String()
	}
	// The CC policy wants networks in string order.
	sort.Strings(result)
	return result, nil
}

// normalize masks, sorts (IPv4 first, by address then length), drops
// prefixes contained in an earlier one and merges sibling halves.
func normalize(prefixes []netip.Prefix) []netip.Prefix {
	list := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		list = append(list, prefix.Masked())
	}
	for {
		sort.Slice(list, func(i, j int) bool {
			if list[i].Addr() != list[j].Addr() {
				return list[i].Addr().Less(list[j].Addr())
			}
			return list[i].Bits() < list[j].Bits()
		})
		out := list[:0:0]
		for _, prefix := range list {
			if len(out) > 0 && out[len(out)-1].Overlaps(prefix) && out[len(out)-1].Bits() <= prefix.Bits() {
				continue
			}
			out = append(out, prefix)
		}
		merged := false
		for index := 0; index+1 < len(out); index++ {
			left, right := out[index], out[index+1]
			if left.Bits() == right.Bits() && left.Bits() > 0 && left.Addr().Is4() == right.Addr().Is4() {
				parent, _ := left.Addr().Prefix(left.Bits() - 1)
				if parent.Addr() == left.Addr() && parent.Contains(right.Addr()) {
					out[index] = parent
					out = append(out[:index+1], out[index+2:]...)
					merged = true
				}
			}
		}
		list = out
		if !merged {
			return list
		}
	}
}

// commonBits is the length of the longest prefix containing both.
func commonBits(left, right netip.Prefix) int {
	a, b := left.Addr().AsSlice(), right.Addr().AsSlice()
	limit := min(left.Bits(), right.Bits())
	bits := 0
	for index := range a {
		x := a[index] ^ b[index]
		if x == 0 {
			bits += 8
			continue
		}
		for mask := byte(0x80); mask != 0 && x&mask == 0; mask >>= 1 {
			bits++
		}
		break
	}
	return min(bits, limit)
}
