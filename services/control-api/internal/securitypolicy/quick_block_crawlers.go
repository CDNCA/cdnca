package securitypolicy

import (
	"net/netip"
	"slices"
	"sort"
	"strings"
)

const (
	maxQuickBlockCrawlerContracts  = 64
	maxQuickBlockCrawlerCIDRs      = 64
	maxQuickBlockCrawlerUserAgents = 64
	maxQuickBlockCrawlerTextBytes  = 128
)

// TrustedCrawler is one quick block crawler exemption: a request from one of
// the networks whose User-Agent starts with one of the prefixes.
type TrustedCrawler struct {
	Networks          []string `json:"networks"`
	UserAgentPrefixes []string `json:"user_agent_prefixes"`
}

// NormalizeTrustedCrawlers validates and canonically orders a trusted
// crawler list: every contract has canonical, non-overlapping networks and
// sorted, unique user agent prefixes; contracts are unique.
func NormalizeTrustedCrawlers(input []TrustedCrawler) ([]TrustedCrawler, error) {
	if len(input) > maxQuickBlockCrawlerContracts {
		return nil, ErrInvalidInput
	}
	result := make([]TrustedCrawler, len(input))
	for index, crawler := range input {
		networks, err := normalizeCrawlerCIDRs(crawler.Networks)
		if err != nil || len(crawler.UserAgentPrefixes) == 0 || len(crawler.UserAgentPrefixes) > maxQuickBlockCrawlerUserAgents {
			return nil, ErrInvalidInput
		}
		prefixes := slices.Clone(crawler.UserAgentPrefixes)
		sort.Strings(prefixes)
		for prefixIndex, prefix := range prefixes {
			if !validCrawlerText(prefix) || prefixIndex > 0 && prefix == prefixes[prefixIndex-1] {
				return nil, ErrInvalidInput
			}
		}
		result[index] = TrustedCrawler{Networks: networks, UserAgentPrefixes: prefixes}
	}
	sort.Slice(result, func(left, right int) bool {
		if compared := slices.Compare(result[left].Networks, result[right].Networks); compared != 0 {
			return compared < 0
		}
		return slices.Compare(result[left].UserAgentPrefixes, result[right].UserAgentPrefixes) < 0
	})
	for index := 1; index < len(result); index++ {
		if slices.Equal(result[index-1].Networks, result[index].Networks) &&
			slices.Equal(result[index-1].UserAgentPrefixes, result[index].UserAgentPrefixes) {
			return nil, ErrInvalidInput
		}
	}
	return result, nil
}

func normalizeCrawlerCIDRs(input []string) ([]string, error) {
	if len(input) == 0 || len(input) > maxQuickBlockCrawlerCIDRs {
		return nil, ErrInvalidInput
	}
	prefixes := make([]netip.Prefix, len(input))
	for index, value := range input {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.String() != value || prefix != prefix.Masked() || prefix.Bits() == 0 || prefix.Addr().Is4In6() ||
			prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() || prefix.Addr().IsLoopback() ||
			prefix.Addr().IsLinkLocalUnicast() || prefix.Addr().IsLinkLocalMulticast() {
			return nil, ErrInvalidInput
		}
		for previous := 0; previous < index; previous++ {
			left := prefixes[previous]
			if left.Addr().BitLen() == prefix.Addr().BitLen() && (left.Contains(prefix.Addr()) || prefix.Contains(left.Addr())) {
				return nil, ErrInvalidInput
			}
		}
		prefixes[index] = prefix
	}
	sort.Slice(prefixes, func(left, right int) bool {
		if compared := prefixes[left].Addr().Compare(prefixes[right].Addr()); compared != 0 {
			return compared < 0
		}
		return prefixes[left].Bits() < prefixes[right].Bits()
	})
	result := make([]string, len(prefixes))
	for index, prefix := range prefixes {
		result[index] = prefix.String()
	}
	return result, nil
}

func validCrawlerText(value string) bool {
	return value == strings.TrimSpace(value) && len(value) > 0 && len(value) <= maxQuickBlockCrawlerTextBytes &&
		!strings.ContainsAny(value, "\x00\r\n  ")
}
