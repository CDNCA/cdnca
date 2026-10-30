package xdp

import (
	"strings"
)

// SiteDrop is the level D site drop (攻击自动升级 D 级, esc-node §3) the
// program enforces before everything else (exempt networks included):
//   - Ports: every TCP packet to them (ports only level D sites use);
//   - SNIPorts: shared TLS ports; a ClientHello there whose server name
//     matches DropNames (exact, or a leading wildcard "*.example.com") is
//     dropped, unless KeepNames (other sites on those ports) has a more
//     specific match: an exact name beats a wildcard, a longer wildcard a
//     shorter one, as nginx selects the server.
//
// A ClientHello the program cannot parse in the first segment passes
// (OpenResty closes it, esc-node §4). The zero SiteDrop drops nothing.
type SiteDrop struct {
	Ports     []uint16
	SNIPorts  []uint16
	DropNames []string
	KeepNames []string
}

// MaxSiteDropNames bounds the distinct names of a SiteDrop (cdnca_xdp_sni's
// max_entries).
const MaxSiteDropNames = 65536

// Name flags of cdnca_xdp_sni (SNI_* in the program).
const (
	sniDropExact    uint8 = 1
	sniDropWildcard uint8 = 2
	sniKeepExact    uint8 = 4
	sniKeepWildcard uint8 = 8
)

// Site drop counter indexes (enum cdnca_xdp_site_stat).
const (
	siteStatPort = iota
	siteStatSNI
	siteStatCount
)

// SiteDropCounters are the site drops since the program was loaded.
type SiteDropCounters struct {
	Port Counter `json:"port"`
	SNI  Counter `json:"sni"`
}

// sniHash is the program's key of a name: FNV-1a 64 over its lower case
// bytes from the last to the first.
func sniHash(name string) uint64 {
	hash := uint64(0xcbf29ce484222325)
	for index := len(name) - 1; index >= 0; index-- {
		c := name[index]
		if c >= 'A' && c <= 'Z' {
			c |= 0x20
		}
		hash ^= uint64(c)
		hash *= 0x100000001b3
	}
	return hash
}

// sniEntries are cdnca_xdp_sni's entries for drop. A name that is neither a
// host name nor a leading wildcard ("*.example.com") is skipped: nginx
// matches no SNI against it as a plain name either.
func (drop SiteDrop) sniEntries() (map[uint64]uint8, error) {
	entries := map[uint64]uint8{}
	add := func(names []string, exact, wildcard uint8) {
		for _, name := range names {
			name = strings.ToLower(strings.TrimSuffix(name, "."))
			flag := exact
			if suffix, ok := strings.CutPrefix(name, "*."); ok {
				name, flag = suffix, wildcard
			}
			if name == "" || len(name) > 253 || strings.ContainsAny(name, "*") {
				continue
			}
			entries[sniHash(name)] |= flag
		}
	}
	add(drop.DropNames, sniDropExact, sniDropWildcard)
	add(drop.KeepNames, sniKeepExact, sniKeepWildcard)
	if len(entries) > MaxSiteDropNames {
		return nil, ErrInvalid
	}
	return entries, nil
}

// portBitmap is a port bitmap (cdnca_xdp_site_ports / cdnca_xdp_sni_ports,
// the cdnca_xdp_ports layout).
func portBitmap(ports []uint16) [2048]uint32 {
	var words [2048]uint32
	for _, port := range ports {
		if port != 0 {
			words[port>>5] |= 1 << (port & 31)
		}
	}
	return words
}

// empty reports a drop of nothing.
func (drop SiteDrop) empty() bool {
	return len(drop.Ports) == 0 && (len(drop.SNIPorts) == 0 || len(drop.DropNames) == 0)
}
