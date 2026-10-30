package edgesite

import (
	"fmt"
	"sort"
)

// PortProfile is what the node skeleton needs for one public port: one
// shared server, TLS or plain, HTTP/2 (ALPN) on when any site there has it
// (a site without it is turned off per connection in the client hello,
// native patch 27), QUIC listening when any site advertises h3 there, bound
// on the union of the sites' address families.
type PortProfile struct {
	Port      int
	TLS       bool
	HTTP2     bool
	HTTP3     bool
	IPv4      bool
	IPv6      bool
	SiteCount int
}

// PortProfiles checks a set of sites (one scope, or every scope a node
// composes) for what only holds across sites and returns the per-port
// profiles in port order:
//   - each site ID once;
//   - each (port, name) answered by one site only (the node index is a map);
//   - on one port every site agrees on TLS.
func PortProfiles(sites []Site) ([]PortProfile, error) {
	profiles := map[int]*PortProfile{}
	siteIDs := make(map[string]bool, len(sites))
	owners := map[IndexEntry]string{}
	for _, site := range sites {
		if siteIDs[site.SiteID] {
			return nil, fmt.Errorf("%w: site %s appears twice", ErrInvalid, site.SiteID)
		}
		siteIDs[site.SiteID] = true
		for _, entry := range site.IndexEntries() {
			if entry.Name == DefaultSiteName {
				// two default sites only meet while scopes republish one
				// after the other: the index drops both (siteindex.Builder)
				continue
			}
			key := IndexEntry{Port: entry.Port, Name: entry.Name}
			if owner, taken := owners[key]; taken {
				return nil, fmt.Errorf("%w: %s on port %d is served by sites %s and %s", ErrInvalid, entry.Name, entry.Port, owner, site.SiteID)
			}
			owners[key] = site.SiteID
		}
		for _, listener := range site.Listeners {
			profile := profiles[listener.Port]
			if profile == nil {
				profile = &PortProfile{Port: listener.Port, TLS: listener.TLS != nil}
				profiles[listener.Port] = profile
			}
			if profile.TLS != (listener.TLS != nil) {
				return nil, fmt.Errorf("%w: port %d is TLS for some sites and plain for others (site %s)", ErrInvalid, listener.Port, site.SiteID)
			}
			profile.HTTP2 = profile.HTTP2 || listener.HTTP2
			profile.HTTP3 = profile.HTTP3 || listener.HTTP3
			profile.IPv4 = profile.IPv4 || listener.AddressFamily != FamilyIPv6
			profile.IPv6 = profile.IPv6 || listener.AddressFamily != FamilyIPv4
			profile.SiteCount++
		}
	}
	result := make([]PortProfile, 0, len(profiles))
	for _, profile := range profiles {
		result = append(result, *profile)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Port < result[j].Port })
	return result, nil
}
