package edgeconfig

import (
	"sort"
	"strings"
)

// PortClaimKind is how one consumer uses a node port. The rules below are
// the same within one configuration scope and across scopes
// (decisions/multitenant-composition-compat-2026-10-16, 补充 and 补充 2).
type PortClaimKind string

const (
	// PortClaimPlainHTTP is a plaintext website listener (TCP). Websites on
	// one port are told apart by Host.
	PortClaimPlainHTTP PortClaimKind = "plain_http"
	// PortClaimTLSSite is a TLS website listener (TCP), told apart by SNI.
	PortClaimTLSSite PortClaimKind = "tls_site"
	// PortClaimQUIC is the UDP socket of a TLS website serving HTTP/3.
	PortClaimQUIC PortClaimKind = "quic"
	// PortClaimPlainL4 is a plain TCP or UDP stream: nothing on the wire
	// identifies it, so it is alone on its socket apart from TLS consumers,
	// which ssl_preread splits off.
	PortClaimPlainL4 PortClaimKind = "plain_l4"
	// PortClaimTLSL4 is a TLS passthrough stream (TCP), told apart by SNI.
	PortClaimTLSL4 PortClaimKind = "tls_l4"
	// PortClaimReserved is a port nothing else may use, such as the agent
	// health port.
	PortClaimReserved PortClaimKind = "reserved"
)

// PortClaim is one consumer of a node socket. Owner is the caller's label
// (for example a configuration scope); ID names the site or stream, and two
// claims with the same ID never conflict with each other. Names are the TLS
// server names (site domains or stream SNI) and are compared exactly, so
// "*.a.com" and "x.a.com" coexist (exact names win at the node).
// ProxyProtocol marks a stream that reads or sends a PROXY header.
// PortEnd (an L4 port range, 0: the single Port) claims Port..PortEnd; a
// range is never split by SNI, so it conflicts with every other claim on its
// protocol inside it.
type PortClaim struct {
	Owner         string
	ID            string
	Kind          PortClaimKind
	Protocol      StreamProtocol
	Port          uint16
	PortEnd       uint16
	Names         []string
	ProxyProtocol bool
}

// LastPort is the last port the claim covers.
func (claim PortClaim) LastPort() uint16 {
	if claim.PortEnd > claim.Port {
		return claim.PortEnd
	}
	return claim.Port
}

func (claim PortClaim) ranged() bool { return claim.PortEnd > claim.Port }

// PortConflict is a pair of claims that cannot share a socket. Name is the
// repeated server name when the conflict is one. ProxyProtocol is set when
// the pair could share the socket but one side uses PROXY: a split port is
// served behind a local dispatcher, where an inbound header is already read
// and an outbound one could not name the public address.
type PortConflict struct {
	Claim, Other  PortClaim
	Name          string
	ProxyProtocol bool
}

// Overlap is the ports both claims cover.
func (conflict PortConflict) Overlap() (uint16, uint16) {
	return max(conflict.Claim.Port, conflict.Other.Port), min(conflict.Claim.LastPort(), conflict.Other.LastPort())
}

func tlsClaim(kind PortClaimKind) bool { return kind == PortClaimTLSSite || kind == PortClaimTLSL4 }

// claimsConflict applies the sharing rules to two claims with a common port.
func claimsConflict(left, right PortClaim) (bool, string) {
	if left.Kind == PortClaimReserved || right.Kind == PortClaimReserved {
		return true, ""
	}
	if left.Protocol != right.Protocol {
		return false, ""
	}
	if left.ranged() || right.ranged() {
		return true, ""
	}
	if tlsClaim(left.Kind) && tlsClaim(right.Kind) {
		for _, name := range left.Names {
			for _, other := range right.Names {
				if strings.EqualFold(name, other) {
					return true, strings.ToLower(name)
				}
			}
		}
		return false, ""
	}
	if left.Kind != PortClaimPlainL4 && right.Kind != PortClaimPlainL4 {
		return false, "" // websites share by Host or SNI, QUIC by SNI
	}
	other := right.Kind
	if left.Kind != PortClaimPlainL4 {
		other = left.Kind
	}
	switch other {
	case PortClaimPlainL4, PortClaimPlainHTTP, PortClaimQUIC:
		return true, ""
	default: // TLS consumers are split off by ssl_preread
		return false, ""
	}
}

// FindPortConflicts returns every pair of claims that cannot share their
// socket, including a PROXY stream on a split socket, in a stable order: by
// (first) port, protocol, then the claims' position in a sorted copy of the
// input. Claims with port ranges are compared with every claim they overlap.
//
// It only compares pairs that can conflict, so it is linear in the claims
// plus the conflicts: websites on a shared port (plain HTTP by Host, TLS and
// QUIC by SNI) never conflict except on a repeated TLS name, so they are
// paired by name; reserved claims, ranges, plain streams and PROXY streams
// are compared with every claim overlapping them.
func FindPortConflicts(claims []PortClaim) []PortConflict {
	sorted := sortPortClaims(claims)
	type pair struct{ left, right int }
	var candidates []pair
	add := func(left, right int) {
		if left > right {
			left, right = right, left
		}
		if left != right {
			candidates = append(candidates, pair{left, right})
		}
	}
	type nameKey struct {
		port     uint16
		protocol StreamProtocol
		name     string
	}
	byName := map[nameKey][]int{}
	for index, claim := range sorted {
		if !portClaimSpecial(claim) {
			if tlsClaim(claim.Kind) {
				for _, name := range claim.Names {
					key := nameKey{claim.Port, claim.Protocol, strings.ToLower(name)}
					for _, other := range byName[key] {
						add(other, index)
					}
					byName[key] = append(byName[key], index)
				}
			}
			continue
		}
		// Claims overlapping it from its first port on follow it (sorted by
		// first port); before it, only claims on the same first port can
		// (an earlier ranged claim is special and pairs with it forward).
		for other := index + 1; other < len(sorted) && sorted[other].Port <= claim.LastPort(); other++ {
			add(index, other)
		}
		for other := index - 1; other >= 0 && sorted[other].Port == claim.Port; other-- {
			add(other, index)
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].left != candidates[j].left {
			return candidates[i].left < candidates[j].left
		}
		return candidates[i].right < candidates[j].right
	})
	var conflicts []PortConflict
	for index, candidate := range candidates {
		if index > 0 && candidate == candidates[index-1] {
			continue
		}
		if conflict, ok := portClaimPairConflict(sorted[candidate.left], sorted[candidate.right]); ok {
			conflicts = append(conflicts, conflict)
		}
	}
	return conflicts
}

// portClaimSpecial: a claim that can conflict without a repeated TLS name.
func portClaimSpecial(claim PortClaim) bool {
	return claim.Kind == PortClaimReserved || claim.Kind == PortClaimPlainL4 || claim.ranged() || claim.ProxyProtocol
}

func sortPortClaims(claims []PortClaim) []PortClaim {
	sorted := append([]PortClaim(nil), claims...)
	sort.SliceStable(sorted, func(i, j int) bool {
		left, right := sorted[i], sorted[j]
		if left.Port != right.Port {
			return left.Port < right.Port
		}
		if left.Protocol != right.Protocol {
			return left.Protocol < right.Protocol
		}
		if left.Owner != right.Owner {
			return left.Owner < right.Owner
		}
		if left.ID != right.ID {
			return left.ID < right.ID
		}
		return left.Kind < right.Kind
	})
	return sorted
}

// portClaimPairConflict decides one pair of claims with a common port
// (left before right in sortPortClaims order).
func portClaimPairConflict(left, right PortClaim) (PortConflict, bool) {
	if left.ID != "" && left.ID == right.ID && left.Owner == right.Owner {
		return PortConflict{}, false
	}
	if conflict, name := claimsConflict(left, right); conflict {
		return PortConflict{Claim: left, Other: right, Name: name}, true
	}
	if left.Protocol == right.Protocol && (left.ProxyProtocol || right.ProxyProtocol) {
		return PortConflict{Claim: left, Other: right, ProxyProtocol: true}, true
	}
	return PortConflict{}, false
}

// L4StreamPortClaims returns the sockets one v2 stream claims.
func L4StreamPortClaims(owner string, stream L4StreamRuntimeV2) []PortClaim {
	kind := PortClaimPlainL4
	if stream.TLSPassthrough {
		kind = PortClaimTLSL4
	}
	sockets := []L4ListenerV2{stream.Listener}
	for _, listener := range stream.AdditionalListeners {
		sockets = append(sockets, L4ListenerV2{Protocol: listener.Protocol, Address: listener.Address, Port: listener.Port,
			PortEnd: listener.PortEnd})
	}
	claims := make([]PortClaim, 0, len(sockets))
	for _, socket := range sockets {
		claims = append(claims, PortClaim{Owner: owner, ID: stream.StreamID, Kind: kind,
			Protocol: StreamProtocol(socket.Protocol), Port: uint16(socket.Port), PortEnd: uint16(socket.PortEnd),
			Names:         append([]string(nil), stream.ServerNames...),
			ProxyProtocol: stream.ProxyProtocolInbound || stream.ProxyProtocolOutbound})
	}
	return claims
}

// SiteListenerPortClaims returns the sockets one website listener claims: its
// TCP port, plus the UDP port when a TLS listener serves HTTP/3.
func SiteListenerPortClaims(owner, siteID string, port uint16, tls, http3 bool, domains []string) []PortClaim {
	if !tls {
		return []PortClaim{{Owner: owner, ID: siteID, Kind: PortClaimPlainHTTP, Protocol: StreamProtocolTCP, Port: port}}
	}
	names := append([]string(nil), domains...)
	claims := []PortClaim{{Owner: owner, ID: siteID, Kind: PortClaimTLSSite, Protocol: StreamProtocolTCP, Port: port, Names: names}}
	if http3 {
		claims = append(claims, PortClaim{Owner: owner, ID: siteID, Kind: PortClaimQUIC, Protocol: StreamProtocolUDP, Port: port,
			Names: append([]string(nil), domains...)})
	}
	return claims
}
