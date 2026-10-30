// Package cnamelines publishes a site's CNAME owner per carrier DNS line.
// The default line keeps every
// published node address (cnameallocation); each non-default line holds the
// published endpoints whose carrier (电信/联通/移动) or region (outside the
// mainland -> 境外) map to it, so a visitor on a carrier line is answered
// with that carrier's nodes. A provider without the line, a package-mode
// owner and a line the aggregated edge schedules are left alone.
package cnamelines

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocation"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/cdnca/cdnca/services/control-api/internal/marketprobe"
)

// Line scopes (the aggregated edge's names) and their unified DNS line.
var lineScopes = map[string]string{
	"telecom": dnsproviderremote.LineTelecom, "unicom": dnsproviderremote.LineUnicom,
	"mobile": dnsproviderremote.LineMobile, "overseas": dnsproviderremote.LineOverseas,
}

// Scopes lists the non-default line scopes in a fixed order.
var Scopes = []string{"telecom", "unicom", "mobile", "overseas"}

// Endpoint is one published line-group endpoint.
type Endpoint struct {
	Address, Region, Carrier string
}

// EndpointScope is the line an endpoint stands for: its carrier on the
// mainland (or with no region), overseas for a region outside the mainland,
// "" for BGP / multi-line / unknown carriers (default line only).
func EndpointScope(region, carrier string) string {
	if code, ok := marketprobe.Region(region); ok && code != "cn" {
		return "overseas"
	}
	code, ok := marketprobe.Carrier(carrier)
	if !ok || code == "bgp" {
		return ""
	}
	return code
}

// Set is the A/AAAA values of one line, canonical and sorted.
type Set struct {
	A, AAAA []string
}

func (set Set) Empty() bool { return len(set.A)+len(set.AAAA) == 0 }

// Digest identifies a set together with the TTL and weights it is written with.
func (set Set) Digest(ttl uint32, weights map[string]uint32) string {
	var builder strings.Builder
	builder.WriteString("cdnca.cname-line/v1 ttl=" + strconv.FormatUint(uint64(ttl), 10))
	for _, value := range append(slices.Clone(set.A), set.AAAA...) {
		builder.WriteString(" " + value + "=" + strconv.FormatUint(uint64(weights[value]), 10))
	}
	sum := sha256.Sum256([]byte(builder.String()))
	return hex.EncodeToString(sum[:])
}

// Plan groups endpoints by line scope. Every scope of Scopes is present
// (possibly empty: the line then holds no record and falls back to the
// default line's answer).
func Plan(endpoints []Endpoint) map[string]Set {
	sets := make(map[string]Set, len(Scopes))
	for _, scope := range Scopes {
		sets[scope] = Set{A: []string{}, AAAA: []string{}}
	}
	for _, endpoint := range endpoints {
		scope := EndpointScope(endpoint.Region, endpoint.Carrier)
		address, err := netip.ParseAddr(endpoint.Address)
		if scope == "" || err != nil {
			continue
		}
		set := sets[scope]
		value := address.String()
		if address.Is4() {
			if !slices.Contains(set.A, value) {
				set.A = append(set.A, value)
			}
		} else if !slices.Contains(set.AAAA, value) {
			set.AAAA = append(set.AAAA, value)
		}
		sets[scope] = set
	}
	for scope, set := range sets {
		slices.Sort(set.A)
		slices.Sort(set.AAAA)
		sets[scope] = set
	}
	return sets
}

// LineWeights are the weights a scope's line is written with: each address
// takes the weight of its own endpoint on that line, keyed by the endpoint's
// carrier, so one IP on several carrier lines keeps each line's weight. When
// several endpoints of the line share an address (carrier spellings that map
// to the same line), the smallest carrier wins so the result is stable.
func LineWeights(endpoints []Endpoint, scope string, weights map[cnameallocation.WeightKey]uint32) map[string]uint32 {
	result := map[string]uint32{}
	chosen := map[string]string{}
	for _, endpoint := range endpoints {
		address, err := netip.ParseAddr(endpoint.Address)
		if err != nil || EndpointScope(endpoint.Region, endpoint.Carrier) != scope {
			continue
		}
		weight, ok := weights[cnameallocation.WeightKey{Carrier: endpoint.Carrier, Address: endpoint.Address}]
		value := address.String()
		if previous, seen := chosen[value]; !ok || seen && previous <= endpoint.Carrier {
			continue
		}
		chosen[value], result[value] = endpoint.Carrier, weight
	}
	return result
}

// DNSLine returns the unified DNS line of a scope.
func DNSLine(scope string) (string, bool) {
	line, ok := lineScopes[scope]
	return line, ok
}

// Supported reports whether a provider writes the scope's line.
func Supported(providerType, scope string) bool {
	line, ok := DNSLine(scope)
	return ok && slices.Contains(dnsproviderremote.SupportedLines(providerType), line)
}
