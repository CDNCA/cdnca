package edgeconfig

import (
	"encoding/hex"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"
)

// L4GuardRuleV2 is one L4 guard rule of a v2 stream (G4-d #8, tcp/udp v10,
// docs/architecture/l4-v6-fields.md). Rules are evaluated in order on each
// new connection (UDP: session) in the node's preread phase; the first rule
// whose conditions all hold decides. At least one condition is set.
//
//   - drop: the connection is closed.
//   - ban: the connection is closed and the hit counted per rule and client;
//     at Threshold hits within WindowSeconds (Threshold 1: the first hit) the
//     client is refused by the stream for BanSeconds. The ban is the one the
//     new connection rate uses (ban:<stream>:<client>) and, where the node
//     sees the client as the socket peer on a socket only this stream uses,
//     is raised to a kernel (nftables) ban through the node firewall.
//   - allow: no later rule is evaluated (the geo policy and the new
//     connection rate still apply).
type L4GuardRuleV2 struct {
	ID          string              `json:"id"`
	Action      string              `json:"action"`
	FirstPacket *L4GuardFirstPacket `json:"first_packet,omitempty"`
	// ServerNames (TLS passthrough streams only) match the TLS SNI the
	// node reads with ssl_preread: exact names or a leading "*." wildcard.
	ServerNames []string         `json:"server_names,omitempty"`
	ClientIP    *L4GuardClientIP `json:"client_ip,omitempty"`
	// Geo holds when every condition does (the node's IP intelligence
	// library, cdnca_iplib); needs CAPABILITY_NAME_IP_INTEL v2.
	Geo           []WAFIPIntel `json:"geo,omitempty"`
	BanSeconds    int          `json:"ban_seconds,omitempty"`
	Threshold     int          `json:"threshold,omitempty"`
	WindowSeconds int          `json:"window_seconds,omitempty"`
}

// L4GuardFirstPacket matches the first data the client sends: the first TCP
// segment(s) available within the preread wait (at most
// L4GuardFirstPacketBytes) or the first UDP datagram. A client that sends
// nothing within the wait (server-first protocols) does not match.
//
//   - prefix_hex: the data starts with these bytes (lower-case hex).
//   - contains: the data contains this text (bytes, case-sensitive).
//   - regex: the data matches this regular expression (a pattern that is
//     valid both as RE2 and as PCRE; the node runs PCRE with a match limit).
type L4GuardFirstPacket struct {
	Match string `json:"match"`
	Value string `json:"value"`
}

// L4GuardClientIP holds when the client address is in one of CIDRs (or, when
// Negate, in none of them). The client is the one the stream's geo policy
// judges (PROXY protocol from a trusted proxy: the real client).
type L4GuardClientIP struct {
	CIDRs  []string `json:"cidrs"`
	Negate bool     `json:"negate,omitempty"`
}

const (
	L4GuardActionDrop  = "drop"
	L4GuardActionBan   = "ban"
	L4GuardActionAllow = "allow"

	L4GuardMatchPrefixHex = "prefix_hex"
	L4GuardMatchContains  = "contains"
	L4GuardMatchRegex     = "regex"

	// L4GuardRulesMax bounds the rules of one stream.
	L4GuardRulesMax = 64
	// L4GuardFirstPacketBytes is how much of the first data a rule sees.
	L4GuardFirstPacketBytes = 512
	// L4GuardRegexMax bounds a first packet regular expression (bytes).
	L4GuardRegexMax = 256
	// L4GuardContainsMax and L4GuardPrefixBytesMax bound the other matches.
	L4GuardContainsMax    = 256
	L4GuardPrefixBytesMax = 256
	// L4GuardCIDRsPerRuleMax and L4GuardCIDRsMax bound client_ip lists (per
	// rule and over the stream's rules).
	L4GuardCIDRsPerRuleMax = 1024
	L4GuardCIDRsMax        = 4096
	L4GuardServerNamesMax  = L4ServerNamesMax
	L4GuardThresholdMax    = 10_000
	L4GuardWindowMax       = 3_600
	L4GuardBanSecondsMax   = 86_400
	l4GuardGeoPerRuleMax   = maxWAFIPIntelPerRule
)

// L4GuardRulesUsed reports whether a stream has guard rules (tcp/udp v10).
func L4GuardRulesUsed(stream L4StreamRuntimeV2) bool { return len(stream.GuardRules) != 0 }

// L4GuardRulesUseIPIntel reports whether a guard rule has a geo condition
// (needs CAPABILITY_NAME_IP_INTEL v2 and a loaded library on the node).
func L4GuardRulesUseIPIntel(rules []L4GuardRuleV2) bool {
	return slices.ContainsFunc(rules, func(rule L4GuardRuleV2) bool { return len(rule.Geo) != 0 })
}

// L4StreamsUseIPIntel is L4GuardRulesUseIPIntel over streams.
func L4StreamsUseIPIntel(streams []L4StreamRuntimeV2) bool {
	return slices.ContainsFunc(streams, func(stream L4StreamRuntimeV2) bool { return L4GuardRulesUseIPIntel(stream.GuardRules) })
}

// NormalizeL4GuardRules validates a stream's guard rules and returns them in
// canonical form (rule order kept; CIDRs masked and sorted; server names and
// geo values sorted). passthrough is whether the stream is TLS passthrough
// (server_names conditions need it). The agent re-checks with it.
func NormalizeL4GuardRules(rules []L4GuardRuleV2, passthrough bool) ([]L4GuardRuleV2, error) {
	if len(rules) == 0 {
		return nil, nil // unset and empty are both omitted
	}
	if len(rules) > L4GuardRulesMax {
		return nil, ErrInvalidConfig
	}
	result := make([]L4GuardRuleV2, len(rules))
	ids := make(map[string]struct{}, len(rules))
	cidrs := 0
	for index, rule := range rules {
		if !uuidPattern.MatchString(rule.ID) {
			return nil, ErrInvalidConfig
		}
		if _, duplicate := ids[rule.ID]; duplicate {
			return nil, ErrInvalidConfig
		}
		ids[rule.ID] = struct{}{}
		normalized := L4GuardRuleV2{ID: rule.ID, Action: rule.Action}
		switch rule.Action {
		case L4GuardActionDrop, L4GuardActionAllow:
			if rule.BanSeconds != 0 || rule.Threshold != 0 || rule.WindowSeconds != 0 {
				return nil, ErrInvalidConfig
			}
		case L4GuardActionBan:
			if rule.BanSeconds < 1 || rule.BanSeconds > L4GuardBanSecondsMax || rule.Threshold < 1 || rule.Threshold > L4GuardThresholdMax ||
				(rule.Threshold == 1) != (rule.WindowSeconds == 0) || rule.WindowSeconds < 0 || rule.WindowSeconds > L4GuardWindowMax {
				return nil, ErrInvalidConfig
			}
			normalized.BanSeconds, normalized.Threshold, normalized.WindowSeconds = rule.BanSeconds, rule.Threshold, rule.WindowSeconds
		default:
			return nil, ErrInvalidConfig
		}
		if rule.FirstPacket == nil && rule.ServerNames == nil && rule.ClientIP == nil && rule.Geo == nil {
			return nil, ErrInvalidConfig
		}
		if rule.FirstPacket != nil {
			if !validL4GuardFirstPacket(*rule.FirstPacket) {
				return nil, ErrInvalidConfig
			}
			first := *rule.FirstPacket
			normalized.FirstPacket = &first
		}
		if rule.ServerNames != nil {
			names, err := normalizeL4GuardServerNames(rule.ServerNames, passthrough)
			if err != nil {
				return nil, err
			}
			normalized.ServerNames = names
		}
		if rule.ClientIP != nil {
			networks, err := normalizeL4GuardCIDRs(rule.ClientIP.CIDRs)
			if err != nil {
				return nil, err
			}
			cidrs += len(networks)
			normalized.ClientIP = &L4GuardClientIP{CIDRs: networks, Negate: rule.ClientIP.Negate}
		}
		if rule.Geo != nil {
			if len(rule.Geo) > l4GuardGeoPerRuleMax {
				return nil, ErrInvalidConfig
			}
			geo, err := normalizeWAFIPIntel(rule.Geo)
			if err != nil {
				return nil, err
			}
			normalized.Geo = geo
		}
		result[index] = normalized
	}
	if cidrs > L4GuardCIDRsMax {
		return nil, ErrInvalidConfig
	}
	return result, nil
}

// pcreUnportable are RE2 escapes the node's PCRE reads differently or may
// lack (single byte \C, Unicode classes \p / \P): the data is bytes.
var pcreUnportable = regexp.MustCompile(`\\[CpP]`)

func validL4GuardFirstPacket(value L4GuardFirstPacket) bool {
	switch value.Match {
	case L4GuardMatchPrefixHex:
		decoded, err := hex.DecodeString(value.Value)
		return err == nil && len(decoded) >= 1 && len(decoded) <= L4GuardPrefixBytesMax && strings.ToLower(value.Value) == value.Value
	case L4GuardMatchContains:
		return value.Value != "" && len(value.Value) <= L4GuardContainsMax && utf8.ValidString(value.Value) &&
			!strings.ContainsRune(value.Value, 0)
	case L4GuardMatchRegex:
		if value.Value == "" || len(value.Value) > L4GuardRegexMax || !utf8.ValidString(value.Value) ||
			strings.ContainsRune(value.Value, 0) || pcreUnportable.MatchString(value.Value) {
			return false
		}
		_, err := regexp.Compile(value.Value)
		return err == nil
	}
	return false
}

func normalizeL4GuardServerNames(values []string, passthrough bool) ([]string, error) {
	if !passthrough || len(values) == 0 || len(values) > L4GuardServerNamesMax {
		return nil, ErrInvalidConfig
	}
	names := make([]string, 0, len(values))
	for _, value := range values {
		name, err := normalizeL4ServerName(value)
		if err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	sort.Strings(names)
	for index := 1; index < len(names); index++ {
		if names[index] == names[index-1] {
			return nil, ErrInvalidConfig
		}
	}
	return names, nil
}

func normalizeL4GuardCIDRs(values []string) ([]string, error) {
	if len(values) == 0 || len(values) > L4GuardCIDRsPerRuleMax {
		return nil, ErrInvalidConfig
	}
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() || prefix != prefix.Masked() {
			return nil, ErrInvalidConfig
		}
		prefixes = append(prefixes, prefix)
	}
	sort.Slice(prefixes, func(i, j int) bool {
		if prefixes[i].Addr() != prefixes[j].Addr() {
			return prefixes[i].Addr().Less(prefixes[j].Addr())
		}
		return prefixes[i].Bits() < prefixes[j].Bits()
	})
	result := make([]string, len(prefixes))
	for index, prefix := range prefixes {
		if index > 0 && prefix == prefixes[index-1] {
			return nil, ErrInvalidConfig
		}
		result[index] = prefix.String()
	}
	return result, nil
}
