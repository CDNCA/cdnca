// Package ddos applies the platform's node-level connection protection
// (edgeconfig.DDoSProtection) to the node's own
// nftables table, inet cdnca_ddos: per client concurrent connections, new
// connection rates with a timed ban, per port concurrent connections, and the
// ban set the empty connection detector (EmptyConnections) fills.
//
// The table hooks input at priority -5, after inet cdnca_firewall (-10): a
// client the firewall already drops is never counted here. It protects the
// TCP ports the running site runtime listens on (websites and L4 forwards,
// the composed runtime's ports), never the node's management or loopback
// traffic; node addresses and the configured allow networks are exempt.
//
// Before any counting, malformed TCP flag combinations (tcp_flag_filter) and
// packets conntrack classifies INVALID (drop_invalid) are dropped, each class
// into its own named counter (DropCounters reads them; named counters keep
// counting across in-place updates).
//
// The table is updated in place (sets and chains flushed and refilled in one
// atomic batch), so the bans of a running table survive a new release; only
// a spec without protection removes it.
package ddos

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

const (
	TableFamily = "inet"
	TableName   = "cdnca_ddos"

	// BanSetIPv4 / BanSetIPv6 hold banned clients (IPv6 by /64) with their
	// timeout; every protected port drops them.
	BanSetIPv4 = "ban_v4"
	BanSetIPv6 = "ban_v6"

	// setSize bounds every dynamic set: a flood from more distinct clients
	// than this is no longer counted per client (nft refuses to add), the
	// per port limit still applies.
	setSize = 262144
	// ipv6ClientMask counts an IPv6 client by its /64.
	ipv6ClientMask = "ffff:ffff:ffff:ffff::"
	// dropCounterPrefix names the packet filter counters: drop_<kind>.
	dropCounterPrefix = "drop_"
	// tcpFlagMask is the six classic flags every filter compares under.
	tcpFlagMask = "fin|syn|rst|psh|ack|urg"
)

// Drop counter kinds (DropCounters, node telemetry ddos_drops).
const (
	DropTCPNull   = "tcp_null"
	DropTCPXmas   = "tcp_xmas"
	DropTCPSynFin = "tcp_syn_fin"
	DropTCPSynRst = "tcp_syn_rst"
	DropTCPFin    = "tcp_fin"
	DropTCPAll    = "tcp_all"
	DropInvalid   = "ct_invalid"
)

// packetFilter is one drop rule of the packet filters: its counter kind and
// match. The bare FIN rule matches only packets of no established (or
// related) connection: conntrack classifies a FIN without ACK as INVALID,
// never NEW, so "not established" is what "not part of a connection" means;
// a connection's own close (FIN|ACK) never matches the flag test anyway.
type packetFilter struct {
	kind, match string
}

// packetFilters are the drop rules spec enables, in rule order: the flag
// classes before INVALID, so a malformed packet (which conntrack also calls
// INVALID) counts under its class.
func (spec Spec) packetFilters() []packetFilter {
	protection := spec.protection()
	var filters []packetFilter
	flag := func(kind, flagType, match string) {
		if protection.FiltersTCPFlag(flagType) {
			filters = append(filters, packetFilter{kind, match})
		}
	}
	// Exact combinations first: ALL also has SYN and FIN set, and counts as
	// ALL when that class is on (as SYN+FIN otherwise).
	flags := "tcp flags & (" + tcpFlagMask + ") == "
	flag(DropTCPNull, edgeconfig.DDoSTCPFlagNull, flags+"0x0")
	flag(DropTCPXmas, edgeconfig.DDoSTCPFlagXmas, flags+"fin|psh|urg")
	flag(DropTCPAll, edgeconfig.DDoSTCPFlagAll, flags+tcpFlagMask)
	flag(DropTCPFin, edgeconfig.DDoSTCPFlagFin, flags+"fin ct state != { established, related }")
	flag(DropTCPSynFin, edgeconfig.DDoSTCPFlagSynFin, "tcp flags & (fin|syn) == fin|syn")
	flag(DropTCPSynRst, edgeconfig.DDoSTCPFlagSynRst, "tcp flags & (syn|rst) == syn|rst")
	if protection.DropInvalid {
		filters = append(filters, packetFilter{DropInvalid, "ct state invalid"})
	}
	return filters
}

// Spec is what the table enforces.
type Spec struct {
	Protection edgeconfig.DDoSProtection
	// Exempt are the node networks and allow networks (canonical prefixes).
	Exempt []netip.Prefix
	// Ports are the TCP ports to protect (sorted ranges).
	Ports []PortRange
	// Auto is the auto defense part (port group counters and temporary
	// override, autodefense.go); the Manager sets it, nil when none.
	Auto *AutoDefense `json:",omitempty"`
}

// PortRange is first..last inclusive.
type PortRange struct {
	First, Last uint16
}

// NewSpec builds the spec of a v2 document's DDoS block for ports. nil when
// there is nothing to protect.
func NewSpec(value *edgeconfig.SiteRuntimeDDoS, ports []PortRange) (*Spec, error) {
	if value == nil || !value.Protection.Enabled() || len(ports) == 0 {
		return nil, nil
	}
	if err := value.Validate(); err != nil {
		return nil, err
	}
	spec := &Spec{Protection: value.Protection, Ports: MergePorts(ports)}
	seen := map[netip.Prefix]bool{}
	// Loopback: the Agent's own probes of the site ports.
	for _, raw := range append(append([]string{"127.0.0.0/8", "::1/128"}, value.NodeNetworks...), value.Protection.AllowNetworks...) {
		prefix := netip.MustParsePrefix(raw)
		if !seen[prefix] {
			seen[prefix] = true
			spec.Exempt = append(spec.Exempt, prefix)
		}
	}
	sort.Slice(spec.Exempt, func(i, j int) bool {
		if comparison := spec.Exempt[i].Addr().Compare(spec.Exempt[j].Addr()); comparison != 0 {
			return comparison < 0
		}
		return spec.Exempt[i].Bits() < spec.Exempt[j].Bits()
	})
	return spec, nil
}

// MergePorts sorts and merges overlapping or adjacent ranges.
func MergePorts(ports []PortRange) []PortRange {
	sorted := make([]PortRange, 0, len(ports))
	for _, port := range ports {
		if port.First == 0 || port.Last < port.First {
			continue
		}
		sorted = append(sorted, port)
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].First < sorted[j].First })
	var merged []PortRange
	for _, port := range sorted {
		if last := len(merged) - 1; last >= 0 && uint32(port.First) <= uint32(merged[last].Last)+1 {
			merged[last].Last = max(merged[last].Last, port.Last)
			continue
		}
		merged = append(merged, port)
	}
	return merged
}

// renderVersion changes with the rules Batch writes for the same spec, so a
// node upgraded to a new renderer replaces the table it adopted.
// 2: packet filters (TCP flags, conntrack INVALID), loopback interface exempt.
const renderVersion = 2

// Digest names a spec; the table comment carries it so the manager knows
// what the kernel runs.
func (spec Spec) Digest() string {
	encoded, _ := json.Marshal(struct {
		Render     int                       `json:"render"`
		Protection edgeconfig.DDoSProtection `json:"protection"`
		Exempt     []netip.Prefix            `json:"exempt"`
		Ports      []PortRange               `json:"ports"`
		Auto       *AutoDefense              `json:"auto,omitempty"`
	}{renderVersion, spec.Protection, spec.Exempt, spec.Ports, spec.Auto})
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

// marker is the comment of the input chain's jump rule: the digest of the
// spec the kernel runs (a table comment cannot change in place).
func marker(digest string) string { return "cdnca ddos digest=" + digest }

// meterSets are the dynamic sets a spec counts in. Their names carry the
// limit: an element keeps the limit it was created with, so a changed limit
// needs a new set (the old one is deleted, its counts start over).
func (spec Spec) meterSets() map[string]string {
	protection := spec.protection()
	sets := map[string]string{}
	add := func(name, definition string) {
		sets[name+"_v4"] = fmt.Sprintf(definition, "ipv4_addr")
		sets[name+"_v6"] = fmt.Sprintf(definition, "ipv6_addr")
	}
	if limit := protection.NewConnectionsPerSecond; limit != 0 {
		add(fmt.Sprintf("meter_rate_s_%d", limit), "{ type %s; flags dynamic,timeout; timeout 10s; size "+fmt.Sprint(setSize)+"; }")
	}
	if limit := protection.NewConnectionsPerMinute; limit != 0 {
		add(fmt.Sprintf("meter_rate_m_%d", limit), "{ type %s; flags dynamic,timeout; timeout 2m; size "+fmt.Sprint(setSize)+"; }")
	}
	if limit := protection.MaxConnectionsPerIP; limit != 0 {
		add(fmt.Sprintf("meter_conn_%d", limit), "{ type %s; flags dynamic; size "+fmt.Sprint(setSize)+"; }")
	}
	if limit := protection.MaxConnectionsPerPort; limit != 0 {
		sets[fmt.Sprintf("meter_port_%d", limit)] = "{ type inet_service; flags dynamic; size 65536; }"
	}
	return sets
}

// Batch is the nft script that makes the running table equal to spec,
// keeping its ban sets (and their timeouts) and drop counters when it
// already exists. existingSets / existingCounters / existingChains are the
// running table's set, counter and chain names (none when absent).
func (spec Spec) Batch(existingSets, existingCounters, existingChains []string) []byte {
	var exempt4, exempt6 []string
	for _, prefix := range spec.Exempt {
		if prefix.Addr().Is4() {
			exempt4 = append(exempt4, prefix.String())
		} else {
			exempt6 = append(exempt6, prefix.String())
		}
	}
	ports := make([]string, len(spec.Ports))
	for index, port := range spec.Ports {
		ports[index] = fmt.Sprint(port.First)
		if port.Last != port.First {
			ports[index] = fmt.Sprintf("%d-%d", port.First, port.Last)
		}
	}
	protection := spec.protection()
	meters := spec.meterSets()
	for name, definition := range spec.Auto.sets() {
		meters[name] = definition
	}
	filters := spec.packetFilters()
	counters := map[string]bool{}
	for _, filter := range filters {
		counters[dropCounterPrefix+filter.kind] = true
	}
	autoCounters := spec.Auto.counters()
	for _, name := range autoCounters {
		counters[name] = true
	}
	autoChains := spec.Auto.chains()
	var out strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&out, format+"\n", args...) }
	table := TableFamily + " " + TableName
	line("add table %s", table)
	line("add set %s ports { type inet_service; flags interval; auto-merge; }", table)
	line("add set %s exempt_v4 { type ipv4_addr; flags interval; auto-merge; }", table)
	line("add set %s exempt_v6 { type ipv6_addr; flags interval; auto-merge; }", table)
	// A running table keeps its ban sets as they are: a rule adding to one
	// makes the kernel flag it dynamic, and nft before 1.1 (Debian 12's
	// 1.0.6) refuses "add set" with the original flags then (File exists).
	for _, ban := range []struct{ name, kind string }{{BanSetIPv4, "ipv4_addr"}, {BanSetIPv6, "ipv6_addr"}} {
		if !slices.Contains(existingSets, ban.name) {
			line("add set %s %s { type %s; flags timeout; size %d; }", table, ban.name, ban.kind, setSize)
		}
	}
	names := make([]string, 0, len(meters))
	for name := range meters {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		line("add set %s %s %s", table, name, meters[name])
	}
	for _, filter := range filters {
		line("add counter %s %s%s", table, dropCounterPrefix, filter.kind)
	}
	for _, name := range autoCounters {
		line("add counter %s %s", table, name)
	}
	line("add chain %s input { type filter hook input priority -5; policy accept; }", table)
	line("add chain %s guard", table)
	for _, name := range autoChains {
		line("add chain %s %s", table, name)
	}
	line("flush chain %s input", table)
	line("flush chain %s guard", table)
	for _, name := range autoChains {
		line("flush chain %s %s", table, name)
	}
	// Chains of groups no longer run: nothing jumps to them once input and
	// guard are flushed.
	staleChains := append([]string(nil), existingChains...)
	sort.Strings(staleChains)
	for _, name := range staleChains {
		if strings.HasPrefix(name, autoPrefix) && !slices.Contains(autoChains, name) {
			line("flush chain %s %s", table, name)
			line("delete chain %s %s", table, name)
		}
	}
	for _, set := range []string{"ports", "exempt_v4", "exempt_v6"} {
		line("flush set %s %s", table, set)
	}
	stale := append([]string(nil), existingSets...)
	sort.Strings(stale)
	for _, name := range stale {
		if _, used := meters[name]; !used && (strings.HasPrefix(name, "meter_") || strings.HasPrefix(name, autoPrefix)) {
			line("delete set %s %s", table, name)
		}
	}
	staleCounters := append([]string(nil), existingCounters...)
	sort.Strings(staleCounters)
	for _, name := range staleCounters {
		if !counters[name] && (strings.HasPrefix(name, dropCounterPrefix) || strings.HasPrefix(name, autoPrefix)) {
			line("delete counter %s %s", table, name)
		}
	}
	if len(ports) != 0 {
		line("add element %s ports { %s }", table, strings.Join(ports, ", "))
	}
	if len(exempt4) != 0 {
		line("add element %s exempt_v4 { %s }", table, strings.Join(exempt4, ", "))
	}
	if len(exempt6) != 0 {
		line("add element %s exempt_v6 { %s }", table, strings.Join(exempt6, ", "))
	}
	line("add rule %s guard ip saddr @exempt_v4 return", table)
	line("add rule %s guard ip6 saddr @exempt_v6 return", table)
	// The node's own traffic to its addresses (probes of its public IP)
	// arrives on lo whatever its source; the packet filters never see it.
	for _, filter := range filters {
		line("add rule %s guard meta iif != lo %s counter name %q drop", table, filter.match, dropCounterPrefix+filter.kind)
	}
	line("add rule %s guard ip saddr @%s counter drop", table, BanSetIPv4)
	line("add rule %s guard ip6 saddr & %s @%s counter drop", table, ipv6ClientMask, BanSetIPv6)
	line("add rule %s guard ct state != new return", table)
	if spec.Auto != nil {
		spec.Auto.limitRules(line, table)
	}
	v6 := "ip6 saddr & " + ipv6ClientMask
	families := []struct{ key, suffix, ban string }{{"ip saddr", "_v4", BanSetIPv4}, {v6, "_v6", BanSetIPv6}}
	rate := func(name string, limit uint32, unit string) {
		for _, family := range families {
			ban := ""
			if protection.RateBanSeconds != 0 {
				ban = fmt.Sprintf(" add @%s { %s timeout %ds }", family.ban, family.key, protection.RateBanSeconds)
			}
			line("add rule %s guard update @%s%s { %s limit rate over %d/%s burst %d packets }%s counter drop",
				table, name, family.suffix, family.key, limit, unit, limit, ban)
		}
	}
	if limit := protection.NewConnectionsPerSecond; limit != 0 {
		rate(fmt.Sprintf("meter_rate_s_%d", limit), limit, "second")
	}
	if limit := protection.NewConnectionsPerMinute; limit != 0 {
		rate(fmt.Sprintf("meter_rate_m_%d", limit), limit, "minute")
	}
	if limit := protection.MaxConnectionsPerIP; limit != 0 {
		for _, family := range families {
			line("add rule %s guard add @meter_conn_%d%s { %s ct count over %d } counter drop", table, limit, family.suffix, family.key, limit)
		}
	}
	if limit := protection.MaxConnectionsPerPort; limit != 0 {
		line("add rule %s guard add @meter_port_%d { tcp dport ct count over %d } counter drop", table, limit, limit)
	}
	if spec.Auto != nil {
		spec.Auto.counterRules(line, table)
	}
	// Last: the jump names the spec, so a partial table never matches it.
	line("add rule %s input meta l4proto tcp tcp dport @ports jump guard comment %q", table, marker(spec.Digest()))
	return []byte(out.String())
}

// RemoveBatch removes the table (add first: delete of an absent table fails).
func RemoveBatch() []byte {
	return []byte(fmt.Sprintf("add table %s %s\ndelete table %s %s\n", TableFamily, TableName, TableFamily, TableName))
}
