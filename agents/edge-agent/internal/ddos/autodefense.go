package ddos

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// Auto defense layer 4 (ADR 0010 AD-06, section 7A.4). The node's auto
// defense (internal/autodefense/l4) learns every port group of the node and,
// under attack, tightens it with a temporary override. Both live in this
// table, never in the user's DDoS setting:
//
//   - counters (always, for every group): packets/bytes, SYN, new
//     connections, 8 packet length buckets, and a per source set counting the
//     new connections of each client (IPv4, IPv6 /64), in chain ad_c_<g> the
//     input chain dispatches to by destination port (one vmap lookup);
//   - limits (only while the override has them): per client concurrent
//     connections, per client new connections a second / a minute, per /24
//     (IPv6 /48) new connections a second, in chain ad_l_<g> the guard chain
//     dispatches to after the bans, before the platform's own rate rules
//     (TCP); UDP groups (new flows a second / a minute) are dispatched from
//     the input chain, exempt networks first;
//   - group bans (BanGroup): ban sets ad_b4_<g> / ad_b6_<g> dropped at the end
//     of the group's counter chain (counted first, so detection still sees the
//     flood), only on the group's ports;
//   - node level: malformed TCP flag classes, conntrack INVALID and the empty
//     connection idle time are tightened (never relaxed) in protection().
//
// Object names carry a hash of the group ID (stable across renders, so the
// named counters keep counting) and, for limit sets, the limit.
type AutoDefense struct {
	Groups []AutoGroup `json:"groups,omitempty"`
	// Malformed / Invalid switch the node's default TCP flag classes and
	// conntrack INVALID drop on (they only add to the platform setting).
	Malformed bool `json:"malformed,omitempty"`
	Invalid   bool `json:"invalid,omitempty"`
	// IdleSeconds shortens the empty connection idle time (0 = no change);
	// without a platform empty connection policy it turns one on with
	// AutoEmptyThreshold / AutoEmptyWindowSeconds / AutoEmptyBanSeconds.
	IdleSeconds uint32 `json:"idle_seconds,omitempty"`
}

// AutoGroup is one port group: counters always, limits when non-zero.
type AutoGroup struct {
	ID       string      `json:"id"`
	Protocol string      `json:"protocol"` // tcp | udp
	Ports    []PortRange `json:"ports"`
	// Per client (IPv6 /64) limits; CIDRPerSecond counts per /24 (/48).
	MaxConnsPerIP uint32 `json:"max_conns_per_ip,omitempty"`
	NewPerSecond  uint32 `json:"new_per_second,omitempty"`
	NewPerMinute  uint32 `json:"new_per_minute,omitempty"`
	CIDRPerSecond uint32 `json:"cidr_per_second,omitempty"`
}

// Empty connection policy the override turns on when the platform has none.
const (
	AutoEmptyThreshold     = 20
	AutoEmptyWindowSeconds = 60
	AutoEmptyBanSeconds    = 600
	// AutoSourceSetSize bounds a group's per source set (a flood from more
	// sources is spread, not concentrated: no client stands out).
	AutoSourceSetSize = 8192
	// AutoSourceTimeout: a source idle this long leaves the set.
	AutoSourceTimeout = 60
	// AutoBanSetSize bounds a group's ban sets.
	AutoBanSetSize = 65536
	// AutoLengthBuckets are the packet length bucket bounds (meta length,
	// the IP packet): [0,64) [64,128) ... [1500, max].
	autoPrefix = "ad_"
)

// AutoLengthBounds are the lower bounds of the 8 length buckets.
var AutoLengthBounds = [8]uint32{0, 64, 128, 256, 512, 1024, 1280, 1500}

// Counter kinds of a group (AutoCounter.Kind).
const (
	AutoPackets = "pkt"
	AutoSYN     = "syn"
	AutoNew     = "new"
	AutoDrops   = "drop" // packets the override's limits dropped
	// AutoLength is the prefix of the length buckets: len0 ... len7.
	AutoLength = "len"
)

var (
	errAutoGroup = errors.New("invalid auto defense port group")
)

// GroupToken names a group's objects: g + 10 hex of SHA-256(ID).
func GroupToken(id string) string {
	sum := sha256.Sum256([]byte(id))
	return "g" + hex.EncodeToString(sum[:5])
}

func (auto *AutoDefense) validate() error {
	if auto == nil {
		return nil
	}
	tokens := map[string]bool{}
	// One port belongs to at most one group of a protocol (the dispatch is
	// one verdict map per protocol).
	byProtocol := map[string][]PortRange{}
	for _, group := range auto.Groups {
		byProtocol[group.Protocol] = append(byProtocol[group.Protocol], group.Ports...)
	}
	for _, ports := range byProtocol {
		sorted := slices.Clone(ports)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].First < sorted[j].First })
		for index := 1; index < len(sorted); index++ {
			if sorted[index].First <= sorted[index-1].Last {
				return errAutoGroup
			}
		}
	}
	for _, group := range auto.Groups {
		if group.ID == "" || (group.Protocol != "tcp" && group.Protocol != "udp") || len(MergePorts(group.Ports)) == 0 {
			return errAutoGroup
		}
		if group.Protocol == "udp" && (group.MaxConnsPerIP != 0 || group.CIDRPerSecond != 0) {
			return errAutoGroup
		}
		token := GroupToken(group.ID)
		if tokens[token] {
			return errAutoGroup
		}
		tokens[token] = true
	}
	return nil
}

// protection is the setting the table enforces: the platform's, tightened
// by the auto defense override (never relaxed).
func (spec Spec) protection() edgeconfig.DDoSProtection {
	protection := spec.Protection
	auto := spec.Auto
	if auto == nil {
		return protection
	}
	if auto.Malformed {
		types := slices.Clone(protection.TCPFlagTypes)
		if !protection.TCPFlagFilter {
			types = nil
		}
		for _, kind := range edgeconfig.DDoSDefaultTCPFlagTypes {
			if !slices.Contains(types, kind) {
				types = append(types, kind)
			}
		}
		ordered := make([]string, 0, len(types))
		for _, kind := range edgeconfig.DDoSTCPFlagTypes {
			if slices.Contains(types, kind) {
				ordered = append(ordered, kind)
			}
		}
		protection.TCPFlagFilter, protection.TCPFlagTypes = true, ordered
	}
	if auto.Invalid {
		protection.DropInvalid = true
	}
	if auto.IdleSeconds != 0 {
		if empty := protection.EmptyConnection; empty != nil {
			if auto.IdleSeconds < empty.IdleSeconds {
				shorter := *empty
				shorter.IdleSeconds = auto.IdleSeconds
				protection.EmptyConnection = &shorter
			}
		} else {
			protection.EmptyConnection = &edgeconfig.DDoSEmptyConnection{IdleSeconds: auto.IdleSeconds,
				Threshold: AutoEmptyThreshold, WindowSeconds: AutoEmptyWindowSeconds, BanSeconds: AutoEmptyBanSeconds}
		}
	}
	return protection
}

// EffectiveProtection is what the table enforces (the empty connection
// detector reads its policy here).
func (spec *Spec) EffectiveProtection() edgeconfig.DDoSProtection { return spec.protection() }

func portList(ports []PortRange) string {
	parts := make([]string, 0, len(ports))
	for _, port := range MergePorts(ports) {
		if port.First == port.Last {
			parts = append(parts, fmt.Sprint(port.First))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", port.First, port.Last))
		}
	}
	return strings.Join(parts, ", ")
}

// autoSets are the dynamic sets of the override (name -> definition).
func (auto *AutoDefense) sets() map[string]string {
	sets := map[string]string{}
	if auto == nil {
		return sets
	}
	for _, group := range auto.Groups {
		token := GroupToken(group.ID)
		sets[autoPrefix+"s4_"+token] = fmt.Sprintf("{ type ipv4_addr; flags dynamic,timeout; timeout %ds; size %d; }", AutoSourceTimeout, AutoSourceSetSize)
		sets[autoPrefix+"s6_"+token] = fmt.Sprintf("{ type ipv6_addr; flags dynamic,timeout; timeout %ds; size %d; }", AutoSourceTimeout, AutoSourceSetSize)
		sets[autoPrefix+"b4_"+token] = fmt.Sprintf("{ type ipv4_addr; flags timeout; size %d; }", AutoBanSetSize)
		sets[autoPrefix+"b6_"+token] = fmt.Sprintf("{ type ipv6_addr; flags timeout; size %d; }", AutoBanSetSize)
		meter := func(name string, limit uint32, definition string) {
			if limit == 0 {
				return
			}
			sets[fmt.Sprintf("%s%s_%s_%d_v4", autoPrefix, name, token, limit)] = fmt.Sprintf(definition, "ipv4_addr")
			sets[fmt.Sprintf("%s%s_%s_%d_v6", autoPrefix, name, token, limit)] = fmt.Sprintf(definition, "ipv6_addr")
		}
		size := fmt.Sprint(setSize)
		meter("rs", group.NewPerSecond, "{ type %s; flags dynamic,timeout; timeout 10s; size "+size+"; }")
		meter("rm", group.NewPerMinute, "{ type %s; flags dynamic,timeout; timeout 2m; size "+size+"; }")
		meter("cn", group.MaxConnsPerIP, "{ type %s; flags dynamic; size "+size+"; }")
		meter("cr", group.CIDRPerSecond, "{ type %s; flags dynamic,timeout; timeout 10s; size "+size+"; }")
	}
	return sets
}

// autoCounters are the named counters of the override's groups.
func (auto *AutoDefense) counters() []string {
	var names []string
	if auto == nil {
		return names
	}
	for _, group := range auto.Groups {
		token := GroupToken(group.ID)
		kinds := []string{AutoPackets, AutoNew, AutoDrops}
		if group.Protocol == "tcp" {
			kinds = append(kinds, AutoSYN)
		}
		for index := range AutoLengthBounds {
			kinds = append(kinds, fmt.Sprintf("%s%d", AutoLength, index))
		}
		for _, kind := range kinds {
			names = append(names, AutoCounterName(token, kind))
		}
	}
	sort.Strings(names)
	return names
}

// AutoCounterName is the named counter of a group's kind.
func AutoCounterName(token, kind string) string { return autoPrefix + kind + "_" + token }

// autoChains are the override's chains.
func (auto *AutoDefense) chains() []string {
	var names []string
	if auto == nil {
		return names
	}
	for _, group := range auto.Groups {
		token := GroupToken(group.ID)
		names = append(names, autoPrefix+"c_"+token)
		if group.limited() {
			names = append(names, autoPrefix+"l_"+token)
		}
	}
	sort.Strings(names)
	return names
}

func (group AutoGroup) limited() bool {
	return group.MaxConnsPerIP != 0 || group.NewPerSecond != 0 || group.NewPerMinute != 0 || group.CIDRPerSecond != 0
}

func (auto *AutoDefense) sortedGroups() []AutoGroup {
	if auto == nil {
		return nil
	}
	groups := slices.Clone(auto.Groups)
	sort.Slice(groups, func(i, j int) bool { return groups[i].ID < groups[j].ID })
	return groups
}

// counterRules renders the group counter chains and the input chain's
// dispatch (before the guard jump).
func (auto *AutoDefense) counterRules(line func(string, ...any), table string) {
	groups := auto.sortedGroups()
	dispatch := map[string][]string{}
	for _, group := range groups {
		token := GroupToken(group.ID)
		chain := autoPrefix + "c_" + token
		counter := func(kind string) string { return fmt.Sprintf("counter name %q", AutoCounterName(token, kind)) }
		line("add rule %s %s %s", table, chain, counter(AutoPackets))
		if group.Protocol == "tcp" {
			line("add rule %s %s tcp flags & (syn|ack) == syn %s", table, chain, counter(AutoSYN))
		}
		line("add rule %s %s ct state new %s", table, chain, counter(AutoNew))
		line("add rule %s %s ct state new update @%ss4_%s { ip saddr counter }", table, chain, autoPrefix, token)
		line("add rule %s %s ct state new update @%ss6_%s { ip6 saddr & %s counter }", table, chain, autoPrefix, token, ipv6ClientMask)
		for index, low := range AutoLengthBounds {
			bound := fmt.Sprintf("%d-%d", low, 65535)
			if index+1 < len(AutoLengthBounds) {
				bound = fmt.Sprintf("%d-%d", low, AutoLengthBounds[index+1]-1)
			}
			line("add rule %s %s meta length %s %s", table, chain, bound, counter(fmt.Sprintf("%s%d", AutoLength, index)))
		}
		// Group bans last: the banned flood is still counted (the attack does not look over while it lasts). Not in
		// the group's drop counter: that one measures what the limits drop (the engine's misfire guard).
		line("add rule %s %s ip saddr @%sb4_%s counter drop", table, chain, autoPrefix, token)
		line("add rule %s %s ip6 saddr & %s @%sb6_%s counter drop", table, chain, ipv6ClientMask, autoPrefix, token)
		for _, port := range MergePorts(group.Ports) {
			element := fmt.Sprint(port.First)
			if port.Last != port.First {
				element = fmt.Sprintf("%d-%d", port.First, port.Last)
			}
			dispatch[group.Protocol] = append(dispatch[group.Protocol], element+" : jump "+chain)
		}
	}
	for _, protocol := range []string{"tcp", "udp"} {
		if entries := dispatch[protocol]; len(entries) != 0 {
			line("add rule %s input meta l4proto %s %s dport vmap { %s }", table, protocol, protocol, strings.Join(entries, ", "))
		}
	}
	// UDP limits: UDP never reaches the guard chain (it is entered for TCP to the protected ports), so the input
	// chain dispatches the limited UDP groups itself, after counting.
	var limits []string
	for _, group := range groups {
		if group.Protocol == "udp" && group.limited() {
			for _, port := range MergePorts(group.Ports) {
				limits = append(limits, portElement(port)+" : jump "+autoPrefix+"l_"+GroupToken(group.ID))
			}
		}
	}
	if len(limits) != 0 {
		line("add rule %s input meta l4proto udp udp dport vmap { %s }", table, strings.Join(limits, ", "))
	}
}

func portElement(port PortRange) string {
	if port.First == port.Last {
		return fmt.Sprint(port.First)
	}
	return fmt.Sprintf("%d-%d", port.First, port.Last)
}

// limitRules renders the group limit chains and the guard chain's dispatch
// (after the bans and "ct state != new return", before the platform's rate
// rules). Only TCP reaches the guard chain; a UDP group's limit chain starts
// with what guard does first (exempt networks, only new flows) and is
// dispatched from the input chain (counterRules).
func (auto *AutoDefense) limitRules(line func(string, ...any), table string) {
	var dispatch []string
	v6 := "ip6 saddr & " + ipv6ClientMask
	for _, group := range auto.sortedGroups() {
		if !group.limited() {
			continue
		}
		token := GroupToken(group.ID)
		chain := autoPrefix + "l_" + token
		drop := fmt.Sprintf("counter name %q drop", AutoCounterName(token, AutoDrops))
		if group.Protocol == "udp" {
			line("add rule %s %s ip saddr @exempt_v4 return", table, chain)
			line("add rule %s %s ip6 saddr @exempt_v6 return", table, chain)
			line("add rule %s %s ct state != new return", table, chain)
		}
		rate := func(name string, limit uint32, unit, key4, key6 string) {
			if limit == 0 {
				return
			}
			for _, family := range []struct{ key, suffix string }{{key4, "_v4"}, {key6, "_v6"}} {
				line("add rule %s %s update @%s%s_%s_%d%s { %s limit rate over %d/%s burst %d packets } %s",
					table, chain, autoPrefix, name, token, limit, family.suffix, family.key, limit, unit, limit, drop)
			}
		}
		rate("rs", group.NewPerSecond, "second", "ip saddr", v6)
		rate("rm", group.NewPerMinute, "minute", "ip saddr", v6)
		rate("cr", group.CIDRPerSecond, "second", "ip saddr & 255.255.255.0", "ip6 saddr & ffff:ffff:ffff::")
		if limit := group.MaxConnsPerIP; limit != 0 {
			for _, family := range []struct{ key, suffix string }{{"ip saddr", "_v4"}, {v6, "_v6"}} {
				line("add rule %s %s add @%scn_%s_%d%s { %s ct count over %d } %s", table, chain, autoPrefix, token, limit, family.suffix, family.key, limit, drop)
			}
		}
		if group.Protocol != "tcp" {
			continue
		}
		for _, port := range MergePorts(group.Ports) {
			dispatch = append(dispatch, portElement(port)+" : jump "+chain)
		}
	}
	if len(dispatch) != 0 {
		line("add rule %s guard tcp dport vmap { %s }", table, strings.Join(dispatch, ", "))
	}
}

// SetAutoDefense replaces the table's auto defense part (nil removes it) and
// re-applies the running spec. Without a running table it is kept for the
// next Apply (there is no protected port to act on yet).
func (manager *Manager) SetAutoDefense(ctx context.Context, auto *AutoDefense) error {
	if err := auto.validate(); err != nil {
		return err
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if auto != nil {
		copied := *auto
		copied.Groups = slices.Clone(auto.Groups)
		auto = &copied
	}
	manager.auto = auto
	if manager.active == nil {
		return nil
	}
	spec := *manager.active
	spec.Auto = auto
	return manager.applyLocked(ctx, &spec)
}

// AutoDefense is the auto defense part the table runs (adopted from the
// previous Agent process's table after a restart), nil when none.
func (manager *Manager) AutoDefense() *AutoDefense {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.auto == nil {
		return nil
	}
	copied := *manager.auto
	copied.Groups = slices.Clone(manager.auto.Groups)
	return &copied
}

// AutoCounter is one named counter of the table.
type AutoCounter struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// AutoCounters lists every named counter of the running table by name
// (group counters and drop counters); none without a table.
func (manager *Manager) AutoCounters(ctx context.Context) (map[string]AutoCounter, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.active == nil {
		return nil, nil
	}
	output, err := manager.runner.Run(ctx, "--json", "list", "counters", "table", TableFamily, TableName)
	if err != nil {
		return nil, fmt.Errorf("list counters: %w", err)
	}
	var listing struct {
		Objects []struct {
			Counter *struct {
				Name    string `json:"name"`
				Packets uint64 `json:"packets"`
				Bytes   uint64 `json:"bytes"`
			} `json:"counter,omitempty"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(output, &listing); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnhealthy, err)
	}
	counters := map[string]AutoCounter{}
	for _, object := range listing.Objects {
		if counter := object.Counter; counter != nil {
			counters[counter.Name] = AutoCounter{Packets: counter.Packets, Bytes: counter.Bytes}
		}
	}
	return counters, nil
}

// SourceCount is one source of a group: its new connections since it
// entered the set (it leaves after AutoSourceTimeout idle).
type SourceCount struct {
	Client  netip.Addr // IPv4 address or IPv6 /64 network address
	Packets uint64
}

// AutoSources lists a group's source sets; none when the table does not
// run the group.
func (manager *Manager) AutoSources(ctx context.Context, groupID string) ([]SourceCount, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.active == nil || manager.active.Auto == nil ||
		!slices.ContainsFunc(manager.active.Auto.Groups, func(group AutoGroup) bool { return group.ID == groupID }) {
		return nil, nil
	}
	token := GroupToken(groupID)
	var sources []SourceCount
	for _, set := range []string{autoPrefix + "s4_" + token, autoPrefix + "s6_" + token} {
		output, err := manager.runner.Run(ctx, "--json", "list", "set", TableFamily, TableName, set)
		if err != nil {
			return nil, fmt.Errorf("list %s: %w", set, err)
		}
		found, err := sourceElements(output)
		if err != nil {
			return nil, err
		}
		sources = append(sources, found...)
	}
	return sources, nil
}

// sourceElements decodes `nft --json list set` of a counting set: elements
// are {"elem": {"val": address, "counter": {"packets": n, "bytes": n}, ...}}.
func sourceElements(output []byte) ([]SourceCount, error) {
	var listing struct {
		Objects []struct {
			Set *struct {
				Elem []json.RawMessage `json:"elem"`
			} `json:"set,omitempty"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(output, &listing); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnhealthy, err)
	}
	var sources []SourceCount
	for _, object := range listing.Objects {
		if object.Set == nil {
			continue
		}
		for _, raw := range object.Set.Elem {
			var wrapped struct {
				Elem struct {
					Val     string `json:"val"`
					Counter struct {
						Packets uint64 `json:"packets"`
					} `json:"counter"`
				} `json:"elem"`
			}
			if json.Unmarshal(raw, &wrapped) != nil {
				continue
			}
			client, err := netip.ParseAddr(wrapped.Elem.Val)
			if err != nil {
				continue
			}
			sources = append(sources, SourceCount{Client: client, Packets: wrapped.Elem.Counter.Packets})
		}
	}
	return sources, nil
}
