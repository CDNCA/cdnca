package xdp

import (
	"net/netip"
	"sort"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// Config is what the program enforces besides the bans: the node DDoS
// spec's protected ports, exempt networks, flag classes and new connection
// rate (ddos.Spec, the same system.ddos value). The zero Config enforces
// only blocks and port bans.
type Config struct {
	// Ports are the protected TCP ports (first..last inclusive).
	Ports []PortRange
	// Exempt networks always pass (node networks, allow list, loopback).
	Exempt []netip.Prefix
	// TCPFlags are the Flag* classes to drop on the protected ports.
	TCPFlags uint32
	// SYNRate bounds one client's new connections a second (IPv6 by /64),
	// 0 off; SYNBan bans it that long when over (0: only the excess drops).
	SYNRate uint32
	SYNBan  time.Duration
}

// PortRange is first..last inclusive.
type PortRange struct {
	First, Last uint16
}

// MaxExempt bounds Config.Exempt (the exempt map's size).
const MaxExempt = 65536

// ConfigOf maps the DDoS protection of a spec to the program: the flag
// classes XDP can decide alone (fin needs conntrack state, ct_invalid is
// conntrack's), the per second rate with its ban (the per minute rate and
// connection counts stay in nftables).
func ConfigOf(protection edgeconfig.DDoSProtection, ports []PortRange, exempt []netip.Prefix) Config {
	config := Config{Ports: append([]PortRange(nil), ports...), Exempt: append([]netip.Prefix(nil), exempt...),
		SYNRate: protection.NewConnectionsPerSecond}
	if config.SYNRate != 0 {
		config.SYNBan = time.Duration(protection.RateBanSeconds) * time.Second
	}
	for kind, flag := range map[string]uint32{
		edgeconfig.DDoSTCPFlagNull: FlagNull, edgeconfig.DDoSTCPFlagXmas: FlagXmas, edgeconfig.DDoSTCPFlagSynFin: FlagSynFin,
		edgeconfig.DDoSTCPFlagSynRst: FlagSynRst, edgeconfig.DDoSTCPFlagAll: FlagAll,
	} {
		if protection.FiltersTCPFlag(kind) {
			config.TCPFlags |= flag
		}
	}
	return config
}

// portWords is the protected port bitmap (cdnca_xdp_ports).
func (config Config) portWords() [2048]uint32 {
	var words [2048]uint32
	for _, port := range config.Ports {
		for value := uint32(port.First); value <= uint32(port.Last) && value != 0; value++ {
			words[value>>5] |= 1 << (value & 31)
		}
	}
	return words
}

// exemptKeys are the exempt map's keys, sorted and unique.
func (config Config) exemptKeys() []lpmKey {
	seen := map[lpmKey]bool{}
	var keys []lpmKey
	for _, prefix := range config.Exempt {
		if key, ok := keyOf(prefix); ok && !seen[key] {
			seen[key] = true
			keys = append(keys, key)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].PrefixLen != keys[j].PrefixLen {
			return keys[i].PrefixLen < keys[j].PrefixLen
		}
		return string(keys[i].Addr[:]) < string(keys[j].Addr[:])
	})
	return keys
}

// rawConfig is struct cdnca_xdp_config.
type rawConfig struct {
	Enabled       uint32
	TCPFlags      uint32
	SYNRate       uint32
	SYNBanSeconds uint32
	Generation    uint64
}

func (config Config) raw(generation uint64) rawConfig {
	return rawConfig{Enabled: 1, TCPFlags: config.TCPFlags, SYNRate: config.SYNRate,
		SYNBanSeconds: uint32(config.SYNBan / time.Second), Generation: generation}
}
