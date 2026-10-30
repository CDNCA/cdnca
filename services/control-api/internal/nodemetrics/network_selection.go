package nodemetrics

import (
	"math"
	"strings"

	"github.com/google/uuid"
)

func validNetworkSelection(telemetry *Telemetry) bool {
	selection := telemetry.NetworkSelection
	if selection == nil {
		return true
	}
	if selection.Source != "default_route" && selection.Source != "unavailable" ||
		(selection.Source == "default_route") != (len(selection.Interfaces) > 0) || len(selection.Interfaces) > 128 {
		return false
	}
	previous := ""
	for _, name := range selection.Interfaces {
		if name <= previous {
			return false
		}
		found := false
		for _, network := range telemetry.NetworkInterfaces {
			if network.Name == name {
				found = true
				break
			}
		}
		if !found {
			return false
		}
		previous = name
	}
	return true
}

// DDoSDrop is one packet filter's cumulative drops in the node DDoS table
// (agent ddos.DropCounter; NodeDDoSDropV1).
type DDoSDrop struct {
	Kind    string `json:"kind"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// ddosDropKinds are the packet filter kinds a sample may carry.
var ddosDropKinds = map[string]bool{"ct_invalid": true, "tcp_all": true, "tcp_fin": true, "tcp_null": true,
	"tcp_syn_fin": true, "tcp_syn_rst": true, "tcp_xmas": true}

// validSiteDrop: 1..256 canonical UUIDs, sorted and unique; counters within
// int64 (nil: none).
func validSiteDrop(drop *SiteDrop) bool {
	if drop == nil {
		return true
	}
	if len(drop.SiteIDs) == 0 || len(drop.SiteIDs) > 256 || drop.Packets > math.MaxInt64 || drop.Bytes > math.MaxInt64 {
		return false
	}
	previous := ""
	for _, id := range drop.SiteIDs {
		parsed, err := uuid.Parse(id)
		if err != nil || parsed.String() != id || id <= previous {
			return false
		}
		previous = id
	}
	return true
}

// validDDoSDrops: known kinds, sorted, unique; counters within int64.
func validDDoSDrops(drops []DDoSDrop) bool {
	previous := ""
	for _, drop := range drops {
		if drop.Kind <= previous || !ddosDropKinds[drop.Kind] || drop.Packets > 1<<63-1 || drop.Bytes > 1<<63-1 {
			return false
		}
		previous = drop.Kind
	}
	return true
}

// XDPStatus is the node XDP filter's mode (agent internal/xdp,
// NodeXDPStatusV1): native / generic attached (interfaces "<nic>=<mode>"),
// nftables / disabled not (reason says why). Drops only while attached.
type XDPStatus struct {
	Mode       string     `json:"mode"`
	Reason     string     `json:"reason,omitempty"`
	Detail     string     `json:"detail,omitempty"`
	Interfaces []string   `json:"interfaces,omitempty"`
	Drops      []DDoSDrop `json:"drops,omitempty"`
}

var (
	xdpModes   = map[string]bool{"native": true, "generic": true, "nftables": true, "disabled": true}
	xdpReasons = map[string]bool{"attach_failed": true, "bpf_unavailable": true, "disabled": true, "kernel_too_old": true,
		"load_failed": true, "no_interface": true, "self_test_failed": true, "unsupported_os": true, "update_failed": true, "verify_failed": true}
	xdpDropKinds = map[string]bool{"tcp_all": true, "tcp_null": true, "tcp_syn_fin": true, "tcp_syn_rst": true, "tcp_xmas": true,
		"xdp_ban": true, "xdp_block": true, "xdp_port_ban": true, "xdp_rate": true}
)

func validXDPStatus(status *XDPStatus) bool {
	if status == nil {
		return true
	}
	attached := status.Mode == "native" || status.Mode == "generic"
	if !xdpModes[status.Mode] || len(status.Detail) > 256 || strings.ContainsAny(status.Detail, "\x00\r\n") ||
		len(status.Interfaces) > 64 || attached != (status.Reason == "") || attached != (len(status.Interfaces) != 0) ||
		!attached && (len(status.Drops) != 0 || !xdpReasons[status.Reason]) {
		return false
	}
	previous := ""
	for _, nic := range status.Interfaces {
		name, mode, ok := strings.Cut(nic, "=")
		if !ok || name == "" || len(name) > 15 || strings.ContainsAny(name, "/= \x00\r\n\t") ||
			mode != "native" && mode != "generic" || nic <= previous {
			return false
		}
		previous = nic
	}
	previous = ""
	for _, drop := range status.Drops {
		if drop.Kind <= previous || !xdpDropKinds[drop.Kind] || drop.Packets > 1<<63-1 || drop.Bytes > 1<<63-1 {
			return false
		}
		previous = drop.Kind
	}
	return true
}
