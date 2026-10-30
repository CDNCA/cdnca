// Package xdp runs the node XDP filter (bpf/xdp.bpf.c): the NIC
// side front of the node DDoS table (internal/ddos, inet cdnca_ddos). The
// same spec drives both; XDP only moves the drops of banned clients,
// malformed TCP flag classes and SYN floods before the stack, nftables keeps
// enforcing everything (and whatever XDP cannot: conntrack state, connection
// counts). So falling back is detaching: no rule is ever missing.
//
// Mode selection (Probe): kernel 5.9+ (XDP bpf_link), the object loads and
// passes a BPF_PROG_TEST_RUN self-test, then every uplink takes native (driver)
// XDP, else generic (SKB) XDP. Any failure: nftables, with the reason. At run
// time a failed attach, map write or verification also falls back
// (Manager.Fallback), reported in Status.
//
// Three kinds of entry carry their own deadline (the program ignores expired
// ones, Manager.Sweep deletes them): bans (ddos.Manager.Ban's clients, the
// protected ports), port bans (CC kernel bans, one port) and blocks
// (Block/Unblock, every packet: the auto defense L5 hook).
package xdp

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Mode is the filter the node runs.
type Mode string

const (
	// ModeNative: XDP in the NIC driver (every uplink).
	ModeNative Mode = "native"
	// ModeGeneric: XDP after the SKB is built (some uplink lacks native).
	ModeGeneric Mode = "generic"
	// ModeNFTables: no XDP; inet cdnca_ddos alone.
	ModeNFTables Mode = "nftables"
	// ModeDisabled: turned off in the Agent configuration.
	ModeDisabled Mode = "disabled"
)

// Valid reports a known mode.
func (mode Mode) Valid() bool {
	switch mode {
	case ModeNative, ModeGeneric, ModeNFTables, ModeDisabled:
		return true
	}
	return false
}

// XDP reports whether a program is attached.
func (mode Mode) XDP() bool { return mode == ModeNative || mode == ModeGeneric }

// Reason codes (Status.Reason): stable, the page translates them; Detail
// carries the system's words.
const (
	ReasonNone           = ""
	ReasonDisabled       = "disabled"
	ReasonUnsupportedOS  = "unsupported_os"
	ReasonKernelTooOld   = "kernel_too_old"
	ReasonBPFUnavailable = "bpf_unavailable"
	ReasonLoadFailed     = "load_failed"
	ReasonSelfTestFailed = "self_test_failed"
	ReasonNoInterface    = "no_interface"
	ReasonAttachFailed   = "attach_failed"
	ReasonVerifyFailed   = "verify_failed"
	ReasonUpdateFailed   = "update_failed"
)

// Reasons is every reason code.
var Reasons = []string{ReasonDisabled, ReasonUnsupportedOS, ReasonKernelTooOld, ReasonBPFUnavailable, ReasonLoadFailed,
	ReasonSelfTestFailed, ReasonNoInterface, ReasonAttachFailed, ReasonVerifyFailed, ReasonUpdateFailed}

// MinKernel is the first kernel with XDP bpf_link (BPF_LINK_CREATE for XDP).
var MinKernel = [2]int{5, 9}

// Status is the probe or run time outcome (node telemetry, logs, the
// capability).
type Status struct {
	Mode Mode `json:"mode"`
	// Reason is why the node runs nftables (empty with XDP).
	Reason string `json:"reason,omitempty"`
	// Detail is the error text (bounded).
	Detail string `json:"detail,omitempty"`
	// Interfaces are the uplinks the program is attached to, sorted.
	Interfaces []string `json:"interfaces,omitempty"`
	Kernel     string   `json:"kernel,omitempty"`
}

// MaxDetail bounds Status.Detail.
const MaxDetail = 256

func fallback(reason string, err error) Status {
	detail := ""
	if err != nil {
		detail = err.Error()
		if len(detail) > MaxDetail {
			detail = detail[:MaxDetail]
		}
	}
	return Status{Mode: ModeNFTables, Reason: reason, Detail: detail}
}

// Stat indexes mirror enum cdnca_xdp_stat; Kinds name them in telemetry.
const (
	statBlock = iota
	statBan
	statPortBan
	statRate
	statTCPNull
	statTCPXmas
	statTCPSynFin
	statTCPSynRst
	statTCPAll
	statCount
)

// Drop kinds (Counter.Kind). The flag classes share the ddos drop kinds.
const (
	DropBlock   = "xdp_block"
	DropBan     = "xdp_ban"
	DropPortBan = "xdp_port_ban"
	DropRate    = "xdp_rate"
)

var statKinds = [statCount]string{DropBlock, DropBan, DropPortBan, DropRate, "tcp_null", "tcp_xmas", "tcp_syn_fin", "tcp_syn_rst", "tcp_all"}

// DropKinds is every counter kind, sorted.
var DropKinds = []string{"tcp_all", "tcp_null", "tcp_syn_fin", "tcp_syn_rst", "tcp_xmas", DropBan, DropBlock, DropPortBan, DropRate}

// Counter is one drop class since the program was loaded.
type Counter struct {
	Kind    string `json:"kind"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// Flag bits of the config's tcp_flags (FLAG_* in the program).
const (
	FlagNull uint32 = 1 << iota
	FlagXmas
	FlagSynFin
	FlagSynRst
	FlagAll
)

var (
	ErrUnsupported = errors.New("XDP requires Linux")
	ErrNotRunning  = errors.New("XDP filter is not running")
	ErrInvalid     = errors.New("invalid XDP request")
	// ErrNoRetry: Reattach only follows a run time fallback.
	ErrNoRetry = errors.New("XDP filter did not fall back at run time")
)

// kernelAtLeast parses a uname release such as "6.8.0-45-generic".
func kernelAtLeast(release string, want [2]int) (bool, error) {
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return false, fmt.Errorf("unrecognised kernel release %q", release)
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return false, fmt.Errorf("unrecognised kernel release %q", release)
	}
	minorText := parts[1]
	if i := strings.IndexFunc(minorText, func(r rune) bool { return r < '0' || r > '9' }); i >= 0 {
		minorText = minorText[:i]
	}
	minor, err := strconv.Atoi(minorText)
	if err != nil {
		return false, fmt.Errorf("unrecognised kernel release %q", release)
	}
	return major > want[0] || (major == want[0] && minor >= want[1]), nil
}

// lpmKey is struct cdnca_xdp_lpm_key: IPv4 as ::ffff:a.b.c.d.
type lpmKey struct {
	PrefixLen uint32
	Addr      [16]byte
}

func keyOf(prefix netip.Prefix) (lpmKey, bool) {
	if !prefix.IsValid() {
		return lpmKey{}, false
	}
	prefix = prefix.Masked()
	address := prefix.Addr()
	bits := prefix.Bits()
	if address.Is4() {
		bits += 96
	}
	return lpmKey{PrefixLen: uint32(bits), Addr: address.As16()}, true
}

// clientPrefix is how a client is banned: an IPv4 address, an IPv6 /64
// (ddos.Manager.Ban does the same).
func clientPrefix(client netip.Addr) netip.Prefix {
	client = client.Unmap()
	if client.Is4() {
		return netip.PrefixFrom(client, 32)
	}
	return netip.PrefixFrom(client, 64).Masked()
}
