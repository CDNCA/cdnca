//go:build linux

package xdp

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// Built by bpf/build.sh; one object serves amd64 and arm64.
//
//go:embed bpf/xdp.bpf.o
var bpfObject []byte

const (
	programName = "cdnca_xdp_filter"
	mapConfig   = "cdnca_xdp_cfg"
	mapPorts    = "cdnca_xdp_ports"
	mapExempt   = "cdnca_xdp_exempt"
	mapBan      = "cdnca_xdp_ban"
	mapBlock    = "cdnca_xdp_block"
	mapPortBan  = "cdnca_xdp_portban"
	mapRate     = "cdnca_xdp_rate"
	mapStats    = "cdnca_xdp_stats"
	// Site drop (攻击自动升级 D 级, site_drop.go).
	mapSitePorts = "cdnca_xdp_site_ports"
	mapSNIPorts  = "cdnca_xdp_sni_ports"
	mapSNI       = "cdnca_xdp_sni"
	mapSiteStats = "cdnca_xdp_site_stats"
)

// Options are inputs of Probe; empty fields use the real system.
type Options struct {
	// Disabled turns XDP off (ModeDisabled; the Agent configuration).
	Disabled bool
	// Interfaces to attach to; empty: every physical uplink that is up and
	// has an address (Uplinks).
	Interfaces []string
	// Modes are tried per interface in order; empty: native, then generic.
	Modes []Mode
	// Kernel overrides uname (tests).
	Kernel string
}

// Manager owns the loaded program, its maps and its XDP links. The links
// are not pinned: they live as long as the Agent process, so an Agent that
// stops leaves the node on nftables alone.
type Manager struct {
	mu         sync.Mutex
	collection *ebpf.Collection
	links      map[string]link.Link
	status     Status
	config     Config
	generation uint64
	// exempt are the exempt map's current keys.
	exempt []lpmKey
	// options are Probe's, reused by Reattach.
	options Options
	// runFallback: the filter attached at start and fell back at run time
	// (Fallback, a failed write or verification): Reattach may retry.
	runFallback bool
	// blocks mirror the block map (wall clock deadlines): Reattach replays
	// them, an L5 entry must not silently shrink to the nftables ban.
	blocks map[lpmKey]time.Time
	// siteDrop is the site drop the program enforces (Reattach replays it);
	// sniKeys are cdnca_xdp_sni's current keys.
	siteDrop SiteDrop
	sniKeys  map[uint64]uint8
	// changed is signalled (never blocking) on a run time fallback and on a
	// successful Reattach: the Agent re-declares XDP_FILTER at once.
	changed chan struct{}
}

// Probe detects the mode and, unless the node runs nftables, leaves the
// program attached and running with the zero Config (Configure sets the
// DDoS spec). It never fails: the returned Manager's Status says why the
// node runs nftables.
func Probe(options Options) *Manager {
	manager := &Manager{links: map[string]link.Link{}, options: options, blocks: map[lpmKey]time.Time{}, changed: make(chan struct{}, 1)}
	manager.status = manager.probe(options)
	if !manager.status.Mode.XDP() {
		manager.closeLocked()
	}
	return manager
}

func (m *Manager) probe(options Options) Status {
	if options.Disabled {
		return Status{Mode: ModeDisabled, Reason: ReasonDisabled}
	}
	kernel := options.Kernel
	if kernel == "" {
		var uname unix.Utsname
		if err := unix.Uname(&uname); err != nil {
			return fallback(ReasonKernelTooOld, err)
		}
		kernel = unix.ByteSliceToString(uname.Release[:])
	}
	withKernel := func(status Status) Status {
		status.Kernel = kernel
		return status
	}
	if ok, err := kernelAtLeast(kernel, MinKernel); err != nil || !ok {
		if err == nil {
			err = fmt.Errorf("kernel %s, XDP links need %d.%d+", kernel, MinKernel[0], MinKernel[1])
		}
		return withKernel(fallback(ReasonKernelTooOld, err))
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return withKernel(fallback(ReasonBPFUnavailable, err))
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfObject))
	if err != nil {
		return withKernel(fallback(ReasonLoadFailed, err))
	}
	m.collection, err = ebpf.NewCollection(spec)
	if err != nil {
		if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EPERM) || errors.Is(err, ebpf.ErrNotSupported) {
			return withKernel(fallback(ReasonBPFUnavailable, err))
		}
		return withKernel(fallback(ReasonLoadFailed, err))
	}
	if err := m.selfTest(); err != nil {
		return withKernel(fallback(ReasonSelfTestFailed, err))
	}
	names := options.Interfaces
	if len(names) == 0 {
		names = Uplinks()
	}
	if len(names) == 0 {
		return withKernel(fallback(ReasonNoInterface, errors.New("no physical uplink is up with an address")))
	}
	modes := options.Modes
	if len(modes) == 0 {
		modes = []Mode{ModeNative, ModeGeneric}
	}
	overall := ModeNative
	var attached []string
	for _, name := range names {
		mode, err := m.attach(name, modes)
		if err != nil {
			return withKernel(fallback(ReasonAttachFailed, err))
		}
		if mode == ModeGeneric {
			overall = ModeGeneric
		}
		attached = append(attached, name+"="+string(mode))
	}
	sort.Strings(attached)
	if err := m.writeConfig(Config{}); err != nil {
		return withKernel(fallback(ReasonUpdateFailed, err))
	}
	return Status{Mode: overall, Interfaces: attached, Kernel: kernel}
}

func (m *Manager) attach(name string, modes []Mode) (Mode, error) {
	device, err := net.InterfaceByName(name)
	if err != nil {
		return "", fmt.Errorf("interface %s: %w", name, err)
	}
	program := m.collection.Programs[programName]
	var errs []error
	for _, mode := range modes {
		flags := link.XDPGenericMode
		if mode == ModeNative {
			flags = link.XDPDriverMode
		} else if mode != ModeGeneric {
			continue
		}
		attached, err := link.AttachXDP(link.XDPOptions{Program: program, Interface: device.Index, Flags: flags})
		if err == nil {
			m.links[name] = attached
			return mode, nil
		}
		errs = append(errs, fmt.Errorf("%s %s: %w", mode, name, err))
	}
	return "", errors.Join(errs...)
}

// selfTest runs the program on crafted frames (BPF_PROG_TEST_RUN): a
// blocked source must drop and another pass; then the counters are reset.
func (m *Manager) selfTest() error {
	program := m.collection.Programs[programName]
	if program == nil {
		return fmt.Errorf("object lacks %s", programName)
	}
	blocked := netip.MustParseAddr("192.0.2.1")
	if err := m.writeConfig(Config{}); err != nil {
		return err
	}
	key, _ := keyOf(netip.PrefixFrom(blocked, 32))
	if err := m.collection.Maps[mapBlock].Update(key, ^uint64(0), ebpf.UpdateAny); err != nil {
		return fmt.Errorf("write %s: %w", mapBlock, err)
	}
	defer m.collection.Maps[mapBlock].Delete(key)
	for _, test := range []struct {
		source netip.Addr
		want   uint32
	}{{blocked, 1 /* XDP_DROP */}, {netip.MustParseAddr("192.0.2.2"), 2 /* XDP_PASS */}} {
		got, _, err := program.Test(TestFrame(test.source, netip.MustParseAddr("192.0.2.100"), 80, 0x02))
		if err != nil {
			return fmt.Errorf("test run: %w", err)
		}
		if got != test.want {
			return fmt.Errorf("test run from %s returned %d, want %d", test.source, got, test.want)
		}
	}
	return m.resetStats()
}

func (m *Manager) resetStats() error {
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		return err
	}
	zero := make([]rawCounter, cpus)
	for index := uint32(0); index < statCount; index++ {
		if err := m.collection.Maps[mapStats].Update(index, zero, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("reset %s: %w", mapStats, err)
		}
	}
	return nil
}

type rawCounter struct {
	Packets, Bytes uint64
}

// Uplinks are the physical interfaces (a /sys/class/net/<name>/device
// link) that are up and have an address other than link local.
func Uplinks() []string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var names []string
	for _, device := range interfaces {
		if device.Flags&net.FlagUp == 0 || device.Flags&net.FlagLoopback != 0 {
			continue
		}
		if _, err := os.Stat(filepath.Join("/sys/class/net", device.Name, "device")); err != nil {
			continue
		}
		addresses, _ := device.Addrs()
		for _, address := range addresses {
			if prefix, err := netip.ParsePrefix(address.String()); err == nil && !prefix.Addr().IsLinkLocalUnicast() {
				names = append(names, device.Name)
				break
			}
		}
	}
	sort.Strings(names)
	return names
}

// Status is the current outcome.
func (m *Manager) Status() Status {
	if m == nil {
		return Status{Mode: ModeNFTables, Reason: ReasonUnsupportedOS}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	status := m.status
	status.Interfaces = slices.Clone(status.Interfaces)
	return status
}

// Running reports whether the program is attached (the node executes L5).
func (m *Manager) Running() bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status.Mode.XDP()
}

// Fallback detaches the program: the node runs nftables alone from now on
// (nftables already enforces every rule). reason is a Reason* code.
func (m *Manager) Fallback(reason string, err error) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fallbackLocked(reason, err)
}

func (m *Manager) fallbackLocked(reason string, err error) {
	if !m.status.Mode.XDP() {
		return
	}
	kernel := m.status.Kernel
	m.closeLocked()
	m.status = fallback(reason, err)
	m.status.Kernel = kernel
	m.runFallback = true
	m.signalChanged()
}

func (m *Manager) signalChanged() {
	select {
	case m.changed <- struct{}{}:
	default: // a signal is pending already
	}
}

// Changed is signalled when Running changes at run time (fallback, then a
// successful Reattach). One consumer (the Gateway session) reads it and
// compares Running with what it declared; a pending signal is coalesced.
func (m *Manager) Changed() <-chan struct{} {
	if m == nil {
		return nil
	}
	return m.changed
}

// Reattach retries the filter after a run time fallback (the probe again,
// same options), then replays the L5 blocks that have not ended. The bans
// and port bans are not replayed: nftables kept enforcing them; the caller
// re-configures the DDoS spec (ddos.Manager.SetFront). A node that never
// attached (or was closed) returns ErrNoRetry; a failed attempt leaves the
// node on nftables with the new reason, and may be retried.
func (m *Manager) Reattach() error {
	if m == nil {
		return ErrNoRetry
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.status.Mode.XDP() {
		return nil
	}
	if !m.runFallback {
		return ErrNoRetry
	}
	status := m.probe(m.options)
	if !status.Mode.XDP() {
		m.closeLocked()
		m.status = status
		return fmt.Errorf("%s: %s", status.Reason, status.Detail)
	}
	m.status, m.runFallback = status, false
	if err := m.writeSiteDrop(m.siteDrop); err != nil {
		m.fallbackLocked(ReasonUpdateFailed, err)
		return err
	}
	now := time.Now()
	for key, until := range m.blocks {
		if !until.After(now) {
			delete(m.blocks, key)
			continue
		}
		deadline, err := monotonicDeadline(until)
		if err != nil {
			continue // ended meanwhile
		}
		if err := m.putDeadline(mapBlock, key, deadline); err != nil {
			m.fallbackLocked(ReasonUpdateFailed, err)
			return err
		}
	}
	m.signalChanged()
	return nil
}

func (m *Manager) closeLocked() {
	for name, attached := range m.links {
		attached.Close()
		delete(m.links, name)
	}
	if m.collection != nil {
		m.collection.Close()
		m.collection = nil
	}
	m.exempt = nil
	m.sniKeys = nil
}

// Close detaches the program (Agent shutdown).
func (m *Manager) Close() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closeLocked()
	m.runFallback = false
	if m.status.Mode.XDP() {
		m.status = Status{Mode: ModeNFTables, Reason: ReasonDisabled, Kernel: m.status.Kernel}
	}
}

// Configure makes the program enforce config. A failed write falls back.
func (m *Manager) Configure(config Config) error {
	if m == nil {
		return ErrNotRunning
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.status.Mode.XDP() {
		return ErrNotRunning
	}
	if err := m.writeConfig(config); err != nil {
		m.fallbackLocked(ReasonUpdateFailed, err)
		return err
	}
	return nil
}

// writeConfig writes the port bitmap and exempt networks first, the config
// (with its new generation) last.
func (m *Manager) writeConfig(config Config) error {
	if len(config.Exempt) > MaxExempt {
		return ErrInvalid
	}
	words := config.portWords()
	ports := m.collection.Maps[mapPorts]
	for index, word := range words {
		if err := ports.Update(uint32(index), word, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("write %s: %w", mapPorts, err)
		}
	}
	keys := config.exemptKeys()
	exempt := m.collection.Maps[mapExempt]
	for _, key := range keys {
		if err := exempt.Update(key, uint8(1), ebpf.UpdateAny); err != nil {
			return fmt.Errorf("write %s: %w", mapExempt, err)
		}
	}
	for _, key := range m.exempt {
		if !slices.Contains(keys, key) {
			if err := exempt.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				return fmt.Errorf("delete %s: %w", mapExempt, err)
			}
		}
	}
	m.exempt = keys
	m.generation++
	if err := m.collection.Maps[mapConfig].Update(uint32(0), config.raw(m.generation), ebpf.UpdateAny); err != nil {
		return fmt.Errorf("write %s: %w", mapConfig, err)
	}
	m.config = config
	return nil
}

// Verify checks that every link is still attached to its interface and the
// config map holds what was written; a failure falls back (and is
// returned).
func (m *Manager) Verify() error {
	if m == nil {
		return ErrNotRunning
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.status.Mode.XDP() {
		return ErrNotRunning
	}
	err := m.verifyLocked()
	if err != nil {
		m.fallbackLocked(ReasonVerifyFailed, err)
	}
	return err
}

func (m *Manager) verifyLocked() error {
	for name, attached := range m.links {
		device, err := net.InterfaceByName(name)
		if err != nil {
			return fmt.Errorf("interface %s: %w", name, err)
		}
		info, err := attached.Info()
		if err != nil {
			return fmt.Errorf("link on %s: %w", name, err)
		}
		if xdpInfo := info.XDP(); xdpInfo == nil || int(xdpInfo.Ifindex) != device.Index {
			return fmt.Errorf("link on %s is detached", name)
		}
	}
	var raw rawConfig
	if err := m.collection.Maps[mapConfig].Lookup(uint32(0), &raw); err != nil {
		return fmt.Errorf("read %s: %w", mapConfig, err)
	}
	if raw != m.config.raw(m.generation) {
		return fmt.Errorf("%s generation %d, want %d", mapConfig, raw.Generation, m.generation)
	}
	return nil
}

// monotonicDeadline converts a wall clock deadline to bpf_ktime_get_ns.
func monotonicDeadline(until time.Time) (uint64, error) {
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		return 0, err
	}
	remaining := time.Until(until)
	if remaining <= 0 {
		return 0, ErrInvalid
	}
	return uint64(now.Nano()) + uint64(remaining), nil
}

func monotonicNow() (uint64, error) {
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		return 0, err
	}
	return uint64(now.Nano()), nil
}

// putDeadline keeps the later of an existing deadline and until.
func (m *Manager) putDeadline(name string, key any, until uint64) error {
	target := m.collection.Maps[name]
	var existing uint64
	if err := target.Lookup(key, &existing); err == nil && existing >= until {
		return nil
	}
	return target.Update(key, until, ebpf.UpdateAny)
}

// Ban drops clients (IPv4 address, IPv6 /64) on the protected ports until
// the deadline (ddos.Manager.Ban's bans). A failed write falls back.
func (m *Manager) Ban(clients []netip.Addr, until time.Time) error {
	prefixes := make([]netip.Prefix, 0, len(clients))
	for _, client := range clients {
		if client.IsValid() {
			prefixes = append(prefixes, clientPrefix(client))
		}
	}
	return m.write(mapBan, prefixes, until)
}

// Unban deletes Ban's entries of clients (a released auto defense kernel
// ban; absent ones are ignored). A failed delete falls back.
func (m *Manager) Unban(clients []netip.Addr) error {
	if m == nil {
		return ErrNotRunning
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.status.Mode.XDP() {
		return ErrNotRunning
	}
	for _, client := range clients {
		if !client.IsValid() {
			continue
		}
		key, ok := keyOf(clientPrefix(client))
		if !ok {
			return ErrInvalid
		}
		if err := m.collection.Maps[mapBan].Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			m.fallbackLocked(ReasonUpdateFailed, err)
			return err
		}
	}
	return nil
}

// Block drops every packet of prefix until the deadline: the auto defense
// L5 hook (Blocks). A failed write falls back.
func (m *Manager) Block(blocks []Block) error {
	if m == nil {
		return ErrNotRunning
	}
	for _, block := range blocks {
		if err := block.validate(); err != nil {
			return err
		}
	}
	for _, block := range blocks {
		until := time.Now().Add(block.TTL)
		m.rememberBlock(block.Prefix, until)
		if err := m.write(mapBlock, []netip.Prefix{block.Prefix}, until); err != nil {
			return err
		}
	}
	return nil
}

// rememberBlock records a block for Reattach (before the write: a write that
// fails falls back, the block is replayed with the filter). Nothing is
// recorded on a node that cannot reattach, nor beyond the map's capacity.
func (m *Manager) rememberBlock(prefix netip.Prefix, until time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.status.Mode.XDP() && !m.runFallback {
		return
	}
	key, _ := keyOf(prefix)
	if _, ok := m.blocks[key]; !ok && len(m.blocks) >= maxBlocks {
		return
	}
	if until.After(m.blocks[key]) {
		m.blocks[key] = until
	}
}

// maxBlocks is cdnca_xdp_block's max_entries.
const maxBlocks = 65536

// Unblock deletes blocks (absent ones are ignored).
func (m *Manager) Unblock(prefixes []netip.Prefix) error {
	if m == nil {
		return ErrNotRunning
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, prefix := range prefixes {
		if key, ok := keyOf(prefix); ok {
			delete(m.blocks, key) // not replayed by Reattach
		}
	}
	if !m.status.Mode.XDP() {
		return ErrNotRunning
	}
	for _, prefix := range prefixes {
		key, ok := keyOf(prefix)
		if !ok {
			return ErrInvalid
		}
		if err := m.collection.Maps[mapBlock].Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			m.fallbackLocked(ReasonUpdateFailed, err)
			return err
		}
	}
	return nil
}

func (m *Manager) write(name string, prefixes []netip.Prefix, until time.Time) error {
	if m == nil {
		return ErrNotRunning
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.status.Mode.XDP() {
		return ErrNotRunning
	}
	deadline, err := monotonicDeadline(until)
	if err != nil {
		return err
	}
	for _, prefix := range prefixes {
		key, ok := keyOf(prefix)
		if !ok {
			return ErrInvalid
		}
		if err := m.putDeadline(name, key, deadline); err != nil {
			m.fallbackLocked(ReasonUpdateFailed, err)
			return err
		}
	}
	return nil
}

// portBanKey is struct cdnca_xdp_port_key.
type portBanKey struct {
	Addr [16]byte
	Port uint16
	Pad  uint16
}

// BanPorts drops client on each port until the deadline (CC kernel bans;
// IPv6 clients by address, as the firewall's cc_ban entries). A failed
// write falls back.
func (m *Manager) BanPorts(clients []netip.Addr, ports []uint16, until time.Time) error {
	if m == nil {
		return ErrNotRunning
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.status.Mode.XDP() {
		return ErrNotRunning
	}
	deadline, err := monotonicDeadline(until)
	if err != nil {
		return err
	}
	for _, client := range clients {
		if !client.IsValid() {
			continue
		}
		key, _ := keyOf(netip.PrefixFrom(client.Unmap(), client.Unmap().BitLen()))
		for _, port := range ports {
			if port == 0 {
				continue
			}
			if err := m.putDeadline(mapPortBan, portBanKey{Addr: key.Addr, Port: port}, deadline); err != nil {
				m.fallbackLocked(ReasonUpdateFailed, err)
				return err
			}
		}
	}
	return nil
}

// UnbanPorts deletes the port bans of client on each port (CC kernel bans
// narrowed after a topology change; absent ones are ignored). A failed
// delete falls back.
func (m *Manager) UnbanPorts(client netip.Addr, ports []uint16) error {
	if m == nil {
		return ErrNotRunning
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.status.Mode.XDP() {
		return ErrNotRunning
	}
	if !client.IsValid() {
		return ErrInvalid
	}
	key, _ := keyOf(netip.PrefixFrom(client.Unmap(), client.Unmap().BitLen()))
	for _, port := range ports {
		err := m.collection.Maps[mapPortBan].Delete(portBanKey{Addr: key.Addr, Port: port})
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			m.fallbackLocked(ReasonUpdateFailed, err)
			return err
		}
	}
	return nil
}

// Sweep deletes expired bans, port bans and blocks; returns how many.
func (m *Manager) Sweep() (int, error) {
	if m == nil {
		return 0, ErrNotRunning
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.status.Mode.XDP() {
		return 0, ErrNotRunning
	}
	now, err := monotonicNow()
	if err != nil {
		return 0, err
	}
	removed := 0
	wall := time.Now()
	for key, until := range m.blocks {
		if !until.After(wall) {
			delete(m.blocks, key)
		}
	}
	sweep := func(name string, key any) error {
		target := m.collection.Maps[name]
		var expired []any
		var until uint64
		iterator := target.Iterate()
		for iterator.Next(key, &until) {
			if until <= now {
				switch typed := key.(type) {
				case *lpmKey:
					expired = append(expired, *typed)
				case *portBanKey:
					expired = append(expired, *typed)
				}
			}
		}
		if err := iterator.Err(); err != nil {
			return err
		}
		for _, item := range expired {
			if err := target.Delete(item); err == nil {
				removed++
			}
		}
		return nil
	}
	for _, name := range []string{mapBan, mapBlock} {
		if err := sweep(name, &lpmKey{}); err != nil {
			return removed, err
		}
	}
	return removed, sweep(mapPortBan, &portBanKey{})
}

// Counters are the drops since the program was loaded (classes with none
// omitted), sorted by kind.
func (m *Manager) Counters() ([]Counter, error) {
	if m == nil {
		return nil, ErrNotRunning
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.status.Mode.XDP() {
		return nil, ErrNotRunning
	}
	var counters []Counter
	for index := uint32(0); index < statCount; index++ {
		var perCPU []rawCounter
		if err := m.collection.Maps[mapStats].Lookup(index, &perCPU); err != nil {
			return nil, fmt.Errorf("read %s: %w", mapStats, err)
		}
		counter := Counter{Kind: statKinds[index]}
		for _, value := range perCPU {
			counter.Packets += value.Packets
			counter.Bytes += value.Bytes
		}
		if counter.Packets != 0 {
			counters = append(counters, counter)
		}
	}
	sort.Slice(counters, func(i, j int) bool { return counters[i].Kind < counters[j].Kind })
	return counters, nil
}

// SetSiteDrop replaces the site drop the program enforces (the zero SiteDrop
// lifts it). It is kept for Reattach. A failed write falls back.
func (m *Manager) SetSiteDrop(drop SiteDrop) error {
	if m == nil {
		return ErrNotRunning
	}
	if _, err := drop.sniEntries(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.status.Mode.XDP() {
		if m.runFallback {
			m.siteDrop = drop
		}
		return ErrNotRunning
	}
	if err := m.writeSiteDrop(drop); err != nil {
		m.fallbackLocked(ReasonUpdateFailed, err)
		return err
	}
	return nil
}

// writeSiteDrop writes the names first, the port bitmaps next, then deletes
// the names no longer listed: a name the program looks up is always there.
func (m *Manager) writeSiteDrop(drop SiteDrop) error {
	entries, err := drop.sniEntries()
	if err != nil {
		return err
	}
	if drop.empty() {
		entries = map[uint64]uint8{}
	}
	names := m.collection.Maps[mapSNI]
	for key, flags := range entries {
		if m.sniKeys[key] == flags {
			continue
		}
		if err := names.Update(key, flags, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("write %s: %w", mapSNI, err)
		}
	}
	sniPorts := drop.SNIPorts
	if len(drop.DropNames) == 0 {
		sniPorts = nil
	}
	for name, ports := range map[string][]uint16{mapSitePorts: drop.Ports, mapSNIPorts: sniPorts} {
		words := portBitmap(ports)
		target := m.collection.Maps[name]
		for index, word := range words {
			if err := target.Update(uint32(index), word, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("write %s: %w", name, err)
			}
		}
	}
	for key := range m.sniKeys {
		if _, ok := entries[key]; ok {
			continue
		}
		if err := names.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete %s: %w", mapSNI, err)
		}
	}
	m.sniKeys, m.siteDrop = entries, drop
	return nil
}

// SiteDropCounters are the site drops since the program was loaded.
func (m *Manager) SiteDropCounters() (SiteDropCounters, error) {
	if m == nil {
		return SiteDropCounters{}, ErrNotRunning
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.status.Mode.XDP() {
		return SiteDropCounters{}, ErrNotRunning
	}
	var counters [siteStatCount]Counter
	for index := uint32(0); index < siteStatCount; index++ {
		var perCPU []rawCounter
		if err := m.collection.Maps[mapSiteStats].Lookup(index, &perCPU); err != nil {
			return SiteDropCounters{}, fmt.Errorf("read %s: %w", mapSiteStats, err)
		}
		for _, value := range perCPU {
			counters[index].Packets += value.Packets
			counters[index].Bytes += value.Bytes
		}
	}
	counters[siteStatPort].Kind, counters[siteStatSNI].Kind = "site_port", "site_sni"
	return SiteDropCounters{Port: counters[siteStatPort], SNI: counters[siteStatSNI]}, nil
}
