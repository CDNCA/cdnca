package nodemonitoring

import (
	"bufio"
	"context"
	"errors"
	"math"
	"math/bits"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

var (
	ErrLoadMetricsBaseline = errors.New("node load metrics baseline is not ready")
	ErrLoadMetricsCounter  = errors.New("node load metrics counter moved backwards")
	ErrLoadMetricsOverflow = errors.New("node load metrics overflow")
)

type NetworkInterfaceMetrics struct {
	Name           string `json:"name"`
	RXBytes        uint64 `json:"rx_bytes"`
	TXBytes        uint64 `json:"tx_bytes"`
	RXBandwidthBPS uint64 `json:"rx_bandwidth_bps"`
	TXBandwidthBPS uint64 `json:"tx_bandwidth_bps"`
}

type SystemLoadMetrics struct {
	OneMinute        float64 `json:"one_minute"`
	FiveMinutes      float64 `json:"five_minutes"`
	FifteenMinutes   float64 `json:"fifteen_minutes"`
	RunningProcesses uint32  `json:"running_processes"`
	TotalProcesses   uint32  `json:"total_processes"`
}

type DiskUsageMetrics struct {
	Path         string  `json:"path"`
	TotalBytes   uint64  `json:"total_bytes"`
	UsedBytes    uint64  `json:"used_bytes"`
	TotalInodes  uint64  `json:"total_inodes"`
	UsedInodes   uint64  `json:"used_inodes"`
	SpacePercent float64 `json:"space_percent"`
	InodePercent float64 `json:"inode_percent"`
}

// DDoSDropMetrics is one packet filter's cumulative drops in the node DDoS
// table (ddos.DropCounter).
type DDoSDropMetrics struct {
	Kind    string `json:"kind"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// DDoSDropKinds are the packet filter kinds a report may carry.
var DDoSDropKinds = []string{"ct_invalid", "tcp_all", "tcp_fin", "tcp_null", "tcp_syn_fin", "tcp_syn_rst", "tcp_xmas"}

type TelemetryMetrics struct {
	SchemaVersion     uint8                     `json:"schema_version"`
	NetworkSelection  *NetworkSelection         `json:"network_selection,omitempty"`
	NetworkInterfaces []NetworkInterfaceMetrics `json:"network_interfaces,omitempty"`
	SystemLoad        *SystemLoadMetrics        `json:"system_load,omitempty"`
	Disks             []DiskUsageMetrics        `json:"disks,omitempty"`
	TotalRXBytes      uint64                    `json:"total_rx_bytes"`
	TotalTXBytes      uint64                    `json:"total_tx_bytes"`
	DDoSDrops         []DDoSDropMetrics         `json:"ddos_drops,omitempty"`
	XDP               *XDPStatusMetrics         `json:"xdp,omitempty"`
	SiteDrop          *SiteDropMetrics          `json:"site_drop,omitempty"`
	DDoSProtection    *DDoSProtectionMetrics    `json:"ddos_protection,omitempty"`
	// Mounts and PortGroupOverrides: NODE_TELEMETRY_DETAIL v1.
	Mounts             []MountMetrics             `json:"mounts,omitempty"`
	PortGroupOverrides []PortGroupOverrideMetrics `json:"port_group_overrides,omitempty"`
	// Storage: the node storage in effect (NODE_STORAGE v1, NodeStorageV1).
	Storage *StorageMetrics `json:"storage,omitempty"`
}

// StorageMetrics is the node storage in effect (NodeStorageV1).
type StorageMetrics struct {
	CacheDirectory        string `json:"cache_directory"`
	CacheMaxBytes         uint64 `json:"cache_max_bytes"`
	LogDirectory          string `json:"log_directory"`
	State                 string `json:"state"`
	Reason                string `json:"reason,omitempty"`
	RequestedLogDirectory string `json:"requested_log_directory,omitempty"`
}

// PortGroupOverrideMetrics is one layer 4 port group override on the node
// (NodePortGroupOverrideV1): state applied, standby, inactive (Reason says
// why) or failed.
type PortGroupOverrideMetrics struct {
	PortGroupID string `json:"port_group_id"`
	State       string `json:"state"`
	Reason      string `json:"reason,omitempty"`
}

// MaxPortGroupOverrides bounds the port group overrides of one sample.
const MaxPortGroupOverrides = 256

// Port group override vocabulary (NodePortGroupOverrideV1).
var (
	PortGroupOverrideStates  = []string{"applied", "failed", "inactive", "standby"}
	PortGroupOverrideReasons = []string{"auto_mitigation_off", "manual", "shared_ports", "suggest"}
)

// validPortGroupOverrides: sorted by ID, unique, bounded; known state; a
// known reason exactly when inactive.
func validPortGroupOverrides(overrides []PortGroupOverrideMetrics) bool {
	if len(overrides) > MaxPortGroupOverrides {
		return false
	}
	previous := ""
	for _, override := range overrides {
		inactive := override.State == "inactive"
		if override.PortGroupID == "" || len(override.PortGroupID) > 64 || override.PortGroupID <= previous ||
			!slices.Contains(PortGroupOverrideStates, override.State) || inactive != (override.Reason != "") ||
			(inactive && !slices.Contains(PortGroupOverrideReasons, override.Reason)) {
			return false
		}
		previous = override.PortGroupID
	}
	return true
}

// validMounts: sorted by path, unique, bounded; major:minor device; a known
// filter reason or none.
func validMounts(mounts []MountMetrics) bool {
	if len(mounts) > MaxMounts {
		return false
	}
	previous := ""
	for _, mount := range mounts {
		if mount.Path == "" || len(mount.Path) > 4096 || mount.Path[0] != '/' || mount.Path <= previous ||
			!validMountDevice(mount.Device) || len(mount.FSType) > 64 || strings.ContainsAny(mount.FSType, "\x00\r\n\t ") ||
			(mount.FilterReason != "" && !slices.Contains(mountFilterReasons, mount.FilterReason)) {
			return false
		}
		previous = mount.Path
	}
	return true
}

// DDoSProtectionMetrics is the node DDoS protection table's state now
// (NodeDDoSProtectionV1, E1): applied, off, pending, failed or
// unavailable (Reason says why).
type DDoSProtectionMetrics struct {
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// DDoS protection vocabulary (NodeDDoSProtectionV1).
var (
	DDoSProtectionStates  = []string{"applied", "failed", "off", "pending", "unavailable"}
	DDoSProtectionReasons = []string{"init_failed", "nft_missing", "nft_unusable", "unsupported_os"}
)

// validDDoSProtection: known state; a reason exactly when unavailable;
// detail only for failed / unavailable, bounded, single line.
func validDDoSProtection(status *DDoSProtectionMetrics) bool {
	if status == nil {
		return true
	}
	unavailable := status.State == "unavailable"
	return slices.Contains(DDoSProtectionStates, status.State) &&
		unavailable == (status.Reason != "") && (!unavailable || slices.Contains(DDoSProtectionReasons, status.Reason)) &&
		(status.Detail == "" || unavailable || status.State == "failed") &&
		len(status.Detail) <= xdpMaxDetail && !strings.ContainsAny(status.Detail, "\x00\r\n")
}

// SiteDropMetrics are the level D site drops (攻击自动升级: XDP site counters
// and the nftables site_drop counter) since the previous sample. The node's
// counters are not per site: Packets / Bytes are the node total, shared by
// SiteIDs (the sites dropped for in the interval).
type SiteDropMetrics struct {
	SiteIDs []string `json:"site_ids"`
	Packets uint64   `json:"packets"`
	Bytes   uint64   `json:"bytes"`
}

// MaxSiteDropSites bounds SiteDropMetrics.SiteIDs.
const MaxSiteDropSites = 256

// validSiteDrop: 1..MaxSiteDropSites canonical UUIDs, sorted and unique;
// counters within int64.
func validSiteDrop(drop *SiteDropMetrics) bool {
	if drop == nil {
		return true
	}
	if len(drop.SiteIDs) == 0 || len(drop.SiteIDs) > MaxSiteDropSites || drop.Packets > math.MaxInt64 || drop.Bytes > math.MaxInt64 {
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

// XDPStatusMetrics is the node XDP filter's mode now (xdp.Status):
// native / generic attached, nftables / disabled not (with the reason).
type XDPStatusMetrics struct {
	Mode       string            `json:"mode"`
	Reason     string            `json:"reason,omitempty"`
	Detail     string            `json:"detail,omitempty"`
	Interfaces []string          `json:"interfaces,omitempty"`
	Drops      []DDoSDropMetrics `json:"drops,omitempty"`
}

// XDP status vocabulary (xdp.Mode*, xdp.Reason*, xdp.DropKinds).
var (
	XDPModes       = []string{"disabled", "generic", "native", "nftables"}
	XDPReasons     = []string{"attach_failed", "bpf_unavailable", "disabled", "kernel_too_old", "load_failed", "no_interface", "self_test_failed", "unsupported_os", "update_failed", "verify_failed"}
	XDPDropKinds   = []string{"tcp_all", "tcp_null", "tcp_syn_fin", "tcp_syn_rst", "tcp_xmas", "xdp_ban", "xdp_block", "xdp_port_ban", "xdp_rate"}
	xdpMaxDetail   = 256
	xdpMaxNICs     = 64
	xdpMaxNICBytes = 15
)

// validXDPStatus: known mode; attached modes have interfaces and no reason,
// the others a reason and neither interfaces nor drops; bounded strings.
func validXDPStatus(status *XDPStatusMetrics) bool {
	if status == nil {
		return true
	}
	attached := status.Mode == "native" || status.Mode == "generic"
	if !slices.Contains(XDPModes, status.Mode) || len(status.Detail) > xdpMaxDetail ||
		strings.ContainsAny(status.Detail, "\x00\r\n") || len(status.Interfaces) > xdpMaxNICs {
		return false
	}
	if attached != (status.Reason == "") || attached != (len(status.Interfaces) != 0) ||
		!attached && (len(status.Drops) != 0 || !slices.Contains(XDPReasons, status.Reason)) {
		return false
	}
	previous := ""
	for _, nic := range status.Interfaces {
		name, mode, ok := strings.Cut(nic, "=")
		if !ok || name == "" || len(name) > xdpMaxNICBytes || strings.ContainsAny(name, "/= \x00\r\n\t") ||
			mode != "native" && mode != "generic" || nic <= previous {
			return false
		}
		previous = nic
	}
	previous = ""
	for _, drop := range status.Drops {
		if drop.Kind <= previous || !slices.Contains(XDPDropKinds, drop.Kind) ||
			drop.Packets > math.MaxInt64 || drop.Bytes > math.MaxInt64 {
			return false
		}
		previous = drop.Kind
	}
	return true
}

type LoadMetrics struct {
	ObservedAt        time.Time
	CPUPercent        float64
	MemoryUsedBytes   uint64
	MemoryTotalBytes  uint64
	ActiveConnections uint64
	RXBandwidthBPS    uint64
	TXBandwidthBPS    uint64
	Telemetry         *TelemetryMetrics
}

type LoadCollector interface {
	Collect(context.Context, time.Time) (*LoadMetrics, error)
}

type networkCounter struct {
	rxBytes uint64
	txBytes uint64
}

type loadCounters struct {
	at         time.Time
	cpuTotal   uint64
	cpuIdle    uint64
	interfaces map[string]networkCounter
}

type loadSnapshot struct {
	counters    loadCounters
	memoryUsed  uint64
	memoryTotal uint64
	connections uint64
	systemLoad  *SystemLoadMetrics
	disks       []DiskUsageMetrics
	mounts      []MountMetrics
}

type linuxLoadCollector struct {
	mu         sync.Mutex
	readFile   func(string) ([]byte, error)
	statfs     func(string, *unix.Statfs_t) error
	previous   *loadCounters
	routeQuery routeQuery
}

func NewLinuxLoadCollector() LoadCollector {
	collector := newLinuxLoadCollector(os.ReadFile)
	collector.routeQuery = runRouteQuery
	return collector
}

func newLinuxLoadCollector(readFile func(string) ([]byte, error)) *linuxLoadCollector {
	return &linuxLoadCollector{readFile: readFile, statfs: unix.Statfs}
}

func (collector *linuxLoadCollector) Collect(ctx context.Context, observedAt time.Time) (*LoadMetrics, error) {
	if collector == nil || collector.readFile == nil || observedAt.IsZero() || ctx == nil {
		return nil, ErrLoadMetricsCounter
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	collector.mu.Lock()
	defer collector.mu.Unlock()
	snapshot, err := collector.snapshot(observedAt.UTC())
	if err != nil {
		return nil, err
	}
	if collector.previous == nil {
		collector.previous = cloneLoadCounters(snapshot.counters)
		return nil, ErrLoadMetricsBaseline
	}
	previous := collector.previous
	collector.previous = cloneLoadCounters(snapshot.counters)
	if !snapshot.counters.at.After(previous.at) || snapshot.counters.cpuTotal < previous.cpuTotal ||
		snapshot.counters.cpuIdle < previous.cpuIdle {
		return nil, ErrLoadMetricsCounter
	}
	totalDelta := snapshot.counters.cpuTotal - previous.cpuTotal
	idleDelta := snapshot.counters.cpuIdle - previous.cpuIdle
	if totalDelta == 0 || idleDelta > totalDelta {
		return nil, ErrLoadMetricsCounter
	}
	cpuPercent := float64(totalDelta-idleDelta) * 100 / float64(totalDelta)
	if math.IsNaN(cpuPercent) || math.IsInf(cpuPercent, 0) || cpuPercent < 0 || cpuPercent > 100 {
		return nil, ErrLoadMetricsOverflow
	}
	elapsed := snapshot.counters.at.Sub(previous.at)
	interfaces, rxDelta, txDelta, err := networkDeltas(previous.interfaces, snapshot.counters.interfaces, elapsed)
	if err != nil {
		return nil, err
	}
	rxBPS, err := bytesPerSecond(rxDelta, elapsed)
	if err != nil {
		return nil, err
	}
	txBPS, err := bytesPerSecond(txDelta, elapsed)
	if err != nil {
		return nil, err
	}
	totalRX, totalTX, err := networkTotals(snapshot.counters.interfaces)
	if err != nil {
		return nil, err
	}
	var telemetry *TelemetryMetrics
	if len(interfaces) > 0 || snapshot.systemLoad != nil || len(snapshot.disks) > 0 {
		telemetry = &TelemetryMetrics{SchemaVersion: 1, NetworkInterfaces: interfaces,
			SystemLoad: snapshot.systemLoad, Disks: snapshot.disks, Mounts: snapshot.mounts,
			NetworkSelection: detectNetworkSelection(ctx, collector.routeQuery, snapshot.counters.interfaces),
			TotalRXBytes:     totalRX, TotalTXBytes: totalTX}
	}
	return &LoadMetrics{ObservedAt: snapshot.counters.at, CPUPercent: cpuPercent,
		MemoryUsedBytes: snapshot.memoryUsed, MemoryTotalBytes: snapshot.memoryTotal,
		ActiveConnections: snapshot.connections, RXBandwidthBPS: rxBPS, TXBandwidthBPS: txBPS,
		Telemetry: telemetry}, nil
}

func (collector *linuxLoadCollector) snapshot(observedAt time.Time) (loadSnapshot, error) {
	cpuPayload, err := collector.readFile("/proc/stat")
	if err != nil {
		return loadSnapshot{}, err
	}
	total, idle, err := parseCPU(cpuPayload)
	if err != nil {
		return loadSnapshot{}, err
	}
	memoryPayload, err := collector.readFile("/proc/meminfo")
	if err != nil {
		return loadSnapshot{}, err
	}
	memoryUsed, memoryTotal, err := parseMemory(memoryPayload)
	if err != nil {
		return loadSnapshot{}, err
	}
	networkPayload, err := collector.readFile("/proc/net/dev")
	if err != nil {
		return loadSnapshot{}, err
	}
	interfaces, _, _, err := parseNetworkCounters(networkPayload)
	if err != nil {
		return loadSnapshot{}, err
	}
	connections, err := collector.establishedConnections()
	if err != nil {
		return loadSnapshot{}, err
	}
	var systemLoad *SystemLoadMetrics
	if payload, readErr := collector.readFile("/proc/loadavg"); readErr == nil {
		systemLoad, _ = parseLoadAverage(payload)
	}
	disks, mounts := collector.diskUsage()
	return loadSnapshot{
		counters:   loadCounters{at: observedAt, cpuTotal: total, cpuIdle: idle, interfaces: interfaces},
		memoryUsed: memoryUsed, memoryTotal: memoryTotal, connections: connections,
		systemLoad: systemLoad, disks: disks, mounts: mounts,
	}, nil
}

func parseCPU(payload []byte) (uint64, uint64, error) {
	line, _, _ := strings.Cut(string(payload), "\n")
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0, ErrLoadMetricsCounter
	}
	values := make([]uint64, len(fields)-1)
	var total uint64
	for index, field := range fields[1:] {
		value, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return 0, 0, ErrLoadMetricsCounter
		}
		if index < 8 {
			var carry uint64
			total, carry = bits.Add64(total, value, 0)
			if carry != 0 {
				return 0, 0, ErrLoadMetricsOverflow
			}
		}
		values[index] = value
	}
	idle := values[3]
	if len(values) > 4 {
		var carry uint64
		idle, carry = bits.Add64(idle, values[4], 0)
		if carry != 0 {
			return 0, 0, ErrLoadMetricsOverflow
		}
	}
	return total, idle, nil
}

func parseMemory(payload []byte) (uint64, uint64, error) {
	var totalKB, availableKB uint64
	scanner := bufio.NewScanner(strings.NewReader(string(payload)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0, 0, ErrLoadMetricsCounter
		}
		switch fields[0] {
		case "MemTotal:":
			totalKB = value
		case "MemAvailable:":
			availableKB = value
		}
	}
	if scanner.Err() != nil || totalKB == 0 || availableKB > totalKB {
		return 0, 0, ErrLoadMetricsCounter
	}
	high, total := bits.Mul64(totalKB, 1024)
	if high != 0 {
		return 0, 0, ErrLoadMetricsOverflow
	}
	high, available := bits.Mul64(availableKB, 1024)
	if high != 0 {
		return 0, 0, ErrLoadMetricsOverflow
	}
	return total - available, total, nil
}

func parseNetwork(payload []byte) (uint64, uint64, error) {
	_, rx, tx, err := parseNetworkCounters(payload)
	return rx, tx, err
}

func parseNetworkCounters(payload []byte) (map[string]networkCounter, uint64, uint64, error) {
	interfaces := make(map[string]networkCounter)
	var rxTotal, txTotal uint64
	scanner := bufio.NewScanner(strings.NewReader(string(payload)))
	for scanner.Scan() {
		name, values, ok := strings.Cut(scanner.Text(), ":")
		name = strings.TrimSpace(name)
		if !ok || name == "lo" {
			continue
		}
		if name == "" || len(name) > 128 || strings.ContainsAny(name, "\x00\r\n\t") {
			return nil, 0, 0, ErrLoadMetricsCounter
		}
		fields := strings.Fields(values)
		if len(fields) < 9 {
			return nil, 0, 0, ErrLoadMetricsCounter
		}
		rx, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return nil, 0, 0, ErrLoadMetricsCounter
		}
		tx, err := strconv.ParseUint(fields[8], 10, 64)
		if err != nil {
			return nil, 0, 0, ErrLoadMetricsCounter
		}
		if _, exists := interfaces[name]; exists {
			return nil, 0, 0, ErrLoadMetricsCounter
		}
		interfaces[name] = networkCounter{rxBytes: rx, txBytes: tx}
		var carry uint64
		rxTotal, carry = bits.Add64(rxTotal, rx, 0)
		if carry != 0 {
			return nil, 0, 0, ErrLoadMetricsOverflow
		}
		txTotal, carry = bits.Add64(txTotal, tx, 0)
		if carry != 0 {
			return nil, 0, 0, ErrLoadMetricsOverflow
		}
	}
	if scanner.Err() != nil {
		return nil, 0, 0, scanner.Err()
	}
	return interfaces, rxTotal, txTotal, nil
}

func parseLoadAverage(payload []byte) (*SystemLoadMetrics, error) {
	fields := strings.Fields(string(payload))
	if len(fields) < 4 {
		return nil, ErrLoadMetricsCounter
	}
	values := make([]float64, 3)
	for index := range values {
		value, err := strconv.ParseFloat(fields[index], 64)
		if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > 1e9 {
			return nil, ErrLoadMetricsCounter
		}
		values[index] = value
	}
	parts := strings.Split(fields[3], "/")
	if len(parts) != 2 {
		return nil, ErrLoadMetricsCounter
	}
	running, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return nil, ErrLoadMetricsCounter
	}
	total, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil || total == 0 || running > total {
		return nil, ErrLoadMetricsCounter
	}
	return &SystemLoadMetrics{OneMinute: values[0], FiveMinutes: values[1], FifteenMinutes: values[2],
		RunningProcesses: uint32(running), TotalProcesses: uint32(total)}, nil
}

func (collector *linuxLoadCollector) establishedConnections() (uint64, error) {
	var total uint64
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		payload, err := collector.readFile(path)
		if err != nil {
			return 0, err
		}
		scanner := bufio.NewScanner(strings.NewReader(string(payload)))
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) > 3 && fields[3] == "01" {
				if total == math.MaxUint64 {
					return 0, ErrLoadMetricsOverflow
				}
				total++
			}
		}
		if scanner.Err() != nil {
			return 0, scanner.Err()
		}
	}
	return total, nil
}

// diskUsage is the disk rows and every mount (MaxMounts at most) with why
// the rows leave it out.
func (collector *linuxLoadCollector) diskUsage() ([]DiskUsageMetrics, []MountMetrics) {
	if collector == nil || collector.readFile == nil || collector.statfs == nil {
		return nil, nil
	}
	payload, err := collector.readFile("/proc/self/mountinfo")
	if err != nil {
		return nil, nil
	}
	mounts := parseMounts(payload)
	result := make([]DiskUsageMetrics, 0, len(mounts))
	for index := range mounts {
		if mounts[index].FilterReason != "" {
			continue
		}
		path := mounts[index].Path
		disk, ok := collector.diskRow(path)
		if !ok {
			mounts[index].FilterReason = "stat_failed"
			continue
		}
		result = append(result, disk)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })
	if len(mounts) > MaxMounts {
		mounts = mounts[:MaxMounts]
	}
	return result, mounts
}

// diskRow is the statfs numbers of one mount.
func (collector *linuxLoadCollector) diskRow(path string) (DiskUsageMetrics, bool) {
	var stat unix.Statfs_t
	if err := collector.statfs(path, &stat); err != nil || stat.Bsize <= 0 {
		return DiskUsageMetrics{}, false
	}
	blockSize := uint64(stat.Bsize)
	totalBytes, ok := multiplyUint64(uint64(stat.Blocks), blockSize)
	if !ok || totalBytes == 0 {
		return DiskUsageMetrics{}, false
	}
	availableBytes, ok := multiplyUint64(uint64(stat.Bavail), blockSize)
	if !ok || availableBytes > totalBytes {
		return DiskUsageMetrics{}, false
	}
	usedBytes := totalBytes - availableBytes
	totalInodes := uint64(stat.Files)
	freeInodes := uint64(stat.Ffree)
	if freeInodes > totalInodes {
		return DiskUsageMetrics{}, false
	}
	usedInodes := totalInodes - freeInodes
	return DiskUsageMetrics{Path: path, TotalBytes: totalBytes,
		UsedBytes: usedBytes, TotalInodes: totalInodes, UsedInodes: usedInodes,
		SpacePercent: percent(usedBytes, totalBytes), InodePercent: percent(usedInodes, totalInodes)}, true
}

// MountMetrics is one mount of /proc/self/mountinfo (NodeMountV1,
// NODE_TELEMETRY_DETAIL v1). FilterReason says why the disk ranking leaves it
// out (mountFilterReasons); empty: the mount is a disk row.
type MountMetrics struct {
	Path         string `json:"path"`
	Device       string `json:"device"`
	FSType       string `json:"fstype"`
	ReadOnly     bool   `json:"read_only"`
	Bind         bool   `json:"bind"`
	FilterReason string `json:"filter_reason,omitempty"`
}

// MaxMounts bounds the mounts of one sample.
const MaxMounts = 256

// Mount filter reasons (NodeMountV1.filter_reason).
// stat_failed: statfs of the mount failed or gave no size, so it has no disk row.
var mountFilterReasons = []string{"bind_duplicate", "read_only", "squashfs", "stat_failed", "system_path"}

// parseMountPoints lists the mounts worth a disk row (硬盘排行只读挂载污染):
// the mounts parseMounts leaves unfiltered.
func parseMountPoints(payload []byte) []string {
	var paths []string
	for _, mount := range parseMounts(payload) {
		if mount.FilterReason == "" {
			paths = append(paths, mount.Path)
		}
	}
	return paths
}

// parseMounts lists every mount, sorted by path (a path mounted twice keeps
// the later, visible mount), with why the disk ranking leaves it out:
// /proc /sys /dev /run (system_path), squashfs images, read-only mounts
// (mount or super options carry ro: snap/LXD images, ro overlay layers), and
// bind mounts of a device already ranked (bind_duplicate: /etc, a
// bind-mounted PEM file statfs to the device's numbers). A device keeps one
// row: its mount of the filesystem root ("/" mount root), else its shortest
// mount point. Bind marks a mount of a subtree, or a device's mount other
// than the one it is ranked by.
// mountinfo: id parent major:minor root mountpoint options [optional...] - fstype source superoptions.
func parseMounts(payload []byte) []MountMetrics {
	byPath := make(map[string]int)
	var mounts []MountMetrics
	var roots []bool
	for _, line := range strings.Split(string(payload), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		separator := -1
		for index := 6; index < len(fields); index++ {
			if fields[index] == "-" {
				separator = index
				break
			}
		}
		path := decodeMountInfoPath(fields[4])
		if path == "" || path[0] != '/' || len(path) > 4096 || !validMountDevice(fields[2]) {
			continue
		}
		options := strings.Split(fields[5], ",")
		fstype := ""
		if separator >= 0 && separator+1 < len(fields) {
			fstype = fields[separator+1]
			if separator+3 < len(fields) {
				options = append(options, strings.Split(fields[separator+3], ",")...)
			}
		}
		if len(fstype) > 64 {
			fstype = ""
		}
		mount := MountMetrics{Path: path, Device: fields[2], FSType: fstype, ReadOnly: slices.Contains(options, "ro")}
		root := decodeMountInfoPath(fields[3]) == "/"
		switch {
		case path != "/" && (strings.HasPrefix(path, "/proc") || strings.HasPrefix(path, "/sys") ||
			strings.HasPrefix(path, "/dev") || strings.HasPrefix(path, "/run")):
			mount.FilterReason = "system_path"
		case fstype == "squashfs":
			mount.FilterReason = "squashfs"
		case mount.ReadOnly:
			mount.FilterReason = "read_only"
		}
		if index, ok := byPath[path]; ok {
			mounts[index], roots[index] = mount, root
			continue
		}
		byPath[path] = len(mounts)
		mounts = append(mounts, mount)
		roots = append(roots, root)
	}
	// Each device's ranked mount among the unfiltered ones, and its preferred
	// mount among all of them (the others are bind mounts).
	ranked := make(map[string]int)
	preferred := make(map[string]int)
	choice := func(index int) mountChoice { return mountChoice{path: mounts[index].Path, fullRoot: roots[index]} }
	for index, mount := range mounts {
		if current, ok := preferred[mount.Device]; !ok || choice(index).preferredTo(choice(current)) {
			preferred[mount.Device] = index
		}
		if mount.FilterReason != "" {
			continue
		}
		if current, ok := ranked[mount.Device]; !ok || choice(index).preferredTo(choice(current)) {
			ranked[mount.Device] = index
		}
	}
	for index := range mounts {
		mount := &mounts[index]
		mount.Bind = !roots[index] || preferred[mount.Device] != index
		if mount.FilterReason == "" && ranked[mount.Device] != index {
			mount.FilterReason = "bind_duplicate"
		}
	}
	sort.Slice(mounts, func(i, j int) bool { return mounts[i].Path < mounts[j].Path })
	return mounts
}

// validMountDevice: major:minor, decimal.
func validMountDevice(value string) bool {
	major, minor, ok := strings.Cut(value, ":")
	return ok && len(value) <= 24 && decimalDigits(major) && decimalDigits(minor)
}

func decimalDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// mountChoice is a device's mount point; fullRoot: it mounts the filesystem
// root rather than a bind of a subtree or file.
type mountChoice struct {
	path     string
	fullRoot bool
}

// preferredTo: a mount of the filesystem root wins over a bind mount, then the
// shorter mount point, then the smaller path (deterministic).
func (candidate mountChoice) preferredTo(current mountChoice) bool {
	if candidate.fullRoot != current.fullRoot {
		return candidate.fullRoot
	}
	if len(candidate.path) != len(current.path) {
		return len(candidate.path) < len(current.path)
	}
	return candidate.path < current.path
}

func decodeMountInfoPath(value string) string {
	value = strings.ReplaceAll(value, `\040`, " ")
	value = strings.ReplaceAll(value, `\011`, "\t")
	value = strings.ReplaceAll(value, `\012`, "\n")
	return strings.ReplaceAll(value, `\134`, `\`)
}

func networkDeltas(previous, current map[string]networkCounter, elapsed time.Duration) ([]NetworkInterfaceMetrics, uint64, uint64, error) {
	result := make([]NetworkInterfaceMetrics, 0, len(current))
	var rxDelta, txDelta uint64
	for name, now := range current {
		before, ok := previous[name]
		if !ok {
			result = append(result, NetworkInterfaceMetrics{Name: name, RXBytes: now.rxBytes, TXBytes: now.txBytes})
			continue
		}
		rxIncrement := now.rxBytes
		if now.rxBytes >= before.rxBytes {
			rxIncrement = now.rxBytes - before.rxBytes
		}
		txIncrement := now.txBytes
		if now.txBytes >= before.txBytes {
			txIncrement = now.txBytes - before.txBytes
		}
		rx, carry := bits.Add64(rxDelta, rxIncrement, 0)
		if carry != 0 {
			return nil, 0, 0, ErrLoadMetricsOverflow
		}
		rxDelta = rx
		tx, carry := bits.Add64(txDelta, txIncrement, 0)
		if carry != 0 {
			return nil, 0, 0, ErrLoadMetricsOverflow
		}
		txDelta = tx
		rxBPS, err := bytesPerSecond(rxIncrement, elapsed)
		if err != nil {
			return nil, 0, 0, err
		}
		txBPS, err := bytesPerSecond(txIncrement, elapsed)
		if err != nil {
			return nil, 0, 0, err
		}
		result = append(result, NetworkInterfaceMetrics{Name: name, RXBytes: now.rxBytes, TXBytes: now.txBytes,
			RXBandwidthBPS: rxBPS, TXBandwidthBPS: txBPS})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, rxDelta, txDelta, nil
}

func networkTotals(interfaces map[string]networkCounter) (uint64, uint64, error) {
	var rxTotal, txTotal uint64
	for _, value := range interfaces {
		var carry uint64
		rxTotal, carry = bits.Add64(rxTotal, value.rxBytes, 0)
		if carry != 0 {
			return 0, 0, ErrLoadMetricsOverflow
		}
		txTotal, carry = bits.Add64(txTotal, value.txBytes, 0)
		if carry != 0 {
			return 0, 0, ErrLoadMetricsOverflow
		}
	}
	return rxTotal, txTotal, nil
}

func cloneLoadCounters(value loadCounters) *loadCounters {
	interfaces := make(map[string]networkCounter, len(value.interfaces))
	for name, counter := range value.interfaces {
		interfaces[name] = counter
	}
	value.interfaces = interfaces
	return &value
}

func bytesPerSecond(delta uint64, elapsed time.Duration) (uint64, error) {
	if elapsed <= 0 {
		return 0, ErrLoadMetricsCounter
	}
	hi, lo := bits.Mul64(delta, 8_000_000_000)
	divisor := uint64(elapsed)
	if hi >= divisor {
		return 0, ErrLoadMetricsOverflow
	}
	quotient, _ := bits.Div64(hi, lo, divisor)
	return quotient, nil
}

func multiplyUint64(left, right uint64) (uint64, bool) {
	high, low := bits.Mul64(left, right)
	return low, high == 0
}

func percent(used, total uint64) float64 {
	if total == 0 {
		return 0
	}
	return float64(used) * 100 / float64(total)
}

func ValidLoadMetrics(metrics *LoadMetrics, observedAt time.Time) bool {
	return metrics != nil && !metrics.ObservedAt.IsZero() && metrics.ObservedAt.Equal(observedAt) &&
		!math.IsNaN(metrics.CPUPercent) && !math.IsInf(metrics.CPUPercent, 0) &&
		metrics.CPUPercent >= 0 && metrics.CPUPercent <= 100 && metrics.MemoryTotalBytes > 0 &&
		metrics.MemoryUsedBytes <= metrics.MemoryTotalBytes && validTelemetry(metrics.Telemetry)
}

func validLoadMetrics(metrics *LoadMetrics, observedAt time.Time) bool {
	return ValidLoadMetrics(metrics, observedAt)
}

func validTelemetry(telemetry *TelemetryMetrics) bool {
	if telemetry == nil {
		return true
	}
	if telemetry.SchemaVersion != 1 || len(telemetry.NetworkInterfaces) > 128 || len(telemetry.Disks) > 128 {
		return false
	}
	previousName := ""
	if selection := telemetry.NetworkSelection; selection != nil {
		if selection.Source != "default_route" && selection.Source != "unavailable" ||
			(selection.Source == "default_route") != (len(selection.Interfaces) > 0) || len(selection.Interfaces) > 128 {
			return false
		}
		for _, name := range selection.Interfaces {
			if name <= previousName {
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
			previousName = name
		}
		previousName = ""
	}
	for _, network := range telemetry.NetworkInterfaces {
		if network.Name == "" || len(network.Name) > 128 || strings.ContainsAny(network.Name, "\x00\r\n\t") ||
			previousName >= network.Name {
			return false
		}
		previousName = network.Name
	}
	if telemetry.SystemLoad != nil {
		load := telemetry.SystemLoad
		for _, value := range []float64{load.OneMinute, load.FiveMinutes, load.FifteenMinutes} {
			if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > 1e9 {
				return false
			}
		}
		if load.TotalProcesses == 0 || load.RunningProcesses > load.TotalProcesses {
			return false
		}
	}
	if !validDDoSDrops(telemetry.DDoSDrops) || !validXDPStatus(telemetry.XDP) || !validSiteDrop(telemetry.SiteDrop) ||
		!validDDoSProtection(telemetry.DDoSProtection) || !validMounts(telemetry.Mounts) ||
		!validPortGroupOverrides(telemetry.PortGroupOverrides) {
		return false
	}
	previousPath := ""
	for _, disk := range telemetry.Disks {
		if disk.Path == "" || len(disk.Path) > 4096 || disk.Path[0] != '/' || previousPath >= disk.Path ||
			disk.UsedBytes > disk.TotalBytes || disk.UsedInodes > disk.TotalInodes ||
			math.IsNaN(disk.SpacePercent) || math.IsInf(disk.SpacePercent, 0) || disk.SpacePercent < 0 || disk.SpacePercent > 100 ||
			math.IsNaN(disk.InodePercent) || math.IsInf(disk.InodePercent, 0) || disk.InodePercent < 0 || disk.InodePercent > 100 {
			return false
		}
		previousPath = disk.Path
	}
	return true
}

// validDDoSDrops: known kinds, sorted, unique; counters within int64.
func validDDoSDrops(drops []DDoSDropMetrics) bool {
	previous := ""
	for _, drop := range drops {
		if drop.Kind <= previous || !slices.Contains(DDoSDropKinds, drop.Kind) ||
			drop.Packets > math.MaxInt64 || drop.Bytes > math.MaxInt64 {
			return false
		}
		previous = drop.Kind
	}
	return true
}
