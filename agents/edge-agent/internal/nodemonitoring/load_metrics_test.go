package nodemonitoring

import (
	"context"
	"errors"
	"math"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type loadFixtureReader struct{ files map[string][]byte }

func (reader *loadFixtureReader) ReadFile(path string) ([]byte, error) {
	payload, ok := reader.files[path]
	if !ok {
		return nil, errors.New("missing fixture")
	}
	return append([]byte(nil), payload...), nil
}

func TestLinuxLoadCollectorUsesBoundedDeltasAndEstablishedConnections(t *testing.T) {
	reader := &loadFixtureReader{files: loadFixture(100, 850, 100, 200)}
	collector := newLinuxLoadCollector(reader.ReadFile)
	started := time.Date(2026, 8, 8, 1, 0, 0, 0, time.UTC)
	if metrics, err := collector.Collect(t.Context(), started); !errors.Is(err, ErrLoadMetricsBaseline) || metrics != nil {
		t.Fatalf("first Collect() = (%#v, %v), want unknown baseline", metrics, err)
	}
	reader.files = loadFixture(130, 920, 300, 600)
	metrics, err := collector.Collect(t.Context(), started.Add(2*time.Second))
	if err != nil {
		t.Fatalf("second Collect() error = %v", err)
	}
	if metrics.ObservedAt != started.Add(2*time.Second) || math.Abs(metrics.CPUPercent-30) > 0.000001 ||
		metrics.MemoryUsedBytes != 768_000 || metrics.MemoryTotalBytes != 1_024_000 ||
		metrics.ActiveConnections != 2 || metrics.RXBandwidthBPS != 800 || metrics.TXBandwidthBPS != 1_600 {
		t.Fatalf("metrics = %#v", metrics)
	}
}

func TestLinuxLoadCollectorPublishesInterfaceLoadAndDiskTelemetry(t *testing.T) {
	reader := &loadFixtureReader{files: loadFixture(100, 850, 100, 200)}
	reader.files["/proc/loadavg"] = []byte("1.25 0.75 0.50 3/40 1234\n")
	reader.files["/proc/self/mountinfo"] = []byte("36 29 0:32 / / rw,relatime - ext4 /dev/root rw\n")
	reader.files["/proc/net/dev"] = []byte("Inter-| Receive | Transmit\n eth0: 100 0 0 0 0 0 0 0 200 0 0 0 0 0 0 0\n eth1: 50 0 0 0 0 0 0 0 80 0 0 0 0 0 0 0\n")
	collector := newLinuxLoadCollector(reader.ReadFile)
	collector.statfs = func(path string, stat *unix.Statfs_t) error {
		if path != "/" {
			return errors.New("unexpected mount path")
		}
		stat.Bsize, stat.Blocks, stat.Bavail, stat.Files, stat.Ffree = 4096, 100, 25, 1000, 250
		return nil
	}
	started := time.Date(2026, 8, 8, 1, 0, 0, 0, time.UTC)
	_, _ = collector.Collect(t.Context(), started)
	reader.files["/proc/stat"] = []byte("cpu  130 0 50 920 0 0 0 0 0 0\n")
	reader.files["/proc/meminfo"] = []byte("MemTotal:       1000 kB\nMemAvailable:    250 kB\n")
	reader.files["/proc/net/tcp"] = []byte("  sl  local_address rem_address st\n")
	reader.files["/proc/net/tcp6"] = []byte("  sl  local_address rem_address st\n")
	reader.files["/proc/net/dev"] = []byte("Inter-| Receive | Transmit\n eth0: 300 0 0 0 0 0 0 0 600 0 0 0 0 0 0 0\n eth1: 150 0 0 0 0 0 0 0 280 0 0 0 0 0 0 0\n")
	metrics, err := collector.Collect(t.Context(), started.Add(2*time.Second))
	if err != nil {
		t.Fatalf("second Collect() error = %v", err)
	}
	if metrics.Telemetry == nil || len(metrics.Telemetry.NetworkInterfaces) != 2 || metrics.Telemetry.SystemLoad == nil || len(metrics.Telemetry.Disks) != 1 {
		t.Fatalf("telemetry = %#v", metrics.Telemetry)
	}
	if metrics.Telemetry.NetworkInterfaces[0].Name != "eth0" || metrics.Telemetry.NetworkInterfaces[0].RXBytes != 300 ||
		metrics.Telemetry.NetworkInterfaces[0].TXBytes != 600 || metrics.Telemetry.NetworkInterfaces[1].Name != "eth1" ||
		metrics.Telemetry.TotalRXBytes != 450 || metrics.Telemetry.TotalTXBytes != 880 {
		t.Fatalf("network telemetry = %#v", metrics.Telemetry.NetworkInterfaces)
	}
	if metrics.Telemetry.SystemLoad.OneMinute != 1.25 || metrics.Telemetry.SystemLoad.RunningProcesses != 3 ||
		metrics.Telemetry.Disks[0].Path != "/" || metrics.Telemetry.Disks[0].SpacePercent != 75 {
		t.Fatalf("optional telemetry = %#v", metrics.Telemetry)
	}
}

func TestLinuxLoadCollectorResetsNetworkCounterRollback(t *testing.T) {
	reader := &loadFixtureReader{files: loadFixture(100, 850, 100, 200)}
	collector := newLinuxLoadCollector(reader.ReadFile)
	started := time.Date(2026, 8, 8, 1, 0, 0, 0, time.UTC)
	_, _ = collector.Collect(context.Background(), started)
	reader.files = loadFixture(120, 920, 99, 600)
	metrics, err := collector.Collect(context.Background(), started.Add(time.Second))
	if err != nil {
		t.Fatalf("network counter rollback error = %v", err)
	}
	if metrics.RXBandwidthBPS != 792 || metrics.TXBandwidthBPS != 3200 {
		t.Fatalf("network counter rollback rates = (%d, %d), want (792, 3200)",
			metrics.RXBandwidthBPS, metrics.TXBandwidthBPS)
	}
	if metrics.Telemetry == nil || len(metrics.Telemetry.NetworkInterfaces) != 1 ||
		metrics.Telemetry.NetworkInterfaces[0].RXBandwidthBPS != 792 {
		t.Fatalf("network counter rollback telemetry = %#v", metrics.Telemetry)
	}
}

func TestLinuxLoadCollectorIncludesNewInterfaceWithZeroInitialRate(t *testing.T) {
	reader := &loadFixtureReader{files: loadFixture(100, 850, 100, 200)}
	collector := newLinuxLoadCollector(reader.ReadFile)
	started := time.Date(2026, 8, 8, 1, 0, 0, 0, time.UTC)
	_, _ = collector.Collect(context.Background(), started)
	reader.files = loadFixtureWithInterfaces(130, 920, map[string][2]uint64{
		"eth0": {300, 600},
		"eth1": {50, 80},
	})
	metrics, err := collector.Collect(context.Background(), started.Add(2*time.Second))
	if err != nil {
		t.Fatalf("new interface error = %v", err)
	}
	if metrics.RXBandwidthBPS != 800 || metrics.TXBandwidthBPS != 1600 {
		t.Fatalf("new interface aggregate rates = (%d, %d), want (800, 1600)",
			metrics.RXBandwidthBPS, metrics.TXBandwidthBPS)
	}
	if metrics.Telemetry == nil || len(metrics.Telemetry.NetworkInterfaces) != 2 {
		t.Fatalf("new interface telemetry = %#v", metrics.Telemetry)
	}
	for _, network := range metrics.Telemetry.NetworkInterfaces {
		if network.Name == "eth1" &&
			(network.RXBytes != 50 || network.TXBytes != 80 ||
				network.RXBandwidthBPS != 0 || network.TXBandwidthBPS != 0) {
			t.Fatalf("new interface first sample = %#v", network)
		}
	}
}

func TestLinuxLoadCollectorRejectsCPUCounterRollbackAndRateOverflow(t *testing.T) {
	reader := &loadFixtureReader{files: loadFixture(100, 850, 100, 200)}
	collector := newLinuxLoadCollector(reader.ReadFile)
	started := time.Date(2026, 8, 8, 1, 0, 0, 0, time.UTC)
	_, _ = collector.Collect(context.Background(), started)
	reader.files = loadFixture(99, 850, 101, 201)
	if metrics, err := collector.Collect(context.Background(), started.Add(time.Second)); !errors.Is(err, ErrLoadMetricsCounter) || metrics != nil {
		t.Fatalf("CPU counter rollback = (%#v, %v)", metrics, err)
	}

	reader.files = loadFixture(100, 850, 0, 0)
	collector = newLinuxLoadCollector(reader.ReadFile)
	_, _ = collector.Collect(context.Background(), started)
	reader.files = loadFixture(101, 850, math.MaxUint64, math.MaxUint64)
	if metrics, err := collector.Collect(context.Background(), started.Add(time.Nanosecond)); !errors.Is(err, ErrLoadMetricsOverflow) || metrics != nil {
		t.Fatalf("rate overflow = (%#v, %v)", metrics, err)
	}
}

func loadFixture(user, idle, rx, tx uint64) map[string][]byte {
	return loadFixtureWithInterfaces(user, idle, map[string][2]uint64{"eth0": {rx, tx}})
}

func loadFixtureWithInterfaces(user, idle uint64, interfaces map[string][2]uint64) map[string][]byte {
	var network strings.Builder
	network.WriteString("Inter-| Receive | Transmit\n lo: 50 0 0 0 0 0 0 0 50 0 0 0 0 0 0 0\n")
	for name, counters := range interfaces {
		network.WriteString(" " + name + ": " + uintString(counters[0]) + " 0 0 0 0 0 0 0 " +
			uintString(counters[1]) + " 0 0 0 0 0 0 0\n")
	}
	return map[string][]byte{
		"/proc/stat":     []byte("cpu  " + uintString(user) + " 0 50 " + uintString(idle) + " 0 0 0 0 0 0\n"),
		"/proc/meminfo":  []byte("MemTotal:       1000 kB\nMemAvailable:    250 kB\n"),
		"/proc/net/dev":  []byte(network.String()),
		"/proc/net/tcp":  []byte("  sl  local_address rem_address st\n   0: 00000000:0050 00000000:0000 01\n   1: 00000000:0051 00000000:0000 0A\n"),
		"/proc/net/tcp6": []byte("  sl  local_address rem_address st\n   0: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 01\n"),
	}
}

func uintString(value uint64) string {
	if value == 0 {
		return "0"
	}
	var buffer [20]byte
	index := len(buffer)
	for value > 0 {
		index--
		buffer[index] = byte('0' + value%10)
		value /= 10
	}
	return string(buffer[index:])
}

// 硬盘排行只读挂载污染（fz-x1 复现属实）：只读 snap/LXD 镜像（ro、squashfs）不上报；同一设备的 bind
// 挂载（/etc、/etc/cdnca-edge-agent、单个 PEM 文件）只留挂载文件系统根的那一个；独立可写分区保留。
func TestParseMountPointsSkipsReadOnlyImagesAndBindDuplicates(t *testing.T) {
	mountinfo := strings.Join([]string{
		`22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw`,
		`23 22 8:2 / /var/lib/cdnca rw,relatime shared:2 - ext4 /dev/sda2 rw`,
		`24 22 7:0 / /snap/core20/2318 ro,nodev,relatime shared:3 - squashfs /dev/loop0 ro`,
		`25 22 7:1 / /snap/lxd/29351 ro,nodev,relatime shared:4 - squashfs /dev/loop1 ro`,
		`26 22 8:1 /etc /etc rw,relatime - ext4 /dev/sda1 rw`,
		`27 22 8:1 /etc/cdnca-edge-agent /etc/cdnca-edge-agent rw,relatime - ext4 /dev/sda1 rw`,
		`28 22 8:1 /srv/certs/site.pem /etc/ssl/site.pem rw,relatime - ext4 /dev/sda1 rw`,
		`29 22 0:40 / /mnt/ro\040data rw,relatime - nfs4 server:/data ro`,
		`30 22 0:41 / /proc rw,nosuid - proc proc rw`,
		`31 22 8:3 / /data/snapshots rw,relatime - xfs /dev/sdb1 rw`,
		`malformed`,
	}, "\n")
	got := parseMountPoints([]byte(mountinfo))
	want := []string{"/", "/data/snapshots", "/var/lib/cdnca"}
	if !slices.Equal(got, want) {
		t.Fatalf("mount points = %q, want %q", got, want)
	}
	// Only a bind of the device: the shortest mount point stands for it.
	if got := parseMountPoints([]byte("40 1 8:5 /a/b /z/long rw - ext4 /dev/sdc rw\n41 1 8:5 /a /z rw - ext4 /dev/sdc rw\n")); !slices.Equal(got, []string{"/z"}) {
		t.Fatalf("bind-only device = %q", got)
	}
}

// fz-x11：每个挂载都上报设备号、文件系统类型、只读、bind 与被硬盘排行过滤的原因。
func TestParseMountsListsEveryMountWithFilterReason(t *testing.T) {
	mountinfo := strings.Join([]string{
		`22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw`,
		`24 22 7:0 / /snap/core20/2318 ro,nodev,relatime shared:3 - squashfs /dev/loop0 ro`,
		`26 22 8:1 /etc /etc rw,relatime - ext4 /dev/sda1 rw`,
		`29 22 0:40 / /mnt/ro\040data rw,relatime - nfs4 server:/data ro`,
		`30 22 0:41 / /proc rw,nosuid - proc proc rw`,
		`31 22 8:3 / /data rw,relatime - xfs /dev/sdb1 rw`,
		`32 22 8:3 / /data2 rw,relatime - xfs /dev/sdb1 rw`,
		`33 22 bad / /bad rw - ext4 /dev/x rw`,
	}, "\n")
	want := []MountMetrics{
		{Path: "/", Device: "8:1", FSType: "ext4"},
		{Path: "/data", Device: "8:3", FSType: "xfs"},
		{Path: "/data2", Device: "8:3", FSType: "xfs", Bind: true, FilterReason: "bind_duplicate"},
		{Path: "/etc", Device: "8:1", FSType: "ext4", Bind: true, FilterReason: "bind_duplicate"},
		{Path: "/mnt/ro data", Device: "0:40", FSType: "nfs4", ReadOnly: true, FilterReason: "read_only"},
		{Path: "/proc", Device: "0:41", FSType: "proc", FilterReason: "system_path"},
		{Path: "/snap/core20/2318", Device: "7:0", FSType: "squashfs", ReadOnly: true, FilterReason: "squashfs"},
	}
	got := parseMounts([]byte(mountinfo))
	if !slices.Equal(got, want) {
		t.Fatalf("mounts = %+v\nwant %+v", got, want)
	}
	if !validMounts(got) {
		t.Fatal("parsed mounts must be valid telemetry")
	}
	if validMounts([]MountMetrics{{Path: "/", Device: "8:1", FilterReason: "other"}}) ||
		validMounts([]MountMetrics{{Path: "/b", Device: "8:1"}, {Path: "/a", Device: "8:1"}}) {
		t.Fatal("unknown reason / unsorted mounts must be refused")
	}
}

func TestDiskUsageMarksStatFailedMounts(t *testing.T) {
	collector := newLinuxLoadCollector(func(path string) ([]byte, error) {
		return []byte("22 1 8:1 / / rw - ext4 /dev/sda1 rw\n23 22 8:2 / /gone rw - ext4 /dev/sda2 rw\n"), nil
	})
	collector.statfs = func(path string, stat *unix.Statfs_t) error {
		if path == "/gone" {
			return unix.ENOENT
		}
		stat.Bsize, stat.Blocks, stat.Bavail, stat.Files, stat.Ffree = 4096, 100, 50, 10, 5
		return nil
	}
	disks, mounts := collector.diskUsage()
	if len(disks) != 1 || disks[0].Path != "/" || len(mounts) != 2 || mounts[1].FilterReason != "stat_failed" {
		t.Fatalf("disks=%+v mounts=%+v", disks, mounts)
	}
}

func TestValidPortGroupOverrides(t *testing.T) {
	if !validPortGroupOverrides([]PortGroupOverrideMetrics{{PortGroupID: "a", State: "applied"}, {PortGroupID: "b", State: "inactive", Reason: "manual"}}) {
		t.Fatal("valid overrides refused")
	}
	for _, bad := range [][]PortGroupOverrideMetrics{
		{{PortGroupID: "a", State: "inactive"}},
		{{PortGroupID: "a", State: "applied", Reason: "manual"}},
		{{PortGroupID: "a", State: "unknown"}},
		{{PortGroupID: "b", State: "applied"}, {PortGroupID: "a", State: "applied"}},
	} {
		if validPortGroupOverrides(bad) {
			t.Fatalf("invalid overrides accepted: %+v", bad)
		}
	}
}
