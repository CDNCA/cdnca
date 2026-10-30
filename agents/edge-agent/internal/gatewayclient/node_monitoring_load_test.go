package gatewayclient

import (
	"bytes"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/nodemonitoring"
)

func TestNodeMonitoringBridgePersistsTypedLoadMetricsOutsideStrictProbeJSON(t *testing.T) {
	nodeID := "01990000-0000-7000-8000-000000000007"
	bridge, err := NewNodeMonitoringBridge(t.TempDir(), nodeID)
	if err != nil {
		t.Fatalf("NewNodeMonitoringBridge() error = %v", err)
	}
	observed := time.Date(2026, 8, 8, 3, 0, 0, 0, time.UTC)
	report := nodemonitoring.MetricReport{
		SchemaVersion: 1, ObservedAt: observed, NodeID: nodeID, ConfigRevision: 7,
		ActiveConfigRevision: 7, ProbePort: 80, Healthy: true, ProbeSucceeded: true,
		LoadMetrics: &nodemonitoring.LoadMetrics{
			ObservedAt: observed, CPUPercent: 25, MemoryUsedBytes: 512, MemoryTotalBytes: 1024,
			ActiveConnections: 9, RXBandwidthBPS: 1600, TXBandwidthBPS: 800,
			Telemetry: &nodemonitoring.TelemetryMetrics{
				SchemaVersion: 1, TotalRXBytes: 300, TotalTXBytes: 600,
				NetworkSelection: &nodemonitoring.NetworkSelection{Source: "default_route", Interfaces: []string{"eth0"}},
				NetworkInterfaces: []nodemonitoring.NetworkInterfaceMetrics{{
					Name: "eth0", RXBytes: 300, TXBytes: 600, RXBandwidthBPS: 1200, TXBandwidthBPS: 2400,
				}},
				SystemLoad: &nodemonitoring.SystemLoadMetrics{OneMinute: 1.25, FiveMinutes: 0.75,
					FifteenMinutes: 0.5, RunningProcesses: 3, TotalProcesses: 40},
				Disks: []nodemonitoring.DiskUsageMetrics{{Path: "/", TotalBytes: 409600, UsedBytes: 307200,
					TotalInodes: 1000, UsedInodes: 750, SpacePercent: 75, InodePercent: 75}},
				DDoSDrops: []nodemonitoring.DDoSDropMetrics{{Kind: "ct_invalid", Packets: 4, Bytes: 160}, {Kind: "tcp_xmas", Packets: 2, Bytes: 80}},
				XDP: &nodemonitoring.XDPStatusMetrics{Mode: "generic", Interfaces: []string{"eth0=generic"},
					Drops: []nodemonitoring.DDoSDropMetrics{{Kind: "xdp_block", Packets: 7, Bytes: 420}}},
				DDoSProtection: &nodemonitoring.DDoSProtectionMetrics{State: "unavailable", Reason: "nft_missing", Detail: "nft command not found"},
				Mounts: []nodemonitoring.MountMetrics{{Path: "/", Device: "8:1", FSType: "ext4"},
					{Path: "/snap/core", Device: "7:0", FSType: "squashfs", ReadOnly: true, FilterReason: "squashfs"}},
				PortGroupOverrides: []nodemonitoring.PortGroupOverrideMetrics{{PortGroupID: "web-tcp", State: "inactive", Reason: "manual"}},
			},
		},
	}
	if err := bridge.ReportNodeMonitoring(t.Context(), report); err != nil {
		t.Fatalf("ReportNodeMonitoring() error = %v", err)
	}
	pending := bridge.Pending()
	if len(pending) != 1 || pending[0].LoadMetricsV1 == nil || pending[0].LoadMetricsV1.CpuPercent != 25 ||
		pending[0].LoadMetricsV1.ObservedTime.AsTime() != observed ||
		pending[0].LoadMetricsV1.Telemetry == nil || len(pending[0].LoadMetricsV1.Telemetry.NetworkInterfaces) != 1 ||
		pending[0].LoadMetricsV1.Telemetry.NetworkInterfaces[0].Name != "eth0" ||
		pending[0].LoadMetricsV1.Telemetry.NetworkSelection.GetSource() != "default_route" ||
		len(pending[0].LoadMetricsV1.Telemetry.NetworkSelection.GetInterfaces()) != 1 ||
		pending[0].LoadMetricsV1.Telemetry.SystemLoad == nil || len(pending[0].LoadMetricsV1.Telemetry.Disks) != 1 ||
		len(pending[0].LoadMetricsV1.Telemetry.DdosDrops) != 2 || pending[0].LoadMetricsV1.Telemetry.DdosDrops[1].Kind != "tcp_xmas" ||
		pending[0].LoadMetricsV1.Telemetry.DdosDrops[1].Packets != 2 ||
		pending[0].LoadMetricsV1.Telemetry.GetXdp().GetMode() != "generic" ||
		pending[0].LoadMetricsV1.Telemetry.GetXdp().GetInterfaces()[0] != "eth0=generic" ||
		pending[0].LoadMetricsV1.Telemetry.GetXdp().GetDrops()[0].GetPackets() != 7 ||
		pending[0].LoadMetricsV1.Telemetry.GetDdosProtection().GetState() != "unavailable" ||
		pending[0].LoadMetricsV1.Telemetry.GetDdosProtection().GetReason() != "nft_missing" ||
		len(pending[0].LoadMetricsV1.Telemetry.GetMounts()) != 2 ||
		pending[0].LoadMetricsV1.Telemetry.GetMounts()[1].GetFilterReason() != "squashfs" ||
		!pending[0].LoadMetricsV1.Telemetry.GetMounts()[1].GetReadOnly() || pending[0].LoadMetricsV1.Telemetry.GetMounts()[0].GetDevice() != "8:1" ||
		pending[0].LoadMetricsV1.Telemetry.GetPortGroupOverrides()[0].GetReason() != "manual" ||
		bytes.Contains(pending[0].PayloadJson, []byte("cpu_percent")) {
		t.Fatalf("pending report = %#v payload=%s", pending, pending[0].GetPayloadJson())
	}
}
