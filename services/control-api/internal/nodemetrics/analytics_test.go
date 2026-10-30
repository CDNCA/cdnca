package nodemetrics

import (
	"testing"
	"time"
)

func TestRealtimeViewSkipsMissingOptionalMetrics(t *testing.T) {
	first := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	tx := uint64(200)
	view := realtimeViewFromHistory([]HistoryView{
		{ObservedAt: first, Known: true, TXBandwidthBPS: &tx},
		{ObservedAt: first.Add(time.Minute), Known: false},
		{ObservedAt: first.Add(2 * time.Minute), Known: true, Telemetry: &Telemetry{
			NetworkInterfaces: []NetworkInterface{{Name: "eth0", RXBandwidthBPS: 400, TXBandwidthBPS: 800}},
		}},
	}, "bandwidth")

	all := view.Data["all"]
	if len(all) != 1 || all[0].Name != "outbound" || len(all[0].Points) != 1 || all[0].Points[0].Value != 200 {
		t.Fatalf("aggregate series = %#v", all)
	}
	eth0 := view.Data["eth0"]
	if len(eth0) != 2 || eth0[0].Name != "inbound" || eth0[1].Name != "outbound" {
		t.Fatalf("interface series = %#v", eth0)
	}
	if _, exists := view.Data["all"]; !exists {
		t.Fatal("missing optional values removed the aggregate series key")
	}
}

func TestRealtimeViewDoesNotCreateZeroSeriesForMissingLoad(t *testing.T) {
	view := realtimeViewFromHistory([]HistoryView{{Known: true}}, "load")
	if len(view.Data) != 0 {
		t.Fatalf("missing load created a zero series: %#v", view.Data)
	}
}

func TestRealtimeViewProjectsLoadAndDiskTelemetrySeries(t *testing.T) {
	used, total, cpu := uint64(512), uint64(1024), 25.0
	view := realtimeViewFromHistory([]HistoryView{{
		Known:            true,
		CPUPercent:       &cpu,
		MemoryUsedBytes:  &used,
		MemoryTotalBytes: &total,
		Telemetry: &Telemetry{
			SystemLoad: &SystemLoad{OneMinute: 1.25},
			Disks:      []DiskUsage{{Path: "/", SpacePercent: 50, InodePercent: 25}},
		},
	}}, "load")
	all := view.Data["all"]
	if len(all) != 3 || all[0].Name != "cpu" || all[1].Name != "system_load" || all[2].Name != "memory" {
		t.Fatalf("load series = %#v", all)
	}
	if all[0].Points[0].Value != 25 || all[1].Points[0].Value != 1.25 || all[2].Points[0].Value != 50 {
		t.Fatalf("load values = %#v", all)
	}

	diskView := realtimeViewFromHistory([]HistoryView{{
		Known:     true,
		Telemetry: &Telemetry{Disks: []DiskUsage{{Path: "/", SpacePercent: 50, InodePercent: 25}}},
	}}, "disk")
	root := diskView.Data["/"]
	if len(root) != 2 || root[0].Name != "space" || root[1].Name != "inode" || root[0].Points[0].Value != 50 || root[1].Points[0].Value != 25 {
		t.Fatalf("disk series = %#v", root)
	}
}

func TestTrafficIntervalsRequireTwoCounterSnapshotsAndHandleReset(t *testing.T) {
	first := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	if got := trafficIntervals([]TrafficPoint{{ObservedAt: first, BytesReceived: 10, BytesSent: 20}}); len(got) != 0 {
		t.Fatalf("single snapshot returned fabricated interval: %#v", got)
	}
	got := trafficIntervals([]TrafficPoint{
		{ObservedAt: first, BytesReceived: 100, BytesSent: 200},
		{ObservedAt: first.Add(time.Minute), BytesReceived: 150, BytesSent: 260},
		{ObservedAt: first.Add(2 * time.Minute), BytesReceived: 8, BytesSent: 12},
	})
	if len(got) != 3 || got[0].BytesReceived != 0 || got[0].BytesSent != 0 ||
		got[1].BytesReceived != 50 || got[1].BytesSent != 60 ||
		got[2].BytesReceived != 8 || got[2].BytesSent != 12 {
		t.Fatalf("counter intervals = %#v", got)
	}
}

func TestRealtimeViewWithoutSamplesIsEmptyNotMissing(t *testing.T) {
	for _, metric := range []string{"bandwidth", "connections", "load", "disk"} {
		view := realtimeViewFromHistory(nil, metric)
		if view.Data == nil || len(view.Data) != 0 {
			t.Fatalf("%s empty history = %#v", metric, view.Data)
		}
	}
}
