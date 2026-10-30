package nodemetrics

import (
	"testing"
	"time"
)

func monthlyPoints(start time.Time, step time.Duration, counters ...[2]uint64) []monthlyTrafficPoint {
	points := make([]monthlyTrafficPoint, len(counters))
	for index, counter := range counters {
		points[index] = monthlyTrafficPoint{observedAt: start.Add(time.Duration(index) * step), rxBytes: counter[0], txBytes: counter[1]}
	}
	return points
}

// The 10-23 reinstall on 73: both nodes rebooted at 20:02 UTC and their
// default-route counters went 1.35 GB -> 30 KB. The month must keep counting
// (the traffic before the reboot plus the reading after it), not stop there.
func TestMonthlyTrafficCountsAcrossNodeReboot(t *testing.T) {
	start := time.Date(2026, 10, 23, 20, 0, 0, 0, time.UTC)
	points := monthlyPoints(start, 30*time.Second,
		[2]uint64{1_000_000_000, 30_000_000},
		[2]uint64{1_351_876_543, 34_717_605},
		[2]uint64{30_188, 7_126}, // rebooted
		[2]uint64{1_030_188, 107_126},
	)
	now := points[len(points)-1].observedAt.Add(10 * time.Second)
	got, err := summarizeMonthlyTraffic(MonthlyTraffic{}, points, now)
	if err != nil {
		t.Fatal(err)
	}
	want := uint64(351_876_543+4_717_605) + uint64(30_188+7_126) + uint64(1_000_000+100_000)
	if got.State != "available" || got.UsageBytes != want || got.CounterResets != 1 || got.Samples != 4 {
		t.Fatalf("summary = %+v, want available usage %d with 1 reset", got, want)
	}
}

// Only the counter that went down restarts; the other keeps its increment.
func TestMonthlyTrafficResetsEachCounterSeparately(t *testing.T) {
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	points := monthlyPoints(start, time.Minute, [2]uint64{500, 100}, [2]uint64{20, 160})
	got, err := summarizeMonthlyTraffic(MonthlyTraffic{}, points, points[1].observedAt)
	if err != nil {
		t.Fatal(err)
	}
	if got.UsageBytes != 20+60 || got.CounterResets != 1 || got.State != "available" {
		t.Fatalf("summary = %+v", got)
	}
}

func TestMonthlyTrafficKeepsGapAndStaleStates(t *testing.T) {
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	gap := monthlyPoints(start, 6*time.Minute, [2]uint64{0, 0}, [2]uint64{10, 10})
	if got, err := summarizeMonthlyTraffic(MonthlyTraffic{}, gap, gap[1].observedAt); err != nil || got.State != "incomplete" || got.UsageBytes != 20 {
		t.Fatalf("gap summary = %+v err=%v", got, err)
	}
	fresh := monthlyPoints(start, time.Minute, [2]uint64{0, 0}, [2]uint64{10, 10})
	if got, err := summarizeMonthlyTraffic(MonthlyTraffic{}, fresh, fresh[1].observedAt.Add(3*time.Minute)); err != nil || got.State != "stale" || got.CounterResets != 0 {
		t.Fatalf("stale summary = %+v err=%v", got, err)
	}
}
