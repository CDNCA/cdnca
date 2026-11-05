package dbpoolmon

import (
	"slices"
	"testing"
	"time"
)

func TestMeasureDeltasAndReasons(t *testing.T) {
	prev := Stat{MaxConns: 20, TotalConns: 8, AcquiredConns: 6, IdleConns: 2}
	step := func(inUse int32, acquires int64, wait time.Duration, queued, canceled int64) Cycle {
		t.Helper()
		cur := prev
		cur.AcquiredConns, cur.IdleConns = inUse, max(cur.TotalConns-inUse, 0)
		cur.AcquireCount += acquires
		cur.AcquireDuration += wait
		cur.EmptyAcquireCount += queued
		cur.CanceledAcquireCount += canceled
		c := Measure(prev, cur)
		prev = cur
		return c
	}
	if c := step(6, 40, 200*time.Millisecond, 3, 0); c.Acquires != 40 || c.Queued != 3 || c.AvgWaitMS != 5 ||
		c.InUse != 6 || c.Idle != 2 || c.MaxConns != 20 || c.Reasons == nil || len(c.Reasons) != 0 {
		t.Fatalf("quiet cycle = %+v", c)
	}
	if c := step(19, 1, 0, 0, 0); !slices.Equal(c.Reasons, []string{ReasonSaturated}) {
		t.Fatalf("19 of 20 in use: %v", c.Reasons)
	}
	if c := step(18, 1, 0, 0, 0); len(c.Reasons) != 0 {
		t.Fatalf("18 of 20 in use is not saturated: %v", c.Reasons)
	}
	if c := step(6, 4, 404*time.Millisecond, 4, 0); !slices.Equal(c.Reasons, []string{ReasonSlow}) || c.AvgWaitMS != 101 {
		t.Fatalf("101 ms average: %+v", c)
	}
	if c := step(6, 4, 400*time.Millisecond, 4, 0); len(c.Reasons) != 0 {
		t.Fatalf("exactly 100 ms is not slow: %+v", c)
	}
	if c := step(6, 5, 0, 0, 2); len(c.Reasons) != 0 || c.Canceled != 2 {
		t.Fatalf("cancel without pressure: %+v", c)
	}
	if c := step(6, 5, 0, 1, 1); !slices.Equal(c.Reasons, []string{ReasonCanceled}) {
		t.Fatalf("cancel while acquires queued: %v", c.Reasons)
	}
	if c := step(19, 0, 0, 0, 1); !slices.Equal(c.Reasons, []string{ReasonSaturated, ReasonCanceled}) || c.AvgWaitMS != 0 {
		t.Fatalf("cancel while full: %+v", c)
	}
	// A counter going backwards (pool reopened) is not a negative delta.
	if c := Measure(Stat{AcquireCount: 9, MaxConns: 20}, Stat{AcquireCount: 2, MaxConns: 20}); c.Acquires != 0 {
		t.Fatalf("backwards counter: %+v", c)
	}
}

func TestDetectorEntersAndRecovers(t *testing.T) {
	var d Detector
	at := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	observe := func(reasons ...string) Transition {
		at = at.Add(SampleInterval)
		return d.Observe(at, reasons)
	}
	full := []string{ReasonSaturated}
	if observe(full...) != Steady || observe(full...) != Steady || observe() != Steady {
		t.Fatal("two bad cycles then a clean one must not enter")
	}
	observe(full...)
	observe(full...)
	if got := observe(full...); got != Enter {
		t.Fatalf("third consecutive bad cycle = %v", got)
	}
	if firing, since, reasons := d.Firing(); !firing || !since.Equal(at) || !slices.Equal(reasons, full) {
		t.Fatalf("firing = %v %v %v", firing, since, reasons)
	}
	if observe(ReasonSlow) != Steady {
		t.Fatal("bad while firing changes nothing")
	}
	if _, _, reasons := d.Firing(); !slices.Equal(reasons, []string{ReasonSaturated, ReasonSlow}) {
		t.Fatalf("reasons while firing = %v", reasons)
	}
	if observe() != Steady || observe() != Steady {
		t.Fatal("two clean cycles must not recover")
	}
	if got := observe(); got != Recover {
		t.Fatalf("third clean cycle = %v", got)
	}
	if firing, _, reasons := d.Firing(); firing || reasons == nil || len(reasons) != 0 {
		t.Fatalf("after recovery: %v %v", firing, reasons)
	}
	var cancel Detector
	if cancel.Observe(at, []string{ReasonSaturated, ReasonCanceled}) != Enter {
		t.Fatal("a cancelled acquire under pressure enters at once")
	}
}

func TestAppendKeepsOneHour(t *testing.T) {
	var history []int
	for i := range HistoryLen + 5 {
		history = Append(history, i)
	}
	if HistoryLen != 360 || len(history) != HistoryLen || history[0] != 5 || history[HistoryLen-1] != HistoryLen+4 {
		t.Fatalf("history of %d from %d", len(history), history[0])
	}
	if CurrentThresholds() != (Thresholds{EnterCycles: 3, RecoverCycles: 3, SaturationMargin: 1, SlowAcquireMS: 100, DedupMinutes: 15}) {
		t.Fatalf("thresholds = %+v", CurrentThresholds())
	}
}
