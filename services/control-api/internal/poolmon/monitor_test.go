package poolmon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/dbpoolmon"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
)

type fakeNotifier struct {
	calls   []string
	failOne bool // the next write fails once
}

func (f *fakeNotifier) write(call string) error {
	if f.failOne {
		f.failOne = false
		return errors.New("database down")
	}
	f.calls = append(f.calls, call)
	return nil
}

func (f *fakeNotifier) Saturated(_ context.Context, instance string, since time.Time, s Sample) error {
	return f.write(fmt.Sprintf("saturated %s %s in_use=%d", instance, since.Format("15:04:05"), s.InUse))
}

func (f *fakeNotifier) Recovered(_ context.Context, instance string, since time.Time, cause string, _ time.Time) error {
	return f.write(fmt.Sprintf("recovered %s %s %s", instance, since.Format("15:04:05"), cause))
}

func (f *fakeNotifier) CloseStale(_ context.Context, instance string, _ time.Time) error {
	return f.write("close_stale " + instance)
}

// rig drives a monitor with a hand-set pool Stat and a 10-second clock.
type rig struct {
	t        *testing.T
	stat     dbpoolmon.Stat
	held     []database.Resident
	notifier *fakeNotifier
	logs     *bytes.Buffer
	m        *Monitor
	now      time.Time
}

func newRig(t *testing.T) *rig {
	r := &rig{t: t, stat: dbpoolmon.Stat{MaxConns: 20, TotalConns: 8, AcquiredConns: 4, IdleConns: 4}, notifier: &fakeNotifier{},
		logs: &bytes.Buffer{}, now: time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC),
		held: []database.Resident{{Name: "artifact", InPool: true}, {Name: "market", InPool: true}, {Name: "wake", InPool: false}}}
	logger := slog.New(slog.NewTextHandler(r.logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
	r.m = New("ctl-a", func() dbpoolmon.Stat { return r.stat }, func() []database.Resident { return r.held }, r.notifier, logger)
	r.m.Prime()
	return r
}

func (r *rig) tick(inUse int32, acquires int64, wait time.Duration, queued, canceled int64) Sample {
	r.t.Helper()
	r.stat.AcquiredConns, r.stat.IdleConns = inUse, max(r.stat.TotalConns-inUse, 0)
	r.stat.AcquireCount += acquires
	r.stat.AcquireDuration += wait
	r.stat.EmptyAcquireCount += queued
	r.stat.CanceledAcquireCount += canceled
	r.now = r.now.Add(dbpoolmon.SampleInterval)
	r.m.Tick(context.Background(), r.now)
	return *r.m.Snapshot().Current
}

func (r *rig) quiet() Sample { return r.tick(4, 10, 10*time.Millisecond, 0, 0) }
func (r *rig) full() Sample  { return r.tick(19, 10, 10*time.Millisecond, 2, 0) }

func (r *rig) wantCalls(want ...string) {
	r.t.Helper()
	if !slices.Equal(r.notifier.calls, want) {
		r.t.Fatalf("notifier calls = %q, want %q", r.notifier.calls, want)
	}
}

func (r *rig) episode() {
	for range dbpoolmon.EnterCycles {
		r.full()
	}
	for range dbpoolmon.RecoverCycles {
		r.quiet()
	}
}

func TestSampleCountsResidentConnections(t *testing.T) {
	r := newRig(t)
	s := r.tick(6, 40, 200*time.Millisecond, 3, 0)
	if s.ResidentConns != 2 || s.RequestCapacity != 18 || s.InUse != 6 || s.MaxConns != 20 || s.Acquires != 40 ||
		s.Queued != 3 || s.AvgWaitMS != 5 || len(s.Reasons) != 0 {
		t.Fatalf("sample = %+v", s)
	}
	snap := r.m.Snapshot()
	if len(snap.Residents) != 3 || snap.Residents[2].Name != "wake" || snap.Residents[2].InPool {
		t.Fatalf("residents = %+v", snap.Residents)
	}
}

func TestEntersAfterThreeBadCyclesAndRecoversAfterThreeClean(t *testing.T) {
	r := newRig(t)
	r.full()
	r.full()
	if r.m.Snapshot().Firing || len(r.notifier.calls) != 0 {
		t.Fatal("two bad cycles must not alert")
	}
	r.full()
	snap := r.m.Snapshot()
	if !snap.Firing || !snap.Notified || snap.FiringSince == nil || !snap.FiringSince.Equal(r.now) ||
		snap.LastNotifiedAt == nil || !slices.Equal(snap.FiringReasons, []string{dbpoolmon.ReasonSaturated}) {
		t.Fatalf("third bad cycle: %+v", snap)
	}
	r.wantCalls("saturated ctl-a 12:00:30 in_use=19")
	logs := r.logs.String()
	for _, field := range []string{"level=WARN", "instance=ctl-a", "max_conns=20", "in_use=19", "resident_conns=2",
		"request_capacity=18", "queued=2", "reasons=[saturated]", "dedup=false"} {
		if !strings.Contains(logs, field) {
			t.Errorf("WARN line lacks %s: %s", field, logs)
		}
	}
	r.quiet()
	r.quiet()
	if !r.m.Snapshot().Firing {
		t.Fatal("two clean cycles must not recover")
	}
	r.quiet()
	if snap := r.m.Snapshot(); snap.Firing || snap.Notified || snap.FiringSince != nil {
		t.Fatalf("third clean cycle must recover: %+v", snap)
	}
	r.wantCalls("saturated ctl-a 12:00:30 in_use=19", "recovered ctl-a 12:00:30 recovered")
}

func TestCanceledAcquireUnderPressureEntersAtOnce(t *testing.T) {
	r := newRig(t)
	r.tick(19, 3, 0, 2, 1)
	if !r.m.Snapshot().Firing {
		t.Fatal("a request that gave up waiting must alert in the same cycle")
	}
	r.wantCalls("saturated ctl-a 12:00:10 in_use=19")
}

func TestReentryWithinFifteenMinutesIsNotNotifiedAgain(t *testing.T) {
	r := newRig(t)
	r.episode() // sent at 12:00:30, recovered at 12:01:00
	r.episode() // enters 12:01:30: folded, no saturation, no recovery
	r.wantCalls("saturated ctl-a 12:00:30 in_use=19", "recovered ctl-a 12:00:30 recovered")
	if n := strings.Count(r.logs.String(), "dedup=true"); n != 1 {
		t.Fatalf("a folded entry still logs its WARN line, got %d", n)
	}
	// 16 minutes after the last notification: a new one, and its recovery.
	for range int((15 * time.Minute) / dbpoolmon.SampleInterval) {
		r.quiet()
	}
	r.episode()
	if len(r.notifier.calls) != 4 || !strings.HasPrefix(r.notifier.calls[2], "saturated") || !strings.HasPrefix(r.notifier.calls[3], "recovered") {
		t.Fatalf("after the window: %q", r.notifier.calls)
	}
}

func TestFoldedAlertStillFiringAfterTheWindowIsSent(t *testing.T) {
	r := newRig(t)
	r.episode() // sent at 12:00:30
	for range dbpoolmon.EnterCycles {
		r.full() // folded entry at 12:01:30
	}
	if snap := r.m.Snapshot(); !snap.Firing || snap.Notified {
		t.Fatalf("folded alert: %+v", snap)
	}
	// Still saturated: sent once the window from 12:00:30 has passed.
	for r.now.Before(time.Date(2026, 11, 5, 12, 15, 20, 0, time.UTC)) {
		r.full()
	}
	r.wantCalls("saturated ctl-a 12:00:30 in_use=19", "recovered ctl-a 12:00:30 recovered")
	r.full() // 12:15:30
	r.wantCalls("saturated ctl-a 12:00:30 in_use=19", "recovered ctl-a 12:00:30 recovered", "saturated ctl-a 12:01:30 in_use=19")
	if !r.m.Snapshot().Notified || !strings.Contains(r.logs.String(), "still saturated after the dedup window") {
		t.Fatal("late notification not recorded")
	}
	for range dbpoolmon.RecoverCycles {
		r.quiet()
	}
	r.wantCalls("saturated ctl-a 12:00:30 in_use=19", "recovered ctl-a 12:00:30 recovered", "saturated ctl-a 12:01:30 in_use=19",
		"recovered ctl-a 12:01:30 recovered")
}

func TestFailedWritesAreRetriedInOrder(t *testing.T) {
	r := newRig(t)
	r.notifier.failOne = true
	for range dbpoolmon.EnterCycles {
		r.full()
	}
	if len(r.notifier.calls) != 0 || r.m.Snapshot().PendingNotifications != 1 ||
		!strings.Contains(r.logs.String(), "notification not written; retrying next cycle") {
		t.Fatalf("failed write: %q", r.notifier.calls)
	}
	r.full()
	r.wantCalls("saturated ctl-a 12:00:30 in_use=19")
	if r.m.Snapshot().PendingNotifications != 0 {
		t.Fatal("retried write still pending")
	}
}

func TestPendingWritesAreBounded(t *testing.T) {
	r := newRig(t)
	for range maxPending + 10 {
		r.m.push(op{kind: opRecovered})
	}
	if len(r.m.pending) != maxPending {
		t.Fatalf("pending = %d", len(r.m.pending))
	}
}

func TestHistoryKeepsOneHourAndRunClosesStale(t *testing.T) {
	r := newRig(t)
	snap := r.m.Snapshot()
	if snap.Current != nil || snap.Series == nil || snap.Residents == nil || snap.FiringReasons == nil || snap.LastNotifiedAt != nil {
		t.Fatalf("empty snapshot = %+v", snap)
	}
	for range dbpoolmon.HistoryLen + 5 {
		r.quiet()
	}
	snap = r.m.Snapshot()
	if len(snap.Series) != dbpoolmon.HistoryLen || !snap.Series[len(snap.Series)-1].At.Equal(r.now) || snap.IntervalSeconds != 10 ||
		snap.Thresholds != dbpoolmon.CurrentThresholds() {
		t.Fatalf("series of %d, thresholds %+v", len(snap.Series), snap.Thresholds)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.m.Run(ctx); err != nil {
		t.Fatal(err)
	}
	r.wantCalls("close_stale ctl-a")
}

func TestSourceEventIDIsBoundedAndPathSafe(t *testing.T) {
	since := time.UnixMilli(1793000000123)
	if got := SourceEventID("ctl-a", since); got != "control-db-pool/v1/ctl-a/1793000000123" {
		t.Fatalf("source = %q", got)
	}
	long := strings.Repeat("h/", 200)
	got := SourceEventID(long, since)
	if len(got) > 256 || strings.Count(got, "/") != 3 {
		t.Fatalf("long instance source = %q (%d bytes)", got, len(got))
	}
}
