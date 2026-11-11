package eventspool

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/metrics"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// A backlog of unacknowledged events must not be held in memory.
// 78 kept ~747k records (~1.17 KB each) and the agent reached 10.7 GiB RSS
// within 3 minutes because every record, its payload and its decoded envelope
// were cached and copied on every rebuild.

const memoryTestNow = 1_700_000_000

func memoryTestConfig(root string) Config {
	now := time.Unix(memoryTestNow, 0).UTC().Add(time.Hour)
	return Config{
		Root: root, MaxEventBytes: 64 << 10, MaxSegmentBytes: 16 << 20,
		SoftLimitBytes: 4 << 30, HardLimitBytes: 8 << 30, MaxTenantBytes: 4 << 30,
		MaxBatchEvents: 10000, PressureMode: PressureBackpressure,
		SoftAgeLimit: 24 * time.Hour, HardAgeLimit: 7 * 24 * time.Hour,
		Now: func() time.Time { return now },
	}
}

// memoryTestEvent is about the size of the access events in 78's backlog.
func memoryTestEvent(index int) Envelope {
	event := pendingAccess(fmt.Sprintf("evt-%012d", index), tenantOne)
	event.OccurredAt = time.Unix(memoryTestNow, 0).UTC().Add(time.Duration(index) * time.Millisecond)
	event.RequestID = fmt.Sprintf("req-%016x", index)
	event.TraceID = fmt.Sprintf("trace-%032x", index)
	event.Path = fmt.Sprintf("/static/assets/bundle-%d.js?v=%d&%s", index%997, index, strings.Repeat("q", 600))
	event.RequestHeaders = map[string]string{"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"}
	return event
}

func writeMemoryBacklog(t testing.TB, root string, events int) {
	t.Helper()
	spool, err := New(memoryTestConfig(root))
	if err != nil {
		t.Fatal(err)
	}
	const batch = 2000
	envelopes := make([]Envelope, 0, batch)
	for index := 0; index < events; {
		envelopes = envelopes[:0]
		for len(envelopes) < batch && index < events {
			envelopes = append(envelopes, memoryTestEvent(index))
			index++
		}
		if _, err := spool.AppendBatch(context.Background(), envelopes); err != nil {
			t.Fatal(err)
		}
	}
}

// heapPeak samples live heap objects while fn runs and returns the peak and
// the heap retained afterwards (after a GC), both relative to the heap before.
func heapPeak(fn func()) (peak, retained uint64) {
	runtime.GC()
	sample := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	read := func() uint64 { metrics.Read(sample); return sample[0].Value.Uint64() }
	base := read()
	var maximum atomic.Uint64
	maximum.Store(base)
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(2 * time.Millisecond)
		defer ticker.Stop()
		for {
			if value := read(); value > maximum.Load() {
				maximum.Store(value)
			}
			select {
			case <-done:
				return
			case <-ticker.C:
			}
		}
	}()
	fn()
	close(done)
	<-stopped
	if value := read(); value > maximum.Load() {
		maximum.Store(value)
	}
	runtime.GC()
	after := read()
	if after > base {
		retained = after - base
	}
	return maximum.Load() - base, retained
}

type ackAllPublisher struct{}

func (ackAllPublisher) Publish(_ context.Context, publications []Publication) (PublishAck, error) {
	return PublishAck{Acknowledged: len(publications)}, nil
}

type spoolMemoryResult struct {
	events                      int
	newPeak, newRetained        uint64
	flushPeak, flushRetained    uint64
	newElapsed, flushElapsed    time.Duration
	flushedEvents, flushBatches int
}

func measureSpoolMemory(t testing.TB, events, flushes int) spoolMemoryResult {
	t.Helper()
	root := filepath.Join(t.TempDir(), "spool")
	if resolved, err := filepath.EvalSymlinks(filepath.Dir(root)); err == nil {
		root = filepath.Join(resolved, "spool")
	}
	writeMemoryBacklog(t, root, events)
	result := spoolMemoryResult{events: events}
	var spool *Spool
	started := time.Now()
	result.newPeak, result.newRetained = heapPeak(func() {
		var err error
		if spool, err = New(memoryTestConfig(root)); err != nil {
			t.Fatal(err)
		}
	})
	result.newElapsed = time.Since(started)
	started = time.Now()
	result.flushPeak, result.flushRetained = heapPeak(func() {
		for index := 0; index < flushes; index++ {
			published, err := spool.Flush(context.Background(), ackAllPublisher{}, 1000)
			if err != nil {
				t.Fatal(err)
			}
			result.flushedEvents += published.Published
			result.flushBatches++
		}
	})
	result.flushElapsed = time.Since(started)
	stats, err := spool.Stats()
	if err != nil || stats.PendingEvents != events-result.flushedEvents {
		t.Fatalf("stats pending=%d want=%d err=%v", stats.PendingEvents, events-result.flushedEvents, err)
	}
	runtime.KeepAlive(spool)
	return result
}

// The index kept for a backlog must stay small per record: the full record
// cache (payload + decoded envelope + pending copy) was ~5 KB per record.
func TestSpoolBacklogMemoryIsIndexOnly(t *testing.T) {
	const events = 20000
	result := measureSpoolMemory(t, events, 3)
	perRecord := float64(result.newRetained) / events
	t.Logf("events=%d new_peak=%dKiB new_retained=%dKiB (%.0f B/record) flush_peak=%dKiB",
		events, result.newPeak>>10, result.newRetained>>10, perRecord, result.flushPeak>>10)
	if perRecord > 512 {
		t.Fatalf("spool retains %.0f bytes per pending record, want <= 512", perRecord)
	}
	// One Flush batch (1000 records) is decoded at a time; replay must not
	// copy the whole backlog.
	if result.flushPeak > result.newRetained+32<<20 {
		t.Fatalf("flush peak %d KiB over retained index %d KiB", result.flushPeak>>10, result.newRetained>>10)
	}
}

type failingPublisher struct{}

func (failingPublisher) Publish(context.Context, []Publication) (PublishAck, error) {
	return PublishAck{}, fmt.Errorf("control plane unreachable")
}

func readProcStatusKiB(field string) int64 {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(string(data), "\n") {
		if value, ok := strings.CutPrefix(line, field+":"); ok {
			kib, _ := strconv.ParseInt(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(value), "kB")), 10, 64)
			return kib
		}
	}
	return -1
}

// TestSpoolBacklogRSSCurve replays 78's situation (Linux only, opt-in): the
// agent starts on a large backlog while the control plane is unreachable,
// keeps tailing for a while, then reconnects and drains part of it. VmRSS is
// sampled every 200 ms into CDNCA_SPOOL_RSS_OUT (CSV: ms,phase,rss_kib).
// CDNCA_SPOOL_RSS_ROOT names the spool (built once with CDNCA_SPOOL_RSS_BUILD
// events in a separate run, so building does not count).
func TestSpoolBacklogRSSCurve(t *testing.T) {
	root := os.Getenv("CDNCA_SPOOL_RSS_ROOT")
	if root == "" || readProcStatusKiB("VmRSS") < 0 {
		t.Skip("set CDNCA_SPOOL_RSS_ROOT on Linux to record the backlog RSS curve")
	}
	if build, _ := strconv.Atoi(os.Getenv("CDNCA_SPOOL_RSS_BUILD")); build > 0 {
		writeMemoryBacklog(t, root, build)
		return
	}
	output, err := os.Create(os.Getenv("CDNCA_SPOOL_RSS_OUT"))
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	started := time.Now()
	var phase atomic.Value
	phase.Store("start")
	done := make(chan struct{})
	sampled := make(chan struct{})
	go func() {
		defer close(sampled)
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			fmt.Fprintf(output, "%d,%s,%d\n", time.Since(started).Milliseconds(), phase.Load(), readProcStatusKiB("VmRSS"))
			select {
			case <-done:
				return
			case <-ticker.C:
			}
		}
	}()
	spool, err := New(memoryTestConfig(root))
	if err != nil {
		t.Fatal(err)
	}
	stats, err := spool.Stats()
	if err != nil {
		t.Fatal(err)
	}
	newElapsed := time.Since(started)
	phase.Store("offline")
	next := 3_000_000 // event IDs past the backlog; OccurredAt stays under Now (+1 h)
	for second := 0; second < 30; second++ {
		envelopes := make([]Envelope, 200)
		for index := range envelopes {
			envelopes[index] = memoryTestEvent(next)
			next++
		}
		if _, err := spool.AppendBatch(context.Background(), envelopes); err != nil {
			t.Fatal(err)
		}
		_, _ = spool.Flush(context.Background(), failingPublisher{}, 1000)
		if _, err := spool.Stats(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Second)
	}
	phase.Store("drain")
	drainStarted := time.Now()
	flushes, _ := strconv.Atoi(os.Getenv("CDNCA_SPOOL_RSS_FLUSHES"))
	drained := 0
	for index := 0; flushes <= 0 || index < flushes; index++ {
		result, err := spool.Flush(context.Background(), ackAllPublisher{}, 1000)
		if err != nil {
			t.Fatal(err)
		}
		if result.Published == 0 {
			break
		}
		drained += result.Published
	}
	drainElapsed := time.Since(drainStarted)
	close(done)
	<-sampled
	t.Logf("PERF rsscurve pending_at_start=%d new_elapsed=%s drained=%d drain_elapsed=%s vmhwm_mib=%.1f vmrss_end_mib=%.1f",
		stats.PendingEvents, newElapsed.Round(time.Millisecond), drained, drainElapsed.Round(time.Millisecond),
		float64(readProcStatusKiB("VmHWM"))/1024, float64(readProcStatusKiB("VmRSS"))/1024)
}

// TestSpoolSteadyStatePerf is the normal-operation load (opt-in): no backlog,
// the tailer appends CDNCA_SPOOL_STEADY_RATE events per second in 100 ms
// batches, the worker flushes and the realtime source reads Stats every
// second. It reports process CPU and peak RSS for the A/B on a node.
func TestSpoolSteadyStatePerf(t *testing.T) {
	seconds, _ := strconv.Atoi(os.Getenv("CDNCA_SPOOL_STEADY_SECONDS"))
	if seconds <= 0 {
		t.Skip("set CDNCA_SPOOL_STEADY_SECONDS to measure steady-state spool cost")
	}
	rate, _ := strconv.Atoi(os.Getenv("CDNCA_SPOOL_STEADY_RATE"))
	if rate <= 0 {
		rate = 500
	}
	root := filepath.Join(t.TempDir(), "spool")
	if resolved, err := filepath.EvalSymlinks(filepath.Dir(root)); err == nil {
		root = filepath.Join(resolved, "spool")
	}
	spool, err := New(memoryTestConfig(root))
	if err != nil {
		t.Fatal(err)
	}
	var before, after syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &before)
	started := time.Now()
	next := 0
	perTick := max(1, rate/10)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for tick := 0; tick < seconds*10; tick++ {
		<-ticker.C
		envelopes := make([]Envelope, perTick)
		for index := range envelopes {
			envelopes[index] = memoryTestEvent(next)
			next++
		}
		if _, err := spool.AppendBatch(context.Background(), envelopes); err != nil {
			t.Fatal(err)
		}
		if tick%10 == 9 {
			for {
				result, err := spool.Flush(context.Background(), ackAllPublisher{}, 1000)
				if err != nil {
					t.Fatal(err)
				}
				if result.Published == 0 {
					break
				}
			}
			if _, err := spool.Stats(); err != nil {
				t.Fatal(err)
			}
		}
	}
	elapsed := time.Since(started)
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &after)
	cpu := time.Duration(after.Utime.Nano()-before.Utime.Nano()) + time.Duration(after.Stime.Nano()-before.Stime.Nano())
	t.Logf("PERF steady seconds=%d rate=%d events=%d elapsed=%s cpu_ms=%d cpu_pct=%.2f vmhwm_kib=%d",
		seconds, rate, next, elapsed.Round(time.Millisecond), cpu.Milliseconds(), 100*cpu.Seconds()/elapsed.Seconds(),
		readProcStatusKiB("VmHWM"))
}

// TestSpoolBacklogMemoryPerf prints peak heap for a production-size backlog.
// Opt-in: CDNCA_SPOOL_MEM_EVENTS (e.g. 300000), CDNCA_SPOOL_MEM_FLUSHES.
func TestSpoolBacklogMemoryPerf(t *testing.T) {
	events, _ := strconv.Atoi(os.Getenv("CDNCA_SPOOL_MEM_EVENTS"))
	if events <= 0 {
		t.Skip("set CDNCA_SPOOL_MEM_EVENTS to measure spool backlog memory")
	}
	flushes, _ := strconv.Atoi(os.Getenv("CDNCA_SPOOL_MEM_FLUSHES"))
	if flushes <= 0 {
		flushes = 20
	}
	result := measureSpoolMemory(t, events, flushes)
	t.Logf("PERF spoolmem events=%d new_peak_mib=%.1f new_retained_mib=%.1f bytes_per_record=%.0f new_elapsed=%s flush_batches=%d flushed=%d flush_peak_mib=%.1f flush_elapsed=%s",
		events, float64(result.newPeak)/(1<<20), float64(result.newRetained)/(1<<20), float64(result.newRetained)/float64(events),
		result.newElapsed.Round(time.Millisecond), result.flushBatches, result.flushedEvents,
		float64(result.flushPeak)/(1<<20), result.flushElapsed.Round(time.Millisecond))
}
