package eventspool

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// TestTailThroughputPerf measures how fast one tailer moves a large access
// log into a production-sized spool. Opt-in: set
// CDNCA_TAIL_PERF_MB (source size in MiB, e.g. 100).
func TestTailThroughputPerf(t *testing.T) {
	sizeMB, _ := strconv.Atoi(os.Getenv("CDNCA_TAIL_PERF_MB"))
	if sizeMB <= 0 {
		t.Skip("set CDNCA_TAIL_PERF_MB to run the tail throughput measurement")
	}
	root, err := os.MkdirTemp("/tmp", "cdnca-tail-perf-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	_ = os.Chmod(root, 0o700)
	root, _ = filepath.EvalSymlinks(root)
	source := filepath.Join(root, "access.jsonl")
	lines := writePerfSource(t, source, int64(sizeMB)<<20)

	now := time.Unix(1_700_000_000, 0).UTC().Add(time.Hour)
	spool, err := New(Config{
		Root: filepath.Join(root, "spool"), MaxEventBytes: 64 << 10, MaxSegmentBytes: 16 << 20,
		SoftLimitBytes: 4 << 30, HardLimitBytes: 8 << 30, MaxTenantBytes: 4 << 30,
		MaxBatchEvents: 10000, PressureMode: PressureBackpressure,
		SoftAgeLimit: 24 * time.Hour, HardAgeLimit: 7 * 24 * time.Hour,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	tailer, err := NewTailer(TailConfig{
		SourcePath: source, StateDir: filepath.Join(root, "tail-state"),
		Identity:     TrustedIdentity{EnrollmentNodeID: nodeOne, TenantID: tenantOne, SiteID: siteOne, ConfigVersionID: "cfg-1"},
		MaxLineBytes: 64 << 10, MaxBatchEvents: 10000, MaxQuarantineBytes: 64 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	var before, after syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &before)
	started := time.Now()
	result, err := tailer.TailOnce(context.Background(), spool)
	elapsed := time.Since(started)
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &after)
	if err != nil || result.AppendedEvents != lines {
		t.Fatalf("tail result appended=%d want=%d err=%v", result.AppendedEvents, lines, err)
	}
	cpu := time.Duration(after.Utime.Nano()-before.Utime.Nano()) + time.Duration(after.Stime.Nano()-before.Stime.Nano())
	t.Logf("PERF tail size_mib=%d lines=%d elapsed=%s cpu=%s mib_per_s=%.1f events_per_s=%.0f",
		sizeMB, lines, elapsed.Round(time.Millisecond), cpu.Round(time.Millisecond),
		float64(sizeMB)/elapsed.Seconds(), float64(lines)/elapsed.Seconds())
}

func writePerfSource(t *testing.T, path string, target int64) int {
	t.Helper()
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	writer := bufio.NewWriterSize(file, 1<<20)
	event := sourceAccess(tenantOne)
	event.RequestHeaders = map[string]string{"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) perf"}
	var written int64
	lines := 0
	for written < target {
		event.RequestID = fmt.Sprintf("request-%d", lines)
		event.Path = fmt.Sprintf("/static/asset-%d.js?v=%d", lines%997, lines)
		event.OccurredAt = time.Unix(1_700_000_000, 0).UTC().Add(time.Duration(lines) * time.Millisecond)
		payload, marshalErr := json.Marshal(event)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		payload = append(payload, '\n')
		if _, err := writer.Write(payload); err != nil {
			t.Fatal(err)
		}
		written += int64(len(payload))
		lines++
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return lines
}
