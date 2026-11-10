package packagingtoolset

import (
	"os"
	"path/filepath"
	"testing"
)

// countingStats counts the stat calls a report makes.
func countingStats(reporter *Reporter) *int {
	count := 0
	reporter.stat = func(path string) fileSignature { count++; return statSignature(path) }
	return &count
}

// eight stats per unchanged heartbeat still
// cost about 78 us at 100 ms heartbeats. With the three directories watched,
// an unchanged heartbeat makes no stat, and every kind of change shows on the
// next report.
func TestWatchedReportFollowsChanges(t *testing.T) {
	paths := fixture(t)
	writeRecord(t, paths, "status=ok\nversion=1.0.35\ntime=2026-11-09T05:00:00Z\nhelper_status=ok\n")
	reporter := NewReporter(paths)
	stats := countingStats(reporter)
	first := reporter.Report()
	if first.RefreshVersion != "1.0.35" || first.ScriptsSha256 == "" || first.HelperSha256 == "" {
		t.Fatalf("first = %v", first)
	}
	unchanged := func(step string) {
		t.Helper()
		*stats = 0
		for i := 0; i < 5; i++ {
			reporter.Report()
		}
		if *stats != 0 {
			t.Fatalf("%s: %d stats over 5 unchanged reports, want 0", step, *stats)
		}
	}
	unchanged("start")

	lib := filepath.Join(paths.Scripts, "lib.sh")
	if err := os.Chmod(lib, 0o755); err != nil {
		t.Fatal(err)
	}
	reporter.Report() // the chmod is an event: this report stats, then none
	unchanged("before edit")
	if err := os.WriteFile(lib, []byte("#!/bin/sh\n# lib edited in place\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	edited := reporter.Report()
	if edited.ScriptsSha256 == "" || edited.ScriptsSha256 == first.ScriptsSha256 {
		t.Fatalf("in-place edit: %q", edited.ScriptsSha256)
	}
	unchanged("after edit")

	*stats = 0
	if err := os.Chmod(paths.Helper, 0o500); err != nil {
		t.Fatal(err)
	}
	if reporter.Report(); *stats == 0 {
		t.Fatal("chmod: report made no stat")
	}
	unchanged("after chmod")

	if err := os.WriteFile(paths.Record+".new", []byte("status=failed\nversion=1.0.36\nreason=x\ntime=2026-11-09T06:00:00Z\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(paths.Record+".new", paths.Record); err != nil {
		t.Fatal(err)
	}
	if got := reporter.Report(); got.RefreshStatus != "failed" || got.RefreshVersion != "1.0.36" {
		t.Fatalf("record replaced: %v", got)
	}
	unchanged("after record")

	if err := os.Remove(paths.Helper); err != nil {
		t.Fatal(err)
	}
	if got := reporter.Report(); got.HelperSha256 != "" {
		t.Fatalf("helper deleted: %q", got.HelperSha256)
	}

	// The scripts directory replaced as a whole: the watch on the old one is
	// gone, so every report stats again and sees the new scripts.
	replaced := paths.Scripts + ".new"
	if err := os.Mkdir(replaced, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range scriptNames {
		if err := os.WriteFile(filepath.Join(replaced, name+".sh"), []byte("#!/bin/sh\n# v2 "+name+"\n"), 0o555); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Rename(paths.Scripts, paths.Scripts+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replaced, paths.Scripts); err != nil {
		t.Fatal(err)
	}
	if got := reporter.Report(); got.ScriptsSha256 == "" || got.ScriptsSha256 == edited.ScriptsSha256 {
		t.Fatalf("scripts directory replaced: %q", got.ScriptsSha256)
	}
	*stats = 0
	reporter.Report()
	if *stats != 8 {
		t.Fatalf("after the scripts directory was replaced: %d stats, want 8 (stat every report)", *stats)
	}
}

// A directory the Agent cannot watch (missing, or root-only on deb nodes):
// every report stats, as before.
func TestUnwatchableDirectoryStatsEveryReport(t *testing.T) {
	paths := fixture(t)
	paths.Record = filepath.Join(filepath.Dir(paths.Record), "missing", "toolset-refresh")
	reporter := NewReporter(paths)
	stats := countingStats(reporter)
	for i := 0; i < 3; i++ {
		if got := reporter.Report(); got.RefreshStatus != "none" {
			t.Fatalf("report %d = %v", i, got)
		}
	}
	if *stats != 24 {
		t.Fatalf("%d stats over 3 reports, want 24", *stats)
	}
}
