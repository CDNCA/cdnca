package packagingtoolset

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// countingReporter counts reads per path through the injected hash function.
func countingReporter(paths Paths) (*Reporter, func(string) int) {
	reporter := NewReporter(paths)
	var mu sync.Mutex
	reads := map[string]int{}
	reporter.hash = func(path string, limit int64) (string, error) {
		mu.Lock()
		reads[path]++
		mu.Unlock()
		return fileSHA256(path, limit)
	}
	return reporter, func(path string) int { mu.Lock(); defer mu.Unlock(); return reads[path] }
}

// With one file missing every heartbeat used to reread the 4.7 MB helper.
func TestMissingFileDoesNotRereadHelper(t *testing.T) {
	paths := fixture(t)
	if err := os.Remove(filepath.Join(paths.Scripts, "lib.sh")); err != nil {
		t.Fatal(err)
	}
	reporter, reads := countingReporter(paths)
	for i := 0; i < 5; i++ {
		if got := reporter.Report(); got.ScriptsSha256 != "" || got.HelperSha256 == "" {
			t.Fatalf("report %d = %s %s", i, got.ScriptsSha256, got.HelperSha256)
		}
	}
	if got := reads(paths.Helper); got != 1 {
		t.Fatalf("helper read %d times over 5 reports with a script missing, want 1", got)
	}
}

// Each file is read once per stat change: all present, one missing, one
// replaced, one deleted (and created again) show on the next report.
func TestDigestCacheFollowsStat(t *testing.T) {
	paths := fixture(t)
	reporter, reads := countingReporter(paths)
	lib := filepath.Join(paths.Scripts, "lib.sh")
	report := func(times int) (string, string) {
		t.Helper()
		var scripts, helper string
		for i := 0; i < times; i++ {
			got := reporter.Report()
			scripts, helper = got.ScriptsSha256, got.HelperSha256
		}
		return scripts, helper
	}
	replace := func(path, content string) {
		t.Helper()
		staged := path + ".new"
		if err := os.WriteFile(staged, []byte(content), 0o555); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(staged, path); err != nil {
			t.Fatal(err)
		}
	}

	// All present: one read each, however many heartbeats.
	scripts, helper := report(4)
	if scripts == "" || helper == "" || reads(paths.Helper) != 1 || reads(lib) != 1 {
		t.Fatalf("all present: %s %s helper=%d lib=%d", scripts, helper, reads(paths.Helper), reads(lib))
	}
	// Helper replaced: the next report has the new digest; scripts are not reread.
	replace(paths.Helper, "\x7fELF helper v2")
	if _, next := report(3); next == helper || reads(paths.Helper) != 2 || reads(lib) != 1 {
		t.Fatalf("helper replaced: %s helper=%d lib=%d", next, reads(paths.Helper), reads(lib))
	}
	// One script deleted: scripts digest empties at once; nothing is reread.
	if err := os.Remove(lib); err != nil {
		t.Fatal(err)
	}
	if gone, _ := report(3); gone != "" || reads(paths.Helper) != 2 || reads(lib) != 1 {
		t.Fatalf("lib deleted: %q helper=%d lib=%d", gone, reads(paths.Helper), reads(lib))
	}
	// Created again with other bytes: read once, new scripts digest.
	replace(lib, "#!/bin/sh\n# lib v2\n")
	if back, _ := report(3); back == "" || back == scripts || reads(lib) != 2 || reads(paths.Helper) != 2 {
		t.Fatalf("lib created: %q helper=%d lib=%d", back, reads(paths.Helper), reads(lib))
	}
	// Helper deleted: empty digest at once, cached as missing.
	if err := os.Remove(paths.Helper); err != nil {
		t.Fatal(err)
	}
	if _, none := report(3); none != "" || reads(paths.Helper) != 2 {
		t.Fatalf("helper deleted: %q helper=%d", none, reads(paths.Helper))
	}
}

// An unreadable file is cached as a failure until its stat changes.
func TestUnreadableFileIsCached(t *testing.T) {
	paths := fixture(t)
	reporter, reads := countingReporter(paths)
	reporter.hash = func(inner func(string, int64) (string, error)) func(string, int64) (string, error) {
		return func(path string, limit int64) (string, error) {
			sum, err := inner(path, limit)
			if path == paths.Helper {
				return "", os.ErrPermission
			}
			return sum, err
		}
	}(reporter.hash)
	for i := 0; i < 4; i++ {
		if got := reporter.Report(); got.HelperSha256 != "" || got.ScriptsSha256 == "" {
			t.Fatalf("report %d = %s %s", i, got.ScriptsSha256, got.HelperSha256)
		}
	}
	if got := reads(paths.Helper); got != 1 {
		t.Fatalf("unreadable helper read %d times, want 1", got)
	}
}
