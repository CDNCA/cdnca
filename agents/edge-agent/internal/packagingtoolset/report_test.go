package packagingtoolset

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func fixture(t *testing.T) Paths {
	t.Helper()
	root := t.TempDir()
	paths := Paths{Record: filepath.Join(root, "toolset-refresh"), Scripts: filepath.Join(root, "libexec"),
		Helper: filepath.Join(root, "cdnca-edge-agent-helper")}
	if err := os.Mkdir(paths.Scripts, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range scriptNames {
		if err := os.WriteFile(filepath.Join(paths.Scripts, name+".sh"), []byte("#!/bin/sh\n# "+name+"\n"), 0o555); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(paths.Helper, []byte("\x7fELF helper v1"), 0o555); err != nil {
		t.Fatal(err)
	}
	return paths
}

func writeRecord(t *testing.T, paths Paths, content string) {
	t.Helper()
	if err := os.WriteFile(paths.Record, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRecordFormats(t *testing.T) {
	paths := fixture(t)
	reporter := NewReporter(paths)
	if got := reporter.Report(); got.RefreshStatus != "none" || got.RefreshVersion != "" || got.RefreshTime != nil {
		t.Fatalf("no record = %v", got)
	}
	// The record older packaging scripts wrote: no time, no helper.
	writeRecord(t, paths, "status=ok\nversion=1.0.35\n")
	mtime := time.Date(2026, 11, 9, 1, 2, 3, 0, time.UTC)
	if err := os.Chtimes(paths.Record, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	if got := reporter.Report(); got.RefreshStatus != "ok" || got.RefreshVersion != "1.0.35" || got.HelperStatus != "" ||
		!got.RefreshTime.AsTime().Equal(mtime) {
		t.Fatalf("old record = %v", got)
	}
	writeRecord(t, paths, "status=failed\nversion=1.0.29\nreason=cdnca-edge-agent packaging: packaging/scripts/rollback.sh differs from the signed SBOM\n")
	if got := reporter.Report(); got.RefreshStatus != "failed" || got.RefreshReason == "" {
		t.Fatalf("old failed record = %v", got)
	}
	writeRecord(t, paths, "status=ok\nversion=1.0.36\ntime=2026-11-09T04:05:06Z\nhelper_status=failed\nhelper_reason=transient unit could not replace the packaging helper\nfuture_key=x\n")
	got := reporter.Report()
	if got.RefreshStatus != "ok" || got.HelperStatus != "failed" || got.HelperReason != "transient unit could not replace the packaging helper" ||
		!got.RefreshTime.AsTime().Equal(time.Date(2026, 11, 9, 4, 5, 6, 0, time.UTC)) {
		t.Fatalf("new record = %v", got)
	}
	for name, content := range map[string]string{
		"no status":     "version=1.0.36\n",
		"bad status":    "status=done\nversion=1.0.36\n",
		"no version":    "status=ok\n",
		"duplicate key": "status=ok\nstatus=failed\nversion=1.0.36\n",
		"bad time":      "status=ok\nversion=1.0.36\ntime=yesterday\n",
		"not key=value": "garbage\n",
		"bad helper":    "status=ok\nversion=1.0.36\nhelper_status=replaced\n",
		"reserved none": "status=none\nversion=1.0.36\n",
	} {
		writeRecord(t, paths, content)
		if got := reporter.Report(); got.RefreshStatus != "unknown" || got.RefreshVersion != "" {
			t.Errorf("%s: %v, want unknown", name, got)
		}
	}
	if os.Geteuid() != 0 {
		writeRecord(t, paths, "status=ok\nversion=1.0.36\n")
		if err := os.Chmod(paths.Record, 0); err != nil {
			t.Fatal(err)
		}
		if got := reporter.Report(); got.RefreshStatus != "unknown" {
			t.Fatalf("unreadable record = %v", got)
		}
	}
}

func TestDigestsFollowReplacement(t *testing.T) {
	paths := fixture(t)
	reporter := NewReporter(paths)
	want := ""
	for _, name := range scriptNames {
		sum := sha256.Sum256([]byte("#!/bin/sh\n# " + name + "\n"))
		want += fmt.Sprintf("%s  %s.sh\n", hex.EncodeToString(sum[:]), name)
	}
	total := sha256.Sum256([]byte(want))
	helper := sha256.Sum256([]byte("\x7fELF helper v1"))
	first := reporter.Report()
	if first.ScriptsSha256 != hex.EncodeToString(total[:]) || first.HelperSha256 != hex.EncodeToString(helper[:]) {
		t.Fatalf("digests = %s %s", first.ScriptsSha256, first.HelperSha256)
	}
	// An atomic replacement (new inode) is picked up on the next report.
	staged := filepath.Join(filepath.Dir(paths.Helper), ".helper")
	if err := os.WriteFile(staged, []byte("\x7fELF helper v2"), 0o555); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(staged, paths.Helper); err != nil {
		t.Fatal(err)
	}
	second := reporter.Report()
	if second.HelperSha256 == first.HelperSha256 || second.ScriptsSha256 != first.ScriptsSha256 {
		t.Fatalf("after helper replacement = %s %s", second.ScriptsSha256, second.HelperSha256)
	}
	if err := os.Remove(filepath.Join(paths.Scripts, "lib.sh")); err != nil {
		t.Fatal(err)
	}
	if got := reporter.Report(); got.ScriptsSha256 != "" || got.HelperSha256 != second.HelperSha256 {
		t.Fatalf("missing script = %s %s", got.ScriptsSha256, got.HelperSha256)
	}
}
