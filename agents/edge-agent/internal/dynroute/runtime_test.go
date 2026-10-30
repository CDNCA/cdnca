package dynroute

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestRuntime(t *testing.T, recent int) *Runtime {
	t.Helper()
	root := t.TempDir()
	runtime, err := New(Config{StateRoot: filepath.Join(root, "node"), SharedRoot: filepath.Join(root, "shared"),
		LuaRoot: root, OpenResty: "/usr/local/openresty/bin/openresty", WorkerGID: -1, ErrorLogRecent: recent})
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

func TestNewPreparesWorkerDirectories(t *testing.T) {
	runtime := newTestRuntime(t, 0)
	for _, dir := range []string{"run", "site-objects", "site-index", "tls-pool", "challenge", "origin-auth-secrets", "managed-waf"} {
		info, err := os.Stat(filepath.Join(runtime.config.StateRoot, dir))
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0o750 {
			t.Fatalf("%s: %v %v", dir, info, err)
		}
	}
	for _, name := range []string{"placeholder.crt", "placeholder.key"} {
		if _, err := os.Stat(filepath.Join(runtime.config.StateRoot, name)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := New(Config{StateRoot: "relative", SharedRoot: "/x", LuaRoot: "/x", OpenResty: "/x"}); err == nil {
		t.Fatal("relative state root accepted")
	}
}

func TestStateSurvivesRestart(t *testing.T) {
	runtime := newTestRuntime(t, 0)
	runtime.state = persisted{Generation: 7, WAF: "a", PrevWAF: "b", Skeleton: "c"}
	if err := runtime.saveState(); err != nil {
		t.Fatal(err)
	}
	again, err := New(runtime.config)
	if err != nil {
		t.Fatal(err)
	}
	if again.Generation() != 7 || again.state.WAF != "a" || again.state.Skeleton != "c" {
		t.Fatalf("%+v", again.state)
	}
}

func TestErrorLogSummary(t *testing.T) {
	runtime := newTestRuntime(t, 3)
	path := filepath.Join(runtime.config.SharedRoot, "error.log")
	stamp := time.Now().Format("2006/01/02 15:04:05")
	var lines []string
	lines = append(lines, stamp+" [emerg] 12#12: close() socket 0.0.0.0:443 failed (9: Bad file descriptor)")
	lines = append(lines, stamp+" [notice] 12#12: signal process started")
	for index := range 5 {
		lines = append(lines, fmt.Sprintf("%s [crit] 12#12: *%d line %d %s", stamp, index, index, strings.Repeat("y", 600)))
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stats, err := runtime.ReadErrorLog()
	if err != nil {
		t.Fatal(err)
	}
	if stats.SevereTotal != 5 || stats.NoiseTotal != 1 || len(stats.Recent) != 3 || stats.LastSevere.IsZero() {
		t.Fatalf("%+v", stats)
	}
	for _, line := range stats.Recent {
		if len(line) > MaxErrorLineBytes {
			t.Fatalf("line of %d bytes", len(line))
		}
	}
	if !strings.Contains(stats.Recent[2], "line 4") {
		t.Fatalf("newest last: %q", stats.Recent[2])
	}
	again, _ := runtime.ReadErrorLog()
	if again.SevereTotal != 5 {
		t.Fatalf("re-read counted again: %+v", again)
	}
}

// b3-fix: Applied is false until an Apply wrote nginx.conf (Recover's "never
// applied"), true afterwards.
func TestAppliedFollowsTheRuntimeConfiguration(t *testing.T) {
	runtime := newTestRuntime(t, 0)
	if runtime.Applied() || (*Runtime)(nil).Applied() {
		t.Fatal("Applied before any Apply")
	}
	if err := os.WriteFile(runtime.confPath(), []byte("events {}\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if !runtime.Applied() {
		t.Fatal("not Applied after nginx.conf was written")
	}
}
