package dynroute

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The daemon's default roots are <deployment_root parent>/dynroute/{state,shared}:
// the common parent does not exist on a fresh node and New creates it. The
// workers must be able to traverse every directory New creates, under the
// root unit's UMask=0077 too.
func TestNewMakesCreatedParentsWorkerTraversable(t *testing.T) {
	root := t.TempDir()
	rootInfo, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	gid := -1
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	for _, group := range groups {
		if uint32(group) != rootInfo.Sys().(*syscall.Stat_t).Gid {
			gid = group
			break
		}
	}
	if gid < 0 {
		t.Skip("needs a supplementary group different from the temp directory's group")
	}
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	base := filepath.Join(root, "lib", "dynroute")
	if _, err := New(Config{StateRoot: filepath.Join(base, "state"), SharedRoot: filepath.Join(base, "shared"),
		LuaRoot: root, OpenResty: "/usr/local/openresty/bin/openresty", WorkerGID: gid}); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{filepath.Join(root, "lib"), base, filepath.Join(base, "state"), filepath.Join(base, "shared"),
		filepath.Join(base, "state", "site-index")} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o750 || int(info.Sys().(*syscall.Stat_t).Gid) != gid {
			t.Fatalf("%s: mode %v gid %d, want 0750 gid %d", dir, info.Mode().Perm(), info.Sys().(*syscall.Stat_t).Gid, gid)
		}
	}
	// a parent that already existed is left alone
	after, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode() != rootInfo.Mode() || after.Sys().(*syscall.Stat_t).Gid != rootInfo.Sys().(*syscall.Stat_t).Gid {
		t.Fatalf("pre-existing parent changed: %v", after.Mode())
	}
}

// Telemetry on: the aggregated security lines' flush socket directory
// (sec-log-agg) is 0710 of the worker group - workers connect, nothing else
// (nginx makes the unix listener itself 0666).
func TestNewMakesTheSecurityFlushDirectoryWorkerOnly(t *testing.T) {
	root := t.TempDir()
	gid := os.Getgid()
	if _, err := New(Config{StateRoot: filepath.Join(root, "state"), SharedRoot: filepath.Join(root, "shared"),
		LuaRoot: root, OpenResty: "/usr/local/openresty/bin/openresty", WorkerGID: gid, Telemetry: true}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(root, "state", "run", "secagg"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o710 || int(info.Sys().(*syscall.Stat_t).Gid) != gid {
		t.Fatalf("run/secagg mode %v gid %d", info.Mode().Perm(), info.Sys().(*syscall.Stat_t).Gid)
	}
}
