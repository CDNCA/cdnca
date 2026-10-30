package main

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

// D13d-2: on a fresh dynamic routing node the daemon opens the object store
// (below <deployment parent>/dynroute/state) before the dynamic routing
// runtime exists. Every directory it creates on the way must be 0750 with
// the worker group, under the root unit's UMask=0077 too; a dynroute parent
// left 0750 root:root kept the workers out of state/site-index ("no current
// index file" on the first publish).
func TestOpenObjectStoreMakesParentsWorkerTraversable(t *testing.T) {
	root := t.TempDir()
	rootInfo, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	gid, name := -1, ""
	for _, candidate := range groups {
		if uint32(candidate) == rootInfo.Sys().(*syscall.Stat_t).Gid {
			continue
		}
		if group, err := user.LookupGroupId(strconv.Itoa(candidate)); err == nil {
			gid, name = candidate, group.Name
			break
		}
	}
	if gid < 0 {
		t.Skip("needs a named supplementary group different from the temp directory's group")
	}
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	deployment := filepath.Join(root, "lib", "cdnca", "deployments")
	config := fileConfig{DeploymentRoot: deployment, DynamicRouting: dynamicRoutingSettings{Enabled: true, WorkerGroup: name}}
	if _, err := openObjectStore(config); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(root, "lib", "cdnca", "dynroute")
	for _, dir := range []string{filepath.Join(root, "lib"), filepath.Join(root, "lib", "cdnca"), base, filepath.Join(base, "state")} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o750 || int(info.Sys().(*syscall.Stat_t).Gid) != gid {
			t.Fatalf("%s: mode %v gid %d, want 0750 gid %d", dir, info.Mode().Perm(), info.Sys().(*syscall.Stat_t).Gid, gid)
		}
	}
}
