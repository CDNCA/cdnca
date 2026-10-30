//go:build linux

package toa

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestProbeLoadsAttachesAndSelfTests needs root, cgroup v2 and a 5.10+
// kernel; set CDNCA_TOA_PRIVILEGED_TEST=1 to run it (the PoC container in
// docs/architecture/l4-toa-poc.md). It moves the test process into a fresh
// child cgroup so the programs never attach to a shared cgroup.
func TestProbeLoadsAttachesAndSelfTests(t *testing.T) {
	if os.Getenv("CDNCA_TOA_PRIVILEGED_TEST") != "1" {
		t.Skip("set CDNCA_TOA_PRIVILEGED_TEST=1 (root, cgroup v2, kernel 5.10+)")
	}
	cgroup := "/sys/fs/cgroup/cdnca-toa-gotest"
	if err := os.Mkdir(cgroup, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cgroup, "cgroup.procs"), []byte("0"), 0); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "openresty")
	if err := os.WriteFile(binary, []byte("\x00proxy_socket_keepalive\x00proxy_toa\x00"), 0o755); err != nil {
		t.Fatal(err)
	}

	manager := Probe(Options{OpenRestyBinary: binary})
	status := manager.Status()
	if !status.Ready || status.Cgroup != cgroup {
		t.Fatalf("probe not ready: %+v", status)
	}
	stats, err := manager.Stats()
	if err != nil || stats[StatStored] != 1 || stats[StatWritten] < 1 {
		t.Fatalf("self-test stats = %v, %v", stats, err)
	}
	manager.Close()
	if _, err := manager.Stats(); err == nil {
		t.Fatal("stats readable after Close")
	}

	// Unpatched OpenResty: refused before anything is loaded.
	if err := os.WriteFile(binary, []byte("\x00proxy_socket_keepalive\x00"), 0o755); err != nil {
		t.Fatal(err)
	}
	if status := Probe(Options{OpenRestyBinary: binary}).Status(); status.Ready || status.Reason != ErrNoProxyTOA.Error() {
		t.Fatalf("unpatched OpenResty status = %+v", status)
	}
}
