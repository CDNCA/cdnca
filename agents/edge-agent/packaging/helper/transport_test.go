package helper

import (
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/packaging/helper/protocol"
)

func TestSocketPolicyRejectsWrongModeAndOwner(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "cfa-helper-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	path := filepath.Join(directory, "helper.sock")
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	policy := socketPolicy{path: path, uid: uint32(stat.Uid), gid: uint32(stat.Gid)}
	if err := validateSocketPath(policy); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		t.Fatal(err)
	}
	assertProtocolCode(t, validateSocketPath(policy), protocol.ErrorSocketPolicy)
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	policy.uid++
	assertProtocolCode(t, validateSocketPath(policy), protocol.ErrorSocketPolicy)
}

func assertProtocolCode(t *testing.T, err error, want protocol.ErrorCode) {
	t.Helper()
	got, ok := ErrorCode(err)
	if !ok || got != want {
		t.Fatalf("error = %v, code = %q, want %q", err, got, want)
	}
}
