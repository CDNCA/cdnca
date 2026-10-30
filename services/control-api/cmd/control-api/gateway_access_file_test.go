package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// GW-09: the host firewall (nftables set, install-control.sh) follows the same
// allow list as the ControlInternal remote listener.
func TestGatewayAccessFileFollowsAllowList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gateway-access", "allowed-ips")
	ips := []net.IP{net.ParseIP("203.0.113.9"), net.ParseIP("2001:db8::7"), net.ParseIP("203.0.113.9")}
	var fail error
	list := withGatewayAccessFile(func(context.Context) ([]net.IP, error) { return ips, fail }, path)
	got, err := list(context.Background())
	if err != nil || len(got) != 3 {
		t.Fatalf("allow list = %v, %v", got, err)
	}
	contents, err := os.ReadFile(path)
	if err != nil || string(contents) != "2001:db8::7\n203.0.113.9\n" {
		t.Fatalf("access file = %q, %v", contents, err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("access file mode = %v", info.Mode().Perm())
	}
	ips = nil
	if _, err := list(context.Background()); err != nil {
		t.Fatal(err)
	}
	if contents, _ := os.ReadFile(path); string(contents) != "" {
		t.Fatalf("emptied allow list left %q", contents)
	}
	// A failed refresh keeps the previous file (and the previous filter).
	ips, fail = []net.IP{net.ParseIP("198.51.100.1")}, errors.New("db down")
	if _, err := list(context.Background()); err == nil {
		t.Fatal("error swallowed")
	}
	if contents, _ := os.ReadFile(path); string(contents) != "" {
		t.Fatalf("failed refresh rewrote the file: %q", contents)
	}
	if same := withGatewayAccessFile(list, ""); same == nil {
		t.Fatal("empty path must keep the list")
	}
}
