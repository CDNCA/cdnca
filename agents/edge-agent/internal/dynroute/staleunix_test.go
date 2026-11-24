//go:build linux

package dynroute

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestRemoveStaleUnixListenersKeepsLiveAndNonSockets(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, "run", "cdnca-site-admin.sock")
	live := filepath.Join(dir, "run", "secagg", "flush.sock")
	regular := filepath.Join(dir, "mux", "443-tls.sock")
	for _, path := range []string{stale, live, regular} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A socket whose listener is gone (a killed master): the file stays.
	dead, err := net.Listen("unix", stale)
	if err != nil {
		t.Fatal(err)
	}
	dead.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = dead.Close()
	listener, err := net.Listen("unix", live)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.WriteFile(regular, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(dir, "nginx.conf")
	body := "http {\n  server {\n    listen \"unix:" + stale + "\";\n  }\n  server {\n    listen unix:" + live + ";\n  }\n" +
		"  server {\n    listen \"unix:" + regular + "\" ssl proxy_protocol;\n    listen 80;\n  }\n}\n"
	if err := os.WriteFile(conf, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := unixListenPaths(conf); len(got) != 3 {
		t.Fatalf("unix listen paths = %v", got)
	}

	removeStaleUnixListeners(conf)

	if _, err := os.Lstat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale socket kept: %v", err)
	}
	if _, err := os.Lstat(live); err != nil {
		t.Fatalf("live socket removed: %v", err)
	}
	if _, err := os.Lstat(regular); err != nil {
		t.Fatalf("regular file removed: %v", err)
	}
	// The stale path can be bound again (what OpenResty's start needs).
	again, err := net.Listen("unix", stale)
	if err != nil {
		t.Fatalf("bind after cleanup: %v", err)
	}
	_ = again.Close()
}
