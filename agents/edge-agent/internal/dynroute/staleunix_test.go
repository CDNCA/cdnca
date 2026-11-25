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

// PR5-UNIX-LISTENER-PATH-PARSER-1: a path with a non-ASCII space (U+3000) is
// one nginx token; the unreferenced socket at its prefix is left alone and the
// referenced stale socket is the one removed.
func TestRemoveStaleUnixListenersReadsPathsAsNginxTokens(t *testing.T) {
	dir := t.TempDir()
	shared := filepath.Join(dir, "shared")
	full := filepath.Join(dir, "shared　node")
	if err := os.MkdirAll(full, 0o755); err != nil {
		t.Fatal(err)
	}
	staleSocket := func(path string) {
		t.Helper()
		listener, err := net.Listen("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		listener.(*net.UnixListener).SetUnlinkOnClose(false)
		_ = listener.Close()
	}
	// The prefix the old strings.Fields split stopped at: an unreferenced socket.
	staleSocket(shared)
	referenced := filepath.Join(full, "443-tls.sock")
	staleSocket(referenced)
	conf := filepath.Join(dir, "nginx.conf")
	body := "stream {\n  server {\n    listen unix:" + referenced + " proxy_protocol;\n  }\n  server {\n    listen \"unix:" +
		filepath.Join(full, "quoted \\\"a\\\".sock") + "\";\n  }\n}\n"
	if err := os.WriteFile(conf, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got := unixListenPaths(conf)
	want := []string{referenced, filepath.Join(full, `quoted "a".sock`)}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("unix listen paths = %q, want %q", got, want)
	}

	removeStaleUnixListeners(conf)

	if _, err := os.Lstat(shared); err != nil {
		t.Fatalf("unreferenced prefix socket removed: %v", err)
	}
	if _, err := os.Lstat(referenced); !os.IsNotExist(err) {
		t.Fatalf("referenced stale socket kept: %v", err)
	}
}

func TestListenValue(t *testing.T) {
	for line, want := range map[string]string{
		"    listen unix:/a/b.sock;":       "unix:/a/b.sock",
		"\tlisten unix:/a/b.sock ssl;":     "unix:/a/b.sock",
		`  listen "unix:/a b/c.sock" ssl;`: "unix:/a b/c.sock",
		`  listen 'unix:/a/c.sock';`:       "unix:/a/c.sock",
		"  listen unix:/a　b/c.sock;":       "unix:/a　b/c.sock",
		"  listen 80;":                     "80",
	} {
		if got, ok := listenValue(line); !ok || got != want {
			t.Errorf("listenValue(%q) = %q, %v; want %q", line, got, ok, want)
		}
	}
	for _, line := range []string{"  listening unix:/a;", "  # listen unix:/a;", `  listen "unix:/a;`, "  listen", "listen;"} {
		if got, ok := listenValue(line); ok {
			t.Errorf("listenValue(%q) = %q, want no value", line, got)
		}
	}
}
