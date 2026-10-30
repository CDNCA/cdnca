package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// fix-imperson guard: impersonation works for every handler only because the
// served chain is wrapped by api.WithImpersonationDelegate (it swaps the
// administrator's Bearer for the target user's delegate session). Handlers
// that call identityService.AuthenticateSession directly are fine behind it;
// a second HTTP server or a chain without the wrapper is not.
func TestImpersonationDelegateWrapsTheServedHandler(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	servers := 0
	listen := regexp.MustCompile(`http\.Server\{|ListenAndServe\(|http\.Serve\(`)
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		source, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		text := string(source)
		for _, match := range listen.FindAllStringIndex(text, -1) {
			window := text[match[0]:min(len(text), match[0]+400)]
			// fix-migrollback: the frozen console (native_backup.go, cdnca-control-frozen-console.service)
			// runs only while control-api is stopped by a migration hold (systemd Conflicts) and serves
			// its own frozen-session login, status, stop and rollback; no impersonation exists there.
			if file == "native_backup.go" && strings.HasPrefix(window, "http.Server{Addr: address, Handler: console,") {
				continue
			}
			if file == "native_backup.go" && strings.HasPrefix(window, "ListenAndServe(") && strings.Contains(text[max(0, match[0]-20):match[0]], "server.") {
				continue
			}
			servers++
			if file != "main.go" || !strings.Contains(window, "Handler: api.WithClientSourceIP(api.WithImpersonationDelegate(") {
				t.Fatalf("%s serves HTTP without api.WithImpersonationDelegate: %q", file, window[:min(len(window), 160)])
			}
		}
	}
	if servers != 1 {
		t.Fatalf("control-api HTTP servers=%d, want exactly the main one", servers)
	}
}
