package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeControlSocket serves /site-drop on a unix socket and records requests.
func fakeControlSocket(t *testing.T, status int) (string, *[]string, *[][]string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "sd") // short: sun_path limit
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "c.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	methods := &[]string{}
	pushed := &[][]string{}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != siteDropControlPath {
			http.NotFound(w, r)
			return
		}
		*methods = append(*methods, r.Method)
		if r.Method == http.MethodPut {
			raw, _ := io.ReadAll(r.Body)
			var body struct {
				Hosts []string `json:"hosts"`
			}
			if err := json.Unmarshal(raw, &body); err != nil || body.Hosts == nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			*pushed = append(*pushed, body.Hosts)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"error":"x"}`))
	})}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	return path, methods, pushed
}

func TestControlSocketHostPusherPushAndClear(t *testing.T) {
	path, methods, pushed := fakeControlSocket(t, http.StatusOK)
	var pusher siteDropHostPusher = newControlSocketHostPusher(path)
	ctx := context.Background()
	if err := pusher.PushHosts(ctx, []string{"a.example", "*.b.example"}); err != nil {
		t.Fatal(err)
	}
	if err := pusher.PushHosts(ctx, nil); err != nil { // empty set, not null
		t.Fatal(err)
	}
	if err := pusher.ClearHosts(ctx); err != nil {
		t.Fatal(err)
	}
	if strings.Join(*methods, ",") != "PUT,PUT,DELETE" {
		t.Fatalf("methods %v", *methods)
	}
	if len(*pushed) != 2 || strings.Join((*pushed)[0], ",") != "a.example,*.b.example" || len((*pushed)[1]) != 0 {
		t.Fatalf("pushed %v", *pushed)
	}
}

func TestControlSocketHostPusherErrors(t *testing.T) {
	path, _, _ := fakeControlSocket(t, http.StatusBadRequest)
	pusher := newControlSocketHostPusher(path)
	if err := pusher.PushHosts(context.Background(), []string{"a.example"}); err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("err %v", err)
	}
	if err := newControlSocketHostPusher(filepath.Join(t.TempDir(), "none.sock")).ClearHosts(context.Background()); err == nil {
		t.Fatal("missing socket accepted")
	}
	huge := make([]string, 0, 20000)
	for len(huge) < cap(huge) {
		huge = append(huge, strings.Repeat("a", 250)+".example")
	}
	if err := pusher.PushHosts(context.Background(), huge); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("oversized body: %v", err)
	}
}

// merge-esc: the daemon's executor carries the control socket host pusher, so
// a non-empty plan (every one has Hosts) is enforced, not not_supported.
func TestDaemonSiteDropExecutorPushesHosts(t *testing.T) {
	path, methods, pushed := fakeControlSocket(t, http.StatusOK)
	filter := &fakeSiteDropXDP{running: true}
	executor := newKernelSiteDropExecutor(filter, &fakeSiteDropNFT{}, path)
	ctx := context.Background()
	if err := executor.Apply(ctx, executorTestPlan); err != nil {
		t.Fatalf("apply: %v", err)
	}
	plan := executorTestPlan
	plan.Mode, plan.SNIPorts, plan.ServerNames, plan.KeepNames = siteDropModeNFTables, nil, nil, nil
	if err := newKernelSiteDropExecutor(nil, &fakeSiteDropNFT{}, path).Apply(ctx, plan); err != nil {
		t.Fatalf("apply nftables: %v", err)
	}
	if err := executor.Apply(ctx, siteDropPlan{Mode: siteDropModeXDP}); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if strings.Join(*methods, ",") != "PUT,PUT,DELETE" || len(*pushed) != 2 ||
		strings.Join((*pushed)[0], ",") != "*.a.example,a.example" {
		t.Fatalf("methods %v pushed %v", *methods, *pushed)
	}
}
