package originroute

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestOpenRestyRuntimePrecheckAndHealthProbe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test helper uses a POSIX shell")
	}
	base := t.TempDir()
	stateRoot := filepath.Join(base, "state")
	release := filepath.Join(stateRoot, "versions", strings.Repeat("a", 64))
	if err := os.MkdirAll(release, 0o700); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(base, "arguments")
	binary := filepath.Join(base, "openresty")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$CDNCA_RUNTIME_TEST_LOG\"\n"
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CDNCA_RUNTIME_TEST_LOG", logPath)
	probed := ""
	runtime, err := NewOpenRestyRuntime(binary, stateRoot, func(_ context.Context, version string) error {
		probed = version
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Precheck(context.Background(), release); err != nil {
		t.Fatal(err)
	}
	arguments, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	want := "-t -p " + release + string(filepath.Separator) + " -c nginx.conf"
	if strings.TrimSpace(string(arguments)) != want {
		t.Fatalf("precheck arguments=%q, expected %q", strings.TrimSpace(string(arguments)), want)
	}
	if err := runtime.Healthy(context.Background(), "route-v1"); err != nil || probed != "route-v1" {
		t.Fatalf("health err=%v version=%q", err, probed)
	}
	if err := runtime.Precheck(context.Background(), filepath.Join(base, "outside")); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("outside release error=%v", err)
	}
}

func TestNewOpenRestyRuntimeRejectsUnsafeArguments(t *testing.T) {
	probe := func(context.Context, string) error { return nil }
	for _, test := range []struct {
		binary string
		root   string
		probe  HealthProbe
	}{
		{"relative", "/var/lib/cdnca", probe},
		{"/usr/bin/openresty", "relative", probe},
		{"/usr/bin/openresty;bad", "/var/lib/cdnca", probe},
		{"/usr/bin/openresty", "/var/lib/cdnca", nil},
	} {
		if _, err := NewOpenRestyRuntime(test.binary, test.root, test.probe); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatalf("NewOpenRestyRuntime(%q, %q) error=%v", test.binary, test.root, err)
		}
	}
}

func TestOpenRestyRuntimeWaitRunningToleratesPartialPIDWrite(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(filepath.Join(root, "shared"), 0o700); err != nil {
		t.Fatal(err)
	}
	runtime, err := NewOpenRestyRuntime("/usr/bin/true", root, func(context.Context, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runtime.pidFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(30 * time.Millisecond)
		_ = os.WriteFile(runtime.pidFile, []byte(strconv.Itoa(os.Getpid())), 0o600)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := runtime.waitRunning(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestWorkerGenerationReadyRequiresNewWorkerAndOldExit(t *testing.T) {
	if !workerGenerationReady(map[int]struct{}{os.Getpid(): {}}, nil) {
		t.Fatal("initial generation was not ready")
	}
	missingPID := 1 << 30
	if workerGenerationReady(
		map[int]struct{}{os.Getpid(): {}, missingPID: {}},
		map[int]struct{}{os.Getpid(): {}},
	) {
		t.Fatal("reload generation passed while an old worker was alive")
	}
	if !workerGenerationReady(
		map[int]struct{}{os.Getpid(): {}},
		map[int]struct{}{missingPID: {}},
	) {
		t.Fatal("reload generation did not pass after old worker exit")
	}
}
