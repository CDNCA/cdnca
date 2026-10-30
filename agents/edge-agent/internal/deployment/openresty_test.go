package deployment

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestOpenRestyCommandsAndSanitizedErrors(t *testing.T) {
	type invocation struct {
		binary string
		args   []string
	}
	var invocations []invocation
	runner := func(_ context.Context, binary string, args ...string) error {
		invocations = append(invocations, invocation{binary: binary, args: append([]string(nil), args...)})
		return nil
	}
	openresty, err := NewOpenResty("/usr/local/openresty/bin/openresty", "nginx.conf", runner, func(context.Context, string) error { return nil })
	if err != nil {
		t.Fatalf("NewOpenResty() error = %v", err)
	}
	if err := openresty.Precheck(context.Background(), "cfg-v1", "/var/lib/cdnca/releases/digest"); err != nil {
		t.Fatalf("Precheck() error = %v", err)
	}
	if err := openresty.Reload(context.Background(), "cfg-v1", "/var/lib/cdnca/current"); err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	want := []invocation{
		{binary: "/usr/local/openresty/bin/openresty", args: []string{"-t", "-p", "/var/lib/cdnca/releases/digest/", "-c", "nginx.conf"}},
		{binary: "/usr/local/openresty/bin/openresty", args: []string{"-s", "reload", "-p", "/var/lib/cdnca/current/", "-c", "nginx.conf"}},
	}
	if !reflect.DeepEqual(invocations, want) {
		t.Fatalf("invocations = %#v, want %#v", invocations, want)
	}

	secret := "private-key-material"
	failing, err := NewOpenResty("/usr/local/openresty/bin/openresty", "nginx.conf", func(context.Context, string, ...string) error {
		return errors.New(secret)
	}, func(context.Context, string) error {
		return errors.New(secret)
	})
	if err != nil {
		t.Fatalf("NewOpenResty(failing) error = %v", err)
	}
	for name, operation := range map[string]func() error{
		"precheck": func() error {
			return failing.Precheck(context.Background(), "cfg-v1", "/var/lib/cdnca/releases/digest")
		},
		"reload": func() error { return failing.Reload(context.Background(), "cfg-v1", "/var/lib/cdnca/current") },
		"health": func() error { return failing.Healthy(context.Background(), "cfg-v1") },
	} {
		t.Run(name, func(t *testing.T) {
			if err := operation(); err == nil || strings.Contains(err.Error(), secret) {
				t.Fatalf("operation error = %v", err)
			}
		})
	}
}

func TestOpenRestyReloadStartsWhenMasterIsMissing(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(string) error
	}{
		{name: "missing pid file", prepare: func(string) error { return nil }},
		{name: "empty pid file", prepare: func(path string) error { return os.WriteFile(path, nil, 0o600) }},
		{name: "stale pid file", prepare: func(path string) error { return os.WriteFile(path, []byte("2147483647\n"), 0o600) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			pidPath := filepath.Join(root, "nginx.pid")
			if err := test.prepare(pidPath); err != nil {
				t.Fatalf("prepare PID file: %v", err)
			}
			var arguments []string
			runtime, err := NewOpenResty("/usr/local/openresty/bin/openresty", "nginx.conf", func(_ context.Context, _ string, args ...string) error {
				arguments = append([]string(nil), args...)
				return nil
			}, func(context.Context, string) error { return nil })
			if err != nil {
				t.Fatalf("NewOpenResty() error = %v", err)
			}
			if err := runtime.ConfigureGenerationTracking(pidPath); err != nil {
				t.Fatalf("ConfigureGenerationTracking() error = %v", err)
			}
			if err := runtime.Reload(context.Background(), "cfg-v1", "/var/lib/cdnca/current"); err != nil {
				t.Fatalf("Reload() error = %v", err)
			}
			want := []string{"-p", "/var/lib/cdnca/current/", "-c", "nginx.conf"}
			if !reflect.DeepEqual(arguments, want) {
				t.Fatalf("arguments = %#v, want %#v", arguments, want)
			}
			if _, err := os.Lstat(pidPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("stale PID file remains: %v", err)
			}
		})
	}
}

func TestOpenRestyRejectsUnsafeConfiguration(t *testing.T) {
	probe := func(context.Context, string) error { return nil }
	for _, test := range []struct {
		binary string
		config string
	}{
		{binary: "openresty", config: "nginx.conf"},
		{binary: "/usr/bin/../bin/openresty", config: "nginx.conf"},
		{binary: "/usr/bin/openresty", config: "../nginx.conf"},
	} {
		if _, err := NewOpenResty(test.binary, test.config, nil, probe); err == nil {
			t.Fatalf("NewOpenResty(%q, %q) succeeded", test.binary, test.config)
		}
	}
}
