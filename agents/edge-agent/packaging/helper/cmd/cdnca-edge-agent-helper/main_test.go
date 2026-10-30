package main

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestDispatchAllowsOnlyFixedRootCommands(t *testing.T) {
	tests := []struct {
		name      string
		euid      int
		arguments []string
		want      error
		keyCalls  int
		serveCall int
	}{
		{name: "key init", euid: 0, arguments: []string{"key-init"}, keyCalls: 1},
		{name: "serve", euid: 0, arguments: []string{"serve"}, serveCall: 1},
		{name: "non root", euid: 1000, arguments: []string{"serve"}, want: errRootRequired},
		{name: "missing", euid: 0, want: errCommandUsage},
		{name: "unknown", euid: 0, arguments: []string{"shell"}, want: errCommandUsage},
		{name: "extra", euid: 0, arguments: []string{"serve", "--path", "/tmp/attacker"}, want: errCommandUsage},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			keyCalls := 0
			serveCalls := 0
			actions := commandActions{
				euid: func() int { return test.euid },
				keyInit: func() error {
					keyCalls++
					return nil
				},
				serve: func(context.Context) error {
					serveCalls++
					return nil
				},
			}
			err := dispatch(context.Background(), test.arguments, actions)
			if !errors.Is(err, test.want) || keyCalls != test.keyCalls || serveCalls != test.serveCall {
				t.Fatalf("dispatch = (%v, key=%d, serve=%d)", err, keyCalls, serveCalls)
			}
		})
	}
}

func TestDispatchDoesNotUseCallerEnvironment(t *testing.T) {
	for _, key := range []string{"PATH", "CDNCA_HELPER_PATH", "CDNCA_HELPER_COMMAND", "CDNCA_RECEIPT_KEY"} {
		t.Setenv(key, "/tmp/attacker")
	}
	called := false
	actions := commandActions{
		euid: func() int { return 0 },
		keyInit: func() error {
			called = true
			return nil
		},
		serve: func(context.Context) error { return errors.New("unexpected") },
	}
	if err := dispatch(context.Background(), []string{"key-init"}, actions); err != nil || !called {
		t.Fatalf("dispatch = (%v, called=%v)", err, called)
	}
	if value := os.Getenv("CDNCA_HELPER_COMMAND"); value != "/tmp/attacker" {
		t.Fatalf("test environment unexpectedly changed: %q", value)
	}
}

func TestDispatchPropagatesServeCancellation(t *testing.T) {
	want := context.Canceled
	actions := commandActions{
		euid:    func() int { return 0 },
		keyInit: func() error { return errors.New("unexpected") },
		serve:   func(context.Context) error { return want },
	}
	if err := dispatch(context.Background(), []string{"serve"}, actions); !errors.Is(err, want) {
		t.Fatalf("serve error = %v", err)
	}
}
