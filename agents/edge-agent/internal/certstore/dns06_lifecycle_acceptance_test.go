package certstore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDNS06FullChainSNIActivationKeepsLKGOnFailedRenewal(t *testing.T) {
	root := managedStateRoot(t)
	config := RuntimeConfig{StateRoot: root, ListenAddress: "127.0.0.1", ListenPort: 18443}
	runtime := &fakeRuntime{}
	manager, err := newManager(config, runtime, func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}

	first := validTestBundle(t, "dns06-v1", "api.deep.example.test")
	firstResult, err := manager.Apply(t.Context(), first)
	if err != nil || firstResult.ActiveVersionID != first.VersionID {
		t.Fatalf("first activation = %#v, %v", firstResult, err)
	}
	beforeCurrent, err := os.Readlink(filepath.Join(root, "current"))
	if err != nil {
		t.Fatal(err)
	}

	runtime.healthFailures = 1
	renewal := validTestBundle(t, "dns06-v2", "api.deep.example.test")
	if _, err := manager.Apply(context.Background(), renewal); !errors.Is(err, ErrHealth) {
		t.Fatalf("renewal activation error = %v, want %v", err, ErrHealth)
	}
	afterCurrent, err := os.Readlink(filepath.Join(root, "current"))
	if err != nil {
		t.Fatal(err)
	}
	status, err := manager.Status(t.Context())
	if err != nil || beforeCurrent != afterCurrent || status.VersionID != first.VersionID ||
		status.Digest != firstResult.ActiveDigest {
		t.Fatalf("rollback current=%q/%q status=%#v error=%v", beforeCurrent, afterCurrent, status, err)
	}
}
