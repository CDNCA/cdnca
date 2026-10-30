package deployment

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type runtimeDirectoryPrechecker func(context.Context, string, string) error

func (f runtimeDirectoryPrechecker) Precheck(ctx context.Context, versionID, releasePath string) error {
	return f(ctx, versionID, releasePath)
}

func TestPrecheckPreparesPrivateCacheDirectory(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "agent-state")
	t.Cleanup(func() { makeTreeWritable(root) })
	inspected := false
	prechecker := runtimeDirectoryPrechecker(func(_ context.Context, _ string, _ string) error {
		info, err := os.Lstat(filepath.Join(root, "shared", "cache"))
		if err != nil {
			t.Fatalf("Lstat(cache) error = %v", err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
			t.Fatalf("cache mode = %v, want directory 0700", info.Mode())
		}
		inspected = true
		return nil
	})
	manager, err := NewManager(root, prechecker, &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	command := testCommand(t, "deploy-cache-directory", 1, "cfg-v1", "", map[string][]byte{"site.conf": []byte("v1")})

	result, err := manager.Process(context.Background(), command)
	if err != nil || result.State != StateHealthy || !inspected {
		t.Fatalf("Process() = (%+v, %v), inspected=%v", result, err, inspected)
	}
}

func TestPrecheckRejectsCacheDirectorySymlink(t *testing.T) {
	prechecker := &fakePrechecker{failFor: map[string]error{}}
	manager, root := newTestManager(t, prechecker, &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}})
	sharedDir := filepath.Join(root, "shared")
	if err := os.Mkdir(sharedDir, 0o700); err != nil {
		t.Fatalf("Mkdir(shared) error = %v", err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(sharedDir, "cache")); err != nil {
		t.Fatalf("Symlink(cache) error = %v", err)
	}
	command := testCommand(t, "deploy-cache-symlink", 1, "cfg-v1", "", map[string][]byte{"site.conf": []byte("v1")})

	result, err := manager.Process(context.Background(), command)
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if result.State != StateFailed || result.ErrorCode != "PRECHECK_FAILED" || !result.RunningConfigUnchanged {
		t.Fatalf("result = %+v", result)
	}
	if !reflect.DeepEqual(states(result), []State{StateDelivered, StateStaged, StateFailed}) {
		t.Fatalf("states = %v", states(result))
	}
	if len(prechecker.calls) != 0 {
		t.Fatalf("precheck calls = %v, want none", prechecker.calls)
	}
}

func TestPrecheckRejectsBroadCacheDirectoryPermissions(t *testing.T) {
	prechecker := &fakePrechecker{failFor: map[string]error{}}
	manager, root := newTestManager(t, prechecker, &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}})
	cacheDir := filepath.Join(root, "shared", "cache")
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(cache) error = %v", err)
	}
	if err := os.Chmod(cacheDir, 0o755); err != nil {
		t.Fatalf("Chmod(cache) error = %v", err)
	}
	command := testCommand(t, "deploy-cache-permissions", 1, "cfg-v1", "", map[string][]byte{"site.conf": []byte("v1")})

	result, err := manager.Process(context.Background(), command)
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if result.State != StateFailed || result.ErrorCode != "PRECHECK_FAILED" || !result.RunningConfigUnchanged {
		t.Fatalf("result = %+v", result)
	}
	if len(prechecker.calls) != 0 {
		t.Fatalf("precheck calls = %v, want none", prechecker.calls)
	}
	info, err := os.Lstat(cacheDir)
	if err != nil {
		t.Fatalf("Lstat(cache) error = %v", err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("cache permissions = %o, want unchanged 0755", info.Mode().Perm())
	}
}
