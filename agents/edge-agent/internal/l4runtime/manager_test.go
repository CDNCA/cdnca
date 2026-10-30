package l4runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var errInjectedRuntime = errors.New("injected runtime failure")

type fakeRuntime struct {
	mu             sync.Mutex
	precheckCalls  []string
	activateCalls  []string
	stopCalls      []string
	failPrecheck   bool
	failActivation int
}

func (r *fakeRuntime) Precheck(_ context.Context, path string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.precheckCalls = append(r.precheckCalls, path)
	if r.failPrecheck {
		r.failPrecheck = false
		return errInjectedRuntime
	}
	return nil
}

func (r *fakeRuntime) Activate(_ context.Context, path string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.activateCalls = append(r.activateCalls, currentTarget(path))
	if r.failActivation > 0 {
		r.failActivation--
		return errInjectedRuntime
	}
	return nil
}

func (r *fakeRuntime) Stop(_ context.Context, path string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopCalls = append(r.stopCalls, path)
	return nil
}

func currentTarget(path string) string {
	target, _ := os.Readlink(path)
	return filepath.Base(target)
}

func fixedTime() time.Time {
	return time.Date(2026, time.July, 22, 12, 0, 0, 0, time.UTC)
}

func testManager(t *testing.T, runtime Runtime) (*Manager, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "l4")
	t.Cleanup(func() {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err == nil && info.IsDir() {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
	})
	manager, err := newManager(root, runtime, fixedTime)
	if err != nil {
		t.Fatalf("newManager() error = %v", err)
	}
	return manager, root
}

func TestManagerStagesPrechecksAndActivatesImmutableVersion(t *testing.T) {
	runtime := &fakeRuntime{}
	manager, root := testManager(t, runtime)
	result, err := manager.Apply(context.Background(), validConfig("l4-v1"))
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if result.State != StateApplied || result.ActiveVersionID != "l4-v1" || result.Digest == "" || !result.AppliedAt.Equal(fixedTime()) {
		t.Fatalf("Apply() result = %+v", result)
	}
	target, err := os.Readlink(filepath.Join(root, "current"))
	if err != nil || filepath.Base(target) != "l4-v1-"+result.Digest {
		t.Fatalf("current target = %q, error = %v", target, err)
	}
	versionPath := filepath.Join(root, target)
	for _, name := range []string{"config.json", "nginx.conf"} {
		info, err := os.Stat(filepath.Join(versionPath, name))
		if err != nil || info.Mode().Perm() != 0o400 {
			t.Fatalf("sealed %s mode = %v, error = %v", name, info.Mode().Perm(), err)
		}
	}
	if len(runtime.precheckCalls) != 1 || len(runtime.activateCalls) != 1 {
		t.Fatalf("runtime calls precheck=%d activate=%d", len(runtime.precheckCalls), len(runtime.activateCalls))
	}
	status, err := manager.Status()
	if err != nil || !status.Active || status.VersionID != "l4-v1" || status.Digest != result.Digest {
		t.Fatalf("Status() = %+v, %v", status, err)
	}
}

func TestManagerPrecheckFailurePreservesLastKnownGood(t *testing.T) {
	runtime := &fakeRuntime{}
	manager, root := testManager(t, runtime)
	first, err := manager.Apply(context.Background(), validConfig("l4-v1"))
	if err != nil {
		t.Fatal(err)
	}
	runtime.failPrecheck = true
	failed, err := manager.Apply(context.Background(), validConfig("l4-v2"))
	if !errors.Is(err, ErrPrecheck) || failed.ErrorCode != "PRECHECK_FAILED" || !failed.RunningVersionUnchanged || failed.ActiveVersionID != "l4-v1" {
		t.Fatalf("failed Apply() = %+v, %v", failed, err)
	}
	target, _ := os.Readlink(filepath.Join(root, "current"))
	if filepath.Base(target) != "l4-v1-"+first.Digest || len(runtime.activateCalls) != 1 {
		t.Fatalf("precheck failure changed active runtime: target=%q calls=%v", target, runtime.activateCalls)
	}
}

func TestManagerActivationFailureReloadsLastKnownGood(t *testing.T) {
	runtime := &fakeRuntime{}
	manager, root := testManager(t, runtime)
	first, err := manager.Apply(context.Background(), validConfig("l4-v1"))
	if err != nil {
		t.Fatal(err)
	}
	runtime.failActivation = 1
	failed, err := manager.Apply(context.Background(), validConfig("l4-v2"))
	if !errors.Is(err, ErrActivation) || failed.ErrorCode != "ACTIVATION_FAILED" || !failed.RunningVersionUnchanged || failed.ActiveVersionID != "l4-v1" {
		t.Fatalf("failed Apply() = %+v, %v", failed, err)
	}
	target, _ := os.Readlink(filepath.Join(root, "current"))
	if filepath.Base(target) != "l4-v1-"+first.Digest {
		t.Fatalf("activation failure target = %q", target)
	}
	if len(runtime.activateCalls) != 3 || runtime.activateCalls[1] == runtime.activateCalls[2] || runtime.activateCalls[2] != filepath.Base(target) {
		t.Fatalf("activation/rollback calls = %v", runtime.activateCalls)
	}
}

func TestManagerInitialActivationFailureStopsCandidate(t *testing.T) {
	runtime := &fakeRuntime{failActivation: 1}
	manager, root := testManager(t, runtime)
	failed, err := manager.Apply(context.Background(), validConfig("l4-v1"))
	if !errors.Is(err, ErrActivation) || !failed.RunningVersionUnchanged || failed.ActiveVersionID != "" {
		t.Fatalf("Apply() = %+v, %v", failed, err)
	}
	if _, err := os.Lstat(filepath.Join(root, "current")); !errors.Is(err, os.ErrNotExist) || len(runtime.stopCalls) != 1 {
		t.Fatalf("candidate was not stopped and cleared: stat=%v stop=%v", err, runtime.stopCalls)
	}
}

func TestManagerIsIdempotentAndRejectsVersionConflict(t *testing.T) {
	runtime := &fakeRuntime{}
	manager, _ := testManager(t, runtime)
	first, err := manager.Apply(context.Background(), validConfig("l4-v1"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := manager.Apply(context.Background(), validConfig("l4-v1"))
	if err != nil || second.Digest != first.Digest || len(runtime.precheckCalls) != 1 || len(runtime.activateCalls) != 1 {
		t.Fatalf("idempotent Apply() = %+v, %v, calls=%d/%d", second, err, len(runtime.precheckCalls), len(runtime.activateCalls))
	}
	conflict := validConfig("l4-v1")
	conflict.Listeners[0].IdleTimeoutMS++
	if _, err := manager.Apply(context.Background(), conflict); !errors.Is(err, ErrConflict) {
		t.Fatalf("Apply(conflict) error = %v, want ErrConflict", err)
	}
	if _, err := manager.Apply(context.Background(), validConfig("l4-v2")); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Apply(context.Background(), conflict); !errors.Is(err, ErrConflict) {
		t.Fatalf("Apply(inactive version conflict) error = %v, want ErrConflict", err)
	}
}

func TestManagerCompileFailurePreservesLastKnownGood(t *testing.T) {
	runtime := &fakeRuntime{}
	manager, root := testManager(t, runtime)
	first, err := manager.Apply(context.Background(), validConfig("l4-v1"))
	if err != nil {
		t.Fatal(err)
	}
	currentBefore := currentTarget(filepath.Join(root, "current"))
	precheckCalls := len(runtime.precheckCalls)
	activateCalls := len(runtime.activateCalls)
	stopCalls := len(runtime.stopCalls)

	conflict := validConfig("l4-v2")
	conflict.Listeners = []Listener{
		{ID: "tcp-any-443", Protocol: ProtocolTCP, Address: "0.0.0.0", Port: 443, UpstreamPoolID: "pool-v4", ConnectTimeoutMS: 100, IdleTimeoutMS: 1_000, MaxConnectionsPerClient: 10},
		{ID: "tcp-any-8443", Protocol: ProtocolTCP, Address: "0.0.0.0", Port: 8443, UpstreamPoolID: "pool-v4", ConnectTimeoutMS: 100, IdleTimeoutMS: 1_000, MaxConnectionsPerClient: 10},
		{ID: "tcp-specific-443", Protocol: ProtocolTCP, Address: "127.0.0.1", Port: 443, UpstreamPoolID: "pool-v4", ConnectTimeoutMS: 100, IdleTimeoutMS: 1_000, MaxConnectionsPerClient: 10},
	}
	if _, err := manager.Apply(context.Background(), conflict); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Apply(overlap) error = %v, want ErrInvalidConfig", err)
	}
	if len(runtime.precheckCalls) != precheckCalls || len(runtime.activateCalls) != activateCalls || len(runtime.stopCalls) != stopCalls {
		t.Fatalf("compile failure reached runtime: precheck=%d/%d activate=%d/%d stop=%d/%d", len(runtime.precheckCalls), precheckCalls, len(runtime.activateCalls), activateCalls, len(runtime.stopCalls), stopCalls)
	}
	if currentAfter := currentTarget(filepath.Join(root, "current")); currentAfter != currentBefore {
		t.Fatalf("compile failure changed current target from %q to %q", currentBefore, currentAfter)
	}
	status, statusErr := manager.Status()
	if statusErr != nil || !status.Active || status.VersionID != first.VersionID || status.Digest != first.Digest {
		t.Fatalf("Status() = %+v, %v; want active l4-v1 %s", status, statusErr, first.Digest)
	}
}

func TestManagerDoesNotTreatVersionIDPrefixAsConflict(t *testing.T) {
	runtime := &fakeRuntime{}
	manager, _ := testManager(t, runtime)
	if _, err := manager.Apply(context.Background(), validConfig("l4")); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Apply(context.Background(), validConfig("l4-child")); err != nil {
		t.Fatalf("Apply(prefix version) error = %v", err)
	}
}

func TestManagerSerializesConcurrentApply(t *testing.T) {
	runtime := &fakeRuntime{}
	manager, _ := testManager(t, runtime)
	const workers = 16
	var wait sync.WaitGroup
	errorsFound := make(chan error, workers)
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := manager.Apply(context.Background(), validConfig("l4-v1"))
			errorsFound <- err
		}()
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatalf("concurrent Apply() error = %v", err)
		}
	}
	if len(runtime.precheckCalls) != 1 || len(runtime.activateCalls) != 1 {
		t.Fatalf("concurrent runtime calls precheck=%d activate=%d", len(runtime.precheckCalls), len(runtime.activateCalls))
	}
}

func TestManagerRejectsUnsafeStateRoot(t *testing.T) {
	runtime := &fakeRuntime{}
	for _, path := range []string{"relative", "/"} {
		if _, err := NewManager(path, runtime); !errors.Is(err, ErrInvalidPath) {
			t.Errorf("NewManager(%q) error = %v, want ErrInvalidPath", path, err)
		}
	}
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewManager(link, runtime); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("NewManager(symlink) error = %v, want ErrInvalidPath", err)
	}
}

func TestManagerRejectsTamperedLastKnownGood(t *testing.T) {
	runtime := &fakeRuntime{}
	manager, root := testManager(t, runtime)
	result, err := manager.Apply(context.Background(), validConfig("l4-v1"))
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "versions", "l4-v1-"+result.Digest, "config.json")
	if err := os.Chmod(configPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Status(); !errors.Is(err, ErrCorruptState) {
		t.Fatalf("Status() error = %v, want ErrCorruptState", err)
	}
}

func TestManagerRollbackActivatesExactSealedVersionAfterRestart(t *testing.T) {
	runtime := &fakeRuntime{}
	manager, root := testManager(t, runtime)
	first, err := manager.Apply(context.Background(), validConfig("l4-v1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Apply(context.Background(), validConfig("l4-v2")); err != nil {
		t.Fatal(err)
	}

	restarted, err := newManager(root, runtime, fixedTime)
	if err != nil {
		t.Fatalf("newManager(restart) error = %v", err)
	}
	result, err := restarted.Rollback(context.Background(), first.VersionID, first.Digest)
	if err != nil || result.State != StateApplied || result.ActiveVersionID != "l4-v1" || result.ActiveDigest != first.Digest {
		t.Fatalf("Rollback() = %+v, %v", result, err)
	}
	status, err := restarted.Status()
	if err != nil || !status.Active || status.VersionID != "l4-v1" || status.Digest != first.Digest {
		t.Fatalf("Status() = %+v, %v", status, err)
	}
	if got := currentTarget(filepath.Join(root, "current")); got != "l4-v1-"+first.Digest {
		t.Fatalf("current target = %q", got)
	}
}

func TestManagerRollbackFailurePreservesConfirmedActiveVersion(t *testing.T) {
	runtime := &fakeRuntime{}
	manager, root := testManager(t, runtime)
	first, err := manager.Apply(context.Background(), validConfig("l4-v1"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := manager.Apply(context.Background(), validConfig("l4-v2"))
	if err != nil {
		t.Fatal(err)
	}

	runtime.failActivation = 1
	failed, err := manager.Rollback(context.Background(), first.VersionID, first.Digest)
	if !errors.Is(err, ErrActivation) || failed.State != StateFailed || failed.ErrorCode != "ACTIVATION_FAILED" ||
		!failed.RunningVersionUnchanged || failed.ActiveVersionID != second.VersionID || failed.ActiveDigest != second.Digest {
		t.Fatalf("Rollback() = %+v, %v", failed, err)
	}
	status, statusErr := manager.Status()
	if statusErr != nil || status.VersionID != second.VersionID || status.Digest != second.Digest {
		t.Fatalf("Status() = %+v, %v", status, statusErr)
	}
	if got := currentTarget(filepath.Join(root, "current")); got != "l4-v2-"+second.Digest {
		t.Fatalf("current target = %q", got)
	}
}

func TestManagerRollbackPrecheckFailurePreservesConfirmedActiveVersion(t *testing.T) {
	runtime := &fakeRuntime{}
	manager, root := testManager(t, runtime)
	first, err := manager.Apply(context.Background(), validConfig("l4-v1"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := manager.Apply(context.Background(), validConfig("l4-v2"))
	if err != nil {
		t.Fatal(err)
	}
	activateCalls := len(runtime.activateCalls)
	runtime.failPrecheck = true

	failed, err := manager.Rollback(context.Background(), first.VersionID, first.Digest)
	if !errors.Is(err, ErrPrecheck) || failed.State != StateFailed || failed.ErrorCode != "PRECHECK_FAILED" ||
		!failed.RunningVersionUnchanged || failed.ActiveVersionID != second.VersionID || failed.ActiveDigest != second.Digest {
		t.Fatalf("Rollback() = %+v, %v", failed, err)
	}
	rollbackPath := filepath.Join(manager.store.versionsDir, first.VersionID+"-"+first.Digest)
	if got := runtime.precheckCalls[len(runtime.precheckCalls)-1]; got != rollbackPath {
		t.Fatalf("rollback precheck path = %q, want %q", got, rollbackPath)
	}
	if len(runtime.activateCalls) != activateCalls {
		t.Fatalf("rollback precheck failure activateCalls = %v", runtime.activateCalls)
	}
	status, statusErr := manager.Status()
	if statusErr != nil || status.VersionID != second.VersionID || status.Digest != second.Digest {
		t.Fatalf("Status() = %+v, %v", status, statusErr)
	}
	if got := currentTarget(filepath.Join(root, "current")); got != "l4-v2-"+second.Digest {
		t.Fatalf("current target = %q", got)
	}
}

func TestManagerRollbackRejectsUnknownOrMismatchedImmutableVersion(t *testing.T) {
	runtime := &fakeRuntime{}
	manager, _ := testManager(t, runtime)
	first, err := manager.Apply(context.Background(), validConfig("l4-v1"))
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name      string
		versionID string
		digest    string
	}{
		{name: "unknown version", versionID: "l4-missing", digest: first.Digest},
		{name: "mismatched digest", versionID: first.VersionID, digest: strings.Repeat("0", 64)},
		{name: "invalid version", versionID: "../l4-v1", digest: first.Digest},
		{name: "invalid digest", versionID: first.VersionID, digest: "not-a-digest"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := manager.Rollback(context.Background(), test.versionID, test.digest); err == nil {
				t.Fatal("Rollback() error = nil")
			}
			status, statusErr := manager.Status()
			if statusErr != nil || status.VersionID != first.VersionID || status.Digest != first.Digest {
				t.Fatalf("Status() = %+v, %v", status, statusErr)
			}
		})
	}
}
