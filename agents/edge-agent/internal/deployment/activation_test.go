package deployment

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

)

type precheckFunc func(context.Context, string, string) error

func (f precheckFunc) Precheck(ctx context.Context, versionID, releasePath string) error {
	return f(ctx, versionID, releasePath)
}

func TestReloadFailureRestoresPreviousRelease(t *testing.T) {
	runtime := &fakeRuntime{
		activationFailures: map[string]map[int]error{"cfg-v2": {1: errors.New("reload failed with private material")}},
		healthFailures:     map[string]error{},
	}
	manager, root := newTestManager(t, &fakePrechecker{failFor: map[string]error{}}, runtime)
	previous := deployHealthyV1(t, manager)
	command := testCommand(t, "deploy-reload-failure", 1, "cfg-v2", "cfg-v1", map[string][]byte{"site.conf": []byte("v2")})

	result, err := manager.Process(context.Background(), command)
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if !reflect.DeepEqual(states(result), []State{StateDelivered, StateStaged, StatePrechecked, StateFailed}) || !result.RunningConfigUnchanged {
		t.Fatalf("result = %+v", result)
	}
	if strings.Contains(result.Summary, "private material") {
		t.Fatalf("result leaks runtime error: %+v", result)
	}
	pointers, err := manager.Pointers()
	if err != nil {
		t.Fatalf("Pointers() error = %v", err)
	}
	if pointers != (Pointers{Current: "cfg-v1", CurrentDigest: previous.Bundle.ManifestSHA256}) {
		t.Fatalf("pointers = %+v", pointers)
	}
	target, err := os.Readlink(filepath.Join(root, "current"))
	if err != nil || target != filepath.Join("releases", previous.Bundle.ManifestSHA256) {
		t.Fatalf("current target = %q, error = %v", target, err)
	}
}

func TestReloadFailureRejectsUnhealthyPreviousRelease(t *testing.T) {
	runtime := &fakeRuntime{
		activationFailures: map[string]map[int]error{"cfg-v2": {1: errors.New("candidate reload failed")}},
		healthFailures:     map[string]error{},
	}
	manager, _ := newTestManager(t, &fakePrechecker{failFor: map[string]error{}}, runtime)
	deployHealthyV1(t, manager)
	runtime.mu.Lock()
	runtime.healthFailures["cfg-v1"] = errors.New("previous release is unhealthy")
	runtime.mu.Unlock()

	result, err := manager.Process(context.Background(), testCommand(t,
		"deploy-reload-unhealthy-restore", 1, "cfg-v2", "cfg-v1", map[string][]byte{"site.conf": []byte("v2")}))
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	wantStates := []State{StateDelivered, StateStaged, StatePrechecked, StateActivated, StateReverting, StateRollbackFailed}
	if !reflect.DeepEqual(states(result), wantStates) || result.RunningConfigUnchanged || result.ErrorCode != "ACTIVATION_RECOVERY_FAILED" {
		t.Fatalf("result = %+v, want states %v with failed recovery", result, wantStates)
	}
	if strings.Contains(result.Summary, "previous release is unhealthy") {
		t.Fatalf("result leaks runtime error: %+v", result)
	}
}

func TestFirstReloadFailureRestoresEmptyCurrent(t *testing.T) {
	runtime := &fakeRuntime{
		activationFailures: map[string]map[int]error{"cfg-v1": {1: errors.New("reload failed")}},
		healthFailures:     map[string]error{},
	}
	manager, root := newTestManager(t, &fakePrechecker{failFor: map[string]error{}}, runtime)
	command := testCommand(t, "deploy-first-reload-failure", 1, "cfg-v1", "", map[string][]byte{"site.conf": []byte("v1")})
	result, err := manager.Process(context.Background(), command)
	if err != nil || result.State != StateFailed || !result.RunningConfigUnchanged {
		t.Fatalf("Process() = (%+v, %v)", result, err)
	}
	if pointers, err := manager.Pointers(); err != nil || pointers != (Pointers{}) {
		t.Fatalf("Pointers() = (%+v, %v)", pointers, err)
	}
	if _, err := os.Lstat(filepath.Join(root, "current")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("current pointer stat error = %v", err)
	}
}

func TestRollbackHealthFailurePreservesBothPointerBaselines(t *testing.T) {
	root := filepath.Join(t.TempDir(), "agent-state")
	t.Cleanup(func() { makeTreeWritable(root) })
	config := DefaultConfig()
	config.RetainReleases = 2
	config.HealthTimeout = 20 * time.Millisecond
	config.HealthInterval = time.Millisecond
	runtime := &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}}
	manager, err := NewManagerWithConfig(root, &fakePrechecker{failFor: map[string]error{}}, runtime, config)
	if err != nil {
		t.Fatalf("NewManagerWithConfig() error = %v", err)
	}
	previous := testCommand(t, "deploy-rollback-health-v1", 1, "cfg-v1", "", map[string][]byte{"site.conf": []byte("v1")})
	if result, err := manager.Process(context.Background(), previous); err != nil || result.State != StateHealthy {
		t.Fatalf("Process(v1) = (%+v, %v)", result, err)
	}
	runtime.mu.Lock()
	runtime.healthFailures["cfg-v1"] = errors.New("old release unhealthy")
	runtime.healthFailures["cfg-v2"] = errors.New("new release unhealthy")
	runtime.mu.Unlock()
	command := testCommand(t, "deploy-rollback-health-v2", 1, "cfg-v2", "cfg-v1", map[string][]byte{"site.conf": []byte("v2")})
	result, err := manager.Process(context.Background(), command)
	if err != nil || result.State != StateRollbackFailed || result.ErrorCode != "ROLLBACK_HEALTH_FAILED" {
		t.Fatalf("Process(v2) = (%+v, %v)", result, err)
	}
	pointers, err := manager.Pointers()
	if err != nil || pointers.CurrentDigest != command.Bundle.ManifestSHA256 || pointers.PreviousDigest != previous.Bundle.ManifestSHA256 {
		t.Fatalf("Pointers() = (%+v, %v)", pointers, err)
	}
	target, err := os.Readlink(filepath.Join(root, "current"))
	if err != nil || target != filepath.Join("releases", previous.Bundle.ManifestSHA256) {
		t.Fatalf("current target = %q, error = %v", target, err)
	}
	entries, err := os.ReadDir(filepath.Join(root, "releases"))
	if err != nil || len(entries) != 2 {
		t.Fatalf("retained releases = %v, error = %v", entries, err)
	}
}

func TestBundleLimitsRejectBeforeStaging(t *testing.T) {
	tests := []struct {
		name   string
		limits Limits
		files  map[string][]byte
	}{
		{name: "file count", limits: Limits{MaxFiles: 1, MaxFileSize: 8, MaxTotalSize: 8}, files: map[string][]byte{"a": []byte("a"), "b": []byte("b")}},
		{name: "file size", limits: Limits{MaxFiles: 2, MaxFileSize: 1, MaxTotalSize: 8}, files: map[string][]byte{"a": []byte("ab")}},
		{name: "total size", limits: Limits{MaxFiles: 2, MaxFileSize: 2, MaxTotalSize: 3}, files: map[string][]byte{"a": []byte("ab"), "b": []byte("cd")}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "agent-state")
			config := DefaultConfig()
			config.Limits = test.limits
			manager, err := NewManagerWithConfig(root, &fakePrechecker{failFor: map[string]error{}}, &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}}, config)
			if err != nil {
				t.Fatalf("NewManagerWithConfig() error = %v", err)
			}
			command := testCommand(t, "deploy-limit", 1, "cfg-limit", "", test.files)
			if _, err := manager.Process(context.Background(), command); !errors.Is(err, ErrInvalidCommand) {
				t.Fatalf("Process() error = %v, want ErrInvalidCommand", err)
			}
			entries, err := os.ReadDir(filepath.Join(root, "releases"))
			if err != nil || len(entries) != 0 {
				t.Fatalf("release entries = %v, error = %v", entries, err)
			}
		})
	}
}

func TestReleaseSymlinkIsRejectedWithoutFollowingIt(t *testing.T) {
	manager, root := newTestManager(t, &fakePrechecker{failFor: map[string]error{}}, &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}})
	command := testCommand(t, "deploy-release-symlink", 1, "cfg-v1", "", map[string][]byte{"site.conf": []byte("v1")})
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "releases", command.Bundle.ManifestSHA256)); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	result, err := manager.Process(context.Background(), command)
	if !errors.Is(err, ErrInvalidPath) || result.State != StateFailed {
		t.Fatalf("Process() = (%+v, %v)", result, err)
	}
	entries, readErr := os.ReadDir(outside)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("outside entries = %v, error = %v", entries, readErr)
	}
}

func TestPrecheckTimeoutIsBounded(t *testing.T) {
	root := filepath.Join(t.TempDir(), "agent-state")
	t.Cleanup(func() { makeTreeWritable(root) })
	config := DefaultConfig()
	config.PrecheckTimeout = 20 * time.Millisecond
	prechecker := precheckFunc(func(ctx context.Context, _, _ string) error {
		<-ctx.Done()
		return ctx.Err()
	})
	manager, err := NewManagerWithConfig(root, prechecker, &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}}, config)
	if err != nil {
		t.Fatalf("NewManagerWithConfig() error = %v", err)
	}
	start := time.Now()
	result, err := manager.Process(context.Background(), testCommand(t, "deploy-precheck-timeout", 1, "cfg-v1", "", map[string][]byte{"site.conf": []byte("v1")}))
	if err != nil || result.State != StateFailed || result.ErrorCode != "PRECHECK_FAILED" {
		t.Fatalf("Process() = (%+v, %v)", result, err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("precheck elapsed = %v", elapsed)
	}
}

func TestManagersSerializeActivationThroughFileLock(t *testing.T) {
	root := filepath.Join(t.TempDir(), "agent-state")
	t.Cleanup(func() { makeTreeWritable(root) })
	runtime := &fakeRuntime{
		activationFailures: map[string]map[int]error{},
		healthFailures:     map[string]error{},
		activateStarted:    make(chan struct{}),
		releaseActivate:    make(chan struct{}),
	}
	reloadStarted := runtime.activateStarted
	config := DefaultConfig()
	first, err := NewManagerWithConfig(root, &fakePrechecker{failFor: map[string]error{}}, runtime, config)
	if err != nil {
		t.Fatalf("NewManagerWithConfig(first) error = %v", err)
	}
	second, err := NewManagerWithConfig(root, &fakePrechecker{failFor: map[string]error{}}, runtime, config)
	if err != nil {
		t.Fatalf("NewManagerWithConfig(second) error = %v", err)
	}
	command1 := testCommand(t, "deploy-serialized-v1", 1, "cfg-v1", "", map[string][]byte{"site.conf": []byte("v1")})
	command2 := testCommand(t, "deploy-serialized-v2", 1, "cfg-v2", "cfg-v1", map[string][]byte{"site.conf": []byte("v2")})
	type response struct {
		result Result
		err    error
	}
	responses := make(chan response, 2)
	go func() {
		result, err := first.Process(context.Background(), command1)
		responses <- response{result: result, err: err}
	}()
	<-reloadStarted
	go func() {
		result, err := second.Process(context.Background(), command2)
		responses <- response{result: result, err: err}
	}()
	close(runtime.releaseActivate)
	for range 2 {
		response := <-responses
		if response.err != nil || response.result.State != StateHealthy {
			t.Fatalf("Process() = (%+v, %v)", response.result, response.err)
		}
	}
	if got := runtime.activationList(); !reflect.DeepEqual(got, []string{"cfg-v1", "cfg-v2"}) {
		t.Fatalf("reloads = %v", got)
	}
}

func TestRetentionKeepsCurrentAndRollbackBaseline(t *testing.T) {
	root := filepath.Join(t.TempDir(), "agent-state")
	t.Cleanup(func() { makeTreeWritable(root) })
	config := DefaultConfig()
	config.RetainReleases = 2
	config.HealthTimeout = 20 * time.Millisecond
	config.HealthInterval = time.Millisecond
	manager, err := NewManagerWithConfig(root, &fakePrechecker{failFor: map[string]error{}}, &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}}, config)
	if err != nil {
		t.Fatalf("NewManagerWithConfig() error = %v", err)
	}
	previous := ""
	var commands []Command
	for i, content := range []string{"v1", "v2", "v3", "v4"} {
		version := "cfg-v" + string(rune('1'+i))
		command := testCommand(t, "deploy-retain-"+version, 1, version, previous, map[string][]byte{"site.conf": []byte(content)})
		result, err := manager.Process(context.Background(), command)
		if err != nil || result.State != StateHealthy {
			t.Fatalf("Process(%s) = (%+v, %v)", version, result, err)
		}
		commands = append(commands, command)
		previous = version
	}
	entries, err := os.ReadDir(filepath.Join(root, "releases"))
	if err != nil {
		t.Fatalf("ReadDir(releases) error = %v", err)
	}
	got := make([]string, 0, len(entries))
	for _, entry := range entries {
		got = append(got, entry.Name())
	}
	sort.Strings(got)
	want := []string{commands[2].Bundle.ManifestSHA256, commands[3].Bundle.ManifestSHA256}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("retained releases = %v, want %v", got, want)
	}
	pointers, err := manager.Pointers()
	if err != nil || pointers.CurrentDigest != commands[3].Bundle.ManifestSHA256 || pointers.PreviousDigest != commands[2].Bundle.ManifestSHA256 {
		t.Fatalf("Pointers() = (%+v, %v)", pointers, err)
	}
}

func TestRestartRemovesOnlyAbandonedStagingDirectory(t *testing.T) {
	manager, root := newTestManager(t, &fakePrechecker{failFor: map[string]error{}}, &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}})
	abandoned := filepath.Join(root, "staging", strings.Repeat("a", 64)+"-partial")
	if err := os.Mkdir(abandoned, 0o700); err != nil {
		t.Fatalf("Mkdir(abandoned) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(abandoned, "partial"), []byte("secret"), 0o600); err != nil {
		t.Fatalf("WriteFile(partial) error = %v", err)
	}
	if _, err := NewManager(root, manager.prechecker, manager.runtime); err != nil {
		t.Fatalf("NewManager(restart) error = %v", err)
	}
	if _, err := os.Stat(abandoned); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("abandoned staging stat error = %v", err)
	}
}

func TestJournalDoesNotContainBundleContent(t *testing.T) {
	manager, root := newTestManager(t, &fakePrechecker{failFor: map[string]error{}}, &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}})
	secret := "certificate-private-key-material"
	command := testCommand(t, "deploy-sensitive", 1, "cfg-sensitive", "", map[string][]byte{"secret.pem": []byte(secret)})
	if result, err := manager.Process(context.Background(), command); err != nil || result.State != StateHealthy {
		t.Fatalf("Process() = (%+v, %v)", result, err)
	}
	for _, path := range []string{filepath.Join(root, "state", "pointers.json"), manager.store.journalPath(command.DeploymentID)} {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", path, err)
		}
		if strings.Contains(string(content), secret) {
			t.Fatalf("state file %s contains bundle content", path)
		}
	}
}
