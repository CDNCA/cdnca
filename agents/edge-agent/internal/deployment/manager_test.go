package deployment

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"
)

type fakePrechecker struct {
	mu      sync.Mutex
	calls   []string
	failFor map[string]error
}

func (f *fakePrechecker) Precheck(_ context.Context, version, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, version)
	return f.failFor[version]
}

type fakeRuntime struct {
	mu                 sync.Mutex
	activations        []string
	healthChecks       []string
	activationFailures map[string]map[int]error
	healthFailures     map[string]error
	activateStarted    chan struct{}
	releaseActivate    chan struct{}
}

func (f *fakeRuntime) Reload(_ context.Context, versionID, _ string) error {
	f.mu.Lock()
	f.activations = append(f.activations, versionID)
	call := 0
	for _, version := range f.activations {
		if version == versionID {
			call++
		}
	}
	err := f.activationFailures[versionID][call]
	started := f.activateStarted
	release := f.releaseActivate
	if started != nil {
		f.activateStarted = nil
	}
	f.mu.Unlock()
	if started != nil {
		close(started)
		<-release
	}
	return err
}

func (f *fakeRuntime) Healthy(_ context.Context, versionID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.healthChecks = append(f.healthChecks, versionID)
	return f.healthFailures[versionID]
}

func (f *fakeRuntime) activationList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.activations...)
}

func newTestManager(t *testing.T, prechecker *fakePrechecker, runtime *fakeRuntime) (*Manager, string) {
	t.Helper()
	parent := t.TempDir()
	root := filepath.Join(parent, "agent-state")
	config := DefaultConfig()
	config.HealthTimeout = 20 * time.Millisecond
	config.HealthInterval = time.Millisecond
	manager, err := NewManagerWithConfig(root, prechecker, runtime, config)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	t.Cleanup(func() { makeTreeWritable(root) })
	return manager, root
}

func testCommand(t *testing.T, deploymentID string, attempt uint32, versionID, previousVersionID string, files map[string][]byte) Command {
	t.Helper()
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	manifest := Manifest{Files: make([]FileManifest, 0, len(paths))}
	for _, path := range paths {
		sum := sha256.Sum256(files[path])
		manifest.Files = append(manifest.Files, FileManifest{
			Path:   path,
			Size:   int64(len(files[path])),
			SHA256: hex.EncodeToString(sum[:]),
		})
	}
	digest, err := ManifestDigest(manifest)
	if err != nil {
		t.Fatalf("ManifestDigest() error = %v", err)
	}
	return Command{
		DeploymentID:      deploymentID,
		Attempt:           attempt,
		Action:            ActionApply,
		ConfigVersionID:   versionID,
		PreviousVersionID: previousVersionID,
		Bundle: Bundle{
			Manifest:       manifest,
			ManifestSHA256: digest,
			Files:          files,
		},
	}
}

func deployHealthyV1(t *testing.T, manager *Manager) Command {
	t.Helper()
	command := testCommand(t, "deploy-v1", 1, "cfg-v1", "", map[string][]byte{"nginx/site.conf": []byte("v1")})
	result, err := manager.Process(context.Background(), command)
	if err != nil {
		t.Fatalf("Process(v1) error = %v", err)
	}
	if result.State != StateHealthy {
		t.Fatalf("Process(v1) state = %q, want %q", result.State, StateHealthy)
	}
	return command
}

func states(result Result) []State {
	resultStates := make([]State, len(result.Transitions))
	for i, transition := range result.Transitions {
		resultStates[i] = transition.State
	}
	return resultStates
}

func TestSuccessfulDeployment(t *testing.T) {
	prechecker := &fakePrechecker{failFor: map[string]error{}}
	runtime := &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}}
	manager, root := newTestManager(t, prechecker, runtime)
	command := testCommand(t, "deploy-success", 1, "cfg-v1", "", map[string][]byte{
		"nginx/site.conf": []byte("server {}"),
		"waf/rules.json":  []byte(`{"enabled":true}`),
	})

	result, err := manager.Process(context.Background(), command)
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	wantStates := []State{StateDelivered, StateStaged, StatePrechecked, StateActivated, StateHealthy}
	if !reflect.DeepEqual(states(result), wantStates) {
		t.Fatalf("result = %+v; states = %v, want %v", result, states(result), wantStates)
	}
	for i, transition := range result.Transitions {
		if transition.Sequence != uint64(i+1) {
			t.Fatalf("transition %d sequence = %d", i, transition.Sequence)
		}
	}
	pointers, err := manager.Pointers()
	if err != nil {
		t.Fatalf("Pointers() error = %v", err)
	}
	if pointers != (Pointers{Current: "cfg-v1", CurrentDigest: command.Bundle.ManifestSHA256}) {
		t.Fatalf("pointers = %+v", pointers)
	}
	content, err := os.ReadFile(filepath.Join(root, "releases", command.Bundle.ManifestSHA256, "nginx", "site.conf"))
	if err != nil {
		t.Fatalf("ReadFile(release) error = %v", err)
	}
	if string(content) != "server {}" {
		t.Fatalf("release content = %q", content)
	}
}

func TestManifestAndContentHashErrors(t *testing.T) {
	t.Run("manifest digest", func(t *testing.T) {
		manager, _ := newTestManager(t, &fakePrechecker{failFor: map[string]error{}}, &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}})
		command := testCommand(t, "deploy-bad-manifest", 1, "cfg-bad-manifest", "", map[string][]byte{"site.conf": []byte("ok")})
		command.Bundle.ManifestSHA256 = stringsOf("0", sha256.Size*2)

		result, err := manager.Process(context.Background(), command)
		if err != nil {
			t.Fatalf("Process() error = %v", err)
		}
		if result.State != StateFailed || result.ErrorCode != "DIGEST_MISMATCH" || !result.RunningConfigUnchanged {
			t.Fatalf("result = %+v", result)
		}
	})

	t.Run("file content digest", func(t *testing.T) {
		manager, root := newTestManager(t, &fakePrechecker{failFor: map[string]error{}}, &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}})
		command := testCommand(t, "deploy-bad-content", 1, "cfg-bad-content", "", map[string][]byte{"site.conf": []byte("expected")})
		command.Bundle.Files["site.conf"] = []byte("tampered")

		if _, err := manager.Process(context.Background(), command); !errors.Is(err, ErrInvalidCommand) {
			t.Fatalf("Process() error = %v, want ErrInvalidCommand", err)
		}
		if pointers, err := manager.Pointers(); err != nil || pointers != (Pointers{}) {
			t.Fatalf("Pointers() = (%+v, %v), want empty", pointers, err)
		}
		for _, directory := range []string{"releases", "staging", filepath.Join("state", "journal")} {
			entries, err := os.ReadDir(filepath.Join(root, directory))
			if err != nil || len(entries) != 0 {
				t.Fatalf("%s entries = %v, error = %v", directory, entries, err)
			}
		}
		if _, err := os.Lstat(filepath.Join(root, "current")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("current pointer stat error = %v, want not exist", err)
		}
	})
}

func TestPathEscapeRejected(t *testing.T) {
	manager, root := newTestManager(t, &fakePrechecker{failFor: map[string]error{}}, &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}})
	command := Command{
		DeploymentID:    "deploy-escape",
		Attempt:         1,
		Action:          ActionApply,
		ConfigVersionID: "cfg-v1",
		Bundle: Bundle{
			Manifest:       Manifest{Files: []FileManifest{{Path: "../escaped", Size: 1, SHA256: stringsOf("0", 64)}}},
			ManifestSHA256: stringsOf("0", 64),
			Files:          map[string][]byte{"../escaped": []byte("x")},
		},
	}

	if _, err := manager.Process(context.Background(), command); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("Process() error = %v, want ErrInvalidPath", err)
	}
	if _, err := os.Stat(filepath.Join(root, "escaped")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("escaped file stat error = %v", err)
	}

	command = testCommand(t, "deploy-version-escape", 1, "cfg-v1", "", map[string][]byte{"site.conf": []byte("ok")})
	command.ConfigVersionID = "../outside"
	if _, err := manager.Process(context.Background(), command); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("Process(version escape) error = %v, want ErrInvalidPath", err)
	}
}

func stringsOf(value string, count int) string {
	result := ""
	for i := 0; i < count; i++ {
		result += value
	}
	return result
}

func TestDuplicateCommandIsIdempotent(t *testing.T) {
	runtime := &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}}
	manager, _ := newTestManager(t, &fakePrechecker{failFor: map[string]error{}}, runtime)
	command := testCommand(t, "deploy-duplicate", 1, "cfg-v1", "", map[string][]byte{"site.conf": []byte("v1")})

	first, err := manager.Process(context.Background(), command)
	if err != nil {
		t.Fatalf("first Process() error = %v", err)
	}
	second, err := manager.Process(context.Background(), command)
	if err != nil {
		t.Fatalf("second Process() error = %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("duplicate result differs\nfirst: %+v\nsecond: %+v", first, second)
	}
	if got := runtime.activationList(); !reflect.DeepEqual(got, []string{"cfg-v1"}) {
		t.Fatalf("activations = %v", got)
	}
}

func TestSameAttemptDifferentPayloadConflicts(t *testing.T) {
	manager, _ := newTestManager(t, &fakePrechecker{failFor: map[string]error{}}, &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}})
	first := testCommand(t, "deploy-conflict", 1, "cfg-v1", "", map[string][]byte{"site.conf": []byte("v1")})
	if _, err := manager.Process(context.Background(), first); err != nil {
		t.Fatalf("first Process() error = %v", err)
	}
	conflict := testCommand(t, "deploy-conflict", 1, "cfg-v2", "cfg-v1", map[string][]byte{"site.conf": []byte("v2")})
	if _, err := manager.Process(context.Background(), conflict); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting Process() error = %v, want ErrConflict", err)
	}
}

func TestOldAttemptRejected(t *testing.T) {
	manager, _ := newTestManager(t, &fakePrechecker{failFor: map[string]error{}}, &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}})
	current := testCommand(t, "deploy-stale", 2, "cfg-v1", "", map[string][]byte{"site.conf": []byte("v1")})
	if _, err := manager.Process(context.Background(), current); err != nil {
		t.Fatalf("current Process() error = %v", err)
	}
	stale := current
	stale.Attempt = 1
	if _, err := manager.Process(context.Background(), stale); !errors.Is(err, ErrStaleAttempt) {
		t.Fatalf("stale Process() error = %v, want ErrStaleAttempt", err)
	}
}

func TestPrecheckFailureLeavesCurrentUnchanged(t *testing.T) {
	prechecker := &fakePrechecker{failFor: map[string]error{"cfg-v2": errors.New("invalid config containing a secret")}}
	runtime := &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}}
	manager, _ := newTestManager(t, prechecker, runtime)
	deployHealthyV1(t, manager)
	command := testCommand(t, "deploy-v2", 1, "cfg-v2", "cfg-v1", map[string][]byte{"site.conf": []byte("v2")})

	result, err := manager.Process(context.Background(), command)
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if !reflect.DeepEqual(states(result), []State{StateDelivered, StateStaged, StateFailed}) || !result.RunningConfigUnchanged {
		t.Fatalf("result = %+v", result)
	}
	if result.Summary != "release precheck failed" {
		t.Fatalf("summary = %q", result.Summary)
	}
	pointers, err := manager.Pointers()
	if err != nil {
		t.Fatalf("Pointers() error = %v", err)
	}
	if pointers.Current != "cfg-v1" {
		t.Fatalf("current = %q, want cfg-v1", pointers.Current)
	}
	if got := runtime.activationList(); !reflect.DeepEqual(got, []string{"cfg-v1"}) {
		t.Fatalf("activations = %v", got)
	}
}

func TestHealthFailureRollsBack(t *testing.T) {
	runtime := &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{"cfg-v2": errors.New("unhealthy")}}
	manager, _ := newTestManager(t, &fakePrechecker{failFor: map[string]error{}}, runtime)
	previousCommand := deployHealthyV1(t, manager)
	command := testCommand(t, "deploy-v2", 1, "cfg-v2", "cfg-v1", map[string][]byte{"site.conf": []byte("v2")})

	result, err := manager.Process(context.Background(), command)
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	wantStates := []State{StateDelivered, StateStaged, StatePrechecked, StateActivated, StateReverting, StateReverted}
	if !reflect.DeepEqual(states(result), wantStates) {
		t.Fatalf("states = %v, want %v", states(result), wantStates)
	}
	if got := runtime.activationList(); !reflect.DeepEqual(got, []string{"cfg-v1", "cfg-v2", "cfg-v1"}) {
		t.Fatalf("activations = %v", got)
	}
	pointers, err := manager.Pointers()
	if err != nil {
		t.Fatalf("Pointers() error = %v", err)
	}
	if pointers != (Pointers{Current: "cfg-v1", CurrentDigest: previousCommand.Bundle.ManifestSHA256}) {
		t.Fatalf("pointers = %+v", pointers)
	}
}

func TestRollbackFailure(t *testing.T) {
	runtime := &fakeRuntime{
		activationFailures: map[string]map[int]error{"cfg-v1": {2: errors.New("reload failed")}},
		healthFailures:     map[string]error{"cfg-v2": errors.New("unhealthy")},
	}
	manager, root := newTestManager(t, &fakePrechecker{failFor: map[string]error{}}, runtime)
	previousCommand := deployHealthyV1(t, manager)
	command := testCommand(t, "deploy-v2", 1, "cfg-v2", "cfg-v1", map[string][]byte{"site.conf": []byte("v2")})

	result, err := manager.Process(context.Background(), command)
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	wantStates := []State{StateDelivered, StateStaged, StatePrechecked, StateActivated, StateReverting, StateRollbackFailed}
	if !reflect.DeepEqual(states(result), wantStates) {
		t.Fatalf("states = %v, want %v", states(result), wantStates)
	}
	if result.ErrorCode != "ROLLBACK_ACTIVATION_FAILED" {
		t.Fatalf("error code = %q", result.ErrorCode)
	}
	pointers, err := manager.Pointers()
	if err != nil {
		t.Fatalf("Pointers() error = %v", err)
	}
	if pointers != (Pointers{
		Current:        "cfg-v2",
		CurrentDigest:  command.Bundle.ManifestSHA256,
		Previous:       "cfg-v1",
		PreviousDigest: previousCommand.Bundle.ManifestSHA256,
	}) {
		t.Fatalf("pointers = %+v", pointers)
	}
	target, err := os.Readlink(filepath.Join(root, "current"))
	if err != nil || target != filepath.Join("releases", command.Bundle.ManifestSHA256) {
		t.Fatalf("current target = %q, error = %v", target, err)
	}
}

func TestRestartLoadsJournalAndPointers(t *testing.T) {
	prechecker := &fakePrechecker{failFor: map[string]error{}}
	runtime := &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}}
	manager, root := newTestManager(t, prechecker, runtime)
	command := testCommand(t, "deploy-restart", 1, "cfg-v1", "", map[string][]byte{"site.conf": []byte("v1")})
	want, err := manager.Process(context.Background(), command)
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}

	restartedRuntime := &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}}
	restarted, err := NewManager(root, &fakePrechecker{failFor: map[string]error{}}, restartedRuntime)
	if err != nil {
		t.Fatalf("NewManager(restart) error = %v", err)
	}
	got, found, err := restarted.Lookup(command.DeploymentID)
	if err != nil || !found {
		t.Fatalf("Lookup() = (%+v, %t, %v)", got, found, err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Lookup() = %+v, want %+v", got, want)
	}
	duplicate, err := restarted.Process(context.Background(), command)
	if err != nil {
		t.Fatalf("Process(duplicate after restart) error = %v", err)
	}
	if !reflect.DeepEqual(duplicate, want) {
		t.Fatalf("duplicate = %+v, want %+v", duplicate, want)
	}
	if got := restartedRuntime.activationList(); len(got) != 0 {
		t.Fatalf("restart repeated activation: %v", got)
	}
	pointers, err := restarted.Pointers()
	if err != nil || pointers.Current != "cfg-v1" {
		t.Fatalf("Pointers() = (%+v, %v)", pointers, err)
	}
}

func TestRestartResumesPersistedActivationPhase(t *testing.T) {
	prechecker := &fakePrechecker{failFor: map[string]error{}}
	runtime := &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}}
	manager, root := newTestManager(t, prechecker, runtime)
	command := testCommand(t, "deploy-resume", 1, "cfg-v1", "", map[string][]byte{"site.conf": []byte("v1")})
	normalized, digest, err := validateAndDigest(command)
	if err != nil {
		t.Fatalf("validateAndDigest() error = %v", err)
	}
	if _, err := manager.store.stage(command, normalized); err != nil {
		t.Fatalf("stage() error = %v", err)
	}
	value := &journal{
		Version:      journalVersion,
		DeploymentID: command.DeploymentID,
		Attempts: []attemptRecord{{
			Attempt:           command.Attempt,
			Action:            command.Action,
			CommandDigest:     digest,
			ConfigVersionID:   command.ConfigVersionID,
			PreviousVersionID: command.PreviousVersionID,
			ManifestSHA256:    command.Bundle.ManifestSHA256,
			Phase:             phaseActivate,
			PriorPointersSet:  true,
			Transitions: []Transition{
				{Sequence: 1, State: StateDelivered, At: manager.now().UTC()},
				{Sequence: 2, State: StateStaged, At: manager.now().UTC()},
				{Sequence: 3, State: StatePrechecked, At: manager.now().UTC()},
			},
		}},
	}
	if err := manager.store.saveJournal(value); err != nil {
		t.Fatalf("saveJournal() error = %v", err)
	}
	// This is the crash window after the desired pointer was persisted but before
	// the activated transition reached the journal.
	desired := Pointers{Current: command.ConfigVersionID, CurrentDigest: command.Bundle.ManifestSHA256}
	if err := manager.store.switchCurrent(command.Bundle.ManifestSHA256); err != nil {
		t.Fatalf("switchCurrent() error = %v", err)
	}
	if err := manager.store.savePointers(desired); err != nil {
		t.Fatalf("savePointers() error = %v", err)
	}

	restartedRuntime := &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}}
	restarted, err := NewManager(root, &fakePrechecker{failFor: map[string]error{}}, restartedRuntime)
	if err != nil {
		t.Fatalf("NewManager(restart) error = %v", err)
	}
	result, err := restarted.Process(context.Background(), command)
	if err != nil {
		t.Fatalf("Process(resume) error = %v", err)
	}
	wantStates := []State{StateDelivered, StateStaged, StatePrechecked, StateActivated, StateHealthy}
	if !reflect.DeepEqual(states(result), wantStates) {
		t.Fatalf("states = %v, want %v", states(result), wantStates)
	}
	if got := restartedRuntime.activationList(); !reflect.DeepEqual(got, []string{"cfg-v1"}) {
		t.Fatalf("resume activations = %v", got)
	}
}

func TestRestartActivationUncertaintyForcesRollback(t *testing.T) {
	manager, root := newTestManager(t, &fakePrechecker{failFor: map[string]error{}}, &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}})
	previousCommand := deployHealthyV1(t, manager)
	command := testCommand(t, "deploy-resume-v2", 1, "cfg-v2", "cfg-v1", map[string][]byte{"site.conf": []byte("v2")})
	normalized, digest, err := validateAndDigest(command)
	if err != nil {
		t.Fatalf("validateAndDigest() error = %v", err)
	}
	if _, err := manager.store.stage(command, normalized); err != nil {
		t.Fatalf("stage() error = %v", err)
	}
	prior := Pointers{Current: "cfg-v1", CurrentDigest: previousCommand.Bundle.ManifestSHA256}
	value := &journal{
		Version:      journalVersion,
		DeploymentID: command.DeploymentID,
		Attempts: []attemptRecord{{
			Attempt:           command.Attempt,
			Action:            command.Action,
			CommandDigest:     digest,
			ConfigVersionID:   command.ConfigVersionID,
			PreviousVersionID: command.PreviousVersionID,
			ManifestSHA256:    command.Bundle.ManifestSHA256,
			Phase:             phaseActivate,
			PriorPointersSet:  true,
			PriorPointers:     prior,
			Transitions: []Transition{
				{Sequence: 1, State: StateDelivered, At: manager.now().UTC()},
				{Sequence: 2, State: StateStaged, At: manager.now().UTC()},
				{Sequence: 3, State: StatePrechecked, At: manager.now().UTC()},
			},
		}},
	}
	if err := manager.store.saveJournal(value); err != nil {
		t.Fatalf("saveJournal() error = %v", err)
	}
	desired := Pointers{
		Current:        "cfg-v2",
		CurrentDigest:  command.Bundle.ManifestSHA256,
		Previous:       "cfg-v1",
		PreviousDigest: previousCommand.Bundle.ManifestSHA256,
	}
	if err := manager.store.switchCurrent(command.Bundle.ManifestSHA256); err != nil {
		t.Fatalf("switchCurrent() error = %v", err)
	}
	if err := manager.store.savePointers(desired); err != nil {
		t.Fatalf("savePointers() error = %v", err)
	}

	restartedRuntime := &fakeRuntime{
		activationFailures: map[string]map[int]error{"cfg-v2": {1: errors.New("activation status unknown")}},
		healthFailures:     map[string]error{},
	}
	restarted, err := NewManager(root, &fakePrechecker{failFor: map[string]error{}}, restartedRuntime)
	if err != nil {
		t.Fatalf("NewManager(restart) error = %v", err)
	}
	result, err := restarted.Process(context.Background(), command)
	if err != nil {
		t.Fatalf("Process(resume) error = %v", err)
	}
	wantStates := []State{StateDelivered, StateStaged, StatePrechecked, StateActivated, StateReverting, StateReverted}
	if !reflect.DeepEqual(states(result), wantStates) {
		t.Fatalf("states = %v, want %v", states(result), wantStates)
	}
	if got := restartedRuntime.activationList(); !reflect.DeepEqual(got, []string{"cfg-v2", "cfg-v1"}) {
		t.Fatalf("resume activations = %v", got)
	}
	pointers, err := restarted.Pointers()
	if err != nil || pointers != prior {
		t.Fatalf("Pointers() = (%+v, %v), want %+v", pointers, err, prior)
	}
}

func TestConcurrentDuplicateDoesNotActivateTwice(t *testing.T) {
	runtime := &fakeRuntime{
		activationFailures: map[string]map[int]error{},
		healthFailures:     map[string]error{},
		activateStarted:    make(chan struct{}),
		releaseActivate:    make(chan struct{}),
	}
	activateStarted := runtime.activateStarted
	manager, _ := newTestManager(t, &fakePrechecker{failFor: map[string]error{}}, runtime)
	command := testCommand(t, "deploy-concurrent", 1, "cfg-v1", "", map[string][]byte{"site.conf": []byte("v1")})

	type response struct {
		result Result
		err    error
	}
	responses := make(chan response, 2)
	go func() {
		result, err := manager.Process(context.Background(), command)
		responses <- response{result: result, err: err}
	}()
	<-activateStarted
	go func() {
		result, err := manager.Process(context.Background(), command)
		responses <- response{result: result, err: err}
	}()
	close(runtime.releaseActivate)
	for range 2 {
		response := <-responses
		if response.err != nil || response.result.State != StateHealthy {
			t.Fatalf("Process() = (%+v, %v)", response.result, response.err)
		}
	}
	if got := runtime.activationList(); !reflect.DeepEqual(got, []string{"cfg-v1"}) {
		t.Fatalf("activations = %v", got)
	}
}

func TestMaliciousCoreDirectorySymlinkRejected(t *testing.T) {
	prechecker := &fakePrechecker{failFor: map[string]error{}}
	runtime := &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}}
	manager, root := newTestManager(t, prechecker, runtime)
	outside := t.TempDir()
	releases := filepath.Join(root, "releases")
	if err := os.Remove(releases); err != nil {
		t.Fatalf("Remove(releases) error = %v", err)
	}
	if err := os.Symlink(outside, releases); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	command := testCommand(t, "deploy-symlink", 1, "cfg-v1", "", map[string][]byte{"site.conf": []byte("v1")})

	if _, err := manager.Process(context.Background(), command); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("Process() error = %v, want ErrInvalidPath", err)
	}
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatalf("ReadDir(outside) error = %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("outside directory was modified: %v", entries)
	}
}

func TestStateRootValidation(t *testing.T) {
	prechecker := &fakePrechecker{failFor: map[string]error{}}
	runtime := &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}}
	for _, root := range []string{"", ".", string(filepath.Separator)} {
		if _, err := NewManager(root, prechecker, runtime); !errors.Is(err, ErrInvalidPath) {
			t.Errorf("NewManager(%q) error = %v, want ErrInvalidPath", root, err)
		}
	}
}
