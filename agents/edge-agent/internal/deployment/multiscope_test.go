package deployment

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

const (
	testScopeA = "11111111-1111-4111-8111-111111111111"
	testScopeB = "22222222-2222-4222-8222-222222222222"
)

type fakeScopeRuntime struct {
	mu            sync.Mutex
	prechecks     []map[string]string
	reloads       []map[string]string
	precheckFail  map[string]error // scope+"/"+version
	healthFail    map[string]error // scope+"/"+version
	loaded        map[string]string
	missingRelase bool
}

func newFakeScopeRuntime() *fakeScopeRuntime {
	return &fakeScopeRuntime{precheckFail: map[string]error{}, healthFail: map[string]error{}, loaded: map[string]string{}}
}

func versions(releases map[string]ScopeRelease, t *fakeScopeRuntime) map[string]string {
	result := make(map[string]string, len(releases))
	for scope, release := range releases {
		if release.Path == "" || !filepath.IsAbs(release.Path) {
			t.missingRelase = true
		}
		result[scope] = release.ConfigVersionID
	}
	return result
}

func (f *fakeScopeRuntime) PrecheckComposition(_ context.Context, scopeID string, releases map[string]ScopeRelease) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prechecks = append(f.prechecks, versions(releases, f))
	return f.precheckFail[scopeID+"/"+releases[scopeID].ConfigVersionID]
}

func (f *fakeScopeRuntime) ReloadComposition(_ context.Context, releases map[string]ScopeRelease) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	composed := versions(releases, f)
	f.reloads = append(f.reloads, composed)
	f.loaded = composed
	return nil
}

func (f *fakeScopeRuntime) HealthyScope(_ context.Context, scopeID, versionID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.loaded[scopeID] != versionID {
		return errors.New("scope version is not loaded")
	}
	return f.healthFail[scopeID+"/"+versionID]
}

func (f *fakeScopeRuntime) lastReload() map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.reloads) == 0 {
		return nil
	}
	return f.reloads[len(f.reloads)-1]
}

func newTestMultiScopeManager(t *testing.T, runtime *fakeScopeRuntime, root string) *MultiScopeManager {
	t.Helper()
	if root == "" {
		root = filepath.Join(t.TempDir(), "agent-state")
	}
	config := DefaultConfig()
	config.HealthTimeout = 20 * time.Millisecond
	config.HealthInterval = time.Millisecond
	manager, err := NewMultiScopeManager(root, runtime, config)
	if err != nil {
		t.Fatalf("NewMultiScopeManager() error = %v", err)
	}
	t.Cleanup(func() { makeTreeWritable(root) })
	return manager
}

func processScope(t *testing.T, manager *MultiScopeManager, scopeID string, command Command, want State) Result {
	t.Helper()
	result, err := manager.Process(context.Background(), scopeID, command)
	if err != nil || result.State != want {
		t.Fatalf("Process(%s, %s) = (%+v, %v), want %s", scopeID, command.ConfigVersionID, result, err, want)
	}
	return result
}

func TestMultiScopeDeploymentsKeepIndependentPointers(t *testing.T) {
	runtime := newFakeScopeRuntime()
	manager := newTestMultiScopeManager(t, runtime, "")
	a1 := testCommand(t, "deploy-a1", 1, "cfg-a1", "", map[string][]byte{"nginx/site.conf": []byte("a1")})
	b1 := testCommand(t, "deploy-b1", 1, "cfg-b1", "", map[string][]byte{"nginx/site.conf": []byte("b1")})
	processScope(t, manager, testScopeA, a1, StateHealthy)
	processScope(t, manager, testScopeB, b1, StateHealthy)

	if got, want := runtime.lastReload(), map[string]string{testScopeA: "cfg-a1", testScopeB: "cfg-b1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("composition = %v, want %v", got, want)
	}
	if runtime.missingRelase {
		t.Fatal("composition carried a scope without an absolute release path")
	}
	pointersA, err := manager.Pointers(testScopeA)
	if err != nil || pointersA.Current != "cfg-a1" || pointersA.Previous != "" {
		t.Fatalf("Pointers(A) = (%+v, %v)", pointersA, err)
	}
	pointersB, err := manager.Pointers(testScopeB)
	if err != nil || pointersB.Current != "cfg-b1" {
		t.Fatalf("Pointers(B) = (%+v, %v)", pointersB, err)
	}
	if scopes := manager.Scopes(); !reflect.DeepEqual(scopes, []string{testScopeA, testScopeB}) {
		t.Fatalf("Scopes() = %v", scopes)
	}

	a2 := testCommand(t, "deploy-a2", 1, "cfg-a2", "cfg-a1", map[string][]byte{"nginx/site.conf": []byte("a2")})
	processScope(t, manager, testScopeA, a2, StateHealthy)
	pointersA, _ = manager.Pointers(testScopeA)
	if pointersA.Current != "cfg-a2" || pointersA.Previous != "cfg-a1" {
		t.Fatalf("Pointers(A) after a2 = %+v", pointersA)
	}
	if after, _ := manager.Pointers(testScopeB); after != pointersB {
		t.Fatalf("scope B pointers changed: %+v -> %+v", pointersB, after)
	}

	reopened := newTestMultiScopeManager(t, newFakeScopeRuntime(), manager.StateRoot())
	if got, _ := reopened.Pointers(testScopeA); got != pointersA {
		t.Fatalf("reopened Pointers(A) = %+v, want %+v", got, pointersA)
	}
	if scopes := reopened.Scopes(); !reflect.DeepEqual(scopes, []string{testScopeA, testScopeB}) {
		t.Fatalf("reopened Scopes() = %v", scopes)
	}
}

func TestMultiScopeHealthFailureRevertsOnlyFailingScope(t *testing.T) {
	runtime := newFakeScopeRuntime()
	manager := newTestMultiScopeManager(t, runtime, "")
	processScope(t, manager, testScopeA, testCommand(t, "deploy-a1", 1, "cfg-a1", "", map[string][]byte{"a.conf": []byte("a1")}), StateHealthy)
	processScope(t, manager, testScopeB, testCommand(t, "deploy-b1", 1, "cfg-b1", "", map[string][]byte{"b.conf": []byte("b1")}), StateHealthy)
	pointersA, _ := manager.Pointers(testScopeA)

	runtime.healthFail[testScopeB+"/cfg-b2"] = errors.New("unhealthy")
	b2 := testCommand(t, "deploy-b2", 1, "cfg-b2", "cfg-b1", map[string][]byte{"b.conf": []byte("b2")})
	processScope(t, manager, testScopeB, b2, StateReverted)

	if got, want := runtime.lastReload(), map[string]string{testScopeA: "cfg-a1", testScopeB: "cfg-b1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("composition after revert = %v, want %v", got, want)
	}
	if got, _ := manager.Pointers(testScopeB); got.Current != "cfg-b1" {
		t.Fatalf("Pointers(B) after revert = %+v", got)
	}
	if got, _ := manager.Pointers(testScopeA); got != pointersA {
		t.Fatalf("scope A pointers changed by B's failure: %+v -> %+v", pointersA, got)
	}
	for _, composition := range runtime.reloads {
		if composition[testScopeA] != "cfg-a1" {
			t.Fatalf("scope A left cfg-a1 during B's attempt: %v", runtime.reloads)
		}
	}
}

func TestMultiScopeFirstApplyFailureRemovesOnlyThatScope(t *testing.T) {
	runtime := newFakeScopeRuntime()
	manager := newTestMultiScopeManager(t, runtime, "")
	processScope(t, manager, testScopeA, testCommand(t, "deploy-a1", 1, "cfg-a1", "", map[string][]byte{"a.conf": []byte("a1")}), StateHealthy)

	runtime.healthFail[testScopeB+"/cfg-b1"] = errors.New("unhealthy")
	processScope(t, manager, testScopeB, testCommand(t, "deploy-b1", 1, "cfg-b1", "", map[string][]byte{"b.conf": []byte("b1")}), StateReverted)

	if got, want := runtime.lastReload(), map[string]string{testScopeA: "cfg-a1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("composition after first-apply failure = %v, want %v", got, want)
	}
	if got, err := manager.Pointers(testScopeB); err != nil || got != (Pointers{}) {
		t.Fatalf("Pointers(B) = (%+v, %v), want empty", got, err)
	}
}

func TestMultiScopePrecheckComposesCandidateWithOtherScopes(t *testing.T) {
	runtime := newFakeScopeRuntime()
	manager := newTestMultiScopeManager(t, runtime, "")
	processScope(t, manager, testScopeA, testCommand(t, "deploy-a1", 1, "cfg-a1", "", map[string][]byte{"a.conf": []byte("a1")}), StateHealthy)
	reloads := len(runtime.reloads)

	runtime.precheckFail[testScopeB+"/cfg-b1"] = errors.New("server_name conflict")
	result := processScope(t, manager, testScopeB, testCommand(t, "deploy-b1", 1, "cfg-b1", "", map[string][]byte{"b.conf": []byte("b1")}), StateFailed)
	if !result.RunningConfigUnchanged || result.ErrorCode != "PRECHECK_FAILED" {
		t.Fatalf("precheck failure result = %+v", result)
	}
	last := runtime.prechecks[len(runtime.prechecks)-1]
	if want := map[string]string{testScopeA: "cfg-a1", testScopeB: "cfg-b1"}; !reflect.DeepEqual(last, want) {
		t.Fatalf("precheck composition = %v, want %v", last, want)
	}
	if len(runtime.reloads) != reloads {
		t.Fatal("failed precheck reloaded the runtime")
	}
}

func TestMultiScopeCreatesNodeActivationLockAtStartup(t *testing.T) {
	manager := newTestMultiScopeManager(t, newFakeScopeRuntime(), "")
	info, err := os.Lstat(filepath.Join(manager.StateRoot(), "node-activation.lock"))
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("node activation lock = (%v, %v), want a regular file before any apply", info, err)
	}
}

func TestMultiScopeRejectsInvalidScope(t *testing.T) {
	manager := newTestMultiScopeManager(t, newFakeScopeRuntime(), "")
	command := testCommand(t, "deploy-x", 1, "cfg-x", "", map[string][]byte{"x.conf": []byte("x")})
	for _, scope := range []string{"", "../escape", "SCOPE", "00000000-0000-0000-0000-000000000000", "11111111-1111-4111-8111-11111111111A"} {
		if _, err := manager.Process(context.Background(), scope, command); err == nil {
			t.Fatalf("scope %q was accepted", scope)
		}
	}
	if _, err := manager.Pointers("../escape"); err == nil {
		t.Fatal("Pointers accepted an unsafe scope")
	}
}

func TestScopedManagerRoutesCommandsAndLooksUpAcrossScopes(t *testing.T) {
	runtime := newFakeScopeRuntime()
	scoped := newTestMultiScopeManager(t, runtime, "").ScopedManager()
	a1 := testCommand(t, "deploy-a1", 1, "cfg-a1", "", map[string][]byte{"a.conf": []byte("a1")})
	a1.ScopeID = testScopeA
	b1 := testCommand(t, "deploy-b1", 1, "cfg-b1", "", map[string][]byte{"b.conf": []byte("b1")})
	b1.ScopeID = testScopeB
	for _, command := range []Command{a1, b1} {
		if result, err := scoped.Process(context.Background(), command); err != nil || result.State != StateHealthy {
			t.Fatalf("Process(%s) = (%+v, %v)", command.ScopeID, result, err)
		}
	}
	unscoped := testCommand(t, "deploy-x", 1, "cfg-x", "", map[string][]byte{"x.conf": []byte("x")})
	if _, err := scoped.Process(context.Background(), unscoped); err == nil {
		t.Fatal("an unscoped command was accepted by the multi-scope manager")
	}
	if pointers, err := scoped.ScopePointers(testScopeB); err != nil || pointers.Current != "cfg-b1" {
		t.Fatalf("ScopePointers(B) = (%+v, %v)", pointers, err)
	}
	if result, found, err := scoped.Lookup("deploy-b1"); err != nil || !found || result.ConfigVersionID != "cfg-b1" {
		t.Fatalf("Lookup(deploy-b1) = (%+v, %v, %v)", result, found, err)
	}
	if _, found, err := scoped.Lookup("deploy-missing"); err != nil || found {
		t.Fatalf("Lookup(missing) = (%v, %v)", found, err)
	}
	// Two scopes have no single node-wide pointer pair.
	if pointers, err := scoped.Pointers(); err != nil || pointers != (Pointers{}) {
		t.Fatalf("Pointers() with two scopes = (%+v, %v), want empty", pointers, err)
	}
	if got := scoped.Scopes(); !reflect.DeepEqual(got, []string{testScopeA, testScopeB}) {
		t.Fatalf("Scopes() = %v", got)
	}
}
