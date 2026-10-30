package certstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeRuntime struct {
	mu                 sync.Mutex
	precheckError      error
	precheckFailures   int
	activationFailures int
	healthFailures     int
	prechecks          int
	activations        int
	healthChecks       int
	stops              int
}

type recoveryRuntime struct {
	mu               sync.Mutex
	precheckErrors   map[string][]error
	activationErrors map[string][]error
	healthErrors     map[string][]error
	onPrecheck       func(string)
	onHealthy        func(string)
	activeTarget     string
	calls            []string
	healthCalls      []recoveryHealthCall
}

type recoveryHealthCall struct {
	target  string
	targets []HealthTarget
}

func (runtime *recoveryRuntime) Precheck(_ context.Context, path string) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	target := filepath.Base(path)
	runtime.calls = append(runtime.calls, "precheck:"+target)
	if runtime.onPrecheck != nil {
		runtime.onPrecheck(target)
	}
	return popRecoveryError(runtime.precheckErrors, target)
}

func (runtime *recoveryRuntime) Activate(_ context.Context, path string) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	target, err := os.Readlink(path)
	if err != nil {
		return err
	}
	target = filepath.Base(target)
	runtime.calls = append(runtime.calls, "activate:"+target)
	if err := popRecoveryError(runtime.activationErrors, target); err != nil {
		return err
	}
	runtime.activeTarget = target
	return nil
}

func (runtime *recoveryRuntime) Healthy(_ context.Context, targets []HealthTarget) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.calls = append(runtime.calls, "healthy:"+runtime.activeTarget)
	runtime.healthCalls = append(runtime.healthCalls, recoveryHealthCall{
		target: runtime.activeTarget, targets: cloneHealthTargets(targets),
	})
	if runtime.onHealthy != nil {
		runtime.onHealthy(runtime.activeTarget)
	}
	return popRecoveryError(runtime.healthErrors, runtime.activeTarget)
}

func (runtime *recoveryRuntime) Stop(context.Context, string) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.calls = append(runtime.calls, "stop:"+runtime.activeTarget)
	runtime.activeTarget = ""
	return nil
}

func popRecoveryError(script map[string][]error, target string) error {
	if len(script[target]) == 0 {
		return nil
	}
	err := script[target][0]
	script[target] = script[target][1:]
	return err
}

func (runtime *fakeRuntime) Precheck(context.Context, string) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.prechecks++
	if runtime.precheckError != nil {
		return runtime.precheckError
	}
	if runtime.precheckFailures > 0 {
		runtime.precheckFailures--
		return errors.New("precheck failed")
	}
	return nil
}

func (runtime *fakeRuntime) Activate(context.Context, string) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.activations++
	if runtime.activationFailures > 0 {
		runtime.activationFailures--
		return errors.New("activation failed")
	}
	return nil
}

func (runtime *fakeRuntime) Healthy(context.Context, []HealthTarget) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.healthChecks++
	if runtime.healthFailures > 0 {
		runtime.healthFailures--
		return errors.New("health failed")
	}
	return nil
}

func (runtime *fakeRuntime) Stop(context.Context, string) error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.stops++
	return nil
}

func TestManagerAppliesIdempotentlyAndRecoversFromDisk(t *testing.T) {
	root := managedStateRoot(t)
	config := RuntimeConfig{StateRoot: root, ListenAddress: "127.0.0.1", ListenPort: 18443}
	runtime := &fakeRuntime{}
	manager, err := newManager(config, runtime, func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	bundle := validTestBundle(t, "v1", "one.example.test")
	result, err := manager.Apply(context.Background(), bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || result.ActiveVersionID != "v1" || result.ActiveDigest == "" {
		t.Fatalf("Apply() result = %#v", result)
	}
	idempotent, err := manager.Apply(context.Background(), bundle)
	if err != nil {
		t.Fatal(err)
	}
	if idempotent.Changed || !idempotent.RunningVersionUnchanged {
		t.Fatalf("idempotent Apply() result = %#v", idempotent)
	}

	restartedRuntime := &fakeRuntime{}
	restarted, err := newManager(config, restartedRuntime, func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := restarted.Recover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if recovered.ActiveDigest != result.ActiveDigest || restartedRuntime.prechecks != 1 || restartedRuntime.activations != 1 || restartedRuntime.healthChecks != 1 {
		t.Fatalf("Recover() result=%#v runtime=%#v", recovered, restartedRuntime)
	}
	status, err := restarted.Status(context.Background())
	if err != nil || !status.Active || status.Digest != result.ActiveDigest {
		t.Fatalf("Status() = %#v, %v", status, err)
	}
	statusJSON, err := os.ReadFile(filepath.Join(root, "status.json"))
	if err != nil {
		t.Fatal(err)
	}
	if json.Valid(statusJSON) == false || containsPrivateKey(statusJSON) {
		t.Fatalf("unsafe status JSON: %s", statusJSON)
	}
}

func TestManagerRecoverPristineStateIsNoOp(t *testing.T) {
	runtime := &fakeRuntime{}
	manager, err := newManager(RuntimeConfig{
		StateRoot:     managedStateRoot(t),
		ListenAddress: "127.0.0.1",
		ListenPort:    18443,
	}, runtime, func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}

	result, err := manager.Recover(context.Background())
	if err != nil {
		t.Fatalf("Recover() pristine state error = %v", err)
	}
	if result != (Result{}) {
		t.Fatalf("Recover() pristine state result = %#v", result)
	}
	if runtime.prechecks != 0 || runtime.activations != 0 || runtime.healthChecks != 0 {
		t.Fatalf("Recover() pristine state touched runtime: %#v", runtime)
	}
}

func TestManagerRecoverRejectsIncompleteState(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(string) error
	}{
		{name: "orphan-release", mutate: func(root string) error {
			return os.Mkdir(filepath.Join(root, "versions", "orphan"), 0o700)
		}},
		{name: "orphan-pid", mutate: func(root string) error {
			return os.WriteFile(filepath.Join(root, "shared", "nginx.pid"), []byte("123\n"), 0o600)
		}},
		{name: "unexpected-root-entry", mutate: func(root string) error {
			return os.WriteFile(filepath.Join(root, "unexpected"), nil, 0o600)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := managedStateRoot(t)
			runtime := &fakeRuntime{}
			manager, err := newManager(RuntimeConfig{
				StateRoot: root, ListenAddress: "127.0.0.1", ListenPort: 18443,
			}, runtime, func() time.Time { return testNow })
			if err != nil {
				t.Fatal(err)
			}
			if err := test.mutate(root); err != nil {
				t.Fatal(err)
			}
			if _, err := manager.Recover(context.Background()); !errors.Is(err, ErrUnsafeState) {
				t.Fatalf("Recover() incomplete state error = %v, want ErrUnsafeState", err)
			}
			if runtime.prechecks != 0 || runtime.activations != 0 || runtime.healthChecks != 0 {
				t.Fatalf("Recover() incomplete state touched runtime: %#v", runtime)
			}
		})
	}
}

func TestManagerRecoverPreservesCancellationAndFallsBackToLKG(t *testing.T) {
	root := managedStateRoot(t)
	config := RuntimeConfig{StateRoot: root, ListenAddress: "127.0.0.1", ListenPort: 18443}
	manager, err := newManager(config, &fakeRuntime{}, func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Apply(context.Background(), validTestBundle(t, "v1", "one.example.test")); err != nil {
		t.Fatal(err)
	}
	v1Target, err := os.Readlink(filepath.Join(root, "current"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Apply(context.Background(), validTestBundle(t, "v2", "two.example.test")); err != nil {
		t.Fatal(err)
	}
	v2Target, err := os.Readlink(filepath.Join(root, "current"))
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.store.setPointer("lkg", v1Target); err != nil {
		t.Fatal(err)
	}

	cancelled, err := newManager(config, &fakeRuntime{precheckError: context.Canceled}, func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cancelled.Recover(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("Recover() cancellation error = %v", err)
	}

	fallbackRuntime := &fakeRuntime{precheckFailures: 1}
	fallback, err := newManager(config, fallbackRuntime, func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	result, err := fallback.Recover(context.Background())
	if err != nil || result.VersionID != "v1" || fallbackRuntime.prechecks != 2 ||
		fallbackRuntime.activations != 1 || fallbackRuntime.healthChecks != 1 {
		t.Fatalf("Recover() fallback result=%#v runtime=%#v error=%v", result, fallbackRuntime, err)
	}

	if err := manager.store.setPointer("current", v2Target); err != nil {
		t.Fatal(err)
	}
	if err := manager.store.setPointer("lkg", v1Target); err != nil {
		t.Fatal(err)
	}
	brokenRuntime := &fakeRuntime{precheckFailures: 2}
	broken, err := newManager(config, brokenRuntime, func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broken.Recover(context.Background()); !errors.Is(err, ErrPrecheck) {
		t.Fatalf("Recover() both-corrupt error = %v", err)
	}
}

func TestManagerRecoverRestoresOriginalRuntimeAfterCandidateFailure(t *testing.T) {
	tests := []struct {
		name                    string
		activation              []error
		health                  []error
		failOnLKG               bool
		want                    error
		wantOriginalActivations int
	}{
		{name: "current activation", activation: []error{errors.New("activation failed")}, want: ErrPrecheck, wantOriginalActivations: 2},
		{name: "current health", health: []error{errors.New("health failed")}, want: ErrPrecheck, wantOriginalActivations: 2},
		{name: "current cancellation", health: []error{context.Canceled}, want: context.Canceled, wantOriginalActivations: 2},
		{name: "lkg activation", activation: []error{errors.New("activation failed")}, failOnLKG: true, want: ErrActivation, wantOriginalActivations: 1},
		{name: "lkg health", health: []error{errors.New("health failed")}, failOnLKG: true, want: ErrHealth, wantOriginalActivations: 1},
		{name: "lkg cancellation", health: []error{context.Canceled}, failOnLKG: true, want: context.Canceled, wantOriginalActivations: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := managedStateRoot(t)
			config := RuntimeConfig{StateRoot: root, ListenAddress: "127.0.0.1", ListenPort: 18443}
			seed, err := newManager(config, &fakeRuntime{}, func() time.Time { return testNow })
			if err != nil {
				t.Fatal(err)
			}
			if _, err := seed.Apply(context.Background(), validTestBundle(t, "v1", "one.example.test")); err != nil {
				t.Fatal(err)
			}
			v1, err := seed.store.readPointer("current")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := seed.Apply(context.Background(), validTestBundle(t, "v2", "two.example.test")); err != nil {
				t.Fatal(err)
			}
			v2, err := seed.store.readPointer("current")
			if err != nil {
				t.Fatal(err)
			}
			if err := seed.store.setPointer("lkg", v1); err != nil {
				t.Fatal(err)
			}

			runtime := &recoveryRuntime{
				precheckErrors: map[string][]error{}, activationErrors: map[string][]error{}, healthErrors: map[string][]error{},
				activeTarget: filepath.Base(v2),
			}
			failureTarget := filepath.Base(v2)
			if test.failOnLKG {
				failureTarget = filepath.Base(v1)
				runtime.precheckErrors[filepath.Base(v2)] = []error{errors.New("current precheck failed")}
			} else if !errors.Is(test.want, context.Canceled) {
				runtime.precheckErrors[filepath.Base(v1)] = []error{errors.New("lkg precheck failed")}
			}
			runtime.activationErrors[failureTarget] = test.activation
			runtime.healthErrors[failureTarget] = test.health
			manager, err := newManager(config, runtime, func() time.Time { return testNow })
			if err != nil {
				t.Fatal(err)
			}
			if _, err := manager.Recover(context.Background()); !errors.Is(err, test.want) {
				t.Fatalf("Recover() error = %v, want %v", err, test.want)
			}
			current, err := manager.store.readPointer("current")
			if err != nil || current != v2 || runtime.activeTarget != filepath.Base(v2) {
				t.Fatalf("recovery lost original runtime: current=%q active=%q error=%v calls=%v", current, runtime.activeTarget, err, runtime.calls)
			}
			activations := 0
			for _, call := range runtime.calls {
				if call == "activate:"+filepath.Base(v2) {
					activations++
				}
			}
			if activations != test.wantOriginalActivations {
				t.Fatalf("original target activation attempts=%d, want %d: calls=%v", activations, test.wantOriginalActivations, runtime.calls)
			}
		})
	}
}

func TestManagerRecoverUsesLKGOnlyAfterValidatingCurrent(t *testing.T) {
	root := managedStateRoot(t)
	config := RuntimeConfig{StateRoot: root, ListenAddress: "127.0.0.1", ListenPort: 18443}
	seed, err := newManager(config, &fakeRuntime{}, func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := seed.Apply(context.Background(), validTestBundle(t, "v1", "one.example.test")); err != nil {
		t.Fatal(err)
	}
	v1, err := seed.store.readPointer("current")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := seed.Apply(context.Background(), validTestBundle(t, "v2", "two.example.test")); err != nil {
		t.Fatal(err)
	}
	v2, err := seed.store.readPointer("current")
	if err != nil {
		t.Fatal(err)
	}
	if err := seed.store.setPointer("lkg", v1); err != nil {
		t.Fatal(err)
	}
	corruptReleaseManifest(t, root, v2)

	runtime := &recoveryRuntime{
		precheckErrors: map[string][]error{}, activationErrors: map[string][]error{}, healthErrors: map[string][]error{},
		activeTarget: filepath.Base(v2),
	}
	manager, err := newManager(config, runtime, func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	result, err := manager.Recover(context.Background())
	if err != nil || result.VersionID != "v1" || runtime.activeTarget != filepath.Base(v1) {
		t.Fatalf("Recover() valid LKG result=%#v active=%q calls=%v error=%v", result, runtime.activeTarget, runtime.calls, err)
	}
	current, err := manager.store.readPointer("current")
	if err != nil || current != v1 {
		t.Fatalf("current after LKG recovery = %q, %v", current, err)
	}

	if err := manager.store.setPointer("current", v2); err != nil {
		t.Fatal(err)
	}
	corruptReleaseManifest(t, root, v1)
	runtime.calls = nil
	if _, err := manager.Recover(context.Background()); !errors.Is(err, ErrUnsafeState) {
		t.Fatalf("Recover() double corruption error = %v, want ErrUnsafeState", err)
	}
	current, currentErr := manager.store.readPointer("current")
	lkg, lkgErr := manager.store.readPointer("lkg")
	if currentErr != nil || lkgErr != nil || current != v2 || lkg != v1 || len(runtime.calls) != 0 {
		t.Fatalf("double corruption mutated state: current=%q lkg=%q calls=%v errors=%v/%v", current, lkg, runtime.calls, currentErr, lkgErr)
	}
}

func TestManagerRecoverRollsBackFailedLKGWithPersistedHealthEvidence(t *testing.T) {
	tests := []struct {
		name       string
		precheck   []error
		activation []error
		health     []error
		want       error
		rolledBack bool
	}{
		{name: "precheck", precheck: []error{errors.New("precheck failed")}, want: ErrPrecheck},
		{name: "activation", activation: []error{errors.New("activation failed")}, want: ErrActivation, rolledBack: true},
		{name: "health", health: []error{errors.New("health failed")}, want: ErrHealth, rolledBack: true},
		{name: "cancellation", health: []error{context.Canceled}, want: context.Canceled, rolledBack: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := managedStateRoot(t)
			config := RuntimeConfig{StateRoot: root, ListenAddress: "127.0.0.1", ListenPort: 18443}
			seed, err := newManager(config, &fakeRuntime{}, func() time.Time { return testNow })
			if err != nil {
				t.Fatal(err)
			}
			if _, err := seed.Apply(context.Background(), validTestBundle(t, "v1", "one.example.test")); err != nil {
				t.Fatal(err)
			}
			v1, err := seed.store.readPointer("current")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := seed.Apply(context.Background(), validTestBundle(t, "v2", "two.example.test")); err != nil {
				t.Fatal(err)
			}
			v2, err := seed.store.readPointer("current")
			if err != nil {
				t.Fatal(err)
			}
			if err := seed.store.setPointer("lkg", v1); err != nil {
				t.Fatal(err)
			}
			corruptReleaseManifest(t, root, v2)

			runtime := &recoveryRuntime{
				precheckErrors: map[string][]error{}, activationErrors: map[string][]error{}, healthErrors: map[string][]error{},
				activeTarget: filepath.Base(v2),
			}
			runtime.activationErrors[filepath.Base(v1)] = test.activation
			runtime.healthErrors[filepath.Base(v1)] = test.health
			runtime.precheckErrors[filepath.Base(v1)] = test.precheck
			manager, err := newManager(config, runtime, func() time.Time { return testNow })
			if err != nil {
				t.Fatal(err)
			}
			_, err = manager.Recover(context.Background())
			if !errors.Is(err, ErrUnsafeState) || !errors.Is(err, test.want) {
				t.Fatalf("Recover() error = %v, want ErrUnsafeState and %v", err, test.want)
			}
			originalActivation := -1
			originalPrecheck := -1
			originalHealthy := -1
			for index, call := range runtime.calls {
				switch call {
				case "precheck:" + filepath.Base(v2):
					originalPrecheck = index
				case "activate:" + filepath.Base(v2):
					originalActivation = index
				case "healthy:" + filepath.Base(v2):
					originalHealthy = index
				}
			}
			if test.rolledBack {
				if originalPrecheck < 0 || originalActivation <= originalPrecheck || originalHealthy <= originalActivation {
					t.Fatalf("Recover() did not verify original generation before rollback: calls=%v", runtime.calls)
				}
			} else if originalActivation >= 0 || originalHealthy >= 0 {
				t.Fatalf("Recover() touched runtime after candidate precheck failure: calls=%v", runtime.calls)
			}
			current, currentErr := manager.store.readPointer("current")
			lkg, lkgErr := manager.store.readPointer("lkg")
			status, statusErr := manager.store.readStatus()
			if currentErr != nil || lkgErr != nil || statusErr != nil || current != v2 || lkg != v1 ||
				!status.Active || status.VersionID != "v2" || len(status.HealthTargets) == 0 || runtime.activeTarget != filepath.Base(v2) {
				t.Fatalf("unsafe recovery facts: current=%q lkg=%q status=%#v errors=%v/%v/%v calls=%v", current, lkg, status, currentErr, lkgErr, statusErr, runtime.calls)
			}
		})
	}
}

func TestManagerRecoverDoesNotSwitchCorruptCurrentWithoutPersistedHealthEvidence(t *testing.T) {
	root := managedStateRoot(t)
	config := RuntimeConfig{StateRoot: root, ListenAddress: "127.0.0.1", ListenPort: 18443}
	seed, err := newManager(config, &fakeRuntime{}, func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := seed.Apply(context.Background(), validTestBundle(t, "v1", "one.example.test")); err != nil {
		t.Fatal(err)
	}
	v1, err := seed.store.readPointer("current")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := seed.Apply(context.Background(), validTestBundle(t, "v2", "two.example.test")); err != nil {
		t.Fatal(err)
	}
	v2, err := seed.store.readPointer("current")
	if err != nil {
		t.Fatal(err)
	}
	if err := seed.store.setPointer("lkg", v1); err != nil {
		t.Fatal(err)
	}
	status, err := seed.store.readStatus()
	if err != nil {
		t.Fatal(err)
	}
	status.HealthTargets = nil
	if err := seed.store.writeStatus(status); err != nil {
		t.Fatal(err)
	}
	corruptReleaseManifest(t, root, v2)

	runtime := &recoveryRuntime{
		precheckErrors: map[string][]error{}, activationErrors: map[string][]error{}, healthErrors: map[string][]error{},
		activeTarget: filepath.Base(v2),
	}
	manager, err := newManager(config, runtime, func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Recover(context.Background()); !errors.Is(err, ErrUnsafeState) {
		t.Fatalf("Recover() legacy status error = %v, want ErrUnsafeState", err)
	}
	if len(runtime.calls) != 0 || runtime.activeTarget != filepath.Base(v2) {
		t.Fatalf("Recover() touched legacy runtime without health evidence: calls=%v active=%q", runtime.calls, runtime.activeTarget)
	}
	current, currentErr := manager.store.readPointer("current")
	lkg, lkgErr := manager.store.readPointer("lkg")
	if currentErr != nil || lkgErr != nil || current != v2 || lkg != v1 {
		t.Fatalf("Recover() changed legacy facts: current=%q lkg=%q errors=%v/%v", current, lkg, currentErr, lkgErr)
	}
}

func TestManagerRecoverRestoresOriginalStateAfterFactWriteFailure(t *testing.T) {
	for _, failure := range []string{"current", "lkg", "status"} {
		t.Run(failure, func(t *testing.T) {
			root := managedStateRoot(t)
			config := RuntimeConfig{StateRoot: root, ListenAddress: "127.0.0.1", ListenPort: 18443}
			seed, err := newManager(config, &fakeRuntime{}, func() time.Time { return testNow })
			if err != nil {
				t.Fatal(err)
			}
			if _, err := seed.Apply(context.Background(), validTestBundle(t, "v1", "one.example.test")); err != nil {
				t.Fatal(err)
			}
			v1, err := seed.store.readPointer("current")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := seed.Apply(context.Background(), validTestBundle(t, "v2", "two.example.test")); err != nil {
				t.Fatal(err)
			}
			v2, err := seed.store.readPointer("current")
			if err != nil {
				t.Fatal(err)
			}
			if err := seed.store.setPointer("lkg", v1); err != nil {
				t.Fatal(err)
			}
			statusBefore, err := os.ReadFile(seed.store.statusPath)
			if err != nil {
				t.Fatal(err)
			}
			status, err := seed.store.readStatus()
			if err != nil {
				t.Fatal(err)
			}
			originalHealth, err := decodeStatusHealthTargets(status.HealthTargets)
			if err != nil {
				t.Fatal(err)
			}

			currentBlocker := filepath.Join(root, ".current-"+filepath.Base(v1)+".tmp")
			lkgBlocker := filepath.Join(root, ".lkg-"+filepath.Base(v1)+".tmp")
			runtime := &recoveryRuntime{
				precheckErrors:   map[string][]error{filepath.Base(v2): {errors.New("current precheck failed")}},
				activationErrors: map[string][]error{}, healthErrors: map[string][]error{}, activeTarget: filepath.Base(v2),
			}
			runtime.onPrecheck = func(target string) {
				if failure == "current" && target == filepath.Base(v1) {
					if err := os.WriteFile(currentBlocker, []byte("blocked"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			runtime.onHealthy = func(target string) {
				switch {
				case failure == "lkg" && target == filepath.Base(v1):
					if err := os.WriteFile(lkgBlocker, []byte("blocked"), 0o600); err != nil {
						t.Fatal(err)
					}
				case failure == "lkg" && target == filepath.Base(v2):
					if err := os.Remove(lkgBlocker); err != nil {
						t.Fatal(err)
					}
				case failure == "status" && target == filepath.Base(v1):
					if err := os.Remove(seed.store.statusPath); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(seed.store.statusPath, 0o700); err != nil {
						t.Fatal(err)
					}
				case failure == "status" && target == filepath.Base(v2):
					if err := os.Remove(seed.store.statusPath); err != nil {
						t.Fatal(err)
					}
				}
			}
			manager, err := newManager(config, runtime, func() time.Time { return testNow })
			if err != nil {
				t.Fatal(err)
			}
			if _, err := manager.Recover(context.Background()); err == nil || errors.Is(err, ErrRollback) {
				t.Fatalf("Recover() error = %v, want committed write failure with successful rollback", err)
			}
			current, currentErr := manager.store.readPointer("current")
			lkg, lkgErr := manager.store.readPointer("lkg")
			statusAfter, statusErr := os.ReadFile(manager.store.statusPath)
			if currentErr != nil || lkgErr != nil || statusErr != nil || current != v2 || lkg != v1 ||
				!bytes.Equal(statusAfter, statusBefore) || runtime.activeTarget != filepath.Base(v2) {
				t.Fatalf("rollback mismatch current=%q lkg=%q active=%q status_equal=%v errors=%v/%v/%v calls=%v",
					current, lkg, runtime.activeTarget, bytes.Equal(statusAfter, statusBefore), currentErr, lkgErr, statusErr, runtime.calls)
			}
			if failure != "current" {
				last := runtime.healthCalls[len(runtime.healthCalls)-1]
				if last.target != filepath.Base(v2) || !sameHealthTargets(last.targets, originalHealth) {
					t.Fatalf("rollback health evidence = %#v, want persisted original targets %#v", last, originalHealth)
				}
			}
		})
	}
}

func TestStatusRejectsMalformedHealthTargets(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Status)
	}{
		{name: "duplicate", mutate: func(status *Status) {
			status.HealthTargets = append(status.HealthTargets, status.HealthTargets[0])
		}},
		{name: "uppercase digest", mutate: func(status *Status) {
			status.HealthTargets[0].LeafSHA256 = strings.ToUpper(status.HealthTargets[0].LeafSHA256)
		}},
		{name: "noncanonical domain", mutate: func(status *Status) {
			status.HealthTargets[0].ServerName = strings.ToUpper(status.HealthTargets[0].ServerName)
		}},
		{name: "inactive with health evidence", mutate: func(status *Status) {
			status.Active = false
			status.VersionID = ""
			status.Digest = ""
			status.Activation = nil
			status.AppliedAt = time.Time{}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manager, err := newManager(RuntimeConfig{
				StateRoot: managedStateRoot(t), ListenAddress: "127.0.0.1", ListenPort: 18443,
			}, &fakeRuntime{}, func() time.Time { return testNow })
			if err != nil {
				t.Fatal(err)
			}
			if _, err := manager.Apply(context.Background(), validTestBundle(t, "v1", "one.example.test")); err != nil {
				t.Fatal(err)
			}
			status, err := manager.store.readStatus()
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(&status)
			if err := manager.store.writeStatus(status); err != nil {
				t.Fatal(err)
			}
			if _, err := manager.Status(context.Background()); !errors.Is(err, ErrUnsafeState) {
				t.Fatalf("Status() malformed health target error = %v, want ErrUnsafeState", err)
			}
		})
	}
}

func corruptReleaseManifest(t *testing.T, root, target string) {
	t.Helper()
	path := filepath.Join(root, target, "manifest.json")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(content, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestManagerFailuresPreserveLastKnownGood(t *testing.T) {
	root := managedStateRoot(t)
	config := RuntimeConfig{StateRoot: root, ListenAddress: "127.0.0.1", ListenPort: 18443}
	runtime := &fakeRuntime{}
	manager, err := newManager(config, runtime, func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := manager.Apply(context.Background(), validTestBundle(t, "v1", "one.example.test"))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		fail func()
		want error
	}{
		{name: "precheck", fail: func() { runtime.precheckFailures = 1 }, want: ErrPrecheck},
		{name: "activation", fail: func() { runtime.activationFailures = 1 }, want: ErrActivation},
		{name: "health", fail: func() { runtime.healthFailures = 1 }, want: ErrHealth},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.fail()
			candidate := validTestBundle(t, fmt.Sprintf("v%d", index+2), fmt.Sprintf("candidate-%d.example.test", index))
			result, err := manager.Apply(context.Background(), candidate)
			if !errors.Is(err, test.want) || !result.RunningVersionUnchanged || result.ActiveDigest != baseline.ActiveDigest {
				t.Fatalf("Apply() result=%#v error=%v, want %v", result, err, test.want)
			}
			status, statusErr := manager.Status(context.Background())
			if statusErr != nil || status.Digest != baseline.ActiveDigest {
				t.Fatalf("status after failure=%#v error=%v", status, statusErr)
			}
			current, readErr := os.Readlink(filepath.Join(root, "current"))
			lkg, lkgErr := os.Readlink(filepath.Join(root, "lkg"))
			if readErr != nil || lkgErr != nil || current != lkg || filepath.Base(current) != "v1-"+baseline.ActiveDigest {
				t.Fatalf("pointers after failure current=%q lkg=%q errors=%v/%v", current, lkg, readErr, lkgErr)
			}
		})
	}
}

func TestManagerRejectsVersionConflictAndSerializesConcurrentApply(t *testing.T) {
	config := RuntimeConfig{StateRoot: managedStateRoot(t), ListenAddress: "127.0.0.1", ListenPort: 18443}
	runtime := &fakeRuntime{}
	manager, err := newManager(config, runtime, func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	bundle := validTestBundle(t, "v1", "one.example.test")
	if _, err := manager.Apply(context.Background(), bundle); err != nil {
		t.Fatal(err)
	}
	conflict := validTestBundle(t, "v1", "different.example.test")
	if _, err := manager.Apply(context.Background(), conflict); !errors.Is(err, ErrConflict) {
		t.Fatalf("version conflict error = %v", err)
	}

	var wait sync.WaitGroup
	errorsChannel := make(chan error, 12)
	for index := 0; index < 12; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if _, err := manager.Apply(context.Background(), bundle); err != nil {
				errorsChannel <- err
			}
		}()
	}
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Fatal(err)
	}
}

func validTestBundle(t *testing.T, version, domain string) Bundle {
	t.Helper()
	material := issueTestMaterial(t, []string{domain}, testNow.Add(-time.Hour), testNow.Add(time.Hour), nil)
	return Bundle{SchemaVersion: SchemaVersion, VersionID: version, Bindings: []Binding{{
		SiteID: "site", Domains: []string{domain}, CertificateChainPEM: material.chainPEM, PrivateKeyPEM: material.privatePEM,
	}}}
}

func containsPrivateKey(value []byte) bool {
	return bytesContainsFold(value, []byte("private_key_pem")) || bytesContainsFold(value, []byte("BEGIN PRIVATE KEY"))
}

func bytesContainsFold(value, search []byte) bool {
	return strings.Contains(strings.ToLower(string(value)), strings.ToLower(string(search)))
}

func managedStateRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "certstore")
	t.Cleanup(func() {
		_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil || entry.Type()&os.ModeSymlink != 0 {
				return nil
			}
			if entry.IsDir() {
				_ = os.Chmod(path, 0o700)
			} else {
				_ = os.Chmod(path, 0o600)
			}
			return nil
		})
	})
	return root
}
