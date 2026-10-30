package deployment

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestRecoverInterruptedActivationPhases(t *testing.T) {
	for _, phase := range []executionPhase{phaseActivate, phaseHealth, phaseRollback, phaseExplicitRollbackVerify, phaseExplicitRollbackRestore} {
		t.Run(string(phase), func(t *testing.T) {
			manager, runtime, command, prior, value := recoveryFixture(t, phase)
			before := len(runtime.activationList())
			if err := manager.Recover(context.Background()); err != nil {
				t.Fatal(err)
			}
			pointers, err := manager.Pointers()
			if err != nil || pointers != prior {
				t.Fatalf("pointers=%+v want=%+v err=%v", pointers, prior, err)
			}
			if got := runtime.activationList(); !reflect.DeepEqual(got[before:], []string{prior.Current}) {
				t.Fatalf("recovery activations=%v", got[before:])
			}
			if err := manager.Recover(context.Background()); err != nil || len(runtime.activationList()) != before+1 {
				t.Fatalf("repeat recovery mutated runtime: %v", err)
			}
			result, err := manager.Process(context.Background(), command)
			if err != nil || result.State == StateRollbackFailed || len(runtime.activationList()) != before+1 {
				t.Fatalf("command replay=%+v %v", result, err)
			}
			stored, err := manager.store.loadJournal(value.DeploymentID)
			if err != nil || stored.Attempts[len(stored.Attempts)-1].Phase != "" {
				t.Fatalf("recovery not terminal: %+v %v", stored, err)
			}
		})
	}
}

func TestRecoverFailsClosedAndCanRetry(t *testing.T) {
	for _, failure := range []string{"reload", "health", "precheck", "corrupt-release", "newer-current", "multiple-journals"} {
		t.Run(failure, func(t *testing.T) {
			manager, runtime, _, prior, value := recoveryFixture(t, phaseHealth)
			injected := errors.New("injected recovery failure")
			switch failure {
			case "reload":
				runtime.activationFailures[prior.Current] = map[int]error{2: injected}
			case "health":
				runtime.healthFailures[prior.Current] = injected
			case "precheck":
				manager.prechecker.(*fakePrechecker).failFor[prior.Current] = injected
			case "corrupt-release":
				path := filepath.Join(manager.store.releasesDir, prior.CurrentDigest, "nginx", "site.conf")
				if err := os.Chmod(path, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("tampered"), 0o400); err != nil {
					t.Fatal(err)
				}
			case "newer-current":
				// A distinct, healthy deployment after the old journal must win.
				command := testCommand(t, "newer", 1, "newer", "cfg-v3", map[string][]byte{"nginx/site.conf": []byte("newer")})
				if result, err := manager.Process(context.Background(), command); err != nil || result.State != StateHealthy {
					t.Fatalf("newer=%+v %v", result, err)
				}
			case "multiple-journals":
				copy := *value
				copy.DeploymentID = "second-unresolved"
				if err := manager.store.saveJournal(&copy); err != nil {
					t.Fatal(err)
				}
			}
			before := len(runtime.activationList())
			if err := manager.Recover(context.Background()); err == nil {
				t.Fatal("invalid recovery returned success")
			}
			if failure != "reload" && failure != "health" && len(runtime.activationList()) != before {
				t.Fatal("recovery mutated runtime before ownership/integrity/precheck validation")
			}
			stored, err := manager.store.loadJournal(value.DeploymentID)
			if err != nil || stored.Attempts[0].Phase != phaseHealth {
				t.Fatalf("failed recovery consumed journal: %+v %v", stored, err)
			}
			if failure == "reload" || failure == "health" || failure == "precheck" {
				delete(runtime.activationFailures, prior.Current)
				delete(runtime.healthFailures, prior.Current)
				delete(manager.prechecker.(*fakePrechecker).failFor, prior.Current)
				if err := manager.Recover(context.Background()); err != nil {
					t.Fatalf("retry=%v", err)
				}
			}
		})
	}
}

func recoveryFixture(t *testing.T, phase executionPhase) (*Manager, *fakeRuntime, Command, Pointers, *journal) {
	t.Helper()
	runtime := &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}}
	manager, _ := newTestManager(t, &fakePrechecker{failFor: map[string]error{}}, runtime)
	_, _ = deployHealthyV2(t, manager)
	prior, err := manager.Pointers()
	if err != nil {
		t.Fatal(err)
	}
	command := testCommand(t, "interrupted", 1, "cfg-v3", prior.Current, map[string][]byte{"nginx/site.conf": []byte("v3")})
	if phase == phaseExplicitRollbackVerify || phase == phaseExplicitRollbackRestore {
		command = testRollbackCommand("interrupted", prior.Previous, prior.Current)
	}
	normalized, digest, err := validateAndDigestWithLimits(command, manager.config.Limits)
	if err != nil {
		t.Fatal(err)
	}
	manifest := command.Bundle.ManifestSHA256
	if command.Action == ActionApply {
		if _, err := manager.store.stage(command, normalized); err != nil {
			t.Fatal(err)
		}
	} else {
		manifest = prior.PreviousDigest
	}
	states := []State{StateDelivered, StateStaged, StatePrechecked}
	if command.Action == ActionRollback {
		states = append(states, StateReverting)
	} else if phase != phaseActivate {
		states = append(states, StateActivated)
		if phase == phaseRollback {
			states = append(states, StateReverting)
		}
	}
	record := attemptRecord{Attempt: 1, Action: command.Action, CommandDigest: digest, ConfigVersionID: command.ConfigVersionID,
		PreviousVersionID: command.PreviousVersionID, ManifestSHA256: manifest, Phase: phase, PriorPointersSet: true, PriorPointers: prior}
	if phase == phaseExplicitRollbackRestore {
		record.RollbackErrorCode, record.RollbackSummary = "HEALTH_FAILED", "interrupted recovery"
	}
	for index, state := range states {
		record.Transitions = append(record.Transitions, Transition{Sequence: uint64(index + 1), State: state, At: manager.now()})
	}
	value := &journal{Version: journalVersion, DeploymentID: command.DeploymentID, Attempts: []attemptRecord{record}}
	if err := manager.store.saveJournal(value); err != nil {
		t.Fatal(err)
	}
	if err := manager.store.switchCurrent(manifest); err != nil {
		t.Fatal(err)
	}
	if err := manager.store.savePointers(Pointers{Current: command.ConfigVersionID, CurrentDigest: manifest, Previous: prior.Current, PreviousDigest: prior.CurrentDigest}); err != nil {
		t.Fatal(err)
	}
	return manager, runtime, command, prior, value
}
