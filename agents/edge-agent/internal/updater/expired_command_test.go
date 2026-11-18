package updater

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func queuedStates(t *testing.T, runtime *UpgradeRuntime) []EdgeUpgradeState {
	t.Helper()
	statuses, err := runtime.PendingStatuses(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	states := make([]EdgeUpgradeState, 0, len(statuses))
	for _, queued := range statuses {
		states = append(states, queued.Status.State)
	}
	return states
}

func sameStates(left, right []EdgeUpgradeState) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// A command was claimed, the agent state holding
// its manager transaction had been set aside, and the envelope expired.
// Every Recover failed with "upgrade execution is expired" and ended the gateway
// session about every 0.5 s.
func TestUpgradeRuntimeClosesExpiredClaimedCommandWithoutTransactionAsFailed(t *testing.T) {
	fixture, environment, _ := newJournalOrderEnvironment(t)
	installer := &uncertainV2Installer{v2SandboxInstaller: newV2SandboxInstaller(environment.installer)}
	store, runtime := newJournalOrderRuntime(t, environment, fixture, environment.root, installer)
	accepted := acceptAndAcknowledgeRuntimeCommand(t, runtime, fixture)
	if err := runtime.Recover(context.Background()); err == nil {
		t.Fatal("Recover() with a lost prepare response = nil, want uncertain")
	}
	if err := os.Remove(filepath.Join(environment.root, "state", "transaction.json")); err != nil {
		t.Fatal(err)
	}
	environment.now.mu.Lock()
	environment.now.now = time.Unix(fixture.execution.ExpiresAt, 0).UTC().Add(time.Minute)
	environment.now.mu.Unlock()

	for attempt := 0; attempt < 2; attempt++ {
		if err := runtime.Recover(context.Background()); err != nil {
			t.Fatalf("Recover() attempt %d of an expired claimed command = %v, want nil", attempt, err)
		}
	}
	want := []EdgeUpgradeState{EdgeUpgradeStateClaimed, EdgeUpgradeStateInstalling, EdgeUpgradeStateFailed}
	if got := queuedStates(t, runtime); !sameStates(got, want) {
		t.Fatalf("queued states = %v, want %v", got, want)
	}
	last, found, err := store.LastStatus(context.Background(), accepted.Status.CommandID)
	if err != nil || !found || last.State != EdgeUpgradeStateFailed || last.ErrorCode != "PLAN_EXPIRED" ||
		last.InstallerTransactionID == "" || !last.AlertRequired || last.CurrentVersion != fixture.execution.CurrentVersion ||
		last.PreviousVersion != "" {
		t.Fatalf("terminal status = (%+v, %t, %v)", last, found, err)
	}
	if installer.prepares != 1 {
		t.Fatalf("prepares = %d, want 1", installer.prepares)
	}
}

// An accepted command whose envelope expired before it was claimed cannot be claimed
// any more (the claim consumes a valid envelope) and the control plane only moves
// accepted to claimed. The agent leaves it accepted and keeps the session; control
// cancels a paused plan whose only nodes are accepted and expired (migration 675).
func TestUpgradeRuntimeSkipsExpiredAcceptedCommand(t *testing.T) {
	fixture, environment, _ := newJournalOrderEnvironment(t)
	installer := &uncertainV2Installer{v2SandboxInstaller: newV2SandboxInstaller(environment.installer)}
	store, runtime := newJournalOrderRuntime(t, environment, fixture, environment.root, installer)
	accepted := acceptAndAcknowledgeRuntimeCommand(t, runtime, fixture)
	environment.now.mu.Lock()
	environment.now.now = time.Unix(fixture.execution.ExpiresAt, 0).UTC().Add(time.Minute)
	environment.now.mu.Unlock()

	if err := runtime.Recover(context.Background()); err != nil {
		t.Fatalf("Recover() of an expired accepted command = %v, want nil", err)
	}
	last, found, err := store.LastStatus(context.Background(), accepted.Status.CommandID)
	if err != nil || !found || last.State != EdgeUpgradeStateAccepted {
		t.Fatalf("last status = (%+v, %t, %v), want accepted", last, found, err)
	}
	if installer.prepares != 0 {
		t.Fatalf("prepares = %d, want 0", installer.prepares)
	}
}
