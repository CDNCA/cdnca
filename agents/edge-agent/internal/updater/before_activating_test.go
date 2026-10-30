package updater

import (
	"context"
	"errors"
	"testing"
)

// Config.BeforeActivating lets a release refuse switching to a version that
// cannot read the node's local state. These tests pin where the updater asks
// and what a refusal does.

type activationHook struct {
	versions []string
	refuse   map[int]bool // by call index
}

func (h *activationHook) run(_ context.Context, version string) error {
	h.versions = append(h.versions, version)
	if h.refuse[len(h.versions)-1] {
		return errors.New("active L4 version uses tls_passthrough")
	}
	return nil
}

func withActivationHook(t *testing.T, manager *Manager, hook *activationHook) {
	t.Helper()
	manager.config.BeforeActivating = hook.run
}

// TestDowngradePlanRefusedBeforeInstallerWhenStateIsUnreadable: an explicit
// rollback plan to an older version runs the hook with that version before
// the installer is called; a refusal fails the plan with
// L4_STATE_INCOMPATIBLE and keeps the running version.
func TestDowngradePlanRefusedBeforeInstallerWhenStateIsUnreadable(t *testing.T) {
	v2 := []byte("signed-agent-v2")
	environment := newTestEnvironment(t, v2)
	hook := &activationHook{refuse: map[int]bool{1: true}}
	withActivationHook(t, environment.manager, hook)
	upgrade := environment.plan(t, "upgrade-2", 1, 2, "1.0.0", "2.0.0", ActionUpgrade, v2)
	if _, err := environment.manager.Process(context.Background(), upgrade); err != nil {
		t.Fatal(err)
	}
	installs := environment.installer.installCalls
	environment.downloader.content = []byte("baseline-v1")
	rollback := environment.plan(t, "rollback-1", 2, 3, "2.0.0", "1.0.0", ActionRollback, []byte("baseline-v1"))
	result, err := environment.manager.Process(context.Background(), rollback)
	if !errors.Is(err, ErrStateIncompatible) || result.State != StateFailed || result.ErrorCode != "L4_STATE_INCOMPATIBLE" ||
		!result.AlertRequired || environment.installer.installCalls != installs {
		t.Fatalf("refused downgrade = %+v, %v (installs %d -> %d)", result, err, installs, environment.installer.installCalls)
	}
	if len(hook.versions) != 2 || hook.versions[0] != "2.0.0" || hook.versions[1] != "1.0.0" {
		t.Fatalf("hook versions = %v", hook.versions)
	}
	if code := upgradeErrorCode(err); code != "L4_STATE_INCOMPATIBLE" {
		t.Fatalf("reported code = %s", code)
	}
	current, currentErr := environment.manager.Current(context.Background())
	if currentErr != nil || current.CurrentVersion != "2.0.0" {
		t.Fatalf("current after refusal = %+v, %v", current, currentErr)
	}
}

// TestAutomaticRollbackKeepsRunningVersionWhenStateIsUnreadable: the health
// gate asks for a rollback to the previous version; when that version cannot
// read the node's state the rollback is not started (it would stop the
// agent) and the result reports the running version.
func TestAutomaticRollbackKeepsRunningVersionWhenStateIsUnreadable(t *testing.T) {
	artifact := []byte("unhealthy-agent-v2")
	environment := newTestEnvironment(t, artifact)
	environment.probe.errors = []error{nil, errors.New("unhealthy")}
	hook := &activationHook{refuse: map[int]bool{1: true}}
	withActivationHook(t, environment.manager, hook)
	plan := environment.plan(t, "upgrade-unhealthy", 1, 2, "1.0.0", "2.0.0", ActionUpgrade, artifact)
	result, err := environment.manager.Process(context.Background(), plan)
	if !errors.Is(err, ErrRollback) || result.State != StateFailed || result.ErrorCode != "L4_STATE_INCOMPATIBLE" ||
		result.CurrentVersion != "2.0.0" || environment.installer.rollbackCalls != 0 {
		t.Fatalf("refused automatic rollback = %+v, %v, rollback calls %d", result, err, environment.installer.rollbackCalls)
	}
	if len(hook.versions) != 2 || hook.versions[1] != "1.0.0" {
		t.Fatalf("hook versions = %v", hook.versions)
	}
	duplicate, err := environment.manager.Process(context.Background(), plan)
	if err != nil || !duplicate.Duplicate || duplicate.ErrorCode != "L4_STATE_INCOMPATIBLE" || environment.installer.rollbackCalls != 0 {
		t.Fatalf("replay = %+v, %v", duplicate, err)
	}
}

// TestAutomaticRollbackPreparesStateFirst: when the hook succeeds the
// rollback proceeds as before.
func TestAutomaticRollbackPreparesStateFirst(t *testing.T) {
	artifact := []byte("unhealthy-agent-v2")
	environment := newTestEnvironment(t, artifact)
	environment.probe.errors = []error{nil, errors.New("unhealthy")}
	hook := &activationHook{}
	withActivationHook(t, environment.manager, hook)
	plan := environment.plan(t, "upgrade-unhealthy", 1, 2, "1.0.0", "2.0.0", ActionUpgrade, artifact)
	result, err := environment.manager.Process(context.Background(), plan)
	if !errors.Is(err, ErrHealth) || result.State != StateRolledBack || result.CurrentVersion != "1.0.0" ||
		environment.installer.rollbackCalls != 1 || len(hook.versions) != 2 || hook.versions[1] != "1.0.0" {
		t.Fatalf("rollback = %+v, %v, hook %v", result, err, hook.versions)
	}
}

// TestV2InstallerRunsHookAtPrepareAndBeforeActivation: with the transactional
// installer the hook runs before Prepare and again right before Activate
// (state may change in between); a refusal at activation aborts the
// prepared helper transaction instead of switching.
func TestV2InstallerRunsHookAtPrepareAndBeforeActivation(t *testing.T) {
	artifact := []byte("signed-agent-v2-hook")
	environment := newTestEnvironment(t, artifact)
	installer := newV2SandboxInstaller(environment.installer)
	manager := v2ManagerForEnvironment(t, environment, installer)
	hook := &activationHook{refuse: map[int]bool{1: true}}
	withActivationHook(t, manager, hook)
	plan := v2PlanForEnvironment(t, environment, "upgrade-v2-hook", 1, 2, "1.0.0", "2.0.0", ActionUpgrade, artifact)
	prepared, err := manager.prepare(context.Background(), plan)
	if err != nil || prepared.Complete || installer.prepareCalls != 1 || len(hook.versions) != 1 {
		t.Fatalf("prepare = %+v, %v, prepare calls %d, hook %v", prepared, err, installer.prepareCalls, hook.versions)
	}
	result, err := manager.processPrepared(context.Background(), plan, prepared.InstallerTransactionID)
	if !errors.Is(err, ErrStateIncompatible) || result.State != StateFailed || result.ErrorCode != "L4_STATE_INCOMPATIBLE" ||
		installer.activateCalls != 0 || installer.abortCalls != 1 || len(hook.versions) != 2 {
		t.Fatalf("activation refusal = %+v, %v, activate %d abort %d hook %v",
			result, err, installer.activateCalls, installer.abortCalls, hook.versions)
	}

	refusedAtPrepare := newTestEnvironment(t, artifact)
	prepareInstaller := newV2SandboxInstaller(refusedAtPrepare.installer)
	prepareManager := v2ManagerForEnvironment(t, refusedAtPrepare, prepareInstaller)
	withActivationHook(t, prepareManager, &activationHook{refuse: map[int]bool{0: true}})
	early := v2PlanForEnvironment(t, refusedAtPrepare, "upgrade-v2-hook-early", 1, 2, "1.0.0", "2.0.0", ActionUpgrade, artifact)
	result, err = prepareManager.Process(context.Background(), early)
	if !errors.Is(err, ErrStateIncompatible) || result.State != StateFailed || result.ErrorCode != "L4_STATE_INCOMPATIBLE" ||
		prepareInstaller.prepareCalls != 0 {
		t.Fatalf("prepare refusal = %+v, %v, prepare calls %d", result, err, prepareInstaller.prepareCalls)
	}
}
