package l4runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// resumingRuntime records the startup takeover the Manager asks for after an
// agent restart (KillMode=process keeps the L4 master alive across it).
type resumingRuntime struct {
	fakeRuntime
	resumeCalls []string
	resumeErr   error
	drainLimits []time.Duration
}

func (r *resumingRuntime) Resume(_ context.Context, path string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.resumeCalls = append(r.resumeCalls, currentTarget(path))
	return r.resumeErr
}

func (r *resumingRuntime) SetDrainLimit(limit time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.drainLimits = append(r.drainLimits, limit)
	return nil
}

func TestManagerResumesActiveVersionAfterAgentRestart(t *testing.T) {
	runtime := &resumingRuntime{}
	manager, root := testManager(t, runtime)
	result, err := manager.Apply(context.Background(), validConfig("l4-v1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(runtime.resumeCalls) != 0 {
		t.Fatalf("first start resumed %v before any active version", runtime.resumeCalls)
	}
	activations := len(runtime.activateCalls)

	// A restarted agent constructs a new Manager over the same state root.
	if _, err := newManager(root, runtime, fixedTime); err != nil {
		t.Fatalf("restart newManager() error = %v", err)
	}
	want := "l4-v1-" + result.Digest
	if len(runtime.resumeCalls) != 1 || runtime.resumeCalls[0] != want {
		t.Fatalf("resume calls = %v, want [%s]", runtime.resumeCalls, want)
	}
	if len(runtime.activateCalls) != activations {
		t.Fatalf("restart reloaded the runtime: activate calls %v", runtime.activateCalls)
	}
	if len(runtime.drainLimits) == 0 {
		t.Fatal("restart did not restore the active drain limit")
	}
}

func TestManagerResumeFailureDoesNotBlockAgentStartup(t *testing.T) {
	runtime := &resumingRuntime{}
	manager, root := testManager(t, runtime)
	if _, err := manager.Apply(context.Background(), validConfig("l4-v1")); err != nil {
		t.Fatal(err)
	}
	runtime.resumeErr = errInjectedRuntime
	restarted, err := newManager(root, runtime, fixedTime)
	if err != nil {
		t.Fatalf("resume failure blocked agent startup: %v", err)
	}
	status, err := restarted.Status()
	if err != nil || !status.Active || status.VersionID != "l4-v1" {
		t.Fatalf("Status() after failed resume = %+v, %v", status, err)
	}
}

func TestOpenRestyResumeAdoptsRunningMasterWithoutSignals(t *testing.T) {
	root := t.TempDir()
	pidFile := filepath.Join(root, "nginx.pid")
	recorded := testProcessIdentity(t, 43)
	writeProcessFixture(t, pidFile, recorded)
	handle := &fakeProcessHandle{}
	controller := testOpenResty(t, pidFile)
	controller.openProcess = func(pid int) (processHandle, error) {
		if pid != recorded.PID {
			t.Fatalf("openProcess(%d), want %d", pid, recorded.PID)
		}
		return handle, nil
	}
	controller.inspect = func(int) (processIdentity, error) { return recorded, nil }
	controller.start = func(context.Context, []string, ...string) error {
		t.Fatal("Resume started a second OpenResty master")
		return nil
	}
	if err := controller.Resume(context.Background(), root); err != nil {
		t.Fatalf("Resume() error = %v", err)
	}
	signals, closes := handle.snapshot()
	if len(signals) != 0 || closes != 1 {
		t.Fatalf("Resume signalled the adopted master: signals=%v closeCalls=%d", signals, closes)
	}
	stored, err := readProcessRecord(pidFile + ".identity")
	if err != nil || stored != recorded {
		t.Fatalf("adopted identity = %+v, %v", stored, err)
	}
}

func TestOpenRestyResumeRejectsMasterWithoutWorkers(t *testing.T) {
	root := t.TempDir()
	pidFile := filepath.Join(root, "nginx.pid")
	recorded := testProcessIdentity(t, 43)
	writeProcessFixture(t, pidFile, recorded)
	handle := &fakeProcessHandle{}
	controller := testOpenResty(t, pidFile)
	controller.openProcess = func(int) (processHandle, error) { return handle, nil }
	controller.inspect = func(int) (processIdentity, error) { return recorded, nil }
	controller.workerGeneration = func(processIdentity) (workerGeneration, error) { return workerGeneration{}, nil }
	if err := controller.Resume(context.Background(), root); err == nil {
		t.Fatal("Resume() adopted a master with no worker generation")
	}
	if signals, closes := handle.snapshot(); len(signals) != 0 || closes != 1 {
		t.Fatalf("signals=%v closeCalls=%d", signals, closes)
	}
}

func TestOpenRestyResumeStartsMasterKilledWithPreviousAgent(t *testing.T) {
	fixture := newInitialStartFixture(t, time.Second, func(processIdentity) (workerGeneration, error) {
		return workerGeneration{{PID: 201, StartTicks: 2001}: {}}, nil
	})
	// The previous agent recorded a master that has since exited.
	stale := fixture.record
	writeProcessFixture(t, fixture.pidFile, stale)
	controller := fixture.controller
	original := controller.openProcess
	controller.openProcess = func(pid int) (processHandle, error) {
		if fixture.starts == 0 {
			return nil, errProcessNotRunning
		}
		return original(pid)
	}
	if err := controller.Resume(context.Background(), fixture.root); err != nil {
		t.Fatalf("Resume() error = %v", err)
	}
	if fixture.starts != 1 {
		t.Fatalf("Resume started %d masters, want 1", fixture.starts)
	}
	if signals, _ := fixture.handle.snapshot(); len(signals) != 0 {
		t.Fatalf("fresh master was signalled: %v", signals)
	}
}

func TestOpenRestyTreatsRecordFromPreviousBootAsStopped(t *testing.T) {
	fixture := newInitialStartFixture(t, time.Second, func(processIdentity) (workerGeneration, error) {
		return workerGeneration{{PID: 201, StartTicks: 2001}: {}}, nil
	})
	previousBoot := fixture.record
	previousBoot.BootID = "previous-boot"
	writeProcessFixture(t, fixture.pidFile, previousBoot)
	controller := fixture.controller
	// After a reboot the recorded PID may belong to an unrelated process:
	// inspect reports the current boot, which never matches the old record.
	if err := controller.Resume(context.Background(), fixture.root); err != nil {
		t.Fatalf("Resume() after reboot error = %v", err)
	}
	if fixture.starts != 1 {
		t.Fatalf("Resume after reboot started %d masters, want 1", fixture.starts)
	}
	stored, err := readProcessRecord(fixture.pidFile + ".identity")
	if err != nil || stored.BootID != fixture.record.BootID {
		t.Fatalf("identity after reboot = %+v, %v", stored, err)
	}
}

func TestOpenRestyStopAfterRebootOnlyCleansStaleRecord(t *testing.T) {
	root := t.TempDir()
	pidFile := filepath.Join(root, "nginx.pid")
	previousBoot := testProcessIdentity(t, 43)
	previousBoot.BootID = "previous-boot"
	writeProcessFixture(t, pidFile, previousBoot)
	handle := &fakeProcessHandle{}
	controller := testOpenResty(t, pidFile)
	controller.openProcess = func(int) (processHandle, error) {
		t.Fatal("Stop opened a PID recorded in a previous boot")
		return handle, nil
	}
	if err := controller.Stop(context.Background(), root); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	for _, path := range []string{pidFile, pidFile + ".identity"} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stale %s survived: %v", filepath.Base(path), err)
		}
	}
	if signals, _ := handle.snapshot(); len(signals) != 0 {
		t.Fatalf("signals=%v", signals)
	}
}
