package nativebackup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fix-migrollback: stop at a safe point, abort during restore, rollback.

type cancellingRemote struct {
	*fakeRemote
	cancelOn string // command substring that cancels the migration context
	cancel   context.CancelFunc
}

func (remote *cancellingRemote) Run(ctx context.Context, command string, log func(string)) (string, error) {
	if remote.cancelOn != "" && strings.Contains(command, remote.cancelOn) {
		remote.cancel()
		remote.fakeRemote.commands = append(remote.fakeRemote.commands, command)
		return "", context.Canceled
	}
	return remote.fakeRemote.Run(ctx, command, log)
}

func cancellingRig(t *testing.T, cancelOn string) (*testRig, *cancellingRemote, PushMigrator, context.Context) {
	rig, fake, migrator := migrationRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	remote := &cancellingRemote{fakeRemote: fake, cancelOn: cancelOn, cancel: cancel}
	migrator.Dial = func(context.Context, MigrationTarget) (Remote, error) { return remote, nil }
	return rig, remote, migrator, ctx
}

func assertServing(t *testing.T, rig *testRig, want bool) {
	t.Helper()
	for _, unit := range WriterUnits {
		if state := rig.systemd.states[unit]; state.Active != want || state.Enabled != want {
			t.Fatalf("%s active/enabled = %v/%v, want %v", unit, state.Active, state.Enabled, want)
		}
	}
}

func TestMigrationStopBeforeFreezeLeavesSourceServing(t *testing.T) {
	rig, _, migrator, ctx := cancellingRig(t, "install-ubuntu-dependencies.sh")
	_, err := migrator.Migrate(ctx, testTarget, func(string) {})
	if !errors.Is(err, ErrMigrationStopped) {
		t.Fatalf("err = %v, want ErrMigrationStopped", err)
	}
	assertServing(t, rig, true)
	if len(rig.systemd.calls) != 0 {
		t.Fatalf("a stop before the backup must not touch the source: %v", rig.systemd.calls)
	}
}

func TestMigrationStopDuringTransferUnfreezesSource(t *testing.T) {
	rig, remote, migrator, ctx := cancellingRig(t, "install -d -m 0700 '"+BackupRoot+"/")
	_, err := migrator.Migrate(ctx, testTarget, func(string) {})
	if !errors.Is(err, ErrMigrationStopped) {
		t.Fatalf("err = %v, want ErrMigrationStopped", err)
	}
	assertServing(t, rig, true)
	for _, command := range remote.commands {
		if strings.Contains(command, "native-backup restore") {
			t.Fatal("a stopped migration must never start the restore")
		}
	}
	if current, _ := rig.freezer.Current(); current != nil {
		t.Fatalf("freeze record must be gone: %+v", current)
	}
}

func TestMigrationAbortDuringRestoreKeepsSourceFrozen(t *testing.T) {
	rig, _, migrator, ctx := cancellingRig(t, "native-backup restore")
	_, err := migrator.Migrate(ctx, testTarget, func(string) {})
	if !errors.Is(err, ErrMigrationAborted) {
		t.Fatalf("err = %v, want ErrMigrationAborted", err)
	}
	// The target may already run its services: only an explicit rollback
	// (with the new-master check) may restart this host.
	assertServing(t, rig, false)
	if current, _ := rig.freezer.Current(); current == nil || current.Mode != FreezeHold {
		t.Fatalf("hold must remain: %+v", current)
	}
}

func TestMigrationLogsPhasesInOrder(t *testing.T) {
	_, _, migrator := migrationRig(t)
	var phases []string
	_, err := migrator.Migrate(context.Background(), testTarget, func(line string) {
		if phase, ok := strings.CutPrefix(line, "phase: "); ok {
			phases = append(phases, phase)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"connect", "prepare_target", "backup", "transfer", "restore", "verify", "done"}
	if strings.Join(phases, ",") != strings.Join(want, ",") {
		t.Fatalf("phases = %v", phases)
	}
}

func TestRunLoggerTracksPhase(t *testing.T) {
	rig := newRig(t)
	run := Run{ID: newRunID(rig.clock), Kind: RequestMigrate, State: RunRunning, Log: []string{}}
	logger := &runLogger{layout: rig.host.Layout, run: &run, now: rig.now}
	_ = ensurePrivateDirectory(runsDirectory(rig.host.Layout))
	logger.line("phase: transfer")
	logger.line("copy: x")
	stored, err := ReadRun(rig.host.Layout, run.ID)
	if err != nil || stored.Phase != "transfer" || len(stored.Log) != 2 {
		t.Fatalf("run = %+v %v", stored, err)
	}
	if !strings.HasPrefix(stored.Log[0], rig.clock.Add(-time.Second).Format(time.RFC3339)) {
		t.Fatalf("log lines use the injected clock: %q", stored.Log[0])
	}
}

type stoppingMigrator struct{ stopped chan struct{} }

func (migrator stoppingMigrator) Migrate(ctx context.Context, _ MigrationTarget, log func(string)) (MigrationResult, error) {
	log("phase: prepare_target")
	<-ctx.Done()
	close(migrator.stopped)
	return MigrationResult{}, ErrMigrationStopped
}

func TestAgentStopRequestCancelsRunningMigration(t *testing.T) {
	rig := newRig(t)
	migrator := stoppingMigrator{stopped: make(chan struct{})}
	agent := Agent{Layout: rig.host.Layout, Backuper: rig.backuper(nil), Migrator: migrator, Now: rig.now, StopPoll: time.Millisecond}
	run, err := SubmitRequest(rig.host.Layout, Request{Kind: RequestMigrate, Migration: &testTarget}, rig.now())
	if err != nil {
		t.Fatal(err)
	}
	if err := RequestStop(rig.host.Layout, run.ID); err == nil {
		t.Fatal("a queued run that is not running yet is stopped by deleting nothing: expect refusal")
	}
	done := make(chan error, 1)
	go func() { done <- agent.Tick(context.Background()) }()
	deadline := time.After(5 * time.Second)
	for {
		if current, _ := ReadRun(rig.host.Layout, run.ID); current.State == RunRunning {
			break
		}
		select {
		case <-deadline:
			t.Fatal("migration never started")
		case <-time.After(time.Millisecond):
		}
	}
	if err := RequestStop(rig.host.Layout, run.ID); err != nil {
		t.Fatal(err)
	}
	select {
	case <-migrator.stopped:
	case <-deadline:
		t.Fatal("stop request did not cancel the migration")
	}
	<-done
	final, _ := ReadRun(rig.host.Layout, run.ID)
	if final.State != RunStopped || final.Error != "migration_stopped" {
		t.Fatalf("run = %+v", final)
	}
	if _, err := os.Stat(stopPath(rig.host.Layout, run.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the stop marker is removed when the run ends")
	}
}

func TestAgentRollbackUnfreezesHeldSource(t *testing.T) {
	rig := newRig(t)
	if _, err := rig.freezer.Acquire(context.Background(), FreezeHold, "m1"); err != nil {
		t.Fatal(err)
	}
	agent := Agent{Layout: rig.host.Layout, Backuper: rig.backuper(nil), Now: rig.now}
	agent.Backuper.Freezer = rig.freezer
	run, err := SubmitRequest(rig.host.Layout, Request{Kind: RequestRollback, RequestedBy: "admin"}, rig.now())
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertServing(t, rig, true)
	final, _ := ReadRun(rig.host.Layout, run.ID)
	if final.State != RunSucceeded || final.Kind != RequestRollback {
		t.Fatalf("run = %+v", final)
	}
}

func TestRollbackRefusedWhileMigrationRuns(t *testing.T) {
	rig := newRig(t)
	if _, err := SubmitRequest(rig.host.Layout, Request{Kind: RequestMigrate, Migration: &testTarget}, rig.now()); err != nil {
		t.Fatal(err)
	}
	if _, err := SubmitRequest(rig.host.Layout, Request{Kind: RequestRollback}, rig.now()); !errors.Is(err, ErrBusy) {
		t.Fatalf("err = %v, want ErrBusy", err)
	}
}

func TestHoldStartsFrozenConsoleAndStopsItBeforeWriters(t *testing.T) {
	fake := newFakeSystemd(t)
	freezer := testFreezer(t, fake)
	freezer.Console = FrozenConsoleUnit
	fake.states[FrozenConsoleUnit] = &UnitState{Loaded: true}
	if _, err := freezer.Acquire(context.Background(), FreezeHold, "m1"); err != nil {
		t.Fatal(err)
	}
	if state := fake.states[FrozenConsoleUnit]; !state.Active || !state.Enabled {
		t.Fatal("a hold enables and starts the frozen console")
	}
	fake.calls = nil
	if err := freezer.Unfreeze(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fake.calls) == 0 || fake.calls[0] != "stop "+FrozenConsoleUnit {
		t.Fatalf("the console must stop before control-api takes the port: %v", fake.calls)
	}
	if fake.states[FrozenConsoleUnit].Enabled {
		t.Fatal("unfreeze disables the console")
	}
	// A plain backup freeze never starts it.
	fake.calls = nil
	lease, err := freezer.Acquire(context.Background(), FreezeBackup, "b1")
	if err != nil {
		t.Fatal(err)
	}
	_ = lease.Release(context.Background())
	for _, call := range fake.calls {
		if strings.Contains(call, FrozenConsoleUnit) {
			t.Fatalf("backup freeze touched the console: %v", fake.calls)
		}
	}
	if _, ok := AgentUnits()[FrozenConsoleUnit]; !ok {
		t.Fatal("the console unit is installed with the agent units")
	}
}

func TestCleanTargetStopsServicesAndCompensatesCompletedRestore(t *testing.T) {
	rig := newRig(t)
	bundle := rig.backupBundle()
	path := rig.host.Layout.Path("/etc/systemd/system/cdnca-control-api.service")
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	_ = os.WriteFile(path, []byte("[Unit]\n"), 0o644)
	if _, err := rig.restorer(nil).Run(context.Background(), RestoreRequest{Bundle: bundle, Identity: rig.keys.Identity}); err != nil {
		t.Fatal(err)
	}
	rig.journal, rig.systemd.calls = nil, nil
	if err := rig.restorer(nil).CleanTarget(context.Background(), bundle); err != nil {
		t.Fatal(err)
	}
	if state := rig.systemd.states["cdnca-control-api.service"]; state.Active || state.Enabled {
		t.Fatalf("restored control-api must be stopped and disabled: %+v", state)
	}
	if len(rig.restored) != 0 {
		t.Fatalf("every component must be removed: %v", rig.restored)
	}
	if rig.journal[0] != "compensate "+string(ComponentOrder[len(ComponentOrder)-1]) {
		t.Fatalf("compensate in reverse order: %v", rig.journal)
	}
	// The host is empty again: a new restore of the same bundle is accepted.
	if _, err := rig.restorer(nil).Run(context.Background(), RestoreRequest{Bundle: bundle, Identity: rig.keys.Identity}); err != nil {
		t.Fatalf("restore after clean: %v", err)
	}
	if err := rig.restorer(nil).CleanTarget(context.Background(), Bundle{Manifest: Manifest{BackupID: "other"}}); err == nil {
		t.Fatal("cleaning a different bundle must be refused")
	}
}

func TestHoldWithoutConsoleUnitStillUnfreezes(t *testing.T) {
	fake := newFakeSystemd(t)
	freezer := testFreezer(t, fake)
	freezer.Console = FrozenConsoleUnit // not installed on this host
	if _, err := freezer.Acquire(context.Background(), FreezeHold, "m1"); err != nil {
		t.Fatal(err)
	}
	if err := freezer.Unfreeze(context.Background()); err != nil {
		t.Fatalf("a missing console unit must not block unfreeze: %v", err)
	}
	for _, call := range fake.calls {
		if strings.Contains(call, FrozenConsoleUnit) && !strings.HasPrefix(call, "state") {
			t.Fatalf("missing console unit was touched: %v", fake.calls)
		}
	}
}
