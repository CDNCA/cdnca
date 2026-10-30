package drainruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

type fakeDrainProcessHandle struct {
	signals    []syscall.Signal
	alive      bool
	signalErr  error
	aliveErr   error
	closeErr   error
	closeCalls int
	onSignal   func(syscall.Signal)
}

func (handle *fakeDrainProcessHandle) Signal(signal syscall.Signal) error {
	handle.signals = append(handle.signals, signal)
	if handle.onSignal != nil {
		handle.onSignal(signal)
	}
	if handle.signalErr != nil {
		return handle.signalErr
	}
	if signal == syscall.SIGKILL || signal == syscall.SIGQUIT {
		handle.alive = false
	}
	return nil
}

func (handle *fakeDrainProcessHandle) Alive() (bool, error) {
	if handle.aliveErr != nil {
		return false, handle.aliveErr
	}
	return handle.alive, nil
}

func (handle *fakeDrainProcessHandle) Close() error {
	handle.closeCalls++
	return handle.closeErr
}

func TestOpenRestyMasterIdentityFencesReloadStopAndDrain(t *testing.T) {
	operations := []struct {
		name string
		call func(*OpenResty, Artifacts) error
	}{
		{name: "activate", call: func(runtime *OpenResty, artifacts Artifacts) error {
			return runtime.ActivateNew(context.Background(), Plan{}, artifacts)
		}},
		{name: "rollback", call: func(runtime *OpenResty, artifacts Artifacts) error {
			return runtime.Rollback(context.Background(), Plan{}, artifacts)
		}},
		{name: "stop", call: func(runtime *OpenResty, _ Artifacts) error {
			return runtime.Stop(context.Background())
		}},
		{name: "drain", call: func(runtime *OpenResty, artifacts Artifacts) error {
			return runtime.BeginDrain(context.Background(), Plan{}, artifacts)
		}},
	}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			runtime, artifacts := newIdentityTestRuntime(t)
			original := testIdentity(41, 100)
			replacement := original
			replacement.StartTicks++
			installMasterFixture(t, runtime, original)
			handle := &fakeDrainProcessHandle{alive: true}
			runtime.openProcess = func(pid int) (processHandle, error) {
				if pid != original.PID {
					t.Fatalf("openProcess(%d)", pid)
				}
				return handle, nil
			}
			runtime.inspect = func(int) (processIdentity, error) { return replacement, nil }

			if err := operation.call(runtime, artifacts); err == nil {
				t.Fatal("operation accepted a reused master PID")
			}
			if len(handle.signals) != 0 || handle.closeCalls != 1 {
				t.Fatalf("replacement signals=%v close calls=%d", handle.signals, handle.closeCalls)
			}
			stored, err := readProcessRecord(runtime.pidPath + ".identity")
			if err != nil || stored != original {
				t.Fatalf("replacement state changed: %+v, %v", stored, err)
			}
		})
	}
}

func TestRemainingOldWorkersRejectsReusedWorkerPID(t *testing.T) {
	runtime, artifacts := newIdentityTestRuntime(t)
	master := testIdentity(41, 100)
	worker := testIdentity(42, 200)
	replacement := worker
	replacement.ExecutableInode++
	installMasterFixture(t, runtime, master)
	writeWorkerFixture(t, runtime, artifacts, master, []processIdentity{worker}, true)
	masterHandle := &fakeDrainProcessHandle{alive: true}
	workerHandle := &fakeDrainProcessHandle{alive: true}
	runtime.openProcess = func(pid int) (processHandle, error) {
		switch pid {
		case master.PID:
			return masterHandle, nil
		case worker.PID:
			return workerHandle, nil
		default:
			return nil, fmt.Errorf("unexpected PID %d", pid)
		}
	}
	runtime.inspect = func(pid int) (processIdentity, error) {
		if pid == master.PID {
			return master, nil
		}
		return replacement, nil
	}

	remaining, err := runtime.RemainingOldWorkers(context.Background(), Plan{}, artifacts)
	if err == nil || remaining != 0 {
		t.Fatalf("RemainingOldWorkers() = %d, %v", remaining, err)
	}
	if len(workerHandle.signals) != 0 || workerHandle.closeCalls != 1 || masterHandle.closeCalls != 1 {
		t.Fatalf("replacement signals=%v worker close=%d master close=%d", workerHandle.signals, workerHandle.closeCalls, masterHandle.closeCalls)
	}
}

func TestRemainingOldWorkersTreatsRecordedZombieAsExited(t *testing.T) {
	runtime, artifacts := newIdentityTestRuntime(t)
	master := testIdentity(41, 100)
	worker := testIdentity(42, 200)
	installMasterFixture(t, runtime, master)
	writeWorkerFixture(t, runtime, artifacts, master, []processIdentity{worker}, true)
	masterHandle := &fakeDrainProcessHandle{alive: true}
	workerHandle := &fakeDrainProcessHandle{alive: true}
	runtime.openProcess = handleLookup(map[int]processHandle{master.PID: masterHandle, worker.PID: workerHandle})
	runtime.inspect = func(pid int) (processIdentity, error) {
		if pid == master.PID {
			return master, nil
		}
		return processIdentity{}, errProcessExited
	}

	remaining, err := runtime.RemainingOldWorkers(context.Background(), Plan{}, artifacts)
	if err != nil || remaining != 0 {
		t.Fatalf("RemainingOldWorkers() = %d, %v", remaining, err)
	}
	if len(workerHandle.signals) != 0 || workerHandle.closeCalls != 1 || masterHandle.closeCalls != 1 {
		t.Fatalf("worker signals=%v worker close=%d master close=%d", workerHandle.signals, workerHandle.closeCalls, masterHandle.closeCalls)
	}
}

func TestRemainingOldWorkersKeepsUnverifiablePIDFDDraining(t *testing.T) {
	runtime, artifacts := newIdentityTestRuntime(t)
	master := testIdentity(41, 100)
	worker := testIdentity(42, 200)
	installMasterFixture(t, runtime, master)
	writeWorkerFixture(t, runtime, artifacts, master, []processIdentity{worker}, true)
	masterHandle := &fakeDrainProcessHandle{alive: true}
	workerHandle := &fakeDrainProcessHandle{alive: true}
	runtime.openProcess = handleLookup(map[int]processHandle{master.PID: masterHandle, worker.PID: workerHandle})
	runtime.inspect = func(pid int) (processIdentity, error) {
		if pid == master.PID {
			return master, nil
		}
		return processIdentity{}, errProcessNotRunning
	}

	remaining, err := runtime.RemainingOldWorkers(context.Background(), Plan{}, artifacts)
	if err != nil || remaining != 1 {
		t.Fatalf("RemainingOldWorkers() = %d, %v", remaining, err)
	}
	if len(workerHandle.signals) != 0 || workerHandle.closeCalls != 1 || masterHandle.closeCalls != 1 {
		t.Fatalf("worker signals=%v worker close=%d master close=%d", workerHandle.signals, workerHandle.closeCalls, masterHandle.closeCalls)
	}
}

func TestOpenRestyAllowsOwnedMasterToTrackLowerPrivilegeWorkers(t *testing.T) {
	runtime, _ := newIdentityTestRuntime(t)
	master := testIdentity(41, 100)
	worker := testIdentity(42, 200)
	worker.OwnerUID = master.OwnerUID + 1
	installMasterFixture(t, runtime, master)
	masterHandle := &fakeDrainProcessHandle{alive: true}
	workerHandle := &fakeDrainProcessHandle{alive: true}
	runtime.children = stableChildren(worker.PID)
	runtime.inspect = identityLookup(master, worker)
	runtime.openProcess = handleLookup(map[int]processHandle{master.PID: masterHandle, worker.PID: workerHandle})

	generation, workers, err := runtime.captureWorkerGeneration(master)
	if err != nil || !validHex(generation, 32) || len(workers) != 1 || workers[0].Identity != worker {
		t.Fatalf("captureWorkerGeneration() = %q, %+v, %v", generation, workers, err)
	}
	if masterHandle.closeCalls != 1 || workerHandle.closeCalls != 1 {
		t.Fatalf("close calls master=%d worker=%d", masterHandle.closeCalls, workerHandle.closeCalls)
	}
}

func TestOpenRestyRejectsForeignMasterIdentity(t *testing.T) {
	runtime, _ := newIdentityTestRuntime(t)
	master := testIdentity(41, 100)
	master.OwnerUID++
	installMasterFixture(t, runtime, master)
	handle := &fakeDrainProcessHandle{alive: true}
	runtime.inspect = func(int) (processIdentity, error) { return master, nil }
	runtime.openProcess = func(int) (processHandle, error) { return handle, nil }

	if running, err := runtime.running(); err == nil || running {
		t.Fatalf("running() = %v, %v", running, err)
	}
	if len(handle.signals) != 0 || handle.closeCalls != 1 {
		t.Fatalf("foreign master signals=%v close calls=%d", handle.signals, handle.closeCalls)
	}
}

func TestOpenRestyProcessStateRejectsUnsafeFiles(t *testing.T) {
	for _, test := range []struct {
		name  string
		build func(*testing.T, string)
	}{
		{name: "symlink", build: func(t *testing.T, path string) {
			target := path + ".target"
			mustWriteFile(t, target, []byte("safe\n"), 0o600)
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "directory", build: func(t *testing.T, path string) {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "hardlink", build: func(t *testing.T, path string) {
			mustWriteFile(t, path, []byte("safe\n"), 0o600)
			if err := os.Link(path, path+".link"); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "group writable", build: func(t *testing.T, path string) {
			mustWriteFile(t, path, []byte("safe\n"), 0o620)
		}},
		{name: "world writable", build: func(t *testing.T, path string) {
			mustWriteFile(t, path, []byte("safe\n"), 0o602)
		}},
		{name: "empty", build: func(t *testing.T, path string) {
			mustWriteFile(t, path, nil, 0o600)
		}},
		{name: "oversize", build: func(t *testing.T, path string) {
			mustWriteFile(t, path, []byte(strings.Repeat("x", 33)), 0o600)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state")
			test.build(t, path)
			if _, _, err := readOwnedProcessFile(path, 32); err == nil {
				t.Fatal("unsafe process state was accepted")
			}
		})
	}

	path := filepath.Join(t.TempDir(), "foreign")
	mustWriteFile(t, path, []byte("safe\n"), 0o600)
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateProcessFileInfo(info, uint32(os.Geteuid())+1, 32); err == nil {
		t.Fatal("foreign-owned process state was accepted")
	}

	runtime, artifacts := newIdentityTestRuntime(t)
	master := testIdentity(41, 100)
	record := makeWorkerRecord(artifacts, master, []processIdentity{testIdentity(42, 200)}, true)
	content, err := marshalWorkerRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, runtime.workersPath, content, 0o622)
	if err := os.Chmod(runtime.workersPath, 0o622); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.loadWorkers(); !errors.Is(err, ErrCorruptState) {
		t.Fatalf("loadWorkers() error = %v", err)
	}
}

func TestOpenRestyStartIdentityIsDurableAndRecoverable(t *testing.T) {
	runtime, _ := newIdentityTestRuntime(t)
	identity := testIdentity(41, 100)
	start := processStartIdentity{
		ExecutableDevice: identity.ExecutableDevice, ExecutableInode: identity.ExecutableInode,
		OwnerUID: identity.OwnerUID, Token: strings.Repeat("a", 64),
	}
	mustWriteFile(t, runtime.pidPath+".identity.pending", []byte(formatProcessStartIdentity(start)), 0o600)
	mustWriteFile(t, runtime.startPIDPath(start.Token), []byte(strconv.Itoa(identity.PID)+"\n"), 0o600)
	handle := &fakeDrainProcessHandle{alive: true}
	runtime.inspect = func(int) (processIdentity, error) { return identity, nil }
	runtime.matchStart = func(pid int, token string) error {
		if pid != identity.PID || token != start.Token {
			t.Fatalf("matchStart(%d, %q)", pid, token)
		}
		return nil
	}
	runtime.openProcess = func(int) (processHandle, error) { return handle, nil }

	running, err := runtime.running()
	if err != nil || !running {
		t.Fatalf("running() = %v, %v", running, err)
	}
	if handle.closeCalls != 1 || len(handle.signals) != 0 {
		t.Fatalf("recovery signals=%v close calls=%d", handle.signals, handle.closeCalls)
	}
	stored, err := readProcessRecord(runtime.pidPath + ".identity")
	if err != nil || stored != identity {
		t.Fatalf("stored identity = %+v, %v", stored, err)
	}
	if _, err := os.Lstat(runtime.pidPath + ".identity.pending"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending identity residue: %v", err)
	}
}

func TestOpenRestyPersistsPendingIdentityBeforeDaemonStart(t *testing.T) {
	runtime, artifacts := newIdentityTestRuntime(t)
	binaryInfo, err := os.Stat(runtime.binary)
	if err != nil {
		t.Fatal(err)
	}
	binaryStat := binaryInfo.Sys().(*syscall.Stat_t)
	identity := processIdentity{
		PID: 41, StartTicks: 100, ExecutableDevice: uint64(binaryStat.Dev), ExecutableInode: uint64(binaryStat.Ino),
		OwnerUID: uint32(os.Geteuid()), BootID: "boot-a",
	}
	handle := &fakeDrainProcessHandle{alive: true}
	runtime.inspect = func(int) (processIdentity, error) { return identity, nil }
	runtime.matchStart = func(pid int, token string) error {
		if pid != identity.PID || len(token) != 64 {
			return errors.New("start token mismatch")
		}
		return nil
	}
	runtime.openProcess = func(int) (processHandle, error) { return handle, nil }
	sawPending := false
	runtime.startProcess = func(_ context.Context, token string, arguments ...string) error {
		if strings.Contains(strings.Join(arguments, " "), processStartEnvironment) {
			return errors.New("pending start token was exported to the OpenResty environment")
		}
		pending, exists, err := readOptionalProcessStartIdentity(runtime.pidPath + ".identity.pending")
		if err != nil || !exists || pending.Token != token || !pending.matches(identity) {
			return fmt.Errorf("pending before start = %+v, exists=%v, error=%v", pending, exists, err)
		}
		sawPending = true
		return os.WriteFile(runtime.startPIDPath(token), []byte(strconv.Itoa(identity.PID)+"\n"), 0o600)
	}

	if err := runtime.StartBaseline(context.Background(), artifacts.CandidatePath); err != nil {
		t.Fatal(err)
	}
	if !sawPending || handle.closeCalls != 1 || len(handle.signals) != 0 {
		t.Fatalf("saw pending=%v signals=%v close calls=%d", sawPending, handle.signals, handle.closeCalls)
	}
	stored, err := readProcessRecord(runtime.pidPath + ".identity")
	if err != nil || stored != identity {
		t.Fatalf("stored identity = %+v, %v", stored, err)
	}
	if _, err := os.Lstat(runtime.pidPath + ".identity.pending"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending identity residue: %v", err)
	}
}

func TestOpenRestyPendingRecoveryRejectsTokenMismatchWithoutCleanup(t *testing.T) {
	runtime, _ := newIdentityTestRuntime(t)
	identity := testIdentity(41, 100)
	start := processStartIdentity{
		ExecutableDevice: identity.ExecutableDevice, ExecutableInode: identity.ExecutableInode,
		OwnerUID: identity.OwnerUID, Token: strings.Repeat("a", 64),
	}
	mustWriteFile(t, runtime.pidPath+".identity.pending", []byte(formatProcessStartIdentity(start)), 0o600)
	mustWriteFile(t, runtime.startPIDPath(start.Token), []byte(strconv.Itoa(identity.PID)+"\n"), 0o600)
	runtime.inspect = func(int) (processIdentity, error) { return identity, nil }
	runtime.matchStart = func(int, string) error { return errors.New("token mismatch") }
	runtime.openProcess = func(int) (processHandle, error) {
		t.Fatal("pidfd opened after token mismatch")
		return nil, nil
	}

	if running, err := runtime.running(); err == nil || running {
		t.Fatalf("running() = %v, %v", running, err)
	}
	if _, err := os.Lstat(runtime.pidPath + ".identity.pending"); err != nil {
		t.Fatalf("pending identity was removed: %v", err)
	}
}

func TestCaptureWorkerGenerationRejectsSetAndIdentityChanges(t *testing.T) {
	for _, test := range []struct {
		name     string
		children [][]int
		changed  bool
	}{
		{name: "set changed", children: [][]int{{42}, {43}}},
		{name: "identity changed", children: [][]int{{42}, {42}}, changed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime, _ := newIdentityTestRuntime(t)
			master := testIdentity(41, 100)
			worker := testIdentity(42, 200)
			replacement := worker
			replacement.StartTicks++
			childCalls := 0
			runtime.children = func(int) ([]int, error) {
				value := test.children[childCalls]
				childCalls++
				return value, nil
			}
			inspectCalls := 0
			runtime.inspect = func(pid int) (processIdentity, error) {
				if pid == master.PID {
					return master, nil
				}
				inspectCalls++
				if test.changed && inspectCalls > 1 {
					return replacement, nil
				}
				return worker, nil
			}
			masterHandle := &fakeDrainProcessHandle{alive: true}
			workerHandle := &fakeDrainProcessHandle{alive: true}
			installMasterFixture(t, runtime, master)
			runtime.openProcess = func(pid int) (processHandle, error) {
				if pid == master.PID {
					return masterHandle, nil
				}
				return workerHandle, nil
			}

			if _, _, err := runtime.captureWorkerGeneration(master); err == nil {
				t.Fatal("changed worker generation was accepted")
			}
			if masterHandle.closeCalls != 1 || workerHandle.closeCalls != 1 || len(masterHandle.signals) != 0 || len(workerHandle.signals) != 0 {
				t.Fatalf("master signals=%v close=%d worker signals=%v close=%d", masterHandle.signals, masterHandle.closeCalls, workerHandle.signals, workerHandle.closeCalls)
			}
		})
	}
}

func TestBeginDrainRestartKeepsOriginalWorkerGeneration(t *testing.T) {
	runtime, artifacts := newIdentityTestRuntime(t)
	master := testIdentity(41, 100)
	oldWorker := testIdentity(42, 200)
	installMasterFixture(t, runtime, master)
	writeWorkerFixture(t, runtime, artifacts, master, []processIdentity{oldWorker}, false)
	masterHandle := &fakeDrainProcessHandle{alive: true}
	runtime.openProcess = func(pid int) (processHandle, error) {
		if pid != master.PID {
			t.Fatalf("unexpected pidfd capture for PID %d", pid)
		}
		return masterHandle, nil
	}
	runtime.inspect = func(int) (processIdentity, error) { return master, nil }
	runtime.children = func(int) ([]int, error) {
		t.Fatal("restart recovery recaptured a new worker generation")
		return nil, nil
	}

	if err := runtime.BeginDrain(context.Background(), Plan{}, artifacts); err != nil {
		t.Fatal(err)
	}
	if len(masterHandle.signals) != 1 || masterHandle.signals[0] != syscall.SIGHUP || masterHandle.closeCalls != 1 {
		t.Fatalf("master signals=%v close calls=%d", masterHandle.signals, masterHandle.closeCalls)
	}
	stored, err := runtime.loadWorkers()
	if err != nil || !stored.Reloaded || len(stored.Workers) != 1 || stored.Workers[0].Identity != oldWorker {
		t.Fatalf("stored worker generation changed: %+v, %v", stored, err)
	}
}

func TestWorkerRecordRejectsMixedGenerationIdentityPairs(t *testing.T) {
	runtime, artifacts := newIdentityTestRuntime(t)
	master := testIdentity(41, 100)
	worker := testIdentity(42, 200)
	valid := makeWorkerRecord(artifacts, master, []processIdentity{worker}, true)
	for _, mutate := range []struct {
		name string
		call func(*workerRecord)
	}{
		{name: "set generation", call: func(record *workerRecord) { record.Generation = strings.Repeat("b", 64) }},
		{name: "entry generation", call: func(record *workerRecord) { record.Workers[0].Generation = strings.Repeat("b", 64) }},
		{name: "missing start ticks", call: func(record *workerRecord) { record.Workers[0].Identity.StartTicks = 0 }},
		{name: "duplicate identity", call: func(record *workerRecord) { record.Workers = append(record.Workers, record.Workers[0]) }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			record := *valid
			record.Workers = append([]workerIdentity(nil), valid.Workers...)
			mutate.call(&record)
			content, err := marshalWorkerRecord(&record)
			if err != nil {
				t.Fatal(err)
			}
			mustWriteFile(t, runtime.workersPath, content, 0o600)
			if _, err := runtime.loadWorkers(); !errors.Is(err, ErrCorruptState) {
				t.Fatalf("loadWorkers() error = %v", err)
			}
		})
	}
}

func TestForceTerminateValidatesWholeSetBeforeAnySignal(t *testing.T) {
	runtime, artifacts := newIdentityTestRuntime(t)
	master := testIdentity(41, 100)
	worker1 := testIdentity(42, 200)
	worker2 := testIdentity(43, 201)
	installMasterFixture(t, runtime, master)
	writeWorkerFixture(t, runtime, artifacts, master, []processIdentity{worker1, worker2}, true)
	masterHandle := &fakeDrainProcessHandle{alive: true}
	firstHandle := &fakeDrainProcessHandle{alive: true}
	openError := errors.New("pidfd unavailable")
	runtime.children = stableChildren(worker1.PID, worker2.PID)
	runtime.inspect = identityLookup(master, worker1, worker2)
	runtime.openProcess = func(pid int) (processHandle, error) {
		switch pid {
		case master.PID:
			return masterHandle, nil
		case worker1.PID:
			return firstHandle, nil
		case worker2.PID:
			return nil, openError
		default:
			return nil, fmt.Errorf("unexpected PID %d", pid)
		}
	}

	err := runtime.ForceTerminate(context.Background(), Plan{}, artifacts)
	if !errors.Is(err, openError) {
		t.Fatalf("ForceTerminate() error = %v", err)
	}
	if len(firstHandle.signals) != 0 || firstHandle.closeCalls != 1 || masterHandle.closeCalls != 1 {
		t.Fatalf("worker1 signals=%v close=%d master close=%d", firstHandle.signals, firstHandle.closeCalls, masterHandle.closeCalls)
	}
}

func TestForceTerminateUsesExactPIDFDAndWaitsForExit(t *testing.T) {
	runtime, artifacts := newIdentityTestRuntime(t)
	master := testIdentity(41, 100)
	worker := testIdentity(42, 200)
	installMasterFixture(t, runtime, master)
	writeWorkerFixture(t, runtime, artifacts, master, []processIdentity{worker}, true)
	masterHandle := &fakeDrainProcessHandle{alive: true}
	workerHandle := &fakeDrainProcessHandle{alive: true}
	runtime.children = stableChildren(worker.PID)
	runtime.inspect = identityLookup(master, worker)
	runtime.openProcess = handleLookup(map[int]processHandle{master.PID: masterHandle, worker.PID: workerHandle})

	if err := runtime.ForceTerminate(context.Background(), Plan{}, artifacts); err != nil {
		t.Fatal(err)
	}
	if len(workerHandle.signals) != 1 || workerHandle.signals[0] != syscall.SIGKILL || workerHandle.closeCalls != 1 || masterHandle.closeCalls != 1 {
		t.Fatalf("worker signals=%v worker close=%d master close=%d", workerHandle.signals, workerHandle.closeCalls, masterHandle.closeCalls)
	}
}

func TestIdentityChangeBetweenCheckAndSignalFailsClosed(t *testing.T) {
	runtime, artifacts := newIdentityTestRuntime(t)
	master := testIdentity(41, 100)
	worker := testIdentity(42, 200)
	replacement := worker
	replacement.StartTicks++
	installMasterFixture(t, runtime, master)
	writeWorkerFixture(t, runtime, artifacts, master, []processIdentity{worker}, true)
	masterHandle := &fakeDrainProcessHandle{alive: true}
	workerHandle := &fakeDrainProcessHandle{alive: true}
	runtime.children = stableChildren(worker.PID)
	workerInspections := 0
	runtime.inspect = func(pid int) (processIdentity, error) {
		if pid == master.PID {
			return master, nil
		}
		workerInspections++
		if workerInspections > 1 {
			return replacement, nil
		}
		return worker, nil
	}
	runtime.openProcess = handleLookup(map[int]processHandle{master.PID: masterHandle, worker.PID: workerHandle})

	if err := runtime.ForceTerminate(context.Background(), Plan{}, artifacts); err == nil {
		t.Fatal("ForceTerminate accepted a check-to-signal identity change")
	}
	if len(workerHandle.signals) != 0 || workerHandle.closeCalls != 1 {
		t.Fatalf("replacement signals=%v close calls=%d", workerHandle.signals, workerHandle.closeCalls)
	}
}

func TestReloadPostSignalIdentityChangeIsNotSuccess(t *testing.T) {
	runtime, artifacts := newIdentityTestRuntime(t)
	master := testIdentity(41, 100)
	replacement := master
	replacement.BootID = "boot-b"
	installMasterFixture(t, runtime, master)
	changed := false
	handle := &fakeDrainProcessHandle{alive: true, onSignal: func(syscall.Signal) { changed = true }}
	runtime.openProcess = func(int) (processHandle, error) { return handle, nil }
	runtime.inspect = func(int) (processIdentity, error) {
		if changed {
			return replacement, nil
		}
		return master, nil
	}

	if err := runtime.ActivateNew(context.Background(), Plan{}, artifacts); err == nil {
		t.Fatal("reload reported success after the master identity changed")
	}
	if len(handle.signals) != 1 || handle.signals[0] != syscall.SIGHUP || handle.closeCalls != 1 {
		t.Fatalf("signals=%v close calls=%d", handle.signals, handle.closeCalls)
	}
}

func TestOpenRestyRequiresLinuxProcfsAndPIDFD(t *testing.T) {
	runtime, artifacts := newIdentityTestRuntime(t)
	master := testIdentity(41, 100)
	worker := testIdentity(42, 200)
	installMasterFixture(t, runtime, master)
	writeWorkerFixture(t, runtime, artifacts, master, []processIdentity{worker}, true)
	runtime.identityOK = false
	if running, err := runtime.running(); err == nil || running {
		t.Fatalf("running() without Linux identity support = %v, %v", running, err)
	}

	runtime.identityOK = true
	runtime.inspect = identityLookup(master, worker)
	runtime.children = stableChildren(worker.PID)
	runtime.openProcess = func(int) (processHandle, error) { return nil, syscall.ENOSYS }
	if _, err := runtime.RemainingOldWorkers(context.Background(), Plan{}, artifacts); err == nil {
		t.Fatal("RemainingOldWorkers fell back after pidfd failure")
	}
	if err := runtime.ForceTerminate(context.Background(), Plan{}, artifacts); err == nil {
		t.Fatal("ForceTerminate fell back after pidfd failure")
	}

	procError := errors.New("procfs unavailable")
	runtime.openProcess = func(int) (processHandle, error) { return &fakeDrainProcessHandle{alive: true}, nil }
	runtime.inspect = func(int) (processIdentity, error) { return processIdentity{}, procError }
	if running, err := runtime.running(); !errors.Is(err, procError) || running {
		t.Fatalf("running() procfs error = %v, %v", running, err)
	}
}

func TestOpenRestyJoinsCleanupAndCloseErrors(t *testing.T) {
	runtime, artifacts := newIdentityTestRuntime(t)
	master := testIdentity(41, 100)
	worker := testIdentity(42, 200)
	installMasterFixture(t, runtime, master)
	writeWorkerFixture(t, runtime, artifacts, master, []processIdentity{worker}, true)
	masterClose := errors.New("master close failed")
	workerClose := errors.New("worker close failed")
	signalError := errors.New("signal failed")
	masterHandle := &fakeDrainProcessHandle{alive: true, closeErr: masterClose}
	workerHandle := &fakeDrainProcessHandle{alive: true, closeErr: workerClose, signalErr: signalError}
	runtime.children = stableChildren(worker.PID)
	runtime.inspect = identityLookup(master, worker)
	runtime.openProcess = handleLookup(map[int]processHandle{master.PID: masterHandle, worker.PID: workerHandle})

	err := runtime.ForceTerminate(context.Background(), Plan{}, artifacts)
	for _, expected := range []error{signalError, workerClose, masterClose} {
		if !errors.Is(err, expected) {
			t.Fatalf("ForceTerminate() error %v does not include %v", err, expected)
		}
	}
	if masterHandle.closeCalls != 1 || workerHandle.closeCalls != 1 {
		t.Fatalf("close calls master=%d worker=%d", masterHandle.closeCalls, workerHandle.closeCalls)
	}
}

func TestOpenRestyPIDFDsDoNotLeakAcrossSuccessAndFailure(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("pidfd leak proof requires Linux")
	}
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 64; index++ {
		handle, err := openPIDFD(os.Getpid())
		if err != nil {
			t.Fatal(err)
		}
		if err := handle.Close(); err != nil {
			t.Fatal(err)
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("pidfd count grew from %d to %d", len(before), len(after))
	}
}

func TestLinuxPIDFDIdentitySmoke(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux process identity smoke requires procfs and pidfd")
	}
	identity, err := kernelProcessIdentity(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if !validProcessIdentity(identity) || identity.PID != os.Getpid() || identity.OwnerUID != uint32(os.Geteuid()) {
		t.Fatalf("kernel identity = %+v", identity)
	}
	handle, err := openPIDFD(identity.PID)
	if err != nil {
		t.Fatal(err)
	}
	if alive, err := handle.Alive(); err != nil || !alive {
		_ = handle.Close()
		t.Fatalf("pidfd alive = %v, %v", alive, err)
	}
	if err := handle.Signal(0); err != nil {
		_ = handle.Close()
		t.Fatal(err)
	}
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}
}

func newIdentityTestRuntime(t *testing.T) (*OpenResty, Artifacts) {
	t.Helper()
	// These cases set identityOK, i.e. run the Linux process-identity path.
	// That path reaches the pinned prefix and logs directories through their
	// descriptors (/proc/self/fd/N/nginx.pid); only Linux procfs resolves a
	// directory descriptor as a path prefix, macOS /dev/fd/N does not. Off
	// Linux the runtime refuses that path (identityOK false), which
	// TestOpenRestyRequiresLinuxProcfsAndPIDFD's first half pins on Linux.
	if runtime.GOOS != "linux" {
		t.Skip("OpenResty process identity fixtures need Linux procfs descriptor paths")
	}
	root := t.TempDir()
	runtime, err := NewOpenResty("/usr/bin/true", filepath.Join(root, "openresty"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	runtime.identityOK = true
	for _, name := range []string{"candidate.conf", "draining.conf", "rollback.conf"} {
		mustWriteFile(t, filepath.Join(root, name), []byte("events {}\n"), 0o600)
	}
	return runtime, Artifacts{
		Revision: 1, Digest: strings.Repeat("a", 64),
		CandidatePath: filepath.Join(root, "candidate.conf"), DrainingPath: filepath.Join(root, "draining.conf"),
		RollbackPath: filepath.Join(root, "rollback.conf"),
	}
}

func testIdentity(pid int, start uint64) processIdentity {
	return processIdentity{
		PID: pid, StartTicks: start, ExecutableDevice: 7, ExecutableInode: uint64(1000 + pid),
		OwnerUID: uint32(os.Geteuid()), BootID: "boot-a",
	}
}

func installMasterFixture(t *testing.T, runtime *OpenResty, identity processIdentity) {
	t.Helper()
	mustWriteFile(t, runtime.pidPath, []byte(strconv.Itoa(identity.PID)+"\n"), 0o600)
	mustWriteFile(t, runtime.pidPath+".identity", []byte(formatProcessRecord(identity)), 0o600)
}

func writeWorkerFixture(t *testing.T, runtime *OpenResty, artifacts Artifacts, master processIdentity, workers []processIdentity, reloaded bool) {
	t.Helper()
	if err := runtime.saveWorkers(makeWorkerRecord(artifacts, master, workers, reloaded)); err != nil {
		t.Fatal(err)
	}
}

func makeWorkerRecord(artifacts Artifacts, master processIdentity, identities []processIdentity, reloaded bool) *workerRecord {
	generation := workerGeneration(master, identities)
	workers := make([]workerIdentity, 0, len(identities))
	for _, identity := range identities {
		workers = append(workers, workerIdentity{Generation: generation, Identity: identity})
	}
	return &workerRecord{
		SchemaVersion: workerRecordSchemaVersion, Revision: artifacts.Revision, Digest: artifacts.Digest,
		Reloaded: reloaded, Generation: generation, Master: master, Workers: workers,
	}
}

func marshalWorkerRecord(record *workerRecord) ([]byte, error) {
	return json.Marshal(record)
}

func mustWriteFile(t *testing.T, path string, content []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func stableChildren(pids ...int) func(int) ([]int, error) {
	return func(int) ([]int, error) { return append([]int(nil), pids...), nil }
}

func identityLookup(identities ...processIdentity) func(int) (processIdentity, error) {
	values := make(map[int]processIdentity, len(identities))
	for _, identity := range identities {
		values[identity.PID] = identity
	}
	return func(pid int) (processIdentity, error) {
		identity, ok := values[pid]
		if !ok {
			return processIdentity{}, errProcessNotRunning
		}
		return identity, nil
	}
}

func handleLookup(handles map[int]processHandle) func(int) (processHandle, error) {
	return func(pid int) (processHandle, error) {
		handle, ok := handles[pid]
		if !ok {
			return nil, fmt.Errorf("unexpected PID %d", pid)
		}
		return handle, nil
	}
}
