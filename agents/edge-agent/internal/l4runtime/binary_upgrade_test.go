package l4runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

// upgradeFixture: an owned master (pid 43) running an older binary than the
// configured one; USR2 makes "pid 44" (child of 43, running newInode) appear
// the way nginx does it (pid file moved to .oldbin, new pid file).
type upgradeFixture struct {
	pidFile    string
	controller *OpenResty
	old, fresh *fakeProcessHandle
	record     processIdentity
	newMaster  processIdentity
	// retiredMasters lists the (old, fresh) masters retireMaster got;
	// retireErr is what it returns.
	retiredMasters [][2]int
	retireErr      error
}

func newUpgradeFixture(t *testing.T, spawn bool, newInode func(processIdentity) processIdentity) *upgradeFixture {
	t.Helper()
	f := &upgradeFixture{pidFile: filepath.Join(t.TempDir(), "nginx.pid")}
	f.newMaster = newInode(testProcessIdentity(t, 44))
	f.record = testProcessIdentity(t, 43)
	f.record.ExecutableInode++ // the previous runtime's binary
	writeProcessFixture(t, f.pidFile, f.record)
	f.fresh = &fakeProcessHandle{}
	f.old = &fakeProcessHandle{alive: reloadAliveSamples()}
	f.old.onSignal = func(signal syscall.Signal) error {
		if signal == syscall.SIGUSR2 && spawn {
			if err := os.Rename(f.pidFile, f.pidFile+".oldbin"); err != nil {
				return err
			}
			writePIDFixture(t, f.pidFile, 44)
		}
		return nil
	}
	f.controller = testOpenResty(t, f.pidFile)
	f.controller.timeout = time.Second
	f.controller.inspect = func(pid int) (processIdentity, error) {
		if pid == 44 {
			return f.newMaster, nil
		}
		return f.record, nil
	}
	f.controller.parentPID = func(int) (int, error) { return 43, nil }
	f.controller.retireMaster = func(_ context.Context, old, fresh int) error {
		f.retiredMasters = append(f.retiredMasters, [2]int{old, fresh})
		return f.retireErr
	}
	f.controller.openProcess = func(pid int) (processHandle, error) {
		if pid == 44 {
			return f.fresh, nil
		}
		return f.old, nil
	}
	f.controller.workerGeneration = func(processIdentity) (workerGeneration, error) {
		return workerGeneration{{PID: 301, StartTicks: 3001}: {}}, nil
	}
	return f
}

func readFixture(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestOpenRestyUpgradeBinaryMovesL4MasterWithoutReload(t *testing.T) {
	f := newUpgradeFixture(t, true, func(identity processIdentity) processIdentity { return identity })
	if err := f.controller.UpgradeBinary(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The old master never gets HUP (it would retire the session workers):
	// USR2, then it is retired (QUIT/TERM/KILL) once the new master serves.
	if signals, _ := f.old.snapshot(); !reflect.DeepEqual(signals, []syscall.Signal{syscall.SIGUSR2}) {
		t.Fatalf("old master signals = %v", signals)
	}
	if !reflect.DeepEqual(f.retiredMasters, [][2]int{{43, 44}}) {
		t.Fatalf("retired masters = %v, want the old one under the new one", f.retiredMasters)
	}
	if signals, closes := f.fresh.snapshot(); len(signals) != 0 || closes != 1 {
		t.Fatalf("new master signals = %v closes = %d", signals, closes)
	}
	if got := readFixture(t, f.pidFile+".identity"); got != formatProcessRecord(f.newMaster) {
		t.Fatalf("identity record = %q, want the new master", got)
	}
	if len(f.controller.retired) != 0 {
		t.Fatalf("binary upgrade put a drain limit on the old workers: %+v", f.controller.retired)
	}
}

func TestOpenRestyUpgradeBinarySameBinaryIsNoop(t *testing.T) {
	f := newUpgradeFixture(t, true, func(identity processIdentity) processIdentity { return identity })
	f.record.ExecutableInode-- // already the configured binary
	writeProcessFixture(t, f.pidFile, f.record)
	if err := f.controller.UpgradeBinary(context.Background()); err != nil {
		t.Fatal(err)
	}
	if signals, _ := f.old.snapshot(); len(signals) != 0 {
		t.Fatalf("signals = %v, want none", signals)
	}
}

func TestOpenRestyUpgradeBinaryNewMasterAbsentKeepsOldServing(t *testing.T) {
	f := newUpgradeFixture(t, false, func(identity processIdentity) processIdentity { return identity })
	f.controller.timeout = 150 * time.Millisecond
	err := f.controller.UpgradeBinary(context.Background())
	if err == nil || !strings.Contains(err.Error(), "did not start") {
		t.Fatalf("err = %v", err)
	}
	if signals, _ := f.old.snapshot(); !reflect.DeepEqual(signals, []syscall.Signal{syscall.SIGUSR2}) {
		t.Fatalf("old master signals = %v, want USR2 only", signals)
	}
	if got := readFixture(t, f.pidFile+".identity"); got != formatProcessRecord(f.record) {
		t.Fatalf("identity record = %q, want the old master", got)
	}
}

func TestOpenRestyUpgradeBinaryWrongBinaryQuitsNewMaster(t *testing.T) {
	f := newUpgradeFixture(t, true, func(identity processIdentity) processIdentity {
		identity.ExecutableInode += 7
		return identity
	})
	err := f.controller.UpgradeBinary(context.Background())
	if err == nil || !strings.Contains(err.Error(), "does not run the switched binary") {
		t.Fatalf("err = %v", err)
	}
	if signals, _ := f.old.snapshot(); !reflect.DeepEqual(signals, []syscall.Signal{syscall.SIGUSR2}) {
		t.Fatalf("old master signals = %v, want USR2 only (no HUP, no QUIT)", signals)
	}
	if signals, _ := f.fresh.snapshot(); !reflect.DeepEqual(signals, []syscall.Signal{syscall.SIGQUIT}) {
		t.Fatalf("new master signals = %v, want QUIT", signals)
	}
	if got := readFixture(t, f.pidFile); got != "43\n" {
		t.Fatalf("pid file = %q, want the old master", got)
	}
	if got := readFixture(t, f.pidFile+".identity"); got != formatProcessRecord(f.record) {
		t.Fatalf("identity record = %q, want the old master", got)
	}
}

// nginx ignores USR2 in a master whose parent, the master an earlier upgrade
// replaced, still runs: that one is retired first, then the upgrade runs.
func TestOpenRestyUpgradeBinaryRetiresPreviousMasterFirst(t *testing.T) {
	f := newUpgradeFixture(t, true, func(identity processIdentity) processIdentity { return identity })
	writePIDFixture(t, f.pidFile+".oldbin", 42)
	f.controller.parentPID = func(pid int) (int, error) {
		if pid == 43 {
			return 42, nil
		}
		return 43, nil
	}
	if err := f.controller.UpgradeBinary(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.retiredMasters, [][2]int{{42, 43}, {43, 44}}) {
		t.Fatalf("retired masters = %v", f.retiredMasters)
	}
	if signals, _ := f.old.snapshot(); !reflect.DeepEqual(signals, []syscall.Signal{syscall.SIGUSR2}) {
		t.Fatalf("old master signals = %v", signals)
	}
}

// The previous master survived KILL: no USR2 (nginx would ignore it).
func TestOpenRestyUpgradeBinaryPreviousMasterLeftFails(t *testing.T) {
	f := newUpgradeFixture(t, true, func(identity processIdentity) processIdentity { return identity })
	writePIDFixture(t, f.pidFile+".oldbin", 42)
	f.controller.parentPID = func(int) (int, error) { return 42, nil }
	f.retireErr = errors.New("old OpenResty master 42 did not exit after KILL")
	if err := f.controller.UpgradeBinary(context.Background()); err == nil {
		t.Fatal("want an error")
	}
	if signals, _ := f.old.snapshot(); len(signals) != 0 {
		t.Fatalf("signals = %v, want none", signals)
	}
}

// A stale .oldbin (not the master's parent) retires nothing.
func TestOpenRestyUpgradeBinaryIgnoresStaleOldbin(t *testing.T) {
	f := newUpgradeFixture(t, true, func(identity processIdentity) processIdentity { return identity })
	writePIDFixture(t, f.pidFile+".oldbin", 42)
	if err := f.controller.UpgradeBinary(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.retiredMasters, [][2]int{{43, 44}}) {
		t.Fatalf("retired masters = %v", f.retiredMasters)
	}
}
