package l4runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"
)

var errStartupWorkerSnapshot = errors.New("injected startup worker snapshot failure")

type initialStartFixture struct {
	root       string
	pidFile    string
	record     processIdentity
	controller *OpenResty
	handle     *fakeProcessHandle
	starts     int
	opens      int
}

func newInitialStartFixture(t *testing.T, timeout time.Duration,
	snapshot func(processIdentity) (workerGeneration, error)) *initialStartFixture {
	t.Helper()

	root := t.TempDir()
	pidFile := filepath.Join(root, "nginx.pid")
	record := testProcessIdentity(t, 43)
	handle := &fakeProcessHandle{alive: reloadAliveSamples()}
	handle.onSignal = func(signal syscall.Signal) error {
		if signal == syscall.SIGQUIT {
			handle.mu.Lock()
			handle.alive = []bool{false}
			handle.mu.Unlock()
		}
		return nil
	}
	controller := testOpenResty(t, pidFile)
	controller.timeout = timeout
	controller.inspect = func(int) (processIdentity, error) { return record, nil }
	controller.matchStart = func(pid int, token string) error {
		if pid != record.PID || token == "" {
			return errors.New("unexpected startup identity")
		}
		return nil
	}
	fixture := &initialStartFixture{
		root: root, pidFile: pidFile, record: record, controller: controller, handle: handle,
	}
	controller.openProcess = func(pid int) (processHandle, error) {
		fixture.opens++
		if pid != record.PID {
			return nil, errors.New("unexpected startup PID")
		}
		return handle, nil
	}
	controller.start = func(context.Context, []string, ...string) error {
		fixture.starts++
		writePIDFixture(t, pidFile, record.PID)
		return nil
	}
	controller.workerGeneration = snapshot
	return fixture
}

func (fixture *initialStartFixture) assertFailedAndClean(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("Activate() accepted an initial master without a stable worker generation")
	}
	if fixture.starts != 1 || fixture.opens != 1 {
		t.Fatalf("startup attempts=%d pidfd opens=%d, want one each", fixture.starts, fixture.opens)
	}
	if signals, closes := fixture.handle.snapshot(); !reflect.DeepEqual(signals, []syscall.Signal{syscall.SIGQUIT}) || closes != 1 {
		t.Fatalf("signals=%v closeCalls=%d, want one SIGQUIT and one close", signals, closes)
	}
	for _, path := range []string{fixture.pidFile, fixture.pidFile + ".identity", fixture.pidFile + ".identity.pending"} {
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("failed startup left %s: %v", filepath.Base(path), statErr)
		}
	}
}

func TestOpenRestyInitialStartRequiresStableWorkerGeneration(t *testing.T) {
	t.Run("mixed root and dropped owners stabilize", func(t *testing.T) {
		mixedErr := mixedWorkerOwnerError(t)
		calls := 0
		fixture := newInitialStartFixture(t, time.Second, func(processIdentity) (workerGeneration, error) {
			calls++
			if calls <= 2 {
				return nil, mixedErr
			}
			return workerGeneration{{PID: 201, StartTicks: 2001, OwnerUID: 65534}: {}}, nil
		})
		if err := fixture.controller.Activate(context.Background(), fixture.root); err != nil {
			t.Fatalf("Activate() error=%v", err)
		}
		if calls < 4 {
			t.Fatalf("worker generation snapshots=%d, want mixed and stable samples", calls)
		}
	})

	t.Run("mixed owners until deadline fail closed", func(t *testing.T) {
		mixedErr := mixedWorkerOwnerError(t)
		fixture := newInitialStartFixture(t, 80*time.Millisecond, func(processIdentity) (workerGeneration, error) {
			return nil, mixedErr
		})
		started := time.Now()
		err := fixture.controller.Activate(context.Background(), fixture.root)
		fixture.assertFailedAndClean(t, err)
		if elapsed := time.Since(started); elapsed < 60*time.Millisecond {
			t.Fatalf("persistent mixed owners failed after %s, want bounded retry", elapsed)
		}
	})

	t.Run("foreign worker identity is fatal immediately", func(t *testing.T) {
		foreignErr := errors.New("foreign worker executable")
		fixture := newInitialStartFixture(t, time.Second, func(processIdentity) (workerGeneration, error) {
			return nil, foreignErr
		})
		started := time.Now()
		err := fixture.controller.Activate(context.Background(), fixture.root)
		if !errors.Is(err, foreignErr) {
			t.Fatalf("Activate() error=%v, want foreign identity error", err)
		}
		if elapsed := time.Since(started); elapsed >= reloadWorkerStabilityWindow {
			t.Fatalf("foreign worker identity retried for %s", elapsed)
		}
		fixture.assertFailedAndClean(t, err)
	})

	t.Run("no workers until timeout", func(t *testing.T) {
		fixture := newInitialStartFixture(t, 80*time.Millisecond, func(processIdentity) (workerGeneration, error) {
			return workerGeneration{}, nil
		})
		fixture.assertFailedAndClean(t, fixture.controller.Activate(context.Background(), fixture.root))
	})

	t.Run("worker generation churn never stabilizes", func(t *testing.T) {
		calls := 0
		fixture := newInitialStartFixture(t, 120*time.Millisecond, func(processIdentity) (workerGeneration, error) {
			calls++
			if calls%2 == 0 {
				return workerGeneration{{PID: 202, StartTicks: 2002}: {}}, nil
			}
			return workerGeneration{{PID: 201, StartTicks: 2001}: {}}, nil
		})
		fixture.assertFailedAndClean(t, fixture.controller.Activate(context.Background(), fixture.root))
		if calls < 2 {
			t.Fatalf("worker generation snapshots=%d, want churn to be observed", calls)
		}
	})

	t.Run("worker snapshot failure", func(t *testing.T) {
		fixture := newInitialStartFixture(t, time.Second, func(processIdentity) (workerGeneration, error) {
			return nil, errStartupWorkerSnapshot
		})
		err := fixture.controller.Activate(context.Background(), fixture.root)
		if !errors.Is(err, errStartupWorkerSnapshot) {
			t.Fatalf("Activate() error=%v, want snapshot failure", err)
		}
		fixture.assertFailedAndClean(t, err)
	})

	t.Run("master identity drifts during stability window", func(t *testing.T) {
		fixture := newInitialStartFixture(t, time.Second, func(processIdentity) (workerGeneration, error) {
			return workerGeneration{{PID: 201, StartTicks: 2001}: {}}, nil
		})
		inspectCalls := 0
		fixture.controller.inspect = func(int) (processIdentity, error) {
			inspectCalls++
			if inspectCalls <= 3 {
				return fixture.record, nil
			}
			drifted := fixture.record
			drifted.StartTicks++
			return drifted, nil
		}
		fixture.assertFailedAndClean(t, fixture.controller.Activate(context.Background(), fixture.root))
		if inspectCalls < 4 {
			t.Fatalf("master identity inspections=%d, want stability-window recheck", inspectCalls)
		}
	})

	t.Run("stable nonempty generation is committed", func(t *testing.T) {
		snapshots := 0
		fixture := newInitialStartFixture(t, time.Second, func(processIdentity) (workerGeneration, error) {
			snapshots++
			return workerGeneration{{PID: 201, StartTicks: 2001}: {}}, nil
		})
		started := time.Now()
		if err := fixture.controller.Activate(context.Background(), fixture.root); err != nil {
			t.Fatalf("Activate() error=%v", err)
		}
		if elapsed := time.Since(started); elapsed < reloadWorkerStabilityWindow {
			t.Fatalf("Activate() committed after %s, want at least %s", elapsed, reloadWorkerStabilityWindow)
		}
		if snapshots < 2 {
			t.Fatalf("worker generation snapshots=%d, want stability-window confirmation", snapshots)
		}
		if fixture.starts != 1 || fixture.opens != 1 {
			t.Fatalf("startup attempts=%d pidfd opens=%d, want one each", fixture.starts, fixture.opens)
		}
		stored, err := readProcessRecord(fixture.pidFile + ".identity")
		if err != nil || stored != fixture.record {
			t.Fatalf("stored identity=%+v error=%v", stored, err)
		}
		if _, err := os.Lstat(fixture.pidFile + ".identity.pending"); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("pending startup identity remains: %v", err)
		}
		if signals, closes := fixture.handle.snapshot(); len(signals) != 0 || closes != 1 {
			t.Fatalf("signals=%v closeCalls=%d, want no signal and one close", signals, closes)
		}
	})
}

func TestOpenRestyReloadRetriesMixedOwnersUntilStable(t *testing.T) {
	master := processIdentity{PID: 43, StartTicks: 430, ExecutableDevice: 8, ExecutableInode: 80,
		OwnerUID: uint32(os.Geteuid()), BootID: "boot-a"}
	owner := uint32(65534)
	before := workerGeneration{{PID: 201, StartTicks: 2001, ExecutableDevice: master.ExecutableDevice,
		ExecutableInode: master.ExecutableInode, OwnerUID: owner, BootID: master.BootID}: {}}
	after := cloneWorkerGeneration(before)
	after[workerIdentity{PID: 202, StartTicks: 2002, ExecutableDevice: master.ExecutableDevice,
		ExecutableInode: master.ExecutableInode, OwnerUID: owner, BootID: master.BootID}] = struct{}{}
	mixedErr := mixedWorkerOwnerError(t)
	calls := 0
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	generation, err := waitForWorkerGeneration(ctx, &fakeProcessHandle{alive: reloadAliveSamples()}, master, before, len(before),
		func(int) (processIdentity, error) { return master, nil },
		func(processIdentity) (workerGeneration, error) {
			calls++
			if calls <= 2 {
				return nil, mixedErr
			}
			return after, nil
		})
	if err != nil {
		t.Fatalf("waitForWorkerGeneration() error=%v", err)
	}
	if calls < 4 || !sameWorkerGeneration(generation, workerGeneration{{PID: 202, StartTicks: 2002,
		ExecutableDevice: master.ExecutableDevice, ExecutableInode: master.ExecutableInode, OwnerUID: owner, BootID: master.BootID}: {}}) {
		t.Fatalf("snapshots=%d generation=%+v", calls, generation)
	}
}

func TestOpenRestyReloadAcceptsStableReplacementAfterOldWorkersExit(t *testing.T) {
	master := processIdentity{PID: 43, StartTicks: 430, ExecutableDevice: 8, ExecutableInode: 80,
		OwnerUID: uint32(os.Geteuid()), BootID: "boot-a"}
	owner := uint32(65534)
	before := workerGeneration{{PID: 201, StartTicks: 2001, ExecutableDevice: master.ExecutableDevice,
		ExecutableInode: master.ExecutableInode, OwnerUID: owner, BootID: master.BootID}: {}}
	after := workerGeneration{{PID: 202, StartTicks: 2002, ExecutableDevice: master.ExecutableDevice,
		ExecutableInode: master.ExecutableInode, OwnerUID: owner, BootID: master.BootID}: {}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	generation, err := waitForWorkerGeneration(ctx, &fakeProcessHandle{alive: reloadAliveSamples()}, master, before, len(before),
		func(int) (processIdentity, error) { return master, nil },
		func(processIdentity) (workerGeneration, error) { return after, nil })
	if err != nil {
		t.Fatalf("waitForWorkerGeneration() error=%v", err)
	}
	if !sameWorkerGeneration(generation, after) {
		t.Fatalf("generation=%+v, want stable replacement %+v", generation, after)
	}
}

func mixedWorkerOwnerError(t *testing.T) error {
	t.Helper()
	master := processIdentity{PID: 41, StartTicks: 410, ExecutableDevice: 8, ExecutableInode: 80,
		OwnerUID: uint32(os.Geteuid()), BootID: "boot-a"}
	worker := processIdentity{PID: 51, StartTicks: 510, ExecutableDevice: 8, ExecutableInode: 80,
		OwnerUID: 65534, BootID: "boot-a"}
	mixed := worker
	mixed.PID++
	mixed.StartTicks++
	mixed.OwnerUID = 65533
	_, err := buildWorkerGeneration(master, []processIdentity{worker, mixed})
	if err == nil {
		t.Fatal("buildWorkerGeneration() accepted mixed owners")
	}
	return err
}
