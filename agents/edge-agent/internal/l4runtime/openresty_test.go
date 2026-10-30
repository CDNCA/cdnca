package l4runtime

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"
)

type fakeProcessHandle struct {
	mu         sync.Mutex
	signals    []syscall.Signal
	alive      []bool
	aliveError error
	signalErr  error
	closeErr   error
	closeCalls int
	onSignal   func(syscall.Signal) error
}

func (handle *fakeProcessHandle) Signal(signal syscall.Signal) error {
	handle.mu.Lock()
	handle.signals = append(handle.signals, signal)
	onSignal := handle.onSignal
	signalErr := handle.signalErr
	handle.mu.Unlock()
	if onSignal != nil {
		return onSignal(signal)
	}
	return signalErr
}

func (handle *fakeProcessHandle) Alive() (bool, error) {
	handle.mu.Lock()
	defer handle.mu.Unlock()
	if handle.aliveError != nil {
		return false, handle.aliveError
	}
	if len(handle.alive) == 0 {
		return false, nil
	}
	alive := handle.alive[0]
	handle.alive = handle.alive[1:]
	return alive, nil
}

func (handle *fakeProcessHandle) Close() error {
	handle.mu.Lock()
	defer handle.mu.Unlock()
	handle.closeCalls++
	return handle.closeErr
}

func (handle *fakeProcessHandle) snapshot() ([]syscall.Signal, int) {
	handle.mu.Lock()
	defer handle.mu.Unlock()
	return append([]syscall.Signal(nil), handle.signals...), handle.closeCalls
}

func reloadAliveSamples() []bool {
	alive := make([]bool, 128)
	for index := range alive {
		alive[index] = true
	}
	return alive
}

func TestNewOpenRestyRejectsDirectivePathInjection(t *testing.T) {
	for _, pidFile := range []string{"relative.pid", "/tmp/l4 pid", "/tmp/l4;pid", "/tmp/l4\npid"} {
		if _, err := NewOpenResty("/bin/true", pidFile, time.Second); !errors.Is(err, ErrInvalidPath) {
			t.Errorf("NewOpenResty(pid=%q) error = %v, want ErrInvalidPath", pidFile, err)
		}
	}
	pidFile := filepath.Join(t.TempDir(), "nginx.pid")
	if _, err := NewOpenResty("/bin/true", pidFile, time.Second); err != nil {
		t.Fatalf("NewOpenResty(valid) error = %v", err)
	}
}

func TestOpenRestyRejectsUnsafeProcessFiles(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(*testing.T, string, processIdentity)
	}{
		{name: "unowned numeric PID", setup: func(t *testing.T, pidFile string, _ processIdentity) {
			writePIDFixture(t, pidFile, os.Getpid())
		}},
		{name: "PID symlink", setup: func(t *testing.T, pidFile string, _ processIdentity) {
			realPID := pidFile + ".real"
			writePIDFixture(t, realPID, os.Getpid())
			if err := os.Symlink(realPID, pidFile); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "identity symlink", setup: func(t *testing.T, pidFile string, identity processIdentity) {
			writePIDFixture(t, pidFile, identity.PID)
			realIdentity := pidFile + ".identity.real"
			if err := os.WriteFile(realIdentity, []byte(formatProcessRecord(identity)), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(realIdentity, pidFile+".identity"); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "pending symlink", setup: func(t *testing.T, pidFile string, identity processIdentity) {
			start := testStartIdentity(identity)
			realPending := pidFile + ".identity.pending.real"
			if err := os.WriteFile(realPending, []byte(formatProcessStartIdentity(start)), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(realPending, pidFile+".identity.pending"); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "PID directory", setup: func(t *testing.T, pidFile string, _ processIdentity) {
			if err := os.Mkdir(pidFile, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			pidFile := filepath.Join(root, "nginx.pid")
			identity := testProcessIdentity(t, 43)
			test.setup(t, pidFile, identity)
			controller := testOpenResty(t, pidFile)
			starts := 0
			controller.start = func(context.Context, []string, ...string) error {
				starts++
				return nil
			}
			if err := controller.Activate(context.Background(), root); err == nil {
				t.Fatal("Activate() accepted unsafe process state")
			}
			if starts != 0 {
				t.Fatalf("Activate() started OpenResty %d time(s)", starts)
			}
		})
	}
}

func TestProcessFileValidationRejectsNonRegularWritableHardlinkedAndForeignOwner(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "nginx.pid")
	if err := os.WriteFile(path, []byte("42\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateProcessFileInfo(info, uint32(os.Geteuid())+1, 32); err == nil {
		t.Fatal("process file validation accepted a foreign owner")
	}
	if err := os.Chmod(path, 0o622); err != nil {
		t.Fatal(err)
	}
	info, err = os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateProcessFileInfo(info, uint32(os.Geteuid()), 32); err == nil {
		t.Fatal("process file validation accepted group/world write access")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, path+".hardlink"); err != nil {
		t.Fatal(err)
	}
	info, err = os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateProcessFileInfo(info, uint32(os.Geteuid()), 32); err == nil {
		t.Fatal("process file validation accepted a hardlinked file")
	}
	directoryInfo, err := os.Lstat(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateProcessFileInfo(directoryInfo, uint32(os.Geteuid()), 32); err == nil {
		t.Fatal("process file validation accepted a non-regular file")
	}
}

func TestOpenRestyRejectsReusedPIDIdentity(t *testing.T) {
	changes := []struct {
		name   string
		change func(*processIdentity)
	}{
		{name: "start ticks", change: func(value *processIdentity) { value.StartTicks++ }},
		{name: "executable device", change: func(value *processIdentity) { value.ExecutableDevice++ }},
		{name: "executable inode", change: func(value *processIdentity) { value.ExecutableInode++ }},
		{name: "owner UID", change: func(value *processIdentity) { value.OwnerUID++ }},
		{name: "boot ID", change: func(value *processIdentity) { value.BootID = "replacement-boot" }},
	}
	for _, test := range changes {
		t.Run(test.name, func(t *testing.T) {
			pidFile := filepath.Join(t.TempDir(), "nginx.pid")
			recorded := testProcessIdentity(t, 43)
			writeProcessFixture(t, pidFile, recorded)
			current := recorded
			test.change(&current)
			handle := &fakeProcessHandle{}
			controller := testOpenResty(t, pidFile)
			controller.openProcess = func(int) (processHandle, error) { return handle, nil }
			controller.inspect = func(int) (processIdentity, error) { return current, nil }
			starts := 0
			controller.start = func(context.Context, []string, ...string) error { starts++; return nil }
			if err := controller.Activate(context.Background(), filepath.Dir(pidFile)); err == nil {
				t.Fatal("Activate() accepted a reused PID identity")
			}
			signals, closes := handle.snapshot()
			if len(signals) != 0 || closes != 1 || starts != 0 {
				t.Fatalf("signals=%v closeCalls=%d starts=%d", signals, closes, starts)
			}
		})
	}
}

func TestOpenRestySignalsOnlyCapturedHandleAfterPIDFileChanges(t *testing.T) {
	for _, operation := range []struct {
		name       string
		wantSignal syscall.Signal
		call       func(*OpenResty, string) error
	}{
		{name: "reload", wantSignal: syscall.SIGHUP, call: func(controller *OpenResty, path string) error {
			return controller.Activate(context.Background(), path)
		}},
		{name: "stop", wantSignal: syscall.SIGQUIT, call: func(controller *OpenResty, path string) error {
			return controller.Stop(context.Background(), path)
		}},
	} {
		t.Run(operation.name, func(t *testing.T) {
			root := t.TempDir()
			pidFile := filepath.Join(root, "nginx.pid")
			recorded := testProcessIdentity(t, 43)
			replacement := recorded
			replacement.PID = 44
			replacement.StartTicks++
			writeProcessFixture(t, pidFile, recorded)
			handle := &fakeProcessHandle{}
			if operation.wantSignal == syscall.SIGHUP {
				handle.alive = reloadAliveSamples()
			}
			controller := testOpenResty(t, pidFile)
			controller.openProcess = func(pid int) (processHandle, error) {
				if pid != recorded.PID {
					t.Fatalf("openProcess(%d), want %d", pid, recorded.PID)
				}
				return handle, nil
			}
			controller.inspect = func(int) (processIdentity, error) {
				writeProcessFixture(t, pidFile, replacement)
				return recorded, nil
			}
			controller.start = func(context.Context, []string, ...string) error {
				t.Fatal("operation fell back to a PID-file OpenResty command")
				return nil
			}
			if err := operation.call(controller, root); err != nil {
				t.Fatalf("%s error = %v", operation.name, err)
			}
			signals, closes := handle.snapshot()
			if !reflect.DeepEqual(signals, []syscall.Signal{operation.wantSignal}) || closes != 1 {
				t.Fatalf("signals=%v closeCalls=%d", signals, closes)
			}
			stored, err := readProcessRecord(pidFile + ".identity")
			if err != nil || stored != replacement {
				t.Fatalf("replacement identity = %+v, %v", stored, err)
			}
		})
	}
}

func TestOpenRestyReloadConfirmsNewWorkerGeneration(t *testing.T) {
	tests := []struct {
		name            string
		configure       func(*OpenResty, *fakeProcessHandle, processIdentity)
		wantError       bool
		minimumDuration time.Duration
	}{
		{
			name: "stable new generation succeeds",
			configure: func(controller *OpenResty, _ *fakeProcessHandle, _ processIdentity) {
				controller.timeout = 700 * time.Millisecond
				calls := 0
				controller.workerGeneration = func(processIdentity) (workerGeneration, error) {
					calls++
					switch calls {
					case 1:
						return workerGeneration{
							{PID: 101, StartTicks: 1001}: {},
							{PID: 102, StartTicks: 1002}: {},
						}, nil
					case 2:
						return workerGeneration{
							{PID: 101, StartTicks: 1001}: {},
							{PID: 102, StartTicks: 1002}: {},
							{PID: 201, StartTicks: 2001}: {},
							{PID: 202, StartTicks: 2002}: {},
						}, nil
					default:
						return workerGeneration{
							{PID: 201, StartTicks: 2001}: {},
							{PID: 202, StartTicks: 2002}: {},
						}, nil
					}
				}
			},
			minimumDuration: 150 * time.Millisecond,
		},
		{
			name: "old generation respawn is not a reload generation",
			configure: func(controller *OpenResty, _ *fakeProcessHandle, _ processIdentity) {
				controller.timeout = 80 * time.Millisecond
				calls := 0
				controller.workerGeneration = func(processIdentity) (workerGeneration, error) {
					calls++
					if calls == 1 {
						return workerGeneration{
							{PID: 101, StartTicks: 1001}: {},
							{PID: 102, StartTicks: 1002}: {},
						}, nil
					}
					return workerGeneration{
						{PID: 102, StartTicks: 1002}: {},
						{PID: 103, StartTicks: 1003}: {},
					}, nil
				}
			},
			wantError: true,
		},
		{
			name: "short lived new generation is rejected",
			configure: func(controller *OpenResty, _ *fakeProcessHandle, _ processIdentity) {
				controller.timeout = 300 * time.Millisecond
				calls := 0
				controller.workerGeneration = func(processIdentity) (workerGeneration, error) {
					calls++
					switch calls {
					case 1:
						return workerGeneration{{PID: 101, StartTicks: 1001}: {}}, nil
					case 2:
						return workerGeneration{
							{PID: 101, StartTicks: 1001}: {},
							{PID: 201, StartTicks: 2001}: {},
						}, nil
					default:
						return workerGeneration{{PID: 101, StartTicks: 1001}: {}}, nil
					}
				}
			},
			wantError: true,
		},
		{
			name: "signal accepted without new generation times out",
			configure: func(controller *OpenResty, _ *fakeProcessHandle, _ processIdentity) {
				controller.timeout = 10 * time.Millisecond
				controller.workerGeneration = func(processIdentity) (workerGeneration, error) {
					return workerGeneration{{PID: 101, StartTicks: 1001}: {}}, nil
				}
			},
			wantError: true,
		},
		{
			name: "master exits during stability window",
			configure: func(controller *OpenResty, handle *fakeProcessHandle, _ processIdentity) {
				handle.alive = []bool{true, false}
			},
			wantError: true,
		},
		{
			name: "master identity drifts during stability window",
			configure: func(controller *OpenResty, handle *fakeProcessHandle, record processIdentity) {
				handle.alive = reloadAliveSamples()
				calls := 0
				controller.inspect = func(int) (processIdentity, error) {
					calls++
					if calls <= 2 {
						return record, nil
					}
					drifted := record
					drifted.StartTicks++
					return drifted, nil
				}
			},
			wantError: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			pidFile := filepath.Join(root, "nginx.pid")
			record := testProcessIdentity(t, 43)
			writeProcessFixture(t, pidFile, record)
			handle := &fakeProcessHandle{alive: reloadAliveSamples()}
			controller := testOpenResty(t, pidFile)
			controller.inspect = func(int) (processIdentity, error) { return record, nil }
			controller.openProcess = func(int) (processHandle, error) { return handle, nil }
			test.configure(controller, handle, record)

			started := time.Now()
			err := controller.Activate(context.Background(), root)
			elapsed := time.Since(started)
			if (err != nil) != test.wantError {
				t.Fatalf("Activate() error = %v, wantError=%v", err, test.wantError)
			}
			if err == nil && elapsed < test.minimumDuration {
				t.Fatalf("Activate() confirmed worker generation after %s, want at least %s", elapsed, test.minimumDuration)
			}
			if signals, closes := handle.snapshot(); !reflect.DeepEqual(signals, []syscall.Signal{syscall.SIGHUP}) || closes != 1 {
				t.Fatalf("signals=%v closeCalls=%d", signals, closes)
			}
		})
	}
}

func TestOpenRestyPersistsPendingIdentityBeforeStart(t *testing.T) {
	root := t.TempDir()
	pidFile := filepath.Join(root, "nginx.pid")
	record := testProcessIdentity(t, 43)
	controller := testOpenResty(t, pidFile)
	controller.inspect = func(int) (processIdentity, error) { return record, nil }
	controller.matchStart = func(pid int, token string) error {
		if pid != record.PID || token == "" {
			t.Fatalf("matchStart(%d, %q)", pid, token)
		}
		return nil
	}
	handle := &fakeProcessHandle{}
	controller.openProcess = func(int) (processHandle, error) { return handle, nil }
	controller.start = func(_ context.Context, environment []string, arguments ...string) error {
		pending, exists, err := readOptionalProcessStartIdentity(pidFile + ".identity.pending")
		if err != nil || !exists {
			t.Fatalf("pending identity before start = exists=%v err=%v", exists, err)
		}
		if !reflect.DeepEqual(environment, []string{processStartEnvironment + "=" + pending.Token}) {
			t.Fatalf("start environment = %v", environment)
		}
		wantGlobal := "pid " + pidFile + "; env " + processStartEnvironment + "=" + pending.Token + ";"
		foundGlobal := false
		for index := 0; index+1 < len(arguments); index++ {
			if arguments[index] == "-g" && arguments[index+1] == wantGlobal {
				foundGlobal = true
			}
		}
		if !foundGlobal {
			t.Fatalf("start arguments = %v, missing %q", arguments, wantGlobal)
		}
		writePIDFixture(t, pidFile, record.PID)
		return nil
	}
	if err := controller.Activate(context.Background(), root); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	stored, err := readProcessRecord(pidFile + ".identity")
	if err != nil || stored != record {
		t.Fatalf("stored identity = %+v, %v", stored, err)
	}
	if _, err := os.Lstat(pidFile + ".identity.pending"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending identity residue = %v", err)
	}
	if signals, closes := handle.snapshot(); len(signals) != 0 || closes != 1 {
		t.Fatalf("signals=%v closeCalls=%d", signals, closes)
	}
}

func TestOpenRestyRecoversPendingStartedProcess(t *testing.T) {
	root := t.TempDir()
	pidFile := filepath.Join(root, "nginx.pid")
	record := testProcessIdentity(t, 43)
	writePIDFixture(t, pidFile, record.PID)
	start := testStartIdentity(record)
	if err := os.WriteFile(pidFile+".identity.pending", []byte(formatProcessStartIdentity(start)), 0o600); err != nil {
		t.Fatal(err)
	}
	controller := testOpenResty(t, pidFile)
	controller.inspect = func(int) (processIdentity, error) { return record, nil }
	controller.matchStart = func(pid int, token string) error {
		if pid != record.PID || token != start.Token {
			t.Fatalf("matchStart(%d, %q)", pid, token)
		}
		return nil
	}
	handle := &fakeProcessHandle{alive: reloadAliveSamples()}
	controller.openProcess = func(int) (processHandle, error) { return handle, nil }
	controller.start = func(context.Context, []string, ...string) error {
		t.Fatal("pending recovery started a second OpenResty master")
		return nil
	}
	if err := controller.Activate(context.Background(), root); err != nil {
		t.Fatalf("Activate() recovery error = %v", err)
	}
	stored, err := readProcessRecord(pidFile + ".identity")
	if err != nil || stored != record {
		t.Fatalf("recovered identity = %+v, %v", stored, err)
	}
	if _, err := os.Lstat(pidFile + ".identity.pending"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending recovery residue = %v", err)
	}
	if signals, closes := handle.snapshot(); !reflect.DeepEqual(signals, []syscall.Signal{syscall.SIGHUP}) || closes != 1 {
		t.Fatalf("signals=%v closeCalls=%d", signals, closes)
	}
}

func TestOpenRestyInterruptedStartStopsOnlyCapturedProcess(t *testing.T) {
	for _, test := range []struct {
		name           string
		commandFailure bool
	}{
		{name: "parent canceled after command"},
		{name: "command reports cancellation", commandFailure: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			pidFile := filepath.Join(root, "nginx.pid")
			record := testProcessIdentity(t, 43)
			controller := testOpenResty(t, pidFile)
			controller.inspect = func(int) (processIdentity, error) { return record, nil }
			controller.matchStart = func(int, string) error { return nil }
			handle := &fakeProcessHandle{}
			controller.openProcess = func(int) (processHandle, error) { return handle, nil }
			ctx, cancel := context.WithCancel(context.Background())
			controller.start = func(context.Context, []string, ...string) error {
				writePIDFixture(t, pidFile, record.PID)
				cancel()
				if test.commandFailure {
					return context.Canceled
				}
				return nil
			}
			err := controller.Activate(ctx, root)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Activate() error = %v, want context.Canceled", err)
			}
			if signals, closes := handle.snapshot(); !reflect.DeepEqual(signals, []syscall.Signal{syscall.SIGQUIT}) || closes != 1 {
				t.Fatalf("signals=%v closeCalls=%d", signals, closes)
			}
			for _, path := range []string{pidFile, pidFile + ".identity", pidFile + ".identity.pending"} {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("cleanup left %s: %v", filepath.Base(path), err)
				}
			}
		})
	}
}

func TestOpenRestyRetriesWhenPIDFDTargetExitsDuringStartup(t *testing.T) {
	root := t.TempDir()
	pidFile := filepath.Join(root, "nginx.pid")
	record := testProcessIdentity(t, 43)
	writePIDFixture(t, pidFile, record.PID)
	start := testStartIdentity(record)
	if err := os.WriteFile(pidFile+".identity.pending", []byte(formatProcessStartIdentity(start)), 0o600); err != nil {
		t.Fatal(err)
	}
	controller := testOpenResty(t, pidFile)
	controller.inspect = func(int) (processIdentity, error) { return record, nil }
	controller.matchStart = func(int, string) error { return nil }
	handle := &fakeProcessHandle{}
	openCalls := 0
	controller.openProcess = func(int) (processHandle, error) {
		openCalls++
		if openCalls == 1 {
			return nil, errProcessNotRunning
		}
		return handle, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	gotHandle, identity, err := controller.openStartedProcess(ctx)
	if err != nil || gotHandle != handle || identity != record || openCalls != 2 {
		t.Fatalf("openStartedProcess() = handle=%v identity=%+v calls=%d err=%v", gotHandle, identity, openCalls, err)
	}
	if err := gotHandle.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenRestyFailsClosedWithoutProcFSOrPIDFD(t *testing.T) {
	t.Run("Linux identity unavailable before start", func(t *testing.T) {
		root := t.TempDir()
		controller := testOpenResty(t, filepath.Join(root, "nginx.pid"))
		controller.identityOK = false
		starts := 0
		controller.start = func(context.Context, []string, ...string) error { starts++; return nil }
		if err := controller.Activate(context.Background(), root); err == nil || starts != 0 {
			t.Fatalf("Activate() error=%v starts=%d", err, starts)
		}
	})

	t.Run("pidfd unavailable", func(t *testing.T) {
		root := t.TempDir()
		pidFile := filepath.Join(root, "nginx.pid")
		record := testProcessIdentity(t, 43)
		writeProcessFixture(t, pidFile, record)
		controller := testOpenResty(t, pidFile)
		pidfdError := errors.New("pidfd unavailable")
		controller.openProcess = func(int) (processHandle, error) { return nil, pidfdError }
		if err := controller.Activate(context.Background(), root); !errors.Is(err, pidfdError) {
			t.Fatalf("Activate() error = %v", err)
		}
	})

	t.Run("procfs unavailable closes pidfd", func(t *testing.T) {
		root := t.TempDir()
		pidFile := filepath.Join(root, "nginx.pid")
		record := testProcessIdentity(t, 43)
		writeProcessFixture(t, pidFile, record)
		controller := testOpenResty(t, pidFile)
		procError := errors.New("procfs unavailable")
		closeError := errors.New("close failed")
		handle := &fakeProcessHandle{closeErr: closeError}
		controller.openProcess = func(int) (processHandle, error) { return handle, nil }
		controller.inspect = func(int) (processIdentity, error) { return processIdentity{}, procError }
		err := controller.Activate(context.Background(), root)
		if !errors.Is(err, procError) || !errors.Is(err, closeError) {
			t.Fatalf("Activate() error = %v", err)
		}
		if signals, closes := handle.snapshot(); len(signals) != 0 || closes != 1 {
			t.Fatalf("signals=%v closeCalls=%d", signals, closes)
		}
	})

	t.Run("launch token unavailable", func(t *testing.T) {
		root := t.TempDir()
		pidFile := filepath.Join(root, "nginx.pid")
		record := testProcessIdentity(t, 43)
		writePIDFixture(t, pidFile, record.PID)
		start := testStartIdentity(record)
		if err := os.WriteFile(pidFile+".identity.pending", []byte(formatProcessStartIdentity(start)), 0o600); err != nil {
			t.Fatal(err)
		}
		controller := testOpenResty(t, pidFile)
		controller.inspect = func(int) (processIdentity, error) { return record, nil }
		tokenError := errors.New("procfs environ unavailable")
		controller.matchStart = func(int, string) error { return tokenError }
		controller.openProcess = func(int) (processHandle, error) {
			t.Fatal("opened pidfd without confirming the launch token")
			return nil, nil
		}
		if err := controller.Activate(context.Background(), root); !errors.Is(err, tokenError) {
			t.Fatalf("Activate() error = %v", err)
		}
		for _, path := range []string{pidFile, pidFile + ".identity.pending"} {
			if _, err := os.Lstat(path); err != nil {
				t.Fatalf("fail-closed recovery removed %s: %v", filepath.Base(path), err)
			}
		}
	})
}

func TestOpenRestyConcurrentActivateStopSerializesPIDFDLifetime(t *testing.T) {
	root := t.TempDir()
	pidFile := filepath.Join(root, "nginx.pid")
	record := testProcessIdentity(t, 43)
	writeProcessFixture(t, pidFile, record)
	firstSignal := make(chan struct{})
	release := make(chan struct{})
	reloadHandle := &fakeProcessHandle{alive: reloadAliveSamples(), onSignal: func(signal syscall.Signal) error {
		if signal != syscall.SIGHUP {
			t.Fatalf("first signal = %v", signal)
		}
		close(firstSignal)
		<-release
		return nil
	}}
	stopHandle := &fakeProcessHandle{}
	controller := testOpenResty(t, pidFile)
	controller.inspect = func(int) (processIdentity, error) { return record, nil }
	var openMu sync.Mutex
	openCalls := 0
	controller.openProcess = func(int) (processHandle, error) {
		openMu.Lock()
		defer openMu.Unlock()
		openCalls++
		if openCalls == 1 {
			return reloadHandle, nil
		}
		return stopHandle, nil
	}
	reloadDone := make(chan error, 1)
	go func() { reloadDone <- controller.Activate(context.Background(), root) }()
	<-firstSignal
	stopStarted := make(chan struct{})
	stopDone := make(chan error, 1)
	go func() {
		close(stopStarted)
		stopDone <- controller.Stop(context.Background(), root)
	}()
	<-stopStarted
	select {
	case err := <-stopDone:
		t.Fatalf("Stop() completed before reload handle closed: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	openMu.Lock()
	gotOpenCalls := openCalls
	openMu.Unlock()
	if _, closes := reloadHandle.snapshot(); gotOpenCalls != 1 || closes != 0 {
		t.Fatalf("before release openCalls=%d reloadCloseCalls=%d", gotOpenCalls, closes)
	}
	close(release)
	if err := <-reloadDone; err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	if err := <-stopDone; err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if signals, closes := reloadHandle.snapshot(); !reflect.DeepEqual(signals, []syscall.Signal{syscall.SIGHUP}) || closes != 1 {
		t.Fatalf("reload signals=%v closeCalls=%d", signals, closes)
	}
	if signals, closes := stopHandle.snapshot(); !reflect.DeepEqual(signals, []syscall.Signal{syscall.SIGQUIT}) || closes != 1 {
		t.Fatalf("stop signals=%v closeCalls=%d", signals, closes)
	}
}

func TestOpenRestyPreservesSignalCleanupAndCloseErrors(t *testing.T) {
	t.Run("reload signal and close", func(t *testing.T) {
		root := t.TempDir()
		pidFile := filepath.Join(root, "nginx.pid")
		record := testProcessIdentity(t, 43)
		writeProcessFixture(t, pidFile, record)
		signalError := errors.New("signal failed")
		closeError := errors.New("close failed")
		handle := &fakeProcessHandle{signalErr: signalError, closeErr: closeError}
		controller := testOpenResty(t, pidFile)
		controller.inspect = func(int) (processIdentity, error) { return record, nil }
		controller.openProcess = func(int) (processHandle, error) { return handle, nil }
		err := controller.Activate(context.Background(), root)
		if !errors.Is(err, signalError) || !errors.Is(err, closeError) {
			t.Fatalf("Activate() error = %v", err)
		}
	})

	t.Run("stop cleanup sync and close", func(t *testing.T) {
		root := t.TempDir()
		pidFile := filepath.Join(root, "nginx.pid")
		record := testProcessIdentity(t, 43)
		writeProcessFixture(t, pidFile, record)
		removeError := errors.New("remove failed")
		syncError := errors.New("sync failed")
		closeError := errors.New("close failed")
		handle := &fakeProcessHandle{closeErr: closeError}
		controller := testOpenResty(t, pidFile)
		controller.inspect = func(int) (processIdentity, error) { return record, nil }
		controller.openProcess = func(int) (processHandle, error) { return handle, nil }
		removeCalls := 0
		controller.removeProcessFile = func(path string) error {
			removeCalls++
			if removeCalls == 1 {
				return os.Remove(path)
			}
			return removeError
		}
		controller.syncProcessDirectory = func(string) error { return syncError }
		err := controller.Stop(context.Background(), root)
		if !errors.Is(err, removeError) || !errors.Is(err, syncError) || !errors.Is(err, closeError) {
			t.Fatalf("Stop() error = %v", err)
		}
	})
}

func TestOpenRestyClosesPIDFDOnEveryExitPath(t *testing.T) {
	for _, test := range []struct {
		name      string
		signalErr error
		stop      bool
		cancel    bool
	}{
		{name: "reload success"},
		{name: "reload signal failure", signalErr: errors.New("signal failed")},
		{name: "stop success", stop: true},
		{name: "stop context cancellation", stop: true, cancel: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			pidFile := filepath.Join(root, "nginx.pid")
			record := testProcessIdentity(t, 43)
			writeProcessFixture(t, pidFile, record)
			handle := &fakeProcessHandle{signalErr: test.signalErr}
			if !test.stop && test.signalErr == nil {
				handle.alive = reloadAliveSamples()
			}
			if test.cancel {
				handle.alive = []bool{true}
			}
			controller := testOpenResty(t, pidFile)
			controller.inspect = func(int) (processIdentity, error) { return record, nil }
			controller.openProcess = func(int) (processHandle, error) { return handle, nil }
			ctx := context.Background()
			if test.cancel {
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = canceled
			}
			var err error
			if test.stop {
				err = controller.Stop(ctx, root)
			} else {
				err = controller.Activate(ctx, root)
			}
			if test.signalErr != nil && !errors.Is(err, test.signalErr) {
				t.Fatalf("operation error = %v", err)
			}
			if _, closes := handle.snapshot(); closes != 1 {
				t.Fatalf("closeCalls=%d, want 1", closes)
			}
		})
	}
}

func TestStopStartedProcessEscalation(t *testing.T) {
	root := t.TempDir()
	pidFile := filepath.Join(root, "nginx.pid")
	record := testProcessIdentity(t, 43)
	writeProcessFixture(t, pidFile, record)
	start := testStartIdentity(record)
	if err := os.WriteFile(pidFile+".identity.pending", []byte(formatProcessStartIdentity(start)), 0o600); err != nil {
		t.Fatal(err)
	}
	handle := &fakeProcessHandle{}
	waits := 0
	err := stopStartedProcess(handle, pidFile, record, time.Second, func(processHandle, time.Duration) (bool, error) {
		waits++
		return waits == 2, nil
	}, os.Remove, syncDirectory)
	if err != nil {
		t.Fatalf("stopStartedProcess() error = %v", err)
	}
	if signals, _ := handle.snapshot(); !reflect.DeepEqual(signals, []syscall.Signal{syscall.SIGQUIT, syscall.SIGKILL}) {
		t.Fatalf("signals=%v", signals)
	}
	for _, path := range []string{pidFile, pidFile + ".identity", pidFile + ".identity.pending"} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("cleanup left %s: %v", filepath.Base(path), err)
		}
	}
}

func TestLinuxPIDFDSignalsCapturedProcessNotPIDFileReplacement(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux pidfd/procfs test")
	}
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 128; index++ {
		handle, err := openPIDFD(os.Getpid())
		if err != nil {
			t.Fatalf("openPIDFD(self) iteration %d: %v", index, err)
		}
		alive, err := handle.Alive()
		if err != nil || !alive {
			t.Fatalf("pidfd self alive=%v err=%v", alive, err)
		}
		if err := handle.Close(); err != nil {
			t.Fatalf("close pidfd iteration %d: %v", index, err)
		}
	}
	afterPIDFDLoop, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	if len(afterPIDFDLoop) != len(before) {
		t.Fatalf("pidfd leak: before=%d after=%d", len(before), len(afterPIDFDLoop))
	}
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(sleep, "30")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()
	identity, err := kernelProcessIdentity(command.Process.Pid)
	if err != nil || identity.PID != command.Process.Pid {
		t.Fatalf("kernelProcessIdentity() = %+v, %v", identity, err)
	}
	handle, err := openPIDFD(command.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	pidFile := filepath.Join(t.TempDir(), "nginx.pid")
	writePIDFixture(t, pidFile, command.Process.Pid)
	writePIDFixture(t, pidFile, os.Getpid())
	if err := handle.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("pidfd signal: %v", err)
	}
	_ = command.Wait()
	waited = true
	if alive, err := handle.Alive(); err != nil || alive {
		t.Fatalf("reaped pidfd alive=%v err=%v", alive, err)
	}
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}
	if alive, err := handle.Alive(); alive || !errors.Is(err, syscall.EBADF) {
		t.Fatalf("closed pidfd alive=%v err=%v, want EBADF", alive, err)
	}
}

func testOpenResty(t *testing.T, pidFile string) *OpenResty {
	t.Helper()
	controller, err := NewOpenResty("/usr/bin/true", pidFile, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	controller.identityOK = true
	controller.bootID = func() (string, error) { return "test-boot-id", nil }
	// Fixture PIDs are not real workers; tests that need nginx's "shutting
	// down" retitle inject it.
	controller.shuttingDown = func(workerIdentity) bool { return false }
	generation := 0
	controller.workerGeneration = func(processIdentity) (workerGeneration, error) {
		generation++
		if generation == 1 {
			return workerGeneration{{PID: 101, StartTicks: 1001}: {}}, nil
		}
		return workerGeneration{
			{PID: 101, StartTicks: 1001}: {},
			{PID: 201, StartTicks: 2001}: {},
		}, nil
	}
	return controller
}

func testProcessIdentity(t *testing.T, pid int) processIdentity {
	t.Helper()
	info, err := os.Stat("/usr/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("binary stat has no syscall.Stat_t")
	}
	return processIdentity{
		PID: pid, StartTicks: 12345, ExecutableDevice: uint64(stat.Dev), ExecutableInode: uint64(stat.Ino),
		OwnerUID: uint32(os.Geteuid()), BootID: "test-boot-id",
	}
}

func testStartIdentity(identity processIdentity) processStartIdentity {
	return processStartIdentity{
		ExecutableDevice: identity.ExecutableDevice, ExecutableInode: identity.ExecutableInode, OwnerUID: identity.OwnerUID,
		Token: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
}

func writePIDFixture(t *testing.T, pidFile string, pid int) {
	t.Helper()
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeProcessFixture(t *testing.T, pidFile string, identity processIdentity) {
	t.Helper()
	writePIDFixture(t, pidFile, identity.PID)
	if err := os.WriteFile(pidFile+".identity", []byte(formatProcessRecord(identity)), 0o600); err != nil {
		t.Fatal(err)
	}
}
