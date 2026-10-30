package certstore

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"syscall"
	"testing"
	"time"
)

type fakeProcessHandle struct {
	signals    []syscall.Signal
	alive      []bool
	closed     bool
	closeCalls int
	closeErr   error
	onSignal   func(syscall.Signal) error
}

func (handle *fakeProcessHandle) Signal(signal syscall.Signal) error {
	handle.signals = append(handle.signals, signal)
	if handle.onSignal != nil {
		return handle.onSignal(signal)
	}
	return nil
}

func (handle *fakeProcessHandle) Alive() (bool, error) {
	if len(handle.alive) == 0 {
		return false, nil
	}
	alive := handle.alive[0]
	handle.alive = handle.alive[1:]
	return alive, nil
}

func (handle *fakeProcessHandle) Close() error {
	handle.closed = true
	handle.closeCalls++
	return handle.closeErr
}

func TestOpenRestyRuntimeRejectsUnownedOrUnsafePIDFile(t *testing.T) {
	root := t.TempDir()
	candidate := filepath.Join(root, "current")
	if err := os.Mkdir(candidate, 0o700); err != nil {
		t.Fatal(err)
	}
	pid := filepath.Join(root, "nginx.pid")
	if err := os.WriteFile(pid, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	runtime, err := NewOpenRestyRuntime("/usr/bin/true", pid, "127.0.0.1:18443")
	if err != nil {
		t.Fatal(err)
	}
	runs := 0
	runtime.run = func(context.Context, string, []string, ...string) error {
		runs++
		return nil
	}
	if err := runtime.Activate(context.Background(), candidate); !errors.Is(err, ErrActivation) {
		t.Fatalf("Activate() unowned PID error = %v, want ErrActivation", err)
	}
	if runs != 0 {
		t.Fatalf("Activate() signaled an unowned process via %d command(s)", runs)
	}

	realPID := filepath.Join(root, "real.pid")
	if err := os.Rename(pid, realPID); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realPID, pid); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Activate(context.Background(), candidate); !errors.Is(err, ErrActivation) {
		t.Fatalf("Activate() symlink PID error = %v, want ErrActivation", err)
	}
	if runs != 0 {
		t.Fatalf("Activate() followed a PID symlink and ran %d command(s)", runs)
	}
}

func TestProcessRunningRejectsReusedPIDIdentity(t *testing.T) {
	root := t.TempDir()
	pidFile := filepath.Join(root, "nginx.pid")
	record := processIdentity{
		PID: 42, StartTicks: 12345, ExecutableDevice: 7, ExecutableInode: 99,
		OwnerUID: uint32(os.Geteuid()), BootID: "test-boot-id",
	}
	if err := os.WriteFile(pidFile, []byte("42\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pidFile+".identity", []byte(formatProcessRecord(record)), 0o600); err != nil {
		t.Fatal(err)
	}
	current := record
	inspect := func(int) (processIdentity, error) { return current, nil }
	running, err := processRunning(pidFile, inspect)
	if err != nil || !running {
		t.Fatalf("processRunning() exact identity = %v, %v", running, err)
	}

	current.StartTicks++
	if running, err := processRunning(pidFile, inspect); err == nil || running {
		t.Fatalf("processRunning() reused PID = %v, %v", running, err)
	}
	current = record
	current.ExecutableInode++
	if running, err := processRunning(pidFile, inspect); err == nil || running {
		t.Fatalf("processRunning() wrong executable = %v, %v", running, err)
	}
	inspect = func(int) (processIdentity, error) { return processIdentity{}, errProcessNotRunning }
	if running, err := processRunning(pidFile, inspect); err != nil || running {
		t.Fatalf("processRunning() stopped identity = %v, %v", running, err)
	}
}

func TestOpenRestyRuntimeRecordsOnlyProcessItStarts(t *testing.T) {
	root := t.TempDir()
	candidate := filepath.Join(root, "current")
	if err := os.Mkdir(candidate, 0o700); err != nil {
		t.Fatal(err)
	}
	pidFile := filepath.Join(root, "nginx.pid")
	binaryInfo, err := os.Stat("/usr/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	binaryStat := binaryInfo.Sys().(*syscall.Stat_t)
	record := processIdentity{
		PID: 43, StartTicks: 54321, ExecutableDevice: uint64(binaryStat.Dev), ExecutableInode: uint64(binaryStat.Ino),
		OwnerUID: uint32(os.Geteuid()), BootID: "test-boot-id",
	}
	runtime, err := NewOpenRestyRuntime("/usr/bin/true", pidFile, "127.0.0.1:18443")
	if err != nil {
		t.Fatal(err)
	}
	runtime.inspect = func(pid int) (processIdentity, error) {
		if pid != record.PID {
			t.Fatalf("inspect(%d)", pid)
		}
		return record, nil
	}
	runtime.identityOK = true
	handle := &fakeProcessHandle{}
	runtime.openProcess = func(pid int) (processHandle, error) {
		if pid != record.PID {
			t.Fatalf("openProcess(%d)", pid)
		}
		return handle, nil
	}
	runtime.matchStart = func(int, string) error { return nil }
	var calls [][]string
	runtime.run = func(_ context.Context, binary string, _ []string, arguments ...string) error {
		calls = append(calls, append([]string{binary}, arguments...))
		if len(calls) == 1 {
			return os.WriteFile(pidFile, []byte("43\n"), 0o600)
		}
		return nil
	}
	if err := runtime.Activate(context.Background(), candidate); err != nil {
		t.Fatalf("Activate() start error = %v", err)
	}
	stored, err := readProcessRecord(pidFile + ".identity")
	if err != nil || stored != record {
		t.Fatalf("stored identity = %+v, %v", stored, err)
	}
	if err := runtime.Activate(context.Background(), candidate); err != nil {
		t.Fatalf("Activate() reload error = %v", err)
	}
	if len(calls) != 1 || len(handle.signals) != 1 || handle.signals[0] != syscall.SIGHUP || !handle.closed {
		t.Fatalf("OpenResty calls=%v signals=%v closed=%v", calls, handle.signals, handle.closed)
	}
}

func TestOpenRestyRuntimePersistsPendingIdentityBeforeDaemonStart(t *testing.T) {
	root := t.TempDir()
	candidate := filepath.Join(root, "current")
	if err := os.Mkdir(candidate, 0o700); err != nil {
		t.Fatal(err)
	}
	pidFile := filepath.Join(root, "nginx.pid")
	binary := "/usr/bin/true"
	info, err := os.Stat(binary)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	record := processIdentity{
		PID: 43, StartTicks: 54321, ExecutableDevice: uint64(stat.Dev), ExecutableInode: uint64(stat.Ino),
		OwnerUID: uint32(os.Geteuid()), BootID: "test-boot-id",
	}
	runtime, err := NewOpenRestyRuntime(binary, pidFile, "127.0.0.1:18443")
	if err != nil {
		t.Fatal(err)
	}
	runtime.identityOK = true
	runtime.inspect = func(int) (processIdentity, error) { return record, nil }
	runtime.matchStart = func(int, string) error { return nil }
	runtime.openProcess = func(int) (processHandle, error) { return &fakeProcessHandle{}, nil }
	runtime.run = func(_ context.Context, _ string, environment []string, arguments ...string) error {
		pending, exists, err := readOptionalProcessStartIdentity(pidFile + ".identity.pending")
		if err != nil || !exists {
			t.Fatalf("pending identity was not durable before daemon start: exists=%v err=%v", exists, err)
		}
		if !reflect.DeepEqual(environment, []string{processStartEnvironment + "=" + pending.Token}) {
			t.Fatalf("start environment=%v", environment)
		}
		if len(arguments) < 2 || arguments[0] != "-g" || arguments[1] != "env "+processStartEnvironment+";" {
			t.Fatalf("start arguments=%v", arguments)
		}
		return os.WriteFile(pidFile, []byte("43\n"), 0o600)
	}

	if err := runtime.Activate(context.Background(), candidate); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	if _, err := os.Stat(pidFile + ".identity.pending"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("committed startup left pending identity: %v", err)
	}
}

func TestOpenRestyRuntimeRecoversPendingStartedProcess(t *testing.T) {
	root := t.TempDir()
	candidate := filepath.Join(root, "current")
	if err := os.Mkdir(candidate, 0o700); err != nil {
		t.Fatal(err)
	}
	pidFile := filepath.Join(root, "nginx.pid")
	binary := "/usr/bin/true"
	info, err := os.Stat(binary)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	record := processIdentity{
		PID: 43, StartTicks: 54321, ExecutableDevice: uint64(stat.Dev), ExecutableInode: uint64(stat.Ino),
		OwnerUID: uint32(os.Geteuid()), BootID: "test-boot-id",
	}
	if err := os.WriteFile(pidFile, []byte("43\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	token := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	pending := fmt.Sprintf("pending %d %d %d %s\n", record.ExecutableDevice, record.ExecutableInode, record.OwnerUID, token)
	if err := os.WriteFile(pidFile+".identity.pending", []byte(pending), 0o600); err != nil {
		t.Fatal(err)
	}
	runtime, err := NewOpenRestyRuntime(binary, pidFile, "127.0.0.1:18443")
	if err != nil {
		t.Fatal(err)
	}
	runtime.identityOK = true
	runtime.inspect = func(int) (processIdentity, error) { return record, nil }
	runtime.matchStart = func(pid int, got string) error {
		if pid != record.PID || got != token {
			t.Fatalf("matchStart(%d, %q)", pid, got)
		}
		return nil
	}
	handle := &fakeProcessHandle{}
	runtime.openProcess = func(int) (processHandle, error) { return handle, nil }
	runtime.run = func(context.Context, string, []string, ...string) error {
		t.Fatal("recovery started a second OpenResty master")
		return nil
	}

	if err := runtime.Activate(context.Background(), candidate); err != nil {
		t.Fatalf("Activate() recovery error = %v", err)
	}
	if len(handle.signals) != 1 || handle.signals[0] != syscall.SIGHUP || !handle.closed {
		t.Fatalf("recovery signals=%v closed=%v", handle.signals, handle.closed)
	}
	stored, err := readProcessRecord(pidFile + ".identity")
	if err != nil || stored != record {
		t.Fatalf("recovered identity = %+v, %v", stored, err)
	}
	if _, err := os.Stat(pidFile + ".identity.pending"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recovery left pending identity: %v", err)
	}
}

func TestOpenRestyRuntimePendingRecoveryPreservesConfirmationCleanupAndCloseErrors(t *testing.T) {
	root := t.TempDir()
	pidFile := filepath.Join(root, "nginx.pid")
	info, err := os.Stat("/usr/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	record := processIdentity{
		PID: 43, StartTicks: 54321, ExecutableDevice: uint64(stat.Dev), ExecutableInode: uint64(stat.Ino),
		OwnerUID: uint32(os.Geteuid()), BootID: "test-boot-id",
	}
	if err := os.WriteFile(pidFile, []byte("43\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	startRecord := processStartIdentity{
		ExecutableDevice: record.ExecutableDevice, ExecutableInode: record.ExecutableInode,
		OwnerUID: record.OwnerUID, Token: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	if err := os.WriteFile(pidFile+".identity.pending", []byte(formatProcessStartIdentity(startRecord)), 0o600); err != nil {
		t.Fatal(err)
	}
	runtime, err := NewOpenRestyRuntime("/usr/bin/true", pidFile, "127.0.0.1:18443")
	if err != nil {
		t.Fatal(err)
	}
	runtime.identityOK = true
	inspectCalls := 0
	runtime.inspect = func(int) (processIdentity, error) {
		inspectCalls++
		if inspectCalls == 3 {
			changed := record
			changed.StartTicks++
			return changed, nil
		}
		return record, nil
	}
	runtime.matchStart = func(int, string) error { return nil }
	closeError := errors.New("close failed")
	handle := &fakeProcessHandle{closeErr: closeError}
	runtime.openProcess = func(int) (processHandle, error) { return handle, nil }
	removeCalls := 0
	runtime.removeProcessFile = func(path string) error {
		removeCalls++
		if path != pidFile+".identity" {
			t.Fatalf("remove path = %q", path)
		}
		return os.Remove(path)
	}
	syncError := errors.New("sync identity directory failed")
	syncCalls := 0
	runtime.syncProcessDirectory = func(path string) error {
		syncCalls++
		if path != root {
			t.Fatalf("sync path = %q, want %q", path, root)
		}
		return syncError
	}

	gotHandle, _, running, err := runtime.openOwnedProcess()
	if gotHandle != nil || running {
		t.Fatalf("openOwnedProcess() = handle=%v running=%v", gotHandle, running)
	}
	if !errors.Is(err, syncError) {
		t.Fatalf("openOwnedProcess() error = %v, want sync error", err)
	}
	if !errors.Is(err, closeError) {
		t.Fatalf("openOwnedProcess() error = %v, want close error", err)
	}
	if removeCalls != 1 || syncCalls != 1 || !handle.closed {
		t.Fatalf("remove calls=%d sync calls=%d closed=%v", removeCalls, syncCalls, handle.closed)
	}
	if len(handle.signals) != 0 {
		t.Fatalf("pending recovery signaled process: %v", handle.signals)
	}
}

func TestOpenRestyRuntimePendingRecoveryPreservesEarlyCloseErrors(t *testing.T) {
	tokenError := errors.New("launch token changed")
	for _, test := range []struct {
		name     string
		failure  string
		useOwned bool
		want     error
	}{
		{name: "returned start error", failure: "pid", useOwned: true},
		{name: "identity mismatch", failure: "identity"},
		{name: "launch token failure", failure: "token", want: tokenError},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			pidFile := filepath.Join(root, "nginx.pid")
			info, err := os.Stat("/usr/bin/true")
			if err != nil {
				t.Fatal(err)
			}
			stat := info.Sys().(*syscall.Stat_t)
			record := processIdentity{
				PID: 43, StartTicks: 54321, ExecutableDevice: uint64(stat.Dev), ExecutableInode: uint64(stat.Ino),
				OwnerUID: uint32(os.Geteuid()), BootID: "test-boot-id",
			}
			if err := os.WriteFile(pidFile, []byte("43\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			startRecord := processStartIdentity{
				ExecutableDevice: record.ExecutableDevice, ExecutableInode: record.ExecutableInode,
				OwnerUID: record.OwnerUID, Token: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			}
			if err := os.WriteFile(pidFile+".identity.pending", []byte(formatProcessStartIdentity(startRecord)), 0o600); err != nil {
				t.Fatal(err)
			}
			runtime, err := NewOpenRestyRuntime("/usr/bin/true", pidFile, "127.0.0.1:18443")
			if err != nil {
				t.Fatal(err)
			}
			runtime.identityOK = true
			inspectCalls := 0
			runtime.inspect = func(int) (processIdentity, error) {
				inspectCalls++
				if test.failure == "identity" && inspectCalls == 2 {
					changed := record
					changed.StartTicks++
					return changed, nil
				}
				return record, nil
			}
			matchCalls := 0
			runtime.matchStart = func(int, string) error {
				matchCalls++
				if matchCalls != 2 {
					return nil
				}
				if test.failure == "token" {
					return tokenError
				}
				if test.failure == "pid" {
					return os.WriteFile(pidFile, []byte("44\n"), 0o600)
				}
				return nil
			}
			closeError := errors.New("close failed")
			handle := &fakeProcessHandle{closeErr: closeError}
			runtime.openProcess = func(int) (processHandle, error) { return handle, nil }

			var gotHandle processHandle
			var gotErr error
			if test.useOwned {
				var running bool
				gotHandle, _, running, gotErr = runtime.openOwnedProcess()
				if running {
					t.Fatal("openOwnedProcess() reported a failed recovery as running")
				}
			} else {
				gotHandle, _, gotErr = runtime.openStartedProcess(context.Background())
			}
			if gotHandle != nil || gotErr == nil {
				t.Fatalf("pending recovery = handle=%v error=%v", gotHandle, gotErr)
			}
			if test.want != nil && !errors.Is(gotErr, test.want) {
				t.Fatalf("pending recovery error = %v, want %v", gotErr, test.want)
			}
			if !errors.Is(gotErr, closeError) {
				t.Fatalf("pending recovery error = %v, want close error", gotErr)
			}
			if !handle.closed || handle.closeCalls != 1 {
				t.Fatalf("close state = closed=%v calls=%d", handle.closed, handle.closeCalls)
			}
		})
	}
}

func TestOpenRestyRuntimeOpenOwnedProcessPreservesRemainingCloseErrors(t *testing.T) {
	for _, test := range []struct {
		name          string
		failure       string
		pending       bool
		wantOnlyClose bool
	}{
		{name: "inspect reports stopped process", failure: "stopped", wantOnlyClose: true},
		{name: "inspected identity mismatches", failure: "identity"},
		{name: "pending identity removal fails", failure: "remove", pending: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			pidFile := filepath.Join(root, "nginx.pid")
			record := processIdentity{
				PID: 43, StartTicks: 54321, ExecutableDevice: 8, ExecutableInode: 100,
				OwnerUID: uint32(os.Geteuid()), BootID: "test-boot-id",
			}
			writeProcessFixture(t, pidFile, record)
			pendingPath := pidFile + ".identity.pending"
			if test.pending {
				startRecord := processStartIdentity{
					ExecutableDevice: record.ExecutableDevice, ExecutableInode: record.ExecutableInode,
					OwnerUID: record.OwnerUID, Token: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				}
				if err := os.WriteFile(pendingPath, []byte(formatProcessStartIdentity(startRecord)), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			runtime, err := NewOpenRestyRuntime("/usr/bin/true", pidFile, "127.0.0.1:18443")
			if err != nil {
				t.Fatal(err)
			}
			runtime.identityOK = true
			runtime.inspect = func(int) (processIdentity, error) {
				switch test.failure {
				case "stopped":
					return processIdentity{}, errProcessNotRunning
				case "identity":
					changed := record
					changed.StartTicks++
					return changed, nil
				case "remove":
					if err := os.Remove(pendingPath); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(pendingPath, 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(pendingPath, "keep"), nil, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				return record, nil
			}
			closeError := errors.New("close failed")
			handle := &fakeProcessHandle{closeErr: closeError}
			runtime.openProcess = func(int) (processHandle, error) { return handle, nil }

			gotHandle, _, running, gotErr := runtime.openOwnedProcess()
			if gotHandle != nil || running {
				t.Fatalf("openOwnedProcess() = handle=%v running=%v error=%v", gotHandle, running, gotErr)
			}
			if !errors.Is(gotErr, closeError) {
				t.Fatalf("openOwnedProcess() error = %v, want close error", gotErr)
			}
			if test.wantOnlyClose {
				if gotErr != closeError {
					t.Fatalf("openOwnedProcess() error = %v, want only close error", gotErr)
				}
			} else {
				joined, ok := gotErr.(interface{ Unwrap() []error })
				if !ok || len(joined.Unwrap()) != 2 || joined.Unwrap()[0] == nil || joined.Unwrap()[1] != closeError {
					t.Fatalf("openOwnedProcess() joined error = %#v", gotErr)
				}
			}
			if !handle.closed || handle.closeCalls != 1 {
				t.Fatalf("close state = closed=%v calls=%d", handle.closed, handle.closeCalls)
			}
			if len(handle.signals) != 0 {
				t.Fatalf("openOwnedProcess() signaled process: %v", handle.signals)
			}
		})
	}
}

func TestOpenRestyRuntimeTopLevelCloseAndCleanupErrors(t *testing.T) {
	newRecordedRuntime := func(t *testing.T, handle processHandle) (*OpenRestyRuntime, string) {
		t.Helper()
		root := t.TempDir()
		current := filepath.Join(root, "current")
		if err := os.Mkdir(current, 0o700); err != nil {
			t.Fatal(err)
		}
		pidFile := filepath.Join(root, "nginx.pid")
		record := processIdentity{
			PID: 43, StartTicks: 54321, ExecutableDevice: 8, ExecutableInode: 100,
			OwnerUID: uint32(os.Geteuid()), BootID: "test-boot-id",
		}
		writeProcessFixture(t, pidFile, record)
		runtime, err := NewOpenRestyRuntime("/usr/bin/true", pidFile, "127.0.0.1:18443")
		if err != nil {
			t.Fatal(err)
		}
		runtime.identityOK = true
		runtime.inspect = func(int) (processIdentity, error) { return record, nil }
		runtime.openProcess = func(int) (processHandle, error) { return handle, nil }
		return runtime, current
	}

	for _, operation := range []struct {
		name   string
		signal syscall.Signal
		call   func(*OpenRestyRuntime, string) error
	}{
		{name: "activate", signal: syscall.SIGHUP, call: func(runtime *OpenRestyRuntime, path string) error {
			return runtime.Activate(context.Background(), path)
		}},
		{name: "stop", signal: syscall.SIGQUIT, call: func(runtime *OpenRestyRuntime, path string) error {
			return runtime.Stop(context.Background(), path)
		}},
	} {
		t.Run(operation.name+" error", func(t *testing.T) {
			closeError := errors.New("close failed")
			handle := &fakeProcessHandle{closeErr: closeError}
			handle.onSignal = func(signal syscall.Signal) error {
				if handle.closed {
					t.Fatal("handle closed before signal")
				}
				if signal != operation.signal {
					t.Fatalf("signal = %v, want %v", signal, operation.signal)
				}
				return errors.New("signal failed")
			}
			runtime, current := newRecordedRuntime(t, handle)

			gotErr := operation.call(runtime, current)
			if !errors.Is(gotErr, ErrActivation) || !errors.Is(gotErr, closeError) {
				t.Fatalf("%s error = %v, want activation and close errors", operation.name, gotErr)
			}
			if !handle.closed || handle.closeCalls != 1 {
				t.Fatalf("close state = closed=%v calls=%d", handle.closed, handle.closeCalls)
			}
		})

		t.Run(operation.name+" success", func(t *testing.T) {
			handle := &fakeProcessHandle{}
			handle.onSignal = func(signal syscall.Signal) error {
				if handle.closed {
					t.Fatal("handle closed before signal")
				}
				if signal != operation.signal {
					t.Fatalf("signal = %v, want %v", signal, operation.signal)
				}
				return nil
			}
			runtime, current := newRecordedRuntime(t, handle)

			if err := operation.call(runtime, current); err != nil {
				t.Fatalf("%s success error = %v", operation.name, err)
			}
			if !handle.closed || handle.closeCalls != 1 {
				t.Fatalf("close state = closed=%v calls=%d", handle.closed, handle.closeCalls)
			}
		})
	}

	newPendingRuntime := func(t *testing.T, handle processHandle) *OpenRestyRuntime {
		t.Helper()
		root := t.TempDir()
		pidFile := filepath.Join(root, "nginx.pid")
		record := processIdentity{
			PID: 43, StartTicks: 54321, ExecutableDevice: 8, ExecutableInode: 100,
			OwnerUID: uint32(os.Geteuid()), BootID: "test-boot-id",
		}
		if err := os.WriteFile(pidFile, []byte("43\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		startRecord := processStartIdentity{
			ExecutableDevice: record.ExecutableDevice, ExecutableInode: record.ExecutableInode,
			OwnerUID: record.OwnerUID, Token: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		}
		if err := os.WriteFile(pidFile+".identity.pending", []byte(formatProcessStartIdentity(startRecord)), 0o600); err != nil {
			t.Fatal(err)
		}
		runtime, err := NewOpenRestyRuntime("/usr/bin/true", pidFile, "127.0.0.1:18443")
		if err != nil {
			t.Fatal(err)
		}
		runtime.identityOK = true
		runtime.inspect = func(int) (processIdentity, error) { return record, nil }
		runtime.matchStart = func(int, string) error { return nil }
		runtime.openProcess = func(int) (processHandle, error) { return handle, nil }
		return runtime
	}

	t.Run("cleanup error", func(t *testing.T) {
		stopError := errors.New("stop failed")
		closeError := errors.New("close failed")
		handle := &fakeProcessHandle{closeErr: closeError}
		handle.onSignal = func(signal syscall.Signal) error {
			if handle.closed {
				t.Fatal("handle closed before cleanup signal")
			}
			if signal != syscall.SIGQUIT {
				t.Fatalf("signal = %v, want SIGQUIT", signal)
			}
			return stopError
		}
		runtime := newPendingRuntime(t, handle)

		gotErr := runtime.cleanupUnrecordedStart()
		if !errors.Is(gotErr, stopError) || !errors.Is(gotErr, closeError) {
			t.Fatalf("cleanupUnrecordedStart() error = %v", gotErr)
		}
		if !handle.closed || handle.closeCalls != 1 {
			t.Fatalf("close state = closed=%v calls=%d", handle.closed, handle.closeCalls)
		}
	})

	t.Run("cleanup success", func(t *testing.T) {
		handle := &fakeProcessHandle{}
		handle.onSignal = func(signal syscall.Signal) error {
			if handle.closed {
				t.Fatal("handle closed before cleanup signal")
			}
			if signal != syscall.SIGQUIT {
				t.Fatalf("signal = %v, want SIGQUIT", signal)
			}
			return nil
		}
		runtime := newPendingRuntime(t, handle)

		if err := runtime.cleanupUnrecordedStart(); err != nil {
			t.Fatalf("cleanupUnrecordedStart() success error = %v", err)
		}
		if !handle.closed || handle.closeCalls != 1 {
			t.Fatalf("close state = closed=%v calls=%d", handle.closed, handle.closeCalls)
		}
	})

	t.Run("activate run failure preserves cleanup", func(t *testing.T) {
		root := t.TempDir()
		current := filepath.Join(root, "current")
		if err := os.Mkdir(current, 0o700); err != nil {
			t.Fatal(err)
		}
		pidFile := filepath.Join(root, "nginx.pid")
		runtime, err := NewOpenRestyRuntime("/usr/bin/true", pidFile, "127.0.0.1:18443")
		if err != nil {
			t.Fatal(err)
		}
		runtime.identityOK = true
		var record processIdentity
		runtime.run = func(context.Context, string, []string, ...string) error {
			startRecord, exists, err := readOptionalProcessStartIdentity(pidFile + ".identity.pending")
			if err != nil || !exists {
				t.Fatalf("pending identity = exists=%v error=%v", exists, err)
			}
			record = processIdentity{
				PID: 43, StartTicks: 54321, ExecutableDevice: startRecord.ExecutableDevice, ExecutableInode: startRecord.ExecutableInode,
				OwnerUID: startRecord.OwnerUID, BootID: "test-boot-id",
			}
			if err := os.WriteFile(pidFile, []byte("43\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			return errors.New("run failed")
		}
		runtime.inspect = func(int) (processIdentity, error) { return record, nil }
		runtime.matchStart = func(int, string) error { return nil }
		stopError := errors.New("stop failed")
		closeError := errors.New("close failed")
		handle := &fakeProcessHandle{closeErr: closeError}
		handle.onSignal = func(signal syscall.Signal) error {
			if handle.closed {
				t.Fatal("handle closed before cleanup signal")
			}
			if signal != syscall.SIGQUIT {
				t.Fatalf("signal = %v, want SIGQUIT", signal)
			}
			return stopError
		}
		runtime.openProcess = func(int) (processHandle, error) { return handle, nil }

		gotErr := runtime.Activate(context.Background(), current)
		if !errors.Is(gotErr, ErrActivation) || !errors.Is(gotErr, stopError) || !errors.Is(gotErr, closeError) {
			t.Fatalf("Activate() run failure error = %v", gotErr)
		}
		if !handle.closed || handle.closeCalls != 1 {
			t.Fatalf("close state = closed=%v calls=%d", handle.closed, handle.closeCalls)
		}
	})
}

func TestOpenRestyRuntimeDoesNotRecoverProcessWithoutLaunchToken(t *testing.T) {
	root := t.TempDir()
	candidate := filepath.Join(root, "current")
	if err := os.Mkdir(candidate, 0o700); err != nil {
		t.Fatal(err)
	}
	pidFile := filepath.Join(root, "nginx.pid")
	binary := "/usr/bin/true"
	info, err := os.Stat(binary)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	record := processIdentity{
		PID: 43, StartTicks: 54321, ExecutableDevice: uint64(stat.Dev), ExecutableInode: uint64(stat.Ino),
		OwnerUID: uint32(os.Geteuid()), BootID: "test-boot-id",
	}
	if err := os.WriteFile(pidFile, []byte("43\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	token := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	pending := fmt.Sprintf("pending %d %d %d %s\n", record.ExecutableDevice, record.ExecutableInode, record.OwnerUID, token)
	if err := os.WriteFile(pidFile+".identity.pending", []byte(pending), 0o600); err != nil {
		t.Fatal(err)
	}
	runtime, err := NewOpenRestyRuntime(binary, pidFile, "127.0.0.1:18443")
	if err != nil {
		t.Fatal(err)
	}
	runtime.identityOK = true
	runtime.inspect = func(int) (processIdentity, error) { return record, nil }
	runtime.matchStart = func(int, string) error { return errors.New("launch token mismatch") }
	runtime.openProcess = func(int) (processHandle, error) {
		t.Fatal("opened a process without its launch token")
		return nil, nil
	}
	runtime.run = func(context.Context, string, []string, ...string) error {
		t.Fatal("started a second OpenResty master")
		return nil
	}

	if err := runtime.Activate(context.Background(), candidate); !errors.Is(err, ErrActivation) {
		t.Fatalf("Activate() error = %v, want ErrActivation", err)
	}
	for _, path := range []string{pidFile, pidFile + ".identity.pending"} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("unsafe recovery removed %s: %v", filepath.Base(path), err)
		}
	}
}

func TestOpenRestyRuntimePreservesDeadPendingProcessState(t *testing.T) {
	root := t.TempDir()
	candidate := filepath.Join(root, "current")
	if err := os.Mkdir(candidate, 0o700); err != nil {
		t.Fatal(err)
	}
	pidFile := filepath.Join(root, "nginx.pid")
	configFile := filepath.Join(root, "nginx.conf")
	if err := os.WriteFile(configFile, []byte("events {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	binary := "/usr/bin/true"
	info, err := os.Stat(binary)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	record := processIdentity{
		PID: 43, StartTicks: 54321, ExecutableDevice: uint64(stat.Dev), ExecutableInode: uint64(stat.Ino),
		OwnerUID: uint32(os.Geteuid()), BootID: "test-boot-id",
	}
	if err := os.WriteFile(pidFile, []byte("43\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	token := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	pending := fmt.Sprintf("pending %d %d %d %s\n", record.ExecutableDevice, record.ExecutableInode, record.OwnerUID, token)
	if err := os.WriteFile(pidFile+".identity.pending", []byte(pending), 0o600); err != nil {
		t.Fatal(err)
	}
	runtime, err := NewOpenRestyRuntime(binary, pidFile, "127.0.0.1:18443")
	if err != nil {
		t.Fatal(err)
	}
	runtime.identityOK = true
	runtime.inspect = func(int) (processIdentity, error) { return processIdentity{}, errProcessNotRunning }

	handle, _, running, err := runtime.openOwnedProcess()
	if !errors.Is(err, context.DeadlineExceeded) || handle != nil || running {
		t.Fatalf("openOwnedProcess() = handle=%v running=%v err=%v", handle, running, err)
	}
	for _, path := range []string{pidFile, pidFile + ".identity.pending"} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("dead pending state removed %s: %v", filepath.Base(path), err)
		}
	}
	if content, err := os.ReadFile(configFile); err != nil || string(content) != "events {}\n" {
		t.Fatalf("config file changed: %q, %v", content, err)
	}
}

func TestOpenRestyRuntimePreservesPendingOnlyOwnership(t *testing.T) {
	root := t.TempDir()
	current := filepath.Join(root, "current")
	if err := os.Mkdir(current, 0o700); err != nil {
		t.Fatal(err)
	}
	pidFile := filepath.Join(root, "nginx.pid")
	info, err := os.Stat("/usr/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	record := processIdentity{
		PID: 43, StartTicks: 54321, ExecutableDevice: uint64(stat.Dev), ExecutableInode: uint64(stat.Ino),
		OwnerUID: uint32(os.Geteuid()), BootID: "test-boot-id",
	}
	token := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	startRecord := processStartIdentity{
		ExecutableDevice: record.ExecutableDevice, ExecutableInode: record.ExecutableInode,
		OwnerUID: record.OwnerUID, Token: token,
	}
	if err := os.WriteFile(pidFile+".identity.pending", []byte(formatProcessStartIdentity(startRecord)), 0o600); err != nil {
		t.Fatal(err)
	}
	runtime, err := NewOpenRestyRuntime("/usr/bin/true", pidFile, "127.0.0.1:18443")
	if err != nil {
		t.Fatal(err)
	}
	runtime.identityOK = true
	runtime.inspect = func(int) (processIdentity, error) { return record, nil }
	runCalls := 0
	runtime.matchStart = func(pid int, got string) error {
		if pid != record.PID || (runCalls == 0 && got != token) {
			t.Fatalf("matchStart(%d, %q)", pid, got)
		}
		return nil
	}
	handle := &fakeProcessHandle{}
	runtime.openProcess = func(int) (processHandle, error) { return handle, nil }
	runtime.run = func(context.Context, string, []string, ...string) error {
		runCalls++
		return os.WriteFile(pidFile, []byte("43\n"), 0o600)
	}
	activateErr := runtime.Activate(context.Background(), current)
	if runCalls != 0 {
		t.Fatalf("pending-only timeout started %d second master(s)", runCalls)
	}
	if !errors.Is(activateErr, ErrActivation) {
		t.Fatalf("Activate() pending-only error = %v, want ErrActivation", activateErr)
	}
	if _, err := os.Stat(pidFile + ".identity.pending"); err != nil {
		t.Fatalf("pending ownership was removed: %v", err)
	}

	if err := os.WriteFile(pidFile, []byte("43\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Activate(context.Background(), current); err != nil {
		t.Fatalf("Activate() recovery error = %v", err)
	}
	if len(handle.signals) != 1 || handle.signals[0] != syscall.SIGHUP || !handle.closed {
		t.Fatalf("recovery signals=%v closed=%v", handle.signals, handle.closed)
	}
	if runCalls != 0 {
		t.Fatalf("late PID recovery started %d second master(s)", runCalls)
	}
}

func TestKernelProcessIdentityDoesNotAcceptCurrentBinaryPath(t *testing.T) {
	if got := reflect.TypeOf(kernelProcessIdentity).NumIn(); got != 1 {
		t.Fatalf("kernelProcessIdentity accepts %d arguments, want PID only", got)
	}
}

func TestOpenRestyRuntimeRecognizesRecordedMasterAfterBinaryReplacement(t *testing.T) {
	root := t.TempDir()
	candidate := filepath.Join(root, "current")
	if err := os.Mkdir(candidate, 0o700); err != nil {
		t.Fatal(err)
	}
	pidFile := filepath.Join(root, "nginx.pid")
	record := processIdentity{
		PID: 43, StartTicks: 54321, ExecutableDevice: 8, ExecutableInode: 100,
		OwnerUID: uint32(os.Geteuid()), BootID: "test-boot-id",
	}
	writeProcessFixture(t, pidFile, record)
	runtime, err := NewOpenRestyRuntime("/usr/bin/true", pidFile, "127.0.0.1:18443")
	if err != nil {
		t.Fatal(err)
	}
	runtime.identityOK = true
	runtime.inspect = func(int) (processIdentity, error) { return record, nil }
	handle := &fakeProcessHandle{}
	runtime.openProcess = func(int) (processHandle, error) { return handle, nil }
	runtime.run = func(context.Context, string, []string, ...string) error {
		t.Fatal("binary replacement caused a second master start")
		return nil
	}

	if err := runtime.Activate(context.Background(), candidate); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	if len(handle.signals) != 1 || handle.signals[0] != syscall.SIGHUP || !handle.closed {
		t.Fatalf("signals=%v closed=%v", handle.signals, handle.closed)
	}
}

func TestStopStartedProcessEscalation(t *testing.T) {
	signalError := errors.New("signal failed")
	waitError := errors.New("wait failed")
	for _, test := range []struct {
		name  string
		waits []struct {
			exited bool
			err    error
		}
		signal      syscall.Signal
		signalError error
		wantSignals []syscall.Signal
		wantError   bool
		wantRemoved bool
	}{
		{name: "SIGQUIT exits", waits: []struct {
			exited bool
			err    error
		}{{exited: true}}, wantSignals: []syscall.Signal{syscall.SIGQUIT}, wantRemoved: true},
		{name: "SIGKILL exits", waits: []struct {
			exited bool
			err    error
		}{{}, {exited: true}}, wantSignals: []syscall.Signal{syscall.SIGQUIT, syscall.SIGKILL}, wantRemoved: true},
		{name: "SIGKILL remains alive", waits: []struct {
			exited bool
			err    error
		}{{}, {}}, wantSignals: []syscall.Signal{syscall.SIGQUIT, syscall.SIGKILL}, wantError: true},
		{name: "SIGQUIT signal error", signal: syscall.SIGQUIT, signalError: signalError, wantSignals: []syscall.Signal{syscall.SIGQUIT}, wantError: true},
		{name: "SIGQUIT wait error", waits: []struct {
			exited bool
			err    error
		}{{err: waitError}}, wantSignals: []syscall.Signal{syscall.SIGQUIT}, wantError: true},
		{name: "SIGKILL signal error", waits: []struct {
			exited bool
			err    error
		}{{}}, signal: syscall.SIGKILL, signalError: signalError, wantSignals: []syscall.Signal{syscall.SIGQUIT, syscall.SIGKILL}, wantError: true},
		{name: "SIGKILL wait error", waits: []struct {
			exited bool
			err    error
		}{{}, {err: waitError}}, wantSignals: []syscall.Signal{syscall.SIGQUIT, syscall.SIGKILL}, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			pidFile := filepath.Join(root, "nginx.pid")
			configFile := filepath.Join(root, "nginx.conf")
			record := processIdentity{
				PID: 43, StartTicks: 54321, ExecutableDevice: 8, ExecutableInode: 100,
				OwnerUID: uint32(os.Geteuid()), BootID: "test-boot-id",
			}
			writeProcessFixture(t, pidFile, record)
			pending := fmt.Sprintf("pending %d %d %d %s\n", record.ExecutableDevice, record.ExecutableInode, record.OwnerUID,
				"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
			if err := os.WriteFile(pidFile+".identity.pending", []byte(pending), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(configFile, []byte("events {}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			handle := &fakeProcessHandle{onSignal: func(signal syscall.Signal) error {
				if signal == test.signal {
					return test.signalError
				}
				return nil
			}}
			waitIndex := 0
			wait := func(processHandle, time.Duration) (bool, error) {
				if waitIndex >= len(test.waits) {
					t.Fatalf("unexpected wait call %d", waitIndex+1)
				}
				result := test.waits[waitIndex]
				waitIndex++
				return result.exited, result.err
			}

			err := stopStartedProcess(handle, pidFile, record, wait)
			if (err != nil) != test.wantError {
				t.Fatalf("stopStartedProcess() error = %v, wantError=%v", err, test.wantError)
			}
			if !reflect.DeepEqual(handle.signals, test.wantSignals) {
				t.Fatalf("signals=%v, want %v", handle.signals, test.wantSignals)
			}
			for _, path := range []string{pidFile, pidFile + ".identity", pidFile + ".identity.pending"} {
				_, statErr := os.Stat(path)
				if test.wantRemoved && !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("%s was not removed: %v", filepath.Base(path), statErr)
				}
				if !test.wantRemoved && statErr != nil {
					t.Fatalf("%s was not preserved: %v", filepath.Base(path), statErr)
				}
			}
			if content, err := os.ReadFile(configFile); err != nil || string(content) != "events {}\n" {
				t.Fatalf("config file changed: %q, %v", content, err)
			}
		})
	}
}

func TestProcessFileCleanupSyncsParentDirectory(t *testing.T) {
	syncError := errors.New("sync failed")
	for _, cleanup := range []struct {
		name    string
		pending bool
		call    func(string, processIdentity, func(string) error) error
	}{
		{name: "started process", pending: true, call: func(pidFile string, identity processIdentity, sync func(string) error) error {
			return removeStartedProcessFilesIfMatch(pidFile, identity, sync)
		}},
		{name: "recorded process", call: func(pidFile string, identity processIdentity, sync func(string) error) error {
			return removeProcessFilesIfMatch(pidFile, identity, sync)
		}},
	} {
		for _, failure := range []bool{false, true} {
			name := "success"
			if failure {
				name = "sync error"
			}
			t.Run(cleanup.name+"/"+name, func(t *testing.T) {
				root := t.TempDir()
				pidFile := filepath.Join(root, "nginx.pid")
				configFile := filepath.Join(root, "nginx.conf")
				record := processIdentity{
					PID: 43, StartTicks: 54321, ExecutableDevice: 8, ExecutableInode: 100,
					OwnerUID: uint32(os.Geteuid()), BootID: "test-boot-id",
				}
				writeProcessFixture(t, pidFile, record)
				processFiles := []string{pidFile, pidFile + ".identity"}
				if cleanup.pending {
					pending := fmt.Sprintf("pending %d %d %d %s\n", record.ExecutableDevice, record.ExecutableInode, record.OwnerUID,
						"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
					if err := os.WriteFile(pidFile+".identity.pending", []byte(pending), 0o600); err != nil {
						t.Fatal(err)
					}
					processFiles = append(processFiles, pidFile+".identity.pending")
				}
				if err := os.WriteFile(configFile, []byte("events {}\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				syncCalls := 0
				err := cleanup.call(pidFile, record, func(path string) error {
					syncCalls++
					if path != root {
						t.Fatalf("sync path = %q, want %q", path, root)
					}
					if failure {
						return syncError
					}
					return nil
				})
				if failure && !errors.Is(err, syncError) {
					t.Fatalf("cleanup error = %v, want sync error", err)
				}
				if !failure && err != nil {
					t.Fatalf("cleanup error = %v", err)
				}
				if syncCalls != 1 {
					t.Fatalf("sync calls = %d, want 1", syncCalls)
				}
				for _, path := range processFiles {
					if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("cleanup left %s: %v", filepath.Base(path), err)
					}
				}
				if content, err := os.ReadFile(configFile); err != nil || string(content) != "events {}\n" {
					t.Fatalf("config file changed: %q, %v", content, err)
				}
			})
		}
	}
}

func TestRemoveProcessPathsSyncsAfterPartialDelete(t *testing.T) {
	removeError := errors.New("remove failed")
	syncError := errors.New("sync failed")
	t.Run("joins removal and sync errors", func(t *testing.T) {
		root := t.TempDir()
		paths := []string{filepath.Join(root, "nginx.pid"), filepath.Join(root, "nginx.pid.identity")}
		removeCalls := 0
		syncCalls := 0
		err := removeProcessPaths(paths, func(path string) error {
			if path != paths[removeCalls] {
				t.Fatalf("remove path = %q, want %q", path, paths[removeCalls])
			}
			removeCalls++
			if removeCalls == 2 {
				return removeError
			}
			return nil
		}, func(path string) error {
			syncCalls++
			if path != root {
				t.Fatalf("sync path = %q, want %q", path, root)
			}
			return syncError
		})
		if !errors.Is(err, removeError) || !errors.Is(err, syncError) {
			t.Fatalf("removeProcessPaths() error = %v", err)
		}
		if removeCalls != 2 || syncCalls != 1 {
			t.Fatalf("remove calls=%d sync calls=%d", removeCalls, syncCalls)
		}
	})

	t.Run("no deletion skips sync", func(t *testing.T) {
		root := t.TempDir()
		paths := []string{filepath.Join(root, "nginx.pid"), filepath.Join(root, "nginx.pid.identity")}
		removeCalls := 0
		syncCalls := 0
		err := removeProcessPaths(paths, func(string) error {
			removeCalls++
			if removeCalls == 1 {
				return os.ErrNotExist
			}
			return removeError
		}, func(string) error {
			syncCalls++
			return nil
		})
		if !errors.Is(err, removeError) {
			t.Fatalf("removeProcessPaths() error = %v", err)
		}
		if removeCalls != 2 || syncCalls != 0 {
			t.Fatalf("remove calls=%d sync calls=%d", removeCalls, syncCalls)
		}
	})
}

func TestRemoveProcessStartIdentitySkipsSyncWhenMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "nginx.pid.identity.pending")
	if err := removeProcessStartIdentity(path); err != nil {
		t.Fatalf("removeProcessStartIdentity() missing file error = %v", err)
	}
}

func TestRecordStartedProcessPreservesConfirmationCleanupErrors(t *testing.T) {
	removeError := errors.New("remove identity failed")
	syncError := errors.New("sync identity directory failed")
	stopError := errors.New("stop failed")
	closeError := errors.New("close failed")
	for _, test := range []struct {
		name               string
		removeError        error
		syncError          error
		wantIdentityExists bool
	}{
		{name: "remove and later stop errors", removeError: removeError, wantIdentityExists: true},
		{name: "sync and later stop errors", syncError: syncError},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			pidFile := filepath.Join(root, "nginx.pid")
			info, err := os.Stat("/usr/bin/true")
			if err != nil {
				t.Fatal(err)
			}
			stat := info.Sys().(*syscall.Stat_t)
			record := processIdentity{
				PID: 43, StartTicks: 54321, ExecutableDevice: uint64(stat.Dev), ExecutableInode: uint64(stat.Ino),
				OwnerUID: uint32(os.Geteuid()), BootID: "test-boot-id",
			}
			if err := os.WriteFile(pidFile, []byte("43\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			startRecord := processStartIdentity{
				ExecutableDevice: record.ExecutableDevice, ExecutableInode: record.ExecutableInode,
				OwnerUID: record.OwnerUID, Token: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			}
			if err := os.WriteFile(pidFile+".identity.pending", []byte(formatProcessStartIdentity(startRecord)), 0o600); err != nil {
				t.Fatal(err)
			}
			runtime, err := NewOpenRestyRuntime("/usr/bin/true", pidFile, "127.0.0.1:18443")
			if err != nil {
				t.Fatal(err)
			}
			inspectCalls := 0
			runtime.inspect = func(int) (processIdentity, error) {
				inspectCalls++
				if inspectCalls == 3 {
					changed := record
					changed.StartTicks++
					return changed, nil
				}
				return record, nil
			}
			runtime.matchStart = func(int, string) error { return nil }
			handle := &fakeProcessHandle{closeErr: closeError, onSignal: func(syscall.Signal) error { return stopError }}
			runtime.openProcess = func(int) (processHandle, error) { return handle, nil }
			removeCalls := 0
			runtime.removeProcessFile = func(path string) error {
				removeCalls++
				if path != pidFile+".identity" {
					t.Fatalf("remove path = %q", path)
				}
				if test.removeError != nil {
					return test.removeError
				}
				return os.Remove(path)
			}
			syncCalls := 0
			runtime.syncProcessDirectory = func(path string) error {
				syncCalls++
				if path != root {
					t.Fatalf("sync path = %q, want %q", path, root)
				}
				return test.syncError
			}

			err = runtime.recordStartedProcess(context.Background())
			if !errors.Is(err, stopError) {
				t.Fatalf("recordStartedProcess() error = %v, want stop error", err)
			}
			if !errors.Is(err, closeError) {
				t.Fatalf("recordStartedProcess() error = %v, want close error", err)
			}
			if test.removeError != nil && !errors.Is(err, test.removeError) {
				t.Fatalf("recordStartedProcess() error = %v, want remove error", err)
			}
			if test.syncError != nil && !errors.Is(err, test.syncError) {
				t.Fatalf("recordStartedProcess() error = %v, want sync error", err)
			}
			if removeCalls != 1 {
				t.Fatalf("remove calls = %d, want 1", removeCalls)
			}
			wantSyncCalls := 1
			if test.removeError != nil {
				wantSyncCalls = 0
			}
			if syncCalls != wantSyncCalls {
				t.Fatalf("sync calls = %d, want %d", syncCalls, wantSyncCalls)
			}
			_, identityErr := os.Stat(pidFile + ".identity")
			if test.wantIdentityExists && identityErr != nil {
				t.Fatalf("identity was not preserved: %v", identityErr)
			}
			if !test.wantIdentityExists && !errors.Is(identityErr, os.ErrNotExist) {
				t.Fatalf("identity was not removed: %v", identityErr)
			}
		})
	}
}

func TestOpenRestyRuntimeStopsExactStartedProcessWhenIdentityIsNotCommitted(t *testing.T) {
	for _, test := range []struct {
		name          string
		cancel        bool
		runError      error
		identityError error
		inspectError  bool
		pidReadError  bool
		want          error
	}{
		{name: "identity write failure", identityError: errors.New("identity write failed"), want: ErrActivation},
		{name: "cancel after daemon start", cancel: true, want: context.Canceled},
		{name: "command cancellation after daemon start", cancel: true, runError: context.Canceled, want: context.Canceled},
		{name: "identity read failure after pidfd capture", inspectError: true, want: ErrActivation},
		{name: "PID read failure after pidfd capture", pidReadError: true, want: ErrActivation},
		{name: "command failure and PID read failure after pidfd capture", runError: errors.New("start failed"), pidReadError: true, want: ErrActivation},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			candidate := filepath.Join(root, "current")
			if err := os.Mkdir(candidate, 0o700); err != nil {
				t.Fatal(err)
			}
			pidFile := filepath.Join(root, "nginx.pid")
			binaryInfo, err := os.Stat("/usr/bin/true")
			if err != nil {
				t.Fatal(err)
			}
			binaryStat := binaryInfo.Sys().(*syscall.Stat_t)
			record := processIdentity{
				PID: 43, StartTicks: 54321, ExecutableDevice: uint64(binaryStat.Dev), ExecutableInode: uint64(binaryStat.Ino),
				OwnerUID: uint32(os.Geteuid()), BootID: "test-boot-id",
			}
			runtime, err := NewOpenRestyRuntime("/usr/bin/true", pidFile, "127.0.0.1:18443")
			if err != nil {
				t.Fatal(err)
			}
			runtime.identityOK = true
			runtime.matchStart = func(int, string) error { return nil }
			inspectCalls := 0
			runtime.inspect = func(pid int) (processIdentity, error) {
				if pid != record.PID {
					t.Fatalf("inspect(%d)", pid)
				}
				inspectCalls++
				if test.inspectError && inspectCalls == 3 {
					return processIdentity{}, errors.New("inspect failed")
				}
				return record, nil
			}
			handle := &fakeProcessHandle{}
			runtime.openProcess = func(pid int) (processHandle, error) {
				if pid != record.PID {
					t.Fatalf("openProcess(%d)", pid)
				}
				if test.pidReadError {
					if err := os.WriteFile(pidFile, nil, 0o600); err != nil {
						t.Fatal(err)
					}
					handle.onSignal = func(syscall.Signal) error {
						return os.Remove(pidFile)
					}
				}
				return handle, nil
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			runtime.run = func(context.Context, string, []string, ...string) error {
				if err := os.WriteFile(pidFile, []byte("43\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if test.cancel {
					cancel()
				}
				return test.runError
			}
			writes := 0
			runtime.writeIdentity = func(path string, content []byte) error {
				writes++
				if test.identityError != nil && writes == 2 {
					return test.identityError
				}
				return writeAtomicFile(path, content)
			}

			if err := runtime.Activate(ctx, candidate); !errors.Is(err, test.want) {
				t.Fatalf("Activate() error = %v, want %v", err, test.want)
			}
			if len(handle.signals) != 1 || handle.signals[0] != syscall.SIGQUIT || !handle.closed {
				t.Fatalf("cleanup signals=%v closed=%v", handle.signals, handle.closed)
			}
			if test.cancel && writes != 1 {
				t.Fatalf("cancelled startup wrote %d identity records, want pending only", writes)
			}
			if _, err := os.Lstat(pidFile); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("started PID residue error = %v", err)
			}
			if _, err := os.Lstat(pidFile + ".identity"); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("started identity residue error = %v", err)
			}
			if _, err := os.Lstat(pidFile + ".identity.pending"); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("started pending identity residue error = %v", err)
			}
		})
	}
}

func TestOpenRestyRuntimeDoesNotSignalReusedPIDDuringStartup(t *testing.T) {
	root := t.TempDir()
	candidate := filepath.Join(root, "current")
	if err := os.Mkdir(candidate, 0o700); err != nil {
		t.Fatal(err)
	}
	pidFile := filepath.Join(root, "nginx.pid")
	binaryInfo, err := os.Stat("/usr/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	binaryStat := binaryInfo.Sys().(*syscall.Stat_t)
	started := processIdentity{
		PID: 43, StartTicks: 54321, ExecutableDevice: uint64(binaryStat.Dev), ExecutableInode: uint64(binaryStat.Ino),
		OwnerUID: uint32(os.Geteuid()), BootID: "test-boot-id",
	}
	reused := started
	reused.StartTicks++
	runtime, err := NewOpenRestyRuntime("/usr/bin/true", pidFile, "127.0.0.1:18443")
	if err != nil {
		t.Fatal(err)
	}
	runtime.identityOK = true
	runtime.matchStart = func(int, string) error { return nil }
	inspectCalls := 0
	runtime.inspect = func(int) (processIdentity, error) {
		inspectCalls++
		if inspectCalls == 1 {
			return started, nil
		}
		return reused, nil
	}
	handle := &fakeProcessHandle{}
	runtime.openProcess = func(int) (processHandle, error) { return handle, nil }
	runtime.run = func(context.Context, string, []string, ...string) error {
		return os.WriteFile(pidFile, []byte("43\n"), 0o600)
	}

	if err := runtime.Activate(context.Background(), candidate); !errors.Is(err, ErrActivation) {
		t.Fatalf("Activate() error = %v, want ErrActivation", err)
	}
	if len(handle.signals) != 0 || !handle.closed {
		t.Fatalf("reused PID signals=%v closed=%v", handle.signals, handle.closed)
	}
	pid, exists, err := readProcessPID(pidFile)
	if err != nil || !exists || pid != reused.PID {
		t.Fatalf("replacement PID = %d, exists=%v, err=%v", pid, exists, err)
	}
}

func TestProcessFileValidationRejectsNonRegularWritableAndWrongOwner(t *testing.T) {
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
		t.Fatal("PID file validation accepted the wrong owner")
	}
	if err := os.Chmod(path, 0o622); err != nil {
		t.Fatal(err)
	}
	info, err = os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateProcessFileInfo(info, uint32(os.Geteuid()), 32); err == nil {
		t.Fatal("PID file validation accepted group/world write access")
	}
	directoryInfo, err := os.Lstat(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateProcessFileInfo(directoryInfo, uint32(os.Geteuid()), 32); err == nil {
		t.Fatal("PID file validation accepted a non-regular file")
	}
}

func TestOpenRestyRuntimeNeverUsesPIDFileSignalAfterIdentityCheck(t *testing.T) {
	for _, signal := range []struct {
		name string
		call func(*OpenRestyRuntime, string) error
	}{
		{name: "reload", call: func(runtime *OpenRestyRuntime, path string) error {
			return runtime.Activate(context.Background(), path)
		}},
		{name: "quit", call: func(runtime *OpenRestyRuntime, path string) error {
			return runtime.Stop(context.Background(), path)
		}},
	} {
		t.Run(signal.name, func(t *testing.T) {
			root := t.TempDir()
			current := filepath.Join(root, "current")
			if err := os.Mkdir(current, 0o700); err != nil {
				t.Fatal(err)
			}
			pidFile := filepath.Join(root, "nginx.pid")
			original := processIdentity{PID: 42, StartTicks: 100, ExecutableDevice: 1, ExecutableInode: 2, OwnerUID: uint32(os.Geteuid()), BootID: "boot-a"}
			replacement := processIdentity{PID: 43, StartTicks: 200, ExecutableDevice: 1, ExecutableInode: 2, OwnerUID: uint32(os.Geteuid()), BootID: "boot-a"}
			writeProcessFixture(t, pidFile, original)
			runtime, err := NewOpenRestyRuntime("/usr/bin/true", pidFile, "127.0.0.1:18443")
			if err != nil {
				t.Fatal(err)
			}
			replaced := false
			handle := &fakeProcessHandle{}
			runtime.identityOK = true
			runtime.openProcess = func(pid int) (processHandle, error) {
				if pid != original.PID {
					t.Fatalf("openProcess(%d)", pid)
				}
				return handle, nil
			}
			runtime.inspect = func(pid int) (processIdentity, error) {
				if !replaced {
					replaced = true
					writeProcessFixture(t, pidFile, replacement)
					return original, nil
				}
				return replacement, errProcessNotRunning
			}
			runs := 0
			runtime.run = func(context.Context, string, []string, ...string) error {
				runs++
				return nil
			}
			if err := signal.call(runtime, current); err != nil {
				t.Fatalf("%s error = %v", signal.name, err)
			}
			if runs != 0 {
				t.Fatalf("%s used %d PID-file command(s) after identity check", signal.name, runs)
			}
			wantSignal := syscall.SIGHUP
			if signal.name == "quit" {
				wantSignal = syscall.SIGQUIT
			}
			if len(handle.signals) != 1 || handle.signals[0] != wantSignal || !handle.closed {
				t.Fatalf("%s signals=%v closed=%v", signal.name, handle.signals, handle.closed)
			}
			stored, err := readProcessRecord(pidFile + ".identity")
			if err != nil || stored != replacement {
				t.Fatalf("%s removed replacement identity: %+v, %v", signal.name, stored, err)
			}
		})
	}
}

func writeProcessFixture(t *testing.T, pidFile string, identity processIdentity) {
	t.Helper()
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(identity.PID)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pidFile+".identity", []byte(formatProcessRecord(identity)), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A command that only removes sites has no health target: the runtime must
// still accept connections (it used to fail every removal on a real runtime).
func TestOpenRestyRuntimeHealthyWithoutTargetsChecksTheListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			_ = connection.Close()
		}
	}()
	runtime, err := NewOpenRestyRuntime("/usr/bin/openresty", filepath.Join(t.TempDir(), "nginx.pid"), listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Healthy(t.Context(), nil); err != nil {
		t.Fatalf("Healthy(no targets) with a listener: %v", err)
	}
	_ = listener.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	if err := runtime.Healthy(ctx, nil); err == nil {
		t.Fatal("Healthy(no targets) without a listener succeeded")
	}
}
