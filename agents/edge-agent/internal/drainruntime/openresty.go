package drainruntime

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	workerRecordSchemaVersion = 2
	processStartEnvironment   = "CDNCA_DRAIN_OPENRESTY_START_TOKEN"
	maxTrackedWorkers         = 256
	linuxPIDFDOpen            = uintptr(434)
	linuxPIDFDSendSignal      = uintptr(424)
)

var (
	errProcessNotRunning          = errors.New("process is not running")
	errProcessExited              = errors.New("process exited")
	errProcessIdentityUnavailable = errors.New("process identity is temporarily unavailable")
)

type processIdentity struct {
	PID              int    `json:"pid"`
	StartTicks       uint64 `json:"start_ticks"`
	ExecutableDevice uint64 `json:"executable_device"`
	ExecutableInode  uint64 `json:"executable_inode"`
	OwnerUID         uint32 `json:"owner_uid"`
	BootID           string `json:"boot_id"`
}

type processStartIdentity struct {
	ExecutableDevice uint64
	ExecutableInode  uint64
	OwnerUID         uint32
	Token            string
}

func (start processStartIdentity) matches(identity processIdentity) bool {
	return start.ExecutableDevice == identity.ExecutableDevice && start.ExecutableInode == identity.ExecutableInode &&
		start.OwnerUID == identity.OwnerUID
}

type workerIdentity struct {
	Generation string          `json:"generation"`
	Identity   processIdentity `json:"identity"`
}

type workerRecord struct {
	SchemaVersion int              `json:"schema_version"`
	Revision      uint64           `json:"revision"`
	Digest        string           `json:"digest"`
	Reloaded      bool             `json:"reloaded"`
	Generation    string           `json:"generation"`
	Master        processIdentity  `json:"master"`
	Workers       []workerIdentity `json:"workers"`
}

type processHandle interface {
	Signal(syscall.Signal) error
	Alive() (bool, error)
	Close() error
}

type pidfdHandle struct{ fd int }

type ownedProcess struct {
	identity processIdentity
	handle   processHandle
}

type OpenResty struct {
	binary       string
	prefix       string
	binaryFile   *os.File
	prefixDir    *os.File
	logsDir      *os.File
	currentPath  string
	pidPath      string
	workersPath  string
	commandLimit time.Duration

	inspect      func(int) (processIdentity, error)
	matchStart   func(int, string) error
	openProcess  func(int) (processHandle, error)
	children     func(int) ([]int, error)
	startProcess func(context.Context, string, ...string) error
	writeState   func(string, []byte) error
	removeState  func(string) error
	syncState    func(string) error
	identityOK   bool
}

func NewOpenResty(binary, prefix string, commandLimit time.Duration) (*OpenResty, error) {
	if !safeAbsolutePath(binary) || !safeAbsolutePath(prefix) || commandLimit <= 0 || commandLimit > time.Minute {
		return nil, ErrInvalidPath
	}
	var err error
	binary, err = canonicalRuntimePath(binary)
	if err != nil {
		return nil, err
	}
	prefix, err = canonicalRuntimePath(prefix)
	if err != nil {
		return nil, err
	}
	binaryFile, err := openRuntimeBinary(binary)
	if err != nil {
		return nil, err
	}
	prefixDir, err := openTrustedRuntimeDirectory(prefix, true, true)
	if err != nil {
		_ = binaryFile.Close()
		return nil, err
	}
	logsPath := filepath.Join(prefix, "logs")
	logsDir, err := openTrustedRuntimeDirectory(logsPath, true, true)
	if err != nil {
		_ = prefixDir.Close()
		_ = binaryFile.Close()
		return nil, err
	}
	statePrefix := descriptorPath(prefixDir)
	stateLogs := descriptorPath(logsDir)
	value := &OpenResty{
		binary: binary, prefix: prefix, binaryFile: binaryFile, prefixDir: prefixDir, logsDir: logsDir,
		currentPath: filepath.Join(statePrefix, "current.conf"),
		pidPath:     filepath.Join(stateLogs, "nginx.pid"), workersPath: filepath.Join(statePrefix, "drain-workers.json"),
		commandLimit: commandLimit,
		inspect:      kernelProcessIdentity, matchStart: kernelProcessStartMatches, openProcess: openPIDFD, children: childPIDs,
		writeState: writeAtomic, removeState: os.Remove, syncState: syncDirectory, identityOK: runtime.GOOS == "linux",
	}
	value.startProcess = value.runStartCommand
	return value, nil
}

func canonicalRuntimePath(path string) (string, error) {
	components := []string{filepath.Base(path)}
	parent := filepath.Dir(path)
	for {
		resolved, err := filepath.EvalSymlinks(parent)
		if err == nil {
			components = append([]string{resolved}, components...)
			return filepath.Join(components...), nil
		}
		if !errors.Is(err, os.ErrNotExist) || parent == string(filepath.Separator) {
			return "", ErrInvalidPath
		}
		components = append([]string{filepath.Base(parent)}, components...)
		parent = filepath.Dir(parent)
	}
}

func openRuntimeBinary(path string) (*os.File, error) {
	parent, err := openTrustedRuntimeDirectory(filepath.Dir(path), false, false)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	fd, err := unix.Openat(int(parent.Fd()), filepath.Base(path), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrInvalidPath
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, ErrInvalidPath
	}
	info, err := file.Stat()
	if err != nil || validateRuntimeBinaryInfo(info) != nil {
		_ = file.Close()
		return nil, ErrInvalidPath
	}
	return file, nil
}

func validateRuntimeBinaryInfo(info os.FileInfo) error {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Mode().Perm()&0o111 == 0 {
		return ErrInvalidPath
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Ino == 0 || uint64(stat.Nlink) != 1 || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
		return ErrInvalidPath
	}
	return nil
}

func openTrustedRuntimeDirectory(path string, create, privateLeaf bool) (*os.File, error) {
	if !safeAbsolutePath(path) {
		return nil, ErrInvalidPath
	}
	current, err := os.Open(string(filepath.Separator))
	if err != nil {
		return nil, ErrInvalidPath
	}
	components := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	for index, component := range components {
		fd, openErr := unix.Openat(int(current.Fd()), component,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if openErr == unix.ENOENT && create {
			if mkdirErr := unix.Mkdirat(int(current.Fd()), component, 0o700); mkdirErr != nil && mkdirErr != unix.EEXIST {
				_ = current.Close()
				return nil, ErrInvalidPath
			}
			fd, openErr = unix.Openat(int(current.Fd()), component,
				unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		}
		if openErr != nil {
			_ = current.Close()
			return nil, ErrInvalidPath
		}
		next := os.NewFile(uintptr(fd), component)
		if next == nil {
			_ = unix.Close(fd)
			_ = current.Close()
			return nil, ErrInvalidPath
		}
		info, statErr := next.Stat()
		leaf := index == len(components)-1
		if statErr != nil || (!leaf || !privateLeaf) && validateTrustedRuntimeDirectoryInfo(info) != nil ||
			leaf && privateLeaf && validatePrivateRuntimeDirectoryInfo(info) != nil {
			_ = next.Close()
			_ = current.Close()
			return nil, ErrInvalidPath
		}
		_ = current.Close()
		current = next
	}
	return current, nil
}

func validateTrustedRuntimeDirectoryInfo(info os.FileInfo) error {
	if info == nil || !info.IsDir() {
		return ErrInvalidPath
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
		return ErrInvalidPath
	}
	if info.Mode().Perm()&0o022 != 0 && (info.Mode()&os.ModeSticky == 0 || stat.Uid != 0) {
		return ErrInvalidPath
	}
	return nil
}

func validatePrivateRuntimeDirectoryInfo(info os.FileInfo) error {
	if info == nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 || info.Mode().Perm()&0o700 != 0o700 {
		return ErrInvalidPath
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return ErrInvalidPath
	}
	return nil
}

func descriptorPath(file *os.File) string {
	return descriptorNumberPath(int(file.Fd()))
}

func descriptorNumberPath(fd int) string {
	root := "/dev/fd"
	if runtime.GOOS == "linux" {
		root = "/proc/self/fd"
	}
	return filepath.Join(root, strconv.Itoa(fd))
}

func (r *OpenResty) validateRuntimePaths() error {
	if r == nil || r.binaryFile == nil || r.prefixDir == nil || r.logsDir == nil {
		return ErrInvalidPath
	}
	checks := []struct {
		path string
		open func(string) (*os.File, error)
		want *os.File
	}{
		{path: r.binary, open: openRuntimeBinary, want: r.binaryFile},
		{path: r.prefix, open: func(path string) (*os.File, error) {
			return openTrustedRuntimeDirectory(path, false, true)
		}, want: r.prefixDir},
		{path: filepath.Join(r.prefix, "logs"), open: func(path string) (*os.File, error) {
			return openTrustedRuntimeDirectory(path, false, true)
		}, want: r.logsDir},
	}
	for _, check := range checks {
		current, err := check.open(check.path)
		if err != nil {
			return ErrInvalidPath
		}
		currentInfo, currentErr := current.Stat()
		wantInfo, wantErr := check.want.Stat()
		_ = current.Close()
		if currentErr != nil || wantErr != nil || !os.SameFile(currentInfo, wantInfo) {
			return ErrInvalidPath
		}
	}
	return nil
}

func (r *OpenResty) Precheck(ctx context.Context, _ Plan, artifacts Artifacts) error {
	defer os.Remove(filepath.Join(filepath.Dir(r.pidPath), "precheck.pid"))
	for _, path := range []string{artifacts.CandidatePath, artifacts.DrainingPath, artifacts.RollbackPath} {
		if !safeAbsolutePath(path) {
			return ErrInvalidPath
		}
		if err := r.run(ctx, "-t", "-q", "-p", withSeparator(r.prefix), "-c", path, "-g", "pid logs/precheck.pid;"); err != nil {
			return err
		}
	}
	return nil
}

func (r *OpenResty) ActivateNew(ctx context.Context, _ Plan, artifacts Artifacts) error {
	return r.activate(ctx, artifacts.CandidatePath)
}

func (r *OpenResty) NewHealthy(ctx context.Context, plan Plan, _ Artifacts) (bool, error) {
	listeners := make(map[string]Listener, len(plan.New.Listeners))
	for _, listener := range plan.New.Listeners {
		listeners[listener.ID] = listener
	}
	for _, check := range plan.HealthChecks {
		listener := listeners[check.ListenerID]
		var ready bool
		var err error
		if listener.Protocol == ProtocolHTTP {
			ready, err = r.httpHealthy(ctx, listener, check)
		} else {
			ready, err = r.tcpHealthy(ctx, listener, check)
		}
		if err != nil {
			return false, err
		}
		if !ready {
			return false, nil
		}
	}
	return true, nil
}

func (r *OpenResty) BeginDrain(ctx context.Context, _ Plan, artifacts Artifacts) (result error) {
	record, err := r.loadWorkers()
	if err != nil {
		return err
	}
	if record != nil {
		if record.Revision != artifacts.Revision || record.Digest != artifacts.Digest {
			return ErrConflict
		}
		if record.Reloaded {
			return r.verifyRecordedMaster(record.Master)
		}
	} else {
		handle, master, running, err := r.openOwnedMaster()
		if err != nil {
			return err
		}
		if handle == nil || !running {
			return errors.Join(errors.New("OpenResty master is not running"), closeProcessHandle(handle))
		}
		defer func() { result = errors.Join(result, handle.Close()) }()
		generation, workers, err := r.captureWorkerGenerationWithHandle(handle, master)
		if err != nil {
			return err
		}
		record = &workerRecord{
			SchemaVersion: workerRecordSchemaVersion, Revision: artifacts.Revision, Digest: artifacts.Digest,
			Generation: generation, Master: master, Workers: workers,
		}
		if err := r.saveWorkers(record); err != nil {
			return err
		}
	}
	if err := r.reloadExpectedMaster(ctx, artifacts.DrainingPath, record.Master); err != nil {
		return err
	}
	record.Reloaded = true
	return r.saveWorkers(record)
}

func (r *OpenResty) RemainingOldWorkers(_ context.Context, _ Plan, artifacts Artifacts) (remaining int, result error) {
	record, err := r.loadWorkers()
	if err != nil {
		return 0, err
	}
	if record == nil || record.Revision != artifacts.Revision || record.Digest != artifacts.Digest || !record.Reloaded {
		return 0, ErrCorruptState
	}
	masterHandle, master, running, err := r.openOwnedMaster()
	if err != nil {
		return 0, err
	}
	if masterHandle == nil || !running || master != record.Master {
		return 0, errors.Join(ErrCorruptState, closeProcessHandle(masterHandle))
	}
	defer func() { result = errors.Join(result, masterHandle.Close()) }()

	workers := make([]ownedProcess, 0, len(record.Workers))
	defer func() { result = errors.Join(result, closeOwnedProcesses(workers)) }()
	for _, stored := range record.Workers {
		handle, err := r.openProcess(stored.Identity.PID)
		if errors.Is(err, errProcessNotRunning) {
			continue
		}
		if err != nil {
			return 0, err
		}
		alive, err := r.verifyWorkerHandle(handle, stored.Identity)
		if err != nil {
			if errors.Is(err, errProcessIdentityUnavailable) {
				workers = append(workers, ownedProcess{identity: stored.Identity, handle: handle})
				continue
			}
			return 0, errors.Join(err, handle.Close())
		}
		if !alive {
			if err := handle.Close(); err != nil {
				return 0, err
			}
			continue
		}
		workers = append(workers, ownedProcess{identity: stored.Identity, handle: handle})
	}
	if alive, err := r.verifyMasterHandle(masterHandle, master); err != nil || !alive {
		return 0, errors.Join(ErrCorruptState, err)
	}
	for _, worker := range workers {
		alive, err := r.verifyWorkerHandle(worker.handle, worker.identity)
		if err != nil {
			if errors.Is(err, errProcessIdentityUnavailable) {
				remaining++
				continue
			}
			return 0, err
		}
		if alive {
			remaining++
		}
	}
	if alive, err := r.verifyMasterHandle(masterHandle, master); err != nil || !alive {
		return 0, errors.Join(ErrCorruptState, err)
	}
	return remaining, nil
}

func (r *OpenResty) Complete(_ context.Context, _ Plan, artifacts Artifacts) error {
	record, err := r.loadWorkers()
	if err != nil {
		return err
	}
	if record != nil && (record.Revision != artifacts.Revision || record.Digest != artifacts.Digest) {
		return ErrConflict
	}
	return r.removePaths([]string{r.workersPath})
}

func (r *OpenResty) Rollback(ctx context.Context, _ Plan, artifacts Artifacts) error {
	if err := r.activate(ctx, artifacts.RollbackPath); err != nil {
		return err
	}
	return r.removePaths([]string{r.workersPath})
}

func (r *OpenResty) ForceTerminate(ctx context.Context, _ Plan, artifacts Artifacts) (result error) {
	record, err := r.loadWorkers()
	if err != nil {
		return err
	}
	if record == nil || record.Revision != artifacts.Revision || record.Digest != artifacts.Digest || !record.Reloaded {
		return ErrCorruptState
	}
	masterHandle, master, running, err := r.openOwnedMaster()
	if err != nil {
		return err
	}
	if masterHandle == nil || !running || master != record.Master {
		return errors.Join(ErrCorruptState, closeProcessHandle(masterHandle))
	}
	defer func() { result = errors.Join(result, masterHandle.Close()) }()

	children, err := r.children(master.PID)
	if err != nil {
		return err
	}
	childSet := integerSet(children)
	workers := make([]ownedProcess, 0, len(record.Workers))
	defer func() { result = errors.Join(result, closeOwnedProcesses(workers)) }()
	for _, stored := range record.Workers {
		if _, exists := childSet[stored.Identity.PID]; !exists {
			continue
		}
		handle, err := r.openProcess(stored.Identity.PID)
		if errors.Is(err, errProcessNotRunning) {
			continue
		}
		if err != nil {
			return err
		}
		alive, err := r.verifyWorkerHandle(handle, stored.Identity)
		if err != nil {
			return errors.Join(err, handle.Close())
		}
		if !alive {
			if err := handle.Close(); err != nil {
				return err
			}
			continue
		}
		workers = append(workers, ownedProcess{identity: stored.Identity, handle: handle})
	}
	if err := r.verifyTerminationSet(masterHandle, master, workers); err != nil {
		return err
	}
	for _, worker := range workers {
		if err := r.verifyTerminationSet(masterHandle, master, []ownedProcess{worker}); err != nil {
			return err
		}
		if err := worker.handle.Signal(syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			return err
		}
		alive, err := r.verifyWorkerHandle(worker.handle, worker.identity)
		if err != nil {
			return err
		}
		if alive {
			continue
		}
	}

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		remaining := false
		for _, worker := range workers {
			alive, err := r.verifyWorkerHandle(worker.handle, worker.identity)
			if err != nil {
				return err
			}
			remaining = remaining || alive
		}
		if alive, err := r.verifyMasterHandle(masterHandle, master); err != nil || !alive {
			return errors.Join(ErrCorruptState, err)
		}
		if !remaining {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for forced OpenResty workers: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

// StartBaseline is intended for isolated bootstrap and recovery tooling. Normal
// deployments should start from the last confirmed runtime configuration.
func (r *OpenResty) StartBaseline(ctx context.Context, configPath string) error {
	if running, err := r.running(); err != nil {
		return err
	} else if running {
		return fmt.Errorf("OpenResty is already running")
	}
	return r.activate(ctx, configPath)
}

func (r *OpenResty) Stop(ctx context.Context) (result error) {
	handle, identity, running, err := r.openOwnedMaster()
	if err != nil {
		return err
	}
	if handle == nil || !running {
		return errors.Join(r.removeMasterFilesIfMatch(identity), closeProcessHandle(handle))
	}
	defer func() { result = errors.Join(result, handle.Close()) }()
	if alive, err := r.verifyMasterHandle(handle, identity); err != nil || !alive {
		return errors.Join(ErrCorruptState, err)
	}
	if err := handle.Signal(syscall.SIGQUIT); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	for {
		alive, err := handle.Alive()
		if err != nil {
			return err
		}
		if !alive {
			return r.removeMasterFilesIfMatch(identity)
		}
		if verified, err := r.verifyMasterHandle(handle, identity); err != nil || !verified {
			return errors.Join(ErrCorruptState, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func (r *OpenResty) activate(ctx context.Context, configPath string) (result error) {
	if !safeAbsolutePath(configPath) {
		return ErrInvalidPath
	}
	handle, identity, running, err := r.openOwnedMaster()
	if err != nil {
		return err
	}
	if handle != nil {
		defer func() { result = errors.Join(result, handle.Close()) }()
	}
	if running {
		if err := atomicSymlink(configPath, r.currentPath); err != nil {
			return err
		}
		return r.signalMaster(handle, identity, syscall.SIGHUP)
	}
	if err := r.removeMasterFilesIfMatch(identity); err != nil {
		return err
	}
	if err := atomicSymlink(configPath, r.currentPath); err != nil {
		return err
	}
	return r.startMaster(ctx)
}

func (r *OpenResty) reloadExpectedMaster(ctx context.Context, configPath string, expected processIdentity) (result error) {
	if !safeAbsolutePath(configPath) {
		return ErrInvalidPath
	}
	handle, identity, running, err := r.openOwnedMaster()
	if err != nil {
		return err
	}
	if handle == nil || !running || identity != expected {
		return errors.Join(ErrCorruptState, closeProcessHandle(handle))
	}
	defer func() { result = errors.Join(result, handle.Close()) }()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := atomicSymlink(configPath, r.currentPath); err != nil {
		return err
	}
	return r.signalMaster(handle, expected, syscall.SIGHUP)
}

func (r *OpenResty) signalMaster(handle processHandle, expected processIdentity, signal syscall.Signal) error {
	if alive, err := r.verifyMasterHandle(handle, expected); err != nil || !alive {
		return errors.Join(ErrCorruptState, err)
	}
	if err := handle.Signal(signal); err != nil {
		return err
	}
	if alive, err := r.verifyMasterHandle(handle, expected); err != nil || !alive {
		return errors.Join(ErrCorruptState, err)
	}
	return nil
}

func (r *OpenResty) httpHealthy(ctx context.Context, listener Listener, check HealthCheck) (bool, error) {
	address := probeAddress(listener.Address, listener.Port)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+check.Path, nil)
	if err != nil {
		return false, err
	}
	transport := &http.Transport{DisableKeepAlives: true}
	client := &http.Client{Transport: transport}
	response, err := client.Do(request)
	if err != nil {
		return false, nil
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxProbeBytes+1))
	if err != nil {
		return false, nil
	}
	return response.StatusCode == check.ExpectedStatus && len(body) <= maxProbeBytes && strings.HasPrefix(string(body), check.ExpectedBodyPrefix), nil
}

func (r *OpenResty) tcpHealthy(ctx context.Context, listener Listener, check HealthCheck) (bool, error) {
	dialer := net.Dialer{}
	connection, err := dialer.DialContext(ctx, "tcp", probeAddress(listener.Address, listener.Port))
	if err != nil {
		return false, nil
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if _, err := io.WriteString(connection, check.Payload+"\n"); err != nil {
		return false, nil
	}
	response, err := bufio.NewReader(io.LimitReader(connection, maxProbeBytes+1)).ReadString('\n')
	if err != nil || len(response) > maxProbeBytes {
		return false, nil
	}
	return strings.HasPrefix(response, check.ExpectedBodyPrefix), nil
}

func probeAddress(address string, port int) string {
	parsed := netip.MustParseAddr(address)
	if parsed.IsUnspecified() {
		if parsed.Is6() {
			address = "::1"
		} else {
			address = "127.0.0.1"
		}
	}
	return net.JoinHostPort(address, strconv.Itoa(port))
}

func (r *OpenResty) running() (running bool, result error) {
	handle, _, running, err := r.openOwnedMaster()
	if err != nil {
		return false, err
	}
	if handle != nil {
		defer func() { result = errors.Join(result, handle.Close()) }()
	}
	return running, nil
}

func (r *OpenResty) openOwnedMaster() (processHandle, processIdentity, bool, error) {
	pid, pidExists, err := readProcessPID(r.pidPath)
	if err != nil {
		return nil, processIdentity{}, false, err
	}
	record, recordExists, err := readOptionalProcessRecord(r.pidPath + ".identity")
	if err != nil {
		return nil, processIdentity{}, false, err
	}
	start, startExists, err := readOptionalProcessStartIdentity(r.pidPath + ".identity.pending")
	if err != nil {
		return nil, processIdentity{}, false, err
	}
	if !pidExists && !recordExists && !startExists {
		return nil, processIdentity{}, false, nil
	}
	if !r.identityOK {
		return nil, record, false, errors.New("stable OpenResty process identity requires Linux procfs and pidfd")
	}
	if startExists && !recordExists {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		handle, identity, err := r.openStartedMaster(ctx)
		if handle == nil {
			return nil, processIdentity{}, false, err
		}
		if err != nil {
			return nil, processIdentity{}, false, errors.Join(err, handle.Close())
		}
		if err := r.commitStartedMaster(identity); err != nil {
			return nil, processIdentity{}, false, errors.Join(err, handle.Close())
		}
		return handle, identity, true, nil
	}
	if pidExists && !recordExists {
		return nil, processIdentity{}, false, errors.New("OpenResty PID has no recorded kernel identity")
	}
	if startExists && !start.matches(record) {
		return nil, record, false, errors.New("pending OpenResty identity does not match the recorded master")
	}
	if pidExists && pid != record.PID {
		return nil, record, false, errors.New("OpenResty PID does not match the recorded master")
	}
	handle, err := r.openProcess(record.PID)
	if errors.Is(err, errProcessNotRunning) {
		return nil, record, false, nil
	}
	if err != nil {
		return nil, record, false, err
	}
	alive, err := r.verifyMasterHandle(handle, record)
	if err != nil {
		return nil, record, false, errors.Join(err, handle.Close())
	}
	if !alive {
		return nil, record, false, handle.Close()
	}
	if startExists {
		if err := r.removePaths([]string{r.pidPath + ".identity.pending", r.startPIDPath(start.Token)}); err != nil {
			return nil, record, false, errors.Join(err, handle.Close())
		}
	}
	return handle, record, true, nil
}

func (r *OpenResty) verifyRecordedMaster(expected processIdentity) (result error) {
	handle, identity, running, err := r.openOwnedMaster()
	if err != nil {
		return err
	}
	if handle == nil || !running || identity != expected {
		return errors.Join(ErrCorruptState, closeProcessHandle(handle))
	}
	defer func() { result = errors.Join(result, handle.Close()) }()
	alive, err := r.verifyMasterHandle(handle, expected)
	if err != nil || !alive {
		return errors.Join(ErrCorruptState, err)
	}
	return nil
}

func (r *OpenResty) startMaster(ctx context.Context) error {
	if !r.identityOK {
		return errors.New("stable OpenResty process identity requires Linux procfs and pidfd")
	}
	if err := r.validateRuntimePaths(); err != nil {
		return err
	}
	start, err := newProcessStartIdentity(r.binaryFile)
	if err != nil {
		return err
	}
	if err := r.writeState(r.pidPath+".identity.pending", []byte(formatProcessStartIdentity(start))); err != nil {
		return err
	}
	arguments := []string{
		"-p", withSeparator(r.prefix), "-c", "current.conf", "-g",
		"pid " + startPIDRelativePath(start.Token) + ";",
	}
	if err := r.startProcess(ctx, start.Token, arguments...); err != nil {
		return errors.Join(err, r.cleanupUnrecordedStart())
	}
	return r.recordStartedMaster(ctx)
}

func (r *OpenResty) recordStartedMaster(ctx context.Context) (result error) {
	startupContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer cancel()
	handle, identity, err := r.openStartedMaster(startupContext)
	if handle == nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			result = errors.Join(result, r.stopStartedMaster(handle, identity))
		}
		result = errors.Join(result, handle.Close())
	}()
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := r.commitStartedMaster(identity); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	committed = true
	return nil
}

func (r *OpenResty) openStartedMaster(ctx context.Context) (processHandle, processIdentity, error) {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		start, startExists, startErr := readOptionalProcessStartIdentity(r.pidPath + ".identity.pending")
		if startErr != nil || !startExists {
			return nil, processIdentity{}, errors.Join(errors.New("pending OpenResty identity is missing"), startErr)
		}
		pid, exists, err := readProcessPID(r.startPIDPath(start.Token))
		if err != nil {
			return nil, processIdentity{}, err
		}
		if exists {
			identity, inspectErr := r.inspect(pid)
			if inspectErr == nil {
				if !start.matches(identity) {
					return nil, processIdentity{}, errors.New("pending OpenResty identity does not match the started master")
				}
				if err := r.matchStart(pid, start.Token); err != nil {
					return nil, processIdentity{}, err
				}
				handle, openErr := r.openProcess(pid)
				if openErr != nil && !errors.Is(openErr, errProcessNotRunning) {
					return nil, processIdentity{}, openErr
				}
				if openErr == nil {
					alive, verifyErr := r.verifyWorkerHandle(handle, identity)
					if verifyErr != nil || !alive {
						return nil, processIdentity{}, errors.Join(errors.New("OpenResty master identity changed during startup"), verifyErr, handle.Close())
					}
					if err := r.matchStart(pid, start.Token); err != nil {
						return nil, processIdentity{}, errors.Join(err, handle.Close())
					}
					confirmedPID, confirmedExists, pidErr := readProcessPID(r.startPIDPath(start.Token))
					if pidErr != nil || !confirmedExists || confirmedPID != pid {
						return handle, identity, errors.New("OpenResty PID changed during startup")
					}
					return handle, identity, nil
				}
			}
			if !errors.Is(inspectErr, errProcessNotRunning) {
				return nil, processIdentity{}, inspectErr
			}
		}
		select {
		case <-ctx.Done():
			return nil, processIdentity{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (r *OpenResty) commitStartedMaster(identity processIdentity) error {
	start, exists, err := readOptionalProcessStartIdentity(r.pidPath + ".identity.pending")
	if err != nil || !exists || !start.matches(identity) {
		return errors.New("pending OpenResty identity does not match the started master")
	}
	if pid, pidExists, err := readProcessPID(r.pidPath); err != nil || (pidExists && pid != identity.PID) {
		return errors.Join(errors.New("stable OpenResty PID changed during startup"), err)
	}
	if err := r.writeState(r.pidPath, []byte(strconv.Itoa(identity.PID)+"\n")); err != nil {
		return err
	}
	identityPath := r.pidPath + ".identity"
	if err := r.writeState(identityPath, []byte(formatProcessRecord(identity))); err != nil {
		return err
	}
	confirmed, inspectErr := r.inspect(identity.PID)
	pid, pidExists, pidErr := readProcessPID(r.pidPath)
	startPID, startPIDExists, startPIDErr := readProcessPID(r.startPIDPath(start.Token))
	tokenErr := r.matchStart(identity.PID, start.Token)
	if inspectErr != nil || confirmed != identity || pidErr != nil || !pidExists || pid != identity.PID ||
		startPIDErr != nil || !startPIDExists || startPID != identity.PID || tokenErr != nil {
		return errors.Join(errors.New("OpenResty master identity changed during startup"), inspectErr, pidErr, startPIDErr, tokenErr)
	}
	return r.removePaths([]string{r.pidPath + ".identity.pending", r.startPIDPath(start.Token)})
}

func (r *OpenResty) cleanupUnrecordedStart() (result error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	handle, identity, err := r.openStartedMaster(ctx)
	if handle == nil {
		return err
	}
	defer func() { result = errors.Join(result, handle.Close()) }()
	return errors.Join(err, r.stopStartedMaster(handle, identity))
}

func (r *OpenResty) stopStartedMaster(handle processHandle, identity processIdentity) error {
	if alive, err := r.verifyWorkerHandle(handle, identity); err != nil || !alive {
		return err
	}
	if err := handle.Signal(syscall.SIGQUIT); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	exited, err := waitProcessHandleExit(handle, time.Second)
	if err != nil {
		return err
	}
	if !exited {
		if alive, err := r.verifyWorkerHandle(handle, identity); err != nil || !alive {
			return err
		}
		if err := handle.Signal(syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			return err
		}
		exited, err = waitProcessHandleExit(handle, time.Second)
		if err != nil {
			return err
		}
		if !exited {
			return errors.New("started OpenResty master did not exit")
		}
	}
	return r.removeStartedMasterFilesIfMatch(identity)
}

func waitProcessHandleExit(handle processHandle, timeout time.Duration) (bool, error) {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		alive, err := handle.Alive()
		if err != nil {
			return false, err
		}
		if !alive {
			return true, nil
		}
		select {
		case <-deadline.C:
			return false, nil
		case <-ticker.C:
		}
	}
}

func (r *OpenResty) removeStartedMasterFilesIfMatch(expected processIdentity) error {
	pid, pidExists, err := readProcessPID(r.pidPath)
	if err != nil {
		return err
	}
	record, recordExists, err := readOptionalProcessRecord(r.pidPath + ".identity")
	if err != nil {
		return err
	}
	start, startExists, err := readOptionalProcessStartIdentity(r.pidPath + ".identity.pending")
	if err != nil {
		return err
	}
	if (pidExists && pid != expected.PID) || (recordExists && record != expected) || (startExists && !start.matches(expected)) {
		return nil
	}
	paths := []string{r.pidPath, r.pidPath + ".identity", r.pidPath + ".identity.pending"}
	if startExists {
		paths = append(paths, r.startPIDPath(start.Token))
	}
	return r.removePaths(paths)
}

func (r *OpenResty) removeMasterFilesIfMatch(expected processIdentity) error {
	pid, pidExists, err := readProcessPID(r.pidPath)
	if err != nil {
		return err
	}
	record, recordExists, err := readOptionalProcessRecord(r.pidPath + ".identity")
	if err != nil {
		return err
	}
	if !pidExists && !recordExists {
		return nil
	}
	if expected == (processIdentity{}) || !recordExists || record != expected || (pidExists && pid != expected.PID) {
		return nil
	}
	return r.removePaths([]string{r.pidPath, r.pidPath + ".identity"})
}

func (r *OpenResty) loadWorkers() (*workerRecord, error) {
	content, exists, err := readOwnedProcessFile(r.workersPath, maxStateFileBytes)
	if err != nil {
		return nil, errors.Join(ErrCorruptState, err)
	}
	if !exists {
		return nil, nil
	}
	var record workerRecord
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return nil, ErrCorruptState
	}
	if decoder.Decode(&struct{}{}) != io.EOF || validateWorkerRecord(&record) != nil {
		return nil, ErrCorruptState
	}
	canonical, err := json.Marshal(&record)
	if err != nil || !bytes.Equal(content, canonical) {
		return nil, ErrCorruptState
	}
	return &record, nil
}

func (r *OpenResty) saveWorkers(record *workerRecord) error {
	if err := validateWorkerRecord(record); err != nil {
		return ErrCorruptState
	}
	content, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return r.writeState(r.workersPath, content)
}

func validateWorkerRecord(record *workerRecord) error {
	if record == nil || record.SchemaVersion != workerRecordSchemaVersion || record.Revision == 0 || !validHex(record.Digest, 32) ||
		!validHex(record.Generation, 32) || !validProcessIdentity(record.Master) || len(record.Workers) == 0 || len(record.Workers) > maxTrackedWorkers {
		return ErrCorruptState
	}
	identities := make([]processIdentity, 0, len(record.Workers))
	for index, worker := range record.Workers {
		if worker.Generation != record.Generation || !validProcessIdentity(worker.Identity) ||
			(index > 0 && worker.Identity.PID <= record.Workers[index-1].Identity.PID) {
			return ErrCorruptState
		}
		identities = append(identities, worker.Identity)
	}
	if workerGeneration(record.Master, identities) != record.Generation {
		return ErrCorruptState
	}
	return nil
}

func validProcessIdentity(identity processIdentity) bool {
	return identity.PID > 1 && identity.StartTicks > 0 && identity.ExecutableInode > 0 && identity.BootID != "" && len(identity.BootID) <= 64 &&
		!strings.ContainsAny(identity.BootID, " \t\r\n\x00")
}

func validHex(value string, bytes int) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == bytes && value == strings.ToLower(value)
}

func workerGeneration(master processIdentity, workers []processIdentity) string {
	digest := sha256.New()
	writeIdentityDigest(digest, master)
	for _, worker := range workers {
		writeIdentityDigest(digest, worker)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func writeIdentityDigest(writer io.Writer, identity processIdentity) {
	_, _ = fmt.Fprintf(writer, "%d %d %d %d %d %s\n", identity.PID, identity.StartTicks, identity.ExecutableDevice,
		identity.ExecutableInode, identity.OwnerUID, identity.BootID)
}

func (r *OpenResty) captureWorkerGeneration(master processIdentity) (generation string, workers []workerIdentity, result error) {
	handle, err := r.openProcess(master.PID)
	if err != nil {
		return "", nil, err
	}
	defer func() { result = errors.Join(result, handle.Close()) }()
	return r.captureWorkerGenerationWithHandle(handle, master)
}

func (r *OpenResty) captureWorkerGenerationWithHandle(masterHandle processHandle, master processIdentity) (generation string, workers []workerIdentity, result error) {
	if alive, err := r.verifyMasterHandle(masterHandle, master); err != nil || !alive {
		return "", nil, errors.Join(ErrCorruptState, err)
	}
	before, err := r.children(master.PID)
	if err != nil {
		return "", nil, err
	}
	if len(before) == 0 {
		return "", nil, errors.New("OpenResty master has no workers")
	}
	if len(before) > maxTrackedWorkers {
		return "", nil, fmt.Errorf("%w: OpenResty worker generation exceeds %d", ErrCorruptState, maxTrackedWorkers)
	}
	sort.Ints(before)
	handles := make([]ownedProcess, 0, len(before))
	defer func() { result = errors.Join(result, closeOwnedProcesses(handles)) }()
	identities := make([]processIdentity, 0, len(before))
	for _, pid := range before {
		handle, err := r.openProcess(pid)
		if err != nil {
			return "", nil, err
		}
		identity, err := r.inspect(pid)
		if err != nil {
			return "", nil, errors.Join(err, handle.Close())
		}
		alive, err := r.verifyWorkerHandle(handle, identity)
		if err != nil || !alive || !validProcessIdentity(identity) {
			return "", nil, errors.Join(ErrCorruptState, err, handle.Close())
		}
		handles = append(handles, ownedProcess{identity: identity, handle: handle})
		identities = append(identities, identity)
	}
	after, err := r.children(master.PID)
	if err != nil || !equalIntegers(before, after) {
		return "", nil, errors.Join(errors.New("OpenResty worker generation changed during capture"), err)
	}
	if alive, err := r.verifyMasterHandle(masterHandle, master); err != nil || !alive {
		return "", nil, errors.Join(ErrCorruptState, err)
	}
	for _, worker := range handles {
		if alive, err := r.verifyWorkerHandle(worker.handle, worker.identity); err != nil || !alive {
			return "", nil, errors.Join(errors.New("OpenResty worker generation changed during capture"), err)
		}
	}
	generation = workerGeneration(master, identities)
	workers = make([]workerIdentity, 0, len(identities))
	for _, identity := range identities {
		workers = append(workers, workerIdentity{Generation: generation, Identity: identity})
	}
	return generation, workers, nil
}

func (r *OpenResty) verifyTerminationSet(masterHandle processHandle, master processIdentity, workers []ownedProcess) error {
	if alive, err := r.verifyMasterHandle(masterHandle, master); err != nil || !alive {
		return errors.Join(ErrCorruptState, err)
	}
	children, err := r.children(master.PID)
	if err != nil {
		return err
	}
	current := integerSet(children)
	for _, worker := range workers {
		alive, err := r.verifyWorkerHandle(worker.handle, worker.identity)
		if err != nil {
			return err
		}
		if alive {
			if _, exists := current[worker.identity.PID]; !exists {
				return errors.New("recorded OpenResty worker no longer belongs to its master")
			}
		}
	}
	if alive, err := r.verifyMasterHandle(masterHandle, master); err != nil || !alive {
		return errors.Join(ErrCorruptState, err)
	}
	return nil
}

func (r *OpenResty) verifyMasterHandle(handle processHandle, expected processIdentity) (bool, error) {
	if expected.OwnerUID != uint32(os.Geteuid()) {
		return false, errors.New("OpenResty master owner is invalid")
	}
	alive, err := r.verifyWorkerHandle(handle, expected)
	if err != nil || !alive {
		return alive, err
	}
	pid, pidExists, err := readProcessPID(r.pidPath)
	if err != nil || !pidExists || pid != expected.PID {
		return false, errors.Join(errors.New("OpenResty master PID changed"), err)
	}
	record, recordExists, err := readOptionalProcessRecord(r.pidPath + ".identity")
	if err != nil || !recordExists || record != expected {
		return false, errors.Join(errors.New("OpenResty master identity record changed"), err)
	}
	return true, nil
}

func (r *OpenResty) verifyWorkerHandle(handle processHandle, expected processIdentity) (bool, error) {
	alive, err := handle.Alive()
	if err != nil || !alive {
		return alive, err
	}
	identity, err := r.inspect(expected.PID)
	if errors.Is(err, errProcessExited) {
		return false, nil
	}
	if errors.Is(err, errProcessNotRunning) {
		stillAlive, aliveErr := handle.Alive()
		if aliveErr != nil {
			return false, aliveErr
		}
		if !stillAlive {
			return false, nil
		}
		return true, fmt.Errorf("%w for PID %d", errProcessIdentityUnavailable, expected.PID)
	}
	if err != nil {
		return false, err
	}
	if identity != expected {
		return false, errors.New("OpenResty PID was reused or has the wrong executable identity")
	}
	return true, nil
}

func openPIDFD(pid int) (processHandle, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("stable OpenResty process signaling requires Linux pidfd")
	}
	fd, _, errno := syscall.Syscall(linuxPIDFDOpen, uintptr(pid), 0, 0)
	if errno == syscall.ESRCH {
		return nil, errProcessNotRunning
	}
	if errno != 0 {
		return nil, errno
	}
	return &pidfdHandle{fd: int(fd)}, nil
}

func (handle *pidfdHandle) Signal(signal syscall.Signal) error {
	_, _, errno := syscall.Syscall6(linuxPIDFDSendSignal, uintptr(handle.fd), uintptr(signal), 0, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func (handle *pidfdHandle) Alive() (bool, error) {
	fds := []unix.PollFd{{Fd: int32(handle.fd), Events: unix.POLLIN}}
	ready, err := unix.Poll(fds, 0)
	if err != nil {
		return false, err
	}
	if ready > 0 && fds[0].Revents&(unix.POLLIN|unix.POLLHUP|unix.POLLERR) != 0 {
		return false, nil
	}
	return true, nil
}

func (handle *pidfdHandle) Close() error { return syscall.Close(handle.fd) }

func childPIDs(parent int) ([]int, error) {
	path := fmt.Sprintf("/proc/%d/task/%d/children", parent, parent)
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read OpenResty worker PIDs: %w", err)
	}
	fields := strings.Fields(string(content))
	children := make([]int, 0, len(fields))
	for _, field := range fields {
		pid, err := strconv.Atoi(field)
		if err != nil || pid <= 1 {
			return nil, ErrCorruptState
		}
		children = append(children, pid)
	}
	sort.Ints(children)
	return children, nil
}

func readProcessPID(path string) (int, bool, error) {
	content, exists, err := readOwnedProcessFile(path, 32)
	if err != nil || !exists {
		return 0, exists, err
	}
	value := strings.TrimSpace(string(content))
	pid, err := strconv.Atoi(value)
	if err != nil || pid <= 1 || value != strconv.Itoa(pid) || string(content) != value+"\n" {
		return 0, false, errors.New("OpenResty PID file is invalid")
	}
	return pid, true, nil
}

func readOptionalProcessRecord(path string) (processIdentity, bool, error) {
	content, exists, err := readOwnedProcessFile(path, 256)
	if err != nil || !exists {
		return processIdentity{}, exists, err
	}
	record, err := parseProcessRecord(content)
	return record, true, err
}

func readProcessRecord(path string) (processIdentity, error) {
	record, exists, err := readOptionalProcessRecord(path)
	if err != nil {
		return processIdentity{}, err
	}
	if !exists {
		return processIdentity{}, errors.New("OpenResty process identity is missing")
	}
	return record, nil
}

func readOptionalProcessStartIdentity(path string) (processStartIdentity, bool, error) {
	content, exists, err := readOwnedProcessFile(path, 128)
	if err != nil || !exists {
		return processStartIdentity{}, exists, err
	}
	record, err := parseProcessStartIdentity(content)
	return record, true, err
}

func readOwnedProcessFile(path string, limit int64) ([]byte, bool, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, false, errors.New("inspect OpenResty process file")
	}
	if err := validateProcessFileInfo(info, uint32(os.Geteuid()), limit); err != nil {
		return nil, false, err
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, pathInfo) {
		return nil, false, errors.New("OpenResty process path is unsafe")
	}
	content, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(content)) > limit {
		return nil, false, errors.New("read OpenResty process file")
	}
	return content, true, nil
}

func validateProcessFileInfo(info os.FileInfo, owner uint32, limit int64) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Size() < 1 || info.Size() > limit ||
		uint64(stat.Nlink) != 1 || stat.Uid != owner {
		return errors.New("OpenResty process file is unsafe")
	}
	return nil
}

func formatProcessRecord(identity processIdentity) string {
	return fmt.Sprintf("%d %d %d %d %d %s\n", identity.PID, identity.StartTicks, identity.ExecutableDevice,
		identity.ExecutableInode, identity.OwnerUID, identity.BootID)
}

func formatProcessStartIdentity(identity processStartIdentity) string {
	return fmt.Sprintf("pending %d %d %d %s\n", identity.ExecutableDevice, identity.ExecutableInode, identity.OwnerUID, identity.Token)
}

func parseProcessRecord(content []byte) (processIdentity, error) {
	fields := strings.Fields(string(content))
	if len(fields) != 6 || string(content) != strings.Join(fields, " ")+"\n" {
		return processIdentity{}, errors.New("OpenResty process identity is invalid")
	}
	pid, pidErr := strconv.Atoi(fields[0])
	start, startErr := strconv.ParseUint(fields[1], 10, 64)
	device, deviceErr := strconv.ParseUint(fields[2], 10, 64)
	inode, inodeErr := strconv.ParseUint(fields[3], 10, 64)
	owner, ownerErr := strconv.ParseUint(fields[4], 10, 32)
	identity := processIdentity{
		PID: pid, StartTicks: start, ExecutableDevice: device, ExecutableInode: inode,
		OwnerUID: uint32(owner), BootID: fields[5],
	}
	if pidErr != nil || startErr != nil || deviceErr != nil || inodeErr != nil || ownerErr != nil || !validProcessIdentity(identity) {
		return processIdentity{}, errors.New("OpenResty process identity is invalid")
	}
	return identity, nil
}

func parseProcessStartIdentity(content []byte) (processStartIdentity, error) {
	fields := strings.Fields(string(content))
	if len(fields) != 5 || fields[0] != "pending" || string(content) != strings.Join(fields, " ")+"\n" {
		return processStartIdentity{}, errors.New("pending OpenResty process identity is invalid")
	}
	device, deviceErr := strconv.ParseUint(fields[1], 10, 64)
	inode, inodeErr := strconv.ParseUint(fields[2], 10, 64)
	owner, ownerErr := strconv.ParseUint(fields[3], 10, 32)
	token, tokenErr := hex.DecodeString(fields[4])
	if deviceErr != nil || inodeErr != nil || ownerErr != nil || tokenErr != nil || inode == 0 || len(token) != 32 || fields[4] != strings.ToLower(fields[4]) {
		return processStartIdentity{}, errors.New("pending OpenResty process identity is invalid")
	}
	return processStartIdentity{ExecutableDevice: device, ExecutableInode: inode, OwnerUID: uint32(owner), Token: fields[4]}, nil
}

func newProcessStartIdentity(binary *os.File) (processStartIdentity, error) {
	if binary == nil {
		return processStartIdentity{}, errors.New("OpenResty binary identity is invalid")
	}
	info, err := binary.Stat()
	if err != nil || validateRuntimeBinaryInfo(info) != nil {
		return processStartIdentity{}, errors.New("OpenResty binary identity is invalid")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Ino == 0 {
		return processStartIdentity{}, errors.New("OpenResty binary identity is invalid")
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return processStartIdentity{}, errors.New("generate OpenResty start identity")
	}
	return processStartIdentity{
		ExecutableDevice: uint64(stat.Dev), ExecutableInode: uint64(stat.Ino), OwnerUID: uint32(os.Geteuid()), Token: hex.EncodeToString(token),
	}, nil
}

func kernelProcessStartMatches(pid int, token string) error {
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if errors.Is(err, os.ErrNotExist) {
		return errProcessNotRunning
	}
	if err != nil {
		return errors.New("inspect OpenResty start identity")
	}
	expected := "pid " + startPIDRelativePath(token) + ";"
	if bytes.Contains(bytes.ReplaceAll(raw, []byte{0}, []byte{' '}), []byte(expected)) {
		return nil
	}
	return errors.New("OpenResty process does not match the pending start identity")
}

func startPIDRelativePath(token string) string {
	digest := sha256.Sum256([]byte(token))
	return "logs/nginx.pid.start-" + hex.EncodeToString(digest[:])
}

func (r *OpenResty) startPIDPath(token string) string {
	return filepath.Join(descriptorPath(r.prefixDir), filepath.FromSlash(startPIDRelativePath(token)))
}

func kernelProcessIdentity(pid int) (processIdentity, error) {
	if runtime.GOOS != "linux" {
		return processIdentity{}, errors.New("stable OpenResty process identity requires Linux procfs")
	}
	processRoot := filepath.Join("/proc", strconv.Itoa(pid))
	processInfo, err := os.Stat(processRoot)
	if errors.Is(err, os.ErrNotExist) {
		return processIdentity{}, errProcessNotRunning
	}
	if err != nil {
		return processIdentity{}, errors.New("inspect OpenResty process owner")
	}
	processStat, ok := processInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return processIdentity{}, errors.New("OpenResty process owner is unavailable")
	}
	raw, err := os.ReadFile(filepath.Join(processRoot, "stat"))
	if errors.Is(err, os.ErrNotExist) {
		return processIdentity{}, errProcessNotRunning
	}
	separator := bytes.LastIndex(raw, []byte(") "))
	if err != nil || separator < 0 {
		return processIdentity{}, errors.New("read OpenResty kernel process identity")
	}
	fields := strings.Fields(string(raw[separator+2:]))
	if len(fields) <= 19 {
		return processIdentity{}, errors.New("read OpenResty kernel process identity")
	}
	if fields[0] == "Z" || fields[0] == "X" || fields[0] == "x" {
		return processIdentity{}, errProcessExited
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || start == 0 {
		return processIdentity{}, errors.New("OpenResty kernel start identity is invalid")
	}
	executableInfo, err := os.Stat(filepath.Join(processRoot, "exe"))
	if errors.Is(err, os.ErrNotExist) {
		return processIdentity{}, errProcessNotRunning
	}
	if err != nil || !executableInfo.Mode().IsRegular() {
		return processIdentity{}, errors.New("OpenResty process executable is invalid")
	}
	executableStat, executableOK := executableInfo.Sys().(*syscall.Stat_t)
	if !executableOK || executableStat.Ino == 0 {
		return processIdentity{}, errors.New("OpenResty process executable is invalid")
	}
	bootID, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	boot := strings.TrimSpace(string(bootID))
	if err != nil || boot == "" || len(boot) > 64 || strings.ContainsAny(boot, " \t\r\n\x00") {
		return processIdentity{}, errors.New("OpenResty kernel boot identity is invalid")
	}
	return processIdentity{
		PID: pid, StartTicks: start, ExecutableDevice: uint64(executableStat.Dev), ExecutableInode: uint64(executableStat.Ino),
		OwnerUID: processStat.Uid, BootID: boot,
	}, nil
}

func (r *OpenResty) removePaths(paths []string) error {
	changed := false
	var result error
	for _, path := range paths {
		err := r.removeState(path)
		if err == nil {
			changed = true
			continue
		}
		if !errors.Is(err, os.ErrNotExist) {
			result = errors.Join(result, err)
		}
	}
	if changed {
		result = errors.Join(result, r.syncState(filepath.Dir(paths[0])))
	}
	return result
}

func closeProcessHandle(handle processHandle) error {
	if handle == nil {
		return nil
	}
	return handle.Close()
}

func closeOwnedProcesses(processes []ownedProcess) error {
	var result error
	for _, process := range processes {
		result = errors.Join(result, process.handle.Close())
	}
	return result
}

func integerSet(values []int) map[int]struct{} {
	result := make(map[int]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func equalIntegers(left, right []int) bool {
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

func atomicSymlink(target, destination string) error {
	if !safeAbsolutePath(target) || !safeAbsolutePath(destination) {
		return ErrInvalidPath
	}
	temporary := destination + ".new"
	if err := os.Remove(temporary); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale OpenResty pointer: %w", err)
	}
	if err := os.Symlink(target, temporary); err != nil {
		return fmt.Errorf("create OpenResty config pointer: %w", err)
	}
	if err := os.Rename(temporary, destination); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("activate OpenResty config pointer: %w", err)
	}
	return syncDirectory(filepath.Dir(destination))
}

func (r *OpenResty) run(parent context.Context, arguments ...string) error {
	ctx, cancel := context.WithTimeout(parent, r.commandLimit)
	defer cancel()
	command, err := r.command(ctx, arguments...)
	if err != nil {
		return err
	}
	output, err := command.CombinedOutput()
	if err == nil {
		return nil
	}
	message := strings.TrimSpace(string(output))
	if len(message) > 4096 {
		message = message[:4096]
	}
	if message == "" {
		return err
	}
	return fmt.Errorf("OpenResty command failed: %s: %w", message, err)
}

func (r *OpenResty) runStartCommand(parent context.Context, _ string, arguments ...string) error {
	ctx, cancel := context.WithTimeout(parent, r.commandLimit)
	defer cancel()
	command, err := r.command(ctx, arguments...)
	if err != nil {
		return err
	}
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open null device: %w", err)
	}
	defer null.Close()
	prefix := processStartEnvironment + "="
	command.Env = make([]string, 0, len(os.Environ())+1)
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, prefix) {
			command.Env = append(command.Env, value)
		}
	}
	command.Stdout = null
	command.Stderr = null
	if err := command.Run(); err != nil {
		return fmt.Errorf("OpenResty start failed: %w", err)
	}
	return nil
}

func (r *OpenResty) command(ctx context.Context, arguments ...string) (*exec.Cmd, error) {
	if err := r.validateRuntimePaths(); err != nil {
		return nil, err
	}
	path := r.binary
	prefixFD := 3
	extraFiles := []*os.File{r.prefixDir}
	if runtime.GOOS == "linux" {
		path = "/proc/self/fd/3"
		prefixFD = 4
		extraFiles = []*os.File{r.binaryFile, r.prefixDir}
	}
	childArguments := append([]string(nil), arguments...)
	for index := 1; index < len(childArguments); index++ {
		if childArguments[index-1] == "-p" && childArguments[index] == withSeparator(r.prefix) {
			childArguments[index] = withSeparator(descriptorNumberPath(prefixFD))
		}
	}
	command := exec.CommandContext(ctx, path, childArguments...)
	command.ExtraFiles = extraFiles
	return command, nil
}

func withSeparator(path string) string { return path + string(filepath.Separator) }

var _ Runtime = (*OpenResty)(nil)
