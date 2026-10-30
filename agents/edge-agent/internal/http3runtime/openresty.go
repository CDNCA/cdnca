package http3runtime

import (
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
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type HealthProbe interface {
	TCP(context.Context, Policy) error
	HTTP3(context.Context, Policy) error
}

type OpenResty struct {
	mu                         sync.Mutex
	binary, pidFile, stateRoot string
	timeout                    time.Duration
	probe                      HealthProbe
	start                      func(context.Context, []string, ...string) error
	inspect                    func(int) (processIdentity, error)
	matchStart                 func(int, string) error
	openProcess                func(int) (processHandle, error)
	workers                    func(processIdentity) ([]processIdentity, error)
	writeIdentity              func(string, []byte) error
	removeProcessFile          func(string) error
	syncProcessDirectory       func(string) error
	identityOK                 bool
	generation                 workerGeneration
	closed                     bool
}

type processHandle interface {
	Signal(syscall.Signal) error
	Alive() (bool, error)
	Close() error
}

type pidfdHandle struct{ fd int }

type processIdentity struct {
	PID              int
	StartTicks       uint64
	ExecutableDevice uint64
	ExecutableInode  uint64
	OwnerUID         uint32
	BootID           string
}

type processStartIdentity struct {
	ExecutableDevice uint64
	ExecutableInode  uint64
	OwnerUID         uint32
	Token            string
}

type workerGeneration struct {
	Master  processIdentity
	Workers []processIdentity
}

func (start processStartIdentity) matches(identity processIdentity) bool {
	return start.ExecutableDevice == identity.ExecutableDevice && start.ExecutableInode == identity.ExecutableInode &&
		start.OwnerUID == identity.OwnerUID
}

var (
	errProcessNotRunning = errors.New("process is not running")
	errOpenRestyClosed   = errors.New("OpenResty runtime is closed")
)

const processStartEnvironment = "CDNCA_HTTP3_OPENRESTY_START_TOKEN"

const (
	linuxPIDFDOpen       = uintptr(434)
	linuxPIDFDSendSignal = uintptr(424)
)

func NewOpenResty(binary, pidFile string, timeout time.Duration, probe HealthProbe) (*OpenResty, error) {
	if !safeAbsolutePath(binary) || !safeDirectivePath(pidFile) || timeout <= 0 || timeout > time.Minute || probe == nil {
		return nil, ErrInvalidPath
	}
	stateRoot := filepath.Dir(filepath.Dir(pidFile))
	if !safeAbsolutePath(stateRoot) || filepath.Base(filepath.Dir(pidFile)) != "run" {
		return nil, ErrInvalidPath
	}
	openresty := &OpenResty{
		binary: binary, pidFile: pidFile, stateRoot: stateRoot, timeout: timeout, probe: probe,
		inspect: kernelProcessIdentity, matchStart: kernelProcessStartMatches, openProcess: openPIDFD, workers: kernelOpenRestyWorkers,
		writeIdentity:     func(path string, content []byte) error { return writeAtomic(filepath.Dir(path), path, content) },
		removeProcessFile: os.Remove, syncProcessDirectory: syncDirectory, identityOK: runtime.GOOS == "linux",
	}
	openresty.start = openresty.runStart
	return openresty, nil
}

func (r *OpenResty) Precheck(ctx context.Context, candidatePath string) (result error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errOpenRestyClosed
	}
	if !safeAbsolutePath(candidatePath) {
		return ErrInvalidPath
	}
	policy, err := loadPolicy(candidatePath)
	if err != nil {
		return err
	}
	if err := r.checkCapabilities(ctx, policy.Runtime); err != nil {
		return err
	}
	if err := verifyAsset(filepath.Join(candidatePath, releaseTLSDirectory, releaseCertificateFile), policy.TLS.CertificateSHA256); err != nil {
		return err
	}
	if err := verifyAsset(filepath.Join(candidatePath, releaseTLSDirectory, releasePrivateKeyFile), policy.TLS.PrivateKeySHA256); err != nil {
		return err
	}
	handle, _, running, err := r.openOwnedProcess()
	if err != nil {
		return err
	}
	if handle != nil {
		defer func() { result = errors.Join(result, handle.Close()) }()
	}
	currentOwns := false
	currentOwnsUDP := false
	if running {
		if current, currentErr := loadPolicy(filepath.Join(r.stateRoot, "current")); currentErr == nil {
			currentOwns = current.Listener.Address == policy.Listener.Address && current.Listener.Port == policy.Listener.Port
			currentOwnsUDP = currentOwns && current.HTTP3Enabled()
		}
	}
	if !currentOwns {
		if err := checkBindings(ctx, policy.Listener, policy.HTTP3Enabled()); err != nil {
			return err
		}
	} else if policy.HTTP3Enabled() && !currentOwnsUDP {
		if err := checkUDPBinding(ctx, policy.Listener); err != nil {
			return err
		}
	}
	precheckPID := filepath.Join(candidatePath, ".nginx-precheck.pid")
	defer os.Remove(precheckPID)
	return r.run(ctx, "-e", "stderr", "-t", "-q", "-p", withSeparator(candidatePath), "-c", "nginx.conf", "-g", "pid "+precheckPID+";")
}

func (r *OpenResty) Activate(ctx context.Context, currentPath string) (result error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errOpenRestyClosed
	}
	if !safeAbsolutePath(currentPath) {
		return ErrInvalidPath
	}
	handle, record, running, err := r.openOwnedProcess()
	if err != nil {
		return err
	}
	if handle != nil {
		defer func() { result = errors.Join(result, handle.Close()) }()
	}
	if running {
		oldWorkers, err := r.snapshotWorkers(record)
		if err != nil {
			return err
		}
		if len(oldWorkers) == 0 {
			return errors.New("OpenResty running master has no ready worker generation")
		}
		if err := r.signalOwnedProcess(handle, record, syscall.SIGHUP); err != nil {
			return err
		}
		generation, err := r.waitForWorkerGeneration(ctx, record, oldWorkers)
		if err != nil {
			return err
		}
		r.generation = generation
		return nil
	}
	if !r.identityOK {
		return errors.New("stable OpenResty process identity requires Linux pidfd and procfs")
	}
	if err := removeProcessFilesIfMatch(r.pidFile, record, r.removeProcessFile, r.syncProcessDirectory); err != nil {
		return err
	}
	startIdentity, err := newProcessStartIdentity(r.binary)
	if err != nil {
		return err
	}
	if err := r.writeIdentity(r.pidFile+".identity.pending", []byte(formatProcessStartIdentity(startIdentity))); err != nil {
		return err
	}
	global := "env " + processStartEnvironment + "=" + startIdentity.Token + "; pid " + r.pidFile + ";"
	arguments := []string{"-e", "stderr", "-p", withSeparator(currentPath), "-c", "nginx.conf", "-g", global}
	environment := []string{processStartEnvironment + "=" + startIdentity.Token}
	if err := r.start(ctx, environment, arguments...); err != nil {
		return errors.Join(err, r.cleanupUnrecordedStart())
	}
	if err := r.recordStartedProcess(ctx); err != nil {
		return err
	}
	if err := r.waitRunning(ctx); err != nil {
		return err
	}
	master, err := readProcessRecord(r.pidFile + ".identity")
	if err != nil {
		return err
	}
	generation, err := r.waitForWorkerGeneration(ctx, master, nil)
	if err != nil {
		return err
	}
	r.generation = generation
	return nil
}

func (r *OpenResty) runStart(parent context.Context, environment []string, arguments ...string) (result error) {
	ctx, cancel := context.WithTimeout(parent, r.timeout)
	defer cancel()
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, null.Close()) }()
	command := exec.CommandContext(ctx, r.binary, arguments...)
	prefix := processStartEnvironment + "="
	command.Env = make([]string, 0, len(os.Environ())+len(environment))
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, prefix) {
			command.Env = append(command.Env, value)
		}
	}
	command.Env = append(command.Env, environment...)
	command.Stdout = null
	command.Stderr = null
	return command.Run()
}

func (r *OpenResty) Healthy(ctx context.Context, currentPath string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errOpenRestyClosed
	}
	if !safeAbsolutePath(currentPath) {
		return ErrInvalidPath
	}
	policy, err := loadPolicy(currentPath)
	if err != nil {
		return err
	}
	if err := r.verifyCandidateGeneration(); err != nil {
		return err
	}
	if err := r.probe.TCP(ctx, policy); err != nil {
		return fmt.Errorf("TCP health: %w", err)
	}
	if policy.HTTP3Enabled() {
		if err := r.verifyCandidateGeneration(); err != nil {
			return err
		}
		if err := r.probe.HTTP3(ctx, policy); err != nil {
			return fmt.Errorf("HTTP/3 health: %w", err)
		}
	}
	return r.verifyCandidateGeneration()
}

func (r *OpenResty) Stop(ctx context.Context, currentPath string) (result error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errOpenRestyClosed
	}
	if !safeAbsolutePath(currentPath) {
		return ErrInvalidPath
	}
	handle, record, running, err := r.openOwnedProcess()
	if err != nil {
		return err
	}
	if handle != nil {
		defer func() { result = errors.Join(result, handle.Close()) }()
	}
	if !running {
		err := removeProcessFilesIfMatch(r.pidFile, record, r.removeProcessFile, r.syncProcessDirectory)
		if err == nil {
			r.generation = workerGeneration{}
		}
		return err
	}
	if err := r.signalOwnedProcess(handle, record, syscall.SIGQUIT); err != nil {
		return err
	}
	deadline := time.NewTimer(r.timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		alive, err := handle.Alive()
		if err != nil {
			return err
		}
		if !alive {
			err := removeProcessFilesIfMatch(r.pidFile, record, r.removeProcessFile, r.syncProcessDirectory)
			if err == nil {
				r.generation = workerGeneration{}
			}
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("OpenResty stop timed out")
		case <-ticker.C:
		}
	}
}

func (r *OpenResty) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	record, recordExists, err := readOptionalProcessRecord(r.pidFile + ".identity")
	if err != nil {
		return err
	}
	startRecord, startExists, err := readOptionalProcessStartIdentity(r.pidFile + ".identity.pending")
	if err != nil || !startExists {
		return err
	}
	if recordExists {
		if !startRecord.matches(record) {
			return errors.New("pending OpenResty identity does not match its recorded kernel identity")
		}
		return removeProcessPaths([]string{r.pidFile + ".identity.pending"}, r.removeProcessFile, r.syncProcessDirectory)
	}
	return r.cleanupUnrecordedStart()
}

func (r *OpenResty) checkCapabilities(ctx context.Context, runtime RuntimeRef) error {
	output, err := r.command(ctx, "-V")
	if err != nil {
		return fmt.Errorf("%w: version probe failed", ErrUnsupported)
	}
	if !supportsRuntime(string(output), runtime) {
		return ErrUnsupported
	}
	return nil
}

func supportsRuntime(output string, runtime RuntimeRef) bool {
	return runtime.Family == RuntimeFamilyOpenResty && runtime.Version == RuntimeVersionOpenResty &&
		binaryVersion(output) == "openresty/"+RuntimeVersionOpenResty &&
		strings.Contains(output, "--with-http_v3_module") && strings.Contains(output, "--with-http_v2_module") &&
		strings.Contains(output, "--with-http_ssl_module")
}

// binaryVersion returns the whole version token of the first
// "nginx version: <token>" line of `nginx -V`, so that a pinned version never
// matches as a prefix of another one.
func binaryVersion(output string) string {
	for _, line := range strings.Split(output, "\n") {
		if rest, found := strings.CutPrefix(line, "nginx version: "); found {
			if fields := strings.Fields(rest); len(fields) > 0 {
				return fields[0]
			}
			return ""
		}
	}
	return ""
}

func verifyAsset(path, expectedDigest string) error {
	content, err := readRegularFile(path, maxCertificateBytes)
	if err != nil {
		return fmt.Errorf("certificate asset: %w", err)
	}
	digest := sha256.Sum256(content)
	if hex.EncodeToString(digest[:]) != expectedDigest {
		return errors.New("certificate asset digest mismatch")
	}
	return nil
}

func checkBindings(ctx context.Context, listener Listener, http3Enabled bool) error {
	listenConfig := net.ListenConfig{}
	address := nginxAddress(listener.Address, listener.Port)
	tcp, err := listenConfig.Listen(ctx, "tcp", address)
	if err != nil {
		return fmt.Errorf("%w: TCP %s", ErrPortConflict, address)
	}
	defer tcp.Close()
	if !http3Enabled {
		return nil
	}
	return checkUDPBinding(ctx, listener)
}

func checkUDPBinding(ctx context.Context, listener Listener) error {
	listenConfig := net.ListenConfig{}
	address := nginxAddress(listener.Address, listener.Port)
	udp, err := listenConfig.ListenPacket(ctx, "udp", address)
	if err != nil {
		return fmt.Errorf("%w: UDP %s", ErrPortConflict, address)
	}
	return udp.Close()
}

func loadPolicy(directory string) (Policy, error) {
	content, err := readRegularFile(filepath.Join(directory, "policy.json"), maxPolicyBytes)
	if err != nil {
		return Policy{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var policy Policy
	if err := decoder.Decode(&policy); err != nil {
		return Policy{}, ErrCorruptState
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Policy{}, ErrCorruptState
	}
	compiled, err := Compile(policy)
	if err != nil || !bytes.Equal(content, compiled.CanonicalJSON) {
		return Policy{}, ErrCorruptState
	}
	return compiled.Policy, nil
}

func (r *OpenResty) run(ctx context.Context, arguments ...string) error {
	output, err := r.command(ctx, arguments...)
	if err == nil {
		return nil
	}
	message := strings.TrimSpace(string(output))
	if len(message) > 4_096 {
		message = message[:4_096]
	}
	return fmt.Errorf("OpenResty command failed: %s: %w", message, err)
}

func (r *OpenResty) command(parent context.Context, arguments ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, r.timeout)
	defer cancel()
	return exec.CommandContext(ctx, r.binary, arguments...).CombinedOutput()
}

func (r *OpenResty) waitRunning(ctx context.Context) error {
	deadline := time.NewTimer(r.timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		running, err := processRunning(r.pidFile, r.inspect)
		if err != nil {
			return err
		}
		if running {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("OpenResty did not become ready")
		case <-ticker.C:
		}
	}
}

func (r *OpenResty) waitForWorkerGeneration(ctx context.Context, master processIdentity, oldWorkers []processIdentity) (workerGeneration, error) {
	old := make(map[processIdentity]struct{}, len(oldWorkers))
	for _, worker := range oldWorkers {
		old[worker] = struct{}{}
	}
	deadline := time.NewTimer(r.timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	var stable []processIdentity
	stableObservations := 0
	sawNew := false
	sawOldAfterNew := false
	for {
		workers, err := r.snapshotWorkers(master)
		if err != nil {
			return workerGeneration{}, err
		}
		newWorkers := make([]processIdentity, 0, len(workers))
		oldRemaining := false
		for _, worker := range workers {
			if _, exists := old[worker]; exists {
				oldRemaining = true
				continue
			}
			newWorkers = append(newWorkers, worker)
		}
		if len(newWorkers) > 0 {
			sawNew = true
			sawOldAfterNew = sawOldAfterNew || oldRemaining
		}
		if len(workers) == 1 && len(newWorkers) == 1 && !oldRemaining {
			if sameWorkerSet(stable, newWorkers) {
				stableObservations++
			} else {
				stable = append(stable[:0], newWorkers...)
				stableObservations = 1
			}
			if stableObservations >= 2 {
				return workerGeneration{Master: master, Workers: append([]processIdentity(nil), newWorkers...)}, nil
			}
		} else {
			stable = stable[:0]
			stableObservations = 0
		}

		select {
		case <-ctx.Done():
			return workerGeneration{}, ctx.Err()
		case <-deadline.C:
			switch {
			case !sawNew:
				return workerGeneration{}, errors.New("OpenResty new worker generation did not become ready")
			case sawOldAfterNew:
				return workerGeneration{}, errors.New("OpenResty old worker generation drain timed out")
			default:
				return workerGeneration{}, errors.New("OpenResty worker generation did not stabilize")
			}
		case <-ticker.C:
		}
	}
}

func (r *OpenResty) snapshotWorkers(master processIdentity) ([]processIdentity, error) {
	current, err := r.inspect(master.PID)
	if err != nil || current != master {
		return nil, errors.Join(errors.New("OpenResty master identity changed while observing workers"), err)
	}
	workers, err := r.workers(master)
	if err != nil {
		return nil, err
	}
	if len(workers) > 16 {
		return nil, errors.New("OpenResty worker generation is oversized")
	}
	workers = append([]processIdentity(nil), workers...)
	sort.Slice(workers, func(i, j int) bool { return workers[i].PID < workers[j].PID })
	if len(workers) == 0 {
		return workers, nil
	}
	workerUID := workers[0].OwnerUID
	for index, worker := range workers {
		if worker.PID <= 1 || worker.PID == master.PID || worker.StartTicks == 0 || worker.ExecutableInode == 0 || worker.BootID == "" ||
			worker.ExecutableDevice != master.ExecutableDevice || worker.ExecutableInode != master.ExecutableInode || worker.BootID != master.BootID ||
			(master.OwnerUID != 0 && worker.OwnerUID != master.OwnerUID) || worker.OwnerUID != workerUID ||
			(index > 0 && workers[index-1].PID == worker.PID) {
			return nil, errors.New("OpenResty worker identity is not owned by the master")
		}
	}
	return workers, nil
}

func (r *OpenResty) verifyCandidateGeneration() error {
	if r.generation.Master == (processIdentity{}) || len(r.generation.Workers) != 1 {
		return errors.New("OpenResty candidate worker generation is not ready")
	}
	workers, err := r.snapshotWorkers(r.generation.Master)
	if err != nil {
		return err
	}
	if !sameWorkerSet(workers, r.generation.Workers) {
		return errors.New("OpenResty candidate worker generation changed")
	}
	return nil
}

func sameWorkerSet(first, second []processIdentity) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}

func processRunning(pidFile string, inspect func(int) (processIdentity, error)) (bool, error) {
	pid, pidExists, err := readProcessPID(pidFile)
	if err != nil {
		return false, err
	}
	record, recordExists, err := readOptionalProcessRecord(pidFile + ".identity")
	if err != nil {
		return false, err
	}
	if !pidExists && !recordExists {
		return false, nil
	}
	if pidExists && !recordExists {
		return false, errors.New("OpenResty PID has no recorded kernel identity")
	}
	if pidExists && pid != record.PID {
		return false, errors.New("OpenResty PID does not match its recorded kernel identity")
	}
	identity, err := inspect(record.PID)
	if errors.Is(err, errProcessNotRunning) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !pidExists {
		return false, errors.New("recorded OpenResty process has no PID file")
	}
	if identity != record {
		return false, errors.New("OpenResty PID was reused or has the wrong executable identity")
	}
	return true, nil
}

func (r *OpenResty) openOwnedProcess() (processHandle, processIdentity, bool, error) {
	pid, pidExists, err := readProcessPID(r.pidFile)
	if err != nil {
		return nil, processIdentity{}, false, err
	}
	record, recordExists, err := readOptionalProcessRecord(r.pidFile + ".identity")
	if err != nil {
		return nil, processIdentity{}, false, err
	}
	startRecord, startRecordExists, err := readOptionalProcessStartIdentity(r.pidFile + ".identity.pending")
	if err != nil {
		return nil, processIdentity{}, false, err
	}
	if !pidExists && !recordExists && !startRecordExists {
		return nil, processIdentity{}, false, nil
	}
	if startRecordExists && !recordExists {
		startupContext, cancel := context.WithTimeout(context.Background(), r.timeout)
		defer cancel()
		handle, identity, startErr := r.openStartedProcess(startupContext)
		if handle == nil {
			return nil, processIdentity{}, false, startErr
		}
		if startErr != nil {
			return nil, processIdentity{}, false, errors.Join(startErr, handle.Close())
		}
		if err := r.commitStartedProcess(identity); err != nil {
			return nil, processIdentity{}, false, errors.Join(err, handle.Close())
		}
		return handle, identity, true, nil
	}
	if pidExists && !recordExists {
		return nil, processIdentity{}, false, errors.New("OpenResty PID has no recorded kernel identity")
	}
	if startRecordExists && !startRecord.matches(record) {
		return nil, record, false, errors.New("pending OpenResty identity does not match its recorded kernel identity")
	}
	if pidExists && pid != record.PID {
		return nil, record, false, errors.New("OpenResty PID does not match its recorded kernel identity")
	}
	if !r.identityOK {
		return nil, record, false, errors.New("stable OpenResty process identity requires Linux pidfd")
	}
	handle, err := r.openProcess(record.PID)
	if errors.Is(err, errProcessNotRunning) {
		return nil, record, false, nil
	}
	if err != nil {
		return nil, record, false, err
	}
	identity, err := r.inspect(record.PID)
	if err != nil {
		closeErr := handle.Close()
		if errors.Is(err, errProcessNotRunning) {
			return nil, record, false, closeErr
		}
		return nil, record, false, errors.Join(err, closeErr)
	}
	if !pidExists || identity != record {
		return nil, record, false, errors.Join(errors.New("OpenResty PID was reused or has the wrong executable identity"), handle.Close())
	}
	if startRecordExists {
		if err := removeProcessPaths([]string{r.pidFile + ".identity.pending"}, r.removeProcessFile, r.syncProcessDirectory); err != nil {
			return nil, record, false, errors.Join(err, handle.Close())
		}
	}
	return handle, record, true, nil
}

func (r *OpenResty) signalOwnedProcess(handle processHandle, expected processIdentity, signal syscall.Signal) error {
	identity, err := r.inspect(expected.PID)
	if err != nil {
		return err
	}
	pid, pidExists, err := readProcessPID(r.pidFile)
	if err != nil {
		return err
	}
	record, recordExists, err := readOptionalProcessRecord(r.pidFile + ".identity")
	if err != nil {
		return err
	}
	if !pidExists || !recordExists || pid != expected.PID || record != expected || identity != expected {
		return errors.New("OpenResty process identity changed before signal")
	}
	return handle.Signal(signal)
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
	err := handle.Signal(0)
	if errors.Is(err, syscall.ESRCH) {
		return false, nil
	}
	return err == nil, err
}

func (handle *pidfdHandle) Close() error { return syscall.Close(handle.fd) }

func (r *OpenResty) recordStartedProcess(ctx context.Context) (result error) {
	startupContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), r.timeout)
	defer cancel()
	handle, identity, err := r.openStartedProcess(startupContext)
	if handle == nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			result = errors.Join(result, r.stopStartedProcess(handle, identity))
		}
		result = errors.Join(result, handle.Close())
	}()
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := r.commitStartedProcess(identity); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	committed = true
	return nil
}

func (r *OpenResty) commitStartedProcess(identity processIdentity) error {
	startRecord, exists, err := readOptionalProcessStartIdentity(r.pidFile + ".identity.pending")
	if err != nil || !exists || !startRecord.matches(identity) {
		return errors.New("pending OpenResty identity does not match the started process")
	}
	identityPath := r.pidFile + ".identity"
	if err := r.writeIdentity(identityPath, []byte(formatProcessRecord(identity))); err != nil {
		return err
	}
	confirmed, err := r.inspect(identity.PID)
	pid, pidExists, pidErr := readProcessPID(r.pidFile)
	if err != nil || confirmed != identity || pidErr != nil || !pidExists || pid != identity.PID {
		cleanupErr := removeProcessPaths([]string{identityPath}, r.removeProcessFile, r.syncProcessDirectory)
		return errors.Join(errors.New("OpenResty process identity changed during startup"), err, pidErr, cleanupErr)
	}
	return removeProcessPaths([]string{r.pidFile + ".identity.pending"}, r.removeProcessFile, r.syncProcessDirectory)
}

func (r *OpenResty) openStartedProcess(ctx context.Context) (processHandle, processIdentity, error) {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		pid, exists, err := readProcessPID(r.pidFile)
		if err != nil {
			return nil, processIdentity{}, err
		}
		if exists {
			identity, inspectErr := r.inspect(pid)
			if inspectErr == nil {
				startRecord, startExists, startErr := readOptionalProcessStartIdentity(r.pidFile + ".identity.pending")
				if startErr != nil || !startExists || !startRecord.matches(identity) {
					return nil, processIdentity{}, errors.New("pending OpenResty identity does not match the started process")
				}
				if err := r.matchStart(pid, startRecord.Token); err != nil {
					return nil, processIdentity{}, err
				}
				handle, openErr := r.openProcess(pid)
				if openErr != nil && !errors.Is(openErr, errProcessNotRunning) {
					return nil, processIdentity{}, openErr
				}
				if openErr == nil {
					confirmed, confirmErr := r.inspect(pid)
					if confirmErr != nil || confirmed != identity {
						return nil, processIdentity{}, errors.Join(errors.New("OpenResty process identity changed during startup"), confirmErr, handle.Close())
					}
					if err := r.matchStart(pid, startRecord.Token); err != nil {
						return nil, processIdentity{}, errors.Join(err, handle.Close())
					}
					confirmedPID, confirmedExists, pidErr := readProcessPID(r.pidFile)
					if pidErr != nil || !confirmedExists || confirmedPID != pid {
						return handle, identity, errors.Join(errors.New("OpenResty PID changed during startup"), pidErr)
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

func (r *OpenResty) cleanupUnrecordedStart() (result error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()
	handle, identity, err := r.openStartedProcess(ctx)
	if handle == nil {
		return err
	}
	defer func() { result = errors.Join(result, handle.Close()) }()
	return errors.Join(err, r.stopStartedProcess(handle, identity))
}

func (r *OpenResty) stopStartedProcess(handle processHandle, identity processIdentity) error {
	if err := handle.Signal(syscall.SIGQUIT); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	exited, err := waitProcessHandleExit(handle, r.timeout)
	if err != nil {
		return err
	}
	if !exited {
		if err := handle.Signal(syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			return err
		}
		exited, err = waitProcessHandleExit(handle, r.timeout)
		if err != nil {
			return err
		}
		if !exited {
			return errors.New("started OpenResty process did not exit")
		}
	}
	return removeStartedProcessFilesIfMatch(r.pidFile, identity, r.removeProcessFile, r.syncProcessDirectory)
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

func removeStartedProcessFilesIfMatch(pidFile string, expected processIdentity, removePath, syncParent func(string) error) error {
	pid, pidExists, err := readProcessPID(pidFile)
	if err != nil {
		return err
	}
	record, recordExists, err := readOptionalProcessRecord(pidFile + ".identity")
	if err != nil {
		return err
	}
	startRecord, startRecordExists, err := readOptionalProcessStartIdentity(pidFile + ".identity.pending")
	if err != nil {
		return err
	}
	if (pidExists && pid != expected.PID) || (recordExists && record != expected) || (startRecordExists && !startRecord.matches(expected)) {
		return nil
	}
	return removeProcessPaths([]string{pidFile, pidFile + ".identity", pidFile + ".identity.pending"}, removePath, syncParent)
}

func removeProcessFilesIfMatch(pidFile string, expected processIdentity, removePath, syncParent func(string) error) error {
	pid, pidExists, err := readProcessPID(pidFile)
	if err != nil {
		return err
	}
	record, recordExists, err := readOptionalProcessRecord(pidFile + ".identity")
	if err != nil {
		return err
	}
	if !pidExists && !recordExists {
		return nil
	}
	if expected == (processIdentity{}) || !recordExists || record != expected || (pidExists && pid != expected.PID) {
		return nil
	}
	return removeProcessPaths([]string{pidFile, pidFile + ".identity"}, removePath, syncParent)
}

func removeProcessPaths(paths []string, removePath, syncParent func(string) error) error {
	changed := false
	var removeErr error
	for _, path := range paths {
		err := removePath(path)
		if err == nil {
			changed = true
			continue
		}
		if !errors.Is(err, os.ErrNotExist) {
			removeErr = err
			break
		}
	}
	if !changed {
		return removeErr
	}
	return errors.Join(removeErr, syncParent(filepath.Dir(paths[0])))
}

func readProcessPID(path string) (int, bool, error) {
	content, exists, err := readOwnedProcessFile(path, 32)
	if err != nil || !exists {
		return 0, exists, err
	}
	value := strings.TrimSpace(string(content))
	pid, err := strconv.Atoi(value)
	if err != nil || pid <= 1 || value != strconv.Itoa(pid) {
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
	if pidErr != nil || startErr != nil || deviceErr != nil || inodeErr != nil || ownerErr != nil || pid <= 1 || start == 0 || inode == 0 ||
		fields[5] == "" || len(fields[5]) > 64 || hasControl(fields[5]) {
		return processIdentity{}, errors.New("OpenResty process identity is invalid")
	}
	return processIdentity{
		PID: pid, StartTicks: start, ExecutableDevice: device, ExecutableInode: inode,
		OwnerUID: uint32(owner), BootID: fields[5],
	}, nil
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
	if deviceErr != nil || inodeErr != nil || ownerErr != nil || tokenErr != nil || inode == 0 || len(token) != 32 {
		return processStartIdentity{}, errors.New("pending OpenResty process identity is invalid")
	}
	return processStartIdentity{ExecutableDevice: device, ExecutableInode: inode, OwnerUID: uint32(owner), Token: fields[4]}, nil
}

func newProcessStartIdentity(binary string) (processStartIdentity, error) {
	info, err := os.Stat(binary)
	if err != nil || !info.Mode().IsRegular() {
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
	expected := "env " + processStartEnvironment + "=" + token + ";"
	if bytes.Contains(raw, []byte(expected)) {
		return nil
	}
	return errors.New("OpenResty process does not match the pending start identity")
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
	if !ok || processStat.Uid != uint32(os.Geteuid()) {
		return processIdentity{}, errors.New("OpenResty process owner is invalid")
	}
	raw, err := os.ReadFile(filepath.Join(processRoot, "stat"))
	if errors.Is(err, os.ErrNotExist) {
		return processIdentity{}, errProcessNotRunning
	}
	if err != nil {
		return processIdentity{}, errors.New("read OpenResty kernel process identity")
	}
	separator := bytes.LastIndex(raw, []byte(") "))
	if separator < 0 {
		return processIdentity{}, errors.New("read OpenResty kernel process identity")
	}
	fields := strings.Fields(string(raw[separator+2:]))
	if len(fields) <= 19 || fields[0] == "Z" {
		return processIdentity{}, errProcessNotRunning
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
	executableStat, ok := executableInfo.Sys().(*syscall.Stat_t)
	if !ok || executableStat.Ino == 0 {
		return processIdentity{}, errors.New("OpenResty process executable is invalid")
	}
	bootID, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	boot := strings.TrimSpace(string(bootID))
	if err != nil || boot == "" || len(boot) > 64 || hasControl(boot) {
		return processIdentity{}, errors.New("OpenResty kernel boot identity is invalid")
	}
	return processIdentity{
		PID: pid, StartTicks: start, ExecutableDevice: uint64(executableStat.Dev), ExecutableInode: uint64(executableStat.Ino),
		OwnerUID: processStat.Uid, BootID: boot,
	}, nil
}

func kernelOpenRestyWorkers(master processIdentity) ([]processIdentity, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("stable OpenResty worker identity requires Linux procfs")
	}
	childrenPath := filepath.Join("/proc", strconv.Itoa(master.PID), "task", strconv.Itoa(master.PID), "children")
	content, err := os.ReadFile(childrenPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, errProcessNotRunning
	}
	if err != nil {
		return nil, errors.New("inspect OpenResty worker processes")
	}
	children := strings.Fields(string(content))
	if len(children) > 16 {
		return nil, errors.New("OpenResty worker generation is oversized")
	}
	workers := make([]processIdentity, 0, len(children))
	for _, value := range children {
		pid, err := strconv.Atoi(value)
		if err != nil || pid <= 1 {
			return nil, errors.New("OpenResty worker PID is invalid")
		}
		identity, isWorker, err := kernelOpenRestyChildIdentity(pid, master)
		if errors.Is(err, errProcessNotRunning) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if isWorker {
			workers = append(workers, identity)
		}
	}
	return workers, nil
}

func kernelOpenRestyChildIdentity(pid int, master processIdentity) (processIdentity, bool, error) {
	processRoot := filepath.Join("/proc", strconv.Itoa(pid))
	processInfo, err := os.Stat(processRoot)
	if errors.Is(err, os.ErrNotExist) {
		return processIdentity{}, false, errProcessNotRunning
	}
	if err != nil {
		return processIdentity{}, false, errors.New("inspect OpenResty worker owner")
	}
	processStat, ok := processInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return processIdentity{}, false, errors.New("OpenResty worker owner is invalid")
	}
	raw, err := os.ReadFile(filepath.Join(processRoot, "stat"))
	if errors.Is(err, os.ErrNotExist) {
		return processIdentity{}, false, errProcessNotRunning
	}
	if err != nil {
		return processIdentity{}, false, errors.New("read OpenResty worker identity")
	}
	separator := bytes.LastIndex(raw, []byte(") "))
	if separator < 0 {
		return processIdentity{}, false, errors.New("read OpenResty worker identity")
	}
	fields := strings.Fields(string(raw[separator+2:]))
	if len(fields) <= 19 || fields[0] == "Z" {
		return processIdentity{}, false, errProcessNotRunning
	}
	parentPID, parentErr := strconv.Atoi(fields[1])
	start, startErr := strconv.ParseUint(fields[19], 10, 64)
	if parentErr != nil || parentPID != master.PID || startErr != nil || start == 0 {
		return processIdentity{}, false, errors.New("OpenResty worker parent or start identity is invalid")
	}
	commandLine, err := os.ReadFile(filepath.Join(processRoot, "cmdline"))
	if errors.Is(err, os.ErrNotExist) {
		return processIdentity{}, false, errProcessNotRunning
	}
	if err != nil {
		return processIdentity{}, false, errors.New("read OpenResty worker command line")
	}
	if !strings.Contains(strings.ReplaceAll(string(commandLine), "\x00", " "), "worker process") {
		return processIdentity{}, false, nil
	}
	bootID, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	boot := strings.TrimSpace(string(bootID))
	if err != nil || boot == "" || boot != master.BootID || len(boot) > 64 || hasControl(boot) {
		return processIdentity{}, false, errors.New("OpenResty worker boot identity is invalid")
	}
	return processIdentity{
		PID: pid, StartTicks: start, ExecutableDevice: master.ExecutableDevice, ExecutableInode: master.ExecutableInode,
		OwnerUID: processStat.Uid, BootID: boot,
	}, true, nil
}

func hasControl(value string) bool {
	return strings.IndexFunc(value, func(character rune) bool {
		return character < 0x20 || character == 0x7f
	}) >= 0
}

func withSeparator(path string) string {
	return path + string(filepath.Separator)
}
