package certstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type OpenRestyRuntime struct {
	binary               string
	pidFile              string
	dialAddress          string
	run                  func(context.Context, string, []string, ...string) error
	inspect              func(int) (processIdentity, error)
	matchStart           func(int, string) error
	openProcess          func(int) (processHandle, error)
	writeIdentity        func(string, []byte) error
	removeProcessFile    func(string) error
	syncProcessDirectory func(string) error
	identityOK           bool
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

func (start processStartIdentity) matches(identity processIdentity) bool {
	return start.ExecutableDevice == identity.ExecutableDevice && start.ExecutableInode == identity.ExecutableInode &&
		start.OwnerUID == identity.OwnerUID
}

var errProcessNotRunning = errors.New("process is not running")

const processStartEnvironment = "CDNCA_OPENRESTY_START_TOKEN"

const (
	linuxPIDFDOpen       = uintptr(434)
	linuxPIDFDSendSignal = uintptr(424)
)

func NewOpenRestyRuntime(binary, pidFile, dialAddress string) (*OpenRestyRuntime, error) {
	if !filepath.IsAbs(binary) || filepath.Clean(binary) != binary || !filepath.IsAbs(pidFile) || filepath.Clean(pidFile) != pidFile {
		return nil, invalid("OpenResty binary and PID file must be clean absolute paths")
	}
	if _, _, err := net.SplitHostPort(dialAddress); err != nil {
		return nil, invalid("health dial address must include an IP and port")
	}
	return &OpenRestyRuntime{
		binary: binary, pidFile: pidFile, dialAddress: dialAddress,
		run: runCommand, inspect: kernelProcessIdentity, matchStart: kernelProcessStartMatches, openProcess: openPIDFD,
		writeIdentity: writeAtomicFile, removeProcessFile: os.Remove, syncProcessDirectory: syncDirectory,
		identityOK: runtime.GOOS == "linux",
	}, nil
}

func (runtime *OpenRestyRuntime) Precheck(ctx context.Context, candidatePath string) error {
	if !cleanAbsolute(candidatePath) {
		return ErrPrecheck
	}
	if err := runtime.run(ctx, runtime.binary, nil, "-t", "-p", withSlash(candidatePath), "-c", "nginx.conf"); err != nil {
		return sanitized(ctx, ErrPrecheck)
	}
	return nil
}

func (runtime *OpenRestyRuntime) Activate(ctx context.Context, currentPath string) (result error) {
	if !cleanAbsolute(currentPath) {
		return ErrActivation
	}
	handle, record, running, err := runtime.openOwnedProcess()
	if err != nil {
		return ErrActivation
	}
	if handle != nil {
		defer func() { result = errors.Join(result, handle.Close()) }()
	}
	if running {
		if err := handle.Signal(syscall.SIGHUP); err != nil {
			return ErrActivation
		}
		return nil
	} else {
		if !runtime.identityOK {
			return ErrActivation
		}
		if err := removeProcessFilesIfMatch(runtime.pidFile, record, syncDirectory); err != nil {
			return ErrActivation
		}
	}
	startIdentity, err := newProcessStartIdentity(runtime.binary)
	if err != nil {
		return ErrActivation
	}
	if err := runtime.writeIdentity(runtime.pidFile+".identity.pending", []byte(formatProcessStartIdentity(startIdentity))); err != nil {
		return ErrActivation
	}
	environment := []string{processStartEnvironment + "=" + startIdentity.Token}
	if err := runtime.run(ctx, runtime.binary, environment, "-g", "env "+processStartEnvironment+";", "-p", withSlash(currentPath), "-c", "nginx.conf"); err != nil {
		return errors.Join(sanitized(ctx, ErrActivation), runtime.cleanupUnrecordedStart())
	}
	if err := runtime.recordStartedProcess(ctx); err != nil {
		return sanitized(ctx, ErrActivation)
	}
	return nil
}

// healthProbeConcurrency bounds parallel handshakes of one health round.
const healthProbeConcurrency = 16

// Healthy probes every target twice in a row. A command that only removes
// sites has no target: the runtime must still accept connections. The time
// allowed grows with the command's size.
func (runtime *OpenRestyRuntime) Healthy(ctx context.Context, targets []HealthTarget) error {
	timeout := min(5*time.Second+time.Duration(len(targets))*10*time.Millisecond, 2*time.Minute)
	healthContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	consecutiveHealthy := 0
	for {
		allHealthy := runtime.probeRound(healthContext, targets)
		if allHealthy {
			consecutiveHealthy++
			if consecutiveHealthy == 2 {
				return nil
			}
		} else {
			consecutiveHealthy = 0
		}
		select {
		case <-healthContext.Done():
			return sanitized(ctx, ErrHealth)
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (runtime *OpenRestyRuntime) probeRound(ctx context.Context, targets []HealthTarget) bool {
	if len(targets) == 0 {
		connection, err := (&net.Dialer{Timeout: 500 * time.Millisecond}).DialContext(ctx, "tcp", runtime.dialAddress)
		if err != nil {
			return false
		}
		return connection.Close() == nil
	}
	probeContext, cancel := context.WithCancel(ctx)
	defer cancel()
	work := make(chan HealthTarget)
	var failed atomic.Bool
	var group sync.WaitGroup
	for worker := 0; worker < min(healthProbeConcurrency, len(targets)); worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for target := range work {
				if runtime.probe(probeContext, target) != nil {
					failed.Store(true)
					cancel()
				}
			}
		}()
	}
	for _, target := range targets {
		if failed.Load() {
			break
		}
		work <- target
	}
	close(work)
	group.Wait()
	return !failed.Load()
}

func (runtime *OpenRestyRuntime) probe(ctx context.Context, target HealthTarget) error {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 500 * time.Millisecond},
		Config: &tls.Config{
			MinVersion: tls.VersionTLS12, ServerName: target.ServerName, InsecureSkipVerify: true,
			VerifyConnection: func(state tls.ConnectionState) error {
				if len(state.PeerCertificates) == 0 || sha256.Sum256(state.PeerCertificates[0].Raw) != target.LeafSHA256 ||
					state.PeerCertificates[0].VerifyHostname(target.ServerName) != nil {
					return ErrHealth
				}
				return nil
			},
		},
	}
	connection, err := dialer.DialContext(ctx, "tcp", runtime.dialAddress)
	if err != nil {
		return err
	}
	return connection.Close()
}

func (runtime *OpenRestyRuntime) Stop(ctx context.Context, currentPath string) (result error) {
	if !cleanAbsolute(currentPath) {
		return ErrActivation
	}
	handle, record, running, err := runtime.openOwnedProcess()
	if err != nil || !running {
		if err == nil {
			err = removeProcessFilesIfMatch(runtime.pidFile, record, syncDirectory)
		}
		return err
	}
	defer func() { result = errors.Join(result, handle.Close()) }()
	if err := handle.Signal(syscall.SIGQUIT); err != nil {
		return ErrActivation
	}
	for {
		alive, aliveErr := handle.Alive()
		if aliveErr != nil {
			return aliveErr
		}
		if !alive {
			return removeProcessFilesIfMatch(runtime.pidFile, record, syncDirectory)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func runCommand(ctx context.Context, binary string, environment []string, arguments ...string) error {
	command := exec.CommandContext(ctx, binary, arguments...)
	prefix := processStartEnvironment + "="
	command.Env = make([]string, 0, len(os.Environ())+len(environment))
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, prefix) {
			command.Env = append(command.Env, value)
		}
	}
	command.Env = append(command.Env, environment...)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	return command.Run()
}

func (runtime *OpenRestyRuntime) openOwnedProcess() (processHandle, processIdentity, bool, error) {
	pid, pidExists, err := readProcessPID(runtime.pidFile)
	if err != nil {
		return nil, processIdentity{}, false, err
	}
	record, recordExists, err := readOptionalProcessRecord(runtime.pidFile + ".identity")
	if err != nil {
		return nil, processIdentity{}, false, err
	}
	startRecord, startRecordExists, err := readOptionalProcessStartIdentity(runtime.pidFile + ".identity.pending")
	if err != nil {
		return nil, processIdentity{}, false, err
	}
	if !pidExists && !recordExists && !startRecordExists {
		return nil, processIdentity{}, false, nil
	}
	if startRecordExists && !recordExists {
		startupContext, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		handle, identity, startErr := runtime.openStartedProcess(startupContext)
		if handle == nil {
			return nil, processIdentity{}, false, startErr
		}
		if startErr != nil {
			return nil, processIdentity{}, false, errors.Join(startErr, handle.Close())
		}
		if err := runtime.commitStartedProcess(identity); err != nil {
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
	if !runtime.identityOK {
		return nil, record, false, errors.New("stable OpenResty process identity requires Linux pidfd")
	}
	handle, err := runtime.openProcess(record.PID)
	if errors.Is(err, errProcessNotRunning) {
		return nil, record, false, nil
	}
	if err != nil {
		return nil, record, false, err
	}
	identity, err := runtime.inspect(record.PID)
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
		if err := removeProcessStartIdentity(runtime.pidFile + ".identity.pending"); err != nil {
			return nil, record, false, errors.Join(err, handle.Close())
		}
	}
	return handle, record, true, nil
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

func (runtime *OpenRestyRuntime) recordStartedProcess(ctx context.Context) (result error) {
	startupContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer cancel()
	handle, identity, err := runtime.openStartedProcess(startupContext)
	if handle == nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			result = errors.Join(result, stopStartedProcess(handle, runtime.pidFile, identity, waitProcessHandleExit))
		}
		result = errors.Join(result, handle.Close())
	}()
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := runtime.commitStartedProcess(identity); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	committed = true
	return nil
}

func (runtime *OpenRestyRuntime) commitStartedProcess(identity processIdentity) error {
	startRecord, exists, err := readOptionalProcessStartIdentity(runtime.pidFile + ".identity.pending")
	if err != nil || !exists || !startRecord.matches(identity) {
		return errors.New("pending OpenResty identity does not match the started process")
	}
	identityPath := runtime.pidFile + ".identity"
	if err := runtime.writeIdentity(identityPath, []byte(formatProcessRecord(identity))); err != nil {
		return err
	}
	confirmed, err := runtime.inspect(identity.PID)
	pID, pidExists, pidErr := readProcessPID(runtime.pidFile)
	if err != nil || confirmed != identity || pidErr != nil || !pidExists || pID != identity.PID {
		cleanupErr := removeProcessPaths([]string{identityPath}, runtime.removeProcessFile, runtime.syncProcessDirectory)
		return errors.Join(errors.New("OpenResty process identity changed during startup"), cleanupErr)
	}
	return removeProcessStartIdentity(runtime.pidFile + ".identity.pending")
}

func (runtime *OpenRestyRuntime) openStartedProcess(ctx context.Context) (processHandle, processIdentity, error) {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		pid, exists, err := readProcessPID(runtime.pidFile)
		if err != nil {
			return nil, processIdentity{}, err
		}
		if exists {
			identity, err := runtime.inspect(pid)
			if err == nil {
				startRecord, startExists, startErr := readOptionalProcessStartIdentity(runtime.pidFile + ".identity.pending")
				if startErr != nil || !startExists || !startRecord.matches(identity) {
					return nil, processIdentity{}, errors.New("pending OpenResty identity does not match the started process")
				}
				if err := runtime.matchStart(pid, startRecord.Token); err != nil {
					return nil, processIdentity{}, err
				}
				handle, openErr := runtime.openProcess(pid)
				if openErr != nil && !errors.Is(openErr, errProcessNotRunning) {
					return nil, processIdentity{}, openErr
				}
				if openErr == nil {
					confirmed, confirmErr := runtime.inspect(pid)
					if confirmErr != nil || confirmed != identity {
						return nil, processIdentity{}, errors.Join(errors.New("OpenResty process identity changed during startup"), handle.Close())
					}
					if err := runtime.matchStart(pid, startRecord.Token); err != nil {
						return nil, processIdentity{}, errors.Join(err, handle.Close())
					}
					confirmedPID, confirmedExists, pidErr := readProcessPID(runtime.pidFile)
					if pidErr != nil || !confirmedExists || confirmedPID != pid {
						return handle, identity, errors.New("OpenResty PID changed during startup")
					}
					return handle, identity, nil
				}
			}
			if !errors.Is(err, errProcessNotRunning) {
				return nil, processIdentity{}, err
			}
		}
		select {
		case <-ctx.Done():
			return nil, processIdentity{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (runtime *OpenRestyRuntime) cleanupUnrecordedStart() (result error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	handle, identity, err := runtime.openStartedProcess(ctx)
	if handle == nil {
		return err
	}
	defer func() { result = errors.Join(result, handle.Close()) }()
	return errors.Join(err, stopStartedProcess(handle, runtime.pidFile, identity, waitProcessHandleExit))
}

func stopStartedProcess(handle processHandle, pidFile string, identity processIdentity, waitExit func(processHandle, time.Duration) (bool, error)) error {
	if err := handle.Signal(syscall.SIGQUIT); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	exited, err := waitExit(handle, time.Second)
	if err != nil {
		return err
	}
	if !exited {
		if err := handle.Signal(syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			return err
		}
		exited, err = waitExit(handle, time.Second)
		if err != nil {
			return err
		}
		if !exited {
			return errors.New("started OpenResty process did not exit")
		}
	}
	return removeStartedProcessFilesIfMatch(pidFile, identity, syncDirectory)
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

func removeStartedProcessFilesIfMatch(pidFile string, expected processIdentity, syncParent func(string) error) error {
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
	return removeProcessPaths([]string{pidFile, pidFile + ".identity", pidFile + ".identity.pending"}, os.Remove, syncParent)
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
		return nil, false, errors.New("OpenResty process file is unsafe")
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
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "environ"))
	if errors.Is(err, os.ErrNotExist) {
		return errProcessNotRunning
	}
	if err != nil {
		return errors.New("inspect OpenResty start identity")
	}
	expected := processStartEnvironment + "=" + token
	for _, value := range bytes.Split(raw, []byte{0}) {
		if string(value) == expected {
			return nil
		}
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
	separator := bytes.LastIndex(raw, []byte(") "))
	if err != nil || separator < 0 {
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
	executableStat, executableOK := executableInfo.Sys().(*syscall.Stat_t)
	if !executableOK || executableStat.Ino == 0 {
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

func removeProcessStartIdentity(path string) error {
	return removeProcessPaths([]string{path}, os.Remove, syncDirectory)
}

func removeProcessFilesIfMatch(pidFile string, expected processIdentity, syncParent func(string) error) error {
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
	return removeProcessPaths([]string{pidFile, pidFile + ".identity"}, os.Remove, syncParent)
}

func cleanAbsolute(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && !hasControl(path)
}

func withSlash(path string) string { return path + string(filepath.Separator) }
