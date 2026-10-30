package l4runtime

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
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/oldmaster"
)

type OpenResty struct {
	mu                   sync.Mutex
	binary               string
	pidFile              string
	timeout              time.Duration
	start                func(context.Context, []string, ...string) error
	inspect              func(int) (processIdentity, error)
	parentPID            func(int) (int, error)
	matchStart           func(int, string) error
	openProcess          func(int) (processHandle, error)
	workerGeneration     func(processIdentity) (workerGeneration, error)
	writeIdentity        func(string, []byte) error
	removeProcessFile    func(string) error
	syncProcessDirectory func(string) error
	shuttingDown         func(workerIdentity) bool
	bootID               func() (string, error)
	retireMaster         func(ctx context.Context, old, fresh int) error
	identityOK           bool
	// drainLimit bounds how long a generation retired by the next reload may
	// keep its sessions (0: unlimited). retired lists, oldest first, the
	// worker generations reloads replaced that still hold sessions.
	drainLimit time.Duration
	retired    []*retiredGeneration
}

// retiredGeneration is one worker generation a reload replaced. Its workers
// stop accepting and finish their sessions; nginx keeps them until the last
// session ends. They are terminated only past the drain limit, or when more
// than maxRetiredGenerations generations drain at once.
type retiredGeneration struct {
	workers   workerGeneration
	master    processIdentity
	retiredAt time.Time
	limit     time.Duration
	timer     *time.Timer
}

// DrainStatus describes the worker generations still draining sessions.
type DrainStatus struct {
	Generations     int       `json:"generations"`
	Workers         int       `json:"workers"`
	OldestRetiredAt time.Time `json:"oldest_retired_at,omitempty"`
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

type workerIdentity struct {
	PID              int
	StartTicks       uint64
	ExecutableDevice uint64
	ExecutableInode  uint64
	OwnerUID         uint32
	BootID           string
}

type workerGeneration map[workerIdentity]struct{}

type listenerPortPrecheckError struct {
	listenerID string
	reasonCode string
	cause      error
}

func (e *listenerPortPrecheckError) Error() string {
	return fmt.Sprintf("%s for listener %q: %v", e.reasonCode, e.listenerID, e.cause)
}

func (e *listenerPortPrecheckError) Unwrap() error      { return e.cause }
func (e *listenerPortPrecheckError) ListenerID() string { return e.listenerID }
func (e *listenerPortPrecheckError) ReasonCode() string { return e.reasonCode }

func (start processStartIdentity) matches(identity processIdentity) bool {
	return start.ExecutableDevice == identity.ExecutableDevice && start.ExecutableInode == identity.ExecutableInode &&
		start.OwnerUID == identity.OwnerUID
}

var (
	errProcessNotRunning    = errors.New("process is not running")
	errWorkerOwnersUnstable = errors.New("OpenResty worker owners are not stable")
)

const processStartEnvironment = "CDNCA_L4_OPENRESTY_START_TOKEN"

const reloadWorkerStabilityWindow = 200 * time.Millisecond

const (
	linuxPIDFDOpen       = uintptr(434)
	linuxPIDFDSendSignal = uintptr(424)
)

func NewOpenResty(binary, pidFile string, timeout time.Duration) (*OpenResty, error) {
	if !safeAbsolutePath(binary) || !safeDirectivePath(pidFile) || timeout <= 0 || timeout > time.Minute {
		return nil, ErrInvalidPath
	}
	controller := &OpenResty{
		binary: binary, pidFile: pidFile, timeout: timeout,
		inspect: kernelProcessIdentity, parentPID: kernelParentPID, matchStart: kernelProcessStartMatches, openProcess: openPIDFD,
		workerGeneration: kernelWorkerGeneration, shuttingDown: kernelWorkerShuttingDown, retireMaster: oldmaster.Retire,
		drainLimit: time.Duration(DefaultDrainMaxMS) * time.Millisecond,
		writeIdentity: func(path string, content []byte) error {
			return writeAtomic(filepath.Dir(path), path, content)
		},
		removeProcessFile: os.Remove, syncProcessDirectory: syncDirectory,
		bootID: kernelBootID, identityOK: runtime.GOOS == "linux",
	}
	controller.start = controller.runStart
	return controller, nil
}

func (r *OpenResty) Precheck(ctx context.Context, candidatePath string) error {
	if !safeAbsolutePath(candidatePath) {
		return ErrInvalidPath
	}
	candidateDigest := sha256.Sum256([]byte(candidatePath))
	precheckPID := filepath.Join(filepath.Dir(r.pidFile), ".nginx-precheck-"+hex.EncodeToString(candidateDigest[:8])+".pid")
	if !safeDirectivePath(precheckPID) {
		return ErrInvalidPath
	}
	defer os.Remove(precheckPID)
	if err := r.run(ctx, "-e", "stderr", "-t", "-q", "-p", withSeparator(candidatePath), "-c", "nginx.conf", "-g", "pid "+precheckPID+";"); err != nil {
		return err
	}
	return precheckListenerPorts(candidatePath)
}

func precheckListenerPorts(candidatePath string) error {
	candidate, err := readPortPrecheckConfig(filepath.Join(candidatePath, "config.json"))
	if err != nil {
		return fmt.Errorf("LISTENER_PORT_PRECHECK_FAILED: read candidate L4 configuration: %w", err)
	}
	current, err := currentPortPrecheckConfig(candidatePath)
	if err != nil {
		return fmt.Errorf("LISTENER_PORT_PRECHECK_FAILED: read current L4 configuration: %w", err)
	}
	for _, listener := range candidate.Listeners {
		if listener.Disabled {
			continue
		}
		address, err := netip.ParseAddr(listener.Address)
		if err != nil || listener.Port < 1 || listener.Port > 65535 || (listener.Protocol != ProtocolTCP && listener.Protocol != ProtocolUDP) ||
			(listener.PortEnd != 0 && (listener.PortEnd <= listener.Port || listener.PortEnd > 65535)) {
			return newListenerPortPrecheckError(listener.ID, ErrInvalidConfig)
		}
		network := string(listener.Protocol)
		if address.Is4() {
			network += "4"
		} else {
			network += "6"
		}
		// Every port of a range (tcp/udp v9) is probed unless the active
		// runtime already binds it.
		for port := listener.Port; port <= listener.lastPort(); port++ {
			single := listener
			single.Port, single.PortEnd = port, 0
			owned := false
			for _, active := range current.Listeners {
				if active.Disabled {
					continue
				}
				if _, err := netip.ParseAddr(active.Address); err != nil {
					return newListenerPortPrecheckError(listener.ID, ErrCorruptState)
				}
				if bindsOverlap(single, active) {
					owned = true
					break
				}
			}
			if owned {
				continue
			}
			endpoint := net.JoinHostPort(address.String(), strconv.Itoa(port))
			if err := probeListenerPort(network, endpoint); err != nil {
				return newListenerPortPrecheckError(listener.ID, err)
			}
		}
	}
	return nil
}

func readPortPrecheckConfig(path string) (Config, error) {
	runtimePath := filepath.Join(filepath.Dir(path), "runtime.json")
	if content, err := readRegularFile(runtimePath); err == nil {
		compiled, err := decodeStoredRuntimeV2(content)
		if err != nil {
			return Config{}, ErrCorruptState
		}
		return compatibleCompiledV2(compiled).Config, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return Config{}, err
	}
	content, err := readRegularFile(path)
	if err != nil {
		return Config{}, err
	}
	var config Config
	if err := json.Unmarshal(content, &config); err != nil {
		return Config{}, ErrCorruptState
	}
	return config, nil
}

func currentPortPrecheckConfig(candidatePath string) (Config, error) {
	container := filepath.Dir(candidatePath)
	if base := filepath.Base(container); base != "tmp" && base != "versions" {
		return Config{}, ErrInvalidPath
	}
	root := filepath.Dir(container)
	target, err := os.Readlink(filepath.Join(root, "current"))
	if errors.Is(err, os.ErrNotExist) {
		return Config{}, nil
	}
	if err != nil || filepath.Dir(target) != "versions" || !validVersionDirectoryName(filepath.Base(target)) || filepath.Clean(target) != target {
		return Config{}, ErrCorruptState
	}
	return readPortPrecheckConfig(filepath.Join(root, target, "config.json"))
}

func probeListenerPort(network, endpoint string) error {
	if strings.HasPrefix(network, string(ProtocolUDP)) {
		connection, err := net.ListenPacket(network, endpoint)
		if err != nil {
			return err
		}
		return connection.Close()
	}
	listener, err := net.Listen(network, endpoint)
	if err != nil {
		return err
	}
	return listener.Close()
}

func newListenerPortPrecheckError(listenerID string, cause error) error {
	reason := "LISTENER_PORT_PRECHECK_FAILED"
	if errors.Is(cause, syscall.EADDRINUSE) {
		reason = "LISTENER_PORT_CONFLICT"
	}
	return &listenerPortPrecheckError{listenerID: listenerID, reasonCode: reason, cause: cause}
}

func (r *OpenResty) Activate(ctx context.Context, currentPath string) (result error) {
	if !safeAbsolutePath(currentPath) {
		return ErrInvalidPath
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.activateLocked(ctx, currentPath)
}

// Resume takes over the master a previous agent process left running
// (the agent unit uses KillMode=process, so restarts and upgrades keep it).
// An adopted master is not reloaded: a reload would retire the worker
// generation holding the established sessions. Only when no owned master is
// alive does Resume start the current version.
func (r *OpenResty) Resume(ctx context.Context, currentPath string) (result error) {
	if !safeAbsolutePath(currentPath) {
		return ErrInvalidPath
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	handle, record, running, err := r.openOwnedProcess()
	if err != nil {
		return err
	}
	if !running {
		return r.activateLocked(ctx, currentPath)
	}
	defer func() { result = errors.Join(result, handle.Close()) }()
	workers, err := r.workerGeneration(record)
	if err != nil {
		return fmt.Errorf("snapshot adopted OpenResty workers: %w", err)
	}
	if len(workers) == 0 {
		return errors.New("adopted OpenResty master has no verified worker generation")
	}
	return nil
}

func (r *OpenResty) activateLocked(ctx context.Context, currentPath string) (result error) {
	handle, record, running, err := r.openOwnedProcess()
	if err != nil {
		return err
	}
	if handle != nil {
		defer func() { result = errors.Join(result, handle.Close()) }()
	}
	if running {
		before, err := r.workerGeneration(record)
		if err != nil {
			return fmt.Errorf("snapshot owned OpenResty workers before reload: %w", err)
		}
		if len(before) == 0 {
			return errors.New("owned OpenResty master has no verified worker generation")
		}
		r.pruneRetired(record, before)
		serving := r.servingWorkers(before)
		if len(serving) == 0 {
			return errors.New("owned OpenResty master has no serving worker generation")
		}
		if err := handle.Signal(syscall.SIGHUP); err != nil {
			return fmt.Errorf("reload owned OpenResty process: %w", err)
		}
		reloadContext, cancel := context.WithTimeout(ctx, r.timeout)
		defer cancel()
		after, err := waitForWorkerGeneration(reloadContext, handle, record, before, len(serving), r.inspect, r.workerGeneration)
		if err != nil {
			return fmt.Errorf("confirm owned OpenResty reload: %w", err)
		}
		r.retire(record, subtractWorkerGeneration(serving, after))
		return nil
	}
	r.clearRetired()
	if !r.identityOK {
		return errors.New("stable OpenResty process identity requires Linux procfs and pidfd")
	}
	if err := removeProcessFilesIfMatch(r.pidFile, record, r.removeProcessFile, r.syncProcessDirectory); err != nil {
		return fmt.Errorf("remove stopped OpenResty process state: %w", err)
	}
	startIdentity, err := newProcessStartIdentity(r.binary)
	if err != nil {
		return err
	}
	pendingPath := r.pidFile + ".identity.pending"
	if err := r.writeIdentity(pendingPath, []byte(formatProcessStartIdentity(startIdentity))); err != nil {
		return fmt.Errorf("write pending OpenResty process identity: %w", err)
	}
	environment := []string{processStartEnvironment + "=" + startIdentity.Token}
	arguments := []string{
		"-e", "stderr", "-p", withSeparator(currentPath), "-c", "nginx.conf", "-g",
		"pid " + r.pidFile + "; env " + processStartEnvironment + "=" + startIdentity.Token + ";",
	}
	if err := r.start(ctx, environment, arguments...); err != nil {
		return errors.Join(err, r.cleanupUnrecordedStart())
	}
	if err := r.recordStartedProcess(ctx); err != nil {
		return err
	}
	return nil
}

func (r *OpenResty) Healthy(ctx context.Context, config Config) error {
	compiled, err := Compile(config)
	if err != nil {
		return err
	}
	for _, listener := range compiled.Config.Listeners {
		if listener.Disabled {
			continue
		}
		policy := listener.TrafficHealth
		if policy == nil {
			continue
		}
		var probeErr error
		for attempt := 0; attempt < policy.Attempts; attempt++ {
			probeCtx, cancel := context.WithTimeout(ctx, time.Duration(policy.TimeoutMS)*time.Millisecond)
			probeErr = probeTrafficHealth(probeCtx, listener)
			cancel()
			if probeErr == nil {
				break
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
		}
		if probeErr != nil {
			return fmt.Errorf("listener %q traffic health failed: %w", listener.ID, probeErr)
		}
	}
	return nil
}

func probeTrafficHealth(ctx context.Context, listener Listener) error {
	address := netip.MustParseAddr(listener.Address)
	if address.IsUnspecified() {
		if address.Is4() {
			address = netip.MustParseAddr("127.0.0.1")
		} else {
			address = netip.MustParseAddr("::1")
		}
	}
	network := string(listener.Protocol)
	if address.Is4() {
		network += "4"
	} else {
		network += "6"
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(address.String(), strconv.Itoa(listener.Port)))
	if err != nil {
		return err
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			return err
		}
	}
	policy := listener.TrafficHealth
	if len(policy.Request) == 0 {
		return nil
	}
	if _, err := connection.Write(policy.Request); err != nil {
		return err
	}
	if listener.Protocol == ProtocolUDP {
		response := make([]byte, len(policy.ExpectedResponse)+1)
		read, err := connection.Read(response)
		if err != nil {
			return err
		}
		if read != len(policy.ExpectedResponse) || !bytes.Equal(response[:read], policy.ExpectedResponse) {
			return errors.New("unexpected UDP traffic health response")
		}
		return nil
	}
	response := make([]byte, len(policy.ExpectedResponse))
	if _, err := io.ReadFull(connection, response); err != nil {
		return err
	}
	if !bytes.Equal(response, policy.ExpectedResponse) {
		return errors.New("unexpected TCP traffic health response")
	}
	return nil
}

func waitForWorkerGeneration(
	ctx context.Context,
	handle processHandle,
	master processIdentity,
	before workerGeneration,
	expected int,
	inspect func(int) (processIdentity, error),
	snapshot func(processIdentity) (workerGeneration, error),
) (workerGeneration, error) {
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	var candidate workerGeneration
	var candidateSince time.Time
	lastCurrent, lastNew := 0, 0
	var lastSnapshotErr error
	for {
		if err := ctx.Err(); err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return nil, fmt.Errorf("OpenResty reload worker generation confirmation timed out (before=%d current=%d new=%d last_snapshot_error=%v)",
					len(before), lastCurrent, lastNew, lastSnapshotErr)
			}
			return nil, err
		}
		alive, err := handle.Alive()
		if err != nil {
			return nil, err
		}
		if !alive {
			return nil, errors.New("owned OpenResty master exited during reload")
		}
		current, err := inspect(master.PID)
		if err != nil || current != master {
			return nil, errors.Join(errors.New("owned OpenResty master identity changed during reload"), err)
		}
		generation, err := snapshot(master)
		if err != nil {
			if !errors.Is(err, errWorkerOwnersUnstable) {
				return nil, err
			}
			lastSnapshotErr = err
			candidate = nil
			candidateSince = time.Time{}
			generation = nil
		}
		now := time.Now()
		lastCurrent = len(generation)
		lastNew = countNewWorkers(generation, before)
		if err == nil {
			lastSnapshotErr = nil
		}
		if candidate != nil {
			if sameNewWorkerGeneration(generation, before, candidate) {
				if now.Sub(candidateSince) >= reloadWorkerStabilityWindow {
					return cloneWorkerGeneration(candidate), nil
				}
			} else {
				candidate = nil
				candidateSince = time.Time{}
			}
		}
		if candidate == nil {
			if next, ok := initialReloadWorkerGeneration(generation, before, expected); ok {
				candidate = next
				candidateSince = now
			}
		}
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return nil, fmt.Errorf("OpenResty reload worker generation confirmation timed out (before=%d current=%d new=%d last_snapshot_error=%v)",
					len(before), lastCurrent, lastNew, lastSnapshotErr)
			}
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func countNewWorkers(generation, before workerGeneration) int {
	count := 0
	for worker := range generation {
		if _, existed := before[worker]; !existed {
			count++
		}
	}
	return count
}

func subtractWorkerGeneration(before, after workerGeneration) workerGeneration {
	remaining := make(workerGeneration)
	for worker := range before {
		if _, exists := after[worker]; exists {
			continue
		}
		remaining[worker] = struct{}{}
	}
	return remaining
}

// Drain waits up to max for the workers the last reload retired to stop
// accepting: nginx retitles a worker "shutting down" once it closed its
// listeners, and it then serves its open sessions until they end. A retired
// worker still accepting at max is stuck and is terminated. Draining sessions
// never fail a deployment: they end by themselves, at the drain limit, or
// when too many generations drain at once.
func (r *OpenResty) Drain(ctx context.Context, max time.Duration) error {
	if max <= 0 || max > time.Minute {
		return ErrInvalidPath
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.retired) == 0 {
		return nil
	}
	handle, record, running, err := r.openOwnedProcess()
	if err != nil {
		return err
	}
	if handle == nil || !running || !r.retiredBy(record) {
		if handle == nil {
			return errors.New("owned OpenResty master changed during drain")
		}
		return errors.Join(errors.New("owned OpenResty master changed during drain"), handle.Close())
	}
	defer func() { _ = handle.Close() }()
	deadline := time.NewTimer(max)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		generation, err := r.workerGeneration(record)
		if err != nil {
			return err
		}
		r.pruneRetired(record, generation)
		accepting := r.acceptingRetiredWorkers()
		if len(accepting) == 0 {
			r.logDraining()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			if err := r.terminateDrainingWorkers(ctx, handle, record, accepting); err != nil {
				return err
			}
			r.forgetRetired(accepting)
			r.logDraining()
			return nil
		case <-ticker.C:
		}
	}
}

func (r *OpenResty) terminateDrainingWorkers(ctx context.Context, masterHandle processHandle, master processIdentity, workers workerGeneration) error {
	if alive, err := masterHandle.Alive(); err != nil || !alive {
		return errors.Join(errors.New("owned OpenResty master exited during drain"), err)
	}
	if current, err := r.inspect(master.PID); err != nil || current != master {
		return errors.Join(errors.New("owned OpenResty master identity changed during drain"), err)
	}
	if err := r.signalWorkers(workers); err != nil {
		return err
	}
	forceDeadline := time.NewTimer(r.timeout)
	defer forceDeadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		generation, err := r.workerGeneration(master)
		if err != nil {
			return err
		}
		if len(subtractWorkerGeneration(workers, generation)) == len(workers) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-forceDeadline.C:
			return errors.New("OpenResty draining workers did not exit before the force deadline")
		case <-ticker.C:
		}
	}
}

// signalWorkers sends SIGTERM to each worker still running with its recorded
// kernel identity. Workers that already exited are skipped.
func (r *OpenResty) signalWorkers(workers workerGeneration) error {
	for worker := range workers {
		current, err := r.inspect(worker.PID)
		if errors.Is(err, errProcessNotRunning) {
			// It finished draining on its own after the last snapshot.
			continue
		}
		if err != nil {
			return fmt.Errorf("verify draining worker %d: %w", worker.PID, err)
		}
		if workerIdentityFromProcess(current) != worker {
			return errors.New("draining worker identity changed")
		}
		handle, err := r.openProcess(worker.PID)
		if errors.Is(err, errProcessNotRunning) {
			continue
		}
		if err != nil {
			return err
		}
		signalErr := handle.Signal(syscall.SIGTERM)
		closeErr := handle.Close()
		if signalErr != nil && !errors.Is(signalErr, syscall.ESRCH) {
			return errors.Join(signalErr, closeErr)
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

// SetDrainLimit sets how long the generation the next reload retires may keep
// draining its sessions; 0 is unlimited. Generations already retired keep the
// limit they were retired with.
func (r *OpenResty) SetDrainLimit(limit time.Duration) error {
	if limit < 0 || limit > time.Duration(maxDrainMaxMS)*time.Millisecond {
		return ErrInvalidConfig
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.drainLimit = limit
	return nil
}

// DrainStatus reports the worker generations still draining sessions.
func (r *OpenResty) DrainStatus() DrainStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.retired) != 0 {
		master := r.retired[len(r.retired)-1].master
		if generation, err := r.workerGeneration(master); err == nil {
			r.pruneRetired(master, generation)
		}
	}
	return r.drainStatusLocked()
}

func (r *OpenResty) drainStatusLocked() DrainStatus {
	status := DrainStatus{Generations: len(r.retired)}
	for index, generation := range r.retired {
		status.Workers += len(generation.workers)
		if index == 0 {
			status.OldestRetiredAt = generation.retiredAt
		}
	}
	return status
}

func (r *OpenResty) logDraining() {
	if status := r.drainStatusLocked(); status.Generations != 0 {
		slog.Info("L4 OpenResty old sessions draining", "generations", status.Generations,
			"workers", status.Workers, "oldest_retired_at", status.OldestRetiredAt, "drain_limit", r.drainLimit)
	}
}

// retire records the serving workers a confirmed reload replaced. More than
// maxRetiredGenerations draining generations would keep that many copies of
// the worker memory alive, so the oldest is ended.
func (r *OpenResty) retire(master processIdentity, workers workerGeneration) {
	if len(workers) == 0 {
		return
	}
	generation := &retiredGeneration{workers: workers, master: master, retiredAt: time.Now(), limit: r.drainLimit}
	if r.drainLimit > 0 {
		generation.timer = time.AfterFunc(r.drainLimit, func() { r.expireRetired(generation) })
	}
	r.retired = append(r.retired, generation)
	for len(r.retired) > maxRetiredGenerations {
		oldest := r.retired[0]
		r.retired = r.retired[1:]
		if oldest.timer != nil {
			oldest.timer.Stop()
		}
		err := r.signalWorkers(oldest.workers)
		slog.Warn("L4 OpenResty draining generations exceed the limit; ending the oldest one",
			"limit", maxRetiredGenerations, "workers", len(oldest.workers),
			"retired_at", oldest.retiredAt, "error", err)
	}
}

// expireRetired ends a retired generation that drained past its limit.
func (r *OpenResty) expireRetired(generation *retiredGeneration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	index := slices.Index(r.retired, generation)
	if index < 0 {
		return
	}
	r.retired = slices.Delete(r.retired, index, index+1)
	err := r.signalWorkers(generation.workers)
	slog.Warn("L4 OpenResty draining generation reached the drain limit; ending its sessions",
		"limit", generation.limit, "workers", len(generation.workers), "retired_at", generation.retiredAt, "error", err)
}

func (r *OpenResty) clearRetired() {
	for _, generation := range r.retired {
		if generation.timer != nil {
			generation.timer.Stop()
		}
	}
	r.retired = nil
}

// pruneRetired drops retired workers that exited (absent from current, the
// master's children) and generations of another master.
func (r *OpenResty) pruneRetired(master processIdentity, current workerGeneration) {
	kept := r.retired[:0]
	for _, generation := range r.retired {
		if generation.master == master {
			for worker := range generation.workers {
				if _, alive := current[worker]; !alive {
					delete(generation.workers, worker)
				}
			}
		}
		if generation.master != master || len(generation.workers) == 0 {
			if generation.timer != nil {
				generation.timer.Stop()
			}
			continue
		}
		kept = append(kept, generation)
	}
	clear(r.retired[len(kept):])
	r.retired = kept
}

// forgetRetired drops workers that were terminated and exited.
func (r *OpenResty) forgetRetired(workers workerGeneration) {
	kept := r.retired[:0]
	for _, generation := range r.retired {
		for worker := range workers {
			delete(generation.workers, worker)
		}
		if len(generation.workers) == 0 {
			if generation.timer != nil {
				generation.timer.Stop()
			}
			continue
		}
		kept = append(kept, generation)
	}
	clear(r.retired[len(kept):])
	r.retired = kept
}

func (r *OpenResty) retiredBy(master processIdentity) bool {
	for _, generation := range r.retired {
		if generation.master != master {
			return false
		}
	}
	return true
}

// acceptingRetiredWorkers are the retired workers not yet shutting down.
func (r *OpenResty) acceptingRetiredWorkers() workerGeneration {
	accepting := make(workerGeneration)
	for _, generation := range r.retired {
		for worker := range generation.workers {
			if !r.shuttingDown(worker) {
				accepting[worker] = struct{}{}
			}
		}
	}
	return accepting
}

// servingWorkers are the workers of generation a reload replaces: neither
// retired by an earlier reload nor already shutting down.
func (r *OpenResty) servingWorkers(generation workerGeneration) workerGeneration {
	serving := make(workerGeneration, len(generation))
	for worker := range generation {
		retired := false
		for _, old := range r.retired {
			if _, ok := old.workers[worker]; ok {
				retired = true
				break
			}
		}
		if !retired && !r.shuttingDown(worker) {
			serving[worker] = struct{}{}
		}
	}
	return serving
}

func waitForInitialWorkerGeneration(
	ctx context.Context,
	handle processHandle,
	master processIdentity,
	inspect func(int) (processIdentity, error),
	snapshot func(processIdentity) (workerGeneration, error),
) error {
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	var candidate workerGeneration
	var candidateSince time.Time
	for {
		if err := ctx.Err(); err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return errors.New("OpenResty initial worker generation confirmation timed out")
			}
			return err
		}
		current, err := inspect(master.PID)
		if err != nil || current != master {
			return errors.Join(errors.New("owned OpenResty master identity changed during startup"), err)
		}
		generation, err := snapshot(master)
		if err != nil {
			if !errors.Is(err, errWorkerOwnersUnstable) {
				return err
			}
			candidate = nil
			candidateSince = time.Time{}
			generation = nil
		}
		now := time.Now()
		if len(generation) == 0 {
			candidate = nil
			candidateSince = time.Time{}
		} else if candidate == nil || !sameWorkerGeneration(generation, candidate) {
			candidate = cloneWorkerGeneration(generation)
			candidateSince = now
		} else if now.Sub(candidateSince) >= reloadWorkerStabilityWindow {
			return nil
		}
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return errors.New("OpenResty initial worker generation confirmation timed out")
			}
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func cloneWorkerGeneration(generation workerGeneration) workerGeneration {
	clone := make(workerGeneration, len(generation))
	for worker := range generation {
		clone[worker] = struct{}{}
	}
	return clone
}

func sameWorkerGeneration(left, right workerGeneration) bool {
	if len(left) != len(right) {
		return false
	}
	for worker := range left {
		if _, exists := right[worker]; !exists {
			return false
		}
	}
	return true
}

// initialReloadWorkerGeneration returns the workers that appeared since before
// once there are at least expected of them: the serving workers a reload
// replaces. Draining generations in before are not replaced.
func initialReloadWorkerGeneration(generation, before workerGeneration, expected int) (workerGeneration, bool) {
	newWorkers := make(workerGeneration)
	for worker := range generation {
		if _, existed := before[worker]; !existed {
			newWorkers[worker] = struct{}{}
		}
	}
	if len(newWorkers) < expected {
		return nil, false
	}
	return newWorkers, true
}

func sameNewWorkerGeneration(generation, before, candidate workerGeneration) bool {
	newWorkers := 0
	for worker := range generation {
		if _, existed := before[worker]; existed {
			continue
		}
		if _, expected := candidate[worker]; !expected {
			return false
		}
		newWorkers++
	}
	return newWorkers == len(candidate)
}

func (r *OpenResty) runStart(parent context.Context, environment []string, arguments ...string) (result error) {
	ctx, cancel := context.WithTimeout(parent, r.timeout)
	defer cancel()
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open null device: %w", err)
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
	if err := command.Run(); err != nil {
		return fmt.Errorf("OpenResty start failed: %w", err)
	}
	return nil
}

func (r *OpenResty) Stop(ctx context.Context, currentPath string) (result error) {
	if !safeAbsolutePath(currentPath) {
		return ErrInvalidPath
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clearRetired()

	handle, record, running, err := r.openOwnedProcess()
	if err != nil {
		return err
	}
	if !running {
		return removeProcessFilesIfMatch(r.pidFile, record, r.removeProcessFile, r.syncProcessDirectory)
	}
	defer func() { result = errors.Join(result, handle.Close()) }()
	if err := handle.Signal(syscall.SIGQUIT); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return removeProcessFilesIfMatch(r.pidFile, record, r.removeProcessFile, r.syncProcessDirectory)
		}
		return fmt.Errorf("stop owned OpenResty process: %w", err)
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
			return removeProcessFilesIfMatch(r.pidFile, record, r.removeProcessFile, r.syncProcessDirectory)
		}
		if err := ctx.Err(); err != nil {
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

func (r *OpenResty) run(parent context.Context, arguments ...string) error {
	ctx, cancel := context.WithTimeout(parent, r.timeout)
	defer cancel()
	command := exec.CommandContext(ctx, r.binary, arguments...)
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
	owner := uint32(os.Geteuid())
	if (recordExists && record.OwnerUID != owner) || (startRecordExists && startRecord.OwnerUID != owner) {
		return nil, processIdentity{}, false, errors.New("OpenResty master owner is invalid")
	}
	if !pidExists && !recordExists && !startRecordExists {
		return nil, processIdentity{}, false, nil
	}
	if startRecordExists && !recordExists {
		if !r.identityOK {
			return nil, processIdentity{}, false, errors.New("stable OpenResty process identity requires Linux procfs and pidfd")
		}
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
		return nil, record, false, errors.New("stable OpenResty process identity requires Linux procfs and pidfd")
	}
	// The pid files outlive a reboot; a record from another boot names a
	// process that is gone (its PID may now be an unrelated process).
	boot, err := r.bootID()
	if err != nil {
		return nil, record, false, err
	}
	if record.BootID != boot {
		return nil, record, false, nil
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
		if err := removeProcessStartIdentity(r.pidFile+".identity.pending", r.removeProcessFile, r.syncProcessDirectory); err != nil {
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
			result = errors.Join(result, stopStartedProcess(handle, r.pidFile, identity, r.timeout, waitProcessHandleExit,
				r.removeProcessFile, r.syncProcessDirectory))
		}
		result = errors.Join(result, handle.Close())
	}()
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := waitForInitialWorkerGeneration(startupContext, handle, identity, r.inspect, r.workerGeneration); err != nil {
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
		return errors.Join(errors.New("pending OpenResty identity does not match the started process"), err)
	}
	identityPath := r.pidFile + ".identity"
	if err := r.writeIdentity(identityPath, []byte(formatProcessRecord(identity))); err != nil {
		return err
	}
	confirmed, inspectErr := r.inspect(identity.PID)
	pid, pidExists, pidErr := readProcessPID(r.pidFile)
	if inspectErr != nil || confirmed != identity || pidErr != nil || !pidExists || pid != identity.PID {
		cleanupErr := removeProcessPaths([]string{identityPath}, r.removeProcessFile, r.syncProcessDirectory)
		return errors.Join(errors.New("OpenResty process identity changed during startup"), inspectErr, pidErr, cleanupErr)
	}
	return removeProcessStartIdentity(r.pidFile+".identity.pending", r.removeProcessFile, r.syncProcessDirectory)
}

func (r *OpenResty) openStartedProcess(ctx context.Context) (processHandle, processIdentity, error) {
	ticker := time.NewTicker(20 * time.Millisecond)
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
				if startErr != nil {
					return nil, processIdentity{}, startErr
				}
				if !startExists || startRecord.OwnerUID != uint32(os.Geteuid()) || !startRecord.matches(identity) {
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
			} else if !errors.Is(inspectErr, errProcessNotRunning) {
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
	return errors.Join(err, stopStartedProcess(handle, r.pidFile, identity, r.timeout, waitProcessHandleExit,
		r.removeProcessFile, r.syncProcessDirectory))
}

func stopStartedProcess(
	handle processHandle,
	pidFile string,
	identity processIdentity,
	timeout time.Duration,
	waitExit func(processHandle, time.Duration) (bool, error),
	removePath func(string) error,
	syncParent func(string) error,
) error {
	if err := handle.Signal(syscall.SIGQUIT); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return removeStartedProcessFilesIfMatch(pidFile, identity, removePath, syncParent)
		}
		return err
	}
	exited, err := waitExit(handle, timeout)
	if err != nil {
		return err
	}
	if !exited {
		if err := handle.Signal(syscall.SIGKILL); err != nil {
			if !errors.Is(err, syscall.ESRCH) {
				return err
			}
		} else {
			exited, err = waitExit(handle, timeout)
			if err != nil {
				return err
			}
			if !exited {
				return errors.New("started OpenResty process did not exit")
			}
		}
	}
	return removeStartedProcessFilesIfMatch(pidFile, identity, removePath, syncParent)
}

func waitProcessHandleExit(handle processHandle, timeout time.Duration) (bool, error) {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
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

func removeStartedProcessFilesIfMatch(
	pidFile string,
	expected processIdentity,
	removePath func(string) error,
	syncParent func(string) error,
) error {
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
	if (pidExists && pid != expected.PID) || (recordExists && record != expected) ||
		(startRecordExists && !startRecord.matches(expected)) {
		return nil
	}
	return removeProcessPaths([]string{pidFile, pidFile + ".identity", pidFile + ".identity.pending"}, removePath, syncParent)
}

func removeProcessFilesIfMatch(
	pidFile string,
	expected processIdentity,
	removePath func(string) error,
	syncParent func(string) error,
) error {
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
	if !pidExists && !recordExists && !startRecordExists {
		return nil
	}
	if expected == (processIdentity{}) || !recordExists || record != expected || (pidExists && pid != expected.PID) ||
		(startRecordExists && !startRecord.matches(expected)) {
		return nil
	}
	return removeProcessPaths([]string{pidFile, pidFile + ".identity", pidFile + ".identity.pending"}, removePath, syncParent)
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
			removeErr = errors.Join(removeErr, err)
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
	if err != nil || pid <= 1 || string(content) != strconv.Itoa(pid)+"\n" {
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

func readOwnedProcessFile(path string, limit int64) (content []byte, exists bool, result error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer func() { result = errors.Join(result, file.Close()) }()
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
	content, err = io.ReadAll(io.LimitReader(file, limit+1))
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
		fields[5] == "" || len(fields[5]) > 64 || strings.ContainsAny(fields[5], "\r\n\x00") {
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
	expected := processStartEnvironment + "=" + token
	processRoot := filepath.Join("/proc", strconv.Itoa(pid))
	environment, environmentErr := os.ReadFile(filepath.Join(processRoot, "environ"))
	if environmentErr == nil {
		for _, value := range bytes.Split(environment, []byte{0}) {
			if string(value) == expected {
				return nil
			}
		}
	}
	commandLine, commandLineErr := os.ReadFile(filepath.Join(processRoot, "cmdline"))
	if commandLineErr == nil {
		directive := "env " + expected + ";"
		for _, argument := range bytes.Split(commandLine, []byte{0}) {
			if strings.Contains(string(argument), directive) {
				return nil
			}
		}
	}
	if errors.Is(environmentErr, os.ErrNotExist) && errors.Is(commandLineErr, os.ErrNotExist) {
		return errProcessNotRunning
	}
	if environmentErr != nil && commandLineErr != nil {
		return errors.New("inspect OpenResty start identity")
	}
	return errors.New("OpenResty process does not match the pending start identity")
}

// A /proc/<pid> file opened before the task is reaped reads ESRCH afterwards:
// an old worker exiting mid-snapshot is gone, not an unreadable identity.
func procEntryGone(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH)
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
	if procEntryGone(err) {
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
	boot, err := kernelBootID()
	if err != nil {
		return processIdentity{}, err
	}
	return processIdentity{
		PID: pid, StartTicks: start, ExecutableDevice: uint64(executableStat.Dev), ExecutableInode: uint64(executableStat.Ino),
		OwnerUID: processStat.Uid, BootID: boot,
	}, nil
}

func kernelBootID() (string, error) {
	bootID, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	boot := strings.TrimSpace(string(bootID))
	if err != nil || boot == "" || len(boot) > 64 || strings.ContainsAny(boot, "\r\n\x00") {
		return "", errors.New("OpenResty kernel boot identity is invalid")
	}
	return boot, nil
}

func kernelWorkerGeneration(master processIdentity) (workerGeneration, error) {
	if master.OwnerUID != uint32(os.Geteuid()) {
		return nil, errors.New("OpenResty master owner is invalid")
	}
	confirmed, err := kernelProcessIdentity(master.PID)
	if err != nil || confirmed != master {
		return nil, errors.Join(errors.New("OpenResty master identity changed before worker snapshot"), err)
	}
	children, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(master.PID), "task", strconv.Itoa(master.PID), "children"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errProcessNotRunning
		}
		return nil, fmt.Errorf("read OpenResty worker children: %w", err)
	}
	workers := make([]processIdentity, 0)
	for _, field := range strings.Fields(string(children)) {
		pid, err := strconv.Atoi(field)
		if err != nil || pid <= 0 || pid == master.PID {
			return nil, errors.New("invalid OpenResty worker PID in procfs")
		}
		worker, err := kernelProcessIdentity(pid)
		if errors.Is(err, errProcessNotRunning) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("inspect OpenResty worker process: %w", err)
		}
		workers = append(workers, worker)
	}
	return buildWorkerGeneration(master, workers)
}

func buildWorkerGeneration(master processIdentity, workers []processIdentity) (workerGeneration, error) {
	if master.OwnerUID != uint32(os.Geteuid()) {
		return nil, errors.New("OpenResty master owner is invalid")
	}
	generation := make(workerGeneration)
	var workerOwner uint32
	workerOwnerKnown := false
	for _, worker := range workers {
		if worker.PID <= 1 || worker.PID == master.PID || worker.StartTicks == 0 ||
			worker.ExecutableDevice != master.ExecutableDevice || worker.ExecutableInode != master.ExecutableInode || worker.BootID != master.BootID {
			return nil, errors.New("OpenResty worker identity is invalid")
		}
		if workerOwnerKnown && worker.OwnerUID != workerOwner {
			return nil, errWorkerOwnersUnstable
		}
		workerOwner = worker.OwnerUID
		workerOwnerKnown = true
		generation[workerIdentityFromProcess(worker)] = struct{}{}
	}
	if workerOwnerKnown && workerOwner == 0 {
		return nil, errWorkerOwnersUnstable
	}
	return generation, nil
}

func workerIdentityFromProcess(identity processIdentity) workerIdentity {
	return workerIdentity{
		PID: identity.PID, StartTicks: identity.StartTicks,
		ExecutableDevice: identity.ExecutableDevice, ExecutableInode: identity.ExecutableInode,
		OwnerUID: identity.OwnerUID, BootID: identity.BootID,
	}
}

// kernelWorkerShuttingDown reports whether worker still has its recorded
// identity and nginx retitled it "worker process is shutting down": it
// received the reload's graceful quit and closed its listening sockets.
func kernelWorkerShuttingDown(worker workerIdentity) bool {
	current, err := kernelProcessIdentity(worker.PID)
	if err != nil || workerIdentityFromProcess(current) != worker {
		return false
	}
	title, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(worker.PID), "cmdline"))
	return err == nil && bytes.Contains(title, []byte("worker process is shutting down"))
}

func removeProcessStartIdentity(path string, removePath func(string) error, syncParent func(string) error) error {
	return removeProcessPaths([]string{path}, removePath, syncParent)
}

func safeAbsolutePath(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path && path != string(filepath.Separator) && !strings.ContainsAny(path, "\r\n\x00")
}

func safeDirectivePath(path string) bool {
	if !safeAbsolutePath(path) {
		return false
	}
	for _, character := range path {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("/_.-", character) {
			continue
		}
		return false
	}
	return true
}

func withSeparator(path string) string {
	return path + string(filepath.Separator)
}
