//go:build !windows

package controlplaneupgrade

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/google/uuid"
)

type NativeStandaloneConfig struct {
	InstallationID     string
	ProtocolVersion    int
	ReleaseRoot        string
	LockPath           string
	SourceGitDirectory string
	ArtifactPublicKeys map[string]ed25519.PublicKey
	ControlUnit        string
	GatewayUnit        string
	ControlHealthURL   string
	GatewayHealthURL   string
	WebIndexURL        string
	// WebCAFile optionally replaces the system roots for WebIndexURL only (an
	// operator certificate that does not chain to the system store, such as a
	// temporary self-signed one). Root-owned, not group/world writable, PEM.
	WebCAFile       string
	MaintenanceFile string
	HTTPClient      *http.Client
	PollInterval    time.Duration
	StepTimeout     time.Duration
	HealthTimeout   time.Duration
	// DatabaseToolsDirectory holds pg_dump, pg_restore and psql (default
	// /usr/bin); DatabaseTimeout bounds one backup, migration or restore.
	DatabaseToolsDirectory string
	DatabaseTimeout        time.Duration
	// The transport confirms a recent successful authenticated plan-source read.
	// This gate can only narrow native runtime readiness; nil is unconfirmed.
	PlanSourceReady func() bool
}

type NativeStandaloneRunner struct {
	runner   *Runner
	executor *nativeExecutor
	lock     *os.File
	mu       sync.Mutex
	busy     atomic.Bool
	closed   atomic.Bool
}

var nativeUnitName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.@-]{0,126}\.service$`)

func NewNativeStandaloneRunner(config NativeStandaloneConfig, trust *entitlementguard.TrustStore, store *FileStore,
	now func() time.Time) (*NativeStandaloneRunner, error) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return nil, ErrInvalidConfig
	}
	runner, err := newNativeStandaloneRunner(config, trust, store, now, 0, execCommands{}, inspectNativeServiceProcess)
	if err == nil {
		runner.executor.runnerUnit = nativeRunnerUnit()
	}
	return runner, err
}

func newNativeStandaloneRunner(config NativeStandaloneConfig, trust *entitlementguard.TrustStore, store *FileStore,
	now func() time.Time, owner uint32, commands commandRunner, inspect nativeProcessInspector) (*NativeStandaloneRunner, error) {
	installationID, err := uuid.Parse(config.InstallationID)
	if err != nil || installationID == uuid.Nil || installationID.String() != config.InstallationID ||
		config.ProtocolVersion < 1 || trust == nil || store == nil || now == nil || commands == nil || inspect == nil ||
		!nativeUnitName.MatchString(config.ControlUnit) || !nativeUnitName.MatchString(config.GatewayUnit) ||
		config.ControlUnit == config.GatewayUnit {
		return nil, ErrInvalidConfig
	}
	if (config.SourceGitDirectory == "" && len(config.ArtifactPublicKeys) == 0) ||
		(len(config.ArtifactPublicKeys) != 0 && !validNativeArtifactKeys(config.ArtifactPublicKeys)) {
		return nil, ErrInvalidConfig
	}
	keys := make(map[string]ed25519.PublicKey, len(config.ArtifactPublicKeys))
	for keyID, key := range config.ArtifactPublicKeys {
		keys[keyID] = append(ed25519.PublicKey(nil), key...)
	}
	config.ArtifactPublicKeys = keys
	for _, directory := range []string{config.ReleaseRoot, filepath.Join(config.ReleaseRoot, "releases"),
		filepath.Join(config.ReleaseRoot, "artifacts"), store.root} {
		if !filepath.IsAbs(directory) || nativeOwnedDirectory(directory, owner) != nil {
			return nil, ErrInvalidConfig
		}
	}
	if config.SourceGitDirectory != "" && (!filepath.IsAbs(config.SourceGitDirectory) || nativeOwnedDirectory(config.SourceGitDirectory, owner) != nil) {
		return nil, ErrInvalidConfig
	}
	for _, filename := range []string{config.LockPath, config.MaintenanceFile} {
		if !filepath.IsAbs(filename) || filepath.Clean(filename) != filename || nativeOwnedDirectory(filepath.Dir(filename), owner) != nil {
			return nil, ErrInvalidConfig
		}
	}
	for _, address := range []string{config.ControlHealthURL, config.GatewayHealthURL, config.WebIndexURL} {
		if !validSystemdURL(address, false) {
			return nil, ErrInvalidConfig
		}
	}
	if config.PollInterval == 0 {
		config.PollInterval = time.Second
	}
	if config.StepTimeout == 0 {
		config.StepTimeout = 3 * time.Minute
	}
	if config.HealthTimeout == 0 {
		config.HealthTimeout = 2 * time.Minute
	}
	if config.DatabaseTimeout == 0 {
		config.DatabaseTimeout = 30 * time.Minute
	}
	if config.DatabaseToolsDirectory == "" {
		config.DatabaseToolsDirectory = "/usr/bin"
	}
	if config.PollInterval < time.Millisecond || config.PollInterval > time.Minute ||
		config.StepTimeout < time.Millisecond || config.StepTimeout > 30*time.Minute ||
		config.HealthTimeout < time.Millisecond || config.HealthTimeout > 10*time.Minute ||
		config.DatabaseTimeout < time.Millisecond || config.DatabaseTimeout > 2*time.Hour ||
		!filepath.IsAbs(config.DatabaseToolsDirectory) || filepath.Clean(config.DatabaseToolsDirectory) != config.DatabaseToolsDirectory {
		return nil, ErrInvalidConfig
	}
	client := config.HTTPClient
	if client == nil {
		// No whole-request timeout: every request carries a StepTimeout context, and
		// a 100MB release over a slow link needs far longer than any fixed bound.
		client = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	var webClient *http.Client
	if config.WebCAFile != "" {
		roots, err := readNativeWebCA(config.WebCAFile, owner)
		if err != nil {
			return nil, ErrInvalidConfig
		}
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
		webClient = &http.Client{Transport: transport, CheckRedirect: client.CheckRedirect}
		if webClient.CheckRedirect == nil {
			webClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		}
	}
	executor := &nativeExecutor{config: config, owner: owner, commands: commands, inspect: inspect,
		now: now, client: client, webClient: webClient, platform: NativePlatform{OS: "linux", Arch: runtime.GOARCH},
		database: nativePGTools{directory: config.DatabaseToolsDirectory}, freeSpace: nativeFreeSpace,
		backupDir: filepath.Join(store.root, nativeBackupDirectory)}
	if _, _, err := executor.current(); err != nil {
		return nil, err
	}
	lock, err := openNativeLock(filepath.Join(store.root, "runner.lock"), owner, true)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, ErrPlanInProgress
	}
	unlock := func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); _ = lock.Close() }
	maintenanceLock, err := openNativeLock(config.MaintenanceFile+".lock", owner, true)
	if err != nil {
		unlock()
		return nil, err
	}
	_ = maintenanceLock.Close()
	// Enabling this target requires a pre-provisioned, explicit native baseline.
	// Do not bootstrap a mixed deployment or clear an interrupted drain here.
	if _, err := readNativeMaintenance(config.MaintenanceFile, config.InstallationID, owner); err != nil {
		unlock()
		return nil, err
	}
	runner, err := New(Config{InstallationID: config.InstallationID, Component: "control-api", Target: TargetNativeStandalone}, trust, store, executor, now)
	if err != nil {
		unlock()
		return nil, err
	}
	runner.runLog = newRunLogWriter(store.root, now)
	return &NativeStandaloneRunner{runner: runner, executor: executor, lock: lock}, nil
}

// readNativeWebCA reads the optional WebIndexURL trust anchors with the same
// ownership rules as other runner inputs: absolute canonical path, protected
// root-owned parent chain, no symlink or extra link, not group/world writable,
// and only PEM CERTIFICATE blocks.
func readNativeWebCA(filename string, owner uint32) (*x509.CertPool, error) {
	if !filepath.IsAbs(filename) || filepath.Clean(filename) != filename || nativeOwnedDirectory(filepath.Dir(filename), owner) != nil {
		return nil, ErrInvalidConfig
	}
	encoded, err := nativeReadRegular(filename, owner, 1<<20)
	if err != nil {
		return nil, ErrInvalidConfig
	}
	roots := x509.NewCertPool()
	count := 0
	for rest := bytes.TrimSpace(encoded); len(rest) != 0; rest = bytes.TrimSpace(rest) {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, ErrInvalidConfig
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, ErrInvalidConfig
		}
		roots.AddCert(certificate)
		count++
	}
	if count == 0 {
		return nil, ErrInvalidConfig
	}
	return roots, nil
}

func (runner *NativeStandaloneRunner) Run(ctx context.Context, encoded []byte) (Receipt, error) {
	if !runner.mu.TryLock() {
		return Receipt{}, ErrPlanInProgress
	}
	defer runner.mu.Unlock()
	if runner.closed.Load() {
		return Receipt{}, ErrInvalidConfig
	}
	// Reject signature failures before creating a release lock or touching files.
	if _, err := runner.runner.verifyBundle(encoded); err != nil {
		return Receipt{}, err
	}
	lock, err := openNativeLock(runner.executor.config.LockPath, runner.executor.owner, true)
	if err != nil {
		return Receipt{}, err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return Receipt{}, ErrPlanInProgress
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	runner.busy.Store(true)
	defer runner.busy.Store(false)
	return runner.runner.Run(ctx, encoded)
}

func (runner *NativeStandaloneRunner) Probe(ctx context.Context) (NativeStandaloneStatus, error) {
	executor := runner.executor
	status := NativeStandaloneStatus{Schema: NativeStatusSchema, Reason: "control_upgrade_runner_unconfirmed",
		InstallationID: executor.config.InstallationID, ProtocolVersion: executor.config.ProtocolVersion,
		ArtifactFormat: NativeManifestSchema, RunnerPID: os.Getpid(), ObservedAt: executor.now().UTC(), Phase: "idle"}
	if runner.closed.Load() {
		return status, ErrInvalidConfig
	}
	process, err := executor.inspect(status.RunnerPID)
	if err != nil {
		return status, err
	}
	status.StartID, status.RunnerExeSHA256 = process.startID, process.digest
	artifact, manifest, err := executor.current()
	if err != nil {
		status.Reason = "control_upgrade_execution_unavailable"
		return status, err
	}
	status.CurrentVersion, status.CurrentArtifactSHA256 = manifest.Version, artifact.Digest
	status.ArtifactFormat = manifest.Schema
	status.SourceCommit, status.SourceTree = manifest.Source.Commit, manifest.Source.Tree
	maintenance, err := readNativeMaintenance(executor.config.MaintenanceFile, executor.config.InstallationID, executor.owner)
	if err != nil {
		return status, err
	}
	state, stateErr := runner.runner.store.Load()
	if stateErr != nil && !errors.Is(stateErr, ErrStateNotFound) {
		return status, stateErr
	}
	status.Busy = runner.busy.Load() || maintenance.Phase != "active" ||
		(stateErr == nil && state.Phase != PhaseCompleted && state.Phase != PhaseRolledBack && state.Phase != PhaseFailed &&
			!state.Supersedable())
	if status.Busy {
		status.Phase, status.Reason = "draining", "control_upgrade_draining"
		if stateErr == nil {
			status.Phase = string(state.Phase)
		}
		return status, nil
	}
	if manifest.Schema == NativeManifestSchema {
		if err := executor.verifySourceTree(ctx, manifest.Source); err != nil {
			return status, err
		}
	}
	if err := executor.verifyServices(ctx, manifest); err != nil {
		return status, err
	}
	if err := executor.checkHTTP(ctx, manifest); err != nil {
		return status, err
	}
	if runner.busy.Load() {
		status.Busy, status.Phase, status.Reason = true, "draining", "control_upgrade_draining"
		return status, nil
	}
	if executor.config.PlanSourceReady == nil || !executor.config.PlanSourceReady() {
		return status, nil
	}
	status.Ready, status.Reason = true, "ready"
	return status, nil
}

func (runner *NativeStandaloneRunner) PublishStatus(ctx context.Context, filename string) error {
	if !filepath.IsAbs(filename) || nativeOwnedDirectory(filepath.Dir(filename), runner.executor.owner) != nil {
		return ErrInvalidConfig
	}
	status, _ := runner.Probe(ctx)
	encoded, err := json.Marshal(status)
	if err != nil {
		return err
	}
	if err := writeAtomicFile(filepath.Dir(filename), filepath.Base(filename), encoded, 0o640); err != nil {
		return err
	}
	state, err := runner.runner.store.Load()
	if errors.Is(err, ErrStateNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	encoded, err = json.Marshal(state)
	if err != nil {
		return err
	}
	if err := writeAtomicFile(filepath.Dir(filename), filepath.Base(filename)+".state.json", encoded, 0o640); err != nil {
		return err
	}
	// The upgrade log is published beside the state; it never blocks status.
	if history, err := runner.runner.store.LoadHistory(); err == nil && history.PlanID == state.PlanID && history.Sequence == state.Sequence {
		if encoded, err := json.Marshal(history); err == nil {
			_ = writeAtomicFile(filepath.Dir(filename), filepath.Base(filename)+".history.json", encoded, 0o640)
		}
	}
	if log, ok := runner.runner.runLog.snapshot(); ok && log.PlanID == state.PlanID && log.Sequence == state.Sequence {
		if encoded, ok := encodeRunLog(&log); ok {
			_ = writeAtomicFile(filepath.Dir(filename), filepath.Base(filename)+".runlog.json", encoded, 0o640)
		}
	}
	return nil
}

func (runner *NativeStandaloneRunner) Close() error {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if runner.closed.Swap(true) {
		return nil
	}
	_ = syscall.Flock(int(runner.lock.Fd()), syscall.LOCK_UN)
	return runner.lock.Close()
}
