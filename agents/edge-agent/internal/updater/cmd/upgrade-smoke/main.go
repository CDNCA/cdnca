package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/updater"
)

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Sleep(ctx context.Context, duration time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	c.mu.Lock()
	c.now = c.now.Add(duration)
	c.mu.Unlock()
	return nil
}

type downloader struct {
	content []byte
	calls   int
	cancel  context.CancelFunc
}

func (d *downloader) Download(ctx context.Context, _ updater.DownloadRequest, writer io.Writer) error {
	d.calls++
	if d.cancel != nil {
		cancel := d.cancel
		d.cancel = nil
		_, _ = writer.Write(d.content[:len(d.content)/2])
		cancel()
		<-ctx.Done()
		return ctx.Err()
	}
	_, err := writer.Write(d.content)
	return err
}

type installer struct {
	mu               sync.Mutex
	root             string
	key              ed25519.PrivateKey
	clock            *clock
	baselinePath     string
	current          updater.ActivationReceipt
	receipts         map[string]updater.ActivationReceipt
	paths            map[string]string
	installCalls     int
	rollbackCalls    int
	uncertainInstall bool
	tamperReceipt    bool
	rollbackFailure  bool
}

func newInstaller(root, baselinePath string, key ed25519.PrivateKey, currentClock *clock) (*installer, error) {
	content, err := os.ReadFile(baselinePath)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(content)
	value := &installer{
		root: root, key: key, clock: currentClock, baselinePath: baselinePath,
		receipts: make(map[string]updater.ActivationReceipt), paths: make(map[string]string),
	}
	value.current = value.sign(updater.ActivationReceipt{
		SchemaVersion: 1, InstallerTransactionID: "sandbox-bootstrap", ReleaseSequence: 1,
		ArtifactSHA256: hex.EncodeToString(digest[:]), CurrentVersion: "1.0.0",
		Status: updater.ReceiptStatusActive, IssuedAt: currentClock.Now(),
	})
	value.paths[value.current.InstallerTransactionID] = baselinePath
	return value, nil
}

func (i *installer) sign(receipt updater.ActivationReceipt) updater.ActivationReceipt {
	if err := updater.SignReceipt(&receipt, "sandbox-installer", i.key); err != nil {
		panic(err)
	}
	return receipt
}

func (i *installer) Current(context.Context) (updater.ActivationReceipt, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.current, nil
}

func (i *installer) Install(ctx context.Context, request updater.InstallRequest) (updater.ActivationReceipt, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.installCalls++
	if request.Artifact == nil || request.StagedPath == "" {
		return updater.ActivationReceipt{}, errors.New("missing verified staging handle")
	}
	transactionDir := filepath.Join(i.root, "installer", request.InstallerTransactionID)
	if err := os.MkdirAll(transactionDir, 0o700); err != nil {
		return updater.ActivationReceipt{}, err
	}
	target := filepath.Join(transactionDir, "candidate")
	file, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		if receipt, exists := i.receipts[request.InstallerTransactionID]; exists {
			return receipt, nil
		}
		return updater.ActivationReceipt{}, err
	}
	if _, err := request.Artifact.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return updater.ActivationReceipt{}, err
	}
	hash := sha256.New()
	size, copyErr := io.Copy(io.MultiWriter(file, hash), request.Artifact)
	syncErr := file.Sync()
	closeErr := file.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil || size != request.ArtifactSize || hex.EncodeToString(hash.Sum(nil)) != request.ArtifactSHA256 {
		return updater.ActivationReceipt{}, errors.New("installer artifact binding failed")
	}
	if err := exec.CommandContext(ctx, target, "start").Run(); err != nil {
		receipt := i.sign(updater.ActivationReceipt{
			SchemaVersion: 1, InstallerTransactionID: request.InstallerTransactionID,
			ReleaseSequence: request.ReleaseSequence, ArtifactSHA256: request.ArtifactSHA256,
			CurrentVersion: request.CurrentVersion, PreviousVersion: request.TargetVersion,
			Status: updater.ReceiptStatusRolledBack, IssuedAt: i.clock.Now(),
		})
		i.receipts[request.InstallerTransactionID] = receipt
		i.current = i.restoredCurrent(request.InstallerTransactionID, request.ReleaseSequence, request.CurrentReceipt, request.TargetVersion)
		return receipt, errors.New("candidate start failed")
	}
	receipt := i.sign(updater.ActivationReceipt{
		SchemaVersion: 1, InstallerTransactionID: request.InstallerTransactionID,
		ReleaseSequence: request.ReleaseSequence, ArtifactSHA256: request.ArtifactSHA256,
		CurrentVersion: request.TargetVersion, PreviousVersion: request.CurrentVersion,
		Status: updater.ReceiptStatusActive, IssuedAt: i.clock.Now(),
	})
	i.current = receipt
	i.receipts[request.InstallerTransactionID] = receipt
	i.paths[request.InstallerTransactionID] = target
	if i.tamperReceipt {
		receipt.ArtifactSHA256 = stringsRepeat("0", 64)
		return receipt, nil
	}
	if i.uncertainInstall {
		return updater.ActivationReceipt{}, errors.New("lost response after activation")
	}
	return receipt, nil
}

func (i *installer) Query(_ context.Context, transactionID string) (updater.ActivationReceipt, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	receipt, exists := i.receipts[transactionID]
	if !exists {
		return updater.ActivationReceipt{}, updater.ErrInstallerUnknown
	}
	return receipt, nil
}

func (i *installer) Rollback(_ context.Context, request updater.RollbackRequest) (updater.ActivationReceipt, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.rollbackCalls++
	if i.rollbackFailure {
		return updater.ActivationReceipt{}, errors.New("sandbox rollback failed")
	}
	receipt := i.sign(updater.ActivationReceipt{
		SchemaVersion: 1, InstallerTransactionID: request.InstallerTransactionID,
		ReleaseSequence: request.ReleaseSequence, ArtifactSHA256: request.ArtifactSHA256,
		CurrentVersion: request.RollbackVersion, PreviousVersion: request.ExpectedCurrentVersion,
		Status: updater.ReceiptStatusRolledBack, IssuedAt: i.clock.Now(),
	})
	i.current = i.restoredCurrent(request.InstallerTransactionID, request.ReleaseSequence, request.PreviousReceipt, request.ExpectedCurrentVersion)
	i.receipts[request.InstallerTransactionID] = receipt
	return receipt, nil
}

func (i *installer) restoredCurrent(transactionID string, sequence uint64, previous updater.ActivationReceipt, failedVersion string) updater.ActivationReceipt {
	return i.sign(updater.ActivationReceipt{
		SchemaVersion: 1, InstallerTransactionID: transactionID + "-current",
		ReleaseSequence: sequence, ArtifactSHA256: previous.ArtifactSHA256,
		CurrentVersion: previous.CurrentVersion, PreviousVersion: failedVersion,
		Status: updater.ReceiptStatusActive, IssuedAt: i.clock.Now(),
	})
}

type probe struct {
	installer *installer
	cancel    context.CancelFunc
}

func (p *probe) Check(ctx context.Context, receipt updater.ActivationReceipt, _ []string) error {
	if p.cancel != nil {
		cancel := p.cancel
		p.cancel = nil
		cancel()
		return context.Canceled
	}
	p.installer.mu.Lock()
	path := p.installer.paths[receipt.InstallerTransactionID]
	p.installer.mu.Unlock()
	if path == "" {
		return errors.New("sandbox active path is missing")
	}
	return exec.CommandContext(ctx, path, "health").Run()
}

type environment struct {
	root           string
	clock          *clock
	planPrivateKey ed25519.PrivateKey
	planPublicKey  ed25519.PublicKey
	receiptPublic  ed25519.PublicKey
	downloader     *downloader
	installer      *installer
	probe          *probe
	manager        *updater.Manager
}

func newEnvironment(root, baseline string, artifact []byte, planPublic ed25519.PublicKey, planPrivate ed25519.PrivateKey, receiptPublic ed25519.PublicKey, receiptPrivate ed25519.PrivateKey) (*environment, error) {
	currentClock := &clock{now: time.Date(2026, 7, 22, 2, 0, 0, 0, time.UTC)}
	sandboxInstaller, err := newInstaller(root, baseline, receiptPrivate, currentClock)
	if err != nil {
		return nil, err
	}
	value := &environment{
		root: root, clock: currentClock, planPrivateKey: planPrivate, planPublicKey: planPublic,
		receiptPublic: receiptPublic, downloader: &downloader{content: artifact}, installer: sandboxInstaller,
	}
	value.probe = &probe{installer: sandboxInstaller}
	value.manager, err = value.newManager()
	return value, err
}

func (e *environment) newManager() (*updater.Manager, error) {
	config := updater.DefaultConfig(
		filepath.Join(e.root, "updater"), "1.0.0",
		map[string]ed25519.PublicKey{"release-key": e.planPublicKey},
		map[string]ed25519.PublicKey{"sandbox-installer": e.receiptPublic},
		e.downloader, e.installer, e.probe,
	)
	config.NodeID = "smoke-node"
	config.Clock = e.clock
	config.DiskReserveBytes = 0
	return updater.NewManager(config)
}

func (e *environment) plan(id string, revision, sequence uint64, current, target string, action updater.Action, artifact []byte) updater.Plan {
	digest := sha256.Sum256(artifact)
	plan := updater.Plan{
		SchemaVersion: 1, PlanID: id, Revision: revision, ReleaseSequence: sequence,
		IssuedAt: e.clock.Now().Add(-time.Minute), ExpiresAt: e.clock.Now().Add(time.Hour),
		Action: action, CurrentVersion: current, TargetVersion: target,
		Platform: runtime.GOOS, Architecture: runtime.GOARCH,
		Artifact:      updater.Artifact{URL: "https://release.invalid/agent?token=redacted", SHA256: hex.EncodeToString(digest[:]), Size: int64(len(artifact))},
		Compatibility: updater.Compatibility{MinAgentVersion: "1.0.0", MaxAgentVersion: "2.0.0"},
		Health: updater.HealthPolicy{
			ActivationTimeout: time.Second, ObservationWindow: 3 * time.Second,
			Interval: time.Second, ProbeTimeout: time.Second, RequiredConsecutiveSuccesses: 1,
		},
		Rollout:  updater.RolloutPolicy{Percentage: 100, CohortSalt: "smoke-rollout"},
		Rollback: updater.RollbackPolicy{Automatic: true},
	}
	if err := updater.Sign(&plan, "release-key", e.planPrivateKey); err != nil {
		panic(err)
	}
	return plan
}

func main() {
	if len(os.Args) != 5 {
		fatalf("usage: upgrade-smoke ROOT HEALTHY CRASH UNHEALTHY")
	}
	root, healthyPath, crashPath, unhealthyPath := os.Args[1], os.Args[2], os.Args[3], os.Args[4]
	planPublic, planPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fatalf("generate plan key: %v", err)
	}
	receiptPublic, receiptPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fatalf("generate receipt key: %v", err)
	}
	healthy := mustRead(healthyPath)
	crash := mustRead(crashPath)
	unhealthy := mustRead(unhealthyPath)
	newEnv := func(name string, artifact []byte) *environment {
		environment, err := newEnvironment(filepath.Join(root, name), healthyPath, artifact, planPublic, planPrivate, receiptPublic, receiptPrivate)
		if err != nil {
			fatalf("create %s environment: %v", name, err)
		}
		return environment
	}

	success := newEnv("success", healthy)
	plan := success.plan("upgrade-success", 1, 2, "1.0.0", "2.0.0", updater.ActionUpgrade, healthy)
	result, err := success.manager.Process(context.Background(), plan)
	require(err == nil && result.State == updater.StateSucceeded, "successful upgrade", result, err)
	result, err = success.manager.Process(context.Background(), plan)
	require(err == nil && result.Duplicate && success.installer.installCalls == 1, "duplicate idempotency", result, err)
	success.downloader.content = healthy
	rollbackPlan := success.plan("signed-rollback", 2, 3, "2.0.0", "1.0.0", updater.ActionRollback, healthy)
	result, err = success.manager.Process(context.Background(), rollbackPlan)
	require(err == nil && result.State == updater.StateSucceeded && result.CurrentVersion == "1.0.0", "signed rollback release", result, err)

	tamper := newEnv("artifact-tamper", append([]byte(nil), healthy...))
	tamper.downloader.content[0] ^= 0xff
	result, err = tamper.manager.Process(context.Background(), tamper.plan("tamper", 1, 2, "1.0.0", "2.0.0", updater.ActionUpgrade, healthy))
	require(errors.Is(err, updater.ErrArtifactIntegrity) && tamper.installer.installCalls == 0, "artifact tamper rejection", result, err)

	crashed := newEnv("crash", crash)
	result, err = crashed.manager.Process(context.Background(), crashed.plan("crash", 1, 2, "1.0.0", "2.0.0", updater.ActionUpgrade, crash))
	require(errors.Is(err, updater.ErrActivation) && result.State == updater.StateRolledBack, "candidate crash rollback", result, err)

	unhealthyEnv := newEnv("unhealthy", unhealthy)
	result, err = unhealthyEnv.manager.Process(context.Background(), unhealthyEnv.plan("unhealthy", 1, 2, "1.0.0", "2.0.0", updater.ActionUpgrade, unhealthy))
	require(errors.Is(err, updater.ErrHealth) && result.State == updater.StateRolledBack && unhealthyEnv.installer.rollbackCalls == 1, "health rollback", result, err)

	uncertain := newEnv("uncertain", healthy)
	uncertain.installer.uncertainInstall = true
	result, err = uncertain.manager.Process(context.Background(), uncertain.plan("uncertain", 1, 2, "1.0.0", "2.0.0", updater.ActionUpgrade, healthy))
	require(err == nil && result.State == updater.StateSucceeded && uncertain.installer.installCalls == 1, "uncertain install reconciliation", result, err)

	receiptTamper := newEnv("receipt-tamper", healthy)
	receiptTamper.installer.tamperReceipt = true
	plan = receiptTamper.plan("receipt-tamper", 1, 2, "1.0.0", "2.0.0", updater.ActionUpgrade, healthy)
	_, err = receiptTamper.manager.Process(context.Background(), plan)
	require(errors.Is(err, updater.ErrInvalidReceipt), "tampered receipt rejection", updater.Result{}, err)
	receiptTamper.installer.tamperReceipt = false
	receiptTamper.manager, err = receiptTamper.newManager()
	if err != nil {
		fatalf("restart after receipt tamper: %v", err)
	}
	result, found, err := receiptTamper.manager.Recover(context.Background())
	require(err == nil && found && result.State == updater.StateSucceeded && receiptTamper.installer.installCalls == 1, "receipt recovery query", result, err)

	interrupted := newEnv("interrupted", healthy)
	plan = interrupted.plan("interrupted", 1, 2, "1.0.0", "2.0.0", updater.ActionUpgrade, healthy)
	ctx, cancel := context.WithCancel(context.Background())
	interrupted.downloader.cancel = cancel
	_, err = interrupted.manager.Process(ctx, plan)
	require(errors.Is(err, context.Canceled), "mid-download interruption", updater.Result{}, err)
	interrupted.manager, err = interrupted.newManager()
	if err != nil {
		fatalf("restart interrupted manager: %v", err)
	}
	result, found, err = interrupted.manager.Recover(context.Background())
	require(err == nil && found && result.State == updater.StateSucceeded && interrupted.downloader.calls == 2, "journal crash recovery", result, err)

	rollbackFailure := newEnv("rollback-failure", unhealthy)
	rollbackFailure.installer.rollbackFailure = true
	result, err = rollbackFailure.manager.Process(context.Background(), rollbackFailure.plan("rollback-failure", 1, 2, "1.0.0", "2.0.0", updater.ActionUpgrade, unhealthy))
	require(errors.Is(err, updater.ErrRollback) && result.AlertRequired && result.ErrorCode == "ROLLBACK_FAILED", "rollback failure alert", result, err)

	fmt.Println("edge-agent upgrade smoke: PASS")
}

func mustRead(path string) []byte {
	value, err := os.ReadFile(path)
	if err != nil {
		fatalf("read %s: %v", path, err)
	}
	return value
}

func require(ok bool, name string, result updater.Result, err error) {
	if !ok {
		fatalf("%s failed: result=%+v error=%v", name, result, err)
	}
	fmt.Printf("ok: %s\n", name)
}

func fatalf(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", arguments...)
	os.Exit(1)
}

func stringsRepeat(value string, count int) string {
	result := ""
	for index := 0; index < count; index++ {
		result += value
	}
	return result
}
