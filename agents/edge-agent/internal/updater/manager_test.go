package updater

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/packaging/helper"
	"github.com/cdnca/cdnca/agents/edge-agent/packaging/helper/protocol"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Sleep(ctx context.Context, duration time.Duration) error {
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

type memoryDownloader struct {
	content []byte
	calls   int
	cancel  context.CancelFunc
	started chan<- struct{}
	release <-chan struct{}
}

func (d *memoryDownloader) Download(ctx context.Context, _ DownloadRequest, writer io.Writer) error {
	d.calls++
	if d.started != nil {
		d.started <- struct{}{}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-d.release:
		}
	}
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

func TestManagerDoesNotRedirectJournalAfterLockedStateReplacement(t *testing.T) {
	artifact := []byte("anchored-upgrade-artifact")
	environment := newTestEnvironment(t, artifact)
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	environment.downloader.started = started
	environment.downloader.release = release
	plan := environment.plan(t, "upgrade-anchor", 1, 2, "1.0.0", "2.0.0", ActionUpgrade, artifact)

	done := make(chan error, 1)
	go func() {
		_, err := environment.manager.Process(context.Background(), plan)
		done <- err
	}()
	<-started
	state := filepath.Join(environment.root, "state")
	original := state + "-original"
	if err := os.Rename(state, original); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(state, "transaction.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement state received journal: %v", err)
	}
	if _, err := os.Stat(filepath.Join(original, "transaction.json")); err != nil {
		t.Fatalf("anchored journal missing: %v", err)
	}
}

type sandboxInstaller struct {
	mu               sync.Mutex
	privateKey       ed25519.PrivateKey
	now              *fakeClock
	current          ActivationReceipt
	records          map[string]ActivationReceipt
	installCalls     int
	rollbackCalls    int
	uncertainInstall bool
	tamperReceipt    bool
	startFailure     bool
	rollbackFailure  bool
	queryError       error
}

func newSandboxInstaller(t *testing.T, now *fakeClock) (*sandboxInstaller, ed25519.PublicKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	baselineDigest := sha256.Sum256([]byte("baseline-v1"))
	installer := &sandboxInstaller{privateKey: privateKey, now: now, records: make(map[string]ActivationReceipt)}
	installer.current = installer.sign(ActivationReceipt{
		SchemaVersion: receiptSchemaVersion, InstallerTransactionID: "bootstrap-v1", ReleaseSequence: 1,
		ArtifactSHA256: hex.EncodeToString(baselineDigest[:]), CurrentVersion: "1.0.0",
		Status: ReceiptStatusActive, IssuedAt: now.Now(),
	})
	return installer, publicKey
}

func (i *sandboxInstaller) sign(receipt ActivationReceipt) ActivationReceipt {
	if err := SignReceipt(&receipt, "sandbox-helper", i.privateKey); err != nil {
		panic(err)
	}
	return receipt
}

func (i *sandboxInstaller) Current(context.Context) (ActivationReceipt, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.current, nil
}

func (i *sandboxInstaller) Install(_ context.Context, request InstallRequest) (ActivationReceipt, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.installCalls++
	if request.Artifact == nil || request.StagedPath == "" || !stringsContains(request.StagedPath, filepath.Join("staging", "verified")) {
		return ActivationReceipt{}, errors.New("unsafe staging request")
	}
	if _, err := request.Artifact.Seek(0, io.SeekStart); err != nil {
		return ActivationReceipt{}, err
	}
	digest := sha256.New()
	size, err := io.Copy(digest, request.Artifact)
	if err != nil || size != request.ArtifactSize || hex.EncodeToString(digest.Sum(nil)) != request.ArtifactSHA256 {
		return ActivationReceipt{}, errors.New("artifact binding mismatch")
	}
	if i.startFailure {
		receipt := i.sign(ActivationReceipt{
			SchemaVersion: receiptSchemaVersion, InstallerTransactionID: request.InstallerTransactionID,
			ReleaseSequence: request.ReleaseSequence, ArtifactSHA256: request.ArtifactSHA256,
			CurrentVersion: request.CurrentVersion, PreviousVersion: request.TargetVersion,
			Status: ReceiptStatusRolledBack, IssuedAt: i.now.Now(),
		})
		i.records[request.InstallerTransactionID] = receipt
		i.current = i.restoredCurrent(request.InstallerTransactionID, request.ReleaseSequence, request.CurrentReceipt, request.TargetVersion)
		return receipt, errors.New("sandbox target crashed")
	}
	receipt := i.sign(ActivationReceipt{
		SchemaVersion: receiptSchemaVersion, InstallerTransactionID: request.InstallerTransactionID,
		ReleaseSequence: request.ReleaseSequence, ArtifactSHA256: request.ArtifactSHA256,
		CurrentVersion: request.TargetVersion, PreviousVersion: request.CurrentVersion,
		Status: ReceiptStatusActive, IssuedAt: i.now.Now(),
	})
	i.current = receipt
	i.records[request.InstallerTransactionID] = receipt
	if i.tamperReceipt {
		receipt.CurrentVersion = "9.9.9"
		return receipt, nil
	}
	if i.uncertainInstall {
		return ActivationReceipt{}, errors.New("connection lost after activation")
	}
	return receipt, nil
}

func (i *sandboxInstaller) Query(_ context.Context, transactionID string) (ActivationReceipt, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.queryError != nil {
		return ActivationReceipt{}, i.queryError
	}
	receipt, exists := i.records[transactionID]
	if !exists {
		return ActivationReceipt{}, ErrInstallerUnknown
	}
	return receipt, nil
}

func (i *sandboxInstaller) Rollback(_ context.Context, request RollbackRequest) (ActivationReceipt, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.rollbackCalls++
	if i.rollbackFailure {
		return ActivationReceipt{}, errors.New("sandbox rollback failed")
	}
	receipt := i.sign(ActivationReceipt{
		SchemaVersion: receiptSchemaVersion, InstallerTransactionID: request.InstallerTransactionID,
		ReleaseSequence: request.ReleaseSequence, ArtifactSHA256: request.ArtifactSHA256,
		CurrentVersion: request.RollbackVersion, PreviousVersion: request.ExpectedCurrentVersion,
		Status: ReceiptStatusRolledBack, IssuedAt: i.now.Now(),
	})
	i.current = i.restoredCurrent(request.InstallerTransactionID, request.ReleaseSequence, request.PreviousReceipt, request.ExpectedCurrentVersion)
	i.records[request.InstallerTransactionID] = receipt
	return receipt, nil
}

func (i *sandboxInstaller) restoredCurrent(transactionID string, sequence uint64, previous ActivationReceipt, failedVersion string) ActivationReceipt {
	return i.sign(ActivationReceipt{
		SchemaVersion: receiptSchemaVersion, InstallerTransactionID: transactionID + "-current",
		ReleaseSequence: sequence, ArtifactSHA256: previous.ArtifactSHA256,
		CurrentVersion: previous.CurrentVersion, PreviousVersion: failedVersion,
		Status: ReceiptStatusActive, IssuedAt: i.now.Now(),
	})
}

type v2SandboxInstaller struct {
	base                           *sandboxInstaller
	prepared                       map[string]PreparedInstall
	statuses                       map[string]InstallerTransaction
	journal                        *helper.JournalStore
	beforeHelperJournalSave        func(PreparedInstall)
	beforePrepare                  func(InstallRequest)
	beforeMarkInstalling           func(PreparedInstall)
	prepareCalls                   int
	inspectCalls                   int
	activateCalls                  int
	abortCalls                     int
	legacyCalls                    int
	prepareResponseLost            bool
	activateResponseLost           bool
	activateInstallingResponseLost bool
	activateAlwaysLost             bool
}

func newV2SandboxInstaller(base *sandboxInstaller) *v2SandboxInstaller {
	return &v2SandboxInstaller{
		base: base, prepared: make(map[string]PreparedInstall), statuses: make(map[string]InstallerTransaction),
	}
}

func (*v2SandboxInstaller) ProtocolVersion() int { return InstallerProtocolV2 }

type unsupportedProtocolInstaller struct {
	*v2SandboxInstaller
}

func (*unsupportedProtocolInstaller) ProtocolVersion() int { return InstallerProtocolV3 }

func (i *v2SandboxInstaller) Current(ctx context.Context) (ActivationReceipt, error) {
	return i.base.Current(ctx)
}

func (i *v2SandboxInstaller) Install(context.Context, InstallRequest) (ActivationReceipt, error) {
	i.legacyCalls++
	return ActivationReceipt{}, errors.New("legacy Install called by v2 manager")
}

func (i *v2SandboxInstaller) Query(context.Context, string) (ActivationReceipt, error) {
	i.legacyCalls++
	return ActivationReceipt{}, errors.New("legacy Query called by v2 manager")
}

func (i *v2SandboxInstaller) Rollback(ctx context.Context, request RollbackRequest) (ActivationReceipt, error) {
	receipt, err := i.base.Rollback(ctx, request)
	if receipt.SchemaVersion != 0 {
		prepared := i.prepared[request.InstallerTransactionID]
		i.statuses[request.InstallerTransactionID] = InstallerTransaction{
			InstallerTransactionID: request.InstallerTransactionID, Phase: InstallerTransactionRolledBack,
			Prepared: prepared, Receipt: receipt,
		}
	}
	return receipt, err
}

func (i *v2SandboxInstaller) Prepare(_ context.Context, request InstallRequest) (PreparedInstall, error) {
	i.prepareCalls++
	if i.beforePrepare != nil {
		i.beforePrepare(request)
	}
	if request.Artifact == nil {
		return PreparedInstall{}, ErrInstaller
	}
	if _, err := request.Artifact.Seek(0, io.SeekStart); err != nil {
		return PreparedInstall{}, err
	}
	digest := sha256.New()
	size, err := io.Copy(digest, request.Artifact)
	if err != nil || size != request.ArtifactSize || hex.EncodeToString(digest.Sum(nil)) != request.ArtifactSHA256 {
		return PreparedInstall{}, errors.New("v2 artifact binding mismatch")
	}
	payload := preparePacketDigestForSandbox(request)
	manifest := sha256.Sum256([]byte("manifest:" + request.ArtifactSHA256))
	prepared := PreparedInstall{
		SchemaVersion: 1, InstallerTransactionID: request.InstallerTransactionID,
		InstallPayloadSHA256: payload, ReleaseSequence: request.ReleaseSequence,
		ArtifactSHA256: request.ArtifactSHA256, ManifestSHA256: hex.EncodeToString(manifest[:]),
		ExecutableSHA256: hex.EncodeToString(manifest[:]), SBOMSHA256: hex.EncodeToString(manifest[:]),
		PreviousVersion: request.CurrentVersion, TargetVersion: request.TargetVersion,
	}
	if i.journal != nil {
		record := helper.JournalRecord{
			SchemaVersion: helperJournalSchemaV2, TransactionID: prepared.InstallerTransactionID,
			Phase: helper.JournalPrepared, InstallPayloadSHA256: prepared.InstallPayloadSHA256,
			ReleaseSequence: prepared.ReleaseSequence, OuterArtifactSHA256: prepared.ArtifactSHA256,
			ManifestSHA256: prepared.ManifestSHA256, ExecutableSHA256: prepared.ExecutableSHA256,
			SBOMSHA256: prepared.SBOMSHA256, PreviousVersion: prepared.PreviousVersion,
			TargetVersion: prepared.TargetVersion, PreviousPhysicalReleaseSequence: request.CurrentReceipt.ReleaseSequence,
			PreviousManifestSHA256: sha256String([]byte("previous-manifest:" + request.CurrentReceipt.ArtifactSHA256)),
			PreviousReceipt: func() *protocol.Receipt {
				value := receiptToProtocol(request.CurrentReceipt)
				return &value
			}(),
		}
		if i.beforeHelperJournalSave != nil {
			i.beforeHelperJournalSave(prepared)
		}
		if err := i.journal.Save(record); err != nil {
			return PreparedInstall{}, err
		}
	}
	i.prepared[request.InstallerTransactionID] = prepared
	i.statuses[request.InstallerTransactionID] = InstallerTransaction{
		InstallerTransactionID: request.InstallerTransactionID, Phase: InstallerTransactionPrepared, Prepared: prepared,
	}
	if i.prepareResponseLost {
		i.prepareResponseLost = false
		return PreparedInstall{}, errors.New("prepare response lost")
	}
	return prepared, nil
}

func preparePacketDigestForSandbox(request InstallRequest) string {
	current := receiptToProtocol(request.CurrentReceipt)
	packet, err := protocol.MarshalRequest(protocol.Request{
		ProtocolVersion: protocol.JournalVersion, Operation: protocol.OperationPrepareInstall,
		TransactionID: request.InstallerTransactionID, ReleaseSequence: request.ReleaseSequence,
		CurrentVersion: request.CurrentVersion, TargetVersion: request.TargetVersion,
		Platform: request.Platform, Architecture: request.Architecture,
		ArtifactSHA256: request.ArtifactSHA256, ArtifactSize: request.ArtifactSize,
		AuditBasename: filepath.Base(request.StagedPath), CurrentReceipt: &current,
	})
	if err != nil {
		panic(err)
	}
	digest := sha256.Sum256(packet)
	return hex.EncodeToString(digest[:])
}

func (i *v2SandboxInstaller) Inspect(_ context.Context, transactionID string) (InstallerTransaction, error) {
	i.inspectCalls++
	status, found := i.statuses[transactionID]
	if !found {
		return InstallerTransaction{InstallerTransactionID: transactionID, Phase: InstallerTransactionUnknown}, nil
	}
	return status, nil
}

func (i *v2SandboxInstaller) MarkInstalling(_ context.Context, prepared PreparedInstall) (InstallerTransaction, error) {
	if i.beforeMarkInstalling != nil {
		i.beforeMarkInstalling(prepared)
	}
	if i.journal != nil {
		record, err := i.journal.Load(prepared.InstallerTransactionID)
		if err != nil || record.Phase != helper.JournalPrepared {
			return InstallerTransaction{}, ErrInstallerUncertain
		}
		record.Phase = helper.JournalInstalling
		if err := i.journal.Save(record); err != nil {
			return InstallerTransaction{}, err
		}
	}
	stored, found := i.prepared[prepared.InstallerTransactionID]
	if !found || stored != prepared {
		return InstallerTransaction{}, ErrInstallerUncertain
	}
	status, found := i.statuses[prepared.InstallerTransactionID]
	if !found || status.Phase != InstallerTransactionPrepared {
		return InstallerTransaction{}, ErrInstallerUncertain
	}
	status.Phase = InstallerTransactionInstalling
	i.statuses[prepared.InstallerTransactionID] = status
	return status, nil
}

func (i *v2SandboxInstaller) Activate(_ context.Context, prepared PreparedInstall) (ActivationReceipt, error) {
	i.activateCalls++
	stored, found := i.prepared[prepared.InstallerTransactionID]
	if !found || stored != prepared {
		return ActivationReceipt{}, ErrInstallerUncertain
	}
	if i.activateInstallingResponseLost {
		i.activateInstallingResponseLost = false
		i.statuses[prepared.InstallerTransactionID] = InstallerTransaction{
			InstallerTransactionID: prepared.InstallerTransactionID, Phase: InstallerTransactionInstalling,
			Prepared: prepared,
		}
		return ActivationReceipt{}, errors.New("activate response lost after helper entered installing")
	}
	if i.activateAlwaysLost {
		return ActivationReceipt{}, errors.New("activation response lost before durable outcome")
	}
	receipt := i.base.sign(ActivationReceipt{
		SchemaVersion: receiptSchemaVersion, InstallerTransactionID: prepared.InstallerTransactionID,
		ReleaseSequence: prepared.ReleaseSequence, ArtifactSHA256: prepared.ArtifactSHA256,
		CurrentVersion: prepared.TargetVersion, PreviousVersion: prepared.PreviousVersion,
		Status: ReceiptStatusActive, IssuedAt: i.base.now.Now(),
	})
	i.base.mu.Lock()
	i.base.current = receipt
	i.base.records[prepared.InstallerTransactionID] = receipt
	i.base.mu.Unlock()
	i.statuses[prepared.InstallerTransactionID] = InstallerTransaction{
		InstallerTransactionID: prepared.InstallerTransactionID, Phase: InstallerTransactionActive,
		Prepared: prepared, Receipt: receipt,
	}
	if i.activateResponseLost {
		i.activateResponseLost = false
		return ActivationReceipt{}, errors.New("activate response lost")
	}
	return receipt, nil
}

func (i *v2SandboxInstaller) Abort(_ context.Context, prepared PreparedInstall) (InstallerTransaction, error) {
	i.abortCalls++
	stored, found := i.prepared[prepared.InstallerTransactionID]
	if !found || stored != prepared {
		return InstallerTransaction{}, ErrInstallerUncertain
	}
	status := InstallerTransaction{
		InstallerTransactionID: prepared.InstallerTransactionID,
		Phase:                  InstallerTransactionPhase("aborted"), Prepared: prepared,
	}
	i.statuses[prepared.InstallerTransactionID] = status
	return status, nil
}

func v2ManagerForEnvironment(t *testing.T, environment *testEnvironment, installer *v2SandboxInstaller) *Manager {
	t.Helper()
	config := DefaultConfig(
		environment.root, "1.0.0", map[string]ed25519.PublicKey{"release-2026": environment.planPublicKey},
		map[string]ed25519.PublicKey{"sandbox-helper": environment.receiptPublicKey},
		environment.downloader, installer, environment.probe,
	)
	config.NodeID = "node-test-1"
	config.Platform = "linux"
	config.Architecture = "amd64"
	config.Clock = environment.now
	config.DiskReserveBytes = 0
	manager, err := NewManager(config)
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func TestManagerRejectsUnsupportedTransactionalInstallerProtocol(t *testing.T) {
	artifact := []byte("signed-agent-unsupported-installer-protocol")
	environment := newTestEnvironment(t, artifact)
	installer := &unsupportedProtocolInstaller{v2SandboxInstaller: newV2SandboxInstaller(environment.installer)}
	config := DefaultConfig(
		environment.root, "1.0.0", map[string]ed25519.PublicKey{"release-2026": environment.planPublicKey},
		map[string]ed25519.PublicKey{"sandbox-helper": environment.receiptPublicKey},
		environment.downloader, installer, environment.probe,
	)
	config.NodeID = "node-test-1"
	config.Platform = "linux"
	config.Architecture = "amd64"
	config.Clock = environment.now
	config.DiskReserveBytes = 0

	manager, err := NewManager(config)
	if manager != nil || !errors.Is(err, ErrIncompatible) {
		t.Fatalf("NewManager() = (%#v, %v), want nil ErrIncompatible", manager, err)
	}
}

func v2PlanForEnvironment(t *testing.T, environment *testEnvironment, id string, revision, releaseSequence uint64,
	current, target string, action Action, artifact []byte,
) Plan {
	t.Helper()
	plan := environment.plan(t, id, revision, releaseSequence, current, target, action, artifact)
	plan.Platform = "linux"
	plan.Architecture = "amd64"
	if err := Sign(&plan, "release-2026", environment.planPrivateKey); err != nil {
		t.Fatal(err)
	}
	return plan
}

func TestManagerV2PreparesHelperJournalBeforeActivationWithoutLegacyFallback(t *testing.T) {
	artifact := []byte("signed-agent-v2-prepare-activate")
	environment := newTestEnvironment(t, artifact)
	installer := newV2SandboxInstaller(environment.installer)
	manager := v2ManagerForEnvironment(t, environment, installer)
	plan := v2PlanForEnvironment(t, environment, "upgrade-v2-prepare", 1, 2, "1.0.0", "2.0.0", ActionUpgrade, artifact)

	prepared, err := manager.prepare(context.Background(), plan)
	if err != nil || prepared.Complete || prepared.InstallerTransactionID == "" {
		t.Fatalf("prepare = (%#v, %v)", prepared, err)
	}
	status := installer.statuses[prepared.InstallerTransactionID]
	journal, journalErr := manager.fs.loadTransaction()
	if installer.prepareCalls != 1 || installer.activateCalls != 0 || installer.legacyCalls != 0 ||
		status.Phase != InstallerTransactionPrepared || journalErr != nil || journal == nil || journal.PreparedInstall == nil ||
		*journal.PreparedInstall != status.Prepared {
		t.Fatalf("prepared ordering = (prepare=%d activate=%d legacy=%d helper=%#v journal=%#v err=%v)",
			installer.prepareCalls, installer.activateCalls, installer.legacyCalls, status, journal, journalErr)
	}

	result, err := manager.processPrepared(context.Background(), plan, prepared.InstallerTransactionID)
	if err != nil || result.State != StateSucceeded || installer.activateCalls != 1 || installer.legacyCalls != 0 {
		t.Fatalf("process prepared = (%#v, %v), activate=%d legacy=%d", result, err, installer.activateCalls, installer.legacyCalls)
	}
}

func TestManagerV2PersistsInstallingOnlyAfterHelperDurableBoundary(t *testing.T) {
	artifact := []byte("signed-agent-v2-installing-boundary")
	environment := newTestEnvironment(t, artifact)
	installer := newV2SandboxInstaller(environment.installer)
	journalDirectory := filepath.Join(t.TempDir(), "helper-state")
	if err := os.Mkdir(journalDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := helper.NewJournalStore(helper.JournalConfig{
		Directory: journalDirectory, OwnerUID: uint32(os.Geteuid()), OwnerGID: uint32(os.Getegid()),
		TrustedReceiptKeys: map[string]ed25519.PublicKey{"sandbox-helper": environment.receiptPublicKey},
	})
	if err != nil {
		t.Fatal(err)
	}
	installer.journal = journal
	manager := v2ManagerForEnvironment(t, environment, installer)
	plan := v2PlanForEnvironment(t, environment, "upgrade-v2-installing-boundary", 1, 2, "1.0.0", "2.0.0", ActionUpgrade, artifact)

	assertNotInstalling := func(boundary string) func(PreparedInstall) {
		return func(_ PreparedInstall) {
			value, err := manager.fs.loadTransaction()
			if err != nil || value == nil {
				t.Fatalf("%s transaction = (%#v, %v)", boundary, value, err)
			}
			if value.InstallStarted {
				t.Fatalf("Agent persisted installing before helper durable %s boundary: %#v", boundary, value)
			}
		}
	}
	installer.beforePrepare = func(_ InstallRequest) {
		value, loadErr := manager.fs.loadTransaction()
		if loadErr != nil || value == nil {
			t.Fatalf("before helper journal transaction = (%#v, %v)", value, loadErr)
		}
		if value.InstallStarted {
			t.Fatalf("Agent persisted installing before helper journal creation: %#v", value)
		}
	}
	installer.beforeHelperJournalSave = func(prepared PreparedInstall) {
		value, loadErr := manager.fs.loadTransaction()
		if loadErr != nil || value == nil {
			t.Fatalf("before helper journal save transaction = (%#v, %v)", value, loadErr)
		}
		if value.InstallStarted {
			t.Fatalf("Agent persisted installing before helper journal save: %#v", value)
		}
		if _, loadErr := journal.Load(prepared.InstallerTransactionID); !errors.Is(loadErr, helper.ErrJournalNotFound) {
			t.Fatalf("helper journal before save = (%v)", loadErr)
		}
	}
	installer.beforeMarkInstalling = func(prepared PreparedInstall) {
		assertNotInstalling("mark-installing")(prepared)
		record, loadErr := journal.Load(prepared.InstallerTransactionID)
		if loadErr != nil || record.Phase != helper.JournalPrepared {
			t.Fatalf("helper journal before installing = (%#v, %v)", record, loadErr)
		}
	}

	prepared, err := manager.prepare(context.Background(), plan)
	if err != nil || prepared.Complete || prepared.InstallerTransactionID == "" {
		t.Fatalf("prepare = (%#v, %v)", prepared, err)
	}
	value, err := manager.fs.loadTransaction()
	if err != nil || value == nil || value.InstallStarted {
		t.Fatalf("transaction after helper prepare = (%#v, %v)", value, err)
	}
	record, err := journal.Load(prepared.InstallerTransactionID)
	if err != nil || record.Phase != helper.JournalPrepared {
		t.Fatalf("helper journal after prepare = (%#v, %v)", record, err)
	}
	durable, err := manager.beginInstall(context.Background(), prepared.InstallerTransactionID)
	if err != nil || !durable {
		t.Fatalf("begin install = (%t, %v)", durable, err)
	}
	value, err = manager.fs.loadTransaction()
	if err != nil || value == nil || !value.InstallStarted {
		t.Fatalf("transaction after helper installing confirmation = (%#v, %v)", value, err)
	}
	record, err = journal.Load(prepared.InstallerTransactionID)
	if err != nil || record.Phase != helper.JournalInstalling {
		t.Fatalf("helper journal after installing confirmation = (%#v, %v)", record, err)
	}
}

func TestManagerV2RecoversPrepareAndActivateResponseLossByInspectOnly(t *testing.T) {
	for _, stage := range []string{"prepare", "activate"} {
		t.Run(stage, func(t *testing.T) {
			artifact := []byte("signed-agent-v2-response-loss-" + stage)
			environment := newTestEnvironment(t, artifact)
			installer := newV2SandboxInstaller(environment.installer)
			installer.prepareResponseLost = stage == "prepare"
			installer.activateResponseLost = stage == "activate"
			manager := v2ManagerForEnvironment(t, environment, installer)
			plan := v2PlanForEnvironment(t, environment, "upgrade-v2-loss-"+stage, 1, 2, "1.0.0", "2.0.0", ActionUpgrade, artifact)

			prepared, err := manager.prepare(context.Background(), plan)
			if err != nil {
				t.Fatalf("prepare after %s loss: %v", stage, err)
			}
			restarted := v2ManagerForEnvironment(t, environment, installer)
			result, err := restarted.processPrepared(context.Background(), plan, prepared.InstallerTransactionID)
			if err != nil || result.State != StateSucceeded || installer.legacyCalls != 0 || installer.inspectCalls == 0 {
				t.Fatalf("%s recovery = (%#v, %v), inspect=%d legacy=%d", stage, result, err, installer.inspectCalls, installer.legacyCalls)
			}
		})
	}
}

func TestManagerV2InstallingAfterActivationResponseLossDoesNotReactivateAcrossRestart(t *testing.T) {
	artifact := []byte("signed-agent-v2-installing-response-loss")
	environment := newTestEnvironment(t, artifact)
	installer := newV2SandboxInstaller(environment.installer)
	installer.activateInstallingResponseLost = true
	manager := v2ManagerForEnvironment(t, environment, installer)
	plan := v2PlanForEnvironment(t, environment, "upgrade-v2-installing-response-loss", 1, 2, "1.0.0", "2.0.0", ActionUpgrade, artifact)
	prepared, err := manager.prepare(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}

	result, err := manager.processPrepared(context.Background(), plan, prepared.InstallerTransactionID)
	if !errors.Is(err, ErrInstallerUncertain) || result != (Result{}) || installer.activateCalls != 1 ||
		installer.statuses[prepared.InstallerTransactionID].Phase != InstallerTransactionInstalling {
		t.Fatalf("first installing recovery = (%#v, %v), activate=%d helper=%#v",
			result, err, installer.activateCalls, installer.statuses[prepared.InstallerTransactionID])
	}
	journal, err := manager.fs.loadTransaction()
	if err != nil || journal == nil || journal.Phase != phaseInstall || journal.ActivationAttempts != 1 ||
		journal.ActiveReceipt != (ActivationReceipt{}) || journal.Result != (Result{}) {
		t.Fatalf("durable nonterminal installing state = (%#v, %v)", journal, err)
	}

	restarted := v2ManagerForEnvironment(t, environment, installer)
	result, err = restarted.processPrepared(context.Background(), plan, prepared.InstallerTransactionID)
	if !errors.Is(err, ErrInstallerUncertain) || result != (Result{}) || installer.activateCalls != 1 ||
		installer.statuses[prepared.InstallerTransactionID].Phase != InstallerTransactionInstalling {
		t.Fatalf("restarted installing recovery = (%#v, %v), activate=%d helper=%#v",
			result, err, installer.activateCalls, installer.statuses[prepared.InstallerTransactionID])
	}
	journal, err = restarted.fs.loadTransaction()
	if err != nil || journal == nil || journal.Phase != phaseInstall || journal.ActivationAttempts != 1 ||
		journal.ActiveReceipt != (ActivationReceipt{}) || journal.Result != (Result{}) {
		t.Fatalf("restarted durable nonterminal state = (%#v, %v)", journal, err)
	}
}

func TestManagerV2ExpiresPreparedTransactionThroughDurableHelperAbort(t *testing.T) {
	artifact := []byte("signed-agent-v2-expired-prepared-abort")
	environment := newTestEnvironment(t, artifact)
	installer := newV2SandboxInstaller(environment.installer)
	manager := v2ManagerForEnvironment(t, environment, installer)
	plan := v2PlanForEnvironment(t, environment, "upgrade-v2-expired-prepared", 1, 2, "1.0.0", "2.0.0", ActionUpgrade, artifact)

	prepared, err := manager.prepare(context.Background(), plan)
	if err != nil || installer.statuses[prepared.InstallerTransactionID].Phase != InstallerTransactionPrepared {
		t.Fatalf("prepare = (%#v, %v), helper=%#v", prepared, err, installer.statuses[prepared.InstallerTransactionID])
	}
	environment.now.mu.Lock()
	environment.now.now = plan.ExpiresAt
	environment.now.mu.Unlock()
	result, err := manager.processPrepared(context.Background(), plan, prepared.InstallerTransactionID)
	if !errors.Is(err, ErrExpired) || result.State != StateFailed || result.ErrorCode != "PLAN_EXPIRED" ||
		installer.abortCalls != 1 || installer.activateCalls != 0 ||
		installer.statuses[prepared.InstallerTransactionID].Phase != InstallerTransactionPhase("aborted") {
		t.Fatalf("expired prepared = (%#v, %v), abort=%d activate=%d helper=%#v",
			result, err, installer.abortCalls, installer.activateCalls, installer.statuses[prepared.InstallerTransactionID])
	}

	restarted := v2ManagerForEnvironment(t, environment, installer)
	replayed, replayErr := restarted.processPrepared(context.Background(), plan, prepared.InstallerTransactionID)
	if replayErr != nil || replayed.State != StateFailed || !replayed.Duplicate || installer.abortCalls != 1 || installer.activateCalls != 0 {
		t.Fatalf("expired terminal replay = (%#v, %v), abort=%d activate=%d", replayed, replayErr, installer.abortCalls, installer.activateCalls)
	}
}

func TestManagerV2ActivationAttemptBudgetSurvivesAgentRestart(t *testing.T) {
	artifact := []byte("signed-agent-v2-durable-activation-budget")
	environment := newTestEnvironment(t, artifact)
	installer := newV2SandboxInstaller(environment.installer)
	installer.activateAlwaysLost = true
	manager := v2ManagerForEnvironment(t, environment, installer)
	plan := v2PlanForEnvironment(t, environment, "upgrade-v2-durable-activation-budget", 1, 2, "1.0.0", "2.0.0", ActionUpgrade, artifact)
	prepared, err := manager.prepare(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.processPrepared(context.Background(), plan, prepared.InstallerTransactionID); !errors.Is(err, ErrInstallerUncertain) {
		t.Fatalf("first activation cycle error = %v", err)
	}
	if installer.activateCalls != 2 {
		t.Fatalf("first activation cycle calls = %d, want 2", installer.activateCalls)
	}
	encoded, err := os.ReadFile(filepath.Join(environment.root, "state", "transaction.json"))
	if err != nil {
		t.Fatal(err)
	}
	var durable map[string]any
	if err := json.Unmarshal(encoded, &durable); err != nil || durable["activation_attempts"] != float64(2) {
		t.Fatalf("durable activation budget = %#v, err=%v", durable["activation_attempts"], err)
	}

	restarted := v2ManagerForEnvironment(t, environment, installer)
	if _, err := restarted.processPrepared(context.Background(), plan, prepared.InstallerTransactionID); !errors.Is(err, ErrInstallerUncertain) {
		t.Fatalf("restarted activation error = %v", err)
	}
	if installer.activateCalls != 2 {
		t.Fatalf("activation budget reset across restart: calls=%d", installer.activateCalls)
	}
}

func TestManagerV2RevalidatesCanonicalPrepareDigestAcrossInspectRestartAndActivate(t *testing.T) {
	artifact := []byte("signed-agent-v2-prepare-digest-revalidation")
	environment := newTestEnvironment(t, artifact)
	installer := newV2SandboxInstaller(environment.installer)
	manager := v2ManagerForEnvironment(t, environment, installer)
	plan := v2PlanForEnvironment(t, environment, "upgrade-v2-prepare-digest-revalidation", 1, 2, "1.0.0", "2.0.0", ActionUpgrade, artifact)
	prepared, err := manager.prepare(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	value, err := manager.fs.loadTransaction()
	if err != nil || value == nil || value.PreparedInstall == nil {
		t.Fatalf("load prepared transaction = (%#v, %v)", value, err)
	}
	tamperedDigest := sha256.Sum256([]byte("different-canonical-prepare-request"))
	tampered := *value.PreparedInstall
	tampered.InstallPayloadSHA256 = hex.EncodeToString(tamperedDigest[:])
	value.PreparedInstall = &tampered
	if err := manager.fs.saveTransaction(value); err != nil {
		t.Fatal(err)
	}
	installer.prepared[prepared.InstallerTransactionID] = tampered
	status := installer.statuses[prepared.InstallerTransactionID]
	status.Prepared = tampered
	installer.statuses[prepared.InstallerTransactionID] = status

	restarted := v2ManagerForEnvironment(t, environment, installer)
	_, err = restarted.processPrepared(context.Background(), plan, prepared.InstallerTransactionID)
	if err == nil || !(errors.Is(err, ErrInstallerUncertain) || errors.Is(err, ErrCorruptState)) || installer.activateCalls != 0 {
		t.Fatalf("tampered prepare binding = %v, activate=%d", err, installer.activateCalls)
	}
}

type fakeProbe struct {
	mu       sync.Mutex
	errors   []error
	cancel   context.CancelFunc
	evidence ConfigProbeEvidence
}

func (p *fakeProbe) Check(_ context.Context, _ ActivationReceipt, _ []string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cancel != nil {
		cancel := p.cancel
		p.cancel = nil
		cancel()
		return context.Canceled
	}
	if len(p.errors) == 0 {
		return nil
	}
	err := p.errors[0]
	p.errors = p.errors[1:]
	return err
}

func (p *fakeProbe) Evidence(_ context.Context, _ ActivationReceipt, _ []string) (ConfigProbeEvidence, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.evidence, nil
}

type testEnvironment struct {
	root             string
	now              *fakeClock
	planPublicKey    ed25519.PublicKey
	planPrivateKey   ed25519.PrivateKey
	receiptPublicKey ed25519.PublicKey
	downloader       *memoryDownloader
	installer        *sandboxInstaller
	probe            *fakeProbe
	manager          *Manager
}

func newTestEnvironment(t *testing.T, artifact []byte) *testEnvironment {
	t.Helper()
	planPublicKey, planPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := &fakeClock{now: time.Date(2026, 7, 22, 1, 0, 0, 0, time.UTC)}
	installer, receiptPublicKey := newSandboxInstaller(t, now)
	activeConfig := sha256.Sum256([]byte("active-config"))
	lastKnownGoodConfig := sha256.Sum256([]byte("lkg-config"))
	environment := &testEnvironment{
		root: t.TempDir(), now: now, planPublicKey: planPublicKey, planPrivateKey: planPrivateKey,
		receiptPublicKey: receiptPublicKey, downloader: &memoryDownloader{content: artifact},
		installer: installer, probe: &fakeProbe{evidence: ConfigProbeEvidence{
			ActiveConfigSHA256:        hex.EncodeToString(activeConfig[:]),
			LastKnownGoodConfigSHA256: hex.EncodeToString(lastKnownGoodConfig[:]),
		}},
	}
	environment.manager = environment.newManager(t)
	return environment
}

func (e *testEnvironment) newManager(t *testing.T) *Manager {
	t.Helper()
	config := DefaultConfig(
		e.root, "1.0.0", map[string]ed25519.PublicKey{"release-2026": e.planPublicKey},
		map[string]ed25519.PublicKey{"sandbox-helper": e.receiptPublicKey}, e.downloader, e.installer, e.probe,
	)
	config.NodeID = "node-test-1"
	config.Clock = e.now
	config.DiskReserveBytes = 0
	manager, err := NewManager(config)
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func (e *testEnvironment) plan(t *testing.T, id string, revision, releaseSequence uint64, current, target string, action Action, artifact []byte) Plan {
	t.Helper()
	digest := sha256.Sum256(artifact)
	plan := Plan{
		SchemaVersion: planSchemaVersion, PlanID: id, Revision: revision, ReleaseSequence: releaseSequence,
		IssuedAt: e.now.Now().Add(-time.Minute), ExpiresAt: e.now.Now().Add(time.Hour),
		Action: action, CurrentVersion: current, TargetVersion: target,
		Platform: runtime.GOOS, Architecture: runtime.GOARCH,
		Artifact:      Artifact{URL: "https://releases.example.test/artifact?token=secret", SHA256: hex.EncodeToString(digest[:]), Size: int64(len(artifact))},
		Compatibility: Compatibility{MinAgentVersion: "1.0.0", MaxAgentVersion: "2.0.0"},
		Health: HealthPolicy{
			ActivationTimeout: time.Second, ObservationWindow: 3 * time.Second,
			Interval: time.Second, ProbeTimeout: time.Second, RequiredConsecutiveSuccesses: 1,
		},
		Rollout:  RolloutPolicy{Percentage: 100, CohortSalt: "rollout-2026"},
		Rollback: RollbackPolicy{Automatic: true},
	}
	if err := Sign(&plan, "release-2026", e.planPrivateKey); err != nil {
		t.Fatal(err)
	}
	return plan
}

func TestUpgradeSucceedsAndDuplicateIsIdempotent(t *testing.T) {
	artifact := []byte("signed-agent-v2")
	environment := newTestEnvironment(t, artifact)
	plan := environment.plan(t, "upgrade-2", 1, 2, "1.0.0", "2.0.0", ActionUpgrade, artifact)
	result, err := environment.manager.Process(context.Background(), plan)
	if err != nil || result.State != StateSucceeded || result.ReleaseSequence != 2 || result.CurrentVersion != "2.0.0" ||
		result.PreviousVersion != "1.0.0" || result.InstallerTransactionID == "" || result.ErrorCode != "" || result.AlertRequired {
		t.Fatalf("upgrade result = %+v, error = %v", result, err)
	}
	duplicate, err := environment.manager.Process(context.Background(), plan)
	if err != nil || !duplicate.Duplicate || environment.installer.installCalls != 1 || environment.downloader.calls != 1 {
		t.Fatalf("duplicate = %+v, error = %v, install calls = %d", duplicate, err, environment.installer.installCalls)
	}
	changed := plan
	changed.ReleaseSequence++
	if err := Sign(&changed, "release-2026", environment.planPrivateKey); err != nil {
		t.Fatal(err)
	}
	if _, err := environment.manager.Process(context.Background(), changed); !errors.Is(err, ErrReplay) {
		t.Fatalf("changed replay error = %v", err)
	}
}

func TestPreparedUpgradePersistsExactTransactionBeforeExecution(t *testing.T) {
	artifact := []byte("signed-agent-v2")
	environment := newTestEnvironment(t, artifact)
	plan := environment.plan(t, "upgrade-prepared", 1, 2, "1.0.0", "2.0.0", ActionUpgrade, artifact)

	prepared, err := environment.manager.prepare(context.Background(), plan)
	if err != nil || prepared.Complete || prepared.InstallerTransactionID == "" || environment.installer.installCalls != 0 {
		t.Fatalf("prepare = (%+v, %v), install calls = %d", prepared, err, environment.installer.installCalls)
	}
	restarted := environment.newManager(t)
	resumed, err := restarted.prepare(context.Background(), plan)
	if err != nil || resumed.Complete || resumed.InstallerTransactionID != prepared.InstallerTransactionID {
		t.Fatalf("resumed prepare = (%+v, %v), want transaction %q", resumed, err, prepared.InstallerTransactionID)
	}
	if _, err := restarted.processPrepared(context.Background(), plan, prepared.InstallerTransactionID+"-wrong"); !errors.Is(err, ErrReplay) {
		t.Fatalf("wrong transaction error = %v", err)
	}
	result, err := restarted.processPrepared(context.Background(), plan, prepared.InstallerTransactionID)
	if err != nil || result.State != StateSucceeded || environment.installer.installCalls != 1 {
		t.Fatalf("process prepared = (%+v, %v), install calls = %d", result, err, environment.installer.installCalls)
	}
	complete, err := environment.manager.prepare(context.Background(), plan)
	if err != nil || !complete.Complete || !complete.Result.Duplicate ||
		complete.InstallerTransactionID != prepared.InstallerTransactionID || environment.installer.installCalls != 1 {
		t.Fatalf("completed prepare = (%+v, %v), install calls = %d", complete, err, environment.installer.installCalls)
	}
}

func TestManagerRecoverRejectsJournalPlanDigestDriftBeforeExecution(t *testing.T) {
	artifact := []byte("journal-binding-artifact")
	environment := newTestEnvironment(t, artifact)
	plan := environment.plan(t, "recover-journal-binding", 1, 2, "1.0.0", "2.0.0", ActionUpgrade, artifact)
	prepared, err := environment.manager.prepare(context.Background(), plan)
	if err != nil || prepared.Complete || environment.downloader.calls != 0 || environment.installer.installCalls != 0 {
		t.Fatalf("prepare = (%+v, %v), downloader=%d installer=%d", prepared, err, environment.downloader.calls, environment.installer.installCalls)
	}
	journal, err := environment.manager.store.loadTransaction()
	if err != nil || journal == nil {
		t.Fatalf("load journal = (%+v, %v)", journal, err)
	}
	journal.Digest = sha256String([]byte("valid-but-wrong-plan-digest"))
	if err := writeJSONAtomic(environment.manager.store.journalPath, journal); err != nil {
		t.Fatal(err)
	}

	_, found, err := environment.newManager(t).Recover(context.Background())
	if !errors.Is(err, ErrCorruptState) && !errors.Is(err, ErrReplay) {
		t.Fatalf("digest-drift recovery error = %v", err)
	}
	if found || environment.downloader.calls != 0 || environment.installer.installCalls != 0 {
		t.Fatalf("digest-drift recovery effects = (found=%t downloader=%d installer=%d)", found, environment.downloader.calls, environment.installer.installCalls)
	}
}

func TestUncertainInstallReconcilesSignedReceipt(t *testing.T) {
	artifact := []byte("signed-agent-v2")
	environment := newTestEnvironment(t, artifact)
	environment.installer.uncertainInstall = true
	plan := environment.plan(t, "upgrade-uncertain", 1, 2, "1.0.0", "2.0.0", ActionUpgrade, artifact)
	result, err := environment.manager.Process(context.Background(), plan)
	if err != nil || result.State != StateSucceeded || environment.installer.installCalls != 1 {
		t.Fatalf("uncertain install result = %+v, error = %v", result, err)
	}
}

func TestInstallerStartFailureAndHealthFailureRollback(t *testing.T) {
	t.Run("installer already rolled back crash", func(t *testing.T) {
		artifact := []byte("crashing-agent-v2")
		environment := newTestEnvironment(t, artifact)
		environment.installer.startFailure = true
		plan := environment.plan(t, "upgrade-crash", 1, 2, "1.0.0", "2.0.0", ActionUpgrade, artifact)
		result, err := environment.manager.Process(context.Background(), plan)
		if !errors.Is(err, ErrActivation) || result.State != StateRolledBack || result.CurrentVersion != "1.0.0" ||
			result.PreviousVersion != "2.0.0" || result.InstallerTransactionID == "" || result.ErrorCode != "INSTALLER_ROLLED_BACK" {
			t.Fatalf("crash result = %+v, error = %v", result, err)
		}
	})

	t.Run("health gate requests rollback", func(t *testing.T) {
		artifact := []byte("unhealthy-agent-v2")
		environment := newTestEnvironment(t, artifact)
		environment.probe.errors = []error{nil, errors.New("unhealthy")}
		plan := environment.plan(t, "upgrade-unhealthy", 1, 2, "1.0.0", "2.0.0", ActionUpgrade, artifact)
		result, err := environment.manager.Process(context.Background(), plan)
		if !errors.Is(err, ErrHealth) || result.State != StateRolledBack || environment.installer.rollbackCalls != 1 ||
			result.CurrentVersion != "1.0.0" || result.PreviousVersion != "2.0.0" || result.ErrorCode != "HEALTH_FAILED" {
			t.Fatalf("health result = %+v, error = %v", result, err)
		}
		current, currentErr := environment.manager.Current(context.Background())
		if currentErr != nil || current.CurrentVersion != "1.0.0" || current.ReleaseSequence != 2 {
			t.Fatalf("restored current = %+v, %v", current, currentErr)
		}
	})
}

func TestRollbackFailureRaisesAlert(t *testing.T) {
	artifact := []byte("unhealthy-agent-v2")
	environment := newTestEnvironment(t, artifact)
	environment.probe.errors = []error{nil, errors.New("unhealthy")}
	environment.installer.rollbackFailure = true
	plan := environment.plan(t, "upgrade-rollback-fails", 1, 2, "1.0.0", "2.0.0", ActionUpgrade, artifact)
	result, err := environment.manager.Process(context.Background(), plan)
	if !errors.Is(err, ErrRollback) || result.State != StateFailed || !result.AlertRequired || result.ErrorCode != "HEALTH_FAILED" ||
		result.CurrentVersion != "2.0.0" || result.PreviousVersion != "1.0.0" || result.InstallerTransactionID == "" {
		t.Fatalf("rollback failure = %+v, error = %v", result, err)
	}
	duplicate, err := environment.manager.Process(context.Background(), plan)
	if err != nil || !duplicate.Duplicate || duplicate.ErrorCode != "HEALTH_FAILED" || environment.installer.rollbackCalls != 1 {
		t.Fatalf("rollback failure replay = %+v, error = %v, rollback calls = %d", duplicate, err, environment.installer.rollbackCalls)
	}
}

func TestRollbackFailureWithUnknownInstalledStateOmitsVersionTuple(t *testing.T) {
	artifact := []byte("unhealthy-agent-v2")
	environment := newTestEnvironment(t, artifact)
	environment.probe.errors = []error{nil, errors.New("unhealthy")}
	environment.installer.rollbackFailure = true
	environment.installer.queryError = errors.New("installer query unavailable")
	plan := environment.plan(t, "upgrade-rollback-unknown", 1, 2, "1.0.0", "2.0.0", ActionUpgrade, artifact)
	result, err := environment.manager.Process(context.Background(), plan)
	if !errors.Is(err, ErrRollback) || result.State != StateFailed || result.CurrentVersion != "" || result.PreviousVersion != "" ||
		result.InstallerTransactionID == "" || result.ErrorCode != "ROLLBACK_FAILED" || !result.AlertRequired {
		t.Fatalf("unknown rollback failure = %+v, error = %v", result, err)
	}
	journal, journalErr := environment.manager.store.loadTransaction()
	if journalErr != nil || journal == nil || journal.Phase != phaseRollback || journal.ErrorCode != "HEALTH_FAILED" {
		t.Fatalf("recoverable rollback journal = (%+v, %v)", journal, journalErr)
	}
	environment.installer.queryError = nil
	reconciled, found, err := environment.newManager(t).Recover(context.Background())
	if !errors.Is(err, ErrRollback) || !found || reconciled.State != StateFailed ||
		reconciled.CurrentVersion != "2.0.0" || reconciled.PreviousVersion != "1.0.0" ||
		reconciled.ErrorCode != "HEALTH_FAILED" || !reconciled.AlertRequired {
		t.Fatalf("reconciled rollback failure = (%+v, %t, %v)", reconciled, found, err)
	}
}

func TestTamperedReceiptIsRejectedThenRecoveredByQuery(t *testing.T) {
	artifact := []byte("signed-agent-v2")
	environment := newTestEnvironment(t, artifact)
	environment.installer.tamperReceipt = true
	plan := environment.plan(t, "upgrade-tampered-receipt", 1, 2, "1.0.0", "2.0.0", ActionUpgrade, artifact)
	if _, err := environment.manager.Process(context.Background(), plan); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("tampered receipt error = %v", err)
	}
	environment.installer.tamperReceipt = false
	restarted := environment.newManager(t)
	result, found, err := restarted.Recover(context.Background())
	if err != nil || !found || result.State != StateSucceeded || environment.installer.installCalls != 1 {
		t.Fatalf("receipt recovery = (%+v, %v, %v)", result, found, err)
	}
}

func TestInterruptedDownloadAndObservationRecoverFromJournal(t *testing.T) {
	t.Run("download", func(t *testing.T) {
		artifact := bytes.Repeat([]byte("agent"), 32)
		environment := newTestEnvironment(t, artifact)
		plan := environment.plan(t, "upgrade-download-interrupted", 1, 2, "1.0.0", "2.0.0", ActionUpgrade, artifact)
		ctx, cancel := context.WithCancel(context.Background())
		environment.downloader.cancel = cancel
		if _, err := environment.manager.Process(ctx, plan); !errors.Is(err, context.Canceled) {
			t.Fatalf("interrupted download error = %v", err)
		}
		result, found, err := environment.newManager(t).Recover(context.Background())
		if err != nil || !found || result.State != StateSucceeded || environment.downloader.calls != 2 {
			t.Fatalf("download recovery = (%+v, %v, %v)", result, found, err)
		}
	})

	t.Run("observation", func(t *testing.T) {
		artifact := []byte("agent-v2")
		environment := newTestEnvironment(t, artifact)
		plan := environment.plan(t, "upgrade-observe-interrupted", 1, 2, "1.0.0", "2.0.0", ActionUpgrade, artifact)
		ctx, cancel := context.WithCancel(context.Background())
		environment.probe.cancel = cancel
		if _, err := environment.manager.Process(ctx, plan); !errors.Is(err, context.Canceled) {
			t.Fatalf("interrupted observation error = %v", err)
		}
		result, found, err := environment.newManager(t).Recover(context.Background())
		if err != nil || !found || result.State != StateSucceeded || environment.installer.installCalls != 1 {
			t.Fatalf("observation recovery = (%+v, %v, %v)", result, found, err)
		}
	})
}

func TestExplicitSignedRollbackUsesHigherReleaseSequence(t *testing.T) {
	v2 := []byte("signed-agent-v2")
	environment := newTestEnvironment(t, v2)
	upgrade := environment.plan(t, "upgrade-2", 1, 2, "1.0.0", "2.0.0", ActionUpgrade, v2)
	if _, err := environment.manager.Process(context.Background(), upgrade); err != nil {
		t.Fatal(err)
	}
	v1 := []byte("baseline-v1")
	environment.downloader.content = v1
	rollback := environment.plan(t, "rollback-1", 2, 3, "2.0.0", "1.0.0", ActionRollback, v1)
	result, err := environment.manager.Process(context.Background(), rollback)
	if err != nil || result.State != StateSucceeded || result.CurrentVersion != "1.0.0" || result.PreviousVersion != "2.0.0" ||
		result.InstallerTransactionID == "" || result.ReleaseSequence != 3 {
		t.Fatalf("signed rollback = %+v, %v", result, err)
	}
}

func TestManagerV3UsesExecutionHighWaterAndAllowsOlderRollbackArtifact(t *testing.T) {
	forwardArtifact := []byte("signed-agent-v2-v3-contract")
	environment := newTestEnvironment(t, forwardArtifact)
	makeV3 := func(plan Plan, executionSequence, releaseSequence uint64) Plan {
		plan.SchemaVersion = planSchemaVersionV3
		plan.Domain = upgradeExecutionEdgeDomainV3
		plan.PlanID = "00000000-0000-4000-8000-000000000901"
		plan.BatchID = "00000000-0000-4000-8000-000000000902"
		plan.ArtifactBundleID = "00000000-0000-4000-8000-000000000903"
		plan.ArtifactBundleSHA256 = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x91}, sha256.Size))
		plan.CommandIssuanceNotAfter = plan.ExpiresAt.Add(time.Hour).Unix()
		plan.ExecutionSequence = executionSequence
		plan.ReleaseSequence = releaseSequence
		plan.Health.Command = []string{"{artifact}", "--version"}
		if err := Sign(&plan, "release-2026", environment.planPrivateKey); err != nil {
			t.Fatal(err)
		}
		return plan
	}
	forward := makeV3(environment.plan(t, "ignored", 1, 12, "1.0.0", "2.0.0", ActionUpgrade, forwardArtifact), 20, 12)
	first, err := environment.manager.Process(context.Background(), forward)
	if err != nil || first.ExecutionSequence != 20 || first.ReleaseSequence != 12 {
		t.Fatalf("forward result = (%#v, %v)", first, err)
	}
	rollbackArtifact := []byte("signed-agent-v1-v3-contract")
	environment.downloader.content = rollbackArtifact
	rollback := makeV3(environment.plan(t, "ignored", 2, 4, "2.0.0", "1.0.0", ActionRollback, rollbackArtifact), 21, 4)
	rolledBack, err := environment.manager.Process(context.Background(), rollback)
	if err != nil || rolledBack.ExecutionSequence != 21 || rolledBack.ReleaseSequence != 4 || rolledBack.CurrentVersion != "1.0.0" {
		t.Fatalf("rollback result = (%#v, %v)", rolledBack, err)
	}
	environment.downloader.content = forwardArtifact
	reuseForward := makeV3(environment.plan(t, "ignored", 3, 12, "1.0.0", "2.0.0", ActionUpgrade, forwardArtifact), 22, 12)
	reused, err := environment.manager.Process(context.Background(), reuseForward)
	if err != nil || reused.ExecutionSequence != 22 || reused.ReleaseSequence != 12 || reused.CurrentVersion != "2.0.0" {
		t.Fatalf("reused forward result = (%#v, %v)", reused, err)
	}
	conflict := reuseForward
	conflict.Artifact.SHA256 = strings.Repeat("a", sha256.Size*2)
	if err := Sign(&conflict, "release-2026", environment.planPrivateKey); err != nil {
		t.Fatal(err)
	}
	if _, err := environment.manager.Process(context.Background(), conflict); !errors.Is(err, ErrReplay) {
		t.Fatalf("same execution conflicting bundle error = %v", err)
	}
	lower := reuseForward
	lower.ExecutionSequence = 21
	if err := Sign(&lower, "release-2026", environment.planPrivateKey); err != nil {
		t.Fatal(err)
	}
	if _, err := environment.manager.Process(context.Background(), lower); !errors.Is(err, ErrReplay) {
		t.Fatalf("lower execution sequence error = %v", err)
	}
}

func TestArtifactAndPlanValidationFailuresDoNotCallInstaller(t *testing.T) {
	artifact := []byte("expected-agent-v2")
	environment := newTestEnvironment(t, []byte("tampered-agent-v2"))
	plan := environment.plan(t, "upgrade-tampered", 1, 2, "1.0.0", "2.0.0", ActionUpgrade, artifact)
	result, err := environment.manager.Process(context.Background(), plan)
	if !errors.Is(err, ErrArtifactIntegrity) || result.State != StateFailed || environment.installer.installCalls != 0 ||
		result.CurrentVersion != "1.0.0" || result.PreviousVersion != "" || result.InstallerTransactionID == "" ||
		result.ErrorCode != "ARTIFACT_INTEGRITY_FAILED" || !result.AlertRequired {
		t.Fatalf("tamper result = %+v, error = %v", result, err)
	}

	for _, test := range []struct {
		name   string
		mutate func(*Plan, *testEnvironment)
		resign bool
		want   error
	}{
		{name: "tampered signature", mutate: func(plan *Plan, _ *testEnvironment) { plan.TargetVersion = "3.0.0" }, want: ErrInvalidSignature},
		{name: "unknown key", mutate: func(plan *Plan, _ *testEnvironment) { plan.Signature.KeyID = "unknown" }, want: ErrUnknownKey},
		{name: "expired", mutate: func(plan *Plan, environment *testEnvironment) { plan.ExpiresAt = environment.now.Now() }, resign: true, want: ErrExpired},
		{name: "path traversal", mutate: func(plan *Plan, _ *testEnvironment) { plan.PlanID = "../escape" }, resign: true, want: ErrInvalidPlan},
		{name: "downgrade without rollback action", mutate: func(plan *Plan, _ *testEnvironment) { plan.CurrentVersion, plan.TargetVersion = "2.0.0", "1.0.0" }, resign: true, want: ErrDowngrade},
		{name: "wrong architecture", mutate: func(plan *Plan, _ *testEnvironment) { plan.Architecture = "not-this-architecture" }, resign: true, want: ErrIncompatible},
		{name: "outside rollout", mutate: func(plan *Plan, environment *testEnvironment) {
			plan.Rollout.Percentage = 1
			for index := 0; ; index++ {
				candidate := fmt.Sprintf("node-outside-%d", index)
				digest := sha256.Sum256([]byte(plan.Rollout.CohortSalt + "\x00" + candidate))
				if (uint16(digest[0])<<8|uint16(digest[1]))%10000 >= 100 {
					environment.manager.config.NodeID = candidate
					break
				}
			}
		}, resign: true, want: ErrRolloutIneligible},
	} {
		t.Run(test.name, func(t *testing.T) {
			environment := newTestEnvironment(t, artifact)
			plan := environment.plan(t, "upgrade-2", 1, 2, "1.0.0", "2.0.0", ActionUpgrade, artifact)
			test.mutate(&plan, environment)
			if test.resign {
				if err := Sign(&plan, "release-2026", environment.planPrivateKey); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := environment.manager.Process(context.Background(), plan); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestInsufficientDiskAndOversizeAreRejectedBeforeInstaller(t *testing.T) {
	artifact := []byte("agent-v2")
	disk := newTestEnvironment(t, artifact)
	disk.manager.config.DiskReserveBytes = int64(^uint64(0) >> 1)
	result, err := disk.manager.Process(context.Background(), disk.plan(t, "no-disk", 1, 2, "1.0.0", "2.0.0", ActionUpgrade, artifact))
	if !errors.Is(err, ErrInsufficientDisk) || result.ErrorCode != "INSUFFICIENT_DISK" || disk.installer.installCalls != 0 {
		t.Fatalf("disk rejection = %+v, %v", result, err)
	}

	oversize := newTestEnvironment(t, artifact)
	plan := oversize.plan(t, "oversize", 1, 2, "1.0.0", "2.0.0", ActionUpgrade, artifact)
	plan.Artifact.Size = oversize.manager.config.MaxArtifactBytes + 1
	if err := Sign(&plan, "release-2026", oversize.planPrivateKey); err != nil {
		t.Fatal(err)
	}
	if _, err := oversize.manager.Process(context.Background(), plan); !errors.Is(err, ErrArtifactTooLarge) {
		t.Fatalf("oversize error = %v", err)
	}
}

func TestStoreRejectsSymlinkAndHardlinkStaging(t *testing.T) {
	store, err := newDiskStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	unsafe := filepath.Join(store.stagingDir, "pending-unsafe")
	if err := os.Symlink(outside, unsafe); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.prepareStaging("unsafe"); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("symlink staging error = %v", err)
	}
	if err := os.Remove(unsafe); err != nil {
		t.Fatal(err)
	}
	file, path, err := store.prepareStaging("hardlink")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("artifact")); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, filepath.Join(outside, "linked")); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("artifact"))
	if _, err := store.commitStaging("hardlink", path, hex.EncodeToString(digest[:]), int64(len("artifact"))); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("hardlink staging error = %v", err)
	}
}

func TestStoreRejectsPermissiveRootAndSymlinkLock(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := newDiskStore(root); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("permissive root error = %v", err)
	}

	root = t.TempDir()
	store, err := newDiskStore(root)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "lock")
	if err := os.WriteFile(target, []byte("lock"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, store.lockPath); err != nil {
		t.Fatal(err)
	}
	if _, err := store.lock(context.Background()); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("symlink lock error = %v", err)
	}
}

func stringsContains(value, part string) bool {
	return len(value) >= len(part) && bytes.Contains([]byte(value), []byte(part))
}
