package updater

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/packaging/helper"
)

const helperJournalSchemaV2 = 2

type journalOrderV2Installer struct {
	*v2SandboxInstaller
	journal                           *helper.JournalStore
	beforeActivate                    func(PreparedInstall)
	skipJournal                       bool
	reportWithoutJournal              bool
	reportInstallingWithoutJournal    bool
	reportInstallingAfterFirstInspect bool
	initialSettledPhase               InstallerTransactionPhase
	settledReceipts                   map[string]ActivationReceipt
	settledCurrent                    map[string]ActivationReceipt
	inspectErrors                     int
}

func (installer *journalOrderV2Installer) Prepare(ctx context.Context, request InstallRequest) (PreparedInstall, error) {
	prepared, err := installer.v2SandboxInstaller.Prepare(ctx, request)
	if err != nil {
		return PreparedInstall{}, err
	}
	if installer.skipJournal {
		return prepared, nil
	}
	previous := receiptToProtocol(request.CurrentReceipt)
	record := helper.JournalRecord{
		SchemaVersion: helperJournalSchemaV2, TransactionID: prepared.InstallerTransactionID,
		Phase: helper.JournalPrepared, InstallPayloadSHA256: prepared.InstallPayloadSHA256,
		ReleaseSequence: prepared.ReleaseSequence, OuterArtifactSHA256: prepared.ArtifactSHA256,
		ManifestSHA256: prepared.ManifestSHA256, ExecutableSHA256: prepared.ExecutableSHA256,
		SBOMSHA256: prepared.SBOMSHA256, PreviousVersion: prepared.PreviousVersion,
		TargetVersion: prepared.TargetVersion, PreviousPhysicalReleaseSequence: request.CurrentReceipt.ReleaseSequence,
		PreviousManifestSHA256: sha256String([]byte("previous-manifest:" + request.CurrentReceipt.ArtifactSHA256)),
		PreviousReceipt:        &previous,
	}
	if err := installer.journal.Save(record); err != nil {
		delete(installer.prepared, prepared.InstallerTransactionID)
		delete(installer.statuses, prepared.InstallerTransactionID)
		return PreparedInstall{}, err
	}
	if installer.initialSettledPhase == InstallerTransactionActive || installer.initialSettledPhase == InstallerTransactionRolledBack {
		receipt := ActivationReceipt{
			SchemaVersion: receiptSchemaVersion, InstallerTransactionID: prepared.InstallerTransactionID,
			ReleaseSequence: prepared.ReleaseSequence, ArtifactSHA256: prepared.ArtifactSHA256,
			IssuedAt: installer.v2SandboxInstaller.base.now.Now(),
		}
		if installer.initialSettledPhase == InstallerTransactionActive {
			receipt.CurrentVersion = prepared.TargetVersion
			receipt.PreviousVersion = prepared.PreviousVersion
			receipt.Status = ReceiptStatusActive
		} else {
			receipt.CurrentVersion = prepared.PreviousVersion
			receipt.PreviousVersion = prepared.TargetVersion
			receipt.Status = ReceiptStatusRolledBack
		}
		receipt = installer.v2SandboxInstaller.base.sign(receipt)
		if installer.settledReceipts == nil {
			installer.settledReceipts = make(map[string]ActivationReceipt)
			installer.settledCurrent = make(map[string]ActivationReceipt)
		}
		installer.settledReceipts[prepared.InstallerTransactionID] = receipt
		if receipt.Status == ReceiptStatusActive {
			installer.settledCurrent[prepared.InstallerTransactionID] = receipt
		} else {
			installer.settledCurrent[prepared.InstallerTransactionID] = installer.v2SandboxInstaller.base.restoredCurrent(
				prepared.InstallerTransactionID, prepared.ReleaseSequence, request.CurrentReceipt, prepared.TargetVersion,
			)
		}
	}
	return prepared, nil
}

func (installer *journalOrderV2Installer) settleAfterPrepareInspect(transactionID string, status InstallerTransaction) InstallerTransaction {
	if installer.initialSettledPhase == "" || installer.v2SandboxInstaller.inspectCalls <= 1 {
		return status
	}
	receipt, ok := installer.settledReceipts[transactionID]
	current, currentOK := installer.settledCurrent[transactionID]
	if !ok || !currentOK {
		return status
	}
	status.Phase = installer.initialSettledPhase
	status.Receipt = receipt
	installer.statuses[transactionID] = status
	installer.v2SandboxInstaller.base.mu.Lock()
	installer.v2SandboxInstaller.base.records[transactionID] = receipt
	installer.v2SandboxInstaller.base.current = current
	installer.v2SandboxInstaller.base.mu.Unlock()
	return status
}

func (installer *journalOrderV2Installer) Inspect(ctx context.Context, transactionID string) (InstallerTransaction, error) {
	if installer.inspectErrors > 0 {
		installer.inspectErrors--
		return InstallerTransaction{}, errors.New("helper journal readback interrupted")
	}
	if installer.reportInstallingWithoutJournal {
		status, found := installer.v2SandboxInstaller.statuses[transactionID]
		if !found {
			return InstallerTransaction{InstallerTransactionID: transactionID, Phase: InstallerTransactionUnknown}, nil
		}
		status.Phase = InstallerTransactionInstalling
		return status, nil
	}
	if installer.reportInstallingAfterFirstInspect {
		status, err := installer.v2SandboxInstaller.Inspect(ctx, transactionID)
		if err != nil || status.Phase == InstallerTransactionUnknown {
			return status, err
		}
		if installer.v2SandboxInstaller.inspectCalls > 1 {
			status.Phase = InstallerTransactionInstalling
		}
		return status, nil
	}
	record, err := installer.journal.Load(transactionID)
	if errors.Is(err, helper.ErrJournalNotFound) {
		return InstallerTransaction{InstallerTransactionID: transactionID, Phase: InstallerTransactionUnknown}, nil
	}
	if err != nil || (record.Phase != helper.JournalPrepared && record.Phase != helper.JournalInstalling) {
		return InstallerTransaction{}, ErrInstallerUncertain
	}
	status, err := installer.v2SandboxInstaller.Inspect(ctx, transactionID)
	if err != nil {
		return InstallerTransaction{}, err
	}
	status = installer.settleAfterPrepareInspect(transactionID, status)
	if record.Phase == helper.JournalPrepared && status.Phase == InstallerTransactionInstalling {
		return InstallerTransaction{}, ErrInstallerUncertain
	}
	return status, nil
}

func (installer *journalOrderV2Installer) MarkInstalling(ctx context.Context, prepared PreparedInstall) (InstallerTransaction, error) {
	if installer.reportWithoutJournal {
		return installer.v2SandboxInstaller.MarkInstalling(ctx, prepared)
	}
	record, err := installer.journal.Load(prepared.InstallerTransactionID)
	if err != nil || record.Phase != helper.JournalPrepared {
		return InstallerTransaction{}, ErrInstallerUncertain
	}
	record.Phase = helper.JournalInstalling
	if err := installer.journal.Save(record); err != nil {
		return InstallerTransaction{}, err
	}
	return installer.v2SandboxInstaller.MarkInstalling(ctx, prepared)
}

func (installer *journalOrderV2Installer) Activate(ctx context.Context, prepared PreparedInstall) (ActivationReceipt, error) {
	if installer.beforeActivate != nil {
		installer.beforeActivate(prepared)
	}
	return installer.v2SandboxInstaller.Activate(ctx, prepared)
}

func TestUpgradeRuntimePersistsHelperJournalBeforeInstallingStatus(t *testing.T) {
	fixture, environment, storeRoot := newJournalOrderEnvironment(t)
	journal, config := newRuntimeHelperJournal(t, environment)
	installer := &journalOrderV2Installer{v2SandboxInstaller: newV2SandboxInstaller(environment.installer), journal: journal}
	store, runtime := newJournalOrderRuntime(t, environment, fixture, storeRoot, installer)
	accepted := acceptAndAcknowledgeRuntimeCommand(t, runtime, fixture)

	observed := false
	installer.beforeActivate = func(prepared PreparedInstall) {
		reopened, err := helper.NewJournalStore(config)
		if err != nil {
			t.Fatalf("reopen helper journal: %v", err)
		}
		record, err := reopened.Load(prepared.InstallerTransactionID)
		if err != nil || record.Phase != helper.JournalInstalling ||
			record.InstallPayloadSHA256 != prepared.InstallPayloadSHA256 {
			t.Fatalf("helper journal at installing boundary = (%+v, %v)", record, err)
		}
		last, found, err := store.LastStatus(context.Background(), accepted.Status.CommandID)
		if err != nil || !found || last.State != EdgeUpgradeStateInstalling ||
			last.InstallerTransactionID != prepared.InstallerTransactionID {
			t.Fatalf("runtime status at activation boundary = (%+v, %t, %v)", last, found, err)
		}
		observed = true
	}

	if err := runtime.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !observed {
		t.Fatal("activation did not observe the durable helper journal and installing status")
	}
}

func TestUpgradeRuntimeDoesNotPersistInstallingWhenHelperJournalSaveFails(t *testing.T) {
	fixture, environment, storeRoot := newJournalOrderEnvironment(t)
	journal, config := newRuntimeHelperJournal(t, environment)
	installer := &journalOrderV2Installer{v2SandboxInstaller: newV2SandboxInstaller(environment.installer), journal: journal}
	store, runtime := newJournalOrderRuntime(t, environment, fixture, storeRoot, installer)
	accepted := acceptAndAcknowledgeRuntimeCommand(t, runtime, fixture)

	if err := os.Chmod(config.Directory, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(config.Directory, 0o700) })
	if err := runtime.Recover(context.Background()); !errors.Is(err, ErrInstallerUncertain) {
		t.Fatalf("Recover() error = %v, want %v", err, ErrInstallerUncertain)
	}
	last, found, err := store.LastStatus(context.Background(), accepted.Status.CommandID)
	if err != nil || !found || last.State != EdgeUpgradeStateClaimed {
		t.Fatalf("status after helper journal failure = (%+v, %t, %v)", last, found, err)
	}
	entries, err := os.ReadDir(config.Directory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("helper journal directory after save failure = (%v, %v)", entries, err)
	}
}

func TestUpgradeRuntimeDoesNotPublishInstallingFromNonDurableHelperResponse(t *testing.T) {
	fixture, environment, storeRoot := newJournalOrderEnvironment(t)
	journal, _ := newRuntimeHelperJournal(t, environment)
	installer := &journalOrderV2Installer{
		v2SandboxInstaller: newV2SandboxInstaller(environment.installer), journal: journal, reportWithoutJournal: true,
	}
	store, runtime := newJournalOrderRuntime(t, environment, fixture, storeRoot, installer)
	accepted := acceptAndAcknowledgeRuntimeCommand(t, runtime, fixture)

	if err := runtime.Recover(context.Background()); !errors.Is(err, ErrInstallerUncertain) {
		t.Fatalf("Recover() error = %v, want %v", err, ErrInstallerUncertain)
	}
	last, found, err := store.LastStatus(context.Background(), accepted.Status.CommandID)
	if err != nil || !found || last.State == EdgeUpgradeStateInstalling {
		t.Fatalf("status after non-durable helper response = (%+v, %t, %v)", last, found, err)
	}
	unlock, err := store.lock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	history, err := store.statusHistoryLocked(accepted.Status.CommandID)
	unlock()
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range history {
		if status.State == EdgeUpgradeStateInstalling {
			t.Fatalf("non-durable helper response published installing status: %+v", history)
		}
	}
}

func TestUpgradeRuntimeRejectsInstallingStatusWithoutDurableHelperJournal(t *testing.T) {
	fixture, environment, storeRoot := newJournalOrderEnvironment(t)
	journal, _ := newRuntimeHelperJournal(t, environment)
	installer := &journalOrderV2Installer{
		v2SandboxInstaller: newV2SandboxInstaller(environment.installer), journal: journal,
		skipJournal: true, reportInstallingAfterFirstInspect: true,
	}
	store, runtime := newJournalOrderRuntime(t, environment, fixture, storeRoot, installer)
	accepted := acceptAndAcknowledgeRuntimeCommand(t, runtime, fixture)

	if err := runtime.Recover(context.Background()); !errors.Is(err, ErrInstallerUncertain) {
		t.Fatalf("Recover() error = %v, want %v", err, ErrInstallerUncertain)
	}
	last, found, err := store.LastStatus(context.Background(), accepted.Status.CommandID)
	if err != nil || !found || last.State != EdgeUpgradeStateClaimed {
		t.Fatalf("status after unverified installing response = (%+v, %t, %v)", last, found, err)
	}
}

func TestUpgradeRuntimeRejectsPreparedAckWithoutDurableHelperJournal(t *testing.T) {
	fixture, environment, storeRoot := newJournalOrderEnvironment(t)
	journal, _ := newRuntimeHelperJournal(t, environment)
	installer := &journalOrderV2Installer{
		v2SandboxInstaller: newV2SandboxInstaller(environment.installer), journal: journal, skipJournal: true,
	}
	store, runtime := newJournalOrderRuntime(t, environment, fixture, storeRoot, installer)
	accepted := acceptAndAcknowledgeRuntimeCommand(t, runtime, fixture)

	if err := runtime.Recover(context.Background()); !errors.Is(err, ErrInstallerUncertain) {
		t.Fatalf("Recover() error = %v, want %v", err, ErrInstallerUncertain)
	}
	last, found, err := store.LastStatus(context.Background(), accepted.Status.CommandID)
	if err != nil || !found || last.State != EdgeUpgradeStateClaimed {
		t.Fatalf("status after unverified prepared ack = (%+v, %t, %v)", last, found, err)
	}
}

func TestUpgradeRuntimeRecoversJournalReadbackBeforeInstalling(t *testing.T) {
	fixture, environment, storeRoot := newJournalOrderEnvironment(t)
	journal, _ := newRuntimeHelperJournal(t, environment)
	installer := &journalOrderV2Installer{
		v2SandboxInstaller: newV2SandboxInstaller(environment.installer), journal: journal, inspectErrors: 1,
	}
	store, runtime := newJournalOrderRuntime(t, environment, fixture, storeRoot, installer)
	accepted := acceptAndAcknowledgeRuntimeCommand(t, runtime, fixture)

	if err := runtime.Recover(context.Background()); !errors.Is(err, ErrInstallerUncertain) {
		t.Fatalf("first Recover() error = %v, want %v", err, ErrInstallerUncertain)
	}
	last, found, err := store.LastStatus(context.Background(), accepted.Status.CommandID)
	if err != nil || !found || last.State != EdgeUpgradeStateClaimed {
		t.Fatalf("status before journal readback recovery = (%+v, %t, %v)", last, found, err)
	}

	_, restarted := newJournalOrderRuntime(t, environment, fixture, storeRoot, installer)
	if err := restarted.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	last, found, err = store.LastStatus(context.Background(), accepted.Status.CommandID)
	if err != nil || !found || last.State != EdgeUpgradeStateHealthy || installer.activateCalls != 1 {
		t.Fatalf("status after journal readback recovery = (%+v, %t, %v), activate=%d",
			last, found, err, installer.activateCalls)
	}
}

func TestUpgradeRuntimeResumesAlreadySettledInstallerStatus(t *testing.T) {
	for _, test := range []struct {
		name      string
		phase     InstallerTransactionPhase
		wantState EdgeUpgradeState
		wantErr   error
	}{
		{name: "active", phase: InstallerTransactionActive, wantState: EdgeUpgradeStateHealthy},
		{name: "rolled back", phase: InstallerTransactionRolledBack, wantState: EdgeUpgradeStateRolledBack, wantErr: ErrActivation},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture, environment, storeRoot := newJournalOrderEnvironment(t)
			journal, _ := newRuntimeHelperJournal(t, environment)
			installer := &journalOrderV2Installer{
				v2SandboxInstaller: newV2SandboxInstaller(environment.installer), journal: journal,
				initialSettledPhase: test.phase,
			}
			store, runtime := newJournalOrderRuntime(t, environment, fixture, storeRoot, installer)
			accepted := acceptAndAcknowledgeRuntimeCommand(t, runtime, fixture)

			err := runtime.Recover(context.Background())
			if test.wantErr == nil {
				if err != nil {
					t.Fatalf("Recover() error = %v", err)
				}
			} else if !errors.Is(err, test.wantErr) {
				t.Fatalf("Recover() error = %v, want %v", err, test.wantErr)
			}
			last, found, statusErr := store.LastStatus(context.Background(), accepted.Status.CommandID)
			if statusErr != nil || !found || last.State != test.wantState {
				t.Fatalf("LastStatus() = (%+v, %t, %v), want %s", last, found, statusErr, test.wantState)
			}
			if installer.activateCalls != 0 {
				t.Fatalf("already settled installer activated %d times", installer.activateCalls)
			}
		})
	}
}

func newJournalOrderEnvironment(t *testing.T) (executionFixture, *testEnvironment, string) {
	t.Helper()
	fixture, environment, storeRoot := newActualRuntimeEnvironment(t, newExecutionV2Fixture(t))
	fixture.execution.Platform = "linux"
	fixture.execution.Architecture = "amd64"
	resignExecutionFixture(t, &fixture)
	return fixture, environment, storeRoot
}

func newRuntimeHelperJournal(t *testing.T, environment *testEnvironment) (*helper.JournalStore, helper.JournalConfig) {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "helper-state")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	config := helper.JournalConfig{
		Directory: directory, OwnerUID: uint32(os.Geteuid()), OwnerGID: uint32(os.Getegid()),
		TrustedReceiptKeys: map[string]ed25519.PublicKey{"sandbox-helper": environment.receiptPublicKey},
	}
	journal, err := helper.NewJournalStore(config)
	if err != nil {
		t.Fatal(err)
	}
	return journal, config
}

func newJournalOrderRuntime(t *testing.T, environment *testEnvironment, fixture executionFixture, storeRoot string,
	installer Installer,
) (*DurableUpgradeStore, *UpgradeRuntime) {
	t.Helper()
	config := DefaultConfig(
		environment.root, fixture.execution.CurrentVersion,
		map[string]ed25519.PublicKey{fixture.envelope.EdgeKeyID: fixture.edgePublic},
		map[string]ed25519.PublicKey{"sandbox-helper": environment.receiptPublicKey},
		environment.downloader, installer, environment.probe,
	)
	config.NodeID = fixture.execution.NodeID
	config.Platform = fixture.execution.Platform
	config.Architecture = fixture.execution.Architecture
	config.Clock = environment.now
	config.DiskReserveBytes = 0
	manager, err := NewManager(config)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewDurableUpgradeStore(storeRoot)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := NewUpgradeRuntime(UpgradeRuntimeConfig{
		Store: store, Manager: manager, Options: fixture.options(), Now: environment.now.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return store, runtime
}
