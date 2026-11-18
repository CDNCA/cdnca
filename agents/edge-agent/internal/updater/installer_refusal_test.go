package updater

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/packaging/helper/protocol"
)

// refusingV2Installer answers Prepare the way the 1.0.35 helper answered
// a same-version re-release: TRANSACTION_CONFLICT, nothing staged, Inspect reports the transaction unknown.
type refusingV2Installer struct {
	*v2SandboxInstaller
	refusals int
}

func (installer *refusingV2Installer) Prepare(context.Context, InstallRequest) (PreparedInstall, error) {
	installer.refusals++
	return PreparedInstall{}, &InstallerRefusal{Code: "TRANSACTION_CONFLICT", cause: ErrInstallerUncertain}
}

func TestUpgradeRuntimeClosesHelperRefusedPrepareAsFailed(t *testing.T) {
	fixture, environment, storeRoot := newJournalOrderEnvironment(t)
	installer := &refusingV2Installer{v2SandboxInstaller: newV2SandboxInstaller(environment.installer)}
	store, runtime := newJournalOrderRuntime(t, environment, fixture, storeRoot, installer)
	accepted := acceptAndAcknowledgeRuntimeCommand(t, runtime, fixture)

	if err := runtime.Recover(context.Background()); err != nil {
		t.Fatalf("Recover() after a helper refusal = %v, want nil so the gateway session stays up", err)
	}
	statuses, err := runtime.PendingStatuses(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var states []EdgeUpgradeState
	for _, queued := range statuses {
		states = append(states, queued.Status.State)
	}
	want := []EdgeUpgradeState{EdgeUpgradeStateClaimed, EdgeUpgradeStateInstalling, EdgeUpgradeStateFailed}
	if len(states) != len(want) {
		t.Fatalf("queued states = %v, want %v", states, want)
	}
	for index := range want {
		if states[index] != want[index] {
			t.Fatalf("queued states = %v, want %v", states, want)
		}
	}
	last, found, err := store.LastStatus(context.Background(), accepted.Status.CommandID)
	if err != nil || !found || last.State != EdgeUpgradeStateFailed || last.ErrorCode != installerRefusedCode ||
		last.InstallerTransactionID == "" {
		t.Fatalf("terminal status = (%+v, %t, %v)", last, found, err)
	}
	if err := runtime.Recover(context.Background()); err != nil || installer.refusals != 1 {
		t.Fatalf("second Recover() = %v with %d prepares, want nil and no new prepare", err, installer.refusals)
	}
}

// The upgrade worker held the state flock for the whole 60 s download and
// the gateway session, reading the status queue under the same flock, missed its
// heartbeat deadline.
func TestUpgradeRuntimeStatusQueueStaysReadableDuringDownload(t *testing.T) {
	fixture, environment, _ := newJournalOrderEnvironment(t)
	installer := &refusingV2Installer{v2SandboxInstaller: newV2SandboxInstaller(environment.installer)}
	// Production opens the store and the manager on the same upgrade root (daemon.go).
	store, runtime := newJournalOrderRuntime(t, environment, fixture, environment.root, installer)
	accepted := acceptAndAcknowledgeRuntimeCommand(t, runtime, fixture)

	started := make(chan struct{})
	release := make(chan struct{})
	environment.downloader.started = started
	environment.downloader.release = release
	recovered := make(chan error, 1)
	go func() { recovered <- runtime.Recover(context.Background()) }()
	<-started

	readCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	statuses, err := store.PendingStatuses(readCtx)
	cancel()
	close(release)
	if err != nil || len(statuses) == 0 {
		t.Fatalf("status queue during download = (%d statuses, %v), want readable", len(statuses), err)
	}
	if err := <-recovered; err != nil {
		t.Fatalf("Recover() = %v", err)
	}
	if environment.downloader.calls != 1 {
		t.Fatalf("download calls = %d, want 1", environment.downloader.calls)
	}
	last, found, err := store.LastStatus(context.Background(), accepted.Status.CommandID)
	if err != nil || !found || last.State != EdgeUpgradeStateFailed {
		t.Fatalf("terminal status = (%+v, %t, %v)", last, found, err)
	}
}

// helperWireTransport answers with the exact wire responses the 1.0.35 helper gave
// A v3 prepare refused with TRANSACTION_CONFLICT, inspect reports phase unknown.
type helperWireTransport struct{ prepares int }

func (t *helperWireTransport) RoundTrip(_ context.Context, request protocol.Request, _ *os.File) (protocol.Response, error) {
	switch request.Operation {
	case protocol.OperationPrepareInstall:
		t.prepares++
		return protocol.FailureForVersion(request.ProtocolVersion, protocol.ErrorTransactionConflict), nil
	case protocol.OperationInspectTransaction:
		return protocol.Response{ProtocolVersion: request.ProtocolVersion, OK: true,
			TransactionStatus: &protocol.TransactionStatus{TransactionID: request.TransactionID, Phase: "unknown"}}, nil
	default:
		return protocol.FailureForVersion(request.ProtocolVersion, protocol.ErrorBadRequest), nil
	}
}

type helperWireInstaller struct {
	*v2SandboxInstaller
	wire *PackagingInstaller
}

func (i *helperWireInstaller) Prepare(ctx context.Context, request InstallRequest) (PreparedInstall, error) {
	return i.wire.Prepare(ctx, request)
}

func (i *helperWireInstaller) Inspect(ctx context.Context, transactionID string) (InstallerTransaction, error) {
	return i.wire.Inspect(ctx, transactionID)
}

func TestUpgradeRuntimeReportsHelperWireConflictAsRefused(t *testing.T) {
	fixture, environment, _ := newJournalOrderEnvironment(t)
	transport := &helperWireTransport{}
	installer := &helperWireInstaller{v2SandboxInstaller: newV2SandboxInstaller(environment.installer),
		wire: &PackagingInstaller{transport: transport}}
	store, runtime := newJournalOrderRuntime(t, environment, fixture, environment.root, installer)
	accepted := acceptAndAcknowledgeRuntimeCommand(t, runtime, fixture)

	for attempt := 0; attempt < 3; attempt++ {
		if err := runtime.Recover(context.Background()); err != nil {
			t.Fatalf("Recover() attempt %d = %v", attempt, err)
		}
	}
	last, found, err := store.LastStatus(context.Background(), accepted.Status.CommandID)
	if err != nil || !found || last.State != EdgeUpgradeStateFailed || last.ErrorCode != installerRefusedCode {
		t.Fatalf("terminal status = (%+v, %t, %v)", last, found, err)
	}
	if transport.prepares != 1 {
		t.Fatalf("helper prepares = %d, want 1", transport.prepares)
	}
}

// uncertainV2Installer loses every prepare response (a transport failure, not a refusal),
// so the upgrade stays uncertain until its signed plan expires.
type uncertainV2Installer struct {
	*v2SandboxInstaller
	prepares int
}

func (installer *uncertainV2Installer) Prepare(context.Context, InstallRequest) (PreparedInstall, error) {
	installer.prepares++
	return PreparedInstall{}, ErrInstallerUncertain
}

// Once the claimed command's envelope expired, every recovery
// re-verified it, failed with "upgrade execution is expired" and ended the session.
func TestUpgradeRuntimeClosesExpiredClaimedCommandAsPlanExpired(t *testing.T) {
	fixture, environment, _ := newJournalOrderEnvironment(t)
	installer := &uncertainV2Installer{v2SandboxInstaller: newV2SandboxInstaller(environment.installer)}
	store, runtime := newJournalOrderRuntime(t, environment, fixture, environment.root, installer)
	accepted := acceptAndAcknowledgeRuntimeCommand(t, runtime, fixture)

	if err := runtime.Recover(context.Background()); err == nil {
		t.Fatal("Recover() with a lost prepare response = nil, want uncertain")
	}
	environment.now.mu.Lock()
	environment.now.now = time.Unix(fixture.execution.ExpiresAt, 0).UTC().Add(time.Minute)
	environment.now.mu.Unlock()
	if err := runtime.Recover(context.Background()); err != nil {
		t.Fatalf("Recover() after expiry = %v, want the command closed", err)
	}
	last, found, err := store.LastStatus(context.Background(), accepted.Status.CommandID)
	if err != nil || !found || last.State != EdgeUpgradeStateFailed || last.ErrorCode != "PLAN_EXPIRED" {
		t.Fatalf("terminal status = (%+v, %t, %v)", last, found, err)
	}
	prepares := installer.prepares
	if err := runtime.Recover(context.Background()); err != nil || installer.prepares != prepares {
		t.Fatalf("Recover() after close = %v with prepares %d->%d", err, prepares, installer.prepares)
	}
}

func TestValidPreparedInstallAcceptsV3SameVersionRerelease(t *testing.T) {
	digest := sha256String([]byte("x"))
	prepared := PreparedInstall{SchemaVersion: 2, InstallerTransactionID: "txn-c3de1306d87e22e88b94bc69",
		InstallPayloadSHA256: digest, ExecutionSequence: 125, ReleaseSequence: 139, ArtifactSHA256: digest,
		ManifestSHA256: digest, ExecutableSHA256: digest, SBOMSHA256: digest,
		PreviousVersion: "1.0.35", TargetVersion: "1.0.35"}
	if !validPreparedInstall(prepared, prepared.InstallerTransactionID) {
		t.Fatal("v3 same-version prepared ack refused")
	}
	legacy := prepared
	legacy.SchemaVersion, legacy.ExecutionSequence = 1, 0
	if validPreparedInstall(legacy, legacy.InstallerTransactionID) {
		t.Fatal("legacy same-version prepared ack accepted")
	}
}

// currentWireTransport answers Current the way a node's helper did: the
// stale prepared transaction left by an out-of-band upgrade made it STATE_UNCERTAIN.
type currentWireTransport struct{ currents int }

func (t *currentWireTransport) RoundTrip(_ context.Context, request protocol.Request, _ *os.File) (protocol.Response, error) {
	if request.Operation == protocol.OperationCurrent {
		t.currents++
		return protocol.FailureForVersion(request.ProtocolVersion, protocol.ErrorStateUncertain), nil
	}
	return protocol.FailureForVersion(request.ProtocolVersion, protocol.ErrorBadRequest), nil
}

type currentWireInstaller struct {
	*v2SandboxInstaller
	wire *PackagingInstaller
}

func (i *currentWireInstaller) Current(ctx context.Context) (ActivationReceipt, error) {
	return i.wire.Current(ctx)
}

// After claimed, Manager.prepare called helper Current, got
// "installer operation failed" and returned it, ending the gateway session about every
// 2 s; no helper transaction existed, so the INSTALLER_REFUSED close never ran.
func TestUpgradeRuntimeClosesUnavailableInstallerCurrentAsFailed(t *testing.T) {
	fixture, environment, _ := newJournalOrderEnvironment(t)
	transport := &currentWireTransport{}
	installer := &currentWireInstaller{v2SandboxInstaller: newV2SandboxInstaller(environment.installer),
		wire: &PackagingInstaller{transport: transport}}
	store, runtime := newJournalOrderRuntime(t, environment, fixture, environment.root, installer)
	accepted := acceptAndAcknowledgeRuntimeCommand(t, runtime, fixture)

	if err := runtime.Recover(context.Background()); err != nil {
		t.Fatalf("Recover() with helper Current unavailable = %v, want nil so the gateway session stays up", err)
	}
	statuses, err := runtime.PendingStatuses(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var states []EdgeUpgradeState
	for _, queued := range statuses {
		states = append(states, queued.Status.State)
	}
	want := []EdgeUpgradeState{EdgeUpgradeStateClaimed, EdgeUpgradeStateInstalling, EdgeUpgradeStateFailed}
	if len(states) != len(want) || states[0] != want[0] || states[1] != want[1] || states[2] != want[2] {
		t.Fatalf("queued states = %v, want %v", states, want)
	}
	last, found, err := store.LastStatus(context.Background(), accepted.Status.CommandID)
	if err != nil || !found || last.State != EdgeUpgradeStateFailed || last.ErrorCode != installerCurrentUnavailableCode ||
		last.InstallerTransactionID == "" || !last.AlertRequired || last.CurrentVersion != fixture.execution.CurrentVersion {
		t.Fatalf("terminal status = (%+v, %t, %v)", last, found, err)
	}
	if statuses[1].Status.InstallerTransactionID != last.InstallerTransactionID {
		t.Fatalf("installing transaction %q != failed transaction %q", statuses[1].Status.InstallerTransactionID, last.InstallerTransactionID)
	}
	if err := runtime.Recover(context.Background()); err != nil || transport.currents != 1 || installer.prepareCalls != 0 {
		t.Fatalf("second Recover() = %v with %d Current and %d Prepare calls, want nil, 1, 0", err, transport.currents, installer.prepareCalls)
	}
}
