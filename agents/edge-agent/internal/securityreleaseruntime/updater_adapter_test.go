package securityreleaseruntime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/securityrelease"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/updater"
)

type adapterCurrentReceiptSource struct {
	receipt updater.ActivationReceipt
	err     error
	calls   int
}

func (source *adapterCurrentReceiptSource) Current(context.Context) (updater.ActivationReceipt, error) {
	source.calls++
	return source.receipt, source.err
}

type adapterCommandSource struct {
	binding SignedCommandBinding
	err     error
	lookups []SignedCommandLookup
}

func (source *adapterCommandSource) Load(_ context.Context, lookup SignedCommandLookup) (SignedCommandBinding, error) {
	source.lookups = append(source.lookups, lookup)
	return source.binding, source.err
}

type adapterUpgradeRuntime struct {
	accepts      [][]byte
	recovers     int
	acceptErr    error
	recoverErr   error
	afterRecover func()
}

func (runtime *adapterUpgradeRuntime) AcceptCommand(_ context.Context, encoded []byte) error {
	runtime.accepts = append(runtime.accepts, append([]byte(nil), encoded...))
	return runtime.acceptErr
}

func (runtime *adapterUpgradeRuntime) Recover(context.Context) error {
	runtime.recovers++
	if runtime.afterRecover != nil {
		runtime.afterRecover()
	}
	return runtime.recoverErr
}

type adapterStatusSource struct {
	status updater.EdgeUpgradeStatus
	found  bool
	err    error
	calls  int
}

func (source *adapterStatusSource) LastStatus(context.Context, string) (updater.EdgeUpgradeStatus, bool, error) {
	source.calls++
	return source.status, source.found, source.err
}

type adapterTransactionReceiptSource struct {
	receipt updater.ActivationReceipt
	err     error
	calls   int
	ids     []string
}

func (source *adapterTransactionReceiptSource) Query(_ context.Context, transactionID string) (updater.ActivationReceipt, error) {
	source.calls++
	source.ids = append(source.ids, transactionID)
	return source.receipt, source.err
}

func TestOPS15UpdaterRuntimeFactsSourceUsesVerifiedCurrentReceipt(t *testing.T) {
	now := time.Date(2026, 8, 8, 8, 0, 0, 0, time.UTC)
	publicKey, privateKey := adapterReceiptKey()
	receipt := signedAdapterReceipt(t, privateKey, now, updater.ReceiptStatusActive,
		"txn-current-runtime", 100, testDigest, "1.27.1.2", "1.26.3.1")
	current := &adapterCurrentReceiptSource{receipt: receipt}
	source, err := NewUpdaterRuntimeFactsSource(UpdaterRuntimeFactsConfig{
		NodeID: testNodeID, AgentVersion: "1.8.0", Current: current,
		ReceiptKeys: map[string]ed25519.PublicKey{"helper-2026": publicKey}, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	facts, err := source.Current(t.Context())
	if err != nil || facts != (RuntimeFacts{
		NodeID: testNodeID, AgentVersion: "1.8.0", RuntimeVersion: "1.27.1.2",
		RuntimeImageDigest: "sha256:" + testDigest,
	}) || current.calls != 1 {
		t.Fatalf("Current() = (%+v, %v), calls=%d", facts, err, current.calls)
	}

	current.receipt.Signature.Value = "invalid"
	if _, err := source.Current(t.Context()); !errors.Is(err, ErrFactsUnavailable) {
		t.Fatalf("invalid current receipt error = %v", err)
	}
	current.receipt = receipt
	current.receipt.Status = updater.ReceiptStatusRolledBack
	if _, err := source.Current(t.Context()); !errors.Is(err, ErrFactsUnavailable) {
		t.Fatalf("non-active current receipt error = %v", err)
	}
}

func TestOPS15SignedUpdaterAdapterExecutesTerminalDeployAndReplaysWithoutRepublish(t *testing.T) {
	fixture := newSignedAdapterFixture(t, securityrelease.ActionDeploy)
	fixture.runtime.afterRecover = func() { fixture.statuses.found = true }
	adapter := fixture.adapter(t)

	receipt, err := adapter.Execute(t.Context(), fixture.request)
	if err != nil || receipt.Action != securityrelease.ActionDeploy || receipt.ActiveReceiptSHA256 == "" ||
		receipt.RollbackReceiptSHA256 != "" || receipt.InstallerTransactionID != fixture.statuses.status.InstallerTransactionID ||
		len(fixture.runtime.accepts) != 1 || fixture.runtime.recovers != 1 || fixture.receipts.calls != 1 {
		t.Fatalf("Execute(deploy) = (%+v, %v), accepts=%d recovers=%d receipt_reads=%d",
			receipt, err, len(fixture.runtime.accepts), fixture.runtime.recovers, fixture.receipts.calls)
	}
	if !bytes.Equal(fixture.runtime.accepts[0], fixture.commands.binding.Encoded) ||
		fixture.commands.lookups[0].ExecutionID != fixture.request.ExecutionID {
		t.Fatalf("accepted command or lookup mismatch: accepts=%x lookups=%+v", fixture.runtime.accepts, fixture.commands.lookups)
	}

	replayed, err := adapter.Execute(t.Context(), fixture.request)
	if err != nil || replayed != receipt || len(fixture.runtime.accepts) != 1 || fixture.runtime.recovers != 1 ||
		fixture.receipts.calls != 2 {
		t.Fatalf("terminal replay = (%+v, %v), accepts=%d recovers=%d receipt_reads=%d",
			replayed, err, len(fixture.runtime.accepts), fixture.runtime.recovers, fixture.receipts.calls)
	}
}

func TestOPS15SignedUpdaterAdapterRollbackBindsLKGReceipt(t *testing.T) {
	fixture := newSignedAdapterFixture(t, securityrelease.ActionRollback)
	fixture.statuses.found = true
	adapter := fixture.adapter(t)
	receipt, err := adapter.Execute(t.Context(), fixture.request)
	if err != nil || receipt.Action != securityrelease.ActionRollback || receipt.ActiveReceiptSHA256 != "" ||
		receipt.RollbackReceiptSHA256 == "" || receipt.ResultRuntimeVersion != fixture.request.LKGRuntimeVersion ||
		receipt.LKGImageDigest != fixture.request.LKGImageDigest || len(fixture.runtime.accepts) != 0 ||
		fixture.runtime.recovers != 0 {
		t.Fatalf("Execute(rollback) = (%+v, %v), accepts=%d recovers=%d",
			receipt, err, len(fixture.runtime.accepts), fixture.runtime.recovers)
	}
}

func TestOPS15SignedUpdaterAdapterFailsClosedForNonterminalAndMissingReceipt(t *testing.T) {
	for _, test := range []struct {
		name  string
		state updater.EdgeUpgradeState
		found bool
	}{
		{name: "accepted remains pending", state: updater.EdgeUpgradeStateAccepted, found: true},
		{name: "uncertain", state: updater.EdgeUpgradeStateUncertain, found: true},
		{name: "failed", state: updater.EdgeUpgradeStateFailed, found: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSignedAdapterFixture(t, securityrelease.ActionDeploy)
			fixture.statuses.found = test.found
			fixture.statuses.status.State = test.state
			adapter := fixture.adapter(t)
			if _, err := adapter.Execute(t.Context(), fixture.request); !errors.Is(err, ErrUpdaterExecution) {
				t.Fatalf("Execute(%s) error = %v", test.state, err)
			}
			if test.state == updater.EdgeUpgradeStateAccepted && (len(fixture.runtime.accepts) != 1 || fixture.runtime.recovers != 1) {
				t.Fatalf("pending resume calls = accepts %d recovers %d", len(fixture.runtime.accepts), fixture.runtime.recovers)
			}
			if test.state != updater.EdgeUpgradeStateAccepted && (len(fixture.runtime.accepts) != 0 || fixture.runtime.recovers != 0) {
				t.Fatalf("terminal failure was re-executed: accepts %d recovers %d", len(fixture.runtime.accepts), fixture.runtime.recovers)
			}
		})
	}

	fixture := newSignedAdapterFixture(t, securityrelease.ActionDeploy)
	fixture.statuses.found = true
	fixture.receipts.err = errors.New("receipt missing")
	if _, err := fixture.adapter(t).Execute(t.Context(), fixture.request); !errors.Is(err, ErrReceiptMismatch) {
		t.Fatalf("missing receipt error = %v", err)
	}
}

func TestOPS15SignedUpdaterAdapterRejectsCommandAndReceiptIdentityDrift(t *testing.T) {
	fixture := newSignedAdapterFixture(t, securityrelease.ActionDeploy)
	fixture.commands.binding.ManifestSHA256 = testDigest
	if _, err := fixture.adapter(t).Execute(t.Context(), fixture.request); !errors.Is(err, ErrSignedCommandConflict) {
		t.Fatalf("command binding drift error = %v", err)
	}
	if len(fixture.runtime.accepts) != 0 || fixture.runtime.recovers != 0 {
		t.Fatal("drifted command reached updater runtime")
	}

	fixture = newSignedAdapterFixture(t, securityrelease.ActionDeploy)
	fixture.statuses.found = true
	fixture.receipts.receipt.ArtifactSHA256 = testDigest
	if _, err := fixture.adapter(t).Execute(t.Context(), fixture.request); !errors.Is(err, ErrReceiptMismatch) {
		t.Fatalf("receipt artifact drift error = %v", err)
	}
}

type signedAdapterFixture struct {
	request  ExecutionRequest
	commands *adapterCommandSource
	runtime  *adapterUpgradeRuntime
	statuses *adapterStatusSource
	receipts *adapterTransactionReceiptSource
	keys     map[string]ed25519.PublicKey
	now      time.Time
}

func newSignedAdapterFixture(t *testing.T, action securityrelease.Action) *signedAdapterFixture {
	t.Helper()
	now := time.Date(2026, 8, 8, 8, 0, 0, 0, time.UTC)
	publicKey, privateKey := adapterReceiptKey()
	current, target := "1.27.1.2", "1.31.3.1"
	artifact, lkgArtifact := testOtherDigest, testDigest
	receiptStatus := updater.ReceiptStatusActive
	statusState := updater.EdgeUpgradeStateHealthy
	commandAction := string(updater.ActionUpgrade)
	if action == securityrelease.ActionRollback {
		current, target = "1.31.3.1", "1.27.1.2"
		artifact, lkgArtifact = testDigest, testDigest
		receiptStatus = updater.ReceiptStatusRolledBack
		statusState = updater.EdgeUpgradeStateRolledBack
		commandAction = string(updater.ActionRollback)
	}
	signedExecution := []byte("real-signed-updater-execution")
	executionDigest := sha256.Sum256(signedExecution)
	command := updater.EdgeUpgradeCommand{
		Schema: updater.EdgeUpgradeCommandSchema, CommandID: "00000000-0000-4000-8000-000000000201",
		PlanID: "00000000-0000-4000-8000-000000000202", PlanRevision: 101,
		BatchID: "00000000-0000-4000-8000-000000000203", InstallationID: "00000000-0000-4000-8000-000000000204",
		NodeID: testNodeID, Action: commandAction, SignedExecution: signedExecution,
		SignedExecutionSHA256: hex.EncodeToString(executionDigest[:]),
	}
	encoded, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	commandDigest := sha256.Sum256(encoded)
	request := ExecutionRequest{
		Version: SignedUpdaterAdapterVersion, ExecutionID: testDigest, NodeID: testNodeID,
		ReleaseID: testReleaseID, ReleaseSequence: 101, ManifestSHA256: testOtherDigest, Action: action,
		CurrentRuntimeVersion: current, TargetRuntimeVersion: target,
		LKGRuntimeVersion: "1.27.1.2", LKGImageDigest: "sha256:" + lkgArtifact,
		SignedCommand: encoded, SignedCommandSHA256: hex.EncodeToString(commandDigest[:]),
	}
	binding := SignedCommandBinding{
		Version: SignedUpdaterAdapterVersion, ExecutionID: request.ExecutionID, ReleaseID: request.ReleaseID,
		ReleaseSequence: request.ReleaseSequence, ManifestSHA256: request.ManifestSHA256, Action: action,
		CurrentRuntimeVersion: current, TargetRuntimeVersion: target,
		ArtifactSHA256: artifact, LKGArtifactSHA256: lkgArtifact,
		SignedCommandSHA256: request.SignedCommandSHA256, Command: command, Encoded: encoded,
	}
	transactionID := "txn-security-release-101"
	status := updater.EdgeUpgradeStatus{
		Schema: updater.EdgeUpgradeStatusSchemaV2, StatusID: "00000000-0000-4000-8000-000000000205",
		StatusRevision: 4, CommandID: command.CommandID, PlanID: command.PlanID, PlanRevision: command.PlanRevision,
		InstallationID: command.InstallationID, NodeID: command.NodeID,
		CommandSHA256: request.SignedCommandSHA256, State: statusState,
		CurrentVersion: target, PreviousVersion: current, InstallerTransactionID: transactionID,
		ObservedAt: now, ActiveEvidence: &updater.ActiveProbeEvidence{
			Schema: updater.ActiveProbeEvidenceSchema, ActiveArtifactSHA256: artifact,
			LastKnownGoodArtifactSHA256: lkgArtifact,
		},
	}
	receipt := signedAdapterReceipt(t, privateKey, now, receiptStatus, transactionID, 101, artifact, target, current)
	return &signedAdapterFixture{
		request: request, commands: &adapterCommandSource{binding: binding}, runtime: &adapterUpgradeRuntime{},
		statuses: &adapterStatusSource{status: status}, receipts: &adapterTransactionReceiptSource{receipt: receipt},
		keys: map[string]ed25519.PublicKey{"helper-2026": publicKey}, now: now,
	}
}

func (fixture *signedAdapterFixture) adapter(t *testing.T) *UpdaterSignedCommandAdapter {
	t.Helper()
	adapter, err := NewSignedUpdaterAdapter(SignedUpdaterAdapterConfig{
		Commands: fixture.commands, Runtime: fixture.runtime, Statuses: fixture.statuses,
		Receipts: fixture.receipts, ReceiptKeys: fixture.keys, Clock: func() time.Time { return fixture.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func adapterReceiptKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x24}, ed25519.SeedSize))
	return privateKey.Public().(ed25519.PublicKey), privateKey
}

func signedAdapterReceipt(t *testing.T, privateKey ed25519.PrivateKey, now time.Time, status updater.ReceiptStatus,
	transactionID string, releaseSequence uint64, artifactSHA256, current, previous string,
) updater.ActivationReceipt {
	t.Helper()
	receipt := updater.ActivationReceipt{
		SchemaVersion: 1, InstallerTransactionID: transactionID, ReleaseSequence: releaseSequence,
		ArtifactSHA256: artifactSHA256, CurrentVersion: current, PreviousVersion: previous,
		Status: status, IssuedAt: now,
	}
	if err := updater.SignReceipt(&receipt, "helper-2026", privateKey); err != nil {
		t.Fatal(err)
	}
	return receipt
}
