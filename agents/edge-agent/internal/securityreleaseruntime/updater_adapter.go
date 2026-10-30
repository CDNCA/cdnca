package securityreleaseruntime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/securityrelease"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/updater"
)

type currentReceiptSource interface {
	Current(context.Context) (updater.ActivationReceipt, error)
}

type UpdaterRuntimeFactsConfig struct {
	NodeID       string
	AgentVersion string
	Current      currentReceiptSource
	ReceiptKeys  map[string]ed25519.PublicKey
	Clock        func() time.Time
}

type UpdaterRuntimeFactsSource struct {
	nodeID       string
	agentVersion string
	current      currentReceiptSource
	receiptKeys  map[string]ed25519.PublicKey
	now          func() time.Time
}

func NewUpdaterRuntimeFactsSource(config UpdaterRuntimeFactsConfig) (*UpdaterRuntimeFactsSource, error) {
	keys, ok := copyReceiptKeys(config.ReceiptKeys)
	if !validUUID(config.NodeID) || !validVersion(config.AgentVersion, 3) || config.Current == nil || !ok {
		return nil, ErrInvalidConfig
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	return &UpdaterRuntimeFactsSource{
		nodeID: config.NodeID, agentVersion: config.AgentVersion, current: config.Current,
		receiptKeys: keys, now: config.Clock,
	}, nil
}

func (source *UpdaterRuntimeFactsSource) Current(ctx context.Context) (RuntimeFacts, error) {
	if source == nil || source.current == nil || source.now == nil || ctx == nil {
		return RuntimeFacts{}, ErrInvalidConfig
	}
	receipt, err := source.current.Current(ctx)
	if err != nil || receipt.Status != updater.ReceiptStatusActive ||
		!validUpdaterReceipt(receipt, source.receiptKeys, source.now().UTC()) {
		return RuntimeFacts{}, fmt.Errorf("%w: %v", ErrFactsUnavailable, err)
	}
	return RuntimeFacts{
		NodeID: source.nodeID, AgentVersion: source.agentVersion, RuntimeVersion: receipt.CurrentVersion,
		RuntimeImageDigest: "sha256:" + receipt.ArtifactSHA256,
	}, nil
}

type SignedCommandLookup struct {
	Version             uint32
	ExecutionID         string
	NodeID              string
	ReleaseID           string
	ReleaseSequence     uint64
	ManifestSHA256      string
	Action              securityrelease.Action
	SignedCommandSHA256 string
}

type SignedCommandBinding struct {
	Version               uint32
	ExecutionID           string
	ReleaseID             string
	ReleaseSequence       uint64
	ManifestSHA256        string
	Action                securityrelease.Action
	CurrentRuntimeVersion string
	TargetRuntimeVersion  string
	ArtifactSHA256        string
	LKGArtifactSHA256     string
	SignedCommandSHA256   string
	Command               updater.EdgeUpgradeCommand
	Encoded               []byte
}

type SignedCommandSource interface {
	Load(context.Context, SignedCommandLookup) (SignedCommandBinding, error)
}

type updaterExecutionRuntime interface {
	AcceptCommand(context.Context, []byte) error
	Recover(context.Context) error
}

type updaterStatusSource interface {
	LastStatus(context.Context, string) (updater.EdgeUpgradeStatus, bool, error)
}

type transactionReceiptSource interface {
	Query(context.Context, string) (updater.ActivationReceipt, error)
}

type SignedUpdaterAdapterConfig struct {
	Commands    SignedCommandSource
	Runtime     updaterExecutionRuntime
	Statuses    updaterStatusSource
	Receipts    transactionReceiptSource
	ReceiptKeys map[string]ed25519.PublicKey
	Clock       func() time.Time
}

type UpdaterSignedCommandAdapter struct {
	commands    SignedCommandSource
	runtime     updaterExecutionRuntime
	statuses    updaterStatusSource
	receipts    transactionReceiptSource
	receiptKeys map[string]ed25519.PublicKey
	now         func() time.Time
}

func NewSignedUpdaterAdapter(config SignedUpdaterAdapterConfig) (*UpdaterSignedCommandAdapter, error) {
	keys, ok := copyReceiptKeys(config.ReceiptKeys)
	if config.Commands == nil || config.Runtime == nil || config.Statuses == nil || config.Receipts == nil || !ok {
		return nil, ErrInvalidConfig
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	return &UpdaterSignedCommandAdapter{
		commands: config.Commands, runtime: config.Runtime, statuses: config.Statuses,
		receipts: config.Receipts, receiptKeys: keys, now: config.Clock,
	}, nil
}

func (*UpdaterSignedCommandAdapter) Version() uint32 { return SignedUpdaterAdapterVersion }

func (adapter *UpdaterSignedCommandAdapter) Execute(ctx context.Context, request ExecutionRequest) (ExecutionReceipt, error) {
	if adapter == nil || adapter.commands == nil || adapter.runtime == nil || adapter.statuses == nil ||
		adapter.receipts == nil || adapter.now == nil || ctx == nil || !validAdapterRequest(request) {
		return ExecutionReceipt{}, ErrSignedCommandConflict
	}
	binding, err := adapter.commands.Load(ctx, SignedCommandLookup{
		Version: SignedUpdaterAdapterVersion, ExecutionID: request.ExecutionID, NodeID: request.NodeID,
		ReleaseID: request.ReleaseID, ReleaseSequence: request.ReleaseSequence,
		ManifestSHA256: request.ManifestSHA256, Action: request.Action,
		SignedCommandSHA256: request.SignedCommandSHA256,
	})
	if err != nil || !validSignedCommandBinding(binding, request) {
		return ExecutionReceipt{}, fmt.Errorf("%w: %v", ErrSignedCommandConflict, err)
	}

	status, found, err := adapter.statuses.LastStatus(ctx, binding.Command.CommandID)
	if err != nil {
		return ExecutionReceipt{}, fmt.Errorf("%w: %v", ErrUpdaterExecution, err)
	}
	if !found || !terminalAdapterState(status.State) {
		if err := adapter.runtime.AcceptCommand(ctx, binding.Encoded); err != nil {
			return ExecutionReceipt{}, fmt.Errorf("%w: %v", ErrUpdaterExecution, err)
		}
		if err := adapter.runtime.Recover(ctx); err != nil {
			return ExecutionReceipt{}, fmt.Errorf("%w: %v", ErrUpdaterExecution, err)
		}
		status, found, err = adapter.statuses.LastStatus(ctx, binding.Command.CommandID)
		if err != nil {
			return ExecutionReceipt{}, fmt.Errorf("%w: %v", ErrUpdaterExecution, err)
		}
	}
	if !found || !validTerminalStatus(status, binding, request) {
		return ExecutionReceipt{}, ErrUpdaterExecution
	}
	receipt, err := adapter.receipts.Query(ctx, status.InstallerTransactionID)
	if err != nil || !validTerminalReceipt(receipt, status, binding, request, adapter.receiptKeys, adapter.now().UTC()) {
		return ExecutionReceipt{}, fmt.Errorf("%w: %v", ErrReceiptMismatch, err)
	}
	receiptDigest, err := canonicalReceiptSHA256(receipt)
	if err != nil {
		return ExecutionReceipt{}, ErrReceiptMismatch
	}
	result := ExecutionReceipt{
		Version: SignedUpdaterAdapterVersion, ExecutionID: request.ExecutionID, NodeID: request.NodeID,
		ReleaseID: request.ReleaseID, ReleaseSequence: request.ReleaseSequence,
		ManifestSHA256: request.ManifestSHA256, Action: request.Action,
		InstallerTransactionID: receipt.InstallerTransactionID,
		PreviousRuntimeVersion: request.CurrentRuntimeVersion,
		ResultRuntimeVersion:   request.TargetRuntimeVersion,
		LKGRuntimeVersion:      request.LKGRuntimeVersion, LKGImageDigest: request.LKGImageDigest,
	}
	if request.Action == securityrelease.ActionRollback {
		result.RollbackReceiptSHA256 = receiptDigest
	} else {
		result.ActiveReceiptSHA256 = receiptDigest
	}
	return result, nil
}

func validAdapterRequest(request ExecutionRequest) bool {
	if request.Version != SignedUpdaterAdapterVersion || !validDigest(request.ExecutionID) ||
		!validUUID(request.NodeID) || !validUUID(request.ReleaseID) || request.ReleaseSequence == 0 ||
		!validDigest(request.ManifestSHA256) ||
		(request.Action != securityrelease.ActionDeploy && request.Action != securityrelease.ActionRollback) ||
		!validVersion(request.CurrentRuntimeVersion, 4) || !validVersion(request.TargetRuntimeVersion, 4) ||
		!validVersion(request.LKGRuntimeVersion, 4) || !validImageDigest(request.LKGImageDigest) ||
		len(request.SignedCommand) == 0 || len(request.SignedCommand) > maxSignedCommandBytes ||
		!validDigest(request.SignedCommandSHA256) || digestBytes(request.SignedCommand) != request.SignedCommandSHA256 {
		return false
	}
	return request.Action != securityrelease.ActionRollback || request.TargetRuntimeVersion == request.LKGRuntimeVersion
}

func validSignedCommandBinding(binding SignedCommandBinding, request ExecutionRequest) bool {
	expectedAction := string(updater.ActionUpgrade)
	if request.Action == securityrelease.ActionRollback {
		expectedAction = string(updater.ActionRollback)
	}
	canonical, err := json.Marshal(binding.Command)
	return err == nil && binding.Version == SignedUpdaterAdapterVersion && binding.ExecutionID == request.ExecutionID &&
		binding.ReleaseID == request.ReleaseID && binding.ReleaseSequence == request.ReleaseSequence &&
		binding.ManifestSHA256 == request.ManifestSHA256 && binding.Action == request.Action &&
		binding.CurrentRuntimeVersion == request.CurrentRuntimeVersion &&
		binding.TargetRuntimeVersion == request.TargetRuntimeVersion && validDigest(binding.ArtifactSHA256) &&
		validDigest(binding.LKGArtifactSHA256) && binding.LKGArtifactSHA256 == request.LKGImageDigest[7:] &&
		binding.SignedCommandSHA256 == request.SignedCommandSHA256 &&
		bytes.Equal(binding.Encoded, request.SignedCommand) && bytes.Equal(canonical, binding.Encoded) &&
		digestBytes(binding.Encoded) == binding.SignedCommandSHA256 &&
		binding.Command.Schema == updater.EdgeUpgradeCommandSchema && validUUID(binding.Command.CommandID) &&
		validUUID(binding.Command.PlanID) && binding.Command.PlanRevision > 0 && safeToken(binding.Command.BatchID) &&
		validUUID(binding.Command.InstallationID) && binding.Command.NodeID == request.NodeID &&
		binding.Command.Action == expectedAction && len(binding.Command.SignedExecution) > 0 &&
		validDigest(binding.Command.SignedExecutionSHA256) &&
		digestBytes(binding.Command.SignedExecution) == binding.Command.SignedExecutionSHA256 &&
		(request.Action != securityrelease.ActionRollback || binding.ArtifactSHA256 == binding.LKGArtifactSHA256)
}

func terminalAdapterState(state updater.EdgeUpgradeState) bool {
	return state == updater.EdgeUpgradeStateHealthy || state == updater.EdgeUpgradeStateRolledBack ||
		state == updater.EdgeUpgradeStateFailed || state == updater.EdgeUpgradeStateUncertain
}

func validTerminalStatus(status updater.EdgeUpgradeStatus, binding SignedCommandBinding, request ExecutionRequest) bool {
	command := binding.Command
	if status.CommandID != command.CommandID || status.PlanID != command.PlanID ||
		status.PlanRevision != command.PlanRevision || status.InstallationID != command.InstallationID ||
		status.NodeID != request.NodeID || status.CommandSHA256 != request.SignedCommandSHA256 ||
		!safeToken(status.InstallerTransactionID) || status.ActiveEvidence == nil ||
		status.ActiveEvidence.Schema != updater.ActiveProbeEvidenceSchema ||
		status.ActiveEvidence.ActiveArtifactSHA256 != binding.ArtifactSHA256 ||
		status.ActiveEvidence.LastKnownGoodArtifactSHA256 != binding.LKGArtifactSHA256 ||
		status.CurrentVersion != request.TargetRuntimeVersion || status.PreviousVersion != request.CurrentRuntimeVersion {
		return false
	}
	if request.Action == securityrelease.ActionDeploy {
		return status.State == updater.EdgeUpgradeStateHealthy
	}
	return status.State == updater.EdgeUpgradeStateRolledBack
}

func validTerminalReceipt(receipt updater.ActivationReceipt, status updater.EdgeUpgradeStatus,
	binding SignedCommandBinding, request ExecutionRequest, keys map[string]ed25519.PublicKey, now time.Time,
) bool {
	if !validUpdaterReceipt(receipt, keys, now) || receipt.InstallerTransactionID != status.InstallerTransactionID ||
		receipt.ReleaseSequence != request.ReleaseSequence || receipt.ArtifactSHA256 != binding.ArtifactSHA256 ||
		receipt.CurrentVersion != request.TargetRuntimeVersion || receipt.PreviousVersion != request.CurrentRuntimeVersion {
		return false
	}
	if request.Action == securityrelease.ActionDeploy {
		return receipt.Status == updater.ReceiptStatusActive
	}
	return receipt.Status == updater.ReceiptStatusRolledBack
}

func validUpdaterReceipt(receipt updater.ActivationReceipt, keys map[string]ed25519.PublicKey, now time.Time) bool {
	if (receipt.SchemaVersion != 1 && receipt.SchemaVersion != 2) || !safeToken(receipt.InstallerTransactionID) ||
		receipt.ReleaseSequence == 0 || !validDigest(receipt.ArtifactSHA256) ||
		(receipt.Status != updater.ReceiptStatusActive && receipt.Status != updater.ReceiptStatusRolledBack) ||
		!validVersion(receipt.CurrentVersion, 4) ||
		(receipt.PreviousVersion != "" && !validVersion(receipt.PreviousVersion, 4)) ||
		receipt.IssuedAt.IsZero() || !receipt.IssuedAt.Equal(receipt.IssuedAt.UTC()) ||
		receipt.IssuedAt.After(now.Add(5*time.Minute)) || !safeToken(receipt.Signature.KeyID) ||
		receipt.SchemaVersion == 1 && receipt.ExecutionSequence != 0 ||
		receipt.SchemaVersion == 2 && receipt.ExecutionSequence == 0 {
		return false
	}
	key, exists := keys[receipt.Signature.KeyID]
	if !exists {
		return false
	}
	signature, err := base64.RawStdEncoding.DecodeString(receipt.Signature.Value)
	payload, payloadErr := updater.ReceiptSigningBytes(receipt)
	return err == nil && payloadErr == nil && len(signature) == ed25519.SignatureSize &&
		ed25519.Verify(key, payload, signature)
}

func copyReceiptKeys(source map[string]ed25519.PublicKey) (map[string]ed25519.PublicKey, bool) {
	if len(source) == 0 {
		return nil, false
	}
	result := make(map[string]ed25519.PublicKey, len(source))
	for keyID, key := range source {
		if !safeToken(keyID) || len(key) != ed25519.PublicKeySize {
			return nil, false
		}
		result[keyID] = append(ed25519.PublicKey(nil), key...)
	}
	return result, true
}

func canonicalReceiptSHA256(receipt updater.ActivationReceipt) (string, error) {
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return "", err
	}
	return digestBytes(encoded), nil
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
