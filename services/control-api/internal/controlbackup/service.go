package controlbackup

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"time"
)

type WriteFreezeController interface {
	Acquire(context.Context, string) (WriteFreezeLease, error)
}

type WriteFreezeLease interface {
	ID() string
	Release(context.Context) error
}

type ComponentCapturer interface {
	Name() Component
	Capture(context.Context, CaptureRequest) (ComponentCheckpoint, error)
}

type CaptureRequest struct {
	BackupID      string
	WriteFreezeID string
}

type ManifestStore interface {
	Put(context.Context, SignedManifest) error
}

type BackupRequest struct {
	BackupID           string
	SourceClusterID    string
	AppVersion         string
	SchemaVersion      uint64
	CoreManifestSHA256 string
	EnvelopeKey        SecretReference
	TargetRPO          time.Duration
	TargetRTO          time.Duration
}

type BackupResult struct {
	Manifest       Manifest
	SignedManifest SignedManifest
}

type BackupOrchestrator struct {
	Freeze       WriteFreezeController
	Capturers    []ComponentCapturer
	Store        ManifestStore
	SigningKeyID string
	PrivateKey   ed25519.PrivateKey
	Now          func() time.Time
}

func (orchestrator BackupOrchestrator) Run(ctx context.Context, request BackupRequest) (result BackupResult, runErr error) {
	if ctx == nil || orchestrator.Freeze == nil || orchestrator.Store == nil || orchestrator.Now == nil ||
		request.TargetRPO <= 0 || request.TargetRTO <= 0 {
		return BackupResult{}, &BackupRunError{Code: "backup_invalid_config", Err: ErrInvalidManifest}
	}
	lease, err := orchestrator.Freeze.Acquire(ctx, request.BackupID)
	if err != nil {
		return BackupResult{}, &BackupRunError{Code: "backup_freeze_unknown", OutcomeUnknown: true, Err: err}
	}
	if lease == nil || !identifierPattern.MatchString(lease.ID()) {
		if lease != nil {
			_ = lease.Release(context.WithoutCancel(ctx))
		}
		return BackupResult{}, &BackupRunError{Code: "backup_freeze_unknown", OutcomeUnknown: true, Err: ErrInvalidManifest}
	}
	defer func() {
		if releaseErr := lease.Release(context.WithoutCancel(ctx)); releaseErr != nil {
			result = BackupResult{}
			runErr = &BackupRunError{Code: "backup_release_unknown", OutcomeUnknown: true, Err: errors.Join(runErr, releaseErr)}
		}
	}()

	if len(orchestrator.Capturers) != len(requiredComponents) {
		return BackupResult{}, &BackupRunError{Code: "backup_invalid_config", Err: ErrInvalidManifest}
	}
	checkpoints := make([]ComponentCheckpoint, 0, len(requiredComponents))
	for index, expected := range requiredComponents {
		capturer := orchestrator.Capturers[index]
		if capturer == nil || capturer.Name() != expected {
			return BackupResult{}, &BackupRunError{Code: "backup_invalid_config", Err: ErrInvalidManifest}
		}
		checkpoint, captureErr := capturer.Capture(ctx, CaptureRequest{
			BackupID: request.BackupID, WriteFreezeID: lease.ID(),
		})
		if captureErr != nil {
			return BackupResult{}, &BackupRunError{Code: "backup_capture_failed", Err: captureErr}
		}
		if checkpoint.Component != expected {
			return BackupResult{}, &BackupRunError{Code: "backup_invalid_result", Err: ErrInvalidManifest}
		}
		checkpoints = append(checkpoints, checkpoint)
	}
	createdAt := orchestrator.Now().UTC()
	recoveryPoint := checkpoints[0].CapturedAt.UTC()
	for _, checkpoint := range checkpoints[1:] {
		if checkpoint.CapturedAt.Before(recoveryPoint) {
			recoveryPoint = checkpoint.CapturedAt.UTC()
		}
	}
	observedRPO := createdAt.Sub(recoveryPoint)
	if observedRPO < 0 {
		return BackupResult{}, &BackupRunError{Code: "backup_invalid_result", Err: ErrInvalidManifest}
	}
	manifest := Manifest{
		Schema: ManifestSchema, BackupID: request.BackupID, SourceClusterID: request.SourceClusterID,
		AppVersion: request.AppVersion, SchemaVersion: request.SchemaVersion, CreatedAt: createdAt,
		RecoveryPointAt: recoveryPoint, WriteFreezeID: lease.ID(), CoreManifestSHA256: request.CoreManifestSHA256,
		EnvelopeKey: request.EnvelopeKey, Checkpoints: checkpoints,
		Objectives: RecoveryObjectives{
			ObservedRPOSeconds: int64(observedRPO / time.Second),
			TargetRPOSeconds:   int64(request.TargetRPO / time.Second),
			TargetRTOSeconds:   int64(request.TargetRTO / time.Second),
		},
	}
	signed, err := SignManifest(manifest, orchestrator.SigningKeyID, orchestrator.PrivateKey)
	if err != nil {
		return BackupResult{}, &BackupRunError{Code: "backup_manifest_failed", Err: err}
	}
	if err := orchestrator.Store.Put(ctx, signed); err != nil {
		return BackupResult{}, &BackupRunError{Code: "backup_manifest_failed", Err: err}
	}
	return BackupResult{Manifest: manifest, SignedManifest: signed}, nil
}

type RestoreTarget interface {
	Preflight(context.Context, Manifest, string) error
}

type ComponentRestorer interface {
	Name() Component
	Restore(context.Context, ComponentCheckpoint, string) error
	Compensate(context.Context, string, string) error
}

type ProbeName string

const (
	ProbeDNS            ProbeName = "dns"
	ProbeAgentReconnect ProbeName = "agent_reconnect"
)

type RecoveryProbe interface {
	Name() ProbeName
	Check(context.Context, Manifest, string) error
}

type RestoreState string

const (
	RestoreSucceeded RestoreState = "succeeded"
	RestoreFailed    RestoreState = "failed"
)

const (
	FailurePreflight    = "preflight_failed"
	FailureComponent    = "component_restore_failed"
	FailureProbe        = "post_restore_probe_failed"
	FailureCompensation = "compensation_failed"
	FailureReceipt      = "receipt_store_failed"
)

type RestoreReceipt struct {
	Schema             string       `json:"schema"`
	OperationID        string       `json:"operation_id"`
	TargetID           string       `json:"target_id"`
	BackupID           string       `json:"backup_id"`
	ManifestSHA256     string       `json:"manifest_sha256"`
	State              RestoreState `json:"state"`
	FailureCode        string       `json:"failure_code,omitempty"`
	Compensated        bool         `json:"compensated"`
	StartedAt          time.Time    `json:"started_at"`
	CompletedAt        time.Time    `json:"completed_at"`
	RecoveryPointAt    time.Time    `json:"recovery_point_at"`
	ObservedRPOSeconds int64        `json:"observed_rpo_seconds"`
	ObservedRTOSeconds int64        `json:"observed_rto_seconds"`
	Replayed           bool         `json:"replayed"`
}

type ReceiptStore interface {
	Get(context.Context, string) (RestoreReceipt, bool, error)
	Put(context.Context, RestoreReceipt) error
}

type RestoreRequest struct {
	OperationID      string
	TargetID         string
	SignedManifest   SignedManifest
	MaxSchemaVersion uint64
}

type RestoreOrchestrator struct {
	Target     RestoreTarget
	Restorers  []ComponentRestorer
	Probes     []RecoveryProbe
	Receipts   ReceiptStore
	PublicKeys map[string]ed25519.PublicKey
	Now        func() time.Time
}

func (orchestrator RestoreOrchestrator) Run(ctx context.Context, request RestoreRequest) (RestoreReceipt, error) {
	if ctx == nil || orchestrator.Target == nil || orchestrator.Receipts == nil || orchestrator.Now == nil ||
		!identifierPattern.MatchString(request.OperationID) || !identifierPattern.MatchString(request.TargetID) {
		return RestoreReceipt{}, ErrInvalidManifest
	}
	manifest, err := VerifyManifest(request.SignedManifest, orchestrator.PublicKeys, ManifestExpectation{
		MaxSchemaVersion: request.MaxSchemaVersion,
	})
	if err != nil {
		return RestoreReceipt{}, err
	}
	previous, found, err := orchestrator.Receipts.Get(ctx, request.OperationID)
	if err != nil {
		return RestoreReceipt{}, fmt.Errorf("load restore receipt: %w", err)
	}
	if found {
		if previous.TargetID != request.TargetID || previous.BackupID != manifest.BackupID ||
			previous.ManifestSHA256 != request.SignedManifest.PayloadSHA256 {
			return RestoreReceipt{}, ErrIdempotencyConflict
		}
		previous.Replayed = true
		if previous.State == RestoreFailed {
			return previous, ErrRestorePreviouslyFailed
		}
		return previous, nil
	}
	startedAt := orchestrator.Now().UTC()
	receipt := RestoreReceipt{
		Schema: "cdnca.control-recovery.receipt/v1", OperationID: request.OperationID,
		TargetID: request.TargetID, BackupID: manifest.BackupID,
		ManifestSHA256: request.SignedManifest.PayloadSHA256, State: RestoreFailed,
		StartedAt: startedAt, RecoveryPointAt: manifest.RecoveryPointAt,
	}
	if err := orchestrator.Target.Preflight(ctx, manifest, request.TargetID); err != nil {
		receipt.FailureCode = stableFailureCode(err, FailurePreflight)
		return orchestrator.finish(ctx, receipt, err)
	}
	if len(orchestrator.Restorers) != len(requiredComponents) {
		receipt.FailureCode = FailureComponent
		return orchestrator.finish(ctx, receipt, ErrInvalidManifest)
	}
	checkpoints := make(map[Component]ComponentCheckpoint, len(manifest.Checkpoints))
	for _, checkpoint := range manifest.Checkpoints {
		checkpoints[checkpoint.Component] = checkpoint
	}
	applied := make([]ComponentRestorer, 0, len(orchestrator.Restorers))
	for index, expected := range requiredComponents {
		restorer := orchestrator.Restorers[index]
		if restorer == nil || restorer.Name() != expected {
			receipt.FailureCode = FailureComponent
			return orchestrator.failAndCompensate(ctx, receipt, applied, manifest.BackupID, request.TargetID, ErrInvalidManifest)
		}
		applied = append(applied, restorer)
		if err := restorer.Restore(ctx, checkpoints[expected], request.TargetID); err != nil {
			receipt.FailureCode = stableFailureCode(err, FailureComponent)
			return orchestrator.failAndCompensate(ctx, receipt, applied, manifest.BackupID, request.TargetID, err)
		}
	}
	wantProbes := [...]ProbeName{ProbeDNS, ProbeAgentReconnect}
	if len(orchestrator.Probes) != len(wantProbes) {
		receipt.FailureCode = FailureProbe
		return orchestrator.failAndCompensate(ctx, receipt, applied, manifest.BackupID, request.TargetID, ErrInvalidManifest)
	}
	for index, expected := range wantProbes {
		probe := orchestrator.Probes[index]
		if probe == nil || probe.Name() != expected {
			receipt.FailureCode = FailureProbe
			return orchestrator.failAndCompensate(ctx, receipt, applied, manifest.BackupID, request.TargetID, ErrInvalidManifest)
		}
		if err := probe.Check(ctx, manifest, request.TargetID); err != nil {
			receipt.FailureCode = stableFailureCode(err, FailureProbe)
			return orchestrator.failAndCompensate(ctx, receipt, applied, manifest.BackupID, request.TargetID, err)
		}
	}
	receipt.State = RestoreSucceeded
	receipt = orchestrator.stamp(receipt)
	if err := orchestrator.Receipts.Put(context.WithoutCancel(ctx), receipt); err != nil {
		receipt.State = RestoreFailed
		receipt.FailureCode = FailureReceipt
		return orchestrator.failAndCompensate(ctx, receipt, applied, manifest.BackupID, request.TargetID,
			fmt.Errorf("store successful restore receipt: %w", err))
	}
	return receipt, nil
}

func stableFailureCode(err error, fallback string) string {
	var coded interface{ StableCode() string }
	if errors.As(err, &coded) && identifierPattern.MatchString(coded.StableCode()) {
		return coded.StableCode()
	}
	return fallback
}

func (orchestrator RestoreOrchestrator) failAndCompensate(ctx context.Context, receipt RestoreReceipt, applied []ComponentRestorer, backupID, targetID string, cause error) (RestoreReceipt, error) {
	compensated := true
	for index := len(applied) - 1; index >= 0; index-- {
		if err := applied[index].Compensate(context.WithoutCancel(ctx), backupID, targetID); err != nil {
			compensated = false
			cause = errors.Join(cause, fmt.Errorf("compensate %s: %w", applied[index].Name(), err))
		}
	}
	receipt.Compensated = compensated
	if !compensated {
		receipt.FailureCode = FailureCompensation
	}
	return orchestrator.finish(ctx, receipt, cause)
}

func (orchestrator RestoreOrchestrator) finish(ctx context.Context, receipt RestoreReceipt, cause error) (RestoreReceipt, error) {
	receipt = orchestrator.stamp(receipt)
	if err := orchestrator.Receipts.Put(context.WithoutCancel(ctx), receipt); err != nil {
		return receipt, errors.Join(cause, fmt.Errorf("store restore receipt: %w", err))
	}
	return receipt, cause
}

func (orchestrator RestoreOrchestrator) stamp(receipt RestoreReceipt) RestoreReceipt {
	receipt.CompletedAt = orchestrator.Now().UTC()
	receipt.ObservedRTOSeconds = maxSeconds(receipt.CompletedAt.Sub(receipt.StartedAt))
	receipt.ObservedRPOSeconds = maxSeconds(receipt.CompletedAt.Sub(receipt.RecoveryPointAt))
	return receipt
}

func maxSeconds(duration time.Duration) int64 {
	if duration <= 0 {
		return 0
	}
	return int64(duration / time.Second)
}

type MemoryReceiptStore struct {
	mu       sync.Mutex
	receipts map[string]RestoreReceipt
}

func NewMemoryReceiptStore() *MemoryReceiptStore {
	return &MemoryReceiptStore{receipts: make(map[string]RestoreReceipt)}
}

func (store *MemoryReceiptStore) Get(_ context.Context, operationID string) (RestoreReceipt, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	receipt, found := store.receipts[operationID]
	return receipt, found, nil
}

func (store *MemoryReceiptStore) Put(_ context.Context, receipt RestoreReceipt) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if previous, found := store.receipts[receipt.OperationID]; found {
		if previous.TargetID != receipt.TargetID || previous.BackupID != receipt.BackupID ||
			previous.ManifestSHA256 != receipt.ManifestSHA256 {
			return ErrIdempotencyConflict
		}
		return nil
	}
	store.receipts[receipt.OperationID] = receipt
	return nil
}
