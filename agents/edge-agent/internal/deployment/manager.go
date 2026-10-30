package deployment

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/certstore"
	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// Prechecker must inspect the staged release without mutating the active runtime
// and must honor context cancellation.
type Prechecker interface {
	Precheck(context.Context, string, string) error
}

// Runtime implementations must make Reload idempotent and honor context
// cancellation. The Manager owns the atomic current pointer.
type Runtime interface {
	Reload(context.Context, string, string) error
	Healthy(context.Context, string) error
}

type GenerationRuntime interface {
	CaptureGeneration(context.Context) (RuntimeGeneration, error)
	RemainingGeneration(context.Context, RuntimeGeneration) (int, error)
}

type Manager struct {
	mu                   sync.Mutex
	store                *diskStore
	prechecker           Prechecker
	runtime              Runtime
	generationRuntime    GenerationRuntime
	now                  func() time.Time
	config               Config
	certificateVersions  CertificateVersionStore
	certificateStateRoot string
	switchCurrent        func(string) error
	savePointers         func(Pointers) error
	// reloadCleared is set only by MultiScopeManager. It reloads the runtime
	// after this scope's current pointer was removed, so a scope whose first
	// release failed leaves the composition instead of staying loaded. The
	// legacy single-scope path leaves it nil and keeps its behavior.
	reloadCleared func(context.Context) error
}

func NewManager(stateRoot string, prechecker Prechecker, runtime Runtime) (*Manager, error) {
	return NewManagerWithConfig(stateRoot, prechecker, runtime, DefaultConfig())
}

func NewManagerWithConfig(stateRoot string, prechecker Prechecker, runtime Runtime, config Config) (*Manager, error) {
	return newManagerWithConfig(stateRoot, prechecker, runtime, config)
}

func newManagerWithConfig(stateRoot string, prechecker Prechecker, runtime Runtime, config Config) (*Manager, error) {
	if prechecker == nil || runtime == nil {
		return nil, fmt.Errorf("%w: prechecker and runtime are required", ErrInvalidCommand)
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	store, err := newDiskStore(stateRoot, config.Limits)
	if err != nil {
		return nil, err
	}
	manager := &Manager{
		store: store, prechecker: prechecker, runtime: runtime, now: time.Now, config: config,
		switchCurrent: store.switchCurrent, savePointers: store.savePointers,
	}
	return manager, nil
}

func (m *Manager) ConfigureGenerationRuntime(runtime GenerationRuntime) error {
	if m == nil || runtime == nil {
		return ErrInvalidCommand
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.generationRuntime != nil {
		return ErrConflict
	}
	m.generationRuntime = runtime
	return nil
}

func (m *Manager) Process(ctx context.Context, command Command) (Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	unlock, err := m.store.lock(ctx)
	if err != nil {
		return Result{}, err
	}
	defer unlock()

	normalized, digest, err := validateAndDigestWithLimits(command, m.config.Limits)
	if err != nil {
		return Result{}, err
	}
	value, err := m.store.loadJournal(command.DeploymentID)
	if err != nil {
		return Result{}, err
	}
	if value == nil {
		value = &journal{Version: journalVersion, DeploymentID: command.DeploymentID}
	}

	index := len(value.Attempts) - 1
	if index >= 0 {
		latest := &value.Attempts[index]
		switch {
		case command.Attempt < latest.Attempt:
			return Result{}, ErrStaleAttempt
		case command.Attempt > latest.Attempt && latest.Phase != "":
			return Result{}, fmt.Errorf("%w: previous attempt is not terminal", ErrConflict)
		case command.Attempt == latest.Attempt && digest != latest.CommandDigest:
			return Result{}, ErrConflict
		case command.Attempt == latest.Attempt:
			if latest.Action != command.Action || latest.ConfigVersionID != command.ConfigVersionID || latest.PreviousVersionID != command.PreviousVersionID {
				return Result{}, fmt.Errorf("%w: journal metadata differs from command digest", ErrCorruptState)
			}
			if latest.Phase == "" {
				return m.finish(resultFrom(value, latest))
			}
			return m.run(ctx, command, normalized, value, index)
		}
	}

	phase := phaseStage
	if command.Action == ActionRollback {
		phase = phaseExplicitRollbackValidate
	}
	record := attemptRecord{
		Attempt:           command.Attempt,
		Action:            command.Action,
		CommandDigest:     digest,
		ConfigVersionID:   command.ConfigVersionID,
		PreviousVersionID: command.PreviousVersionID,
		ManifestSHA256:    strings.ToLower(command.Bundle.ManifestSHA256),
		Phase:             phase,
		Transitions: []Transition{{
			Sequence: 1,
			State:    StateDelivered,
			At:       m.now().UTC(),
		}},
	}
	value.Attempts = append(value.Attempts, record)
	index = len(value.Attempts) - 1
	if err := m.store.saveJournal(value); err != nil {
		return Result{}, err
	}
	return m.run(ctx, command, normalized, value, index)
}

func (m *Manager) Lookup(deploymentID string) (Result, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := validateID(deploymentID, "deployment id"); err != nil {
		return Result{}, false, err
	}
	value, err := m.store.loadJournal(deploymentID)
	if err != nil {
		return Result{}, false, err
	}
	if value == nil {
		return Result{}, false, nil
	}
	record := &value.Attempts[len(value.Attempts)-1]
	return resultFrom(value, record), true, nil
}

func (m *Manager) Pointers() (Pointers, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.store.loadPointers()
}

func (m *Manager) StateRoot() string {
	if m == nil || m.store == nil {
		return ""
	}
	return m.store.root
}

func (m *Manager) run(ctx context.Context, command Command, normalized Manifest, value *journal, index int) (Result, error) {
	if command.Action == ActionRollback {
		return m.runExplicitRollback(ctx, command, value, index)
	}
	record := &value.Attempts[index]
	for {
		switch record.Phase {
		case phaseStage:
			_, err := m.store.stage(command, normalized)
			if err != nil {
				code := "STAGE_FAILED"
				if errors.Is(err, ErrDigestMismatch) {
					code = "DIGEST_MISMATCH"
				} else if errors.Is(err, ErrInvalidPath) {
					code = "INVALID_PATH"
				}
				return m.terminalFailure(value, record, code, "release staging failed", true, StateFailed)
			}
			if err := m.advance(value, record, StateStaged, phasePrecheck, false, "", ""); err != nil {
				return Result{}, err
			}
		case phasePrecheck:
			releasePath, err := m.store.releasePath(record.ManifestSHA256)
			if err != nil {
				return Result{}, err
			}
			if err := m.store.verifyRelease(releasePath, normalized, command.Bundle.ManifestSHA256); err != nil {
				return m.terminalFailure(value, record, "RELEASE_INVALID", "staged release verification failed", true, StateFailed)
			}
			if err := m.store.prepareRuntimeDirectories(); err != nil {
				return m.terminalFailure(value, record, "PRECHECK_FAILED", "runtime directory preparation failed", true, StateFailed)
			}
			if err := runBounded(ctx, m.config.PrecheckTimeout, func(operationCtx context.Context) error {
				return m.prechecker.Precheck(operationCtx, command.ConfigVersionID, releasePath)
			}); err != nil {
				return m.terminalFailure(value, record, "PRECHECK_FAILED", "release precheck failed", true, StateFailed)
			}
			if err := m.advance(value, record, StatePrechecked, phaseActivate, false, "", ""); err != nil {
				return Result{}, err
			}
		case phaseActivate:
			pointers, err := m.store.loadPointers()
			if err != nil {
				return Result{}, err
			}
			activeDigest, err := m.store.currentDigest()
			if err != nil {
				return Result{}, err
			}
			desiredPointers := Pointers{
				Current:        command.ConfigVersionID,
				CurrentDigest:  record.ManifestSHA256,
				Previous:       record.PriorPointers.Current,
				PreviousDigest: record.PriorPointers.CurrentDigest,
			}
			recoveryUncertain := false
			if !record.PriorPointersSet {
				if pointers.Current != command.PreviousVersionID || activeDigest != pointers.CurrentDigest {
					return m.terminalFailure(value, record, "PREVIOUS_VERSION_MISMATCH", "current version does not match rollback target", true, StateFailed)
				}
				record.PriorPointers = pointers
				record.PriorPointersSet = true
				if err := m.store.saveJournal(value); err != nil {
					return Result{}, err
				}
				desiredPointers = Pointers{
					Current:        command.ConfigVersionID,
					CurrentDigest:  record.ManifestSHA256,
					Previous:       record.PriorPointers.Current,
					PreviousDigest: record.PriorPointers.CurrentDigest,
				}
			} else {
				if record.PriorPointers.Current != command.PreviousVersionID ||
					(pointers != record.PriorPointers && pointers != desiredPointers) ||
					(activeDigest != record.PriorPointers.CurrentDigest && activeDigest != desiredPointers.CurrentDigest) {
					return Result{}, fmt.Errorf("%w: saved activation pointers differ", ErrCorruptState)
				}
				recoveryUncertain = pointers == desiredPointers || activeDigest == desiredPointers.CurrentDigest
			}
			if m.generationRuntime != nil && !record.GenerationCaptured {
				if recoveryUncertain {
					if err := m.advance(value, record, StateActivated, phaseRollback, false, "DRAIN_CAPTURE_RECOVERY_FAILED", "activation recovery cannot identify the previous OpenResty worker generation"); err != nil {
						return Result{}, err
					}
					continue
				}
				if record.PriorPointers.Current != "" {
					generation, err := m.captureGeneration(ctx)
					if err != nil {
						return m.terminalFailure(value, record, "DRAIN_CAPTURE_FAILED", "previous OpenResty worker generation could not be captured", true, StateFailed)
					}
					record.OldGeneration = generation
				}
				record.GenerationCaptured = true
				if err := m.store.saveJournal(value); err != nil {
					return Result{}, err
				}
			}
			priorReferences, referencesChanged, err := m.prepareCertificateReferences(
				ctx, command.ConfigVersionID, desiredPointers.CurrentDigest,
				desiredPointers.Previous, desiredPointers.PreviousDigest,
			)
			if err != nil {
				if errors.Is(err, errCertificateReferenceRecovery) {
					return m.rollbackFailure(value, record, "CERTIFICATE_REFERENCE_RECOVERY_FAILED", "certificate references could not be restored")
				}
				return m.terminalFailure(value, record, "CERTIFICATE_REFERENCE_FAILED", "certificate references could not be verified", true, StateFailed)
			}
			if activeDigest != desiredPointers.CurrentDigest {
				if err := m.switchCurrent(desiredPointers.CurrentDigest); err != nil {
					if restoreErr := m.restoreCertificateReferences(ctx, priorReferences, referencesChanged); restoreErr != nil {
						return m.rollbackFailure(value, record, "CERTIFICATE_REFERENCE_RECOVERY_FAILED", "certificate references could not be restored")
					}
					return m.terminalFailure(value, record, "POINTER_ACTIVATION_FAILED", "release pointer activation failed", true, StateFailed)
				}
			}
			if err := m.reload(ctx, command.ConfigVersionID); err != nil {
				if recoveryUncertain {
					if err := m.advance(value, record, StateActivated, phaseRollback, false, "RECOVERY_ACTIVATION_FAILED", "activation recovery could not confirm the selected release"); err != nil {
						return Result{}, err
					}
					continue
				}
				if restoreErr := m.restore(ctx, record.PriorPointers, priorReferences, referencesChanged); restoreErr != nil {
					return m.rollbackFailure(value, record, "ACTIVATION_RECOVERY_FAILED", "runtime activation failed and the previous release could not be confirmed")
				}
				return m.terminalFailure(value, record, "ACTIVATION_FAILED", "runtime activation failed", true, StateFailed)
			}
			if err := m.savePointers(desiredPointers); err != nil {
				if restoreErr := m.restore(ctx, record.PriorPointers, priorReferences, referencesChanged); restoreErr != nil {
					return m.rollbackFailure(value, record, "POINTER_STATE_RECOVERY_FAILED", "activation state could not be persisted or restored")
				}
				return Result{}, err
			}
			if err := m.advance(value, record, StateActivated, phaseHealth, false, "", ""); err != nil {
				return Result{}, err
			}
		case phaseHealth:
			if err := m.waitHealthy(ctx, command.ConfigVersionID); err == nil {
				if err := m.advance(value, record, StateHealthy, "", false, "", ""); err != nil {
					return Result{}, err
				}
				return m.finish(resultFrom(value, record))
			}
			if err := m.advance(value, record, StateReverting, phaseRollback, false, "HEALTH_FAILED", "activated release failed health verification"); err != nil {
				return Result{}, err
			}
		case phaseRollback:
			if record.Transitions[len(record.Transitions)-1].State == StateActivated {
				latest := record.Transitions[len(record.Transitions)-1]
				code, summary := latest.ErrorCode, latest.Summary
				if code == "" {
					code, summary = "ACTIVATION_RECOVERY_REQUIRED", "reverting an activation with an uncertain outcome"
				}
				if err := m.advance(value, record, StateReverting, phaseRollback, false, code, summary); err != nil {
					return Result{}, err
				}
			}
			return m.rollback(ctx, value, record)
		case "":
			return m.finish(resultFrom(value, record))
		default:
			return Result{}, fmt.Errorf("%w: unknown execution phase", ErrCorruptState)
		}
	}
}

func (m *Manager) runExplicitRollback(ctx context.Context, command Command, value *journal, index int) (Result, error) {
	record := &value.Attempts[index]
	for {
		switch record.Phase {
		case phaseExplicitRollbackValidate:
			pointers, err := m.store.loadPointers()
			if err != nil {
				return m.explicitRollbackFailure(value, record, "ROLLBACK_BASELINE_INVALID", "current rollback baseline is invalid", true, StateFailed)
			}
			if pointers.Current == "" || pointers.Current != command.PreviousVersionID {
				return m.explicitRollbackFailure(value, record, "ROLLBACK_BASELINE_MISMATCH", "current version does not match the rollback command baseline", true, StateFailed)
			}
			if pointers.Previous == "" || pointers.PreviousDigest == "" {
				return m.explicitRollbackFailure(value, record, "ROLLBACK_TARGET_UNAVAILABLE", "no previous healthy release is available", true, StateFailed)
			}
			if pointers.Previous != command.ConfigVersionID {
				return m.explicitRollbackFailure(value, record, "ROLLBACK_TARGET_MISMATCH", "requested rollback target is not the previous healthy version", true, StateFailed)
			}
			activeDigest, err := m.store.currentDigest()
			if err != nil {
				return m.explicitRollbackFailure(value, record, "ROLLBACK_BASELINE_INVALID", "current rollback baseline is invalid", true, StateFailed)
			}
			if activeDigest != pointers.CurrentDigest {
				return m.explicitRollbackFailure(value, record, "ROLLBACK_BASELINE_MISMATCH", "current release pointer does not match the rollback command baseline", true, StateFailed)
			}
			record.PriorPointers = pointers
			record.PriorPointersSet = true
			record.ManifestSHA256 = pointers.PreviousDigest
			if err := m.store.saveJournal(value); err != nil {
				return Result{}, err
			}
			if code, summary := m.verifyExplicitRollbackTarget(record); code != "" {
				return m.explicitRollbackFailure(value, record, code, summary, true, StateFailed)
			}
			if err := m.advance(value, record, StateStaged, phaseExplicitRollbackPrecheck, false, "", ""); err != nil {
				return Result{}, err
			}
		case phaseExplicitRollbackPrecheck:
			if code, summary := m.verifyExplicitRollbackTarget(record); code != "" {
				return m.explicitRollbackFailure(value, record, code, summary, true, StateFailed)
			}
			if err := m.store.prepareRuntimeDirectories(); err != nil {
				return m.explicitRollbackFailure(value, record, "ROLLBACK_PRECHECK_FAILED", "rollback runtime directory preparation failed", true, StateFailed)
			}
			releasePath, _ := m.store.releasePath(record.ManifestSHA256)
			if err := runBounded(ctx, m.config.PrecheckTimeout, func(operationCtx context.Context) error {
				return m.prechecker.Precheck(operationCtx, command.ConfigVersionID, releasePath)
			}); err != nil {
				return m.explicitRollbackFailure(value, record, "ROLLBACK_PRECHECK_FAILED", "rollback release precheck failed", true, StateFailed)
			}
			if err := m.advance(value, record, StatePrechecked, phaseExplicitRollbackActivate, false, "", ""); err != nil {
				return Result{}, err
			}
		case phaseExplicitRollbackActivate:
			pointers, err := m.store.loadPointers()
			if err != nil || pointers != record.PriorPointers {
				return m.explicitRollbackFailure(value, record, "ROLLBACK_BASELINE_MISMATCH", "current pointers changed before rollback activation", true, StateFailed)
			}
			activeDigest, err := m.store.currentDigest()
			if err != nil || activeDigest != record.PriorPointers.CurrentDigest {
				return m.explicitRollbackFailure(value, record, "ROLLBACK_BASELINE_MISMATCH", "current release changed before rollback activation", true, StateFailed)
			}
			if err := m.advance(value, record, StateReverting, phaseExplicitRollbackVerify, false, "", ""); err != nil {
				return Result{}, err
			}
		case phaseExplicitRollbackVerify:
			if code, summary := m.activateExplicitRollback(ctx, command, record); code != "" {
				record.RollbackErrorCode = code
				record.RollbackSummary = summary
				record.Phase = phaseExplicitRollbackRestore
				if err := m.store.saveJournal(value); err != nil {
					_ = m.restoreExplicitRollbackBaseline(context.WithoutCancel(ctx), record)
					return Result{}, err
				}
				continue
			}
			if err := m.advance(value, record, StateReverted, "", false, "", ""); err != nil {
				return Result{}, err
			}
			return m.finish(resultFrom(value, record))
		case phaseExplicitRollbackRestore:
			if err := m.restoreExplicitRollbackBaseline(context.WithoutCancel(ctx), record); err != nil {
				return m.explicitRollbackFailure(value, record, "ROLLBACK_RESTORE_FAILED", "rollback target failed and the original release could not be confirmed", false, StateRollbackFailed)
			}
			code, summary := record.RollbackErrorCode, record.RollbackSummary
			record.RollbackErrorCode = ""
			record.RollbackSummary = ""
			return m.explicitRollbackFailure(value, record, code, summary, true, StateFailed)
		case "":
			return resultFrom(value, record), nil
		default:
			return Result{}, fmt.Errorf("%w: unknown explicit rollback phase", ErrCorruptState)
		}
	}
}

func (m *Manager) verifyExplicitRollbackTarget(record *attemptRecord) (string, string) {
	releasePath, err := m.store.releasePath(record.ManifestSHA256)
	if err != nil {
		return "ROLLBACK_TARGET_INVALID", "rollback target digest is invalid"
	}
	if err := m.store.verifyExistingRelease(releasePath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "ROLLBACK_TARGET_UNAVAILABLE", "rollback target release is unavailable"
		}
		return "ROLLBACK_TARGET_INVALID", "rollback target release failed digest verification"
	}
	return "", ""
}

func (m *Manager) activateExplicitRollback(ctx context.Context, command Command, record *attemptRecord) (string, string) {
	if code, summary := m.verifyExplicitRollbackTarget(record); code != "" {
		return code, summary
	}
	desired := Pointers{
		Current:        command.ConfigVersionID,
		CurrentDigest:  record.ManifestSHA256,
		Previous:       record.PriorPointers.Current,
		PreviousDigest: record.PriorPointers.CurrentDigest,
	}
	pointers, err := m.store.loadPointers()
	if err != nil {
		return "ROLLBACK_BASELINE_INVALID", "rollback pointer state is invalid"
	}
	activeDigest, err := m.store.currentDigest()
	if err != nil {
		return "ROLLBACK_TARGET_INVALID", "active rollback release failed digest verification"
	}
	switch {
	case pointers == record.PriorPointers && (activeDigest == record.PriorPointers.CurrentDigest || activeDigest == record.ManifestSHA256):
	case pointers == desired && activeDigest == record.ManifestSHA256:
	default:
		return "ROLLBACK_BASELINE_MISMATCH", "rollback activation state conflicts with the recorded baseline"
	}
	if _, _, err := m.prepareCertificateReferences(
		ctx, command.ConfigVersionID, record.ManifestSHA256,
		record.PriorPointers.Current, record.PriorPointers.CurrentDigest,
	); err != nil {
		return "ROLLBACK_CERTIFICATE_REFERENCE_FAILED", "rollback certificate references could not be verified"
	}
	if activeDigest != record.ManifestSHA256 {
		if err := m.switchCurrent(record.ManifestSHA256); err != nil {
			return "ROLLBACK_POINTER_FAILED", "rollback target pointer activation failed"
		}
	}
	if err := m.reload(ctx, command.ConfigVersionID); err != nil {
		return "ROLLBACK_ACTIVATION_FAILED", "rollback target activation failed"
	}
	if err := m.waitHealthy(ctx, command.ConfigVersionID); err != nil {
		return "ROLLBACK_HEALTH_FAILED", "rollback target failed health verification"
	}
	if err := m.savePointers(desired); err != nil {
		return "ROLLBACK_POINTER_STATE_FAILED", "rollback pointer state could not be persisted"
	}
	return "", ""
}

func (m *Manager) restoreExplicitRollbackBaseline(ctx context.Context, record *attemptRecord) error {
	if _, _, err := m.prepareCertificateReferences(
		ctx, record.PriorPointers.Current, record.PriorPointers.CurrentDigest,
		record.ConfigVersionID, record.ManifestSHA256,
	); err != nil {
		return err
	}
	activeDigest, err := m.store.currentDigest()
	if err != nil {
		return err
	}
	if activeDigest != record.PriorPointers.CurrentDigest {
		if err := m.switchCurrent(record.PriorPointers.CurrentDigest); err != nil {
			return err
		}
	}
	if err := m.reload(ctx, record.PriorPointers.Current); err != nil {
		return err
	}
	if err := m.waitHealthy(ctx, record.PriorPointers.Current); err != nil {
		return err
	}
	return m.savePointers(record.PriorPointers)
}

func (m *Manager) explicitRollbackFailure(value *journal, record *attemptRecord, code, summary string, unchanged bool, state State) (Result, error) {
	record.RollbackErrorCode = ""
	record.RollbackSummary = ""
	if err := m.advance(value, record, state, "", unchanged, code, summary); err != nil {
		return Result{}, err
	}
	return resultFrom(value, record), nil
}

func (m *Manager) rollback(ctx context.Context, value *journal, record *attemptRecord) (Result, error) {
	previous := record.PriorPointers
	fail := func(code, summary string) (Result, error) {
		if m.certificateVersions == nil {
			return m.terminalFailure(value, record, code, summary, false, StateRollbackFailed)
		}
		if recoveryErr := m.restoreFailedRollbackCandidate(context.WithoutCancel(ctx), record); recoveryErr != nil {
			code = "ROLLBACK_RECOVERY_FAILED"
			summary = "rollback failed and the activated candidate could not be restored"
		}
		return m.terminalFailure(value, record, code, summary, false, StateRollbackFailed)
	}
	if m.reloadCleared != nil && previous == (Pointers{}) && record.PreviousVersionID == "" {
		return m.rollbackToEmpty(ctx, value, record)
	}
	if previous.Current == "" || record.PreviousVersionID != previous.Current || previous.CurrentDigest == "" {
		return m.terminalFailure(value, record, "ROLLBACK_TARGET_UNAVAILABLE", "no explicit previous healthy version is available", false, StateRollbackFailed)
	}
	releasePath, err := m.store.releasePath(previous.CurrentDigest)
	if err != nil {
		return m.terminalFailure(value, record, "ROLLBACK_TARGET_UNAVAILABLE", "previous release is unavailable", false, StateRollbackFailed)
	}
	if err := m.store.verifyExistingRelease(releasePath); err != nil {
		return m.terminalFailure(value, record, "ROLLBACK_TARGET_UNAVAILABLE", "previous release is unavailable", false, StateRollbackFailed)
	}
	if _, _, err := m.prepareCertificateReferences(
		ctx, previous.Current, previous.CurrentDigest,
		previous.Previous, previous.PreviousDigest,
	); err != nil {
		return fail("ROLLBACK_CERTIFICATE_REFERENCE_FAILED", "previous certificate references could not be verified")
	}
	if err := m.switchCurrent(previous.CurrentDigest); err != nil {
		return fail("ROLLBACK_POINTER_FAILED", "rollback pointer activation failed")
	}
	if err := m.reload(ctx, previous.Current); err != nil {
		if m.certificateVersions == nil {
			_ = m.switchCurrent(record.ManifestSHA256)
		}
		return fail("ROLLBACK_ACTIVATION_FAILED", "rollback activation failed")
	}
	if err := m.waitHealthy(ctx, previous.Current); err != nil {
		return fail("ROLLBACK_HEALTH_FAILED", "previous release failed health verification")
	}
	if err := m.savePointers(previous); err != nil {
		if m.certificateVersions == nil {
			return Result{}, err
		}
		return fail("ROLLBACK_POINTER_STATE_FAILED", "rollback pointer state could not be persisted")
	}
	if err := m.advance(value, record, StateReverted, "", false, "", ""); err != nil {
		return Result{}, err
	}
	return m.finish(resultFrom(value, record))
}

// rollbackToEmpty reverts a scope's first release by removing it from the
// runtime; the other scopes keep running unchanged.
func (m *Manager) rollbackToEmpty(ctx context.Context, value *journal, record *attemptRecord) (Result, error) {
	if _, _, err := m.prepareCertificateReferences(ctx, "", "", "", ""); err != nil {
		return m.terminalFailure(value, record, "ROLLBACK_CERTIFICATE_REFERENCE_FAILED", "previous certificate references could not be verified", false, StateRollbackFailed)
	}
	if err := m.switchCurrent(""); err != nil {
		return m.terminalFailure(value, record, "ROLLBACK_POINTER_FAILED", "rollback pointer activation failed", false, StateRollbackFailed)
	}
	if err := runBounded(ctx, m.config.ReloadTimeout, m.reloadCleared); err != nil {
		return m.terminalFailure(value, record, "ROLLBACK_ACTIVATION_FAILED", "rollback activation failed", false, StateRollbackFailed)
	}
	if err := m.savePointers(Pointers{}); err != nil {
		return Result{}, err
	}
	if err := m.advance(value, record, StateReverted, "", false, "", ""); err != nil {
		return Result{}, err
	}
	return m.finish(resultFrom(value, record))
}

func (m *Manager) restoreFailedRollbackCandidate(ctx context.Context, record *attemptRecord) error {
	desired := Pointers{
		Current:        record.ConfigVersionID,
		CurrentDigest:  record.ManifestSHA256,
		Previous:       record.PriorPointers.Current,
		PreviousDigest: record.PriorPointers.CurrentDigest,
	}
	if _, _, err := m.prepareCertificateReferences(
		ctx, desired.Current, desired.CurrentDigest, desired.Previous, desired.PreviousDigest,
	); err != nil {
		return err
	}
	activeDigest, err := m.store.currentDigest()
	if err != nil {
		return err
	}
	if activeDigest != desired.CurrentDigest {
		if err := m.switchCurrent(desired.CurrentDigest); err != nil {
			return err
		}
	}
	if err := m.reload(ctx, desired.Current); err != nil {
		return err
	}
	if err := m.waitHealthy(ctx, desired.Current); err != nil {
		return err
	}
	return m.savePointers(desired)
}

func (m *Manager) rollbackFailure(value *journal, record *attemptRecord, code, summary string) (Result, error) {
	if err := m.advance(value, record, StateActivated, phaseRollback, false, code, summary); err != nil {
		return Result{}, err
	}
	if err := m.advance(value, record, StateReverting, phaseRollback, false, code, summary); err != nil {
		return Result{}, err
	}
	return m.terminalFailure(value, record, code, summary, false, StateRollbackFailed)
}

func (m *Manager) terminalFailure(value *journal, record *attemptRecord, code, summary string, unchanged bool, state State) (Result, error) {
	if err := m.advance(value, record, state, "", unchanged, code, summary); err != nil {
		return Result{}, err
	}
	return m.finish(resultFrom(value, record))
}

func (m *Manager) reload(ctx context.Context, versionID string) error {
	return runBounded(ctx, m.config.ReloadTimeout, func(operationCtx context.Context) error {
		return m.runtime.Reload(operationCtx, versionID, m.store.currentLink)
	})
}

func (m *Manager) captureGeneration(ctx context.Context) (RuntimeGeneration, error) {
	var generation RuntimeGeneration
	err := runBounded(ctx, m.config.ReloadTimeout, func(operationCtx context.Context) error {
		var err error
		generation, err = m.generationRuntime.CaptureGeneration(operationCtx)
		return err
	})
	if err != nil {
		return RuntimeGeneration{}, err
	}
	if !validRuntimeGeneration(generation) {
		return RuntimeGeneration{}, ErrCorruptState
	}
	return generation, nil
}

func (m *Manager) restore(ctx context.Context, pointers Pointers, references certstore.CertificateVersionReferences, referencesChanged bool) error {
	if err := m.restoreCertificateReferences(ctx, references, referencesChanged); err != nil {
		return err
	}
	if err := m.switchCurrent(pointers.CurrentDigest); err != nil {
		return err
	}
	if pointers.Current != "" {
		if err := m.reload(ctx, pointers.Current); err != nil {
			return err
		}
		if err := m.waitHealthy(ctx, pointers.Current); err != nil {
			return err
		}
	} else if m.reloadCleared != nil {
		if err := runBounded(ctx, m.config.ReloadTimeout, m.reloadCleared); err != nil {
			return err
		}
	}
	return m.savePointers(pointers)
}

func (m *Manager) waitHealthy(ctx context.Context, versionID string) error {
	healthCtx, cancel := context.WithTimeout(ctx, m.config.HealthTimeout)
	defer cancel()
	ticker := time.NewTicker(m.config.HealthInterval)
	defer ticker.Stop()
	for {
		if err := m.runtime.Healthy(healthCtx, versionID); err == nil {
			return nil
		}
		if err := healthCtx.Err(); err != nil {
			return err
		}
		select {
		case <-healthCtx.Done():
			return healthCtx.Err()
		case <-ticker.C:
		}
	}
}

func runBounded(ctx context.Context, timeout time.Duration, operation func(context.Context) error) error {
	operationCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return operation(operationCtx)
}

func (m *Manager) finish(result Result) (Result, error) {
	pointers, err := m.store.loadPointers()
	if err != nil {
		return result, err
	}
	protected := map[string]struct{}{}
	for _, digest := range []string{pointers.CurrentDigest, pointers.PreviousDigest} {
		if digest != "" {
			protected[digest] = struct{}{}
		}
	}
	activeDigest, err := m.store.currentDigest()
	if err != nil {
		return result, err
	}
	if activeDigest != "" {
		protected[activeDigest] = struct{}{}
	}
	if err := m.store.protectInProgressReleases(protected); err != nil {
		return result, err
	}
	if err := m.store.pruneReleases(m.config.RetainReleases, protected); err != nil {
		return result, err
	}
	return result, nil
}

func (m *Manager) advance(value *journal, record *attemptRecord, state State, next executionPhase, unchanged bool, code, summary string) error {
	record.Transitions = append(record.Transitions, Transition{
		Sequence:               uint64(len(record.Transitions) + 1),
		State:                  state,
		At:                     m.now().UTC(),
		RunningConfigUnchanged: unchanged,
		ErrorCode:              code,
		Summary:                summary,
	})
	record.Phase = next
	return m.store.saveJournal(value)
}

func resultFrom(value *journal, record *attemptRecord) Result {
	transitions := append([]Transition(nil), record.Transitions...)
	latest := transitions[len(transitions)-1]
	return Result{
		DeploymentID:           value.DeploymentID,
		Attempt:                record.Attempt,
		Action:                 record.Action,
		ConfigVersionID:        record.ConfigVersionID,
		State:                  latest.State,
		Sequence:               latest.Sequence,
		Transitions:            transitions,
		RunningConfigUnchanged: latest.RunningConfigUnchanged,
		ErrorCode:              latest.ErrorCode,
		Summary:                latest.Summary,
	}
}

func validateAndDigest(command Command) (Manifest, string, error) {
	return validateAndDigestWithLimits(command, DefaultConfig().Limits)
}

func validateAndDigestWithLimits(command Command, limits Limits) (Manifest, string, error) {
	if err := validateID(command.DeploymentID, "deployment id"); err != nil {
		return Manifest{}, "", err
	}
	if command.Attempt == 0 {
		return Manifest{}, "", fmt.Errorf("%w: attempt must be positive", ErrInvalidCommand)
	}
	if command.Action != ActionApply && command.Action != ActionRollback {
		return Manifest{}, "", fmt.Errorf("%w: unsupported action", ErrInvalidCommand)
	}
	if err := validateID(command.ConfigVersionID, "config version id"); err != nil {
		return Manifest{}, "", err
	}
	if command.PreviousVersionID != "" {
		if err := validateID(command.PreviousVersionID, "previous version id"); err != nil {
			return Manifest{}, "", err
		}
		if command.PreviousVersionID == command.ConfigVersionID {
			return Manifest{}, "", fmt.Errorf("%w: current and previous versions are identical", ErrInvalidCommand)
		}
	}
	if command.Action == ActionRollback {
		if command.PreviousVersionID == "" {
			return Manifest{}, "", fmt.Errorf("%w: rollback baseline is required", ErrInvalidCommand)
		}
		if command.Bundle.ManifestSHA256 != "" || len(command.Bundle.Manifest.Files) != 0 || len(command.Bundle.Files) != 0 {
			return Manifest{}, "", fmt.Errorf("%w: rollback cannot carry a deployment bundle", ErrInvalidCommand)
		}
		payload := struct {
			DeploymentID      string `json:"deployment_id"`
			Attempt           uint32 `json:"attempt"`
			Action            Action `json:"action"`
			ConfigVersionID   string `json:"config_version_id"`
			PreviousVersionID string `json:"previous_version_id"`
		}{command.DeploymentID, command.Attempt, command.Action, command.ConfigVersionID, command.PreviousVersionID}
		encoded, err := json.Marshal(payload)
		if err != nil {
			return Manifest{}, "", fmt.Errorf("marshal command digest: %w", err)
		}
		sum := sha256.Sum256(encoded)
		return Manifest{}, hex.EncodeToString(sum[:]), nil
	}
	if !validSHA256(command.Bundle.ManifestSHA256) {
		return Manifest{}, "", fmt.Errorf("%w: invalid manifest digest", ErrInvalidCommand)
	}
	normalized, err := normalizeManifest(command.Bundle.Manifest)
	if err != nil {
		return Manifest{}, "", err
	}
	if err := validateBundleLimits(normalized, command.Bundle.Files, limits); err != nil {
		return Manifest{}, "", err
	}
	if err := edgeconfig.ValidateBundle(command.Bundle); err != nil {
		return Manifest{}, "", fmt.Errorf("%w: bundle semantics are invalid", ErrInvalidCommand)
	}
	payload := struct {
		DeploymentID      string   `json:"deployment_id"`
		Attempt           uint32   `json:"attempt"`
		Action            Action   `json:"action"`
		ConfigVersionID   string   `json:"config_version_id"`
		PreviousVersionID string   `json:"previous_version_id,omitempty"`
		Manifest          Manifest `json:"manifest"`
		ManifestSHA256    string   `json:"manifest_sha256"`
	}{
		DeploymentID:      command.DeploymentID,
		Attempt:           command.Attempt,
		Action:            command.Action,
		ConfigVersionID:   command.ConfigVersionID,
		PreviousVersionID: command.PreviousVersionID,
		Manifest:          normalized,
		ManifestSHA256:    strings.ToLower(command.Bundle.ManifestSHA256),
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return Manifest{}, "", fmt.Errorf("marshal command digest: %w", err)
	}
	sum := sha256.Sum256(b)
	return normalized, hex.EncodeToString(sum[:]), nil
}
