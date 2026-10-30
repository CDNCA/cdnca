package http3runtime

import (
	"context"
	"crypto/hmac"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Runtime interface {
	Precheck(context.Context, string) error
	Activate(context.Context, string) error
	Healthy(context.Context, string) error
	Stop(context.Context, string) error
}

type runtimeEvidenceProvider interface {
	ActiveEvidence(context.Context, string, string, string) (string, error)
}

type Manager struct {
	mu      sync.Mutex
	store   *diskStore
	runtime Runtime
	now     func() time.Time
}

func NewManager(stateRoot string, runtime Runtime) (*Manager, error) {
	return newManager(stateRoot, runtime, time.Now)
}

func newManager(stateRoot string, runtime Runtime, now func() time.Time) (*Manager, error) {
	if runtime == nil || now == nil {
		return nil, ErrInvalidPolicy
	}
	store, err := newDiskStore(stateRoot)
	if err != nil {
		return nil, err
	}
	manager := &Manager{store: store, runtime: runtime, now: now}
	unlock, err := store.lock(context.Background())
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := manager.recoverActivation(context.Background()); err != nil {
		return nil, err
	}
	return manager, nil
}

func (m *Manager) Apply(ctx context.Context, policy Policy) (Result, error) {
	compiled, err := Compile(policy)
	if err != nil {
		return Result{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	unlock, err := m.store.lock(ctx)
	if err != nil {
		return Result{}, err
	}
	defer unlock()
	if err := m.recoverActivation(ctx); err != nil {
		return Result{}, err
	}
	previous, err := m.store.loadActive()
	if err != nil {
		return Result{}, err
	}
	if previous != nil && previous.VersionID == compiled.Policy.VersionID {
		if previous.Digest != compiled.Digest {
			return Result{}, ErrConflict
		}
		return appliedResult(previous), nil
	}
	stagePath, err := m.store.stage(compiled)
	if err != nil {
		if errors.Is(err, errCandidateAsset) {
			return failedResult(compiled, previous, "PRECHECK_FAILED", true), fmt.Errorf("%w: %v", ErrPrecheck, err)
		}
		return Result{}, err
	}
	stagePending := true
	defer func() {
		if stagePending {
			_ = os.RemoveAll(stagePath)
		}
	}()
	if err := m.runtime.Precheck(ctx, stagePath); err != nil {
		return failedResult(compiled, previous, "PRECHECK_FAILED", true), fmt.Errorf("%w: %v", ErrPrecheck, err)
	}
	versionDir, err := m.store.commitStage(stagePath, compiled)
	if err != nil {
		return Result{}, err
	}
	stagePending = false
	active := activeRecord{
		SchemaVersion: stateSchemaVersion, VersionID: compiled.Policy.VersionID, Digest: compiled.Digest,
		VersionDir: versionDir, AppliedAt: m.now().UTC(),
	}
	journal := activationJournal{
		SchemaVersion: activationJournalSchemaVersion,
		Stage:         activationStagePrepared,
		Candidate:     active,
		Previous:      previous,
		CreatedAt:     m.now().UTC(),
	}
	if err := m.store.saveActivationJournal(journal); err != nil {
		return Result{}, err
	}
	if err := m.store.switchCurrent(versionDir); err != nil {
		return Result{}, err
	}
	if err := m.runtime.Activate(ctx, m.store.currentPath); err != nil {
		return m.activationFailure(compiled, previous, "ACTIVATION_FAILED", err)
	}
	if err := m.runtime.Healthy(ctx, m.store.currentPath); err != nil {
		return m.activationFailure(compiled, previous, "HEALTH_FAILED", fmt.Errorf("%w: %v", ErrHealth, err))
	}
	if provider, ok := m.runtime.(runtimeEvidenceProvider); ok {
		evidence, err := provider.ActiveEvidence(ctx, m.store.currentPath, active.VersionID, active.Digest)
		if err != nil || !validDigest(evidence) {
			if err == nil {
				err = ErrCorruptState
			}
			return m.activationFailure(compiled, previous, "EVIDENCE_FAILED", err)
		}
		journal.Stage = activationStageConfirmed
		journal.Evidence = evidence
		if err := m.store.saveActivationJournal(journal); err != nil {
			return m.activationFailure(compiled, previous, "EVIDENCE_FAILED", err)
		}
	}
	if err := m.store.saveActive(active); err != nil {
		if _, rollbackErr := m.restoreWithTimeout(previous); rollbackErr != nil {
			return failedResult(compiled, previous, "ROLLBACK_FAILED", false), fmt.Errorf("persist active state: %w; restore LKG: %v", err, rollbackErr)
		}
		if restoreErr := m.store.restoreActive(previous); restoreErr != nil {
			return failedResult(compiled, previous, "ROLLBACK_FAILED", false), restoreErr
		}
		if clearErr := m.store.clearActivationJournal(); clearErr != nil {
			return failedResult(compiled, previous, "ROLLBACK_FAILED", false), clearErr
		}
		return Result{}, err
	}
	if err := m.store.clearActivationJournal(); err != nil {
		return Result{}, err
	}
	return appliedResult(&active), nil
}

func (m *Manager) activationFailure(compiled CompiledPolicy, previous *activeRecord, code string, cause error) (Result, error) {
	unchanged, rollbackErr := m.restoreWithTimeout(previous)
	if rollbackErr != nil {
		return failedResult(compiled, previous, "ROLLBACK_FAILED", false), fmt.Errorf("%w: %v; restore LKG: %v", ErrActivation, cause, rollbackErr)
	}
	if clearErr := m.store.clearActivationJournal(); clearErr != nil {
		return failedResult(compiled, previous, "ROLLBACK_FAILED", false), fmt.Errorf("%w: %v; clear recovery journal: %v", ErrActivation, cause, clearErr)
	}
	return failedResult(compiled, previous, code, unchanged), fmt.Errorf("%w: %v", ErrActivation, cause)
}

func (m *Manager) restoreWithTimeout(previous *activeRecord) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return m.restore(ctx, previous)
}

func (m *Manager) restore(ctx context.Context, previous *activeRecord) (bool, error) {
	if previous == nil {
		if err := m.runtime.Stop(ctx, m.store.currentPath); err != nil {
			return false, err
		}
		if err := m.store.clearCurrent(); err != nil {
			return false, err
		}
		return true, nil
	}
	if err := m.store.switchCurrent(previous.VersionDir); err != nil {
		return false, err
	}
	if err := m.runtime.Activate(ctx, m.store.currentPath); err != nil {
		return false, err
	}
	if err := m.runtime.Healthy(ctx, m.store.currentPath); err != nil {
		return false, err
	}
	return true, nil
}

func (m *Manager) recoverActivation(ctx context.Context) error {
	journal, err := m.store.loadActivationJournal()
	if err != nil || journal == nil {
		return err
	}
	active, err := m.store.loadActive()
	if err != nil {
		return err
	}
	current, err := m.store.currentVersionDir()
	if err != nil {
		return err
	}
	if sameActiveRecord(active, &journal.Candidate) {
		if current != journal.Candidate.VersionDir {
			if err := m.store.switchCurrent(journal.Candidate.VersionDir); err != nil {
				return err
			}
		}
		return m.store.clearActivationJournal()
	}
	if !sameActiveRecord(active, journal.Previous) ||
		(current != "" && current != journal.Candidate.VersionDir &&
			(journal.Previous == nil || current != journal.Previous.VersionDir)) {
		return ErrCorruptState
	}
	if journal.Stage == activationStageConfirmed && current == journal.Candidate.VersionDir {
		if provider, ok := m.runtime.(runtimeEvidenceProvider); ok {
			evidence, evidenceErr := provider.ActiveEvidence(ctx, m.store.currentPath, journal.Candidate.VersionID, journal.Candidate.Digest)
			if evidenceErr == nil && validDigest(evidence) && hmac.Equal([]byte(evidence), []byte(journal.Evidence)) {
				if healthErr := m.runtime.Healthy(ctx, m.store.currentPath); healthErr == nil {
					if err := m.store.saveActive(journal.Candidate); err != nil {
						return err
					}
					return m.store.clearActivationJournal()
				}
			}
		}
	}
	if _, err := m.restore(ctx, journal.Previous); err != nil {
		return fmt.Errorf("recover HTTP/3 last known good: %w", err)
	}
	return m.store.clearActivationJournal()
}

func (r *OpenResty) ActiveEvidence(ctx context.Context, currentPath, versionID, digest string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if r.closed || currentPath != filepath.Join(r.stateRoot, "current") || !validDigest(digest) {
		return "", ErrCorruptState
	}
	target, err := os.Readlink(currentPath)
	if err != nil || filepath.Dir(target) != "versions" || filepath.Base(target) != versionID+"-"+digest {
		return "", ErrCorruptState
	}
	policy, err := loadPolicy(currentPath)
	if err != nil || policy.VersionID != versionID {
		return "", ErrCorruptState
	}
	compiled, err := Compile(policy)
	if err != nil || compiled.Digest != digest {
		return "", ErrCorruptState
	}
	handle, identity, running, err := r.openOwnedProcess()
	if err != nil {
		return "", err
	}
	if handle == nil || !running {
		if handle != nil {
			_ = handle.Close()
		}
		return "", errors.New("OpenResty candidate process is not running")
	}
	if identity != r.generation.Master {
		return "", errors.Join(errors.New("OpenResty candidate master generation changed"), handle.Close())
	}
	if err := r.verifyCandidateGeneration(); err != nil {
		return "", errors.Join(err, handle.Close())
	}
	alive, aliveErr := handle.Alive()
	closeErr := handle.Close()
	if aliveErr != nil || closeErr != nil || !alive {
		return "", errors.Join(errors.New("OpenResty candidate process identity is not stable"), aliveErr, closeErr)
	}
	materialParts := []string{formatProcessRecord(identity)}
	for _, worker := range r.generation.Workers {
		materialParts = append(materialParts, formatProcessRecord(worker))
	}
	materialParts = append(materialParts, versionID, digest)
	material := strings.Join(materialParts, "\x00")
	return digestBytes([]byte(material)), nil
}

func (m *Manager) Status() (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	active, err := m.store.loadActive()
	if err != nil {
		return Status{}, err
	}
	if active == nil {
		return Status{}, nil
	}
	return Status{Active: true, VersionID: active.VersionID, Digest: active.Digest, AppliedAt: active.AppliedAt}, nil
}

func appliedResult(active *activeRecord) Result {
	return Result{
		VersionID: active.VersionID, Digest: active.Digest, State: StateApplied,
		ActiveVersionID: active.VersionID, ActiveDigest: active.Digest, AppliedAt: active.AppliedAt,
	}
}

func failedResult(compiled CompiledPolicy, active *activeRecord, code string, unchanged bool) Result {
	result := Result{
		VersionID: compiled.Policy.VersionID, Digest: compiled.Digest, State: StateFailed,
		ErrorCode: code, RunningVersionUnchanged: unchanged,
	}
	if active != nil {
		result.ActiveVersionID = active.VersionID
		result.ActiveDigest = active.Digest
	}
	return result
}
