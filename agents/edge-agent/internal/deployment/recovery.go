package deployment

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Recover settles an interrupted activation from verified local releases before
// accepting commands. It does not need the control plane or the original bundle.
func (m *Manager) Recover(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	unlock, err := m.store.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	value, err := m.store.interruptedActivation()
	if err != nil || value == nil {
		return err
	}
	record := &value.Attempts[len(value.Attempts)-1]
	prior := record.PriorPointers
	desired := Pointers{Current: record.ConfigVersionID, CurrentDigest: record.ManifestSHA256,
		Previous: prior.Current, PreviousDigest: prior.CurrentDigest}
	pointers, err := m.store.loadPointers()
	if err != nil {
		return err
	}
	active, err := m.store.currentDigest()
	if err != nil {
		return err
	}
	if (pointers != prior && pointers != desired) || (active != prior.CurrentDigest && active != desired.CurrentDigest) {
		return fmt.Errorf("%w: interrupted activation does not own current release", ErrCorruptState)
	}
	target := prior
	if prior.Current == "" {
		if record.Action != ActionApply || record.Phase == phaseRollback {
			return fmt.Errorf("%w: interrupted release has no healthy baseline", ErrCorruptState)
		}
		target = desired
	}
	release, err := m.store.releasePath(target.CurrentDigest)
	if err != nil {
		return err
	}
	if err := m.store.verifyExistingRelease(release); err != nil {
		return err
	}
	if err := runBounded(ctx, m.config.PrecheckTimeout, func(operationCtx context.Context) error {
		return m.prechecker.Precheck(operationCtx, target.Current, release)
	}); err != nil {
		return err
	}
	// Use the normal certificate, pointer, runtime and health restoration path.
	references, _, err := m.prepareCertificateReferencesForRecovery(ctx, target.Current, target.CurrentDigest, target.Previous, target.PreviousDigest, true)
	if err != nil {
		return err
	}
	if err := m.restore(ctx, target, references, false); err != nil {
		// Keep the recovery journal pending. A subsequent offline startup retries
		// the same verified target; no command can run while recovery fails.
		return err
	}
	if _, _, err := m.prepareCertificateReferences(ctx, target.Current, target.CurrentDigest, target.Previous, target.PreviousDigest); err != nil {
		return err
	}
	if prior.Current == "" {
		if record.Phase == phaseActivate {
			if err := m.advance(value, record, StateActivated, phaseHealth, false, "", ""); err != nil {
				return err
			}
		}
		return m.advance(value, record, StateHealthy, "", false, "", "")
	}
	if record.Action == ActionRollback {
		_, err := m.explicitRollbackFailure(value, record, "STARTUP_RECOVERED", "interrupted rollback restored its verified baseline", true, StateFailed)
		return err
	}
	if record.Phase == phaseActivate {
		return m.advance(value, record, StateFailed, "", true, "STARTUP_RECOVERED", "interrupted activation restored its verified baseline")
	}
	if record.Transitions[len(record.Transitions)-1].State == StateActivated {
		if err := m.advance(value, record, StateReverting, phaseRollback, false, "STARTUP_RECOVERED", "interrupted activation restored its verified baseline"); err != nil {
			return err
		}
	}
	return m.advance(value, record, StateReverted, "", false, "", "")
}

func (s *diskStore) interruptedActivation() (*journal, error) {
	entries, err := os.ReadDir(s.journalDir)
	if err != nil {
		return nil, err
	}
	var pending *journal
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			return nil, ErrCorruptState
		}
		content, err := readRegularFile(filepath.Join(s.journalDir, entry.Name()))
		if err != nil {
			return nil, err
		}
		var value journal
		if err := json.Unmarshal(content, &value); err != nil || filepath.Base(s.journalPath(value.DeploymentID)) != entry.Name() {
			return nil, ErrCorruptState
		}
		if err := validateJournal(&value, value.DeploymentID); err != nil {
			return nil, err
		}
		record := value.Attempts[len(value.Attempts)-1]
		if !record.PriorPointersSet {
			continue
		}
		switch record.Phase {
		case phaseActivate, phaseHealth, phaseRollback, phaseExplicitRollbackVerify, phaseExplicitRollbackRestore:
			if pending != nil {
				return nil, fmt.Errorf("%w: multiple interrupted activations", ErrCorruptState)
			}
			pending = &value
		}
	}
	return pending, nil
}
