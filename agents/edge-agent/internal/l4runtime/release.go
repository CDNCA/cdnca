package l4runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// NewDeploymentManager defers runtime recovery to the enclosing full-release
// transaction so constructing L4 cannot leave HTTP and L4 on different releases.
func NewDeploymentManager(stateRoot string, runtime Runtime) (*Manager, error) {
	if runtime == nil {
		return nil, ErrInvalidConfig
	}
	store, err := newDiskStore(stateRoot)
	if err != nil {
		return nil, err
	}
	return &Manager{store: store, runtime: runtime, now: time.Now}, nil
}

// The activation journal covers L4 itself; this journal retains the actual
// previous L4 identity until the enclosing HTTP release passes health checks.
type releaseJournal struct {
	SchemaVersion int           `json:"schema_version"`
	VersionID     string        `json:"version_id"`
	Previous      *activeRecord `json:"previous,omitempty"`
}

func (m *Manager) BeginRelease(ctx context.Context, versionID string) error {
	if !identifierPattern.MatchString(versionID) {
		return ErrInvalidConfig
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	unlock, err := m.store.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	if err := m.recoverActivation(ctx); err != nil {
		return err
	}
	pending, err := m.store.loadReleaseJournal()
	if err != nil {
		return err
	}
	if pending != nil && pending.VersionID == versionID {
		return nil
	}
	if pending != nil {
		if err := m.recoverRelease(ctx); err != nil {
			return err
		}
	}
	previous, err := m.store.loadActive()
	if err != nil {
		return err
	}
	content, err := json.Marshal(releaseJournal{SchemaVersion: 1, VersionID: versionID, Previous: previous})
	if err != nil {
		return err
	}
	return writeAtomic(m.store.stateDir, m.store.releaseJournalPath(), append(content, '\n'))
}

func (m *Manager) FinishRelease(ctx context.Context, versionID string, succeeded bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	unlock, err := m.store.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	pending, err := m.store.loadReleaseJournal()
	if err != nil {
		return err
	}
	if pending != nil && pending.VersionID != versionID {
		return ErrConflict
	}
	if !succeeded {
		return m.recoverRelease(ctx)
	}
	active, err := m.store.loadActive()
	if err != nil {
		return err
	}
	if active == nil && pending == nil {
		// Existing HTTP-only installations have never created L4 snapshots.
		// A reverted new release leaves its immutable snapshot behind, so it
		// cannot use this compatibility path to certify an aborted candidate.
		versions, err := os.ReadDir(m.store.versionsDir)
		if err != nil {
			return err
		}
		if len(versions) == 0 {
			return nil
		}
	}
	// A failed health attempt already restored the baseline. A later transient
	// HTTP success must not certify the candidate while L4 is on that baseline.
	if active == nil || active.VersionID != versionID {
		return ErrConflict
	}
	compiled, _, err := m.store.loadVersion(active.VersionID, active.Digest)
	if err != nil {
		return err
	}
	if err := m.healthy(ctx, compiled); err != nil {
		return err
	}
	return m.store.clearReleaseJournal()
}

func (m *Manager) recoverRelease(ctx context.Context) error {
	pending, err := m.store.loadReleaseJournal()
	if err != nil || pending == nil {
		return err
	}
	if _, err := m.restore(ctx, pending.Previous); err != nil {
		return err
	}
	if err := m.store.restoreActive(pending.Previous); err != nil {
		return err
	}
	return m.store.clearReleaseJournal()
}

func (s *diskStore) releaseJournalPath() string {
	return filepath.Join(s.stateDir, "release-journal.json")
}

func (s *diskStore) loadReleaseJournal() (*releaseJournal, error) {
	content, err := readRegularFile(s.releaseJournalPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var journal releaseJournal
	if err := decoder.Decode(&journal); err != nil || ensureJSONEOF(decoder) != nil ||
		journal.SchemaVersion != 1 || !identifierPattern.MatchString(journal.VersionID) {
		return nil, ErrCorruptState
	}
	if journal.Previous != nil {
		if err := s.validateActiveRecord(*journal.Previous); err != nil {
			return nil, err
		}
	}
	return &journal, nil
}

func (s *diskStore) clearReleaseJournal() error {
	if _, err := s.loadReleaseJournal(); err != nil {
		return err
	}
	if err := os.Remove(s.releaseJournalPath()); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	return syncDirectory(s.stateDir)
}
