package drainruntime

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	stateSchemaVersion              = 1
	terminationJournalSchemaVersion = 1
	maxStateFileBytes               = 1 << 20

	terminationOperationComplete = "complete"
	terminationOperationForce    = "force"
	terminationStageForce        = "force"
	terminationStageComplete     = "complete"
	terminationStageCommit       = "commit"
)

type terminationJournal struct {
	SchemaVersion int       `json:"schema_version"`
	Operation     string    `json:"operation"`
	Stage         string    `json:"stage"`
	PlanID        string    `json:"plan_id"`
	Revision      uint64    `json:"revision"`
	Digest        string    `json:"digest"`
	Phase         Phase     `json:"phase"`
	CreatedAt     time.Time `json:"created_at"`
}

type stateRecord struct {
	SchemaVersion       int                 `json:"schema_version"`
	PlanID              string              `json:"plan_id"`
	Revision            uint64              `json:"revision"`
	Digest              string              `json:"digest"`
	Phase               Phase               `json:"phase"`
	HealthDeadline      time.Time           `json:"health_deadline,omitempty"`
	DrainDeadline       time.Time           `json:"drain_deadline,omitempty"`
	RemainingOldWorkers int                 `json:"remaining_old_workers,omitempty"`
	ForcedTermination   bool                `json:"forced_termination,omitempty"`
	RollbackPending     bool                `json:"rollback_pending,omitempty"`
	RollbackErrorCode   string              `json:"rollback_error_code,omitempty"`
	RollbackSummary     string              `json:"rollback_summary,omitempty"`
	TerminationJournal  *terminationJournal `json:"termination_journal,omitempty"`
	Transitions         []Transition        `json:"transitions"`
}

func newTerminationJournal(state *stateRecord, operation, stage string, createdAt time.Time) *terminationJournal {
	return &terminationJournal{
		SchemaVersion: terminationJournalSchemaVersion,
		Operation:     operation,
		Stage:         stage,
		PlanID:        state.PlanID,
		Revision:      state.Revision,
		Digest:        state.Digest,
		Phase:         state.Phase,
		CreatedAt:     createdAt.UTC(),
	}
}

type diskStore struct {
	plansDir  string
	stateDir  string
	statePath string
	lockPath  string
}

func newDiskStore(configuredRoot string) (*diskStore, error) {
	if !safeAbsolutePath(configuredRoot) {
		return nil, ErrInvalidPath
	}
	if info, err := os.Lstat(configuredRoot); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrInvalidPath
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect drain state root: %w", err)
	}
	if err := os.MkdirAll(configuredRoot, 0o700); err != nil {
		return nil, fmt.Errorf("create drain state root: %w", err)
	}
	realRoot, err := filepath.EvalSymlinks(configuredRoot)
	if err != nil || !safeAbsolutePath(realRoot) {
		return nil, ErrInvalidPath
	}
	if err := ensurePrivateDirectory(realRoot); err != nil {
		return nil, err
	}
	store := &diskStore{
		plansDir: filepath.Join(realRoot, "plans"), stateDir: filepath.Join(realRoot, "state"),
		statePath: filepath.Join(realRoot, "state", "drain.json"), lockPath: filepath.Join(realRoot, "state", "drain.lock"),
	}
	for _, directory := range []string{store.plansDir, store.stateDir} {
		if err := ensurePrivateDirectory(directory); err != nil {
			return nil, err
		}
	}
	return store, nil
}

func ensurePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o700); err != nil {
			return fmt.Errorf("create drain directory: %w", err)
		}
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return ErrInvalidPath
	}
	return nil
}

func (s *diskStore) lock(ctx context.Context) (func(), error) {
	file, err := os.OpenFile(s.lockPath, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open drain state lock: %w", err)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		_ = file.Close()
		return nil, ErrInvalidPath
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() {
				_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
				_ = file.Close()
			}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			_ = file.Close()
			return nil, fmt.Errorf("lock drain state: %w", err)
		}
		select {
		case <-ctx.Done():
			_ = file.Close()
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (s *diskStore) stage(compiled CompiledPlan) (Artifacts, error) {
	prefix := fmt.Sprintf("%020d-", compiled.Plan.Revision)
	name := prefix + compiled.Digest
	entries, err := os.ReadDir(s.plansDir)
	if err != nil {
		return Artifacts{}, fmt.Errorf("read drain plans: %w", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), prefix) && entry.Name() != name {
			return Artifacts{}, ErrConflict
		}
	}
	destination := filepath.Join(s.plansDir, name)
	artifacts := artifactsAt(destination, compiled)
	if info, err := os.Lstat(destination); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o500 {
			return Artifacts{}, ErrCorruptState
		}
		if err := verifyArtifacts(artifacts, compiled); err != nil {
			return Artifacts{}, err
		}
		return artifacts, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return Artifacts{}, fmt.Errorf("inspect drain plan artifacts: %w", err)
	}
	temporary, err := os.MkdirTemp(s.plansDir, ".stage-")
	if err != nil {
		return Artifacts{}, fmt.Errorf("create drain plan staging directory: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(temporary)
		}
	}()
	files := map[string][]byte{
		"plan.json": compiled.CanonicalJSON, "candidate.conf": compiled.CandidateNginx,
		"draining.conf": compiled.DrainingNginx, "rollback.conf": compiled.RollbackNginx,
	}
	for _, filename := range []string{"plan.json", "candidate.conf", "draining.conf", "rollback.conf"} {
		if err := writeExclusive(filepath.Join(temporary, filename), files[filename], 0o400); err != nil {
			return Artifacts{}, err
		}
	}
	if err := syncDirectory(temporary); err != nil {
		return Artifacts{}, err
	}
	if err := os.Chmod(temporary, 0o500); err != nil {
		return Artifacts{}, fmt.Errorf("seal drain plan staging directory: %w", err)
	}
	if err := os.Rename(temporary, destination); err != nil {
		return Artifacts{}, fmt.Errorf("commit drain plan artifacts: %w", err)
	}
	ok = true
	if err := syncDirectory(s.plansDir); err != nil {
		return Artifacts{}, err
	}
	return artifacts, nil
}

func artifactsAt(directory string, compiled CompiledPlan) Artifacts {
	return Artifacts{
		PlanPath: filepath.Join(directory, "plan.json"), CandidatePath: filepath.Join(directory, "candidate.conf"),
		DrainingPath: filepath.Join(directory, "draining.conf"), RollbackPath: filepath.Join(directory, "rollback.conf"),
		Digest: compiled.Digest, Revision: compiled.Plan.Revision,
	}
}

func verifyArtifacts(artifacts Artifacts, compiled CompiledPlan) error {
	expected := map[string][]byte{
		artifacts.PlanPath: compiled.CanonicalJSON, artifacts.CandidatePath: compiled.CandidateNginx,
		artifacts.DrainingPath: compiled.DrainingNginx, artifacts.RollbackPath: compiled.RollbackNginx,
	}
	for path, wanted := range expected {
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o400 {
			return ErrCorruptState
		}
		content, err := readRegularFile(path, maxStateFileBytes)
		if err != nil {
			return ErrCorruptState
		}
		if string(content) != string(wanted) {
			return ErrConflict
		}
	}
	return nil
}

func (s *diskStore) load() (*stateRecord, error) {
	content, err := readRegularFile(s.statePath, maxStateFileBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var state stateRecord
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil || decoder.Decode(&struct{}{}) != io.EOF || !validState(state) {
		return nil, ErrCorruptState
	}
	canonical, err := json.Marshal(&state)
	if err != nil || !bytes.Equal(content, canonical) {
		return nil, ErrCorruptState
	}
	return &state, nil
}

func (s *diskStore) save(state *stateRecord) error {
	if state == nil || !validState(*state) {
		return ErrCorruptState
	}
	content, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal drain state: %w", err)
	}
	return writeAtomic(s.statePath, content)
}

func validState(state stateRecord) bool {
	decodedDigest, digestErr := hex.DecodeString(state.Digest)
	if state.SchemaVersion != stateSchemaVersion || !validIdentifier(state.PlanID) || state.Revision == 0 || digestErr != nil ||
		len(decodedDigest) != 32 || state.Digest != strings.ToLower(state.Digest) || len(state.Transitions) == 0 {
		return false
	}
	var healthGateAt, drainingAt time.Time
	for index, transition := range state.Transitions {
		if transition.Sequence != uint64(index+1) || transition.At.IsZero() || !validPhase(transition.Phase) ||
			!validTransitionMetadata(transition) || (index > 0 && transition.At.Before(state.Transitions[index-1].At)) {
			return false
		}
		if transition.Phase == PhaseHealthGate {
			healthGateAt = transition.At
		}
		if transition.Phase == PhaseDrainingOld {
			drainingAt = transition.At
		}
		if index == 0 {
			if transition.Phase != PhasePrecheck {
				return false
			}
			continue
		}
		if !validPhaseTransition(state.Transitions[index-1].Phase, transition.Phase) {
			return false
		}
	}
	if state.Transitions[len(state.Transitions)-1].Phase != state.Phase || !validPhase(state.Phase) || state.RemainingOldWorkers < 0 {
		return false
	}
	if state.RollbackPending {
		if state.Phase != PhaseActivateNew && state.Phase != PhaseHealthGate && state.Phase != PhaseDrainingOld {
			return false
		}
		if state.RollbackErrorCode == "" || state.RollbackSummary == "" {
			return false
		}
	} else if state.RollbackErrorCode != "" || state.RollbackSummary != "" {
		return false
	}
	if healthGateAt.IsZero() != state.HealthDeadline.IsZero() {
		return false
	}
	if !healthGateAt.IsZero() && (!state.HealthDeadline.After(healthGateAt) ||
		state.HealthDeadline.After(healthGateAt.Add(maxHealthTimeoutSeconds*time.Second))) {
		return false
	}
	if drainingAt.IsZero() != state.DrainDeadline.IsZero() {
		return false
	}
	if !drainingAt.IsZero() && (!state.DrainDeadline.After(drainingAt) ||
		state.DrainDeadline.After(drainingAt.Add(maxDrainTimeoutSeconds*time.Second))) {
		return false
	}
	if state.TerminationJournal != nil {
		journal := state.TerminationJournal
		if journal.SchemaVersion != terminationJournalSchemaVersion || journal.CreatedAt.IsZero() ||
			journal.PlanID != state.PlanID || journal.Revision != state.Revision || journal.Digest != state.Digest ||
			journal.Phase != PhaseDrainingOld || state.Phase != PhaseDrainingOld || state.RollbackPending ||
			journal.CreatedAt.Before(drainingAt) {
			return false
		}
		switch journal.Operation {
		case terminationOperationComplete:
			if (journal.Stage != terminationStageComplete && journal.Stage != terminationStageCommit) ||
				state.RemainingOldWorkers != 0 || state.ForcedTermination {
				return false
			}
		case terminationOperationForce:
			if state.RemainingOldWorkers == 0 || journal.CreatedAt.Before(state.DrainDeadline) {
				return false
			}
			switch journal.Stage {
			case terminationStageForce:
				if state.ForcedTermination {
					return false
				}
			case terminationStageComplete, terminationStageCommit:
				if !state.ForcedTermination {
					return false
				}
			default:
				return false
			}
		default:
			return false
		}
		return true
	}
	if state.ForcedTermination {
		last := state.Transitions[len(state.Transitions)-1]
		return state.Phase == PhaseCompleted && state.RemainingOldWorkers > 0 && last.ErrorCode == "DRAIN_FORCED"
	}
	return state.Phase != PhaseCompleted || state.RemainingOldWorkers == 0
}

func validTransitionMetadata(transition Transition) bool {
	hasCode := transition.ErrorCode != ""
	hasSummary := transition.Summary != ""
	if hasCode != hasSummary {
		return false
	}
	if !hasCode {
		return transition.Phase != PhaseRolledBack
	}
	if len(transition.ErrorCode) > maxIdentifierBytes || !validErrorCode(transition.ErrorCode) || !validReason(transition.Summary) {
		return false
	}
	return transition.Phase == PhaseRolledBack || (transition.Phase == PhaseCompleted && transition.ErrorCode == "DRAIN_FORCED")
}

func validErrorCode(value string) bool {
	for _, character := range value {
		if (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return value != ""
}

func validPhaseTransition(from, to Phase) bool {
	switch from {
	case PhasePrecheck:
		return to == PhaseActivateNew || to == PhaseRolledBack
	case PhaseActivateNew:
		return to == PhaseHealthGate || to == PhaseRolledBack
	case PhaseHealthGate:
		return to == PhaseDrainingOld || to == PhaseRolledBack
	case PhaseDrainingOld:
		return to == PhaseCompleted || to == PhaseRolledBack
	default:
		return false
	}
}

func validPhase(phase Phase) bool {
	switch phase {
	case PhasePrecheck, PhaseActivateNew, PhaseHealthGate, PhaseDrainingOld, PhaseCompleted, PhaseRolledBack:
		return true
	default:
		return false
	}
}

func readRegularFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, ErrCorruptState
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) || openedInfo.Size() > limit {
		return nil, ErrCorruptState
	}
	content, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(content)) > limit {
		return nil, ErrCorruptState
	}
	return content, nil
}

func writeExclusive(path string, content []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return fmt.Errorf("create drain artifact: %w", err)
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(content); err != nil {
		return fmt.Errorf("write drain artifact: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync drain artifact: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close drain artifact: %w", err)
	}
	ok = true
	return nil
}

func writeAtomic(path string, content []byte) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".drain-state-")
	if err != nil {
		return fmt.Errorf("create drain state: %w", err)
	}
	temporaryPath := temporary.Name()
	ok := false
	defer func() {
		_ = temporary.Close()
		if !ok {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		return fmt.Errorf("write drain state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync drain state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close drain state: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("activate drain state: %w", err)
	}
	ok = true
	return syncDirectory(directory)
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open drain directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync drain directory: %w", err)
	}
	return nil
}

func safeAbsolutePath(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path && path != string(filepath.Separator) && !strings.ContainsAny(path, "\r\n\x00")
}
