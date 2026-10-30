package controlplaneupgrade

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const stateFilename = "state.json"

type FileStore struct{ root string }

func NewFileStore(root string) (*FileStore, error) {
	if !filepath.IsAbs(root) {
		return nil, ErrInvalidConfig
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrInvalidConfig
	}
	if info.Mode().Perm() != 0o700 {
		if err := os.Chmod(root, 0o700); err != nil {
			return nil, err
		}
	}
	return &FileStore{root: root}, nil
}

func (store *FileStore) Load() (State, error) {
	path := filepath.Join(store.root, stateFilename)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return State{}, ErrStateNotFound
	}
	stat, ok := infoSysStat(info)
	if err != nil || info == nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || !ok || stat.Nlink != 1 {
		return State{}, ErrCorruptState
	}
	encoded, err := os.ReadFile(path)
	if err != nil || len(encoded) == 0 || len(encoded) > 64*1024 {
		return State{}, ErrCorruptState
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var state State
	if decoder.Decode(&state) != nil || !errors.Is(decoder.Decode(&struct{}{}), io.EOF) || !validState(state) {
		return State{}, ErrCorruptState
	}
	canonical, err := json.Marshal(state)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return State{}, ErrCorruptState
	}
	return state, nil
}

func infoSysStat(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}

func (store *FileStore) Save(state State) error {
	if !validState(state) {
		return ErrCorruptState
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(store.root, ".state-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, filepath.Join(store.root, stateFilename)); err != nil {
		return err
	}
	directory, err := os.Open(store.root)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func validState(state State) bool {
	if state.Schema != StateSchema || state.PlanID == "" || !digestPattern.MatchString(state.BundleSHA256) ||
		state.Sequence == 0 || !validPhase(state.Phase) {
		return false
	}
	if state.PreviousDigest != "" && !digestPattern.MatchString(state.PreviousDigest) {
		return false
	}
	if state.TargetDigest != "" && !digestPattern.MatchString(state.TargetDigest) {
		return false
	}
	if state.Receipt != nil && (state.Receipt.PlanID != state.PlanID || state.Receipt.Sequence != state.Sequence ||
		state.Receipt.BundleSHA256 != state.BundleSHA256 || !validMigrationRecord(state.Receipt.Migration)) {
		return false
	}
	switch state.Phase {
	case PhaseControlStopped:
		if state.Migration == nil || state.Migration.BackupPath != "" {
			return false
		}
	case PhaseDatabaseBackedUp, PhaseDatabaseMigrated:
		if state.Migration == nil || state.Migration.BackupPath == "" || state.Migration.Restored ||
			state.Migration.Migrated != (state.Phase == PhaseDatabaseMigrated) {
			return false
		}
	}
	return validMigrationRecord(state.Migration)
}
