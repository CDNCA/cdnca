package controlbackup

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
)

type FileBackupRunStore struct {
	manifestDirectory string
	keys              map[string]ed25519.PublicKey
	expected          BackupRunExpectation
}

func NewFileBackupRunStore(manifestDirectory string, keys map[string]ed25519.PublicKey,
	expected BackupRunExpectation,
) (*FileBackupRunStore, error) {
	if validatePrivateDirectory(manifestDirectory) != nil || !validBackupRunExpectation(expected) ||
		expected.BackupID == "" || expected.PlanSHA256 == "" || len(keys) == 0 {
		return nil, ErrBackupRunInvalid
	}
	trusted := make(map[string]ed25519.PublicKey, len(keys))
	for id, key := range keys {
		if !identifierPattern.MatchString(id) || len(key) != ed25519.PublicKeySize {
			return nil, ErrBackupRunInvalid
		}
		trusted[id] = append(ed25519.PublicKey(nil), key...)
	}
	return &FileBackupRunStore{manifestDirectory: manifestDirectory, keys: trusted, expected: expected}, nil
}

// Begin's bool is true only for the process that exclusively created the run
// directory and durably published its start. Existing/partial runs never grant
// execution permission, even if their timestamps or terminal are missing.
func (store *FileBackupRunStore) Begin(start BackupRunStart, keyID string, key ed25519.PrivateKey) (VerifiedBackupRun, bool, error) {
	signed, err := SignBackupRunStart(start, keyID, key)
	if err != nil {
		return VerifiedBackupRun{}, false, err
	}
	verified, err := VerifyBackupRun(signed, nil, store.keys, store.expected)
	if err != nil {
		return VerifiedBackupRun{}, false, err
	}
	root := filepath.Join(store.manifestDirectory, "runs")
	if err := os.Mkdir(root, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return VerifiedBackupRun{}, false, ErrBackupRunStore
	}
	if validatePrivateDirectory(root) != nil || syncBackupRunDirectory(store.manifestDirectory) != nil {
		return VerifiedBackupRun{}, false, ErrBackupRunStore
	}
	directory := filepath.Join(root, start.BackupID)
	if err := os.Mkdir(directory, 0o700); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return VerifiedBackupRun{}, false, ErrBackupRunStore
		}
		previous, readErr := ReadBackupRun(store.manifestDirectory, start.BackupID, store.keys, store.expected)
		return previous, false, readErr
	}
	if syncBackupRunDirectory(root) != nil {
		return VerifiedBackupRun{}, false, ErrBackupRunStore
	}
	// A v1 manifest has no whole-run receipt. Never adopt it or execute its ID.
	if _, err := os.Lstat(filepath.Join(store.manifestDirectory, start.BackupID+".signed.json")); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return VerifiedBackupRun{}, false, ErrBackupRunLegacy
		}
		return VerifiedBackupRun{}, false, ErrBackupRunStore
	}
	if writeImmutableJSON(filepath.Join(directory, "start.signed.json"), signed) != nil {
		return VerifiedBackupRun{}, false, ErrBackupRunStore
	}
	return verified, true, nil
}

func (store *FileBackupRunStore) Finish(terminal BackupRunTerminal, keyID string, key ed25519.PrivateKey) (VerifiedBackupRun, error) {
	previous, err := ReadBackupRun(store.manifestDirectory, store.expected.BackupID, store.keys, store.expected)
	if err != nil {
		return VerifiedBackupRun{}, err
	}
	signed, err := SignBackupRunTerminal(terminal, keyID, key)
	if err != nil {
		return VerifiedBackupRun{}, err
	}
	verified, err := VerifyBackupRun(previous.SignedStart, &signed, store.keys, store.expected)
	if err != nil {
		return VerifiedBackupRun{}, err
	}
	if previous.SignedTerminal != nil {
		if previous.SignedTerminal.PayloadSHA256 != signed.PayloadSHA256 {
			return VerifiedBackupRun{}, ErrBackupRunConflict
		}
		return previous, nil
	}
	path := filepath.Join(store.manifestDirectory, "runs", store.expected.BackupID, "terminal.signed.json")
	if err := writeImmutableJSON(path, signed); err != nil {
		return VerifiedBackupRun{}, ErrBackupRunStore
	}
	return verified, nil
}

// ReadBackupRun is read-only and requires a trusted installation/source binding.
// A verified start without terminal is an unknown outcome, returned as nil
// Terminal. Missing or malformed starts are integrity errors, not empty runs.
func ReadBackupRun(manifestDirectory, backupID string, keys map[string]ed25519.PublicKey,
	expected BackupRunExpectation,
) (VerifiedBackupRun, error) {
	if !identifierPattern.MatchString(backupID) || (expected.BackupID != "" && expected.BackupID != backupID) {
		return VerifiedBackupRun{}, ErrBackupRunInvalid
	}
	expected.BackupID = backupID
	root := filepath.Join(manifestDirectory, "runs")
	directory := filepath.Join(root, backupID)
	if validatePrivateDirectory(manifestDirectory) != nil || validatePrivateDirectory(root) != nil ||
		validatePrivateDirectory(directory) != nil {
		return VerifiedBackupRun{}, ErrBackupRunIntegrity
	}
	start, err := readBackupRunFact(filepath.Join(directory, "start.signed.json"))
	if err != nil {
		return VerifiedBackupRun{}, ErrBackupRunIntegrity
	}
	// Verify the caller's complete binding before looking at any stored result.
	verified, err := VerifyBackupRun(start, nil, keys, expected)
	if err != nil {
		return VerifiedBackupRun{}, err
	}
	terminal, err := readBackupRunFact(filepath.Join(directory, "terminal.signed.json"))
	if errors.Is(err, os.ErrNotExist) {
		return verified, nil
	}
	if err != nil {
		return VerifiedBackupRun{}, ErrBackupRunIntegrity
	}
	return VerifyBackupRun(start, &terminal, keys, expected)
}

func readBackupRunFact(path string) (SignedBackupRunFact, error) {
	encoded, err := ReadTrustedFile(path)
	if err != nil {
		return SignedBackupRunFact{}, err
	}
	return DecodeBackupRunFact(encoded)
}

func syncBackupRunDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
