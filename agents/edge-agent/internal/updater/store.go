package updater

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
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
	stateVersion     = 1
	maxStateFileSize = 1 << 20
)

type phase string

const (
	phaseDownload phase = "download"
	phaseInstall  phase = "install"
	phaseObserve  phase = "observe"
	phaseRollback phase = "rollback"
	phaseDone     phase = "done"
)

type transaction struct {
	Version                int               `json:"version"`
	Plan                   Plan              `json:"plan"`
	Digest                 string            `json:"digest"`
	Phase                  phase             `json:"phase"`
	InstallerTransactionID string            `json:"installer_transaction_id"`
	InstallStarted         bool              `json:"install_started"`
	PreparedInstall        *PreparedInstall  `json:"prepared_install,omitempty"`
	ActivationAttempts     int               `json:"activation_attempts,omitempty"`
	RollbackStarted        bool              `json:"rollback_started"`
	Before                 ActivationReceipt `json:"before"`
	ActiveReceipt          ActivationReceipt `json:"active_receipt,omitempty"`
	Result                 Result            `json:"result,omitempty"`
	ErrorCode              string            `json:"error_code,omitempty"`
}

type diskStore struct {
	root        string
	stagingDir  string
	verifiedDir string
	stateDir    string
	journalPath string
	lockPath    string
}

func newDiskStore(configuredRoot string) (*diskStore, error) {
	if configuredRoot == "" || !filepath.IsAbs(configuredRoot) || filepath.Clean(configuredRoot) != configuredRoot ||
		configuredRoot == string(filepath.Separator) {
		return nil, fmt.Errorf("%w: updater root", ErrUnsafePath)
	}
	if info, err := os.Lstat(configuredRoot); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.IsDir()) {
		return nil, fmt.Errorf("%w: updater root", ErrUnsafePath)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect updater root: %w", err)
	}
	if err := os.MkdirAll(configuredRoot, 0o700); err != nil {
		return nil, fmt.Errorf("create updater root: %w", err)
	}
	realRoot, err := filepath.EvalSymlinks(configuredRoot)
	if err != nil || realRoot == string(filepath.Separator) {
		return nil, fmt.Errorf("%w: resolve updater root", ErrUnsafePath)
	}
	store := &diskStore{
		root: realRoot, stagingDir: filepath.Join(realRoot, "staging"),
		verifiedDir: filepath.Join(realRoot, "staging", "verified"), stateDir: filepath.Join(realRoot, "state"),
		journalPath: filepath.Join(realRoot, "state", "transaction.json"),
		lockPath:    filepath.Join(realRoot, "state", "upgrade.lock"),
	}
	for _, directory := range []string{store.root, store.stagingDir, store.verifiedDir, store.stateDir} {
		if err := ensureTrustedDirectory(directory); err != nil {
			return nil, err
		}
	}
	return store, nil
}

func ensureTrustedDirectory(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create updater directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: untrusted updater directory", ErrUnsafePath)
	}
	return nil
}

func (s *diskStore) verify() error {
	for _, directory := range []string{s.root, s.stagingDir, s.verifiedDir, s.stateDir} {
		if err := ensureTrustedDirectory(directory); err != nil {
			return err
		}
		relative, err := filepath.Rel(s.root, directory)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return fmt.Errorf("%w: directory leaves updater root", ErrUnsafePath)
		}
	}
	return nil
}

func (s *diskStore) lock(ctx context.Context) (func(), error) {
	if info, err := os.Lstat(s.lockPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%w: updater lock", ErrUnsafePath)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect updater lock: %w", err)
	}
	file, err := os.OpenFile(s.lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open updater lock: %w", err)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("%w: updater lock", ErrUnsafePath)
	}
	if count, ok := regularLinkCount(info.Sys()); !ok || count != 1 {
		_ = file.Close()
		return nil, fmt.Errorf("%w: updater lock link count", ErrUnsafePath)
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
			return func() {
				_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
				_ = file.Close()
			}, nil
		} else if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			_ = file.Close()
			return nil, fmt.Errorf("lock updater state: %w", err)
		}
		select {
		case <-ctx.Done():
			_ = file.Close()
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (s *diskStore) loadTransaction() (*transaction, error) {
	var value transaction
	found, err := readJSONFile(s.journalPath, &value)
	if err != nil || !found {
		return nil, err
	}
	if value.Version != stateVersion || value.Digest == "" || value.Plan.PlanID == "" ||
		!safeIDPattern.MatchString(value.InstallerTransactionID) ||
		(value.PreparedInstall != nil && !preparedInstallMatchesTransaction(*value.PreparedInstall, &value)) ||
		value.ActivationAttempts < 0 || value.ActivationAttempts > maxInstallerActivationAttempts ||
		value.ActivationAttempts != 0 && value.PreparedInstall == nil ||
		(value.Phase != phaseDownload && value.Phase != phaseInstall && value.Phase != phaseObserve && value.Phase != phaseRollback && value.Phase != phaseDone) {
		return nil, ErrCorruptState
	}
	return &value, nil
}

func (s *diskStore) saveTransaction(value *transaction) error {
	if value == nil {
		return ErrCorruptState
	}
	return writeJSONAtomic(s.journalPath, value)
}

func (s *diskStore) prepareStaging(planID string) (*os.File, string, error) {
	if !safeIDPattern.MatchString(planID) {
		return nil, "", ErrUnsafePath
	}
	directory := filepath.Join(s.stagingDir, "pending-"+planID)
	if info, err := os.Lstat(directory); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, "", ErrUnsafePath
		}
		if err := removeTrustedTree(directory); err != nil {
			return nil, "", err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, "", err
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		return nil, "", fmt.Errorf("create artifact staging directory: %w", err)
	}
	path := filepath.Join(directory, "artifact")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, "", fmt.Errorf("create staged artifact: %w", err)
	}
	return file, path, nil
}

func (s *diskStore) commitStaging(planID, path, digest string, expectedSize int64) (string, error) {
	if !safeIDPattern.MatchString(planID) || !validDigest(digest) || path != filepath.Join(s.stagingDir, "pending-"+planID, "artifact") {
		return "", ErrUnsafePath
	}
	if err := verifyRegularFile(path, expectedSize); err != nil {
		return "", err
	}
	if err := os.Chmod(path, 0o400); err != nil {
		return "", fmt.Errorf("protect staged artifact: %w", err)
	}
	directory := filepath.Dir(path)
	if err := syncDirectory(directory); err != nil {
		return "", err
	}
	verifiedDirectory := filepath.Join(s.verifiedDir, digest)
	if info, err := os.Lstat(verifiedDirectory); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", ErrUnsafePath
		}
		verified, verifyErr := s.verifiedArtifact(digest, expectedSize)
		if verifyErr != nil {
			return "", verifyErr
		}
		if err := removeTrustedTree(directory); err != nil {
			return "", err
		}
		return verified, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := os.Rename(directory, verifiedDirectory); err != nil {
		return "", fmt.Errorf("publish verified artifact: %w", err)
	}
	if err := syncDirectory(s.verifiedDir); err != nil {
		return "", err
	}
	return s.verifiedArtifact(digest, expectedSize)
}

func (s *diskStore) openVerified(digest string, expectedSize int64) (*os.File, string, error) {
	if !validDigest(digest) {
		return nil, "", ErrUnsafePath
	}
	directory := filepath.Join(s.verifiedDir, digest)
	directoryInfo, err := os.Lstat(directory)
	if err != nil || directoryInfo.Mode()&os.ModeSymlink != 0 || !directoryInfo.IsDir() {
		return nil, "", ErrUnsafePath
	}
	path := filepath.Join(directory, "artifact")
	file, err := os.Open(path)
	if err != nil {
		return nil, "", fmt.Errorf("open verified artifact: %w", err)
	}
	info, err := file.Stat()
	pathInfo, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		!os.SameFile(info, pathInfo) || info.Size() != expectedSize {
		_ = file.Close()
		return nil, "", ErrArtifactIntegrity
	}
	if count, ok := regularLinkCount(info.Sys()); !ok || count != 1 {
		_ = file.Close()
		return nil, "", ErrUnsafePath
	}
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil || size != expectedSize || hex.EncodeToString(hash.Sum(nil)) != digest {
		_ = file.Close()
		return nil, "", ErrArtifactIntegrity
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return nil, "", ErrArtifactIntegrity
	}
	return file, path, nil
}

func (s *diskStore) verifiedArtifact(digest string, expectedSize int64) (string, error) {
	if !validDigest(digest) {
		return "", ErrUnsafePath
	}
	directory := filepath.Join(s.verifiedDir, digest)
	info, err := os.Lstat(directory)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fmt.Errorf("%w: verified staging directory", ErrUnsafePath)
	}
	path := filepath.Join(directory, "artifact")
	if err := verifyRegularFile(path, expectedSize); err != nil {
		return "", err
	}
	digestValue, size, err := hashFile(path)
	if err != nil || digestValue != digest || size != expectedSize {
		return "", ErrArtifactIntegrity
	}
	return path, nil
}

func verifyRegularFile(path string, expectedSize int64) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() != expectedSize {
		return ErrArtifactIntegrity
	}
	if count, ok := regularLinkCount(info.Sys()); !ok || count != 1 {
		return fmt.Errorf("%w: artifact hardlink", ErrUnsafePath)
	}
	return nil
}

func hashFile(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

func readJSONFile(path string, destination any) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > maxStateFileSize {
		return false, ErrCorruptState
	}
	if count, ok := regularLinkCount(info.Sys()); !ok || count != 1 {
		return false, ErrCorruptState
	}
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maxStateFileSize+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return false, ErrCorruptState
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return false, ErrCorruptState
	}
	return true, nil
}

func writeJSONAtomic(path string, value any) error {
	directory := filepath.Dir(path)
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > maxStateFileSize {
		return ErrCorruptState
	}
	temporary := filepath.Join(directory, ".state-"+randomSuffix())
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create updater state: %w", err)
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(temporary)
		}
	}()
	if _, err := file.Write(encoded); err != nil {
		return fmt.Errorf("write updater state: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync updater state: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close updater state: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("publish updater state: %w", err)
	}
	ok = true
	return syncDirectory(directory)
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync directory: %w", err)
	}
	return nil
}

func removeTrustedTree(path string) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return ErrUnsafePath
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		entryPath := filepath.Join(path, entry.Name())
		entryInfo, err := os.Lstat(entryPath)
		if err != nil || entryInfo.Mode()&os.ModeSymlink != 0 || (!entryInfo.IsDir() && !entryInfo.Mode().IsRegular()) {
			return ErrUnsafePath
		}
		if entryInfo.IsDir() {
			if err := removeTrustedTree(entryPath); err != nil {
				return err
			}
		} else {
			if count, ok := regularLinkCount(entryInfo.Sys()); !ok || count != 1 {
				return ErrUnsafePath
			}
			if err := os.Remove(entryPath); err != nil {
				return err
			}
		}
	}
	return os.Remove(path)
}

func validDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && strings.ToLower(value) == value
}

func randomSuffix() string {
	buffer := make([]byte, 12)
	if _, err := rand.Read(buffer); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(buffer)
}
