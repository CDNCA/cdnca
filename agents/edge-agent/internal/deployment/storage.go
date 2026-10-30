package deployment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

const (
	releaseManifestFile = ".release-manifest.json"
	journalVersion      = 1
	maxStateFileSize    = 8 << 20
)

type executionPhase string

const (
	phaseStage    executionPhase = "stage"
	phasePrecheck executionPhase = "precheck"
	phaseActivate executionPhase = "activate"
	phaseHealth   executionPhase = "health"
	phaseRollback executionPhase = "rollback"

	phaseExplicitRollbackValidate executionPhase = "explicit_rollback_validate"
	phaseExplicitRollbackPrecheck executionPhase = "explicit_rollback_precheck"
	phaseExplicitRollbackActivate executionPhase = "explicit_rollback_activate"
	phaseExplicitRollbackVerify   executionPhase = "explicit_rollback_verify"
	phaseExplicitRollbackRestore  executionPhase = "explicit_rollback_restore"
)

type attemptRecord struct {
	Attempt            uint32            `json:"attempt"`
	Action             Action            `json:"action"`
	CommandDigest      string            `json:"command_digest"`
	ConfigVersionID    string            `json:"config_version_id"`
	PreviousVersionID  string            `json:"previous_version_id,omitempty"`
	ManifestSHA256     string            `json:"manifest_sha256"`
	Phase              executionPhase    `json:"phase,omitempty"`
	PriorPointersSet   bool              `json:"prior_pointers_set"`
	PriorPointers      Pointers          `json:"prior_pointers"`
	RollbackErrorCode  string            `json:"rollback_error_code,omitempty"`
	RollbackSummary    string            `json:"rollback_summary,omitempty"`
	GenerationCaptured bool              `json:"generation_captured,omitempty"`
	OldGeneration      RuntimeGeneration `json:"old_generation,omitempty"`
	Drain              *drainRecord      `json:"drain,omitempty"`
	Transitions        []Transition      `json:"transitions"`
}

type drainRecord struct {
	Revision            uint64            `json:"revision"`
	Digest              string            `json:"digest"`
	OldVersionID        string            `json:"old_version_id"`
	NewVersionID        string            `json:"new_version_id"`
	Phase               DrainPhase        `json:"phase"`
	StartedAt           time.Time         `json:"started_at"`
	Deadline            time.Time         `json:"deadline"`
	CommandDeadline     time.Time         `json:"command_deadline"`
	RemainingOldWorkers int               `json:"remaining_old_workers"`
	Transitions         []DrainTransition `json:"transitions"`
}

type journal struct {
	Version      int             `json:"version"`
	DeploymentID string          `json:"deployment_id"`
	Attempts     []attemptRecord `json:"attempts"`
}

type diskStore struct {
	root        string
	releasesDir string
	stagingDir  string
	stateDir    string
	journalDir  string
	lockPath    string
	currentLink string
	limits      Limits
}

func newDiskStore(configuredRoot string, limits Limits) (*diskStore, error) {
	if configuredRoot == "" || !filepath.IsAbs(configuredRoot) {
		return nil, fmt.Errorf("%w: state root must be an absolute path", ErrInvalidPath)
	}
	clean := filepath.Clean(configuredRoot)
	if clean != configuredRoot || clean == string(filepath.Separator) || clean == filepath.VolumeName(clean)+string(filepath.Separator) {
		return nil, fmt.Errorf("%w: unsafe state root", ErrInvalidPath)
	}
	if info, err := os.Lstat(clean); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: state root is a symlink", ErrInvalidPath)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect state root: %w", err)
	}
	if err := os.MkdirAll(clean, 0o700); err != nil {
		return nil, fmt.Errorf("create state root: %w", err)
	}
	realRoot, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return nil, fmt.Errorf("resolve state root: %w", err)
	}
	if realRoot == string(filepath.Separator) || realRoot == filepath.VolumeName(realRoot)+string(filepath.Separator) {
		return nil, fmt.Errorf("%w: state root resolves to a filesystem root", ErrInvalidPath)
	}

	store := &diskStore{
		root:        realRoot,
		releasesDir: filepath.Join(realRoot, "releases"),
		stagingDir:  filepath.Join(realRoot, "staging"),
		stateDir:    filepath.Join(realRoot, "state"),
		journalDir:  filepath.Join(realRoot, "state", "journal"),
		lockPath:    filepath.Join(realRoot, "state", "activation.lock"),
		currentLink: filepath.Join(realRoot, "current"),
		limits:      limits,
	}
	for _, dir := range []string{store.releasesDir, store.stagingDir, store.stateDir, store.journalDir} {
		if err := ensureOrCreateDirectory(dir); err != nil {
			return nil, fmt.Errorf("create state directory: %w", err)
		}
	}
	if err := store.verifyCoreDirs(); err != nil {
		return nil, err
	}
	unlock, err := store.lock(context.Background())
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := store.cleanupStaging(); err != nil {
		return nil, err
	}
	return store, nil
}

func ensureOrCreateDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o700); err != nil {
			return err
		}
		return ensureDirectory(path)
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: state directory is not a trusted directory", ErrInvalidPath)
	}
	return nil
}

func (s *diskStore) prepareRuntimeDirectories() error {
	sharedDir := filepath.Join(s.root, "shared")
	cacheDir := filepath.Join(sharedDir, "cache")
	for _, path := range []string{sharedDir, cacheDir} {
		if err := ensureWithin(s.root, path); err != nil {
			return err
		}
	}
	if err := ensureOrCreateDirectory(sharedDir); err != nil {
		return fmt.Errorf("prepare shared runtime directory: %w", err)
	}
	if err := ensureOrCreateDirectory(cacheDir); err != nil {
		return fmt.Errorf("prepare cache runtime directory: %w", err)
	}
	info, err := os.Lstat(cacheDir)
	if err != nil {
		return fmt.Errorf("inspect cache runtime directory: %w", err)
	}
	if info.Mode().Perm() != 0o700 {
		return fmt.Errorf("%w: cache runtime directory permissions must be 0700", ErrInvalidPath)
	}
	return nil
}

func (s *diskStore) verifyCoreDirs() error {
	for _, dir := range []string{s.root, s.releasesDir, s.stagingDir, s.stateDir, s.journalDir} {
		if err := ensureDirectory(dir); err != nil {
			return err
		}
		if err := ensureWithin(s.root, dir); err != nil {
			return err
		}
	}
	return nil
}

func (s *diskStore) cleanupStaging() error {
	entries, err := os.ReadDir(s.stagingDir)
	if err != nil {
		return fmt.Errorf("read staging directory: %w", err)
	}
	for _, entry := range entries {
		path := filepath.Join(s.stagingDir, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("inspect staging entry: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("%w: staging contains an unsupported entry", ErrInvalidPath)
		}
		makeTreeWritable(path)
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("remove abandoned staging directory: %w", err)
		}
	}
	return syncDirectory(s.stagingDir)
}

func (s *diskStore) lock(ctx context.Context) (func(), error) {
	return lockFile(ctx, s.lockPath)
}

// lockFile takes an exclusive flock on a regular, non-symlink file, polling
// until ctx is done.
func lockFile(ctx context.Context, lockPath string) (func(), error) {
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		if info, statErr := os.Lstat(lockPath); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: activation lock is a symlink", ErrInvalidPath)
		}
		return nil, fmt.Errorf("open activation lock: %w", err)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("%w: activation lock is not a regular file", ErrInvalidPath)
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
			return nil, fmt.Errorf("lock activation state: %w", err)
		}
		select {
		case <-ctx.Done():
			_ = file.Close()
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func ensureDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect state directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: state directory is not a trusted directory", ErrInvalidPath)
	}
	return nil
}

func ensureWithin(root, path string) error {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%w: path leaves state root", ErrInvalidPath)
	}
	return nil
}

func (s *diskStore) stage(command Command, normalized Manifest) (string, error) {
	if err := s.verifyCoreDirs(); err != nil {
		return "", err
	}
	digest := strings.ToLower(command.Bundle.ManifestSHA256)
	releasePath := filepath.Join(s.releasesDir, digest)
	if err := ensureWithin(s.root, releasePath); err != nil {
		return "", err
	}
	if info, err := os.Lstat(releasePath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", fmt.Errorf("%w: release target already exists and is not a directory", ErrInvalidPath)
		}
		if err := s.verifyRelease(releasePath, normalized, command.Bundle.ManifestSHA256); err != nil {
			return "", err
		}
		if err := makeTreeImmutable(releasePath); err != nil {
			return "", err
		}
		return releasePath, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect release target: %w", err)
	}

	manifestDigest, err := ManifestDigest(normalized)
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(manifestDigest, command.Bundle.ManifestSHA256) {
		return "", fmt.Errorf("%w: manifest digest differs", ErrDigestMismatch)
	}
	stagePath, err := os.MkdirTemp(s.stagingDir, digest+"-")
	if err != nil {
		return "", fmt.Errorf("create release staging directory: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			makeTreeWritable(stagePath)
			_ = os.RemoveAll(stagePath)
		}
	}()

	if len(command.Bundle.Files) != len(normalized.Files) {
		return "", fmt.Errorf("%w: bundle file set does not match manifest", ErrDigestMismatch)
	}
	for _, entry := range normalized.Files {
		content, ok := command.Bundle.Files[entry.Path]
		if !ok {
			return "", fmt.Errorf("%w: manifest file is missing", ErrDigestMismatch)
		}
		if int64(len(content)) != entry.Size {
			return "", fmt.Errorf("%w: file size does not match manifest", ErrDigestMismatch)
		}
		sum := sha256.Sum256(content)
		if !strings.EqualFold(hex.EncodeToString(sum[:]), entry.SHA256) {
			return "", fmt.Errorf("%w: file content does not match manifest", ErrDigestMismatch)
		}
		filePath := filepath.Join(stagePath, entry.Path)
		if err := ensureWithin(stagePath, filePath); err != nil {
			return "", err
		}
		if err := os.MkdirAll(filepath.Dir(filePath), 0o700); err != nil {
			return "", fmt.Errorf("create release directory: %w", err)
		}
		if err := writeNewFile(filePath, content, 0o440); err != nil {
			return "", err
		}
	}

	manifestBytes, err := json.Marshal(normalized)
	if err != nil {
		return "", fmt.Errorf("marshal release manifest: %w", err)
	}
	if err := writeNewFile(filepath.Join(stagePath, releaseManifestFile), manifestBytes, 0o440); err != nil {
		return "", err
	}
	if err := syncTree(stagePath); err != nil {
		return "", err
	}
	if err := os.Rename(stagePath, releasePath); err != nil {
		return "", fmt.Errorf("commit immutable release: %w", err)
	}
	committed = true
	if err := makeTreeImmutable(releasePath); err != nil {
		return "", err
	}
	if err := syncTree(releasePath); err != nil {
		return "", err
	}
	if err := syncDirectory(s.releasesDir); err != nil {
		return "", err
	}
	if err := s.verifyRelease(releasePath, normalized, command.Bundle.ManifestSHA256); err != nil {
		return "", err
	}
	return releasePath, nil
}

func writeNewFile(path string, content []byte, mode fs.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create release file: %w", err)
	}
	written := false
	defer func() {
		if !written {
			_ = file.Close()
		}
	}()
	if _, err := file.Write(content); err != nil {
		return fmt.Errorf("write release file: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync release file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close release file: %w", err)
	}
	written = true
	return nil
}

func makeTreeImmutable(root string) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return fmt.Errorf("%w: release contains an unsupported file type", ErrInvalidPath)
		}
		mode := fs.FileMode(0o440)
		if info.IsDir() {
			mode = 0o550
		}
		if err := os.Chmod(path, mode); err != nil {
			return fmt.Errorf("make release immutable: %w", err)
		}
		return nil
	})
}

func makeTreeWritable(root string) {
	_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr == nil && entry.IsDir() {
			_ = os.Chmod(path, 0o700)
		}
		return nil
	})
}

func syncTree(root string) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return syncDirectory(path)
		}
		return nil
	})
}

func (s *diskStore) verifyRelease(releasePath string, expected Manifest, expectedDigest string) error {
	if err := ensureWithin(s.root, releasePath); err != nil {
		return err
	}
	if err := ensureDirectory(releasePath); err != nil {
		return err
	}
	manifestPath := filepath.Join(releasePath, releaseManifestFile)
	manifestBytes, err := readRegularFile(manifestPath)
	if err != nil {
		return err
	}
	stored, err := decodeStoredManifest(manifestBytes)
	if err != nil {
		return err
	}
	stored, err = normalizeManifest(stored)
	if err != nil {
		return err
	}
	if err := validateBundleLimits(stored, nil, s.limits); err != nil {
		return err
	}
	storedDigest, err := ManifestDigest(stored)
	if err != nil {
		return err
	}
	if !strings.EqualFold(storedDigest, expectedDigest) {
		return fmt.Errorf("%w: stored manifest digest differs", ErrDigestMismatch)
	}
	expectedBytes, _ := json.Marshal(expected)
	storedBytes, _ := json.Marshal(stored)
	if string(expectedBytes) != string(storedBytes) {
		return fmt.Errorf("%w: immutable release manifest differs", ErrDigestMismatch)
	}

	expectedFiles := make(map[string]FileManifest, len(expected.Files))
	for _, entry := range expected.Files {
		expectedFiles[entry.Path] = entry
	}
	seen := make(map[string]struct{}, len(expected.Files))
	err = filepath.WalkDir(releasePath, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == releasePath {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: release contains a symlink", ErrInvalidPath)
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("%w: release contains an unsupported file type", ErrInvalidPath)
		}
		rel, err := filepath.Rel(releasePath, path)
		if err != nil {
			return err
		}
		if rel == releaseManifestFile {
			return nil
		}
		expectedEntry, ok := expectedFiles[rel]
		if !ok {
			return fmt.Errorf("%w: release contains an unmanifested file", ErrDigestMismatch)
		}
		file, err := openRegularFileNoFollow(path)
		if err != nil {
			return err
		}
		hash := sha256.New()
		size, copyErr := io.Copy(hash, file)
		closeErr := file.Close()
		if copyErr != nil {
			return fmt.Errorf("hash release file: %w", copyErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close release file: %w", closeErr)
		}
		if size != expectedEntry.Size || !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), expectedEntry.SHA256) {
			return fmt.Errorf("%w: release file differs from manifest", ErrDigestMismatch)
		}
		seen[rel] = struct{}{}
		return nil
	})
	if err != nil {
		return err
	}
	if len(seen) != len(expectedFiles) {
		return fmt.Errorf("%w: release is incomplete", ErrDigestMismatch)
	}
	return nil
}

func (s *diskStore) verifyExistingRelease(releasePath string) error {
	if err := ensureWithin(s.root, releasePath); err != nil {
		return err
	}
	if err := ensureDirectory(releasePath); err != nil {
		return err
	}
	manifestBytes, err := readRegularFile(filepath.Join(releasePath, releaseManifestFile))
	if err != nil {
		return err
	}
	manifest, err := decodeStoredManifest(manifestBytes)
	if err != nil {
		return err
	}
	manifest, err = normalizeManifest(manifest)
	if err != nil {
		return err
	}
	if err := validateBundleLimits(manifest, nil, s.limits); err != nil {
		return err
	}
	digest, err := ManifestDigest(manifest)
	if err != nil {
		return err
	}
	if filepath.Base(releasePath) != digest {
		return fmt.Errorf("%w: release directory is not content addressed", ErrDigestMismatch)
	}
	return s.verifyRelease(releasePath, manifest, digest)
}

func decodeStoredManifest(content []byte) (Manifest, error) {
	if err := edgeconfig.RejectDuplicateJSONKeys(content); err != nil {
		return Manifest{}, fmt.Errorf("%w: release manifest cannot be decoded", ErrCorruptState)
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return Manifest{}, fmt.Errorf("%w: release manifest cannot be decoded", ErrCorruptState)
	}
	return manifest, nil
}

func (s *diskStore) releasePath(digest string) (string, error) {
	if !validSHA256(digest) || digest != strings.ToLower(digest) {
		return "", fmt.Errorf("%w: invalid release digest", ErrInvalidPath)
	}
	path := filepath.Join(s.releasesDir, digest)
	if err := ensureWithin(s.releasesDir, path); err != nil {
		return "", err
	}
	return path, nil
}

func (s *diskStore) currentDigest() (string, error) {
	info, err := os.Lstat(s.currentLink)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("inspect current release pointer: %w", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return "", fmt.Errorf("%w: current release pointer is not a symlink", ErrInvalidPath)
	}
	target, err := os.Readlink(s.currentLink)
	if err != nil {
		return "", fmt.Errorf("read current release pointer: %w", err)
	}
	digest := filepath.Base(target)
	if target != filepath.Join("releases", digest) {
		return "", fmt.Errorf("%w: current release pointer leaves the release directory", ErrInvalidPath)
	}
	releasePath, err := s.releasePath(digest)
	if err != nil {
		return "", err
	}
	if err := s.verifyExistingRelease(releasePath); err != nil {
		return "", err
	}
	return digest, nil
}

func (s *diskStore) switchCurrent(digest string) error {
	if err := s.verifyCoreDirs(); err != nil {
		return err
	}
	if _, err := s.currentDigest(); err != nil {
		return err
	}
	if digest == "" {
		if err := os.Remove(s.currentLink); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove current release pointer: %w", err)
		}
		return syncDirectory(s.root)
	}
	releasePath, err := s.releasePath(digest)
	if err != nil {
		return err
	}
	if err := s.verifyExistingRelease(releasePath); err != nil {
		return err
	}

	temp, err := os.CreateTemp(s.root, ".current-")
	if err != nil {
		return fmt.Errorf("reserve current release pointer: %w", err)
	}
	tempPath := temp.Name()
	if err := temp.Close(); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("close current release pointer placeholder: %w", err)
	}
	if err := os.Remove(tempPath); err != nil {
		return fmt.Errorf("remove current release pointer placeholder: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tempPath)
		}
	}()
	if err := os.Symlink(filepath.Join("releases", digest), tempPath); err != nil {
		return fmt.Errorf("create current release pointer: %w", err)
	}
	if err := os.Rename(tempPath, s.currentLink); err != nil {
		return fmt.Errorf("commit current release pointer: %w", err)
	}
	committed = true
	return syncDirectory(s.root)
}

func readRegularFile(path string) ([]byte, error) {
	file, err := openRegularFileNoFollow(path)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("inspect state file: %w", err)
	}
	if info.Size() > maxStateFileSize {
		_ = file.Close()
		return nil, fmt.Errorf("%w: state file size limit exceeded", ErrCorruptState)
	}
	content, readErr := io.ReadAll(io.LimitReader(file, maxStateFileSize+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read state file: %w", readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close state file: %w", closeErr)
	}
	if len(content) > maxStateFileSize {
		return nil, fmt.Errorf("%w: state file size limit exceeded", ErrCorruptState)
	}
	return content, nil
}

func openRegularFileNoFollow(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if info, statErr := os.Lstat(path); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: refused to follow a symlink", ErrInvalidPath)
		}
		return nil, fmt.Errorf("open state file: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("inspect open state file: %w", err)
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("%w: expected a regular file", ErrInvalidPath)
	}
	return file, nil
}

func (s *diskStore) journalPath(deploymentID string) string {
	sum := sha256.Sum256([]byte(deploymentID))
	return filepath.Join(s.journalDir, hex.EncodeToString(sum[:])+".json")
}

func (s *diskStore) loadJournal(deploymentID string) (*journal, error) {
	if err := s.verifyCoreDirs(); err != nil {
		return nil, err
	}
	path := s.journalPath(deploymentID)
	content, err := readRegularFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var value journal
	if err := json.Unmarshal(content, &value); err != nil {
		return nil, fmt.Errorf("%w: journal cannot be decoded", ErrCorruptState)
	}
	if err := validateJournal(&value, deploymentID); err != nil {
		return nil, err
	}
	return &value, nil
}

func validateJournal(value *journal, deploymentID string) error {
	if value.Version != journalVersion || value.DeploymentID != deploymentID || len(value.Attempts) == 0 {
		return fmt.Errorf("%w: invalid journal header", ErrCorruptState)
	}
	var previousAttempt uint32
	for i, attempt := range value.Attempts {
		if attempt.Attempt == 0 || (i > 0 && attempt.Attempt <= previousAttempt) || !validSHA256(attempt.CommandDigest) || len(attempt.Transitions) == 0 {
			return fmt.Errorf("%w: invalid attempt record", ErrCorruptState)
		}
		if (attempt.Action != ActionApply && attempt.Action != ActionRollback) || validateID(attempt.ConfigVersionID, "journal config version id") != nil {
			return fmt.Errorf("%w: invalid attempt metadata", ErrCorruptState)
		}
		if attempt.PreviousVersionID != "" && validateID(attempt.PreviousVersionID, "journal previous version id") != nil {
			return fmt.Errorf("%w: invalid attempt rollback target", ErrCorruptState)
		}
		if attempt.PriorPointersSet {
			if err := validatePointers(attempt.PriorPointers); err != nil {
				return fmt.Errorf("%w: invalid prior pointers", ErrCorruptState)
			}
		} else if attempt.PriorPointers != (Pointers{}) {
			return fmt.Errorf("%w: prior pointers are present without a marker", ErrCorruptState)
		}
		if err := validateGenerationState(&attempt); err != nil {
			return err
		}
		switch attempt.Action {
		case ActionApply:
			if !validSHA256(attempt.ManifestSHA256) || attempt.RollbackErrorCode != "" || attempt.RollbackSummary != "" {
				return fmt.Errorf("%w: invalid apply attempt metadata", ErrCorruptState)
			}
		case ActionRollback:
			if attempt.PreviousVersionID == "" {
				return fmt.Errorf("%w: rollback baseline is missing", ErrCorruptState)
			}
			if attempt.PriorPointersSet {
				if !validSHA256(attempt.ManifestSHA256) || attempt.ManifestSHA256 != attempt.PriorPointers.PreviousDigest || attempt.ConfigVersionID != attempt.PriorPointers.Previous || attempt.PreviousVersionID != attempt.PriorPointers.Current {
					return fmt.Errorf("%w: rollback target differs from prior pointers", ErrCorruptState)
				}
			} else if attempt.ManifestSHA256 != "" {
				return fmt.Errorf("%w: unresolved rollback target has a digest", ErrCorruptState)
			}
			if (attempt.RollbackErrorCode == "") != (attempt.RollbackSummary == "") {
				return fmt.Errorf("%w: incomplete rollback recovery error", ErrCorruptState)
			}
			if attempt.Phase == phaseExplicitRollbackRestore {
				if attempt.RollbackErrorCode == "" {
					return fmt.Errorf("%w: rollback recovery error is missing", ErrCorruptState)
				}
			} else if attempt.RollbackErrorCode != "" {
				return fmt.Errorf("%w: rollback recovery error is out of phase", ErrCorruptState)
			}
		}
		previousAttempt = attempt.Attempt
		for j, transition := range attempt.Transitions {
			if transition.Sequence != uint64(j+1) || !validState(transition.State) {
				return fmt.Errorf("%w: invalid transition sequence", ErrCorruptState)
			}
			if j == 0 && transition.State != StateDelivered {
				return fmt.Errorf("%w: attempt does not begin as delivered", ErrCorruptState)
			}
			if j > 0 && !validTransition(attempt.Action, attempt.Transitions[j-1].State, transition.State) {
				return fmt.Errorf("%w: invalid state transition", ErrCorruptState)
			}
		}
		latest := attempt.Transitions[len(attempt.Transitions)-1].State
		if !phaseMatchesState(attempt.Action, attempt.Phase, latest) {
			return fmt.Errorf("%w: execution phase does not match state", ErrCorruptState)
		}
		if i < len(value.Attempts)-1 && attempt.Phase != "" {
			return fmt.Errorf("%w: newer attempt follows a nonterminal attempt", ErrCorruptState)
		}
	}
	return nil
}

func validateGenerationState(attempt *attemptRecord) error {
	if !attempt.GenerationCaptured {
		if !emptyRuntimeGeneration(attempt.OldGeneration) || attempt.Drain != nil {
			return fmt.Errorf("%w: drain state exists without a captured generation", ErrCorruptState)
		}
		return nil
	}
	if attempt.PriorPointers.Current == "" {
		if !emptyRuntimeGeneration(attempt.OldGeneration) {
			return fmt.Errorf("%w: first deployment captured an old generation", ErrCorruptState)
		}
	} else if !validRuntimeGeneration(attempt.OldGeneration) {
		return fmt.Errorf("%w: captured OpenResty generation is invalid", ErrCorruptState)
	}
	if attempt.Drain == nil {
		return nil
	}
	drain := attempt.Drain
	if drain.Revision == 0 || !validSHA256(drain.Digest) || drain.OldVersionID != attempt.PreviousVersionID ||
		drain.NewVersionID != attempt.ConfigVersionID || drain.StartedAt.IsZero() || !drain.Deadline.After(drain.StartedAt) ||
		drain.CommandDeadline.Before(drain.StartedAt) || drain.RemainingOldWorkers < 0 || len(drain.Transitions) == 0 {
		return fmt.Errorf("%w: deployment drain record is invalid", ErrCorruptState)
	}
	for index, transition := range drain.Transitions {
		if transition.Sequence != uint64(index+1) || transition.At.IsZero() || !validDrainPhase(transition.Phase) {
			return fmt.Errorf("%w: deployment drain transition is invalid", ErrCorruptState)
		}
	}
	if drain.Phase != drain.Transitions[len(drain.Transitions)-1].Phase {
		return fmt.Errorf("%w: deployment drain phase does not match its journal", ErrCorruptState)
	}
	return nil
}

func emptyRuntimeGeneration(generation RuntimeGeneration) bool {
	return generation.Master == (ProcessIdentity{}) && len(generation.Workers) == 0
}

func validRuntimeGeneration(generation RuntimeGeneration) bool {
	if !validProcessIdentity(generation.Master) || generation.Master.Role != "master" || len(generation.Workers) == 0 || len(generation.Workers) > 256 {
		return false
	}
	seen := make(map[int]struct{}, len(generation.Workers))
	for index, worker := range generation.Workers {
		if !validProcessIdentity(worker) || worker.Role != "worker" || worker.ParentPID != generation.Master.PID ||
			(generation.Master.OwnerUID != 0 && worker.OwnerUID != generation.Master.OwnerUID) ||
			(index > 0 && worker.OwnerUID != generation.Workers[0].OwnerUID) ||
			worker.BootID != generation.Master.BootID || worker.ExecutableDevice != generation.Master.ExecutableDevice ||
			worker.ExecutableInode != generation.Master.ExecutableInode {
			return false
		}
		if _, exists := seen[worker.PID]; exists {
			return false
		}
		seen[worker.PID] = struct{}{}
	}
	return true
}

func validProcessIdentity(identity ProcessIdentity) bool {
	return identity.PID > 1 && identity.ParentPID >= 0 && identity.StartTicks > 0 && identity.ExecutableDevice > 0 &&
		identity.ExecutableInode > 0 && identity.BootID != "" && (identity.Role == "master" || identity.Role == "worker")
}

func validDrainPhase(phase DrainPhase) bool {
	switch phase {
	case DrainPhaseHealthGate, DrainPhaseDrainingOld, DrainPhaseCompleted, DrainPhaseFailed:
		return true
	default:
		return false
	}
}

func validTransition(action Action, from, to State) bool {
	if action == ActionRollback {
		switch from {
		case StateDelivered:
			return to == StateStaged || to == StateFailed
		case StateStaged:
			return to == StatePrechecked || to == StateFailed
		case StatePrechecked:
			return to == StateReverting || to == StateFailed
		case StateReverting:
			return to == StateReverted || to == StateFailed || to == StateRollbackFailed
		default:
			return false
		}
	}
	switch from {
	case StateDelivered:
		return to == StateStaged || to == StateFailed
	case StateStaged:
		return to == StatePrechecked || to == StateFailed
	case StatePrechecked:
		return to == StateActivated || to == StateFailed
	case StateActivated:
		return to == StateHealthy || to == StateReverting
	case StateReverting:
		return to == StateReverted || to == StateRollbackFailed
	default:
		return false
	}
}

func phaseMatchesState(action Action, phase executionPhase, state State) bool {
	if action == ActionRollback {
		switch phase {
		case phaseExplicitRollbackValidate:
			return state == StateDelivered
		case phaseExplicitRollbackPrecheck:
			return state == StateStaged
		case phaseExplicitRollbackActivate:
			return state == StatePrechecked
		case phaseExplicitRollbackVerify, phaseExplicitRollbackRestore:
			return state == StateReverting
		case "":
			return state == StateFailed || state == StateReverted || state == StateRollbackFailed
		default:
			return false
		}
	}
	switch phase {
	case phaseStage:
		return state == StateDelivered
	case phasePrecheck:
		return state == StateStaged
	case phaseActivate:
		return state == StatePrechecked
	case phaseHealth:
		return state == StateActivated
	case phaseRollback:
		return state == StateActivated || state == StateReverting
	case "":
		return state == StateHealthy || state == StateFailed || state == StateReverted || state == StateRollbackFailed
	default:
		return false
	}
}

func validState(state State) bool {
	switch state {
	case StateQueued, StateDelivered, StateStaged, StatePrechecked, StateActivated, StateHealthy, StateFailed, StateReverting, StateReverted, StateRollbackFailed:
		return true
	default:
		return false
	}
}

func (s *diskStore) saveJournal(value *journal) error {
	if err := s.verifyCoreDirs(); err != nil {
		return err
	}
	return writeJSONAtomic(s.journalDir, filepath.Base(s.journalPath(value.DeploymentID)), value)
}

func (s *diskStore) loadPointers() (Pointers, error) {
	if err := s.verifyCoreDirs(); err != nil {
		return Pointers{}, err
	}
	path := filepath.Join(s.stateDir, "pointers.json")
	content, err := readRegularFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Pointers{}, nil
	}
	if err != nil {
		return Pointers{}, err
	}
	var pointers Pointers
	if err := json.Unmarshal(content, &pointers); err != nil {
		return Pointers{}, fmt.Errorf("%w: pointers cannot be decoded", ErrCorruptState)
	}
	if err := validatePointers(pointers); err != nil {
		return Pointers{}, fmt.Errorf("%w: invalid pointers", ErrCorruptState)
	}
	return pointers, nil
}

func (s *diskStore) savePointers(pointers Pointers) error {
	if err := s.verifyCoreDirs(); err != nil {
		return err
	}
	if err := validatePointers(pointers); err != nil {
		return err
	}
	return writeJSONAtomic(s.stateDir, "pointers.json", pointers)
}

func validatePointers(pointers Pointers) error {
	if (pointers.Current == "") != (pointers.CurrentDigest == "") || (pointers.Previous == "") != (pointers.PreviousDigest == "") {
		return fmt.Errorf("%w: version ids and digests must be paired", ErrCorruptState)
	}
	if pointers.Current != "" {
		if err := validateID(pointers.Current, "current version id"); err != nil || !validSHA256(pointers.CurrentDigest) || pointers.CurrentDigest != strings.ToLower(pointers.CurrentDigest) {
			return fmt.Errorf("%w: invalid current pointer", ErrCorruptState)
		}
	}
	if pointers.Previous != "" {
		if err := validateID(pointers.Previous, "previous version id"); err != nil || !validSHA256(pointers.PreviousDigest) || pointers.PreviousDigest != strings.ToLower(pointers.PreviousDigest) {
			return fmt.Errorf("%w: invalid previous pointer", ErrCorruptState)
		}
	}
	return nil
}

func (s *diskStore) pruneReleases(limit int, protected map[string]struct{}) error {
	entries, err := os.ReadDir(s.releasesDir)
	if err != nil {
		return fmt.Errorf("read release directory: %w", err)
	}
	type releaseEntry struct {
		name    string
		modTime time.Time
	}
	releases := make([]releaseEntry, 0, len(entries))
	for _, entry := range entries {
		path := filepath.Join(s.releasesDir, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("inspect retained release: %w", err)
		}
		if !validSHA256(entry.Name()) || entry.Name() != strings.ToLower(entry.Name()) || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("%w: release directory contains an unsafe entry", ErrInvalidPath)
		}
		releases = append(releases, releaseEntry{name: entry.Name(), modTime: info.ModTime()})
	}
	sort.Slice(releases, func(i, j int) bool {
		if releases[i].modTime.Equal(releases[j].modTime) {
			return releases[i].name > releases[j].name
		}
		return releases[i].modTime.After(releases[j].modTime)
	})

	remaining := len(releases)
	for i := len(releases) - 1; i >= 0 && remaining > limit; i-- {
		if _, keep := protected[releases[i].name]; keep {
			continue
		}
		path, err := s.releasePath(releases[i].name)
		if err != nil {
			return err
		}
		if err := s.verifyExistingRelease(path); err != nil {
			return err
		}
		makeTreeWritable(path)
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("remove expired release: %w", err)
		}
		remaining--
	}
	return syncDirectory(s.releasesDir)
}

func (s *diskStore) protectInProgressReleases(protected map[string]struct{}) error {
	entries, err := os.ReadDir(s.journalDir)
	if err != nil {
		return fmt.Errorf("read deployment journals: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			return fmt.Errorf("%w: journal directory contains an unsafe entry", ErrInvalidPath)
		}
		content, err := readRegularFile(filepath.Join(s.journalDir, entry.Name()))
		if err != nil {
			return err
		}
		var value journal
		if err := json.Unmarshal(content, &value); err != nil {
			return fmt.Errorf("%w: journal cannot be decoded", ErrCorruptState)
		}
		if filepath.Base(s.journalPath(value.DeploymentID)) != entry.Name() {
			return fmt.Errorf("%w: journal filename does not match deployment", ErrCorruptState)
		}
		if err := validateJournal(&value, value.DeploymentID); err != nil {
			return err
		}
		for _, attempt := range value.Attempts {
			if attempt.Phase == "" {
				continue
			}
			protected[attempt.ManifestSHA256] = struct{}{}
			for _, digest := range []string{attempt.PriorPointers.CurrentDigest, attempt.PriorPointers.PreviousDigest} {
				if digest != "" {
					protected[digest] = struct{}{}
				}
			}
		}
	}
	return nil
}

func writeJSONAtomic(dir, name string, value any) error {
	content, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	content = append(content, '\n')
	temp, err := os.CreateTemp(dir, ".tmp-")
	if err != nil {
		return fmt.Errorf("create temporary state: %w", err)
	}
	tempPath := temp.Name()
	committed := false
	defer func() {
		_ = temp.Close()
		if !committed {
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		return fmt.Errorf("set state permissions: %w", err)
	}
	if _, err := temp.Write(content); err != nil {
		return fmt.Errorf("write state: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return fmt.Errorf("sync state: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close state: %w", err)
	}
	target := filepath.Join(dir, name)
	if err := os.Rename(tempPath, target); err != nil {
		return fmt.Errorf("commit state: %w", err)
	}
	committed = true
	return syncDirectory(dir)
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open directory for sync: %w", err)
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	if syncErr != nil {
		return fmt.Errorf("sync directory: %w", syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close directory: %w", closeErr)
	}
	return nil
}
