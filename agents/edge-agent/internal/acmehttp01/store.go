package acmehttp01

import (
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
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

const (
	releaseSnapshotFile = ".snapshot.json"
	releaseManifestFile = ".manifest.json"
	journalVersion      = 1
	maxStateFileBytes   = 16 << 20
)

type releaseManifest struct {
	SchemaVersion    string `json:"schema_version"`
	OverlayVersionID string `json:"overlay_version_id"`
	OverlayRevision  uint64 `json:"overlay_revision"`
	ArtifactSHA256   string `json:"artifact_sha256"`
	SnapshotSHA256   string `json:"snapshot_sha256"`
	EntryCount       int    `json:"entry_count"`
}

type executionPhase string

const (
	phaseStage    executionPhase = "stage"
	phasePrecheck executionPhase = "precheck"
	phaseActivate executionPhase = "activate"
	phaseHealth   executionPhase = "health"
	phaseRollback executionPhase = "rollback"
	phaseDone     executionPhase = "done"
)

type persistedTransition struct {
	Sequence        uint64    `json:"sequence"`
	State           State     `json:"state"`
	At              time.Time `json:"at"`
	ResultCode      string    `json:"result_code"`
	Summary         string    `json:"summary"`
	ActiveUnchanged bool      `json:"active_unchanged"`
}

type attemptRecord struct {
	Attempt           uint32                `json:"attempt"`
	CommandSHA256     string                `json:"command_sha256"`
	ArtifactSHA256    string                `json:"artifact_sha256"`
	OverlayVersionID  string                `json:"overlay_version_id"`
	OverlayRevision   uint64                `json:"overlay_revision"`
	PreviousVersionID string                `json:"previous_version_id,omitempty"`
	PreviousRevision  uint64                `json:"previous_revision,omitempty"`
	Phase             executionPhase        `json:"phase"`
	PriorPointerSet   bool                  `json:"prior_pointer_set"`
	PriorPointer      Pointer               `json:"prior_pointer"`
	Transitions       []persistedTransition `json:"transitions"`
}

type journal struct {
	Version      int             `json:"version"`
	DeploymentID string          `json:"deployment_id"`
	Attempts     []attemptRecord `json:"attempts"`
}

type diskStore struct {
	configuredRoot string
	deploymentRoot string
	overlayRoot    string
	releasesDir    string
	stagingDir     string
	stateDir       string
	journalDir     string
	currentLink    string
	activationLock string
	runtimeConfigs []string
}

func newDiskStore(configuredRoot string) (*diskStore, error) {
	if configuredRoot == "" || !filepath.IsAbs(configuredRoot) || filepath.Clean(configuredRoot) != configuredRoot || configuredRoot == string(filepath.Separator) {
		return nil, ErrInvalidStateRoot
	}
	info, err := os.Lstat(configuredRoot)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, ErrInvalidStateRoot
	}
	realRoot, err := filepath.EvalSymlinks(configuredRoot)
	if err != nil || realRoot == string(filepath.Separator) {
		return nil, ErrInvalidStateRoot
	}
	store := &diskStore{
		configuredRoot: configuredRoot,
		deploymentRoot: realRoot,
		overlayRoot:    filepath.Join(realRoot, "acme-http01"),
		activationLock: filepath.Join(realRoot, "state", "activation.lock"),
	}
	store.releasesDir = filepath.Join(store.overlayRoot, "releases")
	store.stagingDir = filepath.Join(store.overlayRoot, "staging")
	store.stateDir = filepath.Join(store.overlayRoot, "state")
	store.journalDir = filepath.Join(store.stateDir, "journal")
	store.currentLink = filepath.Join(store.overlayRoot, "current")
	for _, path := range []string{filepath.Join(realRoot, "state"), store.overlayRoot, store.releasesDir, store.stagingDir, store.stateDir, store.journalDir} {
		if err := ensureDirectory(path); err != nil {
			return nil, err
		}
	}
	// The OpenResty worker (nobody / cdnca-runtime) must reach
	// current/<host>/<token>: traversal only, never listing.
	for _, path := range []string{store.overlayRoot, store.releasesDir} {
		if err := os.Chmod(path, traversableDirectoryMode); err != nil {
			return nil, err
		}
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

func (s *diskStore) ready() bool {
	configPath := filepath.Join(s.deploymentRoot, "current", "nginx.conf")
	content, err := readFile(configPath, MaxArtifactBytes)
	// Only a current release without its own nginx.conf (site runtime v2)
	// falls through to the rendered runtime configs.
	for index := 0; errors.Is(err, os.ErrNotExist) && index < len(s.runtimeConfigs); index++ {
		content, err = readFile(s.runtimeConfigs[index], MaxArtifactBytes)
	}
	if err != nil {
		return false
	}
	expectedRoot := edgeconfig.ACMEHTTP01OverlayRoot(s.configuredRoot)
	return strings.Contains(string(content), RouteMarker) && strings.Contains(string(content), "root "+expectedRoot+";")
}

func (s *diskStore) lock(ctx context.Context) (func(), error) {
	file, err := os.OpenFile(s.activationLock, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open shared activation lock: %w", err)
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
			return nil, fmt.Errorf("lock shared activation state: %w", err)
		}
		select {
		case <-ctx.Done():
			_ = file.Close()
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (s *diskStore) stage(snapshot Snapshot, artifactDigest [sha256.Size]byte) error {
	canonical, err := CanonicalSnapshot(snapshot)
	if err != nil {
		return err
	}
	releasePath := filepath.Join(s.releasesDir, snapshot.OverlayVersionID)
	if info, statErr := os.Lstat(releasePath); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return ErrCorruptState
		}
		return s.verifyRelease(releasePath, snapshot, artifactDigest)
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	stagePath, err := os.MkdirTemp(s.stagingDir, snapshot.OverlayVersionID+"-")
	if err != nil {
		return fmt.Errorf("create overlay staging directory: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = filepath.WalkDir(stagePath, func(path string, entry fs.DirEntry, walkErr error) error {
				if walkErr == nil && entry.IsDir() {
					_ = os.Chmod(path, 0o700)
				}
				return nil
			})
			_ = os.RemoveAll(stagePath)
		}
	}()
	for _, entry := range snapshot.Entries {
		hostDir := filepath.Join(stagePath, entry.Host)
		if err := os.MkdirAll(hostDir, 0o700); err != nil {
			return fmt.Errorf("create challenge host directory: %w", err)
		}
		if err := writeNewFile(filepath.Join(hostDir, entry.Token), []byte(entry.Value), 0o440); err != nil {
			return err
		}
	}
	if err := writeNewFile(filepath.Join(stagePath, releaseSnapshotFile), canonical, 0o400); err != nil {
		return err
	}
	snapshotDigest := sha256.Sum256(canonical)
	manifest := releaseManifest{
		SchemaVersion: ArtifactSchemaVersion, OverlayVersionID: snapshot.OverlayVersionID,
		OverlayRevision: snapshot.OverlayRevision, ArtifactSHA256: hex.EncodeToString(artifactDigest[:]),
		SnapshotSHA256: hex.EncodeToString(snapshotDigest[:]), EntryCount: len(snapshot.Entries),
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	if err := writeNewFile(filepath.Join(stagePath, releaseManifestFile), manifestBytes, 0o400); err != nil {
		return err
	}
	if err := syncTree(stagePath); err != nil {
		return err
	}
	if err := os.Rename(stagePath, releasePath); err != nil {
		return fmt.Errorf("commit immutable overlay release: %w", err)
	}
	committed = true
	if err := makeImmutable(releasePath); err != nil {
		return err
	}
	if err := syncTree(releasePath); err != nil {
		return err
	}
	if err := syncDirectory(s.releasesDir); err != nil {
		return err
	}
	return s.verifyRelease(releasePath, snapshot, artifactDigest)
}

func (s *diskStore) verifyRelease(path string, expected Snapshot, artifactDigest [sha256.Size]byte) error {
	pointer, actual, snapshotBytes, err := loadVerifiedRelease(path, expected.OverlayVersionID)
	if err != nil {
		return err
	}
	canonical, err := CanonicalSnapshot(expected)
	if err != nil || !jsonEqual(canonical, snapshotBytes) {
		return ErrConflict
	}
	if pointer.Revision != expected.OverlayRevision || pointer.SHA256 != hex.EncodeToString(artifactDigest[:]) ||
		actual.OverlayRevision != expected.OverlayRevision {
		return ErrConflict
	}
	return nil
}

func (s *diskStore) releasePath(versionID string) string {
	return filepath.Join(s.releasesDir, versionID)
}

func (s *diskStore) current() (Pointer, Snapshot, error) {
	info, err := os.Lstat(s.currentLink)
	if errors.Is(err, os.ErrNotExist) {
		return Pointer{}, Snapshot{}, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return Pointer{}, Snapshot{}, ErrCorruptState
	}
	target, err := os.Readlink(s.currentLink)
	if err != nil {
		return Pointer{}, Snapshot{}, ErrCorruptState
	}
	versionID := filepath.Base(target)
	if target != filepath.Join("releases", versionID) || !canonicalUUID(versionID) {
		return Pointer{}, Snapshot{}, ErrCorruptState
	}
	pointer, snapshot, err := s.loadRelease(versionID)
	if err != nil {
		return Pointer{}, Snapshot{}, err
	}
	return pointer, snapshot, nil
}

func (s *diskStore) loadRelease(versionID string) (Pointer, Snapshot, error) {
	if !canonicalUUID(versionID) {
		return Pointer{}, Snapshot{}, ErrCorruptState
	}
	releasePath := filepath.Join(s.releasesDir, versionID)
	pointer, snapshot, _, err := loadVerifiedRelease(releasePath, versionID)
	return pointer, snapshot, err
}

func loadVerifiedRelease(path, versionID string) (Pointer, Snapshot, []byte, error) {
	if !canonicalUUID(versionID) || !secureDirectory(path) {
		return Pointer{}, Snapshot{}, nil, ErrCorruptState
	}
	manifestBytes, err := readReleaseFile(filepath.Join(path, releaseManifestFile), maxStateFileBytes, releasePrivateMode)
	if err != nil {
		return Pointer{}, Snapshot{}, nil, ErrCorruptState
	}
	var manifest releaseManifest
	if err := decodeStrict(manifestBytes, &manifest); err != nil {
		return Pointer{}, Snapshot{}, nil, ErrCorruptState
	}
	canonicalManifest, err := json.Marshal(manifest)
	if err != nil || !jsonEqual(canonicalManifest, manifestBytes) || manifest.SchemaVersion != ArtifactSchemaVersion ||
		manifest.OverlayVersionID != versionID || manifest.OverlayRevision == 0 || manifest.EntryCount < 0 ||
		manifest.EntryCount > MaxEntries || !validSHA256Hex(manifest.ArtifactSHA256) || !validSHA256Hex(manifest.SnapshotSHA256) {
		return Pointer{}, Snapshot{}, nil, ErrCorruptState
	}
	snapshotBytes, err := readReleaseFile(filepath.Join(path, releaseSnapshotFile), MaxArtifactBytes, releasePrivateMode)
	if err != nil {
		return Pointer{}, Snapshot{}, nil, ErrCorruptState
	}
	var snapshot Snapshot
	if err := decodeStrict(snapshotBytes, &snapshot); err != nil || validateSnapshotStructure(snapshot) != nil {
		return Pointer{}, Snapshot{}, nil, ErrCorruptState
	}
	canonicalSnapshot, err := CanonicalSnapshot(snapshot)
	snapshotDigest := sha256.Sum256(snapshotBytes)
	if err != nil || !jsonEqual(canonicalSnapshot, snapshotBytes) || snapshot.OverlayVersionID != versionID ||
		snapshot.OverlayRevision != manifest.OverlayRevision || len(snapshot.Entries) != manifest.EntryCount ||
		manifest.SnapshotSHA256 != hex.EncodeToString(snapshotDigest[:]) || !releaseTreeMatches(path, snapshot) {
		return Pointer{}, Snapshot{}, nil, ErrCorruptState
	}
	return Pointer{VersionID: versionID, Revision: manifest.OverlayRevision, SHA256: manifest.ArtifactSHA256}, snapshot, snapshotBytes, nil
}

func releaseTreeMatches(path string, snapshot Snapshot) bool {
	expectedHosts := make(map[string]map[string]string)
	for _, entry := range snapshot.Entries {
		if expectedHosts[entry.Host] == nil {
			expectedHosts[entry.Host] = make(map[string]string)
		}
		expectedHosts[entry.Host][entry.Token] = entry.Value
	}
	rootEntries, err := os.ReadDir(path)
	if err != nil || len(rootEntries) != len(expectedHosts)+2 {
		return false
	}
	seenHosts := make(map[string]struct{}, len(expectedHosts))
	for _, item := range rootEntries {
		if item.Name() == releaseManifestFile || item.Name() == releaseSnapshotFile {
			if item.IsDir() {
				return false
			}
			continue
		}
		tokens, exists := expectedHosts[item.Name()]
		if !exists || !secureDirectory(filepath.Join(path, item.Name())) {
			return false
		}
		seenHosts[item.Name()] = struct{}{}
		hostEntries, readErr := os.ReadDir(filepath.Join(path, item.Name()))
		if readErr != nil || len(hostEntries) != len(tokens) {
			return false
		}
		for _, tokenFile := range hostEntries {
			expected, exists := tokens[tokenFile.Name()]
			if !exists || tokenFile.IsDir() {
				return false
			}
			content, readErr := readReleaseFile(filepath.Join(path, item.Name(), tokenFile.Name()), 1024, releaseTokenMode, releasePrivateMode)
			if readErr != nil || string(content) != expected {
				return false
			}
		}
	}
	return len(seenHosts) == len(expectedHosts)
}

func secureDirectory(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode()&os.ModeSymlink == 0 && info.IsDir() &&
		(info.Mode().Perm() == releaseDirectoryMode || info.Mode().Perm() == legacyReleaseDirMode)
}

func readReleaseFile(path string, maximum int64, modes ...fs.FileMode) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || !slices.Contains(modes, info.Mode().Perm()) {
		return nil, ErrCorruptState
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return nil, ErrCorruptState
	}
	return readFile(path, maximum)
}

func validSHA256Hex(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == hex.EncodeToString(decoded)
}

func (s *diskStore) switchCurrent(pointer Pointer) error {
	if pointer.VersionID == "" {
		if err := os.Remove(s.currentLink); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return syncDirectory(s.overlayRoot)
	}
	if !canonicalUUID(pointer.VersionID) {
		return ErrCorruptState
	}
	releasePath := filepath.Join(s.releasesDir, pointer.VersionID)
	if info, err := os.Lstat(releasePath); err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return ErrCorruptState
	}
	temporary, err := os.CreateTemp(s.overlayRoot, ".current-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		return err
	}
	if err := os.Remove(temporaryPath); err != nil {
		return err
	}
	defer os.Remove(temporaryPath)
	if err := os.Symlink(filepath.Join("releases", pointer.VersionID), temporaryPath); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, s.currentLink); err != nil {
		return err
	}
	return syncDirectory(s.overlayRoot)
}

func (s *diskStore) loadJournal(deploymentID string) (journal, error) {
	path := filepath.Join(s.journalDir, deploymentID+".json")
	content, err := readFile(path, maxStateFileBytes)
	if errors.Is(err, os.ErrNotExist) {
		return journal{Version: journalVersion, DeploymentID: deploymentID}, nil
	}
	if err != nil {
		return journal{}, err
	}
	var value journal
	if err := decodeStrict(content, &value); err != nil || value.Version != journalVersion || value.DeploymentID != deploymentID {
		return journal{}, ErrCorruptState
	}
	return value, nil
}

func (s *diskStore) saveJournal(value journal) error {
	content, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return writeAtomic(s.journalDir, value.DeploymentID+".json", content)
}

func (s *diskStore) cleanupStaging() error {
	entries, err := os.ReadDir(s.stagingDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		path := filepath.Join(s.stagingDir, entry.Name())
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return ErrCorruptState
		}
		_ = filepath.WalkDir(path, func(current string, item fs.DirEntry, walkErr error) error {
			if walkErr == nil {
				_ = os.Chmod(current, 0o700)
			}
			return nil
		})
		if err := os.RemoveAll(path); err != nil {
			return err
		}
	}
	return syncDirectory(s.stagingDir)
}

func ensureDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o700); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() ||
		info.Mode().Perm()&0o077 != 0 && info.Mode().Perm() != traversableDirectoryMode {
		return ErrInvalidStateRoot
	}
	return nil
}

// Release modes. Workers only traverse directories and read token files (the
// key authorization is served publicly anyway); the manifest and snapshot stay
// owner-only. Releases written before FX05① (0500/0400) still verify.
const (
	traversableDirectoryMode fs.FileMode = 0o711
	releaseDirectoryMode     fs.FileMode = 0o511
	releaseTokenMode         fs.FileMode = 0o444
	legacyReleaseDirMode     fs.FileMode = 0o500
	releasePrivateMode       fs.FileMode = 0o400
)

func writeNewFile(path string, content []byte, mode fs.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func writeAtomic(directory, name string, content []byte) error {
	temporary, err := os.CreateTemp(directory, ".state-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
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
	if err := os.Rename(temporaryPath, filepath.Join(directory, name)); err != nil {
		return err
	}
	return syncDirectory(directory)
}

func readFile(path string, maximum int64) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maximum {
		return nil, ErrCorruptState
	}
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(content)) > maximum {
		return nil, ErrCorruptState
	}
	return content, nil
}

func makeImmutable(root string) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil || info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return ErrCorruptState
		}
		if info.IsDir() {
			return os.Chmod(path, releaseDirectoryMode)
		}
		if filepath.Dir(path) == root {
			return os.Chmod(path, releasePrivateMode)
		}
		return os.Chmod(path, releaseTokenMode)
	})
}

func syncTree(root string) error {
	var directories []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			directories = append(directories, path)
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		syncErr := file.Sync()
		closeErr := file.Close()
		if syncErr != nil {
			return syncErr
		}
		return closeErr
	})
	if err != nil {
		return err
	}
	for index := len(directories) - 1; index >= 0; index-- {
		if err := syncDirectory(directories[index]); err != nil {
			return err
		}
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func decodeStrict(content []byte, destination any) error {
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	return ensureJSONEOF(decoder)
}

func ensureJSONEOF(decoder *json.Decoder) error {
	if decoder.Decode(&struct{}{}) != io.EOF {
		return ErrCorruptState
	}
	return nil
}

func jsonEqual(left, right []byte) bool {
	return string(left) == string(right)
}
