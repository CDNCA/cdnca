package certstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	statusSchemaVersion     = "cdnca.edge.certificate-status/v1"
	referencesSchemaVersion = "cdnca.edge.certificate-version-references/v1"
	// Sizes, not counts, bound state files: a release holds one command
	// (MaxBundleBytes) and the references name every certificate version a
	// node's site runtime uses.
	maxManifestBytes   = 16 << 20
	maxStatusBytes     = 32 << 20
	maxReferencesBytes = 64 << 20
)

type diskStore struct {
	root             string
	staging          string
	versions         string
	shared           string
	sites            string
	byVersion        string
	gc               string
	current          string
	lkg              string
	statusPath       string
	referencesPath   string
	indexJournalPath string
	lockPath         string
}

func newDiskStore(root string) (*diskStore, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || hasControl(root) {
		return nil, fmt.Errorf("%w: state root must be a clean absolute path", ErrUnsafeState)
	}
	if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(root, 0o700); err != nil {
			return nil, fmt.Errorf("%w: create state root", ErrUnsafeState)
		}
	} else if err != nil {
		return nil, fmt.Errorf("%w: inspect state root", ErrUnsafeState)
	}
	store := &diskStore{
		root: root, staging: filepath.Join(root, "staging"), versions: filepath.Join(root, "versions"),
		shared: filepath.Join(root, "shared"), sites: filepath.Join(root, "sites"), byVersion: filepath.Join(root, "byversion"),
		gc: filepath.Join(root, "gc"), current: filepath.Join(root, "current"), lkg: filepath.Join(root, "lkg"),
		statusPath: filepath.Join(root, "status.json"), referencesPath: filepath.Join(root, "certificate-version-references.json"),
		indexJournalPath: filepath.Join(root, "index-journal.json"), lockPath: filepath.Join(root, "publish.lock"),
	}
	if err := store.validateMutableDirectories(); err != nil {
		return nil, err
	}
	return store, nil
}

func (store *diskStore) validateMutableDirectories() error {
	paths := []string{store.root, store.staging, store.versions, store.shared, store.sites, store.byVersion, store.gc}
	for _, name := range []string{
		clientBodyTempDirectory, proxyTempDirectory, fastCGITempDirectory, uWSGITempDirectory, scgiTempDirectory,
	} {
		paths = append(paths, filepath.Join(store.shared, name))
	}
	for _, path := range paths {
		if path != store.root {
			if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
				if err := os.Mkdir(path, 0o700); err != nil {
					return fmt.Errorf("%w: create state subdirectory", ErrUnsafeState)
				}
			}
		}
		if err := ensurePrivateDirectory(path, true); err != nil {
			return err
		}
	}
	return nil
}

func (store *diskStore) pristine() (bool, error) {
	temporaryNames := []string{
		clientBodyTempDirectory, proxyTempDirectory, fastCGITempDirectory, uWSGITempDirectory, scgiTempDirectory,
	}
	expected := map[string]struct{}{
		filepath.Base(store.staging):   {},
		filepath.Base(store.versions):  {},
		filepath.Base(store.shared):    {},
		filepath.Base(store.sites):     {},
		filepath.Base(store.byVersion): {},
		filepath.Base(store.gc):        {},
		filepath.Base(store.lockPath):  {},
	}
	if _, err := os.Lstat(store.referencesPath); err == nil {
		references, readErr := store.readCertificateVersionReferences()
		if readErr != nil {
			return false, readErr
		}
		if len(references.Current) != 0 || len(references.Previous) != 0 {
			return false, nil
		}
		expected[filepath.Base(store.referencesPath)] = struct{}{}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("%w: inspect certificate version references", ErrUnsafeState)
	}
	entries, err := os.ReadDir(store.root)
	if err != nil {
		return false, fmt.Errorf("%w: inspect pristine state root", ErrUnsafeState)
	}
	if len(entries) != len(expected) {
		return false, nil
	}
	for _, entry := range entries {
		if _, ok := expected[entry.Name()]; !ok {
			return false, nil
		}
	}
	for _, path := range []string{store.staging, store.versions, store.sites, store.byVersion, store.gc} {
		entries, err := os.ReadDir(path)
		if err != nil {
			return false, fmt.Errorf("%w: inspect pristine state directory", ErrUnsafeState)
		}
		if len(entries) != 0 {
			return false, nil
		}
	}
	entries, err = os.ReadDir(store.shared)
	if err != nil {
		return false, fmt.Errorf("%w: inspect pristine shared directory", ErrUnsafeState)
	}
	if len(entries) != len(temporaryNames) {
		return false, nil
	}
	for _, name := range temporaryNames {
		path := filepath.Join(store.shared, name)
		children, err := os.ReadDir(path)
		if err != nil {
			return false, fmt.Errorf("%w: inspect pristine OpenResty directory", ErrUnsafeState)
		}
		if len(children) != 0 {
			return false, nil
		}
	}
	return true, nil
}

func (store *diskStore) lock(ctx context.Context) (func(), error) {
	if err := store.validateMutableDirectories(); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(store.lockPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("%w: open publisher lock", ErrUnsafeState)
	}
	if err := validateOpenedPrivateFile(file); err != nil {
		_ = file.Close()
		return nil, err
	}
	for {
		err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() {
				_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
				_ = file.Close()
			}, nil
		}
		if err != unix.EWOULDBLOCK && err != unix.EAGAIN {
			_ = file.Close()
			return nil, fmt.Errorf("%w: lock publisher", ErrUnsafeState)
		}
		select {
		case <-ctx.Done():
			_ = file.Close()
			return nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func validateOpenedPrivateFile(file *os.File) error {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || hardLinkCount(info) != 1 {
		return fmt.Errorf("%w: lock file is unsafe", ErrUnsafeState)
	}
	pathInfo, err := os.Lstat(file.Name())
	if err != nil || !os.SameFile(info, pathInfo) || pathInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: lock path is unsafe", ErrUnsafeState)
	}
	return nil
}

func (store *diskStore) stage(artifact Artifact) (string, error) {
	stage, err := os.MkdirTemp(store.staging, ".certificate-")
	if err != nil {
		return "", fmt.Errorf("stage certificate artifact: %w", err)
	}
	if err := os.Chmod(stage, 0o700); err != nil {
		_ = os.RemoveAll(stage)
		return "", fmt.Errorf("secure certificate staging directory: %w", err)
	}
	for _, artifactFile := range artifact.Files {
		if !safeRelativePath(artifactFile.Path) || artifactFile.Mode.Perm()&0o077 != 0 {
			_ = os.RemoveAll(stage)
			return "", fmt.Errorf("%w: artifact path or mode is unsafe", ErrUnsafeState)
		}
		path := filepath.Join(stage, artifactFile.Path)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			_ = os.RemoveAll(stage)
			return "", fmt.Errorf("create artifact directory: %w", err)
		}
		if err := writeExclusive(path, artifactFile.Content, artifactFile.Mode); err != nil {
			_ = os.RemoveAll(stage)
			return "", err
		}
	}
	if err := syncTreeDirectories(stage); err != nil {
		_ = os.RemoveAll(stage)
		return "", err
	}
	return stage, nil
}

func writeExclusive(path string, content []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("write certificate artifact: %w", err)
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(content); err != nil {
		return fmt.Errorf("write certificate artifact: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync certificate artifact: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close certificate artifact: %w", err)
	}
	remove = false
	return nil
}

func syncTreeDirectories(root string) error {
	var directories []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			directories = append(directories, path)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("walk staged certificate artifact: %w", err)
	}
	sort.Slice(directories, func(i, j int) bool { return len(directories[i]) > len(directories[j]) })
	for _, directory := range directories {
		if err := syncDirectory(directory); err != nil {
			return err
		}
	}
	return nil
}

func (store *diskStore) commit(stage string, artifact Artifact) (string, error) {
	if filepath.Dir(stage) != store.staging {
		return "", fmt.Errorf("%w: staging path escaped its root", ErrUnsafeState)
	}
	if err := store.rejectVersionConflict(artifact.VersionID, artifact.Digest); err != nil {
		return "", err
	}
	releaseName := artifact.VersionID + "-" + artifact.Digest
	releasePath := filepath.Join(store.versions, releaseName)
	if info, err := os.Lstat(releasePath); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("%w: release path is unsafe", ErrUnsafeState)
		}
		if err := validateReleaseFiles(releasePath, artifact); err != nil {
			return "", err
		}
		return filepath.Join("versions", releaseName), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("%w: inspect release path", ErrUnsafeState)
	}
	if err := os.Rename(stage, releasePath); err != nil {
		return "", fmt.Errorf("commit certificate release: %w", err)
	}
	if err := makeArtifactReadOnly(releasePath); err != nil {
		return "", err
	}
	if err := syncDirectory(store.versions); err != nil {
		return "", err
	}
	if err := validateReleaseFiles(releasePath, artifact); err != nil {
		return "", err
	}
	return filepath.Join("versions", releaseName), nil
}

func makeArtifactReadOnly(root string) error {
	var directories []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: symlink in artifact", ErrUnsafeState)
		}
		if entry.IsDir() {
			directories = append(directories, path)
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || hardLinkCount(info) != 1 {
			return fmt.Errorf("%w: artifact file is unsafe", ErrUnsafeState)
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, directory := range directories {
		if err := os.Chmod(directory, 0o500); err != nil {
			return fmt.Errorf("make artifact directory read-only: %w", err)
		}
	}
	return nil
}

func validateReleaseFiles(release string, artifact Artifact) error {
	if err := ensurePrivateDirectory(release, false); err != nil {
		return err
	}
	if info, err := os.Lstat(release); err != nil || info.Mode().Perm() != 0o500 {
		return fmt.Errorf("%w: release directory mode is not immutable", ErrUnsafeState)
	}
	expected := make(map[string]ArtifactFile, len(artifact.Files))
	for _, file := range artifact.Files {
		expected[filepath.Clean(file.Path)] = file
	}
	seen := make(map[string]struct{}, len(expected))
	err := filepath.WalkDir(release, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == release {
			return nil
		}
		relative, err := filepath.Rel(release, path)
		if err != nil || !safeRelativePath(relative) || entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: release path is unsafe", ErrUnsafeState)
		}
		if entry.IsDir() {
			if err := ensurePrivateDirectory(path, false); err != nil {
				return err
			}
			info, err := entry.Info()
			if err != nil || info.Mode().Perm() != 0o500 {
				return fmt.Errorf("%w: artifact directory mode is not immutable", ErrUnsafeState)
			}
			return nil
		}
		file, exists := expected[relative]
		if !exists {
			return fmt.Errorf("%w: release contains an unexpected file", ErrUnsafeState)
		}
		content, err := validatePrivateFile(path, int64(len(file.Content)))
		info, infoErr := entry.Info()
		if err != nil || infoErr != nil || info.Mode().Perm() != file.Mode.Perm() || !bytes.Equal(content, file.Content) {
			return fmt.Errorf("%w: immutable release content mismatch", ErrUnsafeState)
		}
		seen[relative] = struct{}{}
		return nil
	})
	if err != nil {
		return err
	}
	if len(seen) != len(expected) {
		return fmt.Errorf("%w: release is incomplete", ErrUnsafeState)
	}
	return nil
}

func (store *diskStore) rejectVersionConflict(versionID, digest string) error {
	entries, err := os.ReadDir(store.versions)
	if err != nil {
		return fmt.Errorf("read certificate versions: %w", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: versions contains a non-directory", ErrUnsafeState)
		}
		manifest, err := store.readManifest(filepath.Join(store.versions, entry.Name()))
		if err != nil {
			return err
		}
		if manifest.VersionID == versionID && manifest.Digest != digest {
			return ErrConflict
		}
	}
	return nil
}

func (store *diskStore) readManifest(release string) (Manifest, error) {
	raw, err := validatePrivateFile(filepath.Join(release, "manifest.json"), maxManifestBytes)
	if err != nil {
		return Manifest{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil || requireJSONEOF(decoder) != nil || manifest.SchemaVersion != manifestSchemaVersion ||
		!validIdentifier(manifest.VersionID, MaxVersionIDBytes) || len(manifest.Digest) != 64 {
		return Manifest{}, fmt.Errorf("%w: manifest is invalid", ErrUnsafeState)
	}
	if _, err := strconv.ParseUint(manifest.Digest[:16], 16, 64); err != nil {
		return Manifest{}, fmt.Errorf("%w: manifest digest is invalid", ErrUnsafeState)
	}
	for _, character := range manifest.Digest {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return Manifest{}, fmt.Errorf("%w: manifest digest is invalid", ErrUnsafeState)
		}
	}
	return manifest, nil
}

func (store *diskStore) readBundle(target string) (Bundle, *ActivationMetadata, error) {
	if !validReleaseTarget(target) {
		return Bundle{}, nil, fmt.Errorf("%w: release pointer is invalid", ErrUnsafeState)
	}
	release := filepath.Join(store.root, target)
	if err := ensurePrivateDirectory(release, false); err != nil {
		return Bundle{}, nil, err
	}
	manifest, err := store.readManifest(release)
	if err != nil {
		return Bundle{}, nil, err
	}
	bundle := Bundle{SchemaVersion: SchemaVersion, VersionID: manifest.VersionID, Bindings: make([]Binding, 0, len(manifest.Bindings))}
	for _, binding := range manifest.Bindings {
		if !safeRelativePath(binding.CertificateFile) || !safeRelativePath(binding.PrivateKeyFile) {
			return Bundle{}, nil, fmt.Errorf("%w: manifest file path is unsafe", ErrUnsafeState)
		}
		certificate, err := validatePrivateFile(filepath.Join(release, binding.CertificateFile), MaxCertificateBytes)
		if err != nil {
			return Bundle{}, nil, err
		}
		privateKey, err := validatePrivateFile(filepath.Join(release, binding.PrivateKeyFile), MaxPrivateKeyBytes)
		if err != nil {
			return Bundle{}, nil, err
		}
		bundle.Bindings = append(bundle.Bindings, Binding{
			SiteID: binding.SiteID, Domains: append([]string(nil), binding.Domains...),
			CertificateChainPEM: string(certificate), PrivateKeyPEM: string(privateKey),
		})
	}
	return bundle, cloneActivation(manifest.Activation), nil
}

func validReleaseTarget(target string) bool {
	if !safeRelativePath(target) || !strings.HasPrefix(target, "versions/") || strings.Count(target, "/") != 1 {
		return false
	}
	name := strings.TrimPrefix(target, "versions/")
	separator := strings.LastIndexByte(name, '-')
	if separator < 1 || !validIdentifier(name[:separator], MaxVersionIDBytes) || len(name[separator+1:]) != 64 {
		return false
	}
	for _, character := range name[separator+1:] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func (store *diskStore) readPointer(name string) (string, error) {
	path := store.current
	if name == "lkg" {
		path = store.lkg
	} else if name != "current" {
		return "", fmt.Errorf("%w: unknown pointer", ErrUnsafeState)
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return "", fmt.Errorf("%w: pointer is not a symlink", ErrUnsafeState)
	}
	target, err := os.Readlink(path)
	if err != nil || !validReleaseTarget(target) {
		return "", fmt.Errorf("%w: pointer target is invalid", ErrUnsafeState)
	}
	return target, nil
}

func (store *diskStore) setPointer(name, target string) error {
	if (name != "current" && name != "lkg") || !validReleaseTarget(target) {
		return fmt.Errorf("%w: pointer update is invalid", ErrUnsafeState)
	}
	temporary := filepath.Join(store.root, "."+name+"-"+filepath.Base(target)+".tmp")
	if info, err := os.Lstat(temporary); err == nil {
		if info.Mode()&os.ModeSymlink == 0 {
			return fmt.Errorf("%w: temporary pointer path is unsafe", ErrUnsafeState)
		}
		if err := os.Remove(temporary); err != nil {
			return fmt.Errorf("remove stale certificate pointer: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect temporary certificate pointer: %w", err)
	}
	if err := os.Symlink(target, temporary); err != nil {
		return fmt.Errorf("create certificate pointer: %w", err)
	}
	destination := store.current
	if name == "lkg" {
		destination = store.lkg
	}
	if err := os.Rename(temporary, destination); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("activate certificate pointer: %w", err)
	}
	return syncDirectory(store.root)
}

func (store *diskStore) clearPointer(name string) error {
	path := store.current
	if name == "lkg" {
		path = store.lkg
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("clear certificate pointer: %w", err)
	}
	return syncDirectory(store.root)
}

func (store *diskStore) writeStatus(status Status) error {
	status.SchemaVersion = statusSchemaVersion
	raw, err := json.Marshal(status)
	if err != nil {
		return fmt.Errorf("marshal certificate status: %w", err)
	}
	raw = append(raw, '\n')
	return writeAtomicFile(store.statusPath, raw)
}

func (store *diskStore) readStatus() (Status, error) {
	raw, err := validatePrivateFile(store.statusPath, maxStatusBytes)
	if errors.Is(err, os.ErrNotExist) {
		return Status{}, nil
	}
	if err != nil {
		if _, statErr := os.Lstat(store.statusPath); errors.Is(statErr, os.ErrNotExist) {
			return Status{}, nil
		}
		return Status{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var status Status
	if err := decoder.Decode(&status); err != nil || requireJSONEOF(decoder) != nil || status.SchemaVersion != statusSchemaVersion {
		return Status{}, fmt.Errorf("%w: status file is invalid", ErrUnsafeState)
	}
	if status.Active {
		if !validIdentifier(status.VersionID, MaxVersionIDBytes) || !validDigest(status.Digest) || status.AppliedAt.IsZero() {
			return Status{}, fmt.Errorf("%w: active status is invalid", ErrUnsafeState)
		}
		if _, err := decodeStatusHealthTargets(status.HealthTargets); err != nil {
			return Status{}, err
		}
	} else if status.VersionID != "" || status.Digest != "" || status.Activation != nil || len(status.HealthTargets) != 0 || !status.AppliedAt.IsZero() {
		return Status{}, fmt.Errorf("%w: inactive status contains active certificate facts", ErrUnsafeState)
	}
	return status, nil
}

type certificateVersionReferencesFile struct {
	SchemaVersion string   `json:"schema_version"`
	Current       []string `json:"current"`
	Previous      []string `json:"previous"`
}

func (store *diskStore) writeCertificateVersionReferences(references CertificateVersionReferences) error {
	normalized, err := normalizeCertificateVersionReferences(references)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(certificateVersionReferencesFile{
		SchemaVersion: referencesSchemaVersion, Current: normalized.Current, Previous: normalized.Previous,
	})
	if err != nil {
		return ErrCertificateUnavailable
	}
	raw = append(raw, '\n')
	return writeAtomicFile(store.referencesPath, raw)
}

func (store *diskStore) readCertificateVersionReferences() (CertificateVersionReferences, error) {
	if _, err := os.Lstat(store.referencesPath); errors.Is(err, os.ErrNotExist) {
		return CertificateVersionReferences{}, nil
	} else if err != nil {
		return CertificateVersionReferences{}, err
	}
	raw, err := validatePrivateFile(store.referencesPath, maxReferencesBytes)
	if err != nil {
		return CertificateVersionReferences{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var stored certificateVersionReferencesFile
	if err := decoder.Decode(&stored); err != nil || requireJSONEOF(decoder) != nil || stored.SchemaVersion != referencesSchemaVersion {
		return CertificateVersionReferences{}, fmt.Errorf("%w: certificate version references are invalid", ErrUnsafeState)
	}
	normalized, err := normalizeCertificateVersionReferences(CertificateVersionReferences{
		Current: stored.Current, Previous: stored.Previous,
	})
	if err != nil {
		return CertificateVersionReferences{}, fmt.Errorf("%w: certificate version references are invalid", ErrUnsafeState)
	}
	return normalized, nil
}

func writeAtomicFile(path string, content []byte) error {
	if err := replaceFile(path, content); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

// replaceFile atomically replaces path with content (synced); the caller
// syncs the directory.
func replaceFile(path string, content []byte) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".status-*.tmp")
	if err != nil {
		return fmt.Errorf("create certificate status: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("secure certificate status: %w", err)
	}
	if _, err := temporary.Write(content); err != nil {
		return fmt.Errorf("write certificate status: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync certificate status: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close certificate status: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("activate certificate status: %w", err)
	}
	return nil
}

func (store *diskStore) removeStatus() error {
	if err := os.Remove(store.statusPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove certificate status: %w", err)
	}
	return syncDirectory(store.root)
}

// pruneReleases removes probe releases other than current, lkg and keep. A release
// holds only its command's certificates; the index (sites/) keeps every
// site's versions, so older releases are not needed. Best effort: a release
// that is left is removed by a later prune.
func (store *diskStore) pruneReleases(keep ...string) {
	kept := make(map[string]struct{}, len(keep)+2)
	for _, target := range keep {
		if target != "" {
			kept[target] = struct{}{}
		}
	}
	for _, name := range []string{"current", "lkg"} {
		if target, err := store.readPointer(name); err == nil && target != "" {
			kept[target] = struct{}{}
		}
	}
	entries, err := os.ReadDir(store.versions)
	if err != nil {
		return
	}
	for _, entry := range entries {
		target := filepath.Join("versions", entry.Name())
		if _, keep := kept[target]; keep || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !validReleaseTarget(target) {
			continue
		}
		release := filepath.Join(store.versions, entry.Name())
		_ = filepath.WalkDir(release, func(path string, entry os.DirEntry, err error) error {
			if err == nil && entry.IsDir() {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
		_ = os.RemoveAll(release)
	}
	_ = syncDirectory(store.versions)
}
