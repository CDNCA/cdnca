package httppolicy

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

const (
	commitFilename      = "committed.json"
	commitSchemaVersion = "cdnca.edge.http-policy-commit/v1"
	maxCommitBytes      = 1024
	maxVersionFiles     = 4096
)

type commitManifest struct {
	SchemaVersion string `json:"schema_version"`
	PolicyVersion uint64 `json:"policy_version"`
	SHA256        string `json:"sha256"`
	Artifact      string `json:"artifact"`
}

type publicationIO interface {
	Write(*os.File, []byte) (int, error)
	Sync(*os.File) error
	Rename(string, string) error
}

type systemPublicationIO struct{}

func (systemPublicationIO) Write(file *os.File, content []byte) (int, error) {
	return file.Write(content)
}

func (systemPublicationIO) Sync(file *os.File) error { return file.Sync() }

func (systemPublicationIO) Rename(oldPath, newPath string) error {
	return os.Rename(oldPath, newPath)
}

type Publisher struct {
	root string
	mu   sync.Mutex
	io   publicationIO
}

func NewPublisher(root string) (*Publisher, error) {
	return newPublisherWithIO(root, systemPublicationIO{})
}

func newPublisherWithIO(root string, operations publicationIO) (*Publisher, error) {
	if operations == nil {
		return nil, invalid("publication I/O is required")
	}
	if !safeRoot(root) {
		return nil, invalid("publisher root must be a clean absolute non-root path")
	}
	if info, err := os.Lstat(root); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, invalid("publisher root must not be a symlink")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect HTTP policy root: %w", err)
	}
	resolvedParent, err := filepath.EvalSymlinks(filepath.Dir(root))
	if err != nil {
		return nil, invalid("publisher root parent must exist and be resolvable")
	}
	root = filepath.Join(resolvedParent, filepath.Base(root))
	if info, err := os.Lstat(root); err == nil {
		if err := validatePrivateDirectoryInfo(info); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect HTTP policy root: %w", err)
	}
	return &Publisher{root: root, io: operations}, nil
}

func (publisher *Publisher) PublishJSON(raw []byte) (Publication, error) {
	artifact, err := CompileJSON(raw)
	if err != nil {
		return Publication{}, err
	}
	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	if err := os.Mkdir(publisher.root, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return Publication{}, fmt.Errorf("create HTTP policy root: %w", err)
	}
	if err := requirePrivateDirectory(publisher.root); err != nil {
		return Publication{}, err
	}
	unlock, err := publisher.lock()
	if err != nil {
		return Publication{}, err
	}
	defer unlock()
	versions := filepath.Join(publisher.root, "versions")
	if err := os.Mkdir(versions, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return Publication{}, fmt.Errorf("create HTTP policy versions: %w", err)
	}
	if err := requirePrivateDirectory(versions); err != nil {
		return Publication{}, err
	}
	if err := validateVersionDirectory(versions); err != nil {
		return Publication{}, err
	}

	committed, exists, err := publisher.readCommitted()
	if err != nil {
		return Publication{}, err
	}
	commitPath := filepath.Join(publisher.root, commitFilename)
	versionPath := filepath.Join(versions, versionFilename(artifact.PolicyVersion))
	if exists {
		if artifact.PolicyVersion < committed.PolicyVersion {
			return Publication{}, invalid("policy_version %d is older than committed version %d", artifact.PolicyVersion, committed.PolicyVersion)
		}
		if artifact.PolicyVersion == committed.PolicyVersion {
			if artifact.Digest != committed.Digest || !bytes.Equal(artifact.Canonical, committed.Canonical) {
				return Publication{}, invalid("policy_version %d already has different committed content", artifact.PolicyVersion)
			}
			durable := publisher.syncDirectory(publisher.root) == nil
			return Publication{
				PolicyVersion: artifact.PolicyVersion, Digest: artifact.Digest,
				CommitPath: commitPath, VersionPath: versionPath,
				DurabilityConfirmed: durable,
			}, nil
		}
	}
	if err := publisher.ensureVersion(versionPath, artifact); err != nil {
		return Publication{}, err
	}
	manifest, err := marshalCommit(artifact)
	if err != nil {
		return Publication{}, err
	}
	durable, err := publisher.commit(manifest)
	if err != nil {
		return Publication{}, err
	}
	return Publication{
		PolicyVersion: artifact.PolicyVersion, Digest: artifact.Digest,
		CommitPath: commitPath, VersionPath: versionPath,
		Changed: true, DurabilityConfirmed: durable,
	}, nil
}

func (publisher *Publisher) lock() (func(), error) {
	path := filepath.Join(publisher.root, ".publish.lock")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open HTTP policy publication lock: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("inspect HTTP policy publication lock: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	pathInfo, pathErr := os.Lstat(path)
	if !ok || pathErr != nil || !os.SameFile(info, pathInfo) || !info.Mode().IsRegular() ||
		info.Mode().Perm() != 0o600 || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) {
		_ = file.Close()
		return nil, invalid("publication lock must be an owned, single-linked 0600 regular file")
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock HTTP policy publication: %w", err)
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}, nil
}

func (publisher *Publisher) readCommitted() (Artifact, bool, error) {
	content, err := readPrivateRegular(filepath.Join(publisher.root, commitFilename), maxCommitBytes)
	if errors.Is(err, os.ErrNotExist) {
		return Artifact{}, false, nil
	}
	if err != nil {
		return Artifact{}, false, err
	}
	if err := rejectDuplicateJSONKeys(content); err != nil {
		return Artifact{}, false, err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var manifest commitManifest
	if err := decoder.Decode(&manifest); err != nil {
		return Artifact{}, false, invalid("decode committed manifest: %v", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return Artifact{}, false, err
	}
	if err := validateCommit(manifest); err != nil {
		return Artifact{}, false, err
	}
	artifactPath := filepath.Join(publisher.root, filepath.FromSlash(manifest.Artifact))
	policy, err := readPrivateRegular(artifactPath, MaxPolicyBytes)
	if err != nil {
		return Artifact{}, false, fmt.Errorf("read committed HTTP policy artifact: %w", err)
	}
	artifact, err := CompileJSON(policy)
	if err != nil {
		return Artifact{}, false, err
	}
	if !bytes.Equal(policy, artifact.Canonical) || artifact.PolicyVersion != manifest.PolicyVersion ||
		hex.EncodeToString(artifact.Digest[:]) != manifest.SHA256 {
		return Artifact{}, false, invalid("committed manifest does not match its immutable artifact")
	}
	return artifact, true, nil
}

func marshalCommit(artifact Artifact) ([]byte, error) {
	manifest := commitManifest{
		SchemaVersion: commitSchemaVersion,
		PolicyVersion: artifact.PolicyVersion,
		SHA256:        hex.EncodeToString(artifact.Digest[:]),
		Artifact:      "versions/" + versionFilename(artifact.PolicyVersion),
	}
	content, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("marshal HTTP policy commit: %w", err)
	}
	return append(content, '\n'), nil
}

func validateCommit(manifest commitManifest) error {
	expectedArtifact := "versions/" + versionFilename(manifest.PolicyVersion)
	if manifest.SchemaVersion != commitSchemaVersion || manifest.PolicyVersion == 0 ||
		manifest.PolicyVersion > MaxPolicyVersion || manifest.Artifact != expectedArtifact ||
		len(manifest.SHA256) != 64 || strings.ToLower(manifest.SHA256) != manifest.SHA256 {
		return invalid("committed manifest is invalid")
	}
	digest, err := hex.DecodeString(manifest.SHA256)
	if err != nil || len(digest) != 32 {
		return invalid("committed manifest digest is invalid")
	}
	return nil
}

func validateVersionDirectory(directory string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return fmt.Errorf("read HTTP policy versions: %w", err)
	}
	if len(entries) > maxVersionFiles {
		return invalid("HTTP policy version directory exceeds %d entries", maxVersionFiles)
	}
	for _, entry := range entries {
		version, ok := parseVersionFilename(entry.Name())
		if !ok {
			return invalid("unknown HTTP policy version entry %q", entry.Name())
		}
		content, err := readPrivateRegular(filepath.Join(directory, entry.Name()), MaxPolicyBytes)
		if err != nil {
			return err
		}
		artifact, err := CompileJSON(content)
		if err != nil || artifact.PolicyVersion != version || !bytes.Equal(content, artifact.Canonical) {
			return invalid("HTTP policy version entry %q is not canonical", entry.Name())
		}
	}
	return nil
}

func parseVersionFilename(name string) (uint64, bool) {
	if len(name) != 25 || !strings.HasSuffix(name, ".json") {
		return 0, false
	}
	digits := strings.TrimSuffix(name, ".json")
	for index := range digits {
		if digits[index] < '0' || digits[index] > '9' {
			return 0, false
		}
	}
	version, err := strconv.ParseUint(digits, 10, 64)
	return version, err == nil && version > 0 && version <= MaxPolicyVersion && versionFilename(version) == name
}

func versionFilename(version uint64) string { return fmt.Sprintf("%020d.json", version) }

func (publisher *Publisher) ensureVersion(path string, artifact Artifact) error {
	existing, err := readPrivateRegular(path, MaxPolicyBytes)
	if err == nil {
		if !bytes.Equal(existing, artifact.Canonical) {
			return invalid("policy_version %d already has different immutable content", artifact.PolicyVersion)
		}
		return publisher.syncDirectory(filepath.Dir(path))
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return publisher.writeImmutable(path, artifact.Canonical)
}

func safeRoot(root string) bool {
	return filepath.IsAbs(root) && filepath.Clean(root) == root && root != string(filepath.Separator) &&
		!strings.ContainsAny(root, "\x00\r\n")
}

func validatePrivateDirectoryInfo(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 ||
		stat.Uid != uint32(os.Geteuid()) {
		return invalid("HTTP policy directory must be owned, real, and mode 0700")
	}
	return nil
}

func requirePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	return validatePrivateDirectoryInfo(info)
}

func readPrivateRegular(path string, maximum int64) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Nlink != 1 ||
		stat.Uid != uint32(os.Geteuid()) {
		return nil, invalid("HTTP policy file must be owned, private, regular, and single-linked")
	}
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if len(content) == 0 || int64(len(content)) > maximum {
		return nil, invalid("HTTP policy file size is invalid")
	}
	return content, nil
}

func (publisher *Publisher) writeImmutable(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	if err := publisher.writeAll(file, content); err != nil {
		return err
	}
	if err := publisher.io.Sync(file); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := publisher.syncDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	remove = false
	return nil
}

func (publisher *Publisher) commit(content []byte) (bool, error) {
	temporary, err := os.CreateTemp(publisher.root, ".http-policy-commit-*.json")
	if err != nil {
		return false, err
	}
	temporaryPath := temporary.Name()
	renamed := false
	defer func() {
		_ = temporary.Close()
		if !renamed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return false, err
	}
	if err := publisher.writeAll(temporary, content); err != nil {
		return false, err
	}
	if err := publisher.io.Sync(temporary); err != nil {
		return false, err
	}
	if err := temporary.Close(); err != nil {
		return false, err
	}
	if err := publisher.io.Rename(temporaryPath, filepath.Join(publisher.root, commitFilename)); err != nil {
		return false, err
	}
	renamed = true
	if err := publisher.syncDirectory(publisher.root); err != nil {
		return false, nil
	}
	return true, nil
}

func (publisher *Publisher) writeAll(file *os.File, content []byte) error {
	for len(content) > 0 {
		written, err := publisher.io.Write(file, content)
		if written < 0 || written > len(content) {
			return io.ErrShortWrite
		}
		content = content[written:]
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func (publisher *Publisher) syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := publisher.io.Sync(directory); err != nil && !errors.Is(err, os.ErrInvalid) {
		return err
	}
	return nil
}
