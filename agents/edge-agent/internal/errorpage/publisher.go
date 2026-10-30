package errorpage

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const rollbackTimeout = 10 * time.Second

type Runtime interface {
	Precheck(context.Context, string) error
	Activate(context.Context, string) error
	Health(context.Context, string, Artifact) error
	Stop(context.Context) error
}

type Publisher struct {
	stateRoot    string
	resourceRoot string
	runtime      Runtime
	mu           sync.Mutex
}

type publisherState struct {
	root        *os.File
	versions    *os.File
	staging     *os.File
	lock        *os.File
	runtimeRoot string
}

func (state *publisherState) close() {
	for _, file := range []*os.File{state.staging, state.versions, state.lock, state.root} {
		if file != nil {
			_ = file.Close()
		}
	}
}

type ApplyResult struct {
	Version          string
	Revision         uint64
	Digest           string
	PreviousRevision uint64
	PreviousDigest   string
	Changed          bool
}

type releaseManifest struct {
	Schema        string `json:"schema"`
	Version       string `json:"version"`
	Revision      uint64 `json:"revision"`
	Digest        string `json:"digest"`
	RuntimeSHA256 string `json:"runtime_sha256"`
}

func NewPublisher(stateRoot, resourceRoot string, runtime Runtime) (*Publisher, error) {
	if runtime == nil || !cleanAbsolutePath(stateRoot) || (resourceRoot != "" && !cleanAbsolutePath(resourceRoot)) {
		return nil, invalidPolicy("publisher paths or runtime are invalid")
	}
	return &Publisher{stateRoot: stateRoot, resourceRoot: resourceRoot, runtime: runtime}, nil
}

func (publisher *Publisher) Apply(ctx context.Context, policy Policy) (ApplyResult, error) {
	publisher.mu.Lock()
	defer publisher.mu.Unlock()

	artifact, err := Compile(policy, publisher.resourceRoot)
	if err != nil {
		return ApplyResult{}, err
	}
	state, err := publisher.openState()
	if err != nil {
		return ApplyResult{}, err
	}
	defer state.close()
	previousTarget, previous, found, err := publisher.readPointer(state, "current")
	if err != nil {
		return ApplyResult{}, err
	}
	if found {
		if artifact.Revision < previous.Revision || (artifact.Revision == previous.Revision && artifact.Digest != previous.Digest) {
			return ApplyResult{}, ErrRevision
		}
		if artifact.Revision == previous.Revision && artifact.Digest == previous.Digest {
			return applyResult(artifact, previous, false), nil
		}
	}

	release, err := publisher.writeRelease(state, artifact)
	if err != nil {
		return ApplyResult{}, err
	}
	if err := publisher.runtime.Precheck(ctx, release); err != nil {
		return ApplyResult{}, fmt.Errorf("%w: %v", ErrPrecheck, err)
	}
	if err := publisher.setPointer(state, "current", filepath.ToSlash(filepath.Join("versions", artifact.Digest))); err != nil {
		return ApplyResult{}, err
	}
	if err := publisher.runtime.Activate(ctx, release); err != nil {
		activateErr := fmt.Errorf("%w: %v", ErrActivate, err)
		if rollbackErr := publisher.rollback(state, previousTarget, previous, found); rollbackErr != nil {
			return ApplyResult{}, fmt.Errorf("%w: activation=%v rollback=%v", ErrRollback, activateErr, rollbackErr)
		}
		return ApplyResult{}, activateErr
	}
	if err := publisher.runtime.Health(ctx, release, artifact); err != nil {
		healthErr := fmt.Errorf("%w: %v", ErrHealth, err)
		if rollbackErr := publisher.rollback(state, previousTarget, previous, found); rollbackErr != nil {
			return ApplyResult{}, fmt.Errorf("%w: health=%v rollback=%v", ErrRollback, healthErr, rollbackErr)
		}
		return ApplyResult{}, healthErr
	}
	if err := publisher.setPointer(state, "lkg", filepath.ToSlash(filepath.Join("versions", artifact.Digest))); err != nil {
		if rollbackErr := publisher.rollback(state, previousTarget, previous, found); rollbackErr != nil {
			return ApplyResult{}, fmt.Errorf("%w: lkg=%v rollback=%v", ErrRollback, err, rollbackErr)
		}
		return ApplyResult{}, err
	}
	return applyResult(artifact, previous, true), nil
}

func (publisher *Publisher) Current() (ApplyResult, bool, error) {
	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	state, err := publisher.openState()
	if err != nil {
		return ApplyResult{}, false, err
	}
	defer state.close()
	_, manifest, found, err := publisher.readPointer(state, "current")
	if err != nil || !found {
		return ApplyResult{}, found, err
	}
	return ApplyResult{Version: manifest.Version, Revision: manifest.Revision, Digest: manifest.Digest}, true, nil
}

func (publisher *Publisher) LKG() (ApplyResult, bool, error) {
	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	state, err := publisher.openState()
	if err != nil {
		return ApplyResult{}, false, err
	}
	defer state.close()
	_, manifest, found, err := publisher.readPointer(state, "lkg")
	if err != nil || !found {
		return ApplyResult{}, found, err
	}
	return ApplyResult{Version: manifest.Version, Revision: manifest.Revision, Digest: manifest.Digest}, true, nil
}

func (publisher *Publisher) rollback(state *publisherState, previousTarget string, previous releaseManifest, found bool) error {
	rollbackCtx, cancel := context.WithTimeout(context.Background(), rollbackTimeout)
	defer cancel()
	if !found {
		if err := publisher.removePointer(state, "current"); err != nil {
			return err
		}
		return publisher.runtime.Stop(rollbackCtx)
	}
	release, manifest, err := publisher.validateRelease(state, previousTarget)
	if err != nil {
		return err
	}
	if manifest != previous {
		return fmt.Errorf("previous release changed during activation")
	}
	if err := publisher.setPointer(state, "current", previousTarget); err != nil {
		return err
	}
	artifact := Artifact{
		Version: manifest.Version, Revision: manifest.Revision,
		Digest: manifest.Digest, RuntimeSHA256: manifest.RuntimeSHA256,
	}
	if err := publisher.runtime.Activate(rollbackCtx, release); err != nil {
		return err
	}
	return publisher.runtime.Health(rollbackCtx, release, artifact)
}

func (publisher *Publisher) openState() (*publisherState, error) {
	root, err := openOwnedDirectoryPath(publisher.stateRoot, 0o700)
	if err != nil {
		return nil, err
	}
	state := &publisherState{root: root}
	fail := func(err error) (*publisherState, error) {
		state.close()
		return nil, err
	}
	state.lock, err = lockPublisher(root)
	if err != nil {
		return fail(err)
	}
	state.versions, err = openOwnedDirectoryAt(root, "versions", 0o700, true)
	if err != nil {
		return fail(err)
	}
	state.staging, err = openOwnedDirectoryAt(root, "staging", 0o700, true)
	if err != nil {
		return fail(err)
	}
	state.runtimeRoot, err = descriptorDirectoryPath(root)
	if err != nil {
		return fail(err)
	}
	return state, nil
}

func (publisher *Publisher) writeRelease(state *publisherState, artifact Artifact) (string, error) {
	target := filepath.ToSlash(filepath.Join("versions", artifact.Digest))
	var stat unix.Stat_t
	if err := unix.Fstatat(int(state.versions.Fd()), artifact.Digest, &stat, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		release, manifest, validateErr := publisher.validateRelease(state, target)
		if validateErr != nil {
			return "", validateErr
		}
		if manifest.Version != artifact.Version || manifest.Revision != artifact.Revision || manifest.Digest != artifact.Digest || manifest.RuntimeSHA256 != artifact.RuntimeSHA256 {
			return "", fmt.Errorf("existing release does not match artifact")
		}
		return release, nil
	} else if !errors.Is(err, unix.ENOENT) {
		return "", err
	}

	suffix, err := randomSuffix()
	if err != nil {
		return "", err
	}
	stagingName := artifact.Digest + "-" + suffix
	if err := unix.Mkdirat(int(state.staging.Fd()), stagingName, 0o700); err != nil {
		return "", err
	}
	staging, err := openOwnedDirectoryAt(state.staging, stagingName, 0o700, false)
	if err != nil {
		_ = unix.Unlinkat(int(state.staging.Fd()), stagingName, unix.AT_REMOVEDIR)
		return "", err
	}
	cleanupParent := state.staging
	cleanupName := stagingName
	removeRelease := true
	defer func() {
		if removeRelease {
			removeReleaseDirectory(cleanupParent, cleanupName, staging)
		}
		_ = staging.Close()
	}()
	manifest := releaseManifest{
		Schema: SchemaV1, Version: artifact.Version, Revision: artifact.Revision,
		Digest: artifact.Digest, RuntimeSHA256: artifact.RuntimeSHA256,
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return "", err
	}
	for name, content := range map[string][]byte{
		"manifest.json": manifestJSON, "policy.json": artifact.CanonicalJSON, "policy.lua": artifact.RuntimeLua,
	} {
		if err := writeImmutableAt(staging, name, content); err != nil {
			return "", err
		}
	}
	if err := syncDirectory(staging); err != nil {
		return "", err
	}
	if err := unix.Renameat(int(state.staging.Fd()), stagingName, int(state.versions.Fd()), artifact.Digest); err != nil {
		return "", err
	}
	cleanupParent = state.versions
	cleanupName = artifact.Digest
	if err := unix.Fchmod(int(staging.Fd()), 0o500); err != nil {
		return "", err
	}
	if err := syncDirectory(staging); err != nil {
		return "", err
	}
	if err := syncDirectory(state.versions); err != nil {
		return "", err
	}
	release, validated, err := publisher.validateRelease(state, target)
	if err != nil {
		return "", err
	}
	if validated != manifest {
		return "", fmt.Errorf("release manifest changed after publication")
	}
	removeRelease = false
	return release, nil
}

func (publisher *Publisher) readPointer(state *publisherState, name string) (string, releaseManifest, bool, error) {
	var stat unix.Stat_t
	if err := unix.Fstatat(int(state.root.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return "", releaseManifest{}, false, nil
	} else if err != nil {
		return "", releaseManifest{}, false, err
	}
	if uint32(stat.Mode)&uint32(unix.S_IFMT) != uint32(unix.S_IFLNK) {
		return "", releaseManifest{}, false, fmt.Errorf("%s pointer is not a symlink", name)
	}
	buffer := make([]byte, 4096)
	length, err := unix.Readlinkat(int(state.root.Fd()), name, buffer)
	if err != nil {
		return "", releaseManifest{}, false, err
	}
	target := string(buffer[:length])
	if !validPointerTarget(target) {
		return "", releaseManifest{}, false, fmt.Errorf("%s pointer target is invalid", name)
	}
	_, manifest, err := publisher.validateRelease(state, target)
	return target, manifest, err == nil, err
}

func (publisher *Publisher) validateRelease(state *publisherState, target string) (string, releaseManifest, error) {
	if !validPointerTarget(target) {
		return "", releaseManifest{}, fmt.Errorf("release target is invalid")
	}
	digest := strings.TrimPrefix(target, "versions/")
	release, err := openOwnedDirectoryAt(state.versions, digest, 0o500, false)
	if err != nil {
		return "", releaseManifest{}, err
	}
	defer release.Close()
	entries, err := release.ReadDir(-1)
	if err != nil {
		return "", releaseManifest{}, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	if strings.Join(names, ",") != "manifest.json,policy.json,policy.lua" {
		return "", releaseManifest{}, fmt.Errorf("release file set is invalid")
	}
	manifestJSON, err := readImmutableAt(release, "manifest.json")
	if err != nil {
		return "", releaseManifest{}, err
	}
	var manifest releaseManifest
	if err := json.Unmarshal(manifestJSON, &manifest); err != nil || manifest.Schema != SchemaV1 || !validDigest(manifest.Digest) || !validDigest(manifest.RuntimeSHA256) {
		return "", releaseManifest{}, fmt.Errorf("release manifest is invalid")
	}
	reencoded, err := json.Marshal(manifest)
	if err != nil || string(reencoded) != string(manifestJSON) || digest != manifest.Digest {
		return "", releaseManifest{}, fmt.Errorf("release manifest is not canonical")
	}
	policyJSON, err := readImmutableAt(release, "policy.json")
	if err != nil {
		return "", releaseManifest{}, err
	}
	policyDigest := sha256.Sum256(policyJSON)
	if hex.EncodeToString(policyDigest[:]) != manifest.Digest {
		return "", releaseManifest{}, fmt.Errorf("release policy digest mismatch")
	}
	runtimeLua, err := readImmutableAt(release, "policy.lua")
	if err != nil {
		return "", releaseManifest{}, err
	}
	runtimeDigest := sha256.Sum256(runtimeLua)
	if hex.EncodeToString(runtimeDigest[:]) != manifest.RuntimeSHA256 {
		return "", releaseManifest{}, fmt.Errorf("release runtime digest mismatch")
	}
	return filepath.Join(state.runtimeRoot, filepath.FromSlash(target)), manifest, nil
}

func (publisher *Publisher) setPointer(state *publisherState, name, target string) error {
	if !validPointerTarget(target) {
		return fmt.Errorf("pointer target is invalid")
	}
	suffix, err := randomSuffix()
	if err != nil {
		return err
	}
	temporary := "." + name + "-" + suffix
	if err := unix.Symlinkat(target, int(state.root.Fd()), temporary); err != nil {
		return err
	}
	defer unix.Unlinkat(int(state.root.Fd()), temporary, 0)
	if err := unix.Renameat(int(state.root.Fd()), temporary, int(state.root.Fd()), name); err != nil {
		return err
	}
	return syncDirectory(state.root)
}

func (publisher *Publisher) removePointer(state *publisherState, name string) error {
	var stat unix.Stat_t
	if err := unix.Fstatat(int(state.root.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil || uint32(stat.Mode)&uint32(unix.S_IFMT) != uint32(unix.S_IFLNK) {
		return fmt.Errorf("pointer cannot be removed safely")
	}
	if err := unix.Unlinkat(int(state.root.Fd()), name, 0); err != nil {
		return err
	}
	return syncDirectory(state.root)
}

func openOwnedDirectoryPath(path string, mode os.FileMode) (*os.File, error) {
	parent, err := openDirectoryPathNoSymlink(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	return openOwnedDirectoryAt(parent, filepath.Base(path), mode, true)
}

func openDirectoryPathNoSymlink(path string) (*os.File, error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(fd), "/")
	for _, part := range strings.Split(strings.TrimPrefix(filepath.ToSlash(path), "/"), "/") {
		if part == "" {
			continue
		}
		nextFD, openErr := unix.Openat(int(directory.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if openErr != nil {
			_ = directory.Close()
			return nil, openErr
		}
		next := os.NewFile(uintptr(nextFD), part)
		_ = directory.Close()
		directory = next
	}
	return directory, nil
}

func openOwnedDirectoryAt(parent *os.File, name string, mode os.FileMode, create bool) (*os.File, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) && create {
		if mkdirErr := unix.Mkdirat(int(parent.Fd()), name, uint32(mode.Perm())); mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
			return nil, mkdirErr
		}
		fd, err = unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	}
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(fd), name)
	if directory == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("invalid directory file descriptor")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || uint32(stat.Mode)&uint32(unix.S_IFMT) != uint32(unix.S_IFDIR) || os.FileMode(stat.Mode)&os.ModePerm != mode || stat.Uid != uint32(os.Geteuid()) {
		_ = directory.Close()
		return nil, fmt.Errorf("directory owner or mode mismatch")
	}
	return directory, nil
}

func lockPublisher(root *os.File) (*os.File, error) {
	fd, err := unix.Openat(int(root.Fd()), ".publish.lock", unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	lock := os.NewFile(uintptr(fd), ".publish.lock")
	if lock == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("invalid publication lock file descriptor")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || uint32(stat.Mode)&uint32(unix.S_IFMT) != uint32(unix.S_IFREG) || os.FileMode(stat.Mode)&os.ModePerm != 0o600 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		_ = lock.Close()
		return nil, fmt.Errorf("publication lock owner, mode, or link count is invalid")
	}
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		_ = lock.Close()
		return nil, err
	}
	return lock, nil
}

func descriptorDirectoryPath(directory *os.File) (string, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(int(directory.Fd()), &stat); err != nil {
		return "", err
	}
	var path string
	switch runtime.GOOS {
	case "linux":
		path = fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), directory.Fd())
	case "darwin":
		path = fmt.Sprintf("/.vol/%d/%d", uint64(stat.Dev), uint64(stat.Ino))
	default:
		return "", fmt.Errorf("descriptor paths are unsupported")
	}
	var resolved unix.Stat_t
	if err := unix.Stat(path, &resolved); err != nil || stat.Dev != resolved.Dev || stat.Ino != resolved.Ino {
		return "", fmt.Errorf("descriptor directory identity mismatch")
	}
	return path, nil
}

func writeImmutableAt(directory *os.File, name string, content []byte) error {
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o400)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), name)
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = unix.Unlinkat(int(directory.Fd()), name, 0)
		}
	}()
	if _, err := file.Write(content); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if _, err := readImmutableAt(directory, name); err != nil {
		return err
	}
	remove = false
	return nil
}

func readImmutableAt(directory *os.File, name string) ([]byte, error) {
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	if uint32(stat.Mode)&uint32(unix.S_IFMT) != uint32(unix.S_IFREG) || os.FileMode(stat.Mode)&os.ModePerm != 0o400 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || stat.Size < 1 || stat.Size > 16<<20 {
		return nil, fmt.Errorf("release file owner, mode, link count, or size is invalid")
	}
	content := make([]byte, stat.Size)
	if _, err := file.ReadAt(content, 0); err != nil {
		return nil, err
	}
	return content, nil
}

func removeReleaseDirectory(parent *os.File, name string, directory *os.File) {
	_ = unix.Fchmod(int(directory.Fd()), 0o700)
	for _, file := range []string{"manifest.json", "policy.json", "policy.lua"} {
		_ = unix.Unlinkat(int(directory.Fd()), file, 0)
	}
	_ = unix.Unlinkat(int(parent.Fd()), name, unix.AT_REMOVEDIR)
	_ = syncDirectory(parent)
}

func validPointerTarget(target string) bool {
	if !strings.HasPrefix(target, "versions/") || filepath.IsAbs(target) || filepath.ToSlash(filepath.Clean(target)) != target {
		return false
	}
	digest := strings.TrimPrefix(target, "versions/")
	return !strings.Contains(digest, "/") && validDigest(digest)
}

func cleanAbsolutePath(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n") {
		return false
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return false
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return false
		}
		parent := filepath.Dir(current)
		if parent == current {
			return true
		}
	}
}

func randomSuffix() (string, error) {
	value := make([]byte, 8)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func syncDirectory(directory *os.File) error {
	if err := directory.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return err
	}
	return nil
}

func applyResult(artifact Artifact, previous releaseManifest, changed bool) ApplyResult {
	return ApplyResult{
		Version: artifact.Version, Revision: artifact.Revision, Digest: artifact.Digest,
		PreviousRevision: previous.Revision, PreviousDigest: previous.Digest, Changed: changed,
	}
}
