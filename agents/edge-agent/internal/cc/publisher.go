package cc

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

type Publication struct {
	PolicyVersion uint64
	SHA256        [sha256.Size]byte
	CurrentPath   string
}

type Publisher struct {
	root string
	mu   sync.Mutex
}

func NewPublisher(root string) (*Publisher, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == string(filepath.Separator) {
		return nil, invalid("publisher root must be a clean absolute non-root path")
	}
	if err := rejectSymlinkAncestors(root); err != nil {
		return nil, err
	}
	return &Publisher{root: root}, nil
}

func (publisher *Publisher) PublishJSON(raw []byte) (Publication, error) {
	canonical, policy, err := CompileJSON(raw)
	if err != nil {
		return Publication{}, err
	}
	publisher.mu.Lock()
	defer publisher.mu.Unlock()

	rootDirectory, err := openPublisherRoot(publisher.root)
	if err != nil {
		return Publication{}, err
	}
	defer rootDirectory.Close()
	lock, err := publisher.lock(rootDirectory)
	if err != nil {
		return Publication{}, err
	}
	defer lock.Close()
	versionsDirectory, err := openPrivateDirectoryAt(rootDirectory, "versions")
	if err != nil {
		return Publication{}, err
	}
	defer versionsDirectory.Close()
	latest, err := latestVersion(versionsDirectory)
	if err != nil {
		return Publication{}, err
	}
	versionName := versionFilename(policy.PolicyVersion)
	if policy.PolicyVersion < latest {
		return Publication{}, invalid("policy_version %d is older than published version %d", policy.PolicyVersion, latest)
	}
	if policy.PolicyVersion == latest && latest != 0 {
		existing, err := readPrivateRegularAt(versionsDirectory, versionName)
		if err != nil {
			return Publication{}, fmt.Errorf("read existing CC policy version: %w", err)
		}
		if !bytes.Equal(existing, canonical) {
			return Publication{}, invalid("policy_version %d already has different content", policy.PolicyVersion)
		}
	}
	const currentName = "current.json"
	const fallbackName = "fallback.json"
	currentCanonical, currentPolicy, currentErr := readValidatedPublication(rootDirectory, currentName, versionsDirectory)
	if currentErr == nil {
		if currentPolicy.PolicyVersion > policy.PolicyVersion {
			return Publication{}, invalid("policy_version %d is older than current version %d", policy.PolicyVersion, currentPolicy.PolicyVersion)
		}
		if currentPolicy.PolicyVersion == policy.PolicyVersion && !bytes.Equal(currentCanonical, canonical) {
			return Publication{}, invalid("policy_version %d already has different current content", policy.PolicyVersion)
		}
		if err := writeAtomic(rootDirectory, fallbackName, currentCanonical); err != nil {
			return Publication{}, err
		}
	} else if latest != 0 {
		_, _, fallbackErr := readValidatedPublication(rootDirectory, fallbackName, versionsDirectory)
		initialRetry := pathMissing(rootDirectory, currentName) && pathMissing(rootDirectory, fallbackName) && policy.PolicyVersion == latest
		canRecoverPoisonedLatest := false
		if fallbackErr == nil && policy.PolicyVersion > latest {
			highest, highestErr := readPrivateRegularAt(versionsDirectory, versionFilename(latest))
			var highestPolicy *CompiledPolicy
			if highestErr == nil {
				var highestCanonical []byte
				highestCanonical, highestPolicy, highestErr = CompileJSON(highest)
				if highestErr == nil && !bytes.Equal(highest, highestCanonical) {
					highestErr = invalid("current CC policy version is invalid")
				}
			}
			canRecoverPoisonedLatest = highestErr != nil || highestPolicy.PolicyVersion != latest
		}
		if policy.PolicyVersion != latest && !canRecoverPoisonedLatest || fallbackErr != nil && !initialRetry {
			return Publication{}, invalid("current CC policy is invalid")
		}
	} else if !pathMissing(rootDirectory, currentName) {
		return Publication{}, invalid("current CC policy is invalid")
	}
	if policy.PolicyVersion > latest {
		if err := writeImmutable(versionsDirectory, versionName, canonical); err != nil {
			return Publication{}, err
		}
	}
	if latest == 0 || currentErr != nil && pathMissing(rootDirectory, fallbackName) {
		if err := writeAtomic(rootDirectory, fallbackName, canonical); err != nil {
			return Publication{}, err
		}
	}
	if err := writeAtomic(rootDirectory, currentName, canonical); err != nil {
		return Publication{}, err
	}
	currentPath := filepath.Join(publisher.root, currentName)
	return Publication{PolicyVersion: policy.PolicyVersion, SHA256: sha256.Sum256(canonical), CurrentPath: currentPath}, nil
}

func rejectSymlinkAncestors(path string) error {
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return invalid("publisher root must not have symlink ancestors")
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect CC policy root: %w", err)
		}
		if parent := filepath.Dir(current); parent == current {
			return nil
		}
	}
}

func openPublisherRoot(path string) (*os.File, error) {
	directory, err := openDirectoryPath(path, true)
	if err != nil {
		return nil, err
	}
	if err := requirePrivateDirectory(directory); err != nil {
		_ = directory.Close()
		return nil, err
	}
	return directory, nil
}

func openDirectoryPath(path string, create bool) (*os.File, error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open CC policy filesystem root: %w", err)
	}
	directory := os.NewFile(uintptr(fd), "/")
	if directory == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open CC policy filesystem root: invalid file descriptor")
	}
	for _, component := range strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		nextFD, openErr := unix.Openat(int(directory.Fd()), component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if errors.Is(openErr, unix.ENOENT) && create {
			if mkdirErr := unix.Mkdirat(int(directory.Fd()), component, 0o700); mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				_ = directory.Close()
				return nil, fmt.Errorf("create CC policy directory %q: %w", component, mkdirErr)
			}
			nextFD, openErr = unix.Openat(int(directory.Fd()), component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		}
		if openErr != nil {
			_ = directory.Close()
			if errors.Is(openErr, unix.ELOOP) || errors.Is(openErr, unix.ENOTDIR) {
				return nil, invalid("publisher root must not have symlink ancestors")
			}
			return nil, fmt.Errorf("open CC policy directory %q: %w", component, openErr)
		}
		next := os.NewFile(uintptr(nextFD), component)
		if next == nil {
			_ = unix.Close(nextFD)
			_ = directory.Close()
			return nil, errors.New("open CC policy directory: invalid file descriptor")
		}
		_ = directory.Close()
		directory = next
	}
	return directory, nil
}

func openPrivateDirectoryAt(parent *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		if mkdirErr := unix.Mkdirat(int(parent.Fd()), name, 0o700); mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
			return nil, fmt.Errorf("create CC policy directory %q: %w", name, mkdirErr)
		}
		fd, err = unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	}
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
			return nil, invalid("CC policy directory must be private, real, and owner-only")
		}
		return nil, fmt.Errorf("open CC policy directory %q: %w", name, err)
	}
	directory := os.NewFile(uintptr(fd), name)
	if directory == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open CC policy directory: invalid file descriptor")
	}
	if err := requirePrivateDirectory(directory); err != nil {
		_ = directory.Close()
		return nil, err
	}
	return directory, nil
}

func (publisher *Publisher) lock(root *os.File) (*os.File, error) {
	fd, err := unix.Openat(int(root.Fd()), ".publish.lock", unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	// macOS (APFS) can fail a concurrent O_CREAT of the same new name with
	// ENOENT while the root and the lock file both exist; the open is
	// idempotent, so retry a few times. Linux never takes this branch.
	for attempt := 0; errors.Is(err, unix.ENOENT) && attempt < 8; attempt++ {
		fd, err = unix.Openat(int(root.Fd()), ".publish.lock", unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	}
	if err != nil {
		return nil, fmt.Errorf("open CC policy lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), ".publish.lock")
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open CC policy lock: invalid file descriptor")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		_ = file.Close()
		return nil, invalid("CC policy lock is not a private regular file")
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock CC policy publication: %w", err)
	}
	return file, nil
}

func versionFilename(version uint64) string {
	return fmt.Sprintf("%020d.json", version)
}

func latestVersion(directory *os.File) (uint64, error) {
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return 0, fmt.Errorf("read CC policy versions: %w", err)
	}
	var latest uint64
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		stem := strings.TrimSuffix(entry.Name(), ".json")
		if len(stem) != 20 {
			continue
		}
		version, err := strconv.ParseUint(stem, 10, 64)
		if err != nil {
			continue
		}
		var stat unix.Stat_t
		if err := unix.Fstatat(int(directory.Fd()), entry.Name(), &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return 0, fmt.Errorf("inspect CC policy version %q: %w", entry.Name(), err)
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o077 != 0 || stat.Nlink != 1 {
			return 0, invalid("CC policy version %q must be private, regular, and single-linked", entry.Name())
		}
		if version > latest {
			latest = version
		}
	}
	return latest, nil
}

func requirePrivateDirectory(directory *os.File) error {
	info, err := directory.Stat()
	if err != nil {
		return fmt.Errorf("inspect CC policy directory: %w", err)
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return invalid("CC policy directory must be private, real, and owner-only")
	}
	return nil
}

func readPrivateRegular(path string) ([]byte, error) {
	directory, err := openDirectoryPath(filepath.Dir(path), false)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	return readPrivateRegularAt(directory, filepath.Base(path))
}

func readPrivateRegularAt(directory *os.File, name string) ([]byte, error) {
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open CC policy version: invalid file descriptor")
	}
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o077 != 0 || stat.Nlink != 1 {
		return nil, invalid("CC policy version must be private, regular, and single-linked")
	}
	return io.ReadAll(io.LimitReader(file, MaxPolicyBytes+1))
}

func readValidatedPublication(root *os.File, name string, versionsDirectory *os.File) ([]byte, *CompiledPolicy, error) {
	raw, err := readPrivateRegularAt(root, name)
	if err != nil {
		return nil, nil, err
	}
	canonical, policy, err := CompileJSON(raw)
	if err != nil || !bytes.Equal(raw, canonical) {
		return nil, nil, invalid("current CC policy is invalid")
	}
	version, err := readPrivateRegularAt(versionsDirectory, versionFilename(policy.PolicyVersion))
	if err != nil || !bytes.Equal(version, canonical) {
		return nil, nil, invalid("current CC policy version is invalid")
	}
	return canonical, policy, nil
}

func pathMissing(directory *os.File, name string) bool {
	var stat unix.Stat_t
	err := unix.Fstatat(int(directory.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	return errors.Is(err, unix.ENOENT)
}

func writeImmutable(directory *os.File, name string, content []byte) error {
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("create immutable CC policy: %w", err)
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		_ = unix.Unlinkat(int(directory.Fd()), name, 0)
		return errors.New("create immutable CC policy: invalid file descriptor")
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = unix.Unlinkat(int(directory.Fd()), name, 0)
		}
	}()
	if _, err := file.Write(content); err != nil {
		return fmt.Errorf("write immutable CC policy: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync immutable CC policy: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close immutable CC policy: %w", err)
	}
	remove = false
	return syncDirectory(directory)
}

func writeAtomic(directory *os.File, name string, content []byte) error {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return fmt.Errorf("name temporary CC policy: %w", err)
	}
	temporaryName := fmt.Sprintf(".%s-%x.tmp", name, random)
	fd, err := unix.Openat(int(directory.Fd()), temporaryName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("create temporary CC policy: %w", err)
	}
	temporary := os.NewFile(uintptr(fd), temporaryName)
	if temporary == nil {
		_ = unix.Close(fd)
		_ = unix.Unlinkat(int(directory.Fd()), temporaryName, 0)
		return errors.New("create temporary CC policy: invalid file descriptor")
	}
	defer func() {
		_ = temporary.Close()
		_ = unix.Unlinkat(int(directory.Fd()), temporaryName, 0)
	}()
	if _, err := temporary.Write(content); err != nil {
		return fmt.Errorf("write temporary CC policy: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync temporary CC policy: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary CC policy: %w", err)
	}
	if err := unix.Renameat(int(directory.Fd()), temporaryName, int(directory.Fd()), name); err != nil {
		return fmt.Errorf("activate CC policy: %w", err)
	}
	return syncDirectory(directory)
}

func syncDirectory(directory *os.File) error {
	if err := directory.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return fmt.Errorf("sync CC policy directory: %w", err)
	}
	return nil
}
