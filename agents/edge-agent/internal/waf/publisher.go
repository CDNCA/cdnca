package waf

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
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
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, invalid("publisher root must be a clean absolute path")
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

	root, err := openPrivateRoot(publisher.root)
	if err != nil {
		return Publication{}, err
	}
	defer root.Close()
	lock, err := lockPublisherAt(root, "publish.lock")
	if err != nil {
		return Publication{}, err
	}
	defer lock.Close()

	versions, err := openPrivateDirectoryAt(root, "versions")
	if err != nil {
		return Publication{}, err
	}
	defer versions.Close()
	latest, err := latestVersion(versions)
	if err != nil {
		return Publication{}, err
	}
	versionName := versionFilename(policy.PolicyVersion)
	if policy.PolicyVersion < latest {
		return Publication{}, invalid("policy_version %d is older than published version %d", policy.PolicyVersion, latest)
	}
	if policy.PolicyVersion == latest && latest != 0 {
		existing, err := readPrivateRegularAt(versions, versionName)
		if err != nil {
			return Publication{}, fmt.Errorf("read existing WAF policy version: %w", err)
		}
		if !bytes.Equal(existing, canonical) {
			return Publication{}, invalid("policy_version %d already has different content", policy.PolicyVersion)
		}
	}

	currentName := "current.json"
	fallbackName := "fallback.json"
	currentCanonical, currentPolicy, currentErr := readValidatedPublicationAt(root, currentName, versions)
	if currentErr == nil {
		if currentPolicy.PolicyVersion > policy.PolicyVersion {
			return Publication{}, invalid("policy_version %d is older than current version %d", policy.PolicyVersion, currentPolicy.PolicyVersion)
		}
		if currentPolicy.PolicyVersion == policy.PolicyVersion && !bytes.Equal(currentCanonical, canonical) {
			return Publication{}, invalid("policy_version %d already has different current content", policy.PolicyVersion)
		}
		if err := writeAtomicAt(root, fallbackName, currentCanonical); err != nil {
			return Publication{}, err
		}
	} else if latest != 0 {
		_, _, fallbackErr := readValidatedPublicationAt(root, fallbackName, versions)
		initialRetry := pathMissingAt(root, currentName) && pathMissingAt(root, fallbackName) && policy.PolicyVersion == latest
		if fallbackErr != nil && !initialRetry {
			return Publication{}, invalid("current WAF policy is invalid")
		}
	} else if !pathMissingAt(root, currentName) {
		return Publication{}, invalid("current WAF policy is invalid")
	}
	if policy.PolicyVersion > latest {
		if err := writeImmutableAt(versions, versionName, canonical); err != nil {
			return Publication{}, err
		}
	}
	if latest == 0 || currentErr != nil && pathMissingAt(root, fallbackName) {
		if err := writeAtomicAt(root, fallbackName, canonical); err != nil {
			return Publication{}, err
		}
	}
	if err := writeAtomicAt(root, currentName, canonical); err != nil {
		return Publication{}, err
	}
	return Publication{PolicyVersion: policy.PolicyVersion, SHA256: sha256.Sum256(canonical), CurrentPath: filepath.Join(publisher.root, currentName)}, nil
}

func openPrivateRoot(path string) (*os.File, error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open WAF policy root ancestor: %w", err)
	}
	directory := os.NewFile(uintptr(fd), "/")
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" {
			continue
		}
		nextFD, openErr := unix.Openat(int(directory.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if errors.Is(openErr, unix.ENOENT) {
			if mkdirErr := unix.Mkdirat(int(directory.Fd()), part, 0o700); mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				_ = directory.Close()
				return nil, fmt.Errorf("create WAF policy root: %w", mkdirErr)
			}
			nextFD, openErr = unix.Openat(int(directory.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		}
		if openErr != nil {
			_ = directory.Close()
			return nil, fmt.Errorf("open WAF policy root: %w", openErr)
		}
		next := os.NewFile(uintptr(nextFD), part)
		_ = directory.Close()
		directory = next
	}
	if err := requirePrivateDirectory(directory); err != nil {
		_ = directory.Close()
		return nil, err
	}
	return directory, nil
}

func openPrivateDirectoryAt(parent *os.File, name string) (*os.File, error) {
	if err := unix.Mkdirat(int(parent.Fd()), name, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, fmt.Errorf("create WAF policy directories: %w", err)
	}
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open WAF policy directory: %w", err)
	}
	directory := os.NewFile(uintptr(fd), name)
	if err := requirePrivateDirectory(directory); err != nil {
		_ = directory.Close()
		return nil, err
	}
	return directory, nil
}

func lockPublisherAt(directory *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open WAF publisher lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open WAF publisher lock: invalid file descriptor")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		_ = file.Close()
		return nil, errors.New("open WAF publisher lock: lock file must be private and regular")
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock WAF publisher: %w", err)
	}
	return file, nil
}

func versionFilename(version uint64) string {
	return fmt.Sprintf("%020d.json", version)
}

func latestVersion(directory *os.File) (uint64, error) {
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return 0, fmt.Errorf("read WAF policy versions: %w", err)
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
		file, err := openPrivateRegularAt(directory, entry.Name())
		if err != nil {
			return 0, fmt.Errorf("inspect WAF policy version %q: %w", entry.Name(), err)
		}
		_ = file.Close()
		if version > latest {
			latest = version
		}
	}
	return latest, nil
}

func openPrivateRegularAt(directory *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || stat.Nlink != 1 {
		_ = file.Close()
		return nil, invalid("WAF policy must be private, regular, and single-linked")
	}
	return file, nil
}

func readPrivateRegularAt(directory *os.File, name string) ([]byte, error) {
	file, err := openPrivateRegularAt(directory, name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, MaxPolicyBytes+1))
}

func readValidatedPublicationAt(root *os.File, name string, versions *os.File) ([]byte, *CompiledPolicy, error) {
	raw, err := readPrivateRegularAt(root, name)
	if err != nil {
		return nil, nil, err
	}
	if len(raw) == 0 || len(raw) > MaxPolicyBytes || rejectInvalidJSONUnicode(raw) != nil || rejectDuplicateJSONKeys(raw) != nil {
		return nil, nil, invalid("current WAF policy is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var policy CompiledPolicy
	if err := decoder.Decode(&policy); err != nil || requireJSONEOF(decoder) != nil ||
		(policy.SchemaVersion != SchemaVersionV1 && policy.SchemaVersion != SchemaVersionV2) ||
		policy.PolicyVersion == 0 || policy.PolicyVersion > MaxPolicyVersion || policy.Rules == nil {
		return nil, nil, invalid("current WAF policy is invalid")
	}
	canonical, err := json.Marshal(&policy)
	if err != nil {
		return nil, nil, invalid("current WAF policy is invalid")
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(raw, canonical) {
		return nil, nil, invalid("current WAF policy is invalid")
	}
	version, err := readPrivateRegularAt(versions, versionFilename(policy.PolicyVersion))
	if err != nil || !bytes.Equal(version, canonical) {
		return nil, nil, invalid("current WAF policy version is invalid")
	}
	return canonical, &policy, nil
}

func pathMissingAt(directory *os.File, name string) bool {
	var stat unix.Stat_t
	err := unix.Fstatat(int(directory.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	return errors.Is(err, unix.ENOENT)
}

func requirePrivateDirectory(directory *os.File) error {
	info, err := directory.Stat()
	if err != nil {
		return fmt.Errorf("inspect WAF policy directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("WAF policy directory must be private, real, and accessible only by its owner")
	}
	return nil
}

func writeImmutableAt(directory *os.File, name string, content []byte) error {
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("create immutable WAF policy: %w", err)
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
		return fmt.Errorf("write immutable WAF policy: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync immutable WAF policy: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close immutable WAF policy: %w", err)
	}
	remove = false
	return syncDirectoryAt(directory)
}

func writeAtomicAt(directory *os.File, name string, content []byte) error {
	temporary, temporaryName, err := createTemporaryAt(directory)
	if err != nil {
		return err
	}
	remove := true
	defer func() {
		_ = temporary.Close()
		if remove {
			_ = unix.Unlinkat(int(directory.Fd()), temporaryName, 0)
		}
	}()
	if _, err := temporary.Write(content); err != nil {
		return fmt.Errorf("write temporary WAF policy: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync temporary WAF policy: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary WAF policy: %w", err)
	}
	if err := unix.Renameat(int(directory.Fd()), temporaryName, int(directory.Fd()), name); err != nil {
		return fmt.Errorf("activate WAF policy: %w", err)
	}
	remove = false
	return syncDirectoryAt(directory)
}

func createTemporaryAt(directory *os.File) (*os.File, string, error) {
	for range 10 {
		var suffix [12]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return nil, "", fmt.Errorf("name temporary WAF policy: %w", err)
		}
		name := fmt.Sprintf(".current-%x.json", suffix)
		fd, err := unix.Openat(int(directory.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return nil, "", fmt.Errorf("create temporary WAF policy: %w", err)
		}
		return os.NewFile(uintptr(fd), name), name, nil
	}
	return nil, "", errors.New("create temporary WAF policy: name collision")
}

func syncDirectoryAt(directory *os.File) error {
	if err := directory.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return fmt.Errorf("sync WAF policy directory: %w", err)
	}
	return nil
}
