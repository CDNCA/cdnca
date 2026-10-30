package urlauth

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

var errStoredPolicyContent = errors.New("stored URL auth policy content is invalid")

type storedPolicy struct {
	content []byte
	policy  *CompiledPolicy
}

func NewPublisher(root string) (*Publisher, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == string(filepath.Separator) {
		return nil, invalid("publisher root must be a clean absolute non-root path")
	}
	if info, err := os.Lstat(root); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			return nil, invalid("publisher root must be a private non-symlink directory")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect URL auth policy root: %w", err)
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
	lock, err := lockPublisherAt(rootDirectory)
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
	const currentName = "current.json"
	current, currentExists, currentErr := readStoredPolicyAt(rootDirectory, currentName)
	if currentErr != nil && !errors.Is(currentErr, errStoredPolicyContent) {
		return Publication{}, invalid("current URL auth policy file is unsafe: %v", currentErr)
	}
	var sealed storedPolicy
	if latest == 0 {
		if currentExists || currentErr != nil {
			return Publication{}, invalid("current URL auth policy has no sealed version")
		}
	} else {
		var sealedExists bool
		sealed, sealedExists, err = readStoredPolicyAt(versionsDirectory, versionFilename(latest))
		if err != nil || !sealedExists || sealed.policy.PolicyVersion != latest {
			return Publication{}, invalid("sealed URL auth policy is invalid: %v", err)
		}
		if currentErr == nil && currentExists {
			switch {
			case current.policy.PolicyVersion > latest:
				return Publication{}, invalid("current URL auth policy is newer than sealed state")
			case current.policy.PolicyVersion == latest && !bytes.Equal(current.content, sealed.content):
				return Publication{}, invalid("current URL auth policy conflicts with sealed state")
			case current.policy.PolicyVersion < latest &&
				(policy.PolicyVersion != latest || !bytes.Equal(canonical, sealed.content)):
				return Publication{}, invalid("latest sealed URL auth policy must be repaired before a newer publish")
			}
		}
	}
	if latest != 0 && (sealed.policy.TenantID != policy.TenantID || sealed.policy.SiteID != policy.SiteID) {
		return Publication{}, invalid("URL auth policy belongs to another tenant or site")
	}
	versionName := versionFilename(policy.PolicyVersion)
	if policy.PolicyVersion < latest {
		return Publication{}, invalid("policy_version %d is older than published version %d", policy.PolicyVersion, latest)
	}
	if policy.PolicyVersion == latest && latest != 0 {
		if !bytes.Equal(sealed.content, canonical) {
			return Publication{}, invalid("policy_version %d already has different content", policy.PolicyVersion)
		}
	} else if err := writeImmutableAt(versionsDirectory, versionName, canonical); err != nil {
		return Publication{}, err
	}

	if err := writeAtomicAt(rootDirectory, currentName, canonical); err != nil {
		return Publication{}, err
	}
	currentPath := filepath.Join(publisher.root, currentName)
	return Publication{PolicyVersion: policy.PolicyVersion, SHA256: sha256.Sum256(canonical), CurrentPath: currentPath}, nil
}

// checkOwner rejects a policy whose latest sealed version belongs to another
// tenant or site. A policy that was never published has no owner yet.
func (publisher *Publisher) checkOwner(tenantID, siteID string) error {
	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	if _, err := os.Lstat(publisher.root); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	rootDirectory, err := openPublisherRoot(publisher.root)
	if err != nil {
		return err
	}
	defer rootDirectory.Close()
	lock, err := lockPublisherAt(rootDirectory)
	if err != nil {
		return err
	}
	defer lock.Close()
	versionsDirectory, err := openPrivateDirectoryAt(rootDirectory, "versions")
	if err != nil {
		return err
	}
	defer versionsDirectory.Close()
	latest, err := latestVersion(versionsDirectory)
	if err != nil || latest == 0 {
		return err
	}
	sealed, exists, err := readStoredPolicyAt(versionsDirectory, versionFilename(latest))
	if err != nil || !exists {
		return invalid("sealed URL auth policy is invalid: %v", err)
	}
	if sealed.policy.TenantID != tenantID || sealed.policy.SiteID != siteID {
		return invalid("URL auth policy belongs to another tenant or site")
	}
	return nil
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
		return nil, fmt.Errorf("open URL auth policy filesystem root: %w", err)
	}
	directory := os.NewFile(uintptr(fd), "/")
	if directory == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open URL auth policy filesystem root: invalid file descriptor")
	}
	for _, component := range strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		nextFD, openErr := unix.Openat(int(directory.Fd()), component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if errors.Is(openErr, unix.ENOENT) && create {
			if mkdirErr := unix.Mkdirat(int(directory.Fd()), component, 0o700); mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				_ = directory.Close()
				return nil, fmt.Errorf("create URL auth policy directory %q: %w", component, mkdirErr)
			}
			nextFD, openErr = unix.Openat(int(directory.Fd()), component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		}
		if openErr != nil {
			_ = directory.Close()
			if errors.Is(openErr, unix.ELOOP) || errors.Is(openErr, unix.ENOTDIR) {
				return nil, invalid("publisher root must not have symlink ancestors")
			}
			return nil, fmt.Errorf("open URL auth policy directory %q: %w", component, openErr)
		}
		next := os.NewFile(uintptr(nextFD), component)
		if next == nil {
			_ = unix.Close(nextFD)
			_ = directory.Close()
			return nil, errors.New("open URL auth policy directory: invalid file descriptor")
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
			return nil, fmt.Errorf("create URL auth policy directory %q: %w", name, mkdirErr)
		}
		fd, err = unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	}
	if err != nil {
		return nil, fmt.Errorf("open URL auth policy directory %q: %w", name, err)
	}
	directory := os.NewFile(uintptr(fd), name)
	if directory == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open URL auth policy directory: invalid file descriptor")
	}
	if err := requirePrivateDirectory(directory); err != nil {
		_ = directory.Close()
		return nil, err
	}
	return directory, nil
}

func lockPublisherAt(root *os.File) (*os.File, error) {
	fd, err := unix.Openat(int(root.Fd()), ".publish.lock", unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open URL auth policy lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), ".publish.lock")
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open URL auth policy lock: invalid file descriptor")
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, invalid("URL auth policy lock is not a private regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Nlink != 1 {
		_ = file.Close()
		return nil, invalid("URL auth policy lock is not a private regular file")
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock URL auth policy publication: %w", err)
	}
	return file, nil
}

func requirePrivateDirectory(directory *os.File) error {
	info, err := directory.Stat()
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return invalid("URL auth policy directory must be private and must not be a symlink")
	}
	return nil
}

func versionFilename(version uint64) string {
	return fmt.Sprintf("%020d.json", version)
}

func latestVersion(directory *os.File) (uint64, error) {
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return 0, fmt.Errorf("read URL auth policy versions: %w", err)
	}
	var latest uint64
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !strings.HasSuffix(entry.Name(), ".json") {
			return 0, invalid("URL auth policy versions contain an unsafe entry")
		}
		stem := strings.TrimSuffix(entry.Name(), ".json")
		if len(stem) != 20 {
			return 0, invalid("URL auth policy version filename is invalid")
		}
		version, err := strconv.ParseUint(stem, 10, 64)
		if err != nil || version == 0 || version > MaxPolicyVersion || versionFilename(version) != entry.Name() {
			return 0, invalid("URL auth policy version filename is invalid")
		}
		file, err := openPrivateRegularAt(directory, entry.Name())
		if err != nil {
			return 0, invalid("URL auth policy version file is unsafe: %v", err)
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
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open stored URL auth policy: invalid file descriptor")
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Nlink != 1 {
		_ = file.Close()
		return nil, errors.New("stored URL auth policy must be a private single-linked regular file")
	}
	return file, nil
}

func readStoredPolicyAt(directory *os.File, name string) (storedPolicy, bool, error) {
	file, err := openPrivateRegularAt(directory, name)
	if errors.Is(err, unix.ENOENT) {
		return storedPolicy{}, false, nil
	}
	if err != nil {
		return storedPolicy{}, true, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return storedPolicy{}, true, errors.New("inspect opened URL auth policy")
	}
	if opened.Size() < 1 || opened.Size() > MaxPolicyBytes {
		return storedPolicy{}, true, errStoredPolicyContent
	}
	content, err := io.ReadAll(io.LimitReader(file, MaxPolicyBytes+1))
	if err != nil || len(content) == 0 || len(content) > MaxPolicyBytes {
		return storedPolicy{}, true, errStoredPolicyContent
	}
	policy, err := LoadCompiledJSON(content)
	if err != nil {
		return storedPolicy{}, true, fmt.Errorf("%w: %v", errStoredPolicyContent, err)
	}
	canonical, err := json.Marshal(policy)
	if err != nil {
		return storedPolicy{}, true, fmt.Errorf("%w: marshal canonical policy", errStoredPolicyContent)
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(content, canonical) {
		return storedPolicy{}, true, errStoredPolicyContent
	}
	return storedPolicy{content: content, policy: policy}, true, nil
}

func writeImmutableAt(directory *os.File, name string, content []byte) error {
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("create immutable URL auth policy: %w", err)
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		_ = unix.Unlinkat(int(directory.Fd()), name, 0)
		return errors.New("create immutable URL auth policy: invalid file descriptor")
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = unix.Unlinkat(int(directory.Fd()), name, 0)
		}
	}()
	if _, err := file.Write(content); err != nil {
		return fmt.Errorf("write immutable URL auth policy: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync immutable URL auth policy: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close immutable URL auth policy: %w", err)
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
		return fmt.Errorf("write temporary URL auth policy: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync temporary URL auth policy: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary URL auth policy: %w", err)
	}
	if err := unix.Renameat(int(directory.Fd()), temporaryName, int(directory.Fd()), name); err != nil {
		return fmt.Errorf("activate URL auth policy: %w", err)
	}
	remove = false
	return syncDirectoryAt(directory)
}

func createTemporaryAt(directory *os.File) (*os.File, string, error) {
	for range 10 {
		var suffix [12]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return nil, "", fmt.Errorf("name temporary URL auth policy: %w", err)
		}
		name := fmt.Sprintf(".current-%x.json", suffix)
		fd, err := unix.Openat(int(directory.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return nil, "", fmt.Errorf("create temporary URL auth policy: %w", err)
		}
		file := os.NewFile(uintptr(fd), name)
		if file == nil {
			_ = unix.Close(fd)
			_ = unix.Unlinkat(int(directory.Fd()), name, 0)
			return nil, "", errors.New("create temporary URL auth policy: invalid file descriptor")
		}
		return file, name, nil
	}
	return nil, "", errors.New("create temporary URL auth policy: name collision")
}

func syncDirectoryAt(directory *os.File) error {
	if err := directory.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return fmt.Errorf("sync URL auth policy directory: %w", err)
	}
	return nil
}
