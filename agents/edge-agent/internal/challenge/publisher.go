package challenge

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
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

var errStoredPolicyContent = errors.New("stored challenge policy content is invalid")

type storedPolicy struct {
	content []byte
	policy  *CompiledPolicy
}

func NewPublisher(root string) (*Publisher, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == string(filepath.Separator) {
		return nil, invalid("publisher root must be a clean absolute non-root path")
	}
	if info, err := os.Lstat(root); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
			return nil, invalid("publisher root must be a private non-symlink directory")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect challenge policy root: %w", err)
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
	const currentName = "current.json"
	current, currentExists, currentErr := readStoredPolicy(rootDirectory, currentName)
	if currentErr != nil && !errors.Is(currentErr, errStoredPolicyContent) {
		return Publication{}, invalid("current challenge policy file is unsafe: %v", currentErr)
	}
	var sealed storedPolicy
	if latest == 0 {
		if currentExists || currentErr != nil {
			return Publication{}, invalid("current challenge policy has no sealed version")
		}
	} else {
		var sealedExists bool
		sealed, sealedExists, err = readStoredPolicy(versionsDirectory, versionFilename(latest))
		if err != nil || !sealedExists || sealed.policy.PolicyVersion != latest {
			return Publication{}, invalid("sealed challenge policy is invalid: %v", err)
		}
		if currentErr == nil && currentExists {
			switch {
			case current.policy.PolicyVersion > latest:
				return Publication{}, invalid("current challenge policy is newer than sealed state")
			case current.policy.PolicyVersion == latest && !bytes.Equal(current.content, sealed.content):
				return Publication{}, invalid("current challenge policy conflicts with sealed state")
			case current.policy.PolicyVersion < latest &&
				(policy.PolicyVersion != latest || !bytes.Equal(canonical, sealed.content)):
				return Publication{}, invalid("latest sealed challenge policy must be repaired before a newer publish")
			}
		}
	}
	versionName := versionFilename(policy.PolicyVersion)
	if policy.PolicyVersion < latest {
		return Publication{}, invalid("policy_version %d is older than published version %d", policy.PolicyVersion, latest)
	}
	if policy.PolicyVersion == latest && latest != 0 {
		if !bytes.Equal(sealed.content, canonical) {
			return Publication{}, invalid("policy_version %d already has different content", policy.PolicyVersion)
		}
	} else if err := writeImmutable(versionsDirectory, versionName, canonical); err != nil {
		return Publication{}, err
	}
	if err := writeAtomic(rootDirectory, currentName, canonical); err != nil {
		return Publication{}, err
	}
	currentPath := filepath.Join(publisher.root, currentName)
	return Publication{PolicyVersion: policy.PolicyVersion, SHA256: sha256.Sum256(canonical), CurrentPath: currentPath}, nil
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
	fd, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open challenge policy filesystem root: %w", err)
	}
	directory := os.NewFile(uintptr(fd), string(filepath.Separator))
	if directory == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open challenge policy filesystem root: invalid file descriptor")
	}
	for _, component := range strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		nextFD, openErr := unix.Openat(int(directory.Fd()), component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if errors.Is(openErr, unix.ENOENT) && create {
			if mkdirErr := unix.Mkdirat(int(directory.Fd()), component, 0o700); mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				_ = directory.Close()
				return nil, fmt.Errorf("create challenge policy directory %q: %w", component, mkdirErr)
			}
			nextFD, openErr = unix.Openat(int(directory.Fd()), component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		}
		if openErr != nil {
			_ = directory.Close()
			if errors.Is(openErr, unix.ELOOP) || errors.Is(openErr, unix.ENOTDIR) {
				return nil, invalid("publisher root must not have symlink ancestors")
			}
			return nil, fmt.Errorf("open challenge policy directory %q: %w", component, openErr)
		}
		next := os.NewFile(uintptr(nextFD), component)
		if next == nil {
			_ = unix.Close(nextFD)
			_ = directory.Close()
			return nil, errors.New("open challenge policy directory: invalid file descriptor")
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
			return nil, fmt.Errorf("create challenge policy directory %q: %w", name, mkdirErr)
		}
		fd, err = unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	}
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
			return nil, invalid("challenge policy directory must be real and mode 0700")
		}
		return nil, fmt.Errorf("open challenge policy directory %q: %w", name, err)
	}
	directory := os.NewFile(uintptr(fd), name)
	if directory == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open challenge policy directory: invalid file descriptor")
	}
	if err := requirePrivateDirectory(directory); err != nil {
		_ = directory.Close()
		return nil, err
	}
	return directory, nil
}

func (publisher *Publisher) lock(root *os.File) (*os.File, error) {
	fd, err := unix.Openat(int(root.Fd()), ".publish.lock", unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open challenge publication lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), ".publish.lock")
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open challenge publication lock: invalid file descriptor")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o777 != 0o600 || stat.Nlink != 1 {
		_ = file.Close()
		return nil, invalid("challenge publication lock must be a 0600 regular file")
	}
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock challenge publication: %w", err)
	}
	return file, nil
}

func latestVersion(directory *os.File) (uint64, error) {
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return 0, fmt.Errorf("read challenge policy versions: %w", err)
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
		if err := unix.Fstatat(int(directory.Fd()), entry.Name(), &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
			stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o777 != 0o600 || stat.Nlink != 1 {
			return 0, invalid("challenge policy version %q is not private and independent", entry.Name())
		}
		if version > latest {
			latest = version
		}
	}
	return latest, nil
}

func versionFilename(version uint64) string {
	return fmt.Sprintf("%020d.json", version)
}

func requirePrivateDirectory(directory *os.File) error {
	info, err := directory.Stat()
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return invalid("challenge policy directory must be real and mode 0700")
	}
	return nil
}

func readPrivateRegularAt(directory *os.File, name string) ([]byte, error) {
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open challenge policy: invalid file descriptor")
	}
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Mode&0o777 != 0o600 || stat.Nlink != 1 || stat.Size < 1 || stat.Size > MaxPolicyBytes {
		return nil, invalid("challenge policy must be a private independent bounded file")
	}
	content, err := io.ReadAll(io.LimitReader(file, MaxPolicyBytes+1))
	if err != nil || len(content) == 0 || len(content) > MaxPolicyBytes {
		return nil, invalid("challenge policy content could not be read safely")
	}
	return content, nil
}

func readStoredPolicy(directory *os.File, name string) (storedPolicy, bool, error) {
	var stat unix.Stat_t
	if err := unix.Fstatat(int(directory.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return storedPolicy{}, false, nil
	} else if err != nil {
		return storedPolicy{}, false, err
	}
	content, err := readPrivateRegularAt(directory, name)
	if err != nil {
		return storedPolicy{}, true, err
	}
	var policy CompiledPolicy
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return storedPolicy{}, true, fmt.Errorf("%w: %v", errStoredPolicyContent, err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return storedPolicy{}, true, fmt.Errorf("%w: %v", errStoredPolicyContent, err)
	}
	input, err := storedPolicyInput(&policy)
	if err != nil {
		return storedPolicy{}, true, fmt.Errorf("%w: %v", errStoredPolicyContent, err)
	}
	recompiled, err := compile(input)
	if err != nil {
		return storedPolicy{}, true, fmt.Errorf("%w: %v", errStoredPolicyContent, err)
	}
	canonical, err := json.Marshal(recompiled)
	if err != nil {
		return storedPolicy{}, true, fmt.Errorf("%w: marshal canonical policy", errStoredPolicyContent)
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(content, canonical) {
		return storedPolicy{}, true, errStoredPolicyContent
	}
	return storedPolicy{content: content, policy: &policy}, true, nil
}

func storedPolicyInput(policy *CompiledPolicy) (Policy, error) {
	trusted := make([]string, len(policy.TrustedProxies))
	for index, cidr := range policy.TrustedProxies {
		bytes := make([]byte, len(cidr.Network))
		for offset, value := range cidr.Network {
			if value > 255 {
				return Policy{}, invalid("trusted_proxies entry %d is invalid", index)
			}
			bytes[offset] = byte(value)
		}
		var address netip.Addr
		switch {
		case cidr.Family == 4 && len(bytes) == 4 && cidr.PrefixLength <= 32:
			var value [4]byte
			copy(value[:], bytes)
			address = netip.AddrFrom4(value)
		case cidr.Family == 6 && len(bytes) == 16 && cidr.PrefixLength <= 128:
			var value [16]byte
			copy(value[:], bytes)
			address = netip.AddrFrom16(value)
		default:
			return Policy{}, invalid("trusted_proxies entry %d is invalid", index)
		}
		prefix := netip.PrefixFrom(address, int(cidr.PrefixLength))
		if prefix.Masked() != prefix {
			return Policy{}, invalid("trusted_proxies entry %d is not canonical", index)
		}
		trusted[index] = prefix.String()
	}
	input := Policy{
		SchemaVersion:  policy.SchemaVersion,
		PolicyVersion:  policy.PolicyVersion,
		Algorithm:      policy.Algorithm,
		CookieName:     policy.CookieName,
		TrustedProxies: trusted,
		BypassRoutes:   policy.BypassRoutes,
		CurrentKey:     KeyRef{KeyID: policy.CurrentKey.KeyID, KeyFile: policy.CurrentKey.KeyFile},
		Rules:          policy.Rules,
	}
	if policy.PreviousKey != nil {
		input.PreviousKey = &KeyRef{KeyID: policy.PreviousKey.KeyID, KeyFile: policy.PreviousKey.KeyFile}
	}
	return input, nil
}

func writeImmutable(directory *os.File, name string, content []byte) error {
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("create immutable challenge policy: %w", err)
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		_ = unix.Unlinkat(int(directory.Fd()), name, 0)
		return errors.New("create immutable challenge policy: invalid file descriptor")
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = unix.Unlinkat(int(directory.Fd()), name, 0)
		}
	}()
	if _, err := file.Write(content); err != nil {
		return fmt.Errorf("write immutable challenge policy: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync immutable challenge policy: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close immutable challenge policy: %w", err)
	}
	remove = false
	return syncDirectory(directory)
}

func writeAtomic(directory *os.File, name string, content []byte) error {
	temporary, temporaryName, err := createTemporaryAt(directory)
	if err != nil {
		return err
	}
	defer func() {
		_ = temporary.Close()
		_ = unix.Unlinkat(int(directory.Fd()), temporaryName, 0)
	}()
	if _, err := temporary.Write(content); err != nil {
		return fmt.Errorf("write temporary challenge policy: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync temporary challenge policy: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary challenge policy: %w", err)
	}
	if err := unix.Renameat(int(directory.Fd()), temporaryName, int(directory.Fd()), name); err != nil {
		return fmt.Errorf("activate challenge policy: %w", err)
	}
	return syncDirectory(directory)
}

func createTemporaryAt(directory *os.File) (*os.File, string, error) {
	for range 10 {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, "", fmt.Errorf("name temporary challenge policy: %w", err)
		}
		name := fmt.Sprintf(".current-%x.json", random)
		fd, err := unix.Openat(int(directory.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return nil, "", fmt.Errorf("create temporary challenge policy: %w", err)
		}
		file := os.NewFile(uintptr(fd), name)
		if file == nil {
			_ = unix.Close(fd)
			_ = unix.Unlinkat(int(directory.Fd()), name, 0)
			return nil, "", errors.New("create temporary challenge policy: invalid file descriptor")
		}
		return file, name, nil
	}
	return nil, "", errors.New("create temporary challenge policy: name collision")
}

func syncDirectory(directory *os.File) error {
	if err := directory.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return fmt.Errorf("sync challenge policy directory: %w", err)
	}
	return nil
}
