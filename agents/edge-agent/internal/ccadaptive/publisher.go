package ccadaptive

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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
	Revision uint64
	Digest   string
	Path     string
}

type Publisher struct {
	root string
	mu   sync.Mutex
}

func NewPublisher(root string) (*Publisher, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == string(filepath.Separator) {
		return nil, errors.New("CC adaptive publication root must be a clean absolute non-root path")
	}
	if err := rejectSymlinkAncestors(root); err != nil {
		return nil, err
	}
	return &Publisher{root: root}, nil
}

func rejectSymlinkAncestors(path string) error {
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return errors.New("CC adaptive publication root must not have symlink ancestors")
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect CC adaptive publication root: %w", err)
		}
		if parent := filepath.Dir(current); parent == current {
			return nil
		}
	}
}

func (publisher *Publisher) PublishJSON(raw []byte) (Publication, error) {
	canonical, policy, err := CompileJSON(raw)
	if err != nil {
		return Publication{}, err
	}
	publisher.mu.Lock()
	defer publisher.mu.Unlock()

	rootDirectory, err := openPublisherRoot(publisher.root, true)
	if err != nil {
		return Publication{}, err
	}
	defer rootDirectory.Close()
	lock, err := publisher.lock(rootDirectory)
	if err != nil {
		return Publication{}, err
	}
	defer lock.Close()

	versionsDirectory, err := openPrivateDirectoryAt(rootDirectory, "versions", true)
	if err != nil {
		return Publication{}, err
	}
	defer versionsDirectory.Close()
	latest, err := latestVersion(versionsDirectory)
	if err != nil {
		return Publication{}, err
	}
	const currentName = "current.json"
	const fallbackName = "fallback.json"
	currentCanonical, currentPolicy, currentErr := readValidatedPublication(rootDirectory, currentName, versionsDirectory)
	_, _, fallbackErr := readValidatedPublication(rootDirectory, fallbackName, versionsDirectory)
	if policy.Revision < latest {
		return Publication{}, fmt.Errorf("CC adaptive revision %d is older than published revision %d", policy.Revision, latest)
	}
	if currentErr == nil {
		if currentPolicy.Revision > policy.Revision {
			return Publication{}, fmt.Errorf("CC adaptive revision %d is older than active revision %d", policy.Revision, currentPolicy.Revision)
		}
		if currentPolicy.Revision == policy.Revision && !equalBytes(currentCanonical, canonical) {
			return Publication{}, errors.New("CC adaptive revision content conflict")
		}
	} else {
		initial := latest == 0 && pathMissing(rootDirectory, currentName) && pathMissing(rootDirectory, fallbackName)
		recovery := latest != 0 && policy.Revision == latest &&
			(fallbackErr == nil || pathMissing(rootDirectory, currentName) && pathMissing(rootDirectory, fallbackName))
		if !initial && !recovery {
			return Publication{}, errors.New("current CC adaptive release is invalid")
		}
	}

	versionName := versionName(policy.Revision)
	writeVersion := policy.Revision > latest
	if policy.Revision == latest && latest != 0 {
		existing, readErr := readPrivateRegular(versionsDirectory, versionName)
		if readErr != nil {
			return Publication{}, fmt.Errorf("read existing CC adaptive revision: %w", readErr)
		}
		if !equalBytes(existing, canonical) {
			_, existingPolicy, compileErr := CompileJSON(existing)
			if compileErr == nil && existingPolicy.Revision == policy.Revision {
				return Publication{}, errors.New("CC adaptive revision content conflict")
			}
			if currentErr == nil && currentPolicy.Revision >= policy.Revision {
				return Publication{}, errors.New("CC adaptive revision content conflict")
			}
			if err := unix.Unlinkat(int(versionsDirectory.Fd()), versionName, 0); err != nil {
				return Publication{}, fmt.Errorf("remove incomplete CC adaptive revision: %w", err)
			}
			if err := syncDirectory(versionsDirectory); err != nil {
				return Publication{}, err
			}
			writeVersion = true
		}
	}
	if writeVersion {
		if err := writeImmutable(versionsDirectory, versionName, canonical); err != nil {
			return Publication{}, err
		}
	}
	if currentErr == nil {
		if err := writeAtomic(rootDirectory, fallbackName, currentCanonical); err != nil {
			return Publication{}, err
		}
	} else if pathMissing(rootDirectory, fallbackName) {
		if err := writeAtomic(rootDirectory, fallbackName, canonical); err != nil {
			return Publication{}, err
		}
	}
	if err := writeAtomic(rootDirectory, currentName, canonical); err != nil {
		return Publication{}, err
	}
	return publicationFor(publisher.root, policy.Revision, canonical), nil
}

func (publisher *Publisher) Rollback(revision uint64) (Publication, error) {
	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	rootDirectory, err := openPublisherRoot(publisher.root, false)
	if err != nil {
		return Publication{}, err
	}
	defer rootDirectory.Close()
	lock, err := publisher.lock(rootDirectory)
	if err != nil {
		return Publication{}, err
	}
	defer lock.Close()
	versionsDirectory, err := openPrivateDirectoryAt(rootDirectory, "versions", false)
	if err != nil {
		return Publication{}, err
	}
	defer versionsDirectory.Close()
	raw, policy, err := readValidatedPublication(versionsDirectory, versionName(revision), versionsDirectory)
	if err != nil {
		return Publication{}, fmt.Errorf("read CC adaptive rollback revision: %w", err)
	}
	if policy.Revision != revision {
		return Publication{}, errors.New("CC adaptive rollback revision is not a canonical valid release")
	}
	const currentName = "current.json"
	const fallbackName = "fallback.json"
	currentCanonical, _, currentErr := readValidatedPublication(rootDirectory, currentName, versionsDirectory)
	if currentErr == nil {
		if err := writeAtomic(rootDirectory, fallbackName, currentCanonical); err != nil {
			return Publication{}, err
		}
	} else if _, _, fallbackErr := readValidatedPublication(rootDirectory, fallbackName, versionsDirectory); fallbackErr != nil {
		if !pathMissing(rootDirectory, currentName) || !pathMissing(rootDirectory, fallbackName) {
			return Publication{}, errors.New("current CC adaptive release is invalid")
		}
		if err := writeAtomic(rootDirectory, fallbackName, raw); err != nil {
			return Publication{}, err
		}
	}
	if err := writeAtomic(rootDirectory, currentName, raw); err != nil {
		return Publication{}, err
	}
	return publicationFor(publisher.root, revision, raw), nil
}

func (publisher *Publisher) current() (uint64, []byte, error) {
	rootDirectory, err := openPublisherRoot(publisher.root, false)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil, nil
	}
	if err != nil {
		return 0, nil, err
	}
	defer rootDirectory.Close()
	versionsDirectory, err := openPrivateDirectoryAt(rootDirectory, "versions", false)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil, nil
	}
	if err != nil {
		return 0, nil, err
	}
	defer versionsDirectory.Close()
	raw, policy, err := readValidatedPublication(rootDirectory, "current.json", versionsDirectory)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil, nil
	}
	if err != nil {
		return 0, nil, err
	}
	return policy.Revision, raw, nil
}

func (publisher *Publisher) lock(rootDirectory *os.File) (*os.File, error) {
	fd, err := unix.Openat(int(rootDirectory.Fd()), ".publish.lock", unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open CC adaptive publication lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), ".publish.lock")
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open CC adaptive publication lock: invalid file descriptor")
	}
	info, err := file.Stat()
	var stat unix.Stat_t
	statErr := unix.Fstat(fd, &stat)
	if err != nil || statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || stat.Nlink != 1 {
		_ = file.Close()
		return nil, errors.New("CC adaptive publication lock must be private, regular, and single-linked")
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock CC adaptive publication: %w", err)
	}
	return file, nil
}

func publicationFor(root string, revision uint64, raw []byte) Publication {
	digest := sha256.Sum256(raw)
	return Publication{Revision: revision, Digest: hex.EncodeToString(digest[:]), Path: filepath.Join(root, "versions", versionName(revision))}
}

func versionName(revision uint64) string { return fmt.Sprintf("%020d.json", revision) }

func openPublisherRoot(path string, create bool) (*os.File, error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open CC adaptive filesystem root: %w", err)
	}
	directory := os.NewFile(uintptr(fd), "/")
	if directory == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open CC adaptive filesystem root: invalid file descriptor")
	}
	for _, component := range strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		nextFD, openErr := unix.Openat(int(directory.Fd()), component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if errors.Is(openErr, unix.ENOENT) && create {
			if mkdirErr := unix.Mkdirat(int(directory.Fd()), component, 0o700); mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				_ = directory.Close()
				return nil, fmt.Errorf("create CC adaptive publication directory %q: %w", component, mkdirErr)
			}
			nextFD, openErr = unix.Openat(int(directory.Fd()), component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		}
		if openErr != nil {
			_ = directory.Close()
			if errors.Is(openErr, unix.ELOOP) || errors.Is(openErr, unix.ENOTDIR) {
				return nil, errors.New("CC adaptive publication root must not have symlink ancestors")
			}
			return nil, fmt.Errorf("open CC adaptive publication directory %q: %w", component, openErr)
		}
		next := os.NewFile(uintptr(nextFD), component)
		if next == nil {
			_ = unix.Close(nextFD)
			_ = directory.Close()
			return nil, errors.New("open CC adaptive publication directory: invalid file descriptor")
		}
		_ = directory.Close()
		directory = next
	}
	if err := requirePrivateDirectory(directory); err != nil {
		_ = directory.Close()
		return nil, err
	}
	return directory, nil
}

func openPrivateDirectoryAt(parent *os.File, name string, create bool) (*os.File, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) && create {
		if mkdirErr := unix.Mkdirat(int(parent.Fd()), name, 0o700); mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
			return nil, fmt.Errorf("create CC adaptive publication directory %q: %w", name, mkdirErr)
		}
		fd, err = unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	}
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
			return nil, errors.New("CC adaptive publication directory must be private, real, and owner-only")
		}
		return nil, fmt.Errorf("open CC adaptive publication directory %q: %w", name, err)
	}
	directory := os.NewFile(uintptr(fd), name)
	if directory == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open CC adaptive publication directory: invalid file descriptor")
	}
	if err := requirePrivateDirectory(directory); err != nil {
		_ = directory.Close()
		return nil, err
	}
	return directory, nil
}

func latestVersion(directory *os.File) (uint64, error) {
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return 0, fmt.Errorf("read CC adaptive versions: %w", err)
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
		revision, err := strconv.ParseUint(stem, 10, 64)
		if err != nil {
			continue
		}
		var stat unix.Stat_t
		if err := unix.Fstatat(int(directory.Fd()), entry.Name(), &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return 0, fmt.Errorf("inspect CC adaptive revision %q: %w", entry.Name(), err)
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o077 != 0 || stat.Nlink != 1 {
			return 0, fmt.Errorf("CC adaptive revision %q must be private, regular, and single-linked", entry.Name())
		}
		if revision > latest {
			latest = revision
		}
	}
	return latest, nil
}

func requirePrivateDirectory(directory *os.File) error {
	info, err := directory.Stat()
	if err != nil {
		return fmt.Errorf("inspect CC adaptive publication directory: %w", err)
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("CC adaptive publication directory must be private, real, and owner-only")
	}
	return nil
}

func writeImmutable(directory *os.File, name string, content []byte) error {
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("create immutable CC adaptive revision: %w", err)
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		_ = unix.Unlinkat(int(directory.Fd()), name, 0)
		return errors.New("create immutable CC adaptive revision: invalid file descriptor")
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = unix.Unlinkat(int(directory.Fd()), name, 0)
		}
	}()
	if _, err := file.Write(content); err != nil {
		return fmt.Errorf("write immutable CC adaptive revision: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync immutable CC adaptive revision: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close immutable CC adaptive revision: %w", err)
	}
	if err := syncDirectory(directory); err != nil {
		return err
	}
	remove = false
	return nil
}

func writeAtomic(directory *os.File, name string, content []byte) error {
	temporary, temporaryName, err := createTemporary(directory, name)
	if err != nil {
		return err
	}
	defer func() {
		_ = temporary.Close()
		_ = unix.Unlinkat(int(directory.Fd()), temporaryName, 0)
	}()
	if _, err := temporary.Write(content); err != nil {
		return fmt.Errorf("write temporary CC adaptive release: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync temporary CC adaptive release: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary CC adaptive release: %w", err)
	}
	if err := unix.Renameat(int(directory.Fd()), temporaryName, int(directory.Fd()), name); err != nil {
		return fmt.Errorf("activate CC adaptive release: %w", err)
	}
	return syncDirectory(directory)
}

func createTemporary(directory *os.File, target string) (*os.File, string, error) {
	for range 10 {
		var suffix [12]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return nil, "", fmt.Errorf("name temporary CC adaptive release: %w", err)
		}
		name := fmt.Sprintf(".%s-%x.tmp", target, suffix)
		fd, err := unix.Openat(int(directory.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return nil, "", fmt.Errorf("create temporary CC adaptive release: %w", err)
		}
		file := os.NewFile(uintptr(fd), name)
		if file == nil {
			_ = unix.Close(fd)
			_ = unix.Unlinkat(int(directory.Fd()), name, 0)
			return nil, "", errors.New("create temporary CC adaptive release: invalid file descriptor")
		}
		return file, name, nil
	}
	return nil, "", errors.New("create temporary CC adaptive release: name collision")
}

func equalBytes(left, right []byte) bool { return bytes.Equal(left, right) }

func readPrivateRegular(directory *os.File, name string) ([]byte, error) {
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open CC adaptive release: invalid file descriptor")
	}
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o077 != 0 || stat.Nlink != 1 {
		return nil, errors.New("CC adaptive release must be private, regular, and single-linked")
	}
	return io.ReadAll(io.LimitReader(file, MaxPolicyBytes+1))
}

func readValidatedPublication(directory *os.File, name string, versionsDirectory *os.File) ([]byte, *Policy, error) {
	raw, err := readPrivateRegular(directory, name)
	if err != nil {
		return nil, nil, err
	}
	canonical, policy, err := CompileJSON(raw)
	if err != nil || !equalBytes(raw, canonical) {
		return nil, nil, errors.New("current CC adaptive release is invalid")
	}
	version, err := readPrivateRegular(versionsDirectory, versionName(policy.Revision))
	if err != nil || !equalBytes(version, canonical) {
		return nil, nil, errors.New("current CC adaptive release is invalid")
	}
	return canonical, policy, nil
}

func pathMissing(directory *os.File, name string) bool {
	var stat unix.Stat_t
	err := unix.Fstatat(int(directory.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	return errors.Is(err, unix.ENOENT)
}

func syncDirectory(directory *os.File) error {
	if err := directory.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return fmt.Errorf("sync CC adaptive publication directory: %w", err)
	}
	return nil
}
