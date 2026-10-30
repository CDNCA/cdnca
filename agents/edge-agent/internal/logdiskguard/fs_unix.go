//go:build linux || darwin

package logdiskguard

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type fileIdentity struct {
	device uint64
	inode  uint64
	links  uint64
}

func (identity fileIdentity) same(other fileIdentity) bool {
	return identity.device == other.device && identity.inode == other.inode && identity.links == other.links
}

type openDirectory struct {
	fd       int
	path     string
	identity fileIdentity
}

func (directory *openDirectory) close() {
	if directory != nil && directory.fd >= 0 {
		_ = unix.Close(directory.fd)
		directory.fd = -1
	}
}

type openFile struct {
	fd        int
	identity  fileIdentity
	size      int64
	allocated uint64
	modified  time.Time
}

func (file *openFile) close() {
	if file != nil && file.fd >= 0 {
		_ = unix.Close(file.fd)
		file.fd = -1
	}
}

func safeAbsolutePath(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value && value != string(filepath.Separator) && !strings.ContainsRune(value, 0)
}

func ensurePrivateDirectory(path string) error {
	if !safeAbsolutePath(path) {
		return ErrInvalidConfig
	}
	if err := rejectSymlinkComponents(path); err != nil {
		return err
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create private directory: %w", err)
	}
	directory, err := secureOpenDirectory(path)
	if err != nil {
		return err
	}
	directory.close()
	return nil
}

func rejectSymlinkComponents(path string) error {
	if !safeAbsolutePath(path) {
		return ErrUnsafePath
	}
	current := string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return ErrUnsafePath
		}
	}
	return nil
}

func secureOpenDirectory(path string) (*openDirectory, error) {
	if !safeAbsolutePath(path) {
		return nil, ErrUnsafePath
	}
	fd, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnsafePath
	}
	for _, component := range strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		next, openErr := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if openErr != nil {
			return nil, ErrUnsafePath
		}
		fd = next
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || uint32(stat.Uid) != uint32(os.Geteuid()) || stat.Mode&0o022 != 0 {
		_ = unix.Close(fd)
		return nil, ErrUnsafePath
	}
	return &openDirectory{fd: fd, path: path, identity: identityFromStat(&stat)}, nil
}

func secureOpenOptionalDirectory(path string) (*openDirectory, bool, error) {
	directory, err := secureOpenDirectory(path)
	if err == nil {
		return directory, true, nil
	}
	if _, statErr := os.Lstat(path); errors.Is(statErr, os.ErrNotExist) {
		return nil, false, nil
	}
	return nil, false, err
}

func identityFromStat(stat *unix.Stat_t) fileIdentity {
	return fileIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino), links: uint64(stat.Nlink)}
}

func openRegularAt(directory *openDirectory, name string, flags int) (*openFile, error) {
	if filepath.Base(name) != name || name == "." || name == ".." || strings.ContainsRune(name, 0) {
		return nil, ErrUnsafePath
	}
	fd, err := unix.Openat(directory.fd, name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnsafePath
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o077 != 0 || stat.Nlink != 1 || uint64(stat.Dev) != directory.identity.device {
		_ = unix.Close(fd)
		return nil, ErrUnsafePath
	}
	duplicate, duplicateErr := unix.Dup(fd)
	if duplicateErr != nil {
		_ = unix.Close(fd)
		return nil, ErrUnsafePath
	}
	file := os.NewFile(uintptr(duplicate), name)
	info, infoErr := file.Stat()
	_ = file.Close()
	if infoErr != nil {
		_ = unix.Close(fd)
		return nil, ErrUnsafePath
	}
	return &openFile{
		fd: fd, identity: identityFromStat(&stat), size: stat.Size,
		allocated: uint64(stat.Blocks) * 512, modified: info.ModTime(),
	}, nil
}

func verifyNameIdentity(directory *openDirectory, name string, expected fileIdentity, size int64) error {
	var stat unix.Stat_t
	if err := unix.Fstatat(directory.fd, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
		stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o077 != 0 || stat.Nlink != 1 || stat.Size != size ||
		!expected.same(identityFromStat(&stat)) {
		return ErrUnsafePath
	}
	return nil
}

func nameExists(directory *openDirectory, name string) (bool, error) {
	var stat unix.Stat_t
	err := unix.Fstatat(directory.fd, name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, ErrUnsafePath
	}
	return true, nil
}

func duplicateDirectoryFile(directory *openDirectory) (*os.File, error) {
	fd, err := unix.Dup(directory.fd)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), directory.path), nil
}

func acquirePrivateLock(directory *openDirectory, name string, create bool) (func(), error) {
	flags := unix.O_RDWR
	if create {
		flags |= unix.O_CREAT
	}
	fd, err := unix.Openat(directory.fd, name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, ErrUnsafePath
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o077 != 0 || stat.Nlink != 1 || uint64(stat.Dev) != directory.identity.device {
		_ = unix.Close(fd)
		return nil, ErrUnsafePath
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = unix.Close(fd)
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, ErrAlreadyRunning
		}
		return nil, ErrUnsafePath
	}
	return func() {
		_ = unix.Flock(fd, unix.LOCK_UN)
		_ = unix.Close(fd)
	}, nil
}

func syncDirectory(directory *openDirectory) error {
	if err := unix.Fsync(directory.fd); err != nil {
		return fmt.Errorf("sync directory: %w", err)
	}
	return nil
}

func nativeUsage(path string) (Usage, error) {
	directory, err := secureOpenDirectory(path)
	if err != nil {
		return Usage{}, err
	}
	defer directory.close()
	var stat unix.Statfs_t
	if err := unix.Fstatfs(directory.fd, &stat); err != nil || stat.Blocks == 0 || stat.Bsize <= 0 {
		return Usage{}, ErrUnsafePath
	}
	blockSize := uint64(stat.Bsize)
	return Usage{TotalBytes: uint64(stat.Blocks) * blockSize, AvailableBytes: uint64(stat.Bavail) * blockSize}, nil
}
