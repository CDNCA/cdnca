package nativebackup

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// writeFileAtomic replaces path with data durably: temporary file in the same
// directory, fsync, rename, fsync of the directory.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
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
	if err := os.Rename(name, path); err != nil {
		return err
	}
	ok = true
	return syncDirectory(directory)
}

func syncDirectory(directory string) error {
	handle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}

// ensurePrivateDirectory creates directory (and parents) and requires it to
// be a real directory owned by the current user without group/other access.
func ensurePrivateDirectory(directory string) error {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("private directory is not a directory")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != os.Geteuid() {
		return errors.New("private directory has an unexpected owner")
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(directory, 0o700); err != nil {
			return err
		}
	}
	return nil
}

// readPrivateFile reads a bounded regular file that is not a symlink and is
// not writable by group or others.
func readPrivateFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit || info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("file is not a bounded private regular file")
	}
	return os.ReadFile(path)
}

// LockRelease takes the exclusive native release lock that the control
// upgrade runner also takes, so backups, restores and upgrades never overlap.
func LockRelease(layout Layout) (func(), error) {
	path := layout.Path(ReleaseLock)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	flags := os.O_RDWR | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		// A fresh restore target has no upgrade runner yet. Its tmpfiles rule
		// creates the release lock with the runner's group at boot and never
		// adjusts an existing file, so do not create it here.
		path = filepath.Join(filepath.Dir(path), "cdnca-control-restore.lock")
		flags |= os.O_CREATE
	}
	file, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	stat, ok := info.Sys().(*syscall.Stat_t)
	if err != nil || !ok || int(stat.Uid) != os.Geteuid() || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, errors.New("release lock is unsafe")
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, ErrBusy
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}, nil
}

// ErrBusy means an upgrade, backup or restore already holds the release lock.
var ErrBusy = errors.New("another control upgrade, backup or restore is running")

func fileExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}
