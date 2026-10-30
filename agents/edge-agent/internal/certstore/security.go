package certstore

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

func ensurePrivateDirectory(path string, mutable bool) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o700); err != nil {
			return fmt.Errorf("%w: create state directory", ErrUnsafeState)
		}
		info, err = os.Lstat(path)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: directory is not private and real", ErrUnsafeState)
	}
	if mutable && info.Mode().Perm()&0o700 != 0o700 {
		return fmt.Errorf("%w: mutable directory lacks owner permissions", ErrUnsafeState)
	}
	return nil
}

func validatePrivateFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: file is not private and regular", ErrUnsafeState)
	}
	if info.Size() < 0 || info.Size() > maximum || hardLinkCount(info) != 1 {
		return nil, fmt.Errorf("%w: file size or hard-link count is unsafe", ErrUnsafeState)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: read private file", ErrUnsafeState)
	}
	if int64(len(content)) != info.Size() {
		return nil, fmt.Errorf("%w: file changed while reading", ErrUnsafeState)
	}
	return content, nil
}

func hardLinkCount(info fs.FileInfo) uint64 {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return uint64(stat.Nlink)
}

func safeRelativePath(path string) bool {
	return path != "" && !filepath.IsAbs(path) && filepath.Clean(path) == path && path != "." &&
		path != ".." && len(path) < 512 && !hasControl(path)
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("sync directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return fmt.Errorf("sync directory: %w", err)
	}
	return nil
}
