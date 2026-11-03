package dyncache

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// freeBytes is what an unprivileged writer may still use on path's file
// system.
func freeBytes(path string) (int64, error) {
	var stat syscall.Statfs_t
	if err := statfsNearest(path, &stat); err != nil {
		return 0, err
	}
	return int64(stat.Bavail) * int64(stat.Bsize), nil
}

func statfsNearest(path string, stat *syscall.Statfs_t) error {
	for {
		err := syscall.Statfs(path, stat)
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		parent := filepath.Dir(path)
		if parent == path {
			return err
		}
		path = parent
	}
}
