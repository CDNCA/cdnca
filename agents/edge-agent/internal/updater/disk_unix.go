//go:build darwin || linux

package updater

import (
	"fmt"
	"syscall"
)

func availableDiskBytes(path string) (uint64, error) {
	var status syscall.Statfs_t
	if err := syscall.Statfs(path, &status); err != nil {
		return 0, fmt.Errorf("inspect updater disk capacity: %w", err)
	}
	return uint64(status.Bavail) * uint64(status.Bsize), nil
}

func regularLinkCount(info any) (uint64, bool) {
	status, ok := info.(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(status.Nlink), true
}
