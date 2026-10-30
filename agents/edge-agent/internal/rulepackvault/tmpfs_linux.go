//go:build linux

package rulepackvault

import "golang.org/x/sys/unix"

func isTmpfs(dir string) (bool, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(dir, &stat); err != nil {
		return false, err
	}
	return stat.Type == unix.TMPFS_MAGIC, nil
}
