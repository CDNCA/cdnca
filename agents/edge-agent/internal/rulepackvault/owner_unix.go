//go:build unix

package rulepackvault

import (
	"os"
	"syscall"
)

// ownerUID is the file's owner (ok false: unknown on this platform).
func ownerUID(info os.FileInfo) (int, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(stat.Uid), true
}
