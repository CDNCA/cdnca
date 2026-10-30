//go:build darwin

package diskguard

import "golang.org/x/sys/unix"

func statMtime(stat unix.Stat_t) fileTimestamp {
	return fileTimestamp{seconds: stat.Mtim.Sec, nanoseconds: stat.Mtim.Nsec}
}
