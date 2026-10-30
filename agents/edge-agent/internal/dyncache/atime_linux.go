package dyncache

import (
	"syscall"
	"time"
)

func accessTime(stat *syscall.Stat_t) time.Time {
	return time.Unix(int64(stat.Atim.Sec), int64(stat.Atim.Nsec))
}

// noAtime: the agent's own reads (key scans, usage) must not count as an
// access, or the soft quota's LRU order becomes the scan order (relatime
// updates atime on the first read after a write).
const noAtime = syscall.O_NOATIME
