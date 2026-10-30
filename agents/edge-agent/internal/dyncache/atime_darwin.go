package dyncache

import (
	"syscall"
	"time"
)

func accessTime(stat *syscall.Stat_t) time.Time {
	return time.Unix(stat.Atimespec.Sec, stat.Atimespec.Nsec)
}

// noAtime: no O_NOATIME on darwin (development only).
const noAtime = 0
