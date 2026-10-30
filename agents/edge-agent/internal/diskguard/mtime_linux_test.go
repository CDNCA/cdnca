//go:build linux

package diskguard

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestFutureMtimeOutsideUnixNanoRangeFailsClosed(t *testing.T) {
	future := time.Date(2300, time.January, 2, 3, 4, 5, 987654321, time.UTC)
	stat := unix.Stat_t{}
	stat.Mtim.Sec = future.Unix()
	stat.Mtim.Nsec = int64(future.Nanosecond())
	assertFutureMtimeFailsClosed(t, metadataFromStat(stat), future)
}
