package packagingtoolset

import "syscall"

func statCtime(stat *syscall.Stat_t) int64 { return stat.Ctimespec.Nano() }
