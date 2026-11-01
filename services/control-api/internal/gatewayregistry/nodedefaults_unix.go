package gatewayregistry

import (
	"os"
	"syscall"
)

func chownLike(path string, info os.FileInfo) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		_ = os.Lchown(path, int(stat.Uid), int(stat.Gid))
	}
}
