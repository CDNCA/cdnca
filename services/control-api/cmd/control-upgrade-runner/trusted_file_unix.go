//go:build !windows

package main

import (
	"fmt"
	"io"
	"os"
	"syscall"
)

func readStableRegularFile(path string, expected os.FileInfo, limit int64) ([]byte, error) {
	stat, ok := expected.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || expected.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("untrusted file metadata")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	openedStat, openedOK := opened.Sys().(*syscall.Stat_t)
	if err != nil || !openedOK || openedStat.Nlink != 1 || !os.SameFile(expected, opened) {
		return nil, fmt.Errorf("file changed before open")
	}
	encoded, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || len(encoded) == 0 || int64(len(encoded)) > limit {
		return nil, fmt.Errorf("invalid file size")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(opened, after) || after.Size() != int64(len(encoded)) {
		return nil, fmt.Errorf("file changed while reading")
	}
	return encoded, nil
}
