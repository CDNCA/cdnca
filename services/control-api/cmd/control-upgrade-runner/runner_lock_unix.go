//go:build !windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

type runnerLock struct {
	file *os.File
}

func acquireRunnerLock(stateDirectory string) (*runnerLock, error) {
	path := filepath.Join(stateDirectory, "runner.lock")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	info, statErr := file.Stat()
	stat, ok := info.Sys().(*syscall.Stat_t)
	if statErr != nil || !ok || !info.Mode().IsRegular() || stat.Nlink != 1 ||
		(info.Mode().Perm() != 0o600 && file.Chmod(0o600) != nil) {
		_ = file.Close()
		return nil, fmt.Errorf("control upgrade runner lock is invalid")
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("control upgrade runner is already active: %w", err)
	}
	return &runnerLock{file: file}, nil
}

func (lock *runnerLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	_ = syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN)
	err := lock.file.Close()
	lock.file = nil
	return err
}
