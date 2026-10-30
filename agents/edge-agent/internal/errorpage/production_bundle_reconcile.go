package errorpage

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"

	"golang.org/x/sys/unix"
)

var productionBundleOrphanName = regexp.MustCompile(`^[a-f0-9]{64}-[a-f0-9]{16}$`)

func (publisher *Publisher) reconcileProductionBundleOrphans() (int, error) {
	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	state, err := publisher.openState()
	if err != nil {
		return 0, err
	}
	defer state.close()
	entries, err := state.staging.ReadDir(-1)
	if err != nil {
		return 0, err
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].Name() < entries[right].Name() })
	removed := 0
	for _, entry := range entries {
		if !productionBundleOrphanName.MatchString(entry.Name()) {
			return removed, fmt.Errorf("unsafe error page staging orphan name")
		}
		if err := removeProductionBundleOrphan(state.staging, entry.Name()); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

func removeProductionBundleOrphan(parent *os.File, name string) error {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(fd), name)
	defer directory.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || uint32(stat.Mode)&uint32(unix.S_IFMT) != uint32(unix.S_IFDIR) ||
		stat.Uid != uint32(os.Geteuid()) || os.FileMode(stat.Mode)&os.ModePerm != 0o700 && os.FileMode(stat.Mode)&os.ModePerm != 0o500 {
		return fmt.Errorf("unsafe error page staging orphan directory")
	}
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return err
	}
	allowed := map[string]struct{}{"manifest.json": {}, "policy.json": {}, "policy.lua": {}}
	for _, entry := range entries {
		if _, ok := allowed[entry.Name()]; !ok {
			return fmt.Errorf("unsafe error page staging orphan file")
		}
		var fileStat unix.Stat_t
		if err := unix.Fstatat(fd, entry.Name(), &fileStat, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
			uint32(fileStat.Mode)&uint32(unix.S_IFMT) != uint32(unix.S_IFREG) || fileStat.Uid != uint32(os.Geteuid()) ||
			os.FileMode(fileStat.Mode)&os.ModePerm != 0o400 || fileStat.Nlink != 1 {
			return fmt.Errorf("unsafe error page staging orphan file")
		}
	}
	if err := unix.Fchmod(fd, 0o700); err != nil {
		return err
	}
	for _, entry := range entries {
		if err := unix.Unlinkat(fd, entry.Name(), 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return err
		}
	}
	if err := directory.Close(); err != nil {
		return err
	}
	if err := unix.Unlinkat(int(parent.Fd()), name, unix.AT_REMOVEDIR); err != nil {
		return err
	}
	return syncDirectory(parent)
}
