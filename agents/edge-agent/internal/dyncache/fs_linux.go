package dyncache

import (
	"strconv"
	"syscall"
)

// localFilesystems: statfs f_type of the file systems the purge index
// trusts (a directory's mtime changes with every entry created, renamed in
// or removed, on the node itself). Anything else (nfs, cifs/smb, fuse,
// ceph, 9p, ...) disables the index: the zone scan does not depend on it.
var localFilesystems = map[int64]string{
	0xEF53: "ext4", 0x58465342: "xfs", 0x9123683E: "btrfs", 0x01021994: "tmpfs",
	0x794C7630: "overlay", 0x2FC12FC1: "zfs", 0xF2F52010: "f2fs",
}

// localFilesystem reports whether path (or its nearest existing parent) is
// on a local file system, and the file system's name or magic.
func localFilesystem(path string) (bool, string, error) {
	var stat syscall.Statfs_t
	if err := statfsNearest(path, &stat); err != nil {
		return false, "", err
	}
	if name, ok := localFilesystems[int64(stat.Type)]; ok {
		return true, name, nil
	}
	return false, "0x" + strconv.FormatUint(uint64(uint32(stat.Type)), 16), nil
}
