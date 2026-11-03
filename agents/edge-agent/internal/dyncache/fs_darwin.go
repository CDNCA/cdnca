package dyncache

import "syscall"

// localFilesystem on macOS (development only): apfs and hfs are local.
func localFilesystem(path string) (bool, string, error) {
	var stat syscall.Statfs_t
	if err := statfsNearest(path, &stat); err != nil {
		return false, "", err
	}
	name := make([]byte, 0, len(stat.Fstypename))
	for _, character := range stat.Fstypename {
		if character == 0 {
			break
		}
		name = append(name, byte(character))
	}
	return string(name) == "apfs" || string(name) == "hfs", string(name), nil
}
