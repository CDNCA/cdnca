package nativebackup

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Owners maps archived owner names to local IDs. Restoring on another host
// must not trust numeric IDs: the clickhouse or objectstore account usually
// has a different uid there.
type Owners interface {
	Lookup(userName, groupName string, uid, gid int) (int, int, error)
	Chown(path string, uid, gid int) error
}

type osOwners struct{}

func (osOwners) Lookup(userName, groupName string, uid, gid int) (int, int, error) {
	resolvedUID, err := resolveID(userName, uid, func(name string) (string, error) {
		found, err := user.Lookup(name)
		if err != nil {
			return "", err
		}
		return found.Uid, nil
	})
	if err != nil {
		return 0, 0, fmt.Errorf("restore_account_missing:%s", userName)
	}
	resolvedGID, err := resolveID(groupName, gid, func(name string) (string, error) {
		found, err := user.LookupGroup(name)
		if err != nil {
			return "", err
		}
		return found.Gid, nil
	})
	if err != nil {
		return 0, 0, fmt.Errorf("restore_group_missing:%s", groupName)
	}
	return resolvedUID, resolvedGID, nil
}

func resolveID(name string, numeric int, lookup func(string) (string, error)) (int, error) {
	if name == "" || name == "root" {
		if numeric == 0 || name == "root" {
			return 0, nil
		}
		return 0, errors.New("unnamed owner")
	}
	value, err := lookup(name)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(value)
}

func (osOwners) Chown(path string, uid, gid int) error { return os.Lchown(path, uid, gid) }

type TreeStats struct {
	Present []string
	Files   int
	Bytes   int64
}

// ArchiveTree writes the given paths (below layout) as one tar stream. Names
// are the absolute host paths without the leading slash.
func ArchiveTree(layout Layout, paths []treePath, output io.Writer) (TreeStats, error) {
	writer := tar.NewWriter(output)
	var stats TreeStats
	for _, entry := range paths {
		hostPath := layout.Path(entry.Path)
		info, err := os.Lstat(hostPath)
		if errors.Is(err, os.ErrNotExist) {
			if entry.Required {
				return stats, fmt.Errorf("required path is missing: %s", entry.Path)
			}
			continue
		}
		if err != nil {
			return stats, err
		}
		stats.Present = append(stats.Present, entry.Path)
		if !info.IsDir() {
			if err := archiveEntry(writer, hostPath, entry.Path, info, &stats); err != nil {
				return stats, err
			}
			continue
		}
		err = filepath.WalkDir(hostPath, func(current string, directoryEntry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			relative, err := filepath.Rel(hostPath, current)
			if err != nil {
				return err
			}
			relative = filepath.ToSlash(relative)
			if relative != "." && entry.excluded(relative) {
				if directoryEntry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			info, err := directoryEntry.Info()
			if err != nil {
				return err
			}
			name := entry.Path
			if relative != "." {
				name = entry.Path + "/" + relative
			}
			return archiveEntry(writer, current, name, info, &stats)
		})
		if err != nil {
			return stats, err
		}
	}
	return stats, writer.Close()
}

func archiveEntry(writer *tar.Writer, hostPath, name string, info fs.FileInfo, stats *TreeStats) error {
	mode := info.Mode()
	if mode&(fs.ModeSocket|fs.ModeNamedPipe|fs.ModeDevice|fs.ModeCharDevice|fs.ModeIrregular) != 0 {
		return nil // Runtime sockets and devices are recreated by their services.
	}
	link := ""
	if mode&fs.ModeSymlink != 0 {
		target, err := os.Readlink(hostPath)
		if err != nil {
			return err
		}
		link = target
	}
	header, err := tar.FileInfoHeader(info, link)
	if err != nil {
		return err
	}
	header.Name = strings.TrimPrefix(name, "/")
	if info.IsDir() {
		header.Name += "/"
	}
	header.Format = tar.FormatPAX
	header.AccessTime, header.ChangeTime = time.Time{}, time.Time{}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		header.Uid, header.Gid = int(stat.Uid), int(stat.Gid)
		if found, err := user.LookupId(strconv.Itoa(header.Uid)); err == nil {
			header.Uname = found.Username
		}
		if found, err := user.LookupGroupId(strconv.Itoa(header.Gid)); err == nil {
			header.Gname = found.Name
		}
	}
	if err := writer.WriteHeader(header); err != nil {
		return err
	}
	if !mode.IsRegular() {
		return nil
	}
	file, err := os.Open(hostPath)
	if err != nil {
		return err
	}
	defer file.Close()
	written, err := io.Copy(writer, file)
	if err != nil {
		return err
	}
	if written != header.Size {
		return fmt.Errorf("file changed while archiving: %s", name)
	}
	stats.Files++
	stats.Bytes += written
	return nil
}

// CheckTreeAbsent is the restore preflight: every archived top-level path
// must be absent on the target (an empty directory counts as absent).
func CheckTreeAbsent(layout Layout, present []string) error {
	for _, path := range present {
		if err := checkAbsent(layout.Path(path)); err != nil {
			return fmt.Errorf("restore_target_not_empty:%s", path)
		}
	}
	return nil
}

func checkAbsent(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.IsDir() {
		return errors.New("exists")
	}
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 0 {
		return errors.New("exists")
	}
	return nil
}

type deferredDirectory struct {
	path  string
	mode  os.FileMode
	mtime time.Time
}

// ExtractTree restores a stream written by ArchiveTree. Only names below the
// allowed top-level paths are accepted, nothing existing is overwritten, and
// ownership is resolved by name.
func ExtractTree(layout Layout, allowed []treePath, owners Owners, input io.Reader) ([]string, error) {
	reader := tar.NewReader(input)
	created := map[string]bool{}
	var directories []deferredDirectory
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return sortedKeys(created), ErrArtifactCorrupt
		}
		name := "/" + strings.TrimSuffix(header.Name, "/")
		if filepath.Clean(name) != name || strings.Contains(header.Name, "..") {
			return sortedKeys(created), ErrArtifactCorrupt
		}
		top := ""
		for _, entry := range allowed {
			if name == entry.Path || strings.HasPrefix(name, entry.Path+"/") {
				top = entry.Path
				break
			}
		}
		if top == "" {
			return sortedKeys(created), fmt.Errorf("archive entry outside the allowed paths: %s", name)
		}
		target := layout.Path(name)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return sortedKeys(created), err
		}
		created[top] = true
		uid, gid, err := owners.Lookup(header.Uname, header.Gname, header.Uid, header.Gid)
		if err != nil {
			return sortedKeys(created), err
		}
		mode := os.FileMode(header.Mode & 0o7777)
		if header.Mode&04000 != 0 {
			mode |= os.ModeSetuid
		}
		if header.Mode&02000 != 0 {
			mode |= os.ModeSetgid
		}
		if header.Mode&01000 != 0 {
			mode |= os.ModeSticky
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.Mkdir(target, 0o700); err != nil && !(errors.Is(err, os.ErrExist) && name == top && checkAbsent(target) == nil) {
				return sortedKeys(created), fmt.Errorf("restore_target_not_empty:%s", name)
			}
			if err := owners.Chown(target, uid, gid); err != nil {
				return sortedKeys(created), err
			}
			directories = append(directories, deferredDirectory{path: target, mode: mode, mtime: header.ModTime})
		case tar.TypeReg:
			file, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				return sortedKeys(created), fmt.Errorf("restore_target_not_empty:%s", name)
			}
			written, copyErr := io.Copy(file, reader)
			syncErr := file.Sync()
			closeErr := file.Close()
			if copyErr != nil || syncErr != nil || closeErr != nil || written != header.Size {
				return sortedKeys(created), errors.Join(ErrArtifactCorrupt, copyErr)
			}
			if err := owners.Chown(target, uid, gid); err != nil {
				return sortedKeys(created), err
			}
			if err := os.Chmod(target, mode); err != nil {
				return sortedKeys(created), err
			}
			_ = os.Chtimes(target, header.ModTime, header.ModTime)
		case tar.TypeSymlink:
			if err := os.Symlink(header.Linkname, target); err != nil {
				return sortedKeys(created), fmt.Errorf("restore_target_not_empty:%s", name)
			}
			if err := owners.Chown(target, uid, gid); err != nil {
				return sortedKeys(created), err
			}
		case tar.TypeLink:
			source := layout.Path("/" + strings.TrimPrefix(header.Linkname, "/"))
			if err := os.Link(source, target); err != nil {
				return sortedKeys(created), ErrArtifactCorrupt
			}
		default:
			return sortedKeys(created), ErrArtifactCorrupt
		}
	}
	// Apply directory modes last (deepest first) so read-only directories
	// could still be populated.
	for index := len(directories) - 1; index >= 0; index-- {
		directory := directories[index]
		if err := os.Chmod(directory.path, directory.mode); err != nil {
			return sortedKeys(created), err
		}
		_ = os.Chtimes(directory.path, directory.mtime, directory.mtime)
	}
	for _, directory := range directories {
		_ = syncDirectory(directory.path)
	}
	return sortedKeys(created), nil
}

// RemoveTrees is the compensation for a failed tree restore.
func RemoveTrees(layout Layout, paths []string) error {
	var joined error
	for _, path := range paths {
		if err := os.RemoveAll(layout.Path(path)); err != nil {
			joined = errors.Join(joined, err)
		}
	}
	return joined
}

func sortedKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func presentDetail(stats TreeStats) map[string]string {
	return map[string]string{"paths": strings.Join(stats.Present, ","), "files": strconv.Itoa(stats.Files), "bytes": strconv.FormatInt(stats.Bytes, 10)}
}

func presentPaths(detail map[string]string) []string {
	if detail["paths"] == "" {
		return nil
	}
	return strings.Split(detail["paths"], ",")
}

// SystemOwners resolves archived owner names through the host account database.
func SystemOwners() Owners { return osOwners{} }
