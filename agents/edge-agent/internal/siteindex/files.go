package siteindex

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

// Access is who may read the files OpenResty workers open: directories
// 0750 and files 0440 owned by the agent with group GID. GID < 0 keeps the
// process's group (tests, a non-root agent whose primary group is the
// worker group).
type Access struct {
	GID int
}

func (access Access) apply(path string, mode os.FileMode) error {
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	if access.GID >= 0 {
		if err := os.Lchown(path, -1, access.GID); err != nil {
			return err
		}
	}
	return nil
}

// mkdirAll creates root (its parent must exist; its mode is the deployer's)
// and the directories below it up to dir, 0750 with the worker group.
func (access Access) mkdirAll(root, dir string) error {
	relative, err := filepath.Rel(root, dir)
	if err != nil || strings.HasPrefix(relative, "..") {
		return fmt.Errorf("site index: %s is outside %s", dir, root)
	}
	current := root
	for _, part := range append([]string{"."}, strings.Split(relative, string(filepath.Separator))...) {
		if part != "." {
			current = filepath.Join(current, part)
		}
		info, err := os.Lstat(current)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			if err := os.Mkdir(current, 0o750); err != nil && !errors.Is(err, fs.ErrExist) {
				return err
			}
		case err != nil:
			return err
		case info.Mode()&os.ModeSymlink != 0 || !info.IsDir():
			return fmt.Errorf("site index: %s is not a directory", current)
		default:
			continue
		}
		if err := access.apply(current, 0o750); err != nil {
			return err
		}
	}
	return nil
}

func writeAtomic(dir, name string, content []byte, access Access) error {
	temp, err := os.CreateTemp(dir, "."+name+".tmp-")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if _, err := temp.Write(content); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := access.apply(tempPath, 0o440); err != nil {
		return err
	}
	return os.Rename(tempPath, filepath.Join(dir, name))
}

func syncDirectory(dir string) error {
	handle, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}

// Files is the whole-generation index files (contract §5.1):
// <root>/gen-<n>.idx and <root>/current naming the active one.
type Files struct {
	Root   string
	Access Access
}

var generationFile = regexp.MustCompile(`^gen-([1-9][0-9]{0,19})\.idx$`)

func generationName(generation uint64) string {
	return "gen-" + strconv.FormatUint(generation, 10) + ".idx"
}

// Write stores index as gen-<n>.idx (fsynced) without changing current.
func (files Files) Write(index Index) error {
	raw, err := MarshalIndex(index)
	if err != nil {
		return err
	}
	if err := files.Access.mkdirAll(files.Root, files.Root); err != nil {
		return err
	}
	if err := writeAtomic(files.Root, generationName(index.Generation), raw, files.Access); err != nil {
		return err
	}
	return syncDirectory(files.Root)
}

// SetCurrent points current at generation (written before) and removes
// every index file but generation and keep (the previous one; 0 = none).
func (files Files) SetCurrent(generation, keep uint64) error {
	if _, err := os.Stat(filepath.Join(files.Root, generationName(generation))); err != nil {
		return err
	}
	if err := writeAtomic(files.Root, "current", []byte(generationName(generation)+"\n"), files.Access); err != nil {
		return err
	}
	if err := syncDirectory(files.Root); err != nil {
		return err
	}
	entries, err := os.ReadDir(files.Root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		match := generationFile.FindStringSubmatch(entry.Name())
		if match == nil {
			continue
		}
		value, err := strconv.ParseUint(match[1], 10, 64)
		if err != nil || value == generation || value == keep {
			continue
		}
		if err := os.Remove(filepath.Join(files.Root, entry.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

// Previous is the newest index file older than active (SetCurrent keeps it
// as the rollback target); ok is false when there is none.
func (files Files) Previous(active uint64) (uint64, bool) {
	best := uint64(0)
	for _, generation := range files.generations() {
		if generation < active && generation > best {
			best = generation
		}
	}
	return best, best != 0
}

// generations lists the gen-<n>.idx files present.
func (files Files) generations() []uint64 {
	entries, err := os.ReadDir(files.Root)
	if err != nil {
		return nil
	}
	var result []uint64
	for _, entry := range entries {
		if match := generationFile.FindStringSubmatch(entry.Name()); match != nil {
			if value, err := strconv.ParseUint(match[1], 10, 64); err == nil {
				result = append(result, value)
			}
		}
	}
	return result
}

// Current reads the generation current names; ok is false when there is
// none.
func (files Files) Current() (Index, bool, error) {
	raw, err := os.ReadFile(filepath.Join(files.Root, "current"))
	if errors.Is(err, fs.ErrNotExist) {
		return Index{}, false, nil
	}
	if err != nil {
		return Index{}, false, err
	}
	name := strings.TrimSuffix(string(raw), "\n")
	if !generationFile.MatchString(name) || name+"\n" != string(raw) {
		return Index{}, false, fmt.Errorf("%w: current %q", ErrFormat, raw)
	}
	return files.read(name)
}

// Read reads gen-<n>.idx.
func (files Files) Read(generation uint64) (Index, error) {
	index, _, err := files.read(generationName(generation))
	return index, err
}

func (files Files) read(name string) (Index, bool, error) {
	raw, err := os.ReadFile(filepath.Join(files.Root, name))
	if err != nil {
		return Index{}, false, err
	}
	index, err := UnmarshalIndex(raw)
	if err != nil {
		return Index{}, false, err
	}
	if generationName(index.Generation) != name {
		return Index{}, false, fmt.Errorf("%w: %s holds generation %d", ErrFormat, name, index.Generation)
	}
	return index, true, nil
}

// ObjectDir is the worker-readable copy of the objects the request path
// reads (contract §5.5): <root>/sha256/<2>/<2>/<64>, the objectstore layout.
// It holds no secrets: site objects and the objects they reference carry
// none (site-object-v2.md §3).
type ObjectDir struct {
	Root   string
	Access Access
	// External: the directory is the agent's object store opened shared
	// (objectstore.OpenShared), which owns writes and collection: Put only
	// checks that the object is there and Remove and Retain keep everything
	// (the store keeps every owner's current and previous generation).
	External bool
}

func (dir ObjectDir) Path(digest string) string {
	return filepath.Join(dir.Root, "sha256", digest[:2], digest[2:4], digest)
}

// Put stores content under its digest (verified) unless a file of that
// name and size is already there: the directory is content addressed and
// every reader verifies the digest, so a damaged copy is only a missing
// object (Lua answers 503 for it) and Verify finds it.
func (dir ObjectDir) Put(digest string, content []byte) error {
	if _, err := ParseDigest(digest); err != nil || edgesite.Digest(content) != digest {
		return fmt.Errorf("%w: object %s does not match its digest", ErrFormat, digest)
	}
	path := dir.Path(digest)
	if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() && info.Size() == int64(len(content)) {
		return nil
	}
	if dir.External {
		return fmt.Errorf("%w: object %s is not in the object store", ErrFormat, digest)
	}
	parent := filepath.Dir(path)
	if err := dir.Access.mkdirAll(dir.Root, parent); err != nil {
		return err
	}
	return writeAtomicNoSync(parent, digest, content, dir.Access)
}

// writeAtomicNoSync: objects are re-verified by every reader (Lua checks the
// SHA-256), so a torn write after a crash is only a missing object that the
// agent puts again before activating.
func writeAtomicNoSync(dir, name string, content []byte, access Access) error {
	temp, err := os.CreateTemp(dir, "."+name[:8]+".tmp-")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if _, err := temp.Write(content); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := access.apply(tempPath, 0o440); err != nil {
		return err
	}
	return os.Rename(tempPath, filepath.Join(dir, name))
}

// Verify re-reads digest and removes it when its content does not match, so
// the next Put stores it again; it reports whether the object is intact.
func (dir ObjectDir) Verify(digest string) bool {
	content, err := os.ReadFile(dir.Path(digest))
	if err == nil && edgesite.Digest(content) == digest {
		return true
	}
	if err == nil {
		_ = os.Remove(dir.Path(digest))
	}
	return false
}

// Remove deletes one object (absent is fine).
func (dir ObjectDir) Remove(digest string) error {
	if _, err := ParseDigest(digest); err != nil {
		return err
	}
	if dir.External {
		return nil
	}
	if err := os.Remove(dir.Path(digest)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// Retain removes every object not in keep (the current and the previous
// generation's objects) and returns how many it removed.
func (dir ObjectDir) Retain(keep []string) (int, error) {
	if dir.External {
		return 0, nil
	}
	wanted := make(map[string]bool, len(keep))
	for _, digest := range keep {
		wanted[digest] = true
	}
	removed := 0
	base := filepath.Join(dir.Root, "sha256")
	err := filepath.WalkDir(base, func(path string, entry fs.DirEntry, err error) error {
		if errors.Is(err, fs.ErrNotExist) && path == base {
			return filepath.SkipDir
		}
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		name := entry.Name()
		if wanted[name] {
			return nil
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		removed++
		return nil
	})
	return removed, err
}

// List returns the digests stored, sorted (tests and status).
func (dir ObjectDir) List() ([]string, error) {
	var digests []string
	base := filepath.Join(dir.Root, "sha256")
	err := filepath.WalkDir(base, func(path string, entry fs.DirEntry, err error) error {
		if errors.Is(err, fs.ErrNotExist) && path == base {
			return filepath.SkipDir
		}
		if err != nil {
			return err
		}
		if !entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") {
			digests = append(digests, entry.Name())
		}
		return nil
	})
	sort.Strings(digests)
	return digests, err
}
