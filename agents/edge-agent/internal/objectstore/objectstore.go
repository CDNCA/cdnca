// Package objectstore is the edge agent's content-addressed object store
// (ADR 0009 section 8.2): <root>/sha256/<2>/<2>/<64 hex>, one immutable file
// per object named by the SHA-256 of its bytes. Writers verify the digest
// before an object becomes visible; readers verify it again and drop a
// corrupted file so it is fetched anew.
//
// Each owner (a configuration scope's site objects, the node artifact set)
// commits the complete set of objects its active generation references. The
// store keeps the current and the previous generation of every owner, plus
// the objects staged by in-flight fetches, and Collect removes the rest.
package objectstore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
)

var (
	ErrDigest   = errors.New("object store: digest mismatch or invalid digest")
	ErrNotFound = errors.New("object store: object not found")
	ErrOwner    = errors.New("object store: invalid owner")
	ErrRoot     = errors.New("object store: unsafe root")

	digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	ownerPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
)

const refsSchema = "cdnca.edge.object-refs/v1"

type Store struct {
	root string
	// gid >= 0: objects and their directories are readable by that group
	// (OpenShared); -1: private to the agent.
	gid int

	mu     sync.Mutex
	staged map[string]int
}

type refs struct {
	Schema   string   `json:"schema"`
	Owner    string   `json:"owner"`
	Current  []string `json:"current"`
	Previous []string `json:"previous"`
}

// Open creates or opens the store rooted at root (a clean absolute path that
// is not a symlink) and removes writes interrupted by a crash.
func Open(root string) (*Store, error) { return open(root, -1) }

// OpenShared opens the store with its objects readable by group gid (the
// OpenResty workers of a dynamic routing node read site objects in place,
// ADR 0009 D3): sha256/ directories 0750 and objects 0440 with that group;
// refs/ and tmp/ stay private. The workers verify every object they read.
func OpenShared(root string, gid int) (*Store, error) {
	if gid < 0 {
		return nil, fmt.Errorf("%w: shared store needs a group", ErrRoot)
	}
	return open(root, gid)
}

func open(root string, gid int) (*Store, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root || filepath.Dir(root) == root {
		return nil, fmt.Errorf("%w: %q", ErrRoot, root)
	}
	if info, err := os.Lstat(root); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.IsDir()) {
		return nil, fmt.Errorf("%w: %s is not a directory", ErrRoot, root)
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("inspect object store root: %w", err)
	}
	store := &Store{root: root, gid: gid, staged: map[string]int{}}
	for _, dir := range []string{root, store.objectsDir(), store.refsDir(), store.tempDir()} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create object store directory: %w", err)
		}
		if info, err := os.Lstat(dir); err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, fmt.Errorf("%w: %s", ErrRoot, dir)
		}
	}
	if gid >= 0 {
		for _, dir := range []string{root, store.objectsDir()} {
			if err := store.share(dir, 0o750); err != nil {
				return nil, err
			}
		}
	}
	entries, err := os.ReadDir(store.tempDir())
	if err != nil {
		return nil, fmt.Errorf("read object store temp directory: %w", err)
	}
	for _, entry := range entries {
		if err := os.RemoveAll(filepath.Join(store.tempDir(), entry.Name())); err != nil {
			return nil, fmt.Errorf("remove interrupted object write: %w", err)
		}
	}
	return store, nil
}

func (s *Store) Root() string { return s.root }

// share gives path mode with the store's group.
func (s *Store) share(path string, mode os.FileMode) error {
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("share object store path: %w", err)
	}
	if err := os.Lchown(path, -1, s.gid); err != nil {
		return fmt.Errorf("share object store path: %w", err)
	}
	return nil
}

func (s *Store) objectsDir() string { return filepath.Join(s.root, "sha256") }
func (s *Store) refsDir() string    { return filepath.Join(s.root, "refs") }
func (s *Store) tempDir() string    { return filepath.Join(s.root, "tmp") }

// Path is the file of an object; digest must be valid.
func (s *Store) Path(digest string) string {
	return filepath.Join(s.objectsDir(), digest[:2], digest[2:4], digest)
}

func validDigest(digest string) bool { return digestPattern.MatchString(digest) }

func digestOf(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// Has reports whether an object file exists (without verifying it).
func (s *Store) Has(digest string) bool {
	if !validDigest(digest) {
		return false
	}
	info, err := os.Lstat(s.Path(digest))
	return err == nil && info.Mode().IsRegular()
}

// Get returns a verified object. A file whose bytes are not its digest is
// removed and reported as ErrDigest.
func (s *Store) Get(digest string) ([]byte, error) {
	if !validDigest(digest) {
		return nil, fmt.Errorf("%w: %q", ErrDigest, digest)
	}
	path := s.Path(digest)
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, digest)
	}
	if err != nil {
		return nil, fmt.Errorf("inspect object %s: %w", digest, err)
	}
	if !info.Mode().IsRegular() {
		s.drop(path)
		return nil, fmt.Errorf("%w: object %s is not a regular file", ErrDigest, digest)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read object %s: %w", digest, err)
	}
	if digestOf(content) != digest {
		s.drop(path)
		return nil, fmt.Errorf("%w: stored object %s is corrupted", ErrDigest, digest)
	}
	return content, nil
}

func (s *Store) drop(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = os.Remove(path)
}

// Missing returns, in first-seen order and once each, the digests that are
// not stored as verified objects. Corrupted files are removed.
func (s *Store) Missing(digests []string) ([]string, error) {
	seen := make(map[string]struct{}, len(digests))
	var missing []string
	for _, digest := range digests {
		if _, duplicate := seen[digest]; duplicate {
			continue
		}
		seen[digest] = struct{}{}
		if !validDigest(digest) {
			return nil, fmt.Errorf("%w: %q", ErrDigest, digest)
		}
		if _, err := s.Get(digest); err != nil {
			if errors.Is(err, ErrNotFound) || errors.Is(err, ErrDigest) {
				missing = append(missing, digest)
				continue
			}
			return nil, err
		}
	}
	return missing, nil
}

// Put stores content under digest after checking that it is the content's
// SHA-256. The write is atomic (rename) but not synced: every read verifies
// the digest, so an object lost or torn by a crash is only missing and is
// fetched again (per-object fsync dominated a first delivery). An existing
// object is kept.
func (s *Store) Put(digest string, content []byte) error {
	if !validDigest(digest) || digestOf(content) != digest {
		return fmt.Errorf("%w: %q", ErrDigest, digest)
	}
	if existing, err := s.Get(digest); err == nil && bytes.Equal(existing, content) {
		return nil
	}
	path := s.Path(digest)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create object directory: %w", err)
	}
	mode := os.FileMode(0o400)
	if s.gid >= 0 {
		mode = 0o440
		for _, shared := range []string{filepath.Dir(dir), dir} {
			if err := s.share(shared, 0o750); err != nil {
				return err
			}
		}
	}
	temp, err := os.CreateTemp(s.tempDir(), "put-")
	if err != nil {
		return fmt.Errorf("create object temp file: %w", err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if _, err := temp.Write(content); err != nil {
		temp.Close()
		return fmt.Errorf("write object: %w", err)
	}
	if err := temp.Chmod(mode); err != nil {
		temp.Close()
		return fmt.Errorf("chmod object: %w", err)
	}
	if s.gid >= 0 {
		if err := temp.Chown(-1, s.gid); err != nil {
			temp.Close()
			return fmt.Errorf("chown object: %w", err)
		}
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close object: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("publish object: %w", err)
	}
	return nil
}

func syncDir(dir string) error {
	handle, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open object directory: %w", err)
	}
	defer handle.Close()
	if err := handle.Sync(); err != nil {
		return fmt.Errorf("sync object directory: %w", err)
	}
	return nil
}

// Stage protects digests from Collect while a fetch that will reference them
// is in flight (in this process). The returned function releases them.
func (s *Store) Stage(digests []string) (release func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	held := append([]string(nil), digests...)
	for _, digest := range held {
		s.staged[digest]++
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			for _, digest := range held {
				if s.staged[digest]--; s.staged[digest] <= 0 {
					delete(s.staged, digest)
				}
			}
		})
	}
}

// Commit records digests as owner's current generation; the generation it
// replaces becomes the previous one (re-committing the current set keeps
// the previous generation). Every object must be stored.
func (s *Store) Commit(owner string, digests []string) error {
	if !ownerPattern.MatchString(owner) {
		return fmt.Errorf("%w: %q", ErrOwner, owner)
	}
	current := uniqueSorted(digests)
	for _, digest := range current {
		if !s.Has(digest) {
			return fmt.Errorf("%w: %s", ErrNotFound, digest)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, err := s.readRefs(owner)
	if err != nil {
		return err
	}
	next := refs{Schema: refsSchema, Owner: owner, Current: current, Previous: existing.Previous}
	if !equalStrings(existing.Current, current) {
		next.Previous = existing.Current
	}
	if next.Previous == nil {
		next.Previous = []string{}
	}
	content, err := json.Marshal(next)
	if err != nil {
		return fmt.Errorf("encode object references: %w", err)
	}
	temp, err := os.CreateTemp(s.tempDir(), "refs-")
	if err != nil {
		return fmt.Errorf("create object references: %w", err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if _, err := temp.Write(content); err != nil {
		temp.Close()
		return fmt.Errorf("write object references: %w", err)
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return fmt.Errorf("sync object references: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close object references: %w", err)
	}
	if err := os.Rename(tempPath, filepath.Join(s.refsDir(), owner+".json")); err != nil {
		return fmt.Errorf("publish object references: %w", err)
	}
	return syncDir(s.refsDir())
}

// Current returns owner's current generation (sorted; empty when owner has
// never committed).
func (s *Store) Current(owner string) ([]string, error) {
	if !ownerPattern.MatchString(owner) {
		return nil, fmt.Errorf("%w: %q", ErrOwner, owner)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	value, err := s.readRefs(owner)
	if err != nil {
		return nil, err
	}
	return append([]string{}, value.Current...), nil
}

func (s *Store) readRefs(owner string) (refs, error) {
	content, err := os.ReadFile(filepath.Join(s.refsDir(), owner+".json"))
	if errors.Is(err, fs.ErrNotExist) {
		return refs{}, nil
	}
	if err != nil {
		return refs{}, fmt.Errorf("read object references of %s: %w", owner, err)
	}
	var value refs
	if err := json.Unmarshal(content, &value); err != nil || value.Schema != refsSchema || value.Owner != owner {
		return refs{}, fmt.Errorf("object references of %s are corrupted", owner)
	}
	for _, digest := range append(append([]string(nil), value.Current...), value.Previous...) {
		if !validDigest(digest) {
			return refs{}, fmt.Errorf("object references of %s are corrupted", owner)
		}
	}
	return value, nil
}

// Collect removes every object that no owner's current or previous
// generation references and no in-flight fetch has staged. It refuses to
// collect anything when a reference file cannot be read.
func (s *Store) Collect() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	keep := make(map[string]struct{}, len(s.staged))
	for digest := range s.staged {
		keep[digest] = struct{}{}
	}
	entries, err := os.ReadDir(s.refsDir())
	if err != nil {
		return 0, fmt.Errorf("read object references: %w", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		owner := name[:len(name)-len(filepath.Ext(name))]
		if filepath.Ext(name) != ".json" || !ownerPattern.MatchString(owner) {
			return 0, fmt.Errorf("unexpected object reference file %s", name)
		}
		value, err := s.readRefs(owner)
		if err != nil {
			return 0, err
		}
		for _, digest := range value.Current {
			keep[digest] = struct{}{}
		}
		for _, digest := range value.Previous {
			keep[digest] = struct{}{}
		}
	}
	removed := 0
	err = filepath.WalkDir(s.objectsDir(), func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if _, referenced := keep[entry.Name()]; referenced && validDigest(entry.Name()) && path == s.Path(entry.Name()) {
			return nil
		}
		if err := os.Remove(path); err != nil {
			return err
		}
		removed++
		return nil
	})
	if err != nil {
		return removed, fmt.Errorf("collect objects: %w", err)
	}
	return removed, nil
}

func uniqueSorted(values []string) []string {
	result := append([]string{}, values...)
	sort.Strings(result)
	unique := result[:0]
	for index, value := range result {
		if index == 0 || value != result[index-1] {
			unique = append(unique, value)
		}
	}
	return unique
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
