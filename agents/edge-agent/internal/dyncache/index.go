// Purge index: a
// per-zone bbolt file mapping the zone's cache files to their keys, so a
// directory, prefix or wildcard purge reads a key range instead of opening
// every file of the zone. Indexes (indexes.go) runs one per zone on the
// node, with its fallbacks to the zone scan.
//
// The index follows the disk, not the requests: Sync stats the zone's
// 16+4096 level directories and re-reads only those whose mtime changed
// (a file created, renamed in or unlinked changes its directory's mtime),
// diffing the names against the index; only new names are opened. So the
// index is complete without any report from OpenResty, survives agent
// restarts, and a purge runs Sync first: every file on disk when the purge
// starts is in the index (a file the purge does not see is one filled after
// it started, as with the zone scan).
//
// Correctness first: a directory whose mtime is within Settle of its
// listing is listed again next time (coarse mtime ticks, the "racy" case);
// an index that is not complete, cannot be opened or fails is not used and
// the caller falls back to the zone scan; a candidate is removed only after
// the same Target.matches as the scan accepts its key.
package dyncache

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	bucketMeta  = []byte("meta")  // "complete" -> 1, "objects" -> files indexed (8 bytes), "layout" -> Indexes' layout
	bucketDirs  = []byte("dirs")  // "<l1>/<l2>" -> mtime (unix ns, 8 bytes)
	bucketFiles = []byte("files") // dir id (2) + md5 (16) -> raw key ("" not a dynamic routing key)
	bucketSites = []byte("sites") // site key (siteKey) -> dir id (2) + md5 (16)
)

// ErrIndexUnavailable: the index cannot answer (not built, failed); the
// caller scans the zone.
var ErrIndexUnavailable = errors.New("purge index unavailable")

// ZoneIndex indexes one zone directory.
type ZoneIndex struct {
	Dir  string // the zone directory (Zones.ZoneOf)
	Path string // the index file
	// Settle: a directory listed less than Settle after its mtime is listed
	// again on the next Sync (default 2s).
	Settle time.Duration
	Now    func() time.Time
	db     *bolt.DB
	mu     sync.Mutex
}

// OpenZoneIndex opens (creates) the index file of a zone. path must not be
// inside the zone directory (the cache manager owns every file there).
func OpenZoneIndex(dir, path string) (*ZoneIndex, error) {
	if rel, err := filepath.Rel(dir, path); err == nil && !strings.HasPrefix(rel, "..") {
		return nil, fmt.Errorf("%w: index %s inside zone %s", ErrInvalid, path, dir)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	// NoSync: the index is a cache of the disk; a crash that loses the last
	// transactions leaves directories whose recorded mtime is old, which the
	// next Sync lists again. A file bbolt cannot open is removed and rebuilt.
	options := &bolt.Options{Timeout: time.Second, NoSync: true, NoFreelistSync: true, FreelistType: bolt.FreelistMapType}
	db, err := bolt.Open(path, 0o600, options)
	if err != nil && !errors.Is(err, bolt.ErrTimeout) {
		_ = os.Remove(path)
		db, err = bolt.Open(path, 0o600, options)
	}
	if err != nil {
		return nil, err
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{bucketMeta, bucketDirs, bucketFiles, bucketSites} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		db.Close()
		return nil, err
	}
	return &ZoneIndex{Dir: dir, Path: path, Settle: 2 * time.Second, Now: time.Now, db: db}, nil
}

// Objects is how many cache files the index holds.
func (index *ZoneIndex) Objects() int64 {
	var count int64
	_ = index.db.View(func(tx *bolt.Tx) error {
		count = metaCount(tx.Bucket(bucketMeta))
		return nil
	})
	return count
}

func metaCount(meta *bolt.Bucket) int64 {
	if value := meta.Get([]byte("objects")); len(value) == 8 {
		return int64(binary.BigEndian.Uint64(value))
	}
	return 0
}

func addCount(meta *bolt.Bucket, delta int64) error {
	if delta == 0 {
		return nil
	}
	return meta.Put([]byte("objects"), binary.BigEndian.AppendUint64(nil, uint64(max(metaCount(meta)+delta, 0))))
}

// Meta / SetMeta: a value the index owner keeps with the index (Indexes:
// the zone layout the index was built for).
func (index *ZoneIndex) Meta(name string) []byte {
	var value []byte
	_ = index.db.View(func(tx *bolt.Tx) error {
		value = slices.Clone(tx.Bucket(bucketMeta).Get([]byte("x-" + name)))
		return nil
	})
	return value
}

func (index *ZoneIndex) SetMeta(name string, value []byte) error {
	return index.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucketMeta).Put([]byte("x-"+name), value) })
}

// Close closes the index file.
func (index *ZoneIndex) Close() error { return index.db.Close() }

// Complete: a Sync has listed every directory of the zone since the index
// file was created.
func (index *ZoneIndex) Complete() bool { return index.complete() }

// fileID is a cache file name as the files bucket keys it: the level
// directories (2 bytes) then md5 (16 bytes); ordered like the names.
func fileID(dir [2]byte, name string) ([]byte, bool) {
	if len(name) != 32 {
		return nil, false
	}
	digest, err := hex.DecodeString(name)
	if err != nil || name != strings.ToLower(name) {
		return nil, false
	}
	return append(dir[:], digest...), true
}

func (index *ZoneIndex) pathOf(id []byte) string {
	name := hex.EncodeToString(id[2:])
	return filepath.Join(index.Dir, name[31:], name[29:31], name)
}

// reverseHost orders hosts by their labels from the right, so every host
// under a suffix (and "*.<suffix>") is one key range.
func reverseHost(host string) string {
	labels := strings.Split(host, ".")
	slices.Reverse(labels)
	return strings.Join(labels, ".")
}

func siteRange(prefix string) []byte {
	value, _ := hex.DecodeString(prefix)
	return value
}

// siteKey: site (16) | reversed host | 0 | port (2) | path | 0 | file id.
func siteKey(key Key, id []byte) []byte {
	value := siteRange(key.Prefix)
	value = append(value, reverseHost(key.Host)...)
	value = append(value, 0)
	value = binary.BigEndian.AppendUint16(value, uint16(key.Port))
	value = append(value, key.Path...)
	value = append(value, 0)
	return append(value, id...)
}

// targetRange is a key range holding every object Target.matches can accept
// (a superset: matches decides).
func targetRange(site Site, target Target) []byte {
	value := siteRange(site.Prefix)
	if target.WildcardSuffix != "" && site.KeyByHost {
		// "*.<suffix>" and every "<name>.<suffix>"
		return append(value, reverseHost(target.WildcardSuffix)+"."...)
	}
	host := site.keyName(target.Host)
	if target.WildcardSuffix != "" {
		host = site.Domain
	}
	value = append(value, reverseHost(host)...)
	value = append(value, 0)
	value = binary.BigEndian.AppendUint16(value, uint16(target.Port))
	// every key matches accepts starts with the target's path: the path
	// itself, its directory ("/d" covers "/d/..."), its query variants
	return append(value, target.Path...)
}

// SyncStats of one Sync.
type SyncStats struct {
	Dirs, Listed, Added, Removed, Unreadable int
}

type dirState struct {
	id    [2]byte
	path  string
	mtime int64 // 0: not on disk
}

// levelDirs lists the zone's level directories (levels=1:2) with their mtimes.
func (index *ZoneIndex) levelDirs() ([]dirState, error) {
	first, err := os.ReadDir(index.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var dirs []dirState
	for _, one := range first {
		high, ok := hexNibble(one.Name())
		if !ok || !one.IsDir() {
			continue
		}
		second, err := os.ReadDir(filepath.Join(index.Dir, one.Name()))
		if err != nil {
			return nil, err
		}
		for _, two := range second {
			if len(two.Name()) != 2 || !two.IsDir() {
				continue
			}
			value, err := hex.DecodeString(two.Name())
			if err != nil || two.Name() != strings.ToLower(two.Name()) {
				continue
			}
			info, err := two.Info()
			if err != nil {
				return nil, err
			}
			dirs = append(dirs, dirState{id: [2]byte{high, value[0]}, path: filepath.Join(index.Dir, one.Name(), two.Name()),
				mtime: info.ModTime().UnixNano()})
		}
	}
	return dirs, nil
}

func hexNibble(name string) (byte, bool) {
	if len(name) != 1 {
		return 0, false
	}
	switch character := name[0]; {
	case character >= '0' && character <= '9':
		return character - '0', true
	case character >= 'a' && character <= 'f':
		return character - 'a' + 10, true
	}
	return 0, false
}

func dirPath(root string, id [2]byte) string {
	return filepath.Join(root, fmt.Sprintf("%x", id[0]), fmt.Sprintf("%02x", id[1]))
}

// dirRecord: mtime (8) + racy (1).
func dirRecord(mtime int64, racy bool) []byte {
	value := binary.BigEndian.AppendUint64(nil, uint64(mtime))
	if racy {
		return append(value, 1)
	}
	return append(value, 0)
}

// Sync brings the index up to the zone: every level directory whose mtime
// changed since it was last listed (or that was listed too soon after a
// change) is listed again and diffed. A full pass marks the index complete.
func (index *ZoneIndex) Sync(ctx context.Context) (SyncStats, error) {
	index.mu.Lock()
	defer index.mu.Unlock()
	return index.sync(ctx)
}

func (index *ZoneIndex) sync(ctx context.Context) (SyncStats, error) {
	var stats SyncStats
	onDisk, err := index.levelDirs()
	if err != nil {
		return stats, err
	}
	recorded := map[[2]byte][]byte{}
	if err := index.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketDirs).ForEach(func(key, value []byte) error {
			recorded[[2]byte(key)] = slices.Clone(value)
			return nil
		})
	}); err != nil {
		return stats, err
	}
	var work []dirState
	seen := map[[2]byte]bool{}
	for _, dir := range onDisk {
		seen[dir.id] = true
		if record, ok := recorded[dir.id]; ok && len(record) == 9 && record[8] == 0 &&
			int64(binary.BigEndian.Uint64(record)) == dir.mtime {
			continue
		}
		work = append(work, dir)
	}
	for id := range recorded {
		if !seen[id] {
			work = append(work, dirState{id: id, path: dirPath(index.Dir, id)}) // gone: drop its files
		}
	}
	stats.Dirs = len(onDisk)
	slices.SortFunc(work, func(left, right dirState) int { return bytes.Compare(left.id[:], right.id[:]) })
	const group = 32
	for start := 0; start < len(work); start += group {
		if err := ctx.Err(); err != nil {
			return stats, err
		}
		if err := index.db.Update(func(tx *bolt.Tx) error {
			for _, dir := range work[start:min(start+group, len(work))] {
				if err := index.syncDir(ctx, tx, dir, &stats); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return stats, err
		}
	}
	return stats, index.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketMeta).Put([]byte("complete"), []byte{1})
	})
}

// syncDir lists one level directory and applies the difference.
func (index *ZoneIndex) syncDir(ctx context.Context, tx *bolt.Tx, dir dirState, stats *SyncStats) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	files, sites, dirs := tx.Bucket(bucketFiles), tx.Bucket(bucketSites), tx.Bucket(bucketDirs)
	listedAt := index.Now()
	info, err := os.Lstat(dir.path)
	var names []string
	mtime := int64(0)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return err
	default:
		mtime = info.ModTime().UnixNano()
		entries, err := os.ReadDir(dir.path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		for _, entry := range entries {
			if len(entry.Name()) == 32 && entry.Type().IsRegular() {
				names = append(names, entry.Name())
			}
		}
	}
	stats.Listed++
	addedBefore := stats.Added
	var indexed [][]byte
	cursor := files.Cursor()
	for key, _ := cursor.Seek(dir.id[:]); key != nil && bytes.HasPrefix(key, dir.id[:]); key, _ = cursor.Next() {
		indexed = append(indexed, slices.Clone(key))
	}
	present := map[string]bool{}
	racy := mtime != 0 && listedAt.Sub(time.Unix(0, mtime)) < index.Settle
	for _, name := range names {
		id, ok := fileID(dir.id, name)
		if !ok {
			continue
		}
		present[string(id)] = true
		if files.Get(id) != nil {
			continue
		}
		raw, _, err := readKey(filepath.Join(dir.path, name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			// not a cache file (yet): not indexed, the directory is listed
			// again next time
			stats.Unreadable++
			racy = true
			continue
		}
		if err := files.Put(id, []byte(raw)); err != nil {
			return err
		}
		if key, ok := ParseKey(raw); ok {
			if err := sites.Put(siteKey(key, id), nil); err != nil {
				return err
			}
		}
		stats.Added++
	}
	removed := 0
	for _, id := range indexed {
		if present[string(id)] {
			continue
		}
		if _, err := index.drop(files, sites, id); err != nil {
			return err
		}
		removed++
	}
	stats.Removed += removed
	if err := addCount(tx.Bucket(bucketMeta), int64(stats.Added-addedBefore-removed)); err != nil {
		return err
	}
	if mtime == 0 {
		return dirs.Delete(dir.id[:])
	}
	return dirs.Put(dir.id[:], dirRecord(mtime, racy))
}

// drop removes a file from the index; false: it was not indexed.
func (index *ZoneIndex) drop(files, sites *bolt.Bucket, id []byte) (bool, error) {
	raw := files.Get(id)
	if raw == nil {
		return false, nil
	}
	if key, ok := ParseKey(string(raw)); ok {
		if err := sites.Delete(siteKey(key, id)); err != nil {
			return false, err
		}
	}
	return true, files.Delete(id)
}

type candidate struct {
	id  []byte
	key Key
}

// removeBatch bounds what one step of a purge holds in memory and in one
// write transaction (a variable for the tests).
var removeBatch = 4096

// walk reads the candidates of the ranges that accept accepts, up to
// removeBatch at a time, and hands each batch to step outside the read
// transaction; the next batch starts after the last key read, so step may
// remove what it was given.
func (index *ZoneIndex) walk(ctx context.Context, ranges [][]byte, accept func(Key) bool, step func([]candidate) error) error {
	for _, start := range ranges {
		from := start
		for from != nil {
			if err := ctx.Err(); err != nil {
				return err
			}
			var found []candidate
			var next []byte
			if err := index.db.View(func(tx *bolt.Tx) error {
				files, cursor := tx.Bucket(bucketFiles), tx.Bucket(bucketSites).Cursor()
				key, _ := cursor.Seek(from)
				for ; key != nil && bytes.HasPrefix(key, start) && len(found) < removeBatch; key, _ = cursor.Next() {
					id := key[len(key)-18:]
					if parsed, ok := ParseKey(string(files.Get(id))); ok && accept(parsed) {
						found = append(found, candidate{id: slices.Clone(id), key: parsed})
					}
				}
				if key != nil && bytes.HasPrefix(key, start) {
					next = slices.Clone(key) // not read yet: the next step starts here
				}
				return nil
			}); err != nil {
				return fmt.Errorf("%w: %v", ErrIndexUnavailable, err)
			}
			if err := step(found); err != nil {
				return err
			}
			from = next
		}
	}
	return nil
}

// synced: the index is complete and brought up to the zone (a purge's first
// step: an object on disk when the purge starts is indexed).
func (index *ZoneIndex) synced(ctx context.Context) error {
	if !index.complete() {
		return ErrIndexUnavailable
	}
	if _, err := index.sync(ctx); err != nil {
		return fmt.Errorf("%w: %v", ErrIndexUnavailable, err)
	}
	return nil
}

// remove syncs, then removes every indexed object of the ranges that accept
// accepts, batch by batch (its memory does not grow with the purge).
func (index *ZoneIndex) remove(ctx context.Context, ranges [][]byte, accept func(Key) bool) (Result, error) {
	index.mu.Lock()
	defer index.mu.Unlock()
	var result Result
	if err := index.synced(ctx); err != nil {
		return result, err
	}
	err := index.walk(ctx, ranges, accept, func(found []candidate) error {
		return index.db.Update(func(tx *bolt.Tx) error {
			files, sites := tx.Bucket(bucketFiles), tx.Bucket(bucketSites)
			dropped := 0
			for _, item := range found {
				path := index.pathOf(item.id)
				info, err := os.Lstat(path)
				if err != nil && !errors.Is(err, os.ErrNotExist) {
					return err
				}
				if err == nil && info.Mode().IsRegular() {
					entry := entryOf(path, item.key, info)
					removed, err := remove(entry)
					if err != nil {
						return err
					}
					if removed {
						result.Affected++
						result.Bytes += entry.Size
					}
				}
				ok, err := index.drop(files, sites, item.id)
				if err != nil {
					return err
				}
				if ok {
					dropped++
				}
			}
			return addCount(tx.Bucket(bucketMeta), -int64(dropped))
		})
	})
	return result, err
}

// FileID is a cache file's identity in the index (from its path's name).
type FileID [18]byte

// fileIDOf: the file name's level directories are its last hex digits.
func fileIDOf(path string) (FileID, bool) {
	name := filepath.Base(path)
	if len(name) != 32 {
		return FileID{}, false
	}
	high, ok := hexNibble(name[31:])
	if !ok {
		return FileID{}, false
	}
	low, err := hex.DecodeString(name[29:31])
	if err != nil {
		return FileID{}, false
	}
	id, ok := fileID([2]byte{high, low[0]}, name)
	if !ok {
		return FileID{}, false
	}
	return FileID(id), true
}

// Candidates syncs and returns, without removing anything, what Purge would
// remove for the targets, and when the sync started (the shadow check:
// a file filled after that is not the index's to know).
func (index *ZoneIndex) Candidates(ctx context.Context, site Site, targets []Target, prefix bool) (map[FileID]bool, time.Time, error) {
	ranges, accept := purgeRanges(site, targets, prefix)
	return index.candidates(ctx, ranges, accept)
}

// SiteCandidates: PurgeSite's candidates.
func (index *ZoneIndex) SiteCandidates(ctx context.Context, site Site, generation uint64) (map[FileID]bool, time.Time, error) {
	ranges, accept := siteRanges(site, generation)
	return index.candidates(ctx, ranges, accept)
}

func (index *ZoneIndex) candidates(ctx context.Context, ranges [][]byte, accept func(Key) bool) (map[FileID]bool, time.Time, error) {
	index.mu.Lock()
	defer index.mu.Unlock()
	started := index.Now()
	if err := index.synced(ctx); err != nil {
		return nil, started, err
	}
	found := map[FileID]bool{}
	err := index.walk(ctx, ranges, accept, func(batch []candidate) error {
		for _, item := range batch {
			found[FileID(item.id)] = true
		}
		return nil
	})
	return found, started, err
}

func (index *ZoneIndex) complete() bool {
	complete := false
	_ = index.db.View(func(tx *bolt.Tx) error {
		complete = bytes.Equal(tx.Bucket(bucketMeta).Get([]byte("complete")), []byte{1})
		return nil
	})
	return complete
}

// Purge is Zones.Purge's scan through the index: the same targets, the same
// Target.matches on every candidate's key.
func (index *ZoneIndex) Purge(ctx context.Context, site Site, targets []Target, prefix bool) (Result, error) {
	ranges, accept := purgeRanges(site, targets, prefix)
	return index.remove(ctx, ranges, accept)
}

func purgeRanges(site Site, targets []Target, prefix bool) ([][]byte, func(Key) bool) {
	ranges := make([][]byte, len(targets))
	for position, target := range targets {
		ranges[position] = targetRange(site, target)
	}
	return ranges, func(key Key) bool {
		return slices.ContainsFunc(targets, func(target Target) bool { return target.matches(site, key, prefix) })
	}
}

// PurgeSite removes the site's objects of generations before generation
// (Zones.PurgeSite after the bump).
func (index *ZoneIndex) PurgeSite(ctx context.Context, site Site, generation uint64) (Result, error) {
	ranges, accept := siteRanges(site, generation)
	return index.remove(ctx, ranges, accept)
}

func siteRanges(site Site, generation uint64) ([][]byte, func(Key) bool) {
	return [][]byte{siteRange(site.Prefix)}, func(key Key) bool {
		return key.Prefix == site.Prefix && key.Generation < generation
	}
}
