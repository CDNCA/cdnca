// Package dyncache is the agent side of the dynamic routing cache (ADR 0009
// section 4, D8; key and plan in libs/edgeconfig/edgecache): per-site purge
// in the shared zone pool (exact URL, prefix, whole site), the per-site purge
// generation (node state, pushed to the cache module through the dynamic
// routing control socket), prewarm through the shared server, and the soft
// quota cleaner. Sites are isolated by the stable key prefix every cache key
// starts with: purging or evicting site A never touches site B's objects.
package dyncache

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ErrInvalid wraps every rejected input.
var ErrInvalid = errors.New("invalid dynamic routing cache request")

// Key is a parsed cache key:
// <prefix>|<token>|<generation>|<host or domain>|<port>|<policy key>.
type Key struct {
	Prefix     string
	Token      string
	Generation uint64
	Host       string
	Port       int
	// PolicyKey is $uri + query ("/a.css?v=2") or the projected form
	// ("/a.css?~q=<digest>&~v=<digest>"); Path is the part before "?".
	PolicyKey string
	Path      string
	// Slice is the slice range of a slice variant's object
	// ("<policy key>|slice=bytes=0-1048575"), "" for a whole object.
	Slice string
}

// ParseKey parses a cache key; ok false for keys of other formats (v7).
func ParseKey(value string) (Key, bool) {
	parts := strings.SplitN(value, "|", 6)
	if len(parts) != 6 || len(parts[0]) != 32 || !lowerHex(parts[0]) || len(parts[1]) != 16 || !lowerHex(parts[1]) {
		return Key{}, false
	}
	generation, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil {
		return Key{}, false
	}
	port, err := strconv.Atoi(parts[4])
	if err != nil || port < 1 || port > 65535 || parts[3] == "" || !strings.HasPrefix(parts[5], "/") {
		return Key{}, false
	}
	policyKey, slice, _ := strings.Cut(parts[5], "|slice=")
	path, _, _ := strings.Cut(policyKey, "?")
	return Key{Prefix: parts[0], Token: parts[1], Generation: generation, Host: parts[3], Port: port, PolicyKey: policyKey, Path: path,
		Slice: slice}, true
}

func lowerHex(value string) bool {
	for index := 0; index < len(value); index++ {
		character := value[index]
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

// Entry is one cached object on disk.
type Entry struct {
	Path     string
	Key      Key
	Size     int64     // allocated bytes (what max_size counts)
	Accessed time.Time // last access (nginx updates atime on reads only on some filesystems: mtime is the fill time)
	Filled   time.Time
}

// Zones is the zone pool's directories (<shared>/cache/cdnca-<i>).
type Zones struct {
	Root  string // <shared>/cache
	Count int
}

func (zones Zones) dir(index int) string {
	return filepath.Join(zones.Root, "cdnca-"+strconv.Itoa(index))
}

// ZoneOf returns the directory of a site's zone (edgecache.ZoneIndex).
func (zones Zones) ZoneOf(prefix string) (string, error) {
	if zones.Count < 1 || zones.Count&(zones.Count-1) != 0 || len(prefix) < 8 {
		return "", fmt.Errorf("%w: zone of %q", ErrInvalid, prefix)
	}
	value, err := strconv.ParseUint(prefix[:8], 16, 32)
	if err != nil {
		return "", fmt.Errorf("%w: prefix %q", ErrInvalid, prefix)
	}
	return zones.dir(int(value) & (zones.Count - 1)), nil
}

// FilePath is nginx's file for a key (levels=1:2).
func FilePath(zoneDir, key string) string {
	digest := md5.Sum([]byte(key))
	value := hex.EncodeToString(digest[:])
	return filepath.Join(zoneDir, value[31:], value[29:31], value)
}

// headerLimit bounds how much of a cache file is read for its KEY line.
const headerLimit = 16 << 10

// readKey returns the KEY line of a cache file (nginx file cache header).
func readKey(path string) (string, os.FileInfo, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|noAtime, 0)
	if noAtime != 0 && errors.Is(err, syscall.EPERM) {
		// O_NOATIME needs the file's owner or CAP_FOWNER
		file, err = os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	}
	if err != nil {
		return "", nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return "", nil, fmt.Errorf("%w: not a cache file", ErrInvalid)
	}
	header, err := io.ReadAll(io.LimitReader(file, headerLimit))
	if err != nil {
		return "", nil, err
	}
	start := bytes.Index(header, []byte("\nKEY: "))
	if start < 0 {
		return "", nil, fmt.Errorf("%w: no key", ErrInvalid)
	}
	rest := header[start+6:]
	end := bytes.IndexByte(rest, '\n')
	if end < 0 {
		return "", nil, fmt.Errorf("%w: key too long", ErrInvalid)
	}
	key := string(rest[:end])
	// the file name is md5(key): a file that does not match is not trusted
	digest := md5.Sum([]byte(key))
	if hex.EncodeToString(digest[:]) != filepath.Base(path) {
		return "", nil, fmt.Errorf("%w: key does not match the file name", ErrInvalid)
	}
	return key, info, nil
}

// Walk visits every object of one site (by key prefix) in its zone. Files
// of other sites are opened only to read their key; nothing else is done
// with them.
func (zones Zones) Walk(ctx context.Context, prefix string, visit func(Entry) error) error {
	dir, err := zones.ZoneOf(prefix)
	if err != nil {
		return err
	}
	return walkZone(ctx, dir, func(entry Entry) error {
		if entry.Key.Prefix != prefix {
			return nil
		}
		return visit(entry)
	})
}

// WalkAll visits every object of every site in every zone.
func (zones Zones) WalkAll(ctx context.Context, visit func(Entry) error) error {
	for index := range zones.Count {
		if err := walkZone(ctx, zones.dir(index), visit); err != nil {
			return err
		}
	}
	return nil
}

func walkZone(ctx context.Context, dir string, visit func(Entry) error) error {
	err := filepath.WalkDir(dir, func(path string, item os.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if item.IsDir() || len(item.Name()) != 32 {
			return nil // nginx temp files (".0000000001") and directories
		}
		raw, info, err := readKey(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil // evicted by the cache manager meanwhile
			}
			return nil // not ours to judge: the cache manager owns the file
		}
		key, ok := ParseKey(raw)
		if !ok {
			return nil
		}
		return visit(entryOf(path, key, info))
	})
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func entryOf(path string, key Key, info os.FileInfo) Entry {
	entry := Entry{Path: path, Key: key, Size: info.Size(), Filled: info.ModTime(), Accessed: info.ModTime()}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		entry.Size = stat.Blocks * 512
		accessed := accessTime(stat)
		if accessed.After(entry.Accessed) {
			entry.Accessed = accessed
		}
	}
	return entry
}

// remove unlinks an object; an object already gone counts as removed.
// nginx keeps serving an open file and drops its keys_zone node when the
// next request misses it (ngx_http_file_cache_open ENOENT), so a removed
// object is never served again.
func remove(entry Entry) (bool, error) {
	err := os.Remove(entry.Path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// Usage is one site's bytes in the pool.
type Usage struct {
	Prefix  string
	Bytes   int64
	Objects int
}

// UsageBySite sums every site's objects in the pool.
func (zones Zones) UsageBySite(ctx context.Context) (map[string]*Usage, error) {
	usage := map[string]*Usage{}
	err := zones.WalkAll(ctx, func(entry Entry) error {
		value := usage[entry.Key.Prefix]
		if value == nil {
			value = &Usage{Prefix: entry.Key.Prefix}
			usage[entry.Key.Prefix] = value
		}
		value.Bytes += entry.Size
		value.Objects++
		return nil
	})
	return usage, err
}

func sortByAccess(entries []Entry) {
	sort.Slice(entries, func(left, right int) bool {
		if !entries[left].Accessed.Equal(entries[right].Accessed) {
			return entries[left].Accessed.Before(entries[right].Accessed)
		}
		return entries[left].Path < entries[right].Path
	})
}
