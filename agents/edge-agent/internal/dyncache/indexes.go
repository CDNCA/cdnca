package dyncache

// Purge index manager (on by default).
// One ZoneIndex per zone of the node's pool, built in the background, and a
// way back to the zone scan for everything it cannot vouch for. Per zone:
//   - building: the index is being built (agent start, layout change,
//     rebuild); purges scan;
//   - shadow: built. The first ShadowRuns directory/wildcard purges read the
//     index's candidates, then scan and remove what the scan finds (the scan
//     decides), and compare: all consistent turns the zone active. A file the
//     scan removed that the index did not know, on disk before the index's
//     sync, is a mismatch: the index is dropped and rebuilt (after
//     MaxRebuilds: disabled until the agent restarts);
//   - active: purges go through the index; every RecheckPurges purges or
//     RecheckAfter, one runs as in shadow again;
//   - disabled: purges scan; the reason says why.
// The state of every zone is written to <Dir>/status.json and logged when it
// changes.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"time"
)

// IndexState is a zone index's state (status.json "state").
type IndexState string

const (
	IndexBuilding IndexState = "building"
	IndexShadow   IndexState = "shadow"
	IndexActive   IndexState = "active"
	IndexDisabled IndexState = "disabled"
)

// Reasons (status.json "reason"): why a zone is disabled or rebuilt.
const (
	ReasonStarting         = "starting"
	ReasonLayoutChanged    = "layout_changed"
	ReasonPrefixChanged    = "key_prefix_changed"
	ReasonNotLocal         = "filesystem_not_local"
	ReasonDiskLow          = "state_disk_low"
	ReasonOpenFailed       = "open_failed"
	ReasonIndexError       = "index_error"
	ReasonShadowMismatch   = "shadow_mismatch"
	ReasonRebuildsExceeded = "rebuilds_exceeded"
)

// IndexSettings tune the manager; zero fields take DefaultIndexSettings.
type IndexSettings struct {
	// SyncInterval: the background sync of every zone index (default 30s:
	// a sync that finds no change costs about 1–2 s per 300k files, mostly
	// the index file's first read; a purge's own catch-up then covers at
	// most this long of fills).
	SyncInterval time.Duration
	// Settle: ZoneIndex.Settle (default 2s: ext4 mtimes tick per jiffy, at
	// most 10 ms; 2 s leaves room for clock jitter).
	Settle time.Duration
	// ShadowRuns: consistent shadow purges before a zone turns active.
	ShadowRuns int
	// RecheckPurges / RecheckAfter: an active zone runs one purge as in
	// shadow again after this many purges or this long.
	RecheckPurges int
	RecheckAfter  time.Duration
	// MaxRebuilds: rebuilds after a failure or mismatch before the zone is
	// disabled until the agent restarts.
	MaxRebuilds int
	// BytesPerObject / AverageObjectBytes estimate an index from a zone's
	// size (planned objects = zone bytes / AverageObjectBytes); ReserveBytes
	// stays free on the index's file system (below it: disabled).
	BytesPerObject     int64
	AverageObjectBytes int64
	ReserveBytes       int64
	Now                func() time.Time
	// Local / Free: the file system checks (tests replace them).
	Local func(path string) (bool, string, error)
	Free  func(path string) (int64, error)
}

// DefaultIndexSettings: see IndexSettings. BytesPerObject is twice the
// measured 460–505 B per file.
var DefaultIndexSettings = IndexSettings{SyncInterval: 30 * time.Second, Settle: 2 * time.Second, ShadowRuns: 3,
	RecheckPurges: 1000, RecheckAfter: 24 * time.Hour, MaxRebuilds: 3, BytesPerObject: 1024, AverageObjectBytes: 32 << 10,
	ReserveBytes: 256 << 20}

func (settings IndexSettings) withDefaults() IndexSettings {
	defaults := DefaultIndexSettings
	if settings.SyncInterval <= 0 {
		settings.SyncInterval = defaults.SyncInterval
	}
	if settings.Settle <= 0 {
		settings.Settle = defaults.Settle
	}
	if settings.ShadowRuns <= 0 {
		settings.ShadowRuns = defaults.ShadowRuns
	}
	if settings.RecheckPurges <= 0 {
		settings.RecheckPurges = defaults.RecheckPurges
	}
	if settings.RecheckAfter <= 0 {
		settings.RecheckAfter = defaults.RecheckAfter
	}
	if settings.MaxRebuilds <= 0 {
		settings.MaxRebuilds = defaults.MaxRebuilds
	}
	if settings.BytesPerObject <= 0 {
		settings.BytesPerObject = defaults.BytesPerObject
	}
	if settings.AverageObjectBytes <= 0 {
		settings.AverageObjectBytes = defaults.AverageObjectBytes
	}
	if settings.ReserveBytes <= 0 {
		settings.ReserveBytes = defaults.ReserveBytes
	}
	if settings.Now == nil {
		settings.Now = time.Now
	}
	if settings.Local == nil {
		settings.Local = localFilesystem
	}
	if settings.Free == nil {
		settings.Free = freeBytes
	}
	return settings
}

// ZoneIndexStatus is one zone's index as status.json reports it.
type ZoneIndexStatus struct {
	Zone        int         `json:"zone"`
	State       IndexState  `json:"state"`
	Reason      string      `json:"reason,omitempty"`
	Objects     int64       `json:"objects"`
	IndexBytes  int64       `json:"index_bytes"`
	ShadowLeft  int         `json:"shadow_left,omitempty"`
	Mismatches  int         `json:"mismatches,omitempty"`  // shadow mismatches since the agent started
	Rebuilds    int         `json:"rebuilds,omitempty"`    // rebuilds after a failure since the agent started
	Missed      int         `json:"last_missed,omitempty"` // files the last mismatching shadow purge found unindexed
	BuiltAt     time.Time   `json:"built_at,omitzero"`
	BuildMillis int64       `json:"build_ms,omitempty"`
	SyncedAt    time.Time   `json:"synced_at,omitzero"`
	CheckedAt   time.Time   `json:"checked_at,omitzero"` // last consistent shadow purge
	LastPurge   *PurgeTrace `json:"last_purge,omitempty"`
}

// PurgeTrace is a zone's last purge: the path it took (index, shadow,
// scan, fast) and why it scanned.
type PurgeTrace struct {
	Path     string    `json:"path"`
	Reason   string    `json:"reason,omitempty"`
	Millis   int64     `json:"ms"`
	Affected int       `json:"affected"`
	At       time.Time `json:"at"`
}

// IndexesStatus is status.json.
type IndexesStatus struct {
	Enabled bool              `json:"enabled"`
	Reason  string            `json:"reason,omitempty"`
	Root    string            `json:"cache_root,omitempty"`
	Zones   []ZoneIndexStatus `json:"zones"`
	Updated time.Time         `json:"updated"`
}

// Indexes are the zone indexes of one node. Methods are safe for concurrent
// use: purges run on the caller's goroutine, Run on its own.
type Indexes struct {
	Dir      string // index files and status.json; never under the cache root
	settings IndexSettings

	mu       sync.Mutex
	root     string
	count    int
	zoneSize int64
	prefixes map[string]string // site ID -> key prefix (key_prefix_changed)
	zones    map[int]*zoneEntry
	retired  []*zoneEntry
	wake     chan struct{}
}

// zoneEntry: status and index are guarded by Indexes.mu; op serializes the
// index's use (a purge through it, a build or sync, its closing).
type zoneEntry struct {
	number   int
	dir      string
	file     string
	op       sync.Mutex
	status   ZoneIndexStatus
	index    *ZoneIndex
	rebuild  bool // drop the index file before the next build
	sticky   bool // disabled until the agent restarts
	sinceChk int  // purges since the last check
}

// NewIndexes prepares the manager; it does nothing until Configure.
func NewIndexes(dir string, settings IndexSettings) *Indexes {
	return &Indexes{Dir: dir, settings: settings.withDefaults(), prefixes: map[string]string{}, zones: map[int]*zoneEntry{},
		wake: make(chan struct{}, 1)}
}

func (indexes *Indexes) signal() {
	select {
	case indexes.wake <- struct{}{}:
	default:
	}
}

// layoutValue is what an index file records of the layout it was built for.
func layoutValue(root string, count, zone int) []byte {
	return []byte(root + "|" + strconv.Itoa(count) + "|" + strconv.Itoa(zone))
}

// Configure sets the pool the indexes follow: the cache root, the zone
// count, a zone's size (the index estimate) and every cached site's key
// prefix. A different root or zone count drops every index (the files are
// in other zones now); a site whose key prefix changed rebuilds the zones
// of its old and new prefix. Configure does no I/O: Maintain (Run) builds.
func (indexes *Indexes) Configure(root string, count int, zoneBytes int64, prefixes map[string]string) {
	indexes.mu.Lock()
	defer indexes.mu.Unlock()
	indexes.zoneSize = zoneBytes
	if root != indexes.root || count != indexes.count {
		for _, entry := range indexes.zones {
			indexes.retired = append(indexes.retired, entry)
		}
		indexes.zones = map[int]*zoneEntry{}
		reason := ReasonStarting
		if indexes.root != "" || indexes.count != 0 {
			reason = ReasonLayoutChanged
		}
		indexes.root, indexes.count = root, count
		zones := Zones{Root: root, Count: count}
		for number := range count {
			indexes.zones[number] = &zoneEntry{number: number, dir: zones.dir(number),
				file:   filepath.Join(indexes.Dir, "cdnca-"+strconv.Itoa(number)+".db"),
				status: ZoneIndexStatus{Zone: number, State: IndexBuilding, Reason: reason}}
		}
		indexes.signal()
	}
	zones := Zones{Root: root, Count: count}
	for site, prefix := range prefixes {
		old, known := indexes.prefixes[site]
		if !known || old == prefix {
			continue
		}
		for _, value := range []string{old, prefix} {
			if number, err := zones.zoneNumber(value); err == nil && indexes.zones[number] != nil {
				entry := indexes.zones[number]
				entry.rebuild = true
				if !entry.sticky {
					entry.status.State, entry.status.Reason = IndexBuilding, ReasonPrefixChanged
				}
			}
		}
		indexes.signal()
	}
	indexes.prefixes = prefixes
}

// Maintain is one background pass: closes and removes the indexes of a
// previous layout, then per zone checks the file systems and free space,
// builds an index that is missing and syncs the built ones. It writes
// status.json when done.
func (indexes *Indexes) Maintain(ctx context.Context) {
	indexes.mu.Lock()
	retired := indexes.retired
	indexes.retired = nil
	entries := make([]*zoneEntry, 0, len(indexes.zones))
	for _, entry := range indexes.zones {
		entries = append(entries, entry)
	}
	root := indexes.root
	indexes.mu.Unlock()
	for _, entry := range retired {
		entry.op.Lock()
		indexes.closeLocked(entry, true)
		entry.op.Unlock()
	}
	slices.SortFunc(entries, func(left, right *zoneEntry) int { return left.number - right.number })
	for _, entry := range entries {
		if ctx.Err() != nil {
			break
		}
		indexes.step(ctx, root, entry)
	}
	indexes.writeStatus()
}

// closeLocked closes the entry's index, and removes its file when drop
// (entry.op held).
func (indexes *Indexes) closeLocked(entry *zoneEntry, drop bool) {
	indexes.mu.Lock()
	index := entry.index
	entry.index = nil
	indexes.mu.Unlock()
	if index != nil {
		_ = index.Close()
	}
	if drop {
		_ = os.Remove(entry.file)
	}
}

// set changes a zone's state (Indexes.mu held) and logs a change.
func (indexes *Indexes) set(entry *zoneEntry, state IndexState, reason string) {
	if entry.status.State == state && entry.status.Reason == reason {
		return
	}
	level := slog.LevelInfo
	if state == IndexDisabled {
		level = slog.LevelWarn
	}
	slog.Log(context.Background(), level, "cache purge index state", "zone", entry.number, "state", string(state),
		"reason", reason, "previous", string(entry.status.State), "objects", entry.status.Objects)
	entry.status.State, entry.status.Reason = state, reason
}

// step maintains one zone. It never waits for a purge: a zone whose index is
// in use is skipped this pass (the purge syncs it itself).
func (indexes *Indexes) step(ctx context.Context, root string, entry *zoneEntry) {
	if !entry.op.TryLock() {
		return
	}
	defer entry.op.Unlock()
	indexes.mu.Lock()
	sticky, built, rebuild := entry.sticky, entry.index != nil, entry.rebuild
	objects := entry.status.Objects
	planned := indexes.zoneSize / indexes.settings.AverageObjectBytes
	indexes.mu.Unlock()
	if sticky {
		return
	}
	for _, path := range []string{entry.dir, indexes.Dir} {
		local, name, err := indexes.settings.Local(path)
		if err != nil || !local {
			indexes.closeLocked(entry, false)
			indexes.mu.Lock()
			indexes.set(entry, IndexDisabled, ReasonNotLocal)
			indexes.mu.Unlock()
			slog.Debug("cache purge index file system", "zone", entry.number, "path", path, "fs", name, "error", err)
			return
		}
	}
	need := indexes.settings.ReserveBytes
	if built {
		need += objects * indexes.settings.BytesPerObject / 2 // growth room
	} else {
		need += planned * indexes.settings.BytesPerObject
	}
	free, err := indexes.settings.Free(indexes.Dir)
	if err != nil || free < need {
		indexes.closeLocked(entry, true)
		indexes.mu.Lock()
		entry.rebuild = true
		indexes.set(entry, IndexDisabled, ReasonDiskLow)
		indexes.mu.Unlock()
		slog.Debug("cache purge index free space", "zone", entry.number, "free", free, "need", need, "error", err)
		return
	}
	if !built || rebuild {
		indexes.closeLocked(entry, false) // build removes the file
		indexes.build(ctx, root, entry)
		return
	}
	indexes.syncLocked(ctx, entry)
}

// syncLocked brings a built index up to its zone (entry.op held).
func (indexes *Indexes) syncLocked(ctx context.Context, entry *zoneEntry) {
	indexes.mu.Lock()
	index := entry.index
	indexes.mu.Unlock()
	if _, err := index.Sync(ctx); err != nil {
		if ctx.Err() == nil {
			indexes.fail(entry, ReasonIndexError, err)
		}
		return
	}
	indexes.refresh(entry, index)
}

// refresh records the index's size after a sync.
func (indexes *Indexes) refresh(entry *zoneEntry, index *ZoneIndex) {
	objects := index.Objects()
	size := int64(0)
	if info, err := os.Stat(index.Path); err == nil {
		size = info.Size()
	}
	indexes.mu.Lock()
	entry.status.Objects, entry.status.IndexBytes, entry.status.SyncedAt = objects, size, indexes.settings.Now().UTC()
	indexes.mu.Unlock()
}

// build opens the zone's index file and syncs it complete (entry.op held).
// A file built for this layout is reused (its sync catches up on what
// changed while the agent was down) but checked in shadow again like a new
// one.
func (indexes *Indexes) build(ctx context.Context, root string, entry *zoneEntry) {
	indexes.mu.Lock()
	rebuild, count := entry.rebuild, indexes.count
	entry.rebuild = false
	indexes.set(entry, IndexBuilding, entry.status.Reason)
	indexes.mu.Unlock()
	if rebuild {
		_ = os.Remove(entry.file)
	}
	started := indexes.settings.Now()
	index, err := OpenZoneIndex(entry.dir, entry.file)
	if err != nil {
		indexes.fail(entry, ReasonOpenFailed, err)
		return
	}
	index.Settle, index.Now = indexes.settings.Settle, indexes.settings.Now
	layout := layoutValue(root, count, entry.number)
	if !bytes.Equal(index.Meta("layout"), layout) {
		// not this layout's (or new): start empty
		_ = index.Close()
		_ = os.Remove(entry.file)
		if index, err = OpenZoneIndex(entry.dir, entry.file); err == nil {
			index.Settle, index.Now = indexes.settings.Settle, indexes.settings.Now
			err = index.SetMeta("layout", layout)
		}
		if err != nil {
			indexes.fail(entry, ReasonOpenFailed, err)
			return
		}
	}
	indexes.mu.Lock()
	entry.index = index
	indexes.mu.Unlock()
	stats, err := index.Sync(ctx)
	if err != nil {
		if ctx.Err() == nil {
			indexes.fail(entry, ReasonIndexError, err)
		}
		return
	}
	elapsed := indexes.settings.Now().Sub(started)
	indexes.refresh(entry, index)
	indexes.mu.Lock()
	entry.status.BuiltAt, entry.status.BuildMillis = indexes.settings.Now().UTC(), elapsed.Milliseconds()
	entry.status.ShadowLeft, entry.sinceChk = indexes.settings.ShadowRuns, 0
	indexes.set(entry, IndexShadow, "")
	indexes.mu.Unlock()
	slog.Info("cache purge index built", "zone", entry.number, "objects", index.Objects(), "added", stats.Added,
		"listed", stats.Listed, "duration", elapsed.Round(time.Millisecond))
}

// fail drops the zone's index after an error or a shadow mismatch: it is
// rebuilt, or after MaxRebuilds disabled until the agent restarts
// (entry.op held).
func (indexes *Indexes) fail(entry *zoneEntry, reason string, cause error) {
	indexes.closeLocked(entry, true)
	indexes.mu.Lock()
	defer indexes.mu.Unlock()
	entry.status.Rebuilds++
	slog.Warn("cache purge index dropped", "zone", entry.number, "reason", reason, "rebuilds", entry.status.Rebuilds,
		"error", cause)
	if entry.status.Rebuilds > indexes.settings.MaxRebuilds {
		entry.sticky = true
		indexes.set(entry, IndexDisabled, reason)
		return
	}
	entry.rebuild = true
	indexes.set(entry, IndexBuilding, reason)
	indexes.signal()
}

// Purge is Zones.Purge through the zone's index when the index can be used:
// the exact fast path as Purge takes it, else the index (active), the scan
// checked against the index (shadow), or the scan.
func (indexes *Indexes) Purge(ctx context.Context, zones Zones, site Site, targets []Target, prefix bool,
	generations *Generations) (Result, error) {
	started := indexes.settings.Now()
	if result, done, err := zones.exactFast(ctx, site, targets, prefix, generations); done || err != nil {
		if err == nil {
			indexes.record(zones, site.Prefix, PurgeTrace{Path: "fast"}, started, result)
		}
		return result, err
	}
	ranges, accept := purgeRanges(site, targets, prefix)
	return indexes.run(ctx, zones, site.Prefix, ranges, accept, false, started)
}

// PurgeSite is Zones.RemoveOlder through the zone's index (PurgeSite after
// the bump). A site purge is never a shadow check: it removes everything of
// the site, its candidate set would be the whole site.
func (indexes *Indexes) PurgeSite(ctx context.Context, zones Zones, site Site, generation uint64) (Result, error) {
	ranges, accept := siteRanges(site, generation)
	return indexes.run(ctx, zones, site.Prefix, ranges, accept, true, indexes.settings.Now())
}

func (indexes *Indexes) run(ctx context.Context, zones Zones, prefix string, ranges [][]byte, accept func(Key) bool,
	whole bool, started time.Time) (Result, error) {
	entry, mode, reason := indexes.use(zones, prefix, whole)
	if entry == nil || mode == "" {
		result, err := zones.scanRemove(ctx, prefix, accept, nil)
		if err == nil {
			indexes.record(zones, prefix, PurgeTrace{Path: "scan", Reason: reason}, started, result)
		}
		return result, err
	}
	defer entry.op.Unlock()
	if mode == "shadow" {
		return indexes.shadow(ctx, zones, entry, prefix, ranges, accept, started)
	}
	result, err := entry.index.remove(ctx, ranges, accept)
	if err == nil {
		indexes.record(zones, prefix, PurgeTrace{Path: "index"}, started, result)
		return result, nil
	}
	if ctx.Err() != nil {
		return result, err
	}
	// the index failed: this purge scans, the index is rebuilt
	indexes.fail(entry, ReasonIndexError, err)
	scanned, scanErr := zones.scanRemove(ctx, prefix, accept, nil)
	scanned.Affected += result.Affected
	scanned.Bytes += result.Bytes
	if scanErr == nil {
		indexes.record(zones, prefix, PurgeTrace{Path: "scan", Reason: ReasonIndexError}, started, scanned)
	}
	return scanned, scanErr
}

// use picks the purge path of the site's zone: "index" or "shadow" with
// the entry's op held (the caller unlocks), or "" with the reason the zone
// scans (not indexed, building, disabled, another layout).
func (indexes *Indexes) use(zones Zones, prefix string, whole bool) (*zoneEntry, string, string) {
	number, err := zones.zoneNumber(prefix)
	if err != nil {
		return nil, "", "no_zone"
	}
	indexes.mu.Lock()
	entry := indexes.zones[number]
	if zones.Root != indexes.root || zones.Count != indexes.count || entry == nil {
		indexes.mu.Unlock()
		return nil, "", ReasonLayoutChanged
	}
	if entry.status.State != IndexShadow && entry.status.State != IndexActive {
		reason := entry.status.Reason
		if entry.status.State == IndexBuilding {
			reason = string(IndexBuilding)
		}
		indexes.mu.Unlock()
		return entry, "", reason
	}
	indexes.mu.Unlock()
	entry.op.Lock()
	indexes.mu.Lock()
	defer indexes.mu.Unlock()
	state := entry.status.State
	if entry.index == nil || state != IndexShadow && state != IndexActive {
		entry.op.Unlock()
		return entry, "", string(state)
	}
	if whole {
		if state == IndexShadow {
			entry.op.Unlock()
			return entry, "", string(IndexShadow)
		}
		return entry, "index", ""
	}
	entry.sinceChk++
	checked := entry.status.CheckedAt
	if checked.IsZero() {
		checked = entry.status.BuiltAt
	}
	if state == IndexShadow || entry.sinceChk >= indexes.settings.RecheckPurges ||
		indexes.settings.Now().Sub(checked) >= indexes.settings.RecheckAfter {
		return entry, "shadow", ""
	}
	return entry, "index", ""
}

// shadowSlack: a file whose mtime is within this of the index's sync start
// may have been filled while the sync listed its directory (not a miss).
const shadowSlack = time.Second

// shadow purges by the scan and checks the index against it (entry.op
// held): the index's candidates first (its sync, then a read), then the
// scan removes. A file the scan removes that the index did not have, filled
// before the index's sync started, is a miss: the index is dropped and
// rebuilt. A file only the index has is not (filled after the scan passed
// its directory, or evicted).
func (indexes *Indexes) shadow(ctx context.Context, zones Zones, entry *zoneEntry, prefix string, ranges [][]byte,
	accept func(Key) bool, started time.Time) (Result, error) {
	known, synced, err := entry.index.candidates(ctx, ranges, accept)
	if err != nil {
		if ctx.Err() != nil {
			return Result{}, err
		}
		indexes.fail(entry, ReasonIndexError, err)
		result, scanErr := zones.scanRemove(ctx, prefix, accept, nil)
		if scanErr == nil {
			indexes.record(zones, prefix, PurgeTrace{Path: "scan", Reason: ReasonIndexError}, started, result)
		}
		return result, scanErr
	}
	missed, cutoff := 0, synced.Add(-shadowSlack)
	var sample []string
	result, err := zones.scanRemove(ctx, prefix, accept, func(found Entry) {
		id, ok := fileIDOf(found.Path)
		if !ok || known[id] || !found.Filled.Before(cutoff) {
			return
		}
		missed++
		if len(sample) < 5 {
			sample = append(sample, filepath.Base(found.Path))
		}
	})
	if err != nil {
		return result, err // a failed scan proves nothing about the index
	}
	indexes.record(zones, prefix, PurgeTrace{Path: "shadow"}, started, result)
	indexes.mu.Lock()
	entry.status.Missed = missed
	if missed > 0 {
		entry.status.Mismatches++
		indexes.mu.Unlock()
		indexes.fail(entry, ReasonShadowMismatch, fmt.Errorf("%d of %d removed files not indexed (%v)", missed,
			result.Affected, sample))
		return result, nil
	}
	entry.status.CheckedAt, entry.sinceChk = indexes.settings.Now().UTC(), 0
	if entry.status.State == IndexShadow {
		entry.status.ShadowLeft = max(entry.status.ShadowLeft-1, 0)
		if entry.status.ShadowLeft == 0 {
			indexes.set(entry, IndexActive, "")
		}
	}
	indexes.mu.Unlock()
	slog.Info("cache purge index shadow check", "zone", entry.number, "removed", result.Affected,
		"candidates", len(known), "consistent", true)
	return result, nil
}

// record keeps the zone's last purge; every path but the exact fast one
// also writes status.json (a burst of exact purges is written by the next
// background pass).
func (indexes *Indexes) record(zones Zones, prefix string, trace PurgeTrace, started time.Time, result Result) {
	number, err := zones.zoneNumber(prefix)
	if err != nil {
		return
	}
	now := indexes.settings.Now()
	trace.Millis, trace.Affected, trace.At = now.Sub(started).Milliseconds(), result.Affected, now.UTC()
	indexes.mu.Lock()
	entry := indexes.zones[number]
	if entry != nil && zones.Root == indexes.root && zones.Count == indexes.count {
		entry.status.LastPurge = &trace
	}
	indexes.mu.Unlock()
	slog.Debug("cache purge", "zone", number, "path", trace.Path, "reason", trace.Reason, "affected", trace.Affected,
		"ms", trace.Millis)
	if trace.Path != "fast" {
		indexes.writeStatus()
	}
}

// Status is every zone's index.
func (indexes *Indexes) Status() IndexesStatus {
	indexes.mu.Lock()
	defer indexes.mu.Unlock()
	status := IndexesStatus{Enabled: true, Root: indexes.root, Zones: []ZoneIndexStatus{}, Updated: indexes.settings.Now().UTC()}
	for _, entry := range indexes.zones {
		value := entry.status
		if value.LastPurge != nil {
			trace := *value.LastPurge
			value.LastPurge = &trace
		}
		status.Zones = append(status.Zones, value)
	}
	slices.SortFunc(status.Zones, func(left, right ZoneIndexStatus) int { return left.Zone - right.Zone })
	return status
}

func (indexes *Indexes) writeStatus() { writeIndexStatus(indexes.Dir, indexes.Status()) }

func writeIndexStatus(dir string, status IndexesStatus) {
	raw, err := json.MarshalIndent(status, "", "  ")
	if err == nil {
		err = os.MkdirAll(dir, 0o700)
	}
	if err == nil {
		temporary := filepath.Join(dir, ".status.json.tmp")
		if err = os.WriteFile(temporary, append(raw, '\n'), 0o600); err == nil {
			err = os.Rename(temporary, filepath.Join(dir, "status.json"))
		}
	}
	if err != nil {
		slog.Warn("cache purge index status not written", "error", err)
	}
}

// DisableIndexes is the node without purge indexes (dynamic_routing.
// purge_index false): index files left by an earlier run are removed and
// status.json says so.
func DisableIndexes(dir, reason string) {
	matches, _ := filepath.Glob(filepath.Join(dir, "cdnca-*.db"))
	for _, path := range matches {
		_ = os.Remove(path)
	}
	if _, err := os.Stat(dir); err == nil {
		writeIndexStatus(dir, IndexesStatus{Reason: reason, Zones: []ZoneIndexStatus{}, Updated: time.Now().UTC()})
	}
}

// IndexLayout is what Run reads of the node every pass (Configure's
// arguments).
type IndexLayout struct {
	Root      string
	Zones     int
	ZoneBytes int64
	Prefixes  map[string]string // site ID -> key prefix
}

// Run maintains the indexes until ctx ends: every SyncInterval, and at
// once after a layout change or a dropped index. layout is read at the
// start of every pass. The index files are closed on return.
func (indexes *Indexes) Run(ctx context.Context, layout func() IndexLayout) {
	ticker := time.NewTicker(indexes.settings.SyncInterval)
	defer ticker.Stop()
	defer indexes.Close()
	for {
		value := layout()
		indexes.Configure(value.Root, value.Zones, value.ZoneBytes, value.Prefixes)
		indexes.Maintain(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-indexes.wake:
		}
	}
}

// Close closes every index file (they stay for the next start).
func (indexes *Indexes) Close() {
	indexes.mu.Lock()
	entries := append([]*zoneEntry(nil), indexes.retired...)
	for _, entry := range indexes.zones {
		entries = append(entries, entry)
	}
	indexes.mu.Unlock()
	for _, entry := range entries {
		entry.op.Lock()
		indexes.closeLocked(entry, false)
		entry.op.Unlock()
	}
}
