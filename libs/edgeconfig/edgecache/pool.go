// Package edgecache is the dynamic routing cache (ADR 0009 section 4, D8):
// the node's shared cache zone pool, the site to zone mapping, the cache key
// and the per-site request plan the Lua module executes. The semantics follow
// the ge-cache corrections (A-I): a stable
// key space that only a cache policy change or a site purge renews, keys_zone
// sized from the quota, request cookies ignored on rule-matched requests,
// Range served from cached objects, and a cache status header that tells
// STALE/UPDATING/REVALIDATED apart with a reason for every BYPASS.
package edgecache

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"time"
)

// ErrInvalid wraps every rejection.
var ErrInvalid = errors.New("invalid dynamic routing cache input")

const (
	// ZonePrefix names the pool zones (edgeskeleton.CacheZonePrefix).
	ZonePrefix = "cdnca_cache_"
	// MaxZones bounds the pool (edgeskeleton.MaxCacheZones).
	MaxZones = 64
	// KeysPerMiB is how many cache keys one MiB of keys_zone holds (nginx
	// documents ~8000; ge-cache B uses the same figure).
	KeysPerMiB = 8000
	// AverageObjectBytes estimates the object count of a byte budget
	// (ge-cache B: 32 KiB per object).
	AverageObjectBytes = 32 << 10
	minKeysZoneBytes   = 1 << 20
	maxKeysZoneBytes   = 256 << 20
	// DefaultInactive is the pool inactive time when no rule asks for more.
	DefaultInactive = time.Hour
	maxInactive     = 365 * 24 * time.Hour
)

// PoolInput is the node's cache budget (system settings, ge-cache E).
type PoolInput struct {
	// MaxBytes is the node's total cache disk budget (proxy_cache_max_bytes);
	// split evenly into the zones' max_size (the hard limit).
	MaxBytes int64
	// KeysZoneBytes is the node's total keys_zone budget
	// (proxy_cache_zone_bytes); 0 = derived from MaxBytes.
	KeysZoneBytes int64
	// MinFreeBytes renders min_free on every zone (ge-cache E).
	MinFreeBytes int64
	// MaxRuleTTL is the longest cache rule TTL of the node's sites: the
	// zones' inactive time covers it (ge-cache G).
	MaxRuleTTL time.Duration
}

// Pool is the zone pool the skeleton renders; every zone is the same size.
type Pool struct {
	Zones         int
	KeysZoneBytes int64 // per zone, whole MiB
	MaxBytes      int64 // per zone, whole MiB
	MinFreeBytes  int64 // per zone, whole MiB, 0 = none
	Inactive      time.Duration
}

// poolTiers maps a node's cache budget to a zone count: more zones spread the
// cache manager's work and the keys_zone locks; the count is a power of two
// so the site to zone mapping is a mask. Tiers change only with the budget.
var poolTiers = []struct {
	upTo  int64
	zones int
}{
	{64 << 30, 4},
	{1 << 40, 16},
	{1 << 62, 64},
}

// PlanPool sizes the pool from the node budget.
func PlanPool(input PoolInput) (Pool, error) {
	if input.MaxBytes < 64<<20 || input.MaxBytes > 1<<50 || input.KeysZoneBytes < 0 || input.KeysZoneBytes > 1<<34 ||
		input.MinFreeBytes < 0 || input.MinFreeBytes > 1<<50 || input.MaxRuleTTL < 0 || input.MaxRuleTTL > maxInactive {
		return Pool{}, fmt.Errorf("%w: pool input %+v", ErrInvalid, input)
	}
	zones := MaxZones
	for _, tier := range poolTiers {
		if input.MaxBytes <= tier.upTo {
			zones = tier.zones
			break
		}
	}
	for zones > 1 && input.MaxBytes/int64(zones) < 64<<20 {
		zones /= 2
	}
	maxBytes := floorMiB(input.MaxBytes / int64(zones))
	keys := input.KeysZoneBytes / int64(zones)
	if input.KeysZoneBytes == 0 {
		objects := maxBytes / AverageObjectBytes
		keys = (objects + KeysPerMiB - 1) / KeysPerMiB << 20
	}
	keys = min(max(floorMiB(keys), minKeysZoneBytes), maxKeysZoneBytes)
	inactive := max(DefaultInactive, input.MaxRuleTTL)
	if inactive%time.Second != 0 {
		inactive = inactive.Truncate(time.Second) + time.Second
	}
	return Pool{Zones: zones, KeysZoneBytes: keys, MaxBytes: maxBytes, MinFreeBytes: floorMiB(input.MinFreeBytes), Inactive: inactive}, nil
}

func floorMiB(value int64) int64 { return value >> 20 << 20 }

// ZoneIndex is the zone a site's objects live in: a stable function of the
// site's key prefix (edgesite.CacheKeyPrefix), so a site keeps its zone as
// long as the pool size does not change.
func ZoneIndex(keyPrefix string, zones int) (int, error) {
	if zones < 1 || zones > MaxZones || zones&(zones-1) != 0 || len(keyPrefix) < 8 {
		return 0, fmt.Errorf("%w: zone index (%d zones, prefix %q)", ErrInvalid, zones, keyPrefix)
	}
	value, err := strconv.ParseUint(keyPrefix[:8], 16, 32)
	if err != nil {
		return 0, fmt.Errorf("%w: key prefix %q", ErrInvalid, keyPrefix)
	}
	return int(value) & (zones - 1), nil
}

// ZoneName is the nginx zone name of index i; suffix is ZoneSuffix.
func ZoneName(index int, suffix string) string { return ZonePrefix + strconv.Itoa(index) + suffix }

// ZoneSuffix tells the zones of a cache directory apart: "" for the default
// directory (names unchanged), else "_" and 8 hex of sha256(directory).
// nginx refuses a reload that keeps a zone name on another path ("uses the
// ... cache path while previously it used ..."; nginx -t does not see it),
// so a moved cache directory needs new zone names.
func ZoneSuffix(cacheRoot, defaultRoot string) string {
	cacheRoot, defaultRoot = filepath.Clean(cacheRoot), filepath.Clean(defaultRoot)
	if cacheRoot == defaultRoot {
		return ""
	}
	sum := sha256.Sum256([]byte(cacheRoot))
	return "_" + hex.EncodeToString(sum[:4])
}
