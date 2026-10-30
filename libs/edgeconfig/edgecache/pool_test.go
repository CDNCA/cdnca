package edgecache

import (
	"testing"
	"time"
)

func TestPlanPoolTiers(t *testing.T) {
	cases := []struct {
		max               int64
		zones             int
		zoneMax, keysZone int64
	}{
		{64 << 20, 1, 64 << 20, 1 << 20},      // smallest: one zone
		{1 << 30, 4, 256 << 20, 1 << 20},      // 8192 objects -> 2 MiB? no: 8192/8000 rounds up to 2 MiB
		{100 << 30, 16, 6400 << 20, 26 << 20}, // 6400 MiB / 32 KiB = 204800 objects -> 26 MiB
		{16 << 40, 64, 256 << 30, 256 << 20},  // capped at 256 MiB
	}
	cases[1].keysZone = 2 << 20
	for _, test := range cases {
		pool, err := PlanPool(PoolInput{MaxBytes: test.max})
		if err != nil {
			t.Fatal(err)
		}
		if pool.Zones != test.zones || pool.MaxBytes != test.zoneMax || pool.KeysZoneBytes != test.keysZone || pool.Inactive != DefaultInactive {
			t.Errorf("max %d: %+v", test.max, pool)
		}
	}
}

func TestPlanPoolBudgetsAndInactive(t *testing.T) {
	pool, err := PlanPool(PoolInput{MaxBytes: 1 << 30, KeysZoneBytes: 64 << 20, MinFreeBytes: 5 << 30, MaxRuleTTL: 7 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	// the node keys_zone budget is split over the zones (ge-cache B/E)
	if pool.KeysZoneBytes != 16<<20 || pool.MinFreeBytes != 5<<30 || pool.Inactive != 7*24*time.Hour {
		t.Fatalf("%+v", pool)
	}
	// a rule TTL with a fraction of a second rounds the inactive time up
	pool, _ = PlanPool(PoolInput{MaxBytes: 1 << 30, MaxRuleTTL: 2*time.Hour + time.Millisecond})
	if pool.Inactive != 2*time.Hour+time.Second {
		t.Fatalf("%v", pool.Inactive)
	}
	for name, input := range map[string]PoolInput{
		"tiny":          {MaxBytes: 1 << 20},
		"negative keys": {MaxBytes: 1 << 30, KeysZoneBytes: -1},
		"huge ttl":      {MaxBytes: 1 << 30, MaxRuleTTL: 400 * 24 * time.Hour},
	} {
		if _, err := PlanPool(input); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestZoneIndexStableAndSpread(t *testing.T) {
	counts := make([]int, 16)
	for index := range 16000 {
		prefix := keyPrefixFor(index)
		zone, err := ZoneIndex(prefix, 16)
		if err != nil {
			t.Fatal(err)
		}
		again, _ := ZoneIndex(prefix, 16)
		if zone != again {
			t.Fatal("zone index not stable")
		}
		counts[zone]++
	}
	for zone, count := range counts {
		if count < 800 || count > 1200 {
			t.Errorf("zone %d holds %d of 16000 sites", zone, count)
		}
	}
	if _, err := ZoneIndex("0123abcd", 3); err == nil {
		t.Fatal("non power of two accepted")
	}
	if _, err := ZoneIndex("zz", 4); err == nil {
		t.Fatal("bad prefix accepted")
	}
	if ZoneName(3, "") != "cdnca_cache_3" {
		t.Fatal(ZoneName(3, ""))
	}
	// a moved cache directory renames the zones (nginx refuses a reload
	// that keeps a name on another path); the default keeps cdnca_cache_<i>
	if suffix := ZoneSuffix("/var/lib/cdnca-edge/shared/cache/", "/var/lib/cdnca-edge/shared/cache"); suffix != "" {
		t.Fatal(suffix)
	}
	moved, other := ZoneSuffix("/data/a", "/var/lib/cdnca-edge/shared/cache"), ZoneSuffix("/data/b", "/var/lib/cdnca-edge/shared/cache")
	if len(moved) != 9 || moved[0] != '_' || moved == other || moved != ZoneSuffix("/data/a/", "/x") {
		t.Fatal(moved, other)
	}
	if ZoneName(3, moved) != "cdnca_cache_3"+moved {
		t.Fatal(ZoneName(3, moved))
	}
}
