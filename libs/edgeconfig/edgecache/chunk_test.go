package edgecache

import (
	"strings"
	"testing"
)

// ADR 0021: the chunked range cache is a node switch; off renders exactly
// what it rendered before (no dictionary, map or chunk location).
func TestChunkedRangeOffRendersNothingNew(t *testing.T) {
	pool, err := PlanPool(PoolInput{MaxBytes: 256 << 20})
	if err != nil || pool.ChunkBytes != 0 {
		t.Fatalf("pool %+v err %v", pool, err)
	}
	http := HTTP(pool, "/var/lib/cdnca-edge/shared", "", 1)
	for _, unwanted := range []string{ChunkDictionary, "$cdnca_chunk_valid", "\\|0030\\|", "lua_capture_error_log"} {
		if strings.Contains(http, unwanted) {
			t.Fatalf("chunking off renders %q", unwanted)
		}
	}
}

func TestChunkedRangeOnRenders(t *testing.T) {
	pool, err := PlanPool(PoolInput{MaxBytes: 256 << 20, Chunked: true})
	if err != nil || pool.ChunkBytes != ChunkBytes {
		t.Fatalf("pool %+v err %v", pool, err)
	}
	http := HTTP(pool, "/var/lib/cdnca-edge/shared", "", 1)
	for _, want := range []string{
		"lua_shared_dict cdnca_cache_chunks 32m;", "lua_capture_error_log 1m;",
		"map \"$upstream_status|$cdnca_cache_ttls\" $cdnca_chunk_valid {",
		// a chunk is cached by the rule's 206, else 200, else any entry
		`"~^(?:[^|]*, )?206\|.* 206=(?<cdnca_cache_t>[0-9]+) " $cdnca_cache_t;`,
		`"~^(?:[^|]*, )?206\|.* 200=(?<cdnca_cache_t>[0-9]+) " $cdnca_cache_t;`,
		// fetched but not stored as such: still MISS/EXPIRED
		`"~^1\|cdnca_cache_[0-9]+\|0030\|MISS$" MISS;`,
	} {
		if !strings.Contains(http, want) {
			t.Fatalf("http block lacks %q", want)
		}
	}
	locations := ChunkVariants("  ", "    proxy_pass http://o;\n", pool.ChunkBytes)
	// one chunk location per whole, non-following variant: 2 modes x 3
	// stale modes x 2 Vary modes
	if count := strings.Count(locations, "location @cdnca_cache_"); count != 12 {
		t.Fatalf("%d chunk locations", count)
	}
	for _, want := range []string{
		"location @cdnca_cache_override_c {", "location @cdnca_cache_follow_stalebg_nv_c {",
		"proxy_cache_key $cdnca_cache_key|slice=$slice_range$cdnca_chunk_epoch;",
		"proxy_cache_valid any $cdnca_chunk_valid;",
		"slice 4194304;", "proxy_set_header Range $slice_range;", "proxy_set_header If-Range \"\";",
		"proxy_set_header Accept-Encoding \"\";", "proxy_cache_lock_timeout 30s;", "proxy_cache_lock_age 30s;",
		"add_header X-CDN-Cache $cdnca_cache_status_header always;",
	} {
		if !strings.Contains(locations, want) {
			t.Fatalf("chunk locations lack %q", want)
		}
	}
	if strings.Contains(locations, "proxy_cache_background_update on;") || strings.Contains(locations, "_s256") ||
		strings.Contains(locations, "proxy_hide_header ETag") ||
		strings.Contains(locations, "_f_c") {
		t.Fatal("a chunk location updates in the background, is sliced or follows redirects")
	}
}

func TestWholeAndChunkVariant(t *testing.T) {
	for variant, want := range map[string]string{
		"@cdnca_cache_override":            "@cdnca_cache_override",
		"@cdnca_cache_override_s1024":      "@cdnca_cache_override",
		"@cdnca_cache_follow_stale_s65536": "@cdnca_cache_follow_stale",
		"@cdnca_cache_follow_stalebg_nv":   "@cdnca_cache_follow_stalebg_nv",
		"@cdnca_cache_override_stale":      "@cdnca_cache_override_stale",
	} {
		if got := WholeVariant(variant); got != want {
			t.Fatalf("WholeVariant(%q) = %q, want %q", variant, got, want)
		}
		if got := ChunkVariant(variant); got != want+ChunkSuffix {
			t.Fatalf("ChunkVariant(%q) = %q", variant, got)
		}
	}
	// every chunk variant is a whole variant's name + _c
	names := map[string]bool{}
	for _, name := range VariantNames() {
		names[name] = true
	}
	for _, variant := range variants() {
		if !variant.follow && variant.sliceBytes == 0 && !names[WholeVariant(variant.name)] {
			t.Fatalf("%s has no whole variant", variant.name)
		}
	}
}
