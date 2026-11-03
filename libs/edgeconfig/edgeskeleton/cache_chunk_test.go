package edgeskeleton

import (
	"strings"
	"testing"
)

// ADR 0021: the chunked range cache only renders with Cache.ChunkBytes; the
// default skeleton only declares its variables (never-executed location); a
// chunk size outside 256 KiB..64 MiB or not a power of two is refused.
func TestRenderChunkedRangeCache(t *testing.T) {
	off := render(t, testInput())
	for _, unwanted := range []string{"cdnca_cache_chunks", "cache_chunk_bytes", "_c {", "slice=$slice_range$cdnca_chunk_epoch"} {
		if strings.Contains(off, unwanted) {
			t.Fatalf("chunking off renders %q", unwanted)
		}
	}
	input := testInput()
	input.Cache.ChunkBytes = 4 << 20
	on := render(t, input)
	for _, want := range []string{"lua_shared_dict cdnca_cache_chunks 32m;", "      cache_chunk_bytes = 4194304,\n      cache_chunk_inactive = 3600,\n",
		"location @cdnca_cache_override_c {", "slice 4194304;"} {
		if !strings.Contains(on, want) {
			t.Fatalf("chunking on lacks %q", want)
		}
	}
	// every port's server has the chunk locations
	if count := strings.Count(on, "location @cdnca_cache_override_c {"); count != len(input.Ports) {
		t.Fatalf("%d chunk locations for %d ports", count, len(input.Ports))
	}
	for _, size := range []int64{3 << 20, 128 << 10, 128 << 20} {
		input.Cache.ChunkBytes = size
		if _, err := Render(input); err == nil {
			t.Fatalf("chunk size %d accepted", size)
		}
	}
}
