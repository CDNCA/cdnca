package eventspool

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A running spool reuses decoded segments across rebuilds;
// a sealed segment rewritten in place must still be rejected.
func TestSegmentCacheDetectsSealedRewriteWhileRunning(t *testing.T) {
	config := testConfig(t.TempDir())
	spool := newTestSpool(t, config)
	for index := 0; index < 20; index++ {
		if _, err := spool.AppendBatch(context.Background(), []Envelope{pendingAccess(fmtID(index), tenantOne)}); err != nil {
			t.Fatal(err)
		}
	}
	matches, _ := filepath.Glob(filepath.Join(config.Root, "segments", "*.seg"))
	if len(matches) == 0 {
		t.Fatal("test did not seal a segment")
	}
	if len(spool.segmentCache) == 0 {
		t.Fatal("segments were not cached")
	}
	file, err := os.OpenFile(matches[0], os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte{0xff}, segmentHeaderSize+recordHeaderSize+4); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	// Keep the size; bump mtime explicitly in case the clock tick is coarse.
	future := time.Now().Add(time.Minute)
	_ = os.Chtimes(matches[0], future, future)
	if _, err := spool.Stats(); !errors.Is(err, ErrCorruptState) {
		t.Fatalf("rewritten sealed segment error = %v", err)
	}
}

// Two spool handles on one root (the lock is cross-process) interleave
// appends: each handle's cached open-segment prefix must pick up the other's
// records and keep sequences contiguous.
func TestSegmentCacheOpenSegmentSharedAcrossHandles(t *testing.T) {
	// 4 KiB seals every few records; 16 KiB keeps all in one open segment.
	for _, segmentBytes := range []int64{4 << 10, 16 << 10} {
		config := testConfig(t.TempDir())
		config.MaxSegmentBytes = segmentBytes
		segmentCacheSharedHandles(t, config)
	}
}

func segmentCacheSharedHandles(t *testing.T, config Config) {
	t.Helper()
	first := newTestSpool(t, config)
	second := newTestSpool(t, config)
	for index := 0; index < 12; index++ {
		handle := first
		if index%2 == 1 {
			handle = second
		}
		results, err := handle.AppendBatch(context.Background(), []Envelope{pendingAccess(fmtID(index), tenantOne)})
		if err != nil {
			t.Fatal(err)
		}
		if results[0].Sequence != uint64(index+1) {
			t.Fatalf("append %d sequence = %d", index, results[0].Sequence)
		}
	}
	for _, handle := range []*Spool{first, second} {
		stats, err := handle.Stats()
		if err != nil || stats.PendingEvents != 12 {
			t.Fatalf("stats = %#v, %v", stats, err)
		}
	}
	fresh := newTestSpool(t, config)
	if stats, err := fresh.Stats(); err != nil || stats.PendingEvents != 12 {
		t.Fatalf("fresh stats = %#v, %v", stats, err)
	}
}
