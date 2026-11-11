package eventspool

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// The pending index is maintained incrementally. After every
// operation it must equal the index a fresh New builds from disk.

type partialPublisher struct {
	acknowledge int // publications acknowledged per call; <0 = all
	ids         []string
}

func (p *partialPublisher) Publish(ctx context.Context, publications []Publication) (PublishAck, error) {
	count := len(publications)
	if p.acknowledge >= 0 && p.acknowledge < count {
		count = p.acknowledge
	}
	collector := &collectingPublisher{}
	if _, err := collector.Publish(ctx, publications[:count]); err != nil {
		return PublishAck{}, err
	}
	p.ids = append(p.ids, collector.ids...)
	if count < len(publications) {
		return PublishAck{Acknowledged: count}, errors.New("partial")
	}
	return PublishAck{Acknowledged: count}, nil
}

func indexTestConfig(t *testing.T) Config {
	config := testConfig(t.TempDir())
	config.MaxEventBytes = 4096
	config.MaxSegmentBytes = 16 << 10 // a few records per segment: many seals
	config.SoftLimitBytes, config.HardLimitBytes, config.MaxTenantBytes = 8<<20, 16<<20, 8<<20
	config.Now = func() time.Time { return time.Unix(1_700_000_000, 0).UTC().Add(time.Hour) }
	return config
}

func indexTestEvent(index int, random *rand.Rand) Envelope {
	tenant := tenantOne
	if index%3 == 0 {
		tenant = tenantTwo
	}
	event := pendingAccess(fmt.Sprintf("evt-%08d", index), tenant)
	// Out-of-order times exercise the running minimum behind OldestOccurredAt.
	event.OccurredAt = time.Unix(1_700_000_000, 0).UTC().Add(time.Duration(random.Intn(600)) * time.Second)
	event.Path = fmt.Sprintf("/p/%d", index)
	return event
}

func assertIndexMatchesDisk(t *testing.T, config Config, live *Spool, step string) {
	t.Helper()
	got, err := live.Stats()
	if err != nil {
		t.Fatalf("%s: live stats: %v", step, err)
	}
	fresh, err := New(config)
	if err != nil {
		t.Fatalf("%s: reopen: %v", step, err)
	}
	want, err := fresh.Stats()
	if err != nil {
		t.Fatalf("%s: fresh stats: %v", step, err)
	}
	got.PeakBytes, want.PeakBytes = 0, 0
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s: live index differs from disk\n live=%+v\nfresh=%+v", step, got, want)
	}
	if len(live.pending) != len(fresh.pending) || len(live.eventIDs) != len(fresh.pending) {
		t.Fatalf("%s: pending live=%d fresh=%d ids=%d", step, len(live.pending), len(fresh.pending), len(live.eventIDs))
	}
	for index := range live.pending {
		if live.pending[index] != fresh.pending[index] {
			t.Fatalf("%s: entry %d live=%+v fresh=%+v", step, index, live.pending[index], fresh.pending[index])
		}
	}
}

func TestPendingIndexIncrementalMatchesRebuild(t *testing.T) {
	config := indexTestConfig(t)
	spool := newTestSpool(t, config)
	random := rand.New(rand.NewSource(7))
	next := 0
	appended := map[int]Envelope{}
	// Dedup covers pending events only (as before): a replay of an
	// acknowledged event is stored again under a new sequence.
	assigned := map[uint64]string{}
	record := func(results []AppendResult) {
		for _, result := range results {
			if !result.Duplicate && result.Sequence > 0 {
				assigned[result.Sequence] = result.EventID
			}
		}
	}
	var published []string
	for step := 0; step < 120; step++ {
		switch op := random.Intn(4); {
		case op <= 1: // append, sometimes re-offering already appended events
			batch := make([]Envelope, 0, 8)
			if next > 0 && random.Intn(3) == 0 {
				// Replays (a tailer after a crash) are duplicates, pending or not.
				batch = append(batch, appended[random.Intn(next)])
			}
			for range 1 + random.Intn(8) {
				appended[next] = indexTestEvent(next, random)
				batch = append(batch, appended[next])
				next++
			}
			results, err := spool.AppendBatch(context.Background(), batch)
			if err != nil {
				t.Fatalf("step %d append: %v", step, err)
			}
			record(results)
		case op == 2: // flush, possibly only partly acknowledged
			publisher := &partialPublisher{acknowledge: random.Intn(3) - 1}
			if _, err := spool.Flush(context.Background(), publisher, 1+random.Intn(10)); err != nil && err.Error() != "partial" {
				t.Fatalf("step %d flush: %v", step, err)
			}
			published = append(published, publisher.ids...)
		default: // a second handle appends behind this one's back
			other := newTestSpool(t, config)
			appended[next] = indexTestEvent(next, random)
			results, err := other.AppendBatch(context.Background(), []Envelope{appended[next]})
			if err != nil {
				t.Fatalf("step %d other append: %v", step, err)
			}
			record(results)
			next++
		}
		assertIndexMatchesDisk(t, config, spool, fmt.Sprintf("step %d", step))
	}
	publisher := &partialPublisher{acknowledge: -1}
	for {
		result, err := spool.Flush(context.Background(), publisher, 10)
		if err != nil {
			t.Fatal(err)
		}
		if result.Published == 0 {
			break
		}
	}
	published = append(published, publisher.ids...)
	// At least once, in order, every event once.
	if len(published) != len(assigned) {
		t.Fatalf("published %d events, stored %d", len(published), len(assigned))
	}
	for index, id := range published {
		if id != assigned[uint64(index+1)] {
			t.Fatalf("published[%d] = %s, want %s", index, id, assigned[uint64(index+1)])
		}
	}
	assertIndexMatchesDisk(t, config, spool, "drained")
	if matches, _ := filepath.Glob(filepath.Join(config.Root, "segments", "*.seg")); len(matches) != 0 {
		t.Fatalf("acknowledged sealed segments left: %v", matches)
	}
}

// A duplicate or conflicting event is detected against the index both in the
// running handle and after a restart.
func TestPendingIndexDuplicateAndConflictAcrossRestart(t *testing.T) {
	config := indexTestConfig(t)
	spool := newTestSpool(t, config)
	random := rand.New(rand.NewSource(1))
	events := make([]Envelope, 40)
	for index := range events {
		events[index] = indexTestEvent(index, random)
	}
	if _, err := spool.AppendBatch(context.Background(), events); err != nil {
		t.Fatal(err)
	}
	conflict := events[17]
	conflict.StatusCode = 503
	for name, handle := range map[string]*Spool{"live": spool, "restarted": newTestSpool(t, config)} {
		results, err := handle.AppendBatch(context.Background(), []Envelope{events[17]})
		if err != nil || !results[0].Duplicate || results[0].Sequence != 18 {
			t.Fatalf("%s duplicate = %+v, %v", name, results, err)
		}
		if _, err := handle.AppendBatch(context.Background(), []Envelope{conflict}); !errors.Is(err, ErrConflict) {
			t.Fatalf("%s conflict error = %v", name, err)
		}
	}
}

// A pending record whose bytes change in the already-verified prefix of the
// open segment (size unchanged, so the scan does not read it again) is caught
// when it is read back for publishing. (Records this handle appended last are
// published from memory, as before; a second handle reads disk.)
func TestPendingIndexReadBackVerifiesFrame(t *testing.T) {
	config := indexTestConfig(t)
	config.MaxSegmentBytes = 1 << 20
	spool := newTestSpool(t, config)
	random := rand.New(rand.NewSource(3))
	if _, err := spool.AppendBatch(context.Background(), []Envelope{indexTestEvent(0, random), indexTestEvent(1, random)}); err != nil {
		t.Fatal(err)
	}
	spool = newTestSpool(t, config)
	if _, err := spool.Stats(); err != nil { // builds the index (New does not)
		t.Fatal(err)
	}
	changed := spool.pending[1].offset + recordHeaderSize + 10
	open, _ := filepath.Glob(filepath.Join(config.Root, "segments", "*.open"))
	file, err := os.OpenFile(open[0], os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte{'#'}, changed); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	if _, err := spool.Flush(context.Background(), &partialPublisher{acknowledge: -1}, 10); !errors.Is(err, ErrCorruptState) {
		t.Fatalf("flush of a changed frame error = %v", err)
	}
}

// An incomplete tail left by a crash is truncated both by a running handle
// and by New, and the complete records before it stay pending.
func TestPendingIndexRecoversIncompleteTail(t *testing.T) {
	config := indexTestConfig(t)
	spool := newTestSpool(t, config)
	random := rand.New(rand.NewSource(5))
	for index := 0; index < 30; index++ {
		if _, err := spool.AppendBatch(context.Background(), []Envelope{indexTestEvent(index, random)}); err != nil {
			t.Fatal(err)
		}
	}
	open, _ := filepath.Glob(filepath.Join(config.Root, "segments", "*.open"))
	file, err := os.OpenFile(open[0], os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := encodeEnvelope(indexTestEvent(30, random))
	frame := encodeFrame(payload)
	if _, err := file.Write(frame[:len(frame)/2]); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	stats, err := spool.Stats()
	if err != nil || stats.PendingEvents != 30 || stats.NextSequence != 31 {
		t.Fatalf("live stats after torn tail = %+v, %v", stats, err)
	}
	assertIndexMatchesDisk(t, config, spool, "torn tail")
	results, err := spool.AppendBatch(context.Background(), []Envelope{indexTestEvent(30, random)})
	if err != nil || results[0].Sequence != 31 {
		t.Fatalf("append after recovery = %+v, %v", results, err)
	}
	assertIndexMatchesDisk(t, config, spool, "after recovery append")
}

// Once a large backlog drains, the index storage shrinks back.
func TestPendingIndexCompactsAfterDrain(t *testing.T) {
	config := indexTestConfig(t)
	config.MaxSegmentBytes = 1 << 20
	spool := newTestSpool(t, config)
	random := rand.New(rand.NewSource(9))
	const events = 2 * compactMinimumEntries
	batch := make([]Envelope, 0, 1000)
	for index := 0; index < events; {
		batch = batch[:0]
		for len(batch) < 1000 && index < events {
			batch = append(batch, indexTestEvent(index, random))
			index++
		}
		if _, err := spool.AppendBatch(context.Background(), batch); err != nil {
			t.Fatal(err)
		}
	}
	for flushed := 0; flushed < events-100; {
		result, err := spool.Flush(context.Background(), &partialPublisher{acknowledge: -1}, min(1000, events-100-flushed))
		if err != nil {
			t.Fatal(err)
		}
		flushed += result.Published
	}
	if len(spool.pending) != 100 || cap(spool.pending) > events/4 || spool.indexPeak > events/4 {
		t.Fatalf("pending len=%d cap=%d peak=%d after drain", len(spool.pending), cap(spool.pending), spool.indexPeak)
	}
	assertIndexMatchesDisk(t, config, spool, "compacted")
}

// One handle appending, sealing, flushing and acknowledging never reads its
// own segments again: only the first operation builds the index from disk.
func TestPendingIndexSingleHandleStaysIncremental(t *testing.T) {
	config := indexTestConfig(t)
	spool := newTestSpool(t, config)
	random := rand.New(rand.NewSource(2))
	for index := 0; index < 400; index++ {
		if _, err := spool.AppendBatch(context.Background(), []Envelope{indexTestEvent(index, random)}); err != nil {
			t.Fatal(err)
		}
		if index%7 == 6 {
			if _, err := spool.Flush(context.Background(), &partialPublisher{acknowledge: -1}, 5); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := spool.Stats(); err != nil {
			t.Fatal(err)
		}
	}
	if matches, _ := filepath.Glob(filepath.Join(config.Root, "segments", "*.seg")); len(matches) == 0 {
		t.Fatal("test did not seal a segment")
	}
	if spool.fullRebuilds != 1 {
		t.Fatalf("full index rebuilds = %d, want 1 (the first operation only)", spool.fullRebuilds)
	}
	assertIndexMatchesDisk(t, config, spool, "single handle")
}

// Records published from the recent cache equal the same records read back
// from their segments (what a restarted node publishes).
func TestPendingIndexRecentCacheMatchesDisk(t *testing.T) {
	config := indexTestConfig(t)
	spool := newTestSpool(t, config)
	random := rand.New(rand.NewSource(4))
	for index := 0; index < 60; index++ {
		event := memoryTestEvent(index)
		event.OccurredAt = indexTestEvent(index, random).OccurredAt
		event.RequestBody = map[string]any{"count": index, "nested": map[string]any{"ok": true}}
		if _, err := spool.AppendBatch(context.Background(), []Envelope{event}); err != nil {
			t.Fatal(err)
		}
	}
	if len(spool.recent) == 0 {
		t.Fatal("recent cache is empty")
	}
	live, err := spool.nextBatch(context.Background(), 60)
	if err != nil {
		t.Fatal(err)
	}
	fromDisk, err := newTestSpool(t, config).nextBatch(context.Background(), 60)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(live, fromDisk) {
		t.Fatal("recent cache records differ from the records read back from disk")
	}
}
