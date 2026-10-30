package eventspool

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Offline replay: a node that was cut off from the gateway for longer than the
// soft age limit replays log lines that are themselves old. Once the spool has
// drained, those lines must be accepted (soft pressure is a property of the
// stored backlog, not of the incoming line); lines older than the hard age
// limit are skipped and counted instead of wedging the tailer forever.

func agedAccess(id string, occurred time.Time) Envelope {
	event := pendingAccess(id, tenantOne)
	event.OccurredAt = occurred
	return event
}

func TestSpoolAcceptsOldEventsWhenBacklogIsEmpty(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()
	now := base.Add(25 * time.Hour)
	config := testConfig(t.TempDir())
	config.Now = func() time.Time { return now }
	spool := newTestSpool(t, config)

	// Spool empty, two 25h-old lines in one batch: both stored (the batch's
	// own lines are not backlog).
	results, err := spool.AppendBatch(context.Background(), []Envelope{
		agedAccess("evt-old-1", base), agedAccess("evt-old-2", base.Add(time.Minute)),
	})
	if err != nil || len(results) != 2 || results[0].Sequence != 1 || results[1].Sequence != 2 {
		t.Fatalf("25h-old replay on empty spool = %#v, %v", results, err)
	}
	// Stored backlog is now 25h old: further appends are pushed back until
	// the backlog drains.
	if _, err := spool.AppendBatch(context.Background(), []Envelope{agedAccess("evt-fresh", now)}); !errors.Is(err, ErrBackpressure) {
		t.Fatalf("append behind 25h backlog = %v, want backpressure", err)
	}
	publisher := &collectingPublisher{}
	if result, err := spool.Flush(context.Background(), publisher, 100); err != nil || result.Published != 2 {
		t.Fatalf("flush = %#v, %v", result, err)
	}
	if _, err := spool.AppendBatch(context.Background(), []Envelope{agedAccess("evt-old-3", base.Add(2*time.Minute))}); err != nil {
		t.Fatalf("append after drain = %v", err)
	}
	stats, _ := spool.Stats()
	if stats.PendingEvents != 1 || stats.NextSequence != 4 {
		t.Fatalf("stats after drain = %#v", stats)
	}
}

func TestSpoolSkipsEventsPastHardAgeAndCountsThem(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()
	now := base.Add(170 * time.Hour)
	config := testConfig(t.TempDir())
	config.Now = func() time.Time { return now }
	spool := newTestSpool(t, config)

	batch := []Envelope{agedAccess("evt-expired", base), agedAccess("evt-recent", now.Add(-time.Hour))}
	results, err := spool.AppendBatch(context.Background(), batch)
	if err != nil || len(results) != 2 || !results[0].Expired || results[0].Sequence != 0 ||
		results[1].Expired || results[1].Sequence != 1 {
		t.Fatalf("170h-old line = %#v, %v", results, err)
	}
	// Replay (crash before the tail checkpoint): same outcome, nothing doubles.
	results, err = spool.AppendBatch(context.Background(), batch)
	if err != nil || !results[0].Expired || !results[1].Duplicate || results[1].Sequence != 1 {
		t.Fatalf("replay = %#v, %v", results, err)
	}
	stats, _ := spool.Stats()
	if stats.PendingEvents != 1 || stats.NextSequence != 2 || stats.ExpiredEvents != 2 || stats.LastAlertCode != "SPOOL_EVENT_EXPIRED" {
		t.Fatalf("stats = %#v", stats)
	}
	// The counter survives a restart.
	restarted := newTestSpool(t, config)
	if stats, _ := restarted.Stats(); stats.ExpiredEvents != 2 {
		t.Fatalf("restarted expired = %d", stats.ExpiredEvents)
	}
}

func TestTailerReplaysAfterLongOutage(t *testing.T) {
	source, _, config := newTailHarness(t)
	base := time.Unix(1_700_000_000, 0).UTC()
	now := base.Add(170 * time.Hour)
	spoolConfig := testConfig(t.TempDir())
	spoolConfig.SoftLimitBytes = 1 << 20
	spoolConfig.HardLimitBytes = 2 << 20
	spoolConfig.MaxTenantBytes = 1 << 20
	spoolConfig.Now = func() time.Time { return now }
	spool := newTestSpool(t, spoolConfig)

	for index, occurred := range []time.Time{base, now.Add(-25 * time.Hour), now} {
		event := sourceAccess(tenantOne)
		event.OccurredAt = occurred
		event.RequestID = "request-" + string(rune('a'+index))
		appendSource(t, source, event, true)
	}
	tailer, err := NewTailer(config)
	if err != nil {
		t.Fatal(err)
	}
	result, err := tailer.TailOnce(context.Background(), spool)
	if err != nil || result.CompletedLines != 3 || result.ExpiredEvents != 1 || result.AppendedEvents != 2 {
		t.Fatalf("tail after outage = %#v, %v", result, err)
	}
	result, err = tailer.TailOnce(context.Background(), spool)
	if err != nil || result.CompletedLines != 0 {
		t.Fatalf("tail did not advance past replayed lines: %#v, %v", result, err)
	}
	if stats, _ := spool.Stats(); stats.PendingEvents != 2 || stats.ExpiredEvents != 1 {
		t.Fatalf("stats = %#v", stats)
	}
}
