package eventspool

import (
	"context"
	"errors"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// New must not read the backlog. The agent
// assembles the spool before it hands OpenResty its configuration, so a
// backlog (78: 747k records, 24.8 s in New) kept the node from serving.
// The index is built by the first locked operation, in the telemetry
// goroutine; a corrupt spool is reported there and the node keeps serving.

func TestNewDoesNotReadBacklog(t *testing.T) {
	root := filepath.Join(t.TempDir(), "spool")
	if resolved, err := filepath.EvalSymlinks(filepath.Dir(root)); err == nil {
		root = filepath.Join(resolved, "spool")
	}
	const events = 50000
	writeMemoryBacklog(t, root, events)
	started := time.Now()
	spool, err := New(memoryTestConfig(root))
	elapsed := time.Since(started)
	if err != nil {
		t.Fatal(err)
	}
	if spool.fullRebuilds != 0 || spool.indexed {
		t.Fatalf("New read the backlog: full rebuilds=%d indexed=%v", spool.fullRebuilds, spool.indexed)
	}
	// Reading the directory, the lock and the ack file only: well under the
	// ~1 s a full read of 50k records takes.
	if elapsed > 200*time.Millisecond {
		t.Fatalf("New took %s with %d pending records", elapsed, events)
	}
	stats, err := spool.Stats()
	if err != nil || stats.PendingEvents != events || stats.NextSequence != events+1 {
		t.Fatalf("first operation stats = %+v, %v", stats, err)
	}
	if spool.fullRebuilds != 1 {
		t.Fatalf("full rebuilds after first operation = %d, want 1", spool.fullRebuilds)
	}
	t.Logf("events=%d new=%s", events, elapsed)
}

func corruptLastSealedSegment(t *testing.T, config Config) (string, byte) {
	t.Helper()
	matches, _ := filepath.Glob(filepath.Join(config.Root, "segments", "*.seg"))
	if len(matches) == 0 {
		t.Fatal("no sealed segment")
	}
	path := matches[len(matches)-1]
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	original := make([]byte, 1)
	offset := int64(segmentHeaderSize + recordHeaderSize + 4)
	if _, err := file.ReadAt(original, offset); err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte{original[0] ^ 0xff}, offset); err != nil {
		t.Fatal(err)
	}
	return path, original[0]
}

// A corrupt segment no longer stops New. The first operation reports it and
// records the failure for the node's health; retries do not read the spool
// again until a segment changes; a repaired spool is indexed again.
func TestCorruptSpoolReportedByFirstOperation(t *testing.T) {
	config := indexTestConfig(t)
	writer := newTestSpool(t, config)
	random := rand.New(rand.NewSource(6))
	for index := 0; index < 60; index++ {
		if _, err := writer.AppendBatch(context.Background(), []Envelope{indexTestEvent(index, random)}); err != nil {
			t.Fatal(err)
		}
	}
	path, original := corruptLastSealedSegment(t, config)
	spool, err := New(config)
	if err != nil {
		t.Fatalf("New on a corrupt spool = %v, want success (the node must keep serving)", err)
	}
	if code := spool.FailureCode(); code != "" {
		t.Fatalf("failure code before any operation = %q", code)
	}
	if _, err := spool.Stats(); !errors.Is(err, ErrCorruptState) {
		t.Fatalf("first operation error = %v, want ErrCorruptState", err)
	}
	if code := spool.FailureCode(); code != "TELEMETRY_SPOOL_CORRUPT" {
		t.Fatalf("failure code = %q", code)
	}
	scans := spool.fullRebuilds
	for range 5 {
		if _, err := spool.Flush(context.Background(), &partialPublisher{acknowledge: -1}, 10); !errors.Is(err, ErrCorruptState) {
			t.Fatalf("retry error = %v", err)
		}
		if _, err := spool.AppendBatch(context.Background(), []Envelope{indexTestEvent(1000, random)}); !errors.Is(err, ErrCorruptState) {
			t.Fatalf("append on a corrupt spool = %v", err)
		}
	}
	if spool.fullRebuilds != scans {
		t.Fatalf("unchanged corrupt spool read again: %d full scans after %d", spool.fullRebuilds, scans)
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte{original}, int64(segmentHeaderSize+recordHeaderSize+4)); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	future := time.Now().Add(time.Minute)
	_ = os.Chtimes(path, future, future)
	stats, err := spool.Stats()
	if err != nil || stats.PendingEvents != 60 {
		t.Fatalf("repaired spool stats = %+v, %v", stats, err)
	}
	if code := spool.FailureCode(); code != "" {
		t.Fatalf("failure code after repair = %q", code)
	}
	assertIndexMatchesDisk(t, config, spool, "repaired")
}

// TestStartupBacklogPerf times New and the first operation for a production
// backlog (opt-in: CDNCA_SPOOL_STARTUP_EVENTS, e.g. 747000).
func TestStartupBacklogPerf(t *testing.T) {
	events, _ := strconv.Atoi(os.Getenv("CDNCA_SPOOL_STARTUP_EVENTS"))
	if events <= 0 {
		t.Skip("set CDNCA_SPOOL_STARTUP_EVENTS to time spool startup on a backlog")
	}
	root := filepath.Join(t.TempDir(), "spool")
	if resolved, err := filepath.EvalSymlinks(filepath.Dir(root)); err == nil {
		root = filepath.Join(resolved, "spool")
	}
	writeMemoryBacklog(t, root, events)
	started := time.Now()
	spool, err := New(memoryTestConfig(root))
	if err != nil {
		t.Fatal(err)
	}
	newElapsed := time.Since(started)
	started = time.Now()
	stats, err := spool.Stats()
	if err != nil || stats.PendingEvents != events {
		t.Fatalf("stats = %+v, %v", stats, err)
	}
	t.Logf("PERF startup events=%d new=%s first_operation=%s", events, newElapsed.Round(time.Microsecond),
		time.Since(started).Round(time.Millisecond))
}

type countingPublisher struct{ calls int }

func (p *countingPublisher) Publish(_ context.Context, publications []Publication) (PublishAck, error) {
	p.calls++
	return PublishAck{Acknowledged: len(publications)}, nil
}

// a corrupt ack.json no longer stops New. While it is corrupt
// the spool does not know which events the control plane already has, so
// nothing is published (no duplicate upload); the failure is reported
// (TELEMETRY_SPOOL_ACK_CORRUPT) and a repaired file is picked up again.
func TestCorruptAckReportedAndNotPublished(t *testing.T) {
	config := indexTestConfig(t)
	writer := newTestSpool(t, config)
	random := rand.New(rand.NewSource(8))
	for index := 0; index < 30; index++ {
		if _, err := writer.AppendBatch(context.Background(), []Envelope{indexTestEvent(index, random)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := writer.Flush(context.Background(), &partialPublisher{acknowledge: -1}, 10); err != nil {
		t.Fatal(err)
	}
	ackPath := filepath.Join(config.Root, "state", "ack.json")
	good, err := os.ReadFile(ackPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ackPath, []byte("{\"schema_version\":"), 0o600); err != nil {
		t.Fatal(err)
	}
	spool, err := New(config)
	if err != nil {
		t.Fatalf("New with a corrupt ack.json = %v, want success (the node must keep serving)", err)
	}
	publisher := &countingPublisher{}
	for range 3 {
		if _, err := spool.Flush(context.Background(), publisher, 10); !errors.Is(err, ErrCorruptState) {
			t.Fatalf("flush with a corrupt ack.json = %v, want ErrCorruptState", err)
		}
	}
	if publisher.calls != 0 {
		t.Fatalf("published %d times while the acknowledged position is unknown", publisher.calls)
	}
	if _, err := spool.Stats(); !errors.Is(err, ErrCorruptState) {
		t.Fatalf("stats with a corrupt ack.json = %v", err)
	}
	if code := spool.FailureCode(); code != "TELEMETRY_SPOOL_ACK_CORRUPT" {
		t.Fatalf("failure code = %q", code)
	}
	if err := os.WriteFile(ackPath, good, 0o600); err != nil {
		t.Fatal(err)
	}
	stats, err := spool.Stats()
	if err != nil || stats.AckedSequence == 0 || stats.PendingEvents != 30-int(stats.AckedSequence) {
		t.Fatalf("stats after repair = %+v, %v", stats, err)
	}
	if code := spool.FailureCode(); code != "" {
		t.Fatalf("failure code after repair = %q", code)
	}
	result, err := spool.Flush(context.Background(), publisher, 10)
	if err != nil || result.Published == 0 || result.LastSequence <= stats.AckedSequence {
		t.Fatalf("flush after repair = %+v, %v", result, err)
	}
	assertIndexMatchesDisk(t, config, spool, "ack repaired")
}

// an unsafe ack.json (symbolic link, hard link, mode) is not a
// corrupt one: it stays fatal like an unsafe spool root.
func TestUnsafeAckStaysFatal(t *testing.T) {
	for name, unsafe := range map[string]func(t *testing.T, ackPath string){
		"symlink": func(t *testing.T, ackPath string) {
			target := filepath.Join(t.TempDir(), "ack.json")
			if err := os.Rename(ackPath, target); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, ackPath); err != nil {
				t.Fatal(err)
			}
		},
		"hardlink": func(t *testing.T, ackPath string) {
			if err := os.Link(ackPath, ackPath+".link"); err != nil {
				t.Fatal(err)
			}
		},
		"mode": func(t *testing.T, ackPath string) {
			if err := os.Chmod(ackPath, 0o644); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := indexTestConfig(t)
			spool := newTestSpool(t, config)
			if _, err := spool.AppendBatch(context.Background(), []Envelope{pendingAccess("evt-ack", tenantOne)}); err != nil {
				t.Fatal(err)
			}
			if _, err := spool.Flush(context.Background(), &partialPublisher{acknowledge: -1}, 10); err != nil {
				t.Fatal(err)
			}
			unsafe(t, filepath.Join(config.Root, "state", "ack.json"))
			if _, err := New(config); !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("New with an unsafe ack.json = %v, want ErrUnsafePath", err)
			}
		})
	}
}
