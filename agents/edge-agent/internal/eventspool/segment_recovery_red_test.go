package eventspool

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestNewRejectsOpenSegmentBeforeLaterSealedSegment(t *testing.T) {
	config := testConfig(t.TempDir())
	spool := newTestSpool(t, config)

	openEvent := pendingAccess("evt-open-before-sealed", tenantOne)
	openEvent.Sequence = 1
	sealedEvent := pendingAccess("evt-sealed-after-open", tenantOne)
	sealedEvent.Sequence = 2
	writeRecoverySegment(t, spool, 1, "open", openEvent)
	writeRecoverySegment(t, spool, 2, "seg", sealedEvent)

	// New does not read segments (the node must serve while a
	// backlog or a corrupt spool is read); the first operation reports it.
	restarted, err := New(config)
	if err != nil {
		t.Fatalf("New = %v, want success", err)
	}
	if _, err := restarted.Stats(); !errors.Is(err, ErrCorruptState) {
		t.Fatalf("open segment before sealed segment error = %v, want ErrCorruptState", err)
	}
	if code := restarted.FailureCode(); code != "TELEMETRY_SPOOL_CORRUPT" {
		t.Fatalf("failure code = %q", code)
	}
}

func writeRecoverySegment(t *testing.T, spool *Spool, start uint64, suffix string, event Envelope) {
	t.Helper()
	payload, err := encodeEnvelope(event)
	if err != nil {
		t.Fatal(err)
	}
	data := append(encodeSegmentHeader(start), encodeFrame(payload)...)
	path := filepath.Join(spool.segmentsDir, segmentName(start, suffix))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
