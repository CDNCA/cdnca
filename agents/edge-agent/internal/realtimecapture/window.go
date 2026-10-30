package realtimecapture

import (
	"crypto/sha256"
	"encoding/binary"
	"time"
)

const MaximumGap = 15 * time.Second
const FinalizationGrace = 2 * time.Minute

type CompletedWindow struct {
	Start, End, ObservedAt             time.Time
	Connections                        uint64
	AccessEvidence, ConnectionEvidence [32]byte
}

// Tracker certifies only full UTC hours continuously observed by this process.
// A restart, clock regression, source error or gap discards incomplete coverage.
type Tracker struct {
	start, last      time.Time
	complete         bool
	connections      uint64
	connectionDigest [32]byte
	closed           []CompletedWindow
}

func (tracker *Tracker) Observe(at time.Time, connections uint64, accessEvidence, connectionEvidence [32]byte, healthy bool) []CompletedWindow {
	at = at.UTC()
	if !healthy || at.IsZero() || accessEvidence == ([32]byte{}) || connectionEvidence == ([32]byte{}) ||
		!tracker.last.IsZero() && (at.Before(tracker.last) || at.Sub(tracker.last) > MaximumGap) {
		*tracker = Tracker{}
		return nil
	}
	start := at.Truncate(time.Hour)
	if tracker.last.IsZero() {
		tracker.start, tracker.complete = start, at.Equal(start)
	} else if start.After(tracker.start) {
		end := tracker.start.Add(time.Hour)
		if tracker.complete && end.Sub(tracker.last) <= MaximumGap && at.Sub(end) <= MaximumGap {
			tracker.closed = append(tracker.closed, CompletedWindow{Start: tracker.start, End: end, ObservedAt: tracker.last, Connections: tracker.connections, ConnectionEvidence: tracker.connectionDigest})
		}
		tracker.start, tracker.complete = start, at.Sub(start) <= MaximumGap
		tracker.connectionDigest = [32]byte{}
	}
	var value [8]byte
	binary.BigEndian.PutUint64(value[:], uint64(at.UnixMilli()))
	hash := sha256.New()
	hash.Write(tracker.connectionDigest[:])
	hash.Write(value[:])
	hash.Write(connectionEvidence[:])
	copy(tracker.connectionDigest[:], hash.Sum(nil))
	tracker.last, tracker.connections = at, connections
	var done []CompletedWindow
	for len(tracker.closed) > 0 && !at.Before(tracker.closed[0].End.Add(FinalizationGrace)) {
		window := tracker.closed[0]
		window.AccessEvidence = accessEvidence
		done = append(done, window)
		tracker.closed = tracker.closed[1:]
	}
	return done
}
