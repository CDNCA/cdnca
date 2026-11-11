package eventspool

import (
	"crypto/sha256"
	"time"
)

// pendingRecord is the in-memory index entry of one unacknowledged record
//. The payload stays in its segment at offset and is read back
// only when the record is published.
type pendingRecord struct {
	sequence   uint64
	eventID    string
	tenantID   string
	occurredAt time.Time
	offset     int64 // frame start within its segment
	size       int64 // frame bytes (header + payload)
	digest     [sha256.Size]byte
}

// The index is s.pending: the unacknowledged records in sequence order, always
// contiguous from s.ack.Sequence+1. s.eventIDs maps their event IDs to
// sequences, s.tenantBytes sums their frames per tenant and s.oldest keeps the
// sequences whose occurredAt is a running minimum (front = oldest pending).
// Appends push, acks trim the front; only a change the index cannot explain
// (another handle sealed or recovered a segment differently, a segment
// vanished) makes a rebuild read every segment again.

const compactMinimumEntries = 4096

// The records this handle appended last are kept decoded (bounded) so that a
// node without backlog publishes them from memory, as it did before the index
//; older pending records are read back from their segments.
const (
	recentMaxRecords = 4096
	recentMaxBytes   = 4 << 20
)

func (s *Spool) pushRecentLocked(record Record) {
	if len(s.recent) > 0 && record.Sequence != s.recent[len(s.recent)-1].Sequence+1 {
		s.recent, s.recentBytes = nil, 0
	}
	s.recent = append(s.recent, record)
	s.recentBytes += record.Size
	drop := 0
	for len(s.recent)-drop > recentMaxRecords || s.recentBytes > recentMaxBytes {
		s.recentBytes -= s.recent[drop].Size
		drop++
	}
	s.dropRecentLocked(drop)
}

func (s *Spool) dropRecentLocked(drop int) {
	if drop == 0 {
		return
	}
	clear(s.recent[:drop])
	s.recent = s.recent[drop:]
	if len(s.recent) == 0 {
		s.recent, s.recentBytes = nil, 0
	}
}

// recentLocked returns the cached record with this sequence.
func (s *Spool) recentLocked(sequence uint64) (Record, bool) {
	if len(s.recent) == 0 || sequence < s.recent[0].Sequence || sequence > s.recent[len(s.recent)-1].Sequence {
		return Record{}, false
	}
	return s.recent[sequence-s.recent[0].Sequence], true
}

func (s *Spool) pendingIndexLocked(sequence uint64) (int, bool) {
	if len(s.pending) == 0 || sequence < s.pending[0].sequence {
		return 0, false
	}
	index := sequence - s.pending[0].sequence
	if index >= uint64(len(s.pending)) {
		return 0, false
	}
	return int(index), true
}

func (s *Spool) internTenantLocked(tenant string) string {
	if interned, ok := s.tenantNames[tenant]; ok {
		return interned
	}
	if s.tenantNames == nil {
		s.tenantNames = make(map[string]string)
	}
	s.tenantNames[tenant] = tenant
	return tenant
}

// pushPendingLocked appends the record after the last pending one.
func (s *Spool) pushPendingLocked(record pendingRecord) error {
	if existing, duplicate := s.eventIDs[record.eventID]; duplicate && existing != record.sequence {
		return ErrCorruptState
	}
	record.tenantID = s.internTenantLocked(record.tenantID)
	s.eventIDs[record.eventID] = record.sequence
	s.tenantBytes[record.tenantID] += record.size
	s.pending = append(s.pending, record)
	for len(s.oldest) > 0 {
		back, _ := s.pendingIndexLocked(s.oldest[len(s.oldest)-1])
		if s.pending[back].occurredAt.Before(record.occurredAt) {
			break
		}
		s.oldest = s.oldest[:len(s.oldest)-1]
	}
	s.oldest = append(s.oldest, record.sequence)
	if len(s.pending) > s.indexPeak {
		s.indexPeak = len(s.pending)
	}
	return nil
}

// trimPendingLocked drops the records acknowledged through sequence.
func (s *Spool) trimPendingLocked(sequence uint64) {
	drop := 0
	for drop < len(s.pending) && s.pending[drop].sequence <= sequence {
		record := s.pending[drop]
		delete(s.eventIDs, record.eventID)
		if remaining := s.tenantBytes[record.tenantID] - record.size; remaining > 0 {
			s.tenantBytes[record.tenantID] = remaining
		} else {
			delete(s.tenantBytes, record.tenantID)
			delete(s.tenantNames, record.tenantID)
		}
		drop++
	}
	if drop == 0 {
		return
	}
	clear(s.pending[:drop]) // release the strings of dropped entries
	s.pending = s.pending[drop:]
	front := 0
	for front < len(s.oldest) && s.oldest[front] <= sequence {
		front++
	}
	s.oldest = s.oldest[front:]
	acknowledged := 0
	for acknowledged < len(s.recent) && s.recent[acknowledged].Sequence <= sequence {
		s.recentBytes -= s.recent[acknowledged].Size
		acknowledged++
	}
	s.dropRecentLocked(acknowledged)
	if len(s.pending) == 0 {
		s.pending, s.oldest = nil, nil
	}
	// Go maps and the slice behind s.pending never shrink: once a large
	// backlog has drained, copy what is left into right-sized storage.
	if s.indexPeak >= compactMinimumEntries && len(s.pending) < s.indexPeak/4 {
		s.compactPendingLocked()
	}
}

func (s *Spool) compactPendingLocked() {
	pending := make([]pendingRecord, len(s.pending))
	copy(pending, s.pending)
	s.pending = pending
	s.oldest = append([]uint64(nil), s.oldest...)
	eventIDs := make(map[string]uint64, len(s.pending))
	for _, record := range s.pending {
		eventIDs[record.eventID] = record.sequence
	}
	s.eventIDs = eventIDs
	s.indexPeak = len(s.pending)
}

// resetIndexLocked builds the index from every record on disk (the result of
// a scan with an empty segment cache).
func (s *Spool) resetIndexLocked(records []pendingRecord) error {
	keep := 0
	for _, record := range records {
		if record.sequence > s.ack.Sequence {
			keep++
		}
	}
	// Filter in place: the scan result is not used again, and a second
	// backlog-sized slice would double the startup peak.
	s.pending = records[:0]
	s.oldest = nil
	s.eventIDs = make(map[string]uint64, keep)
	s.tenantBytes = make(map[string]int64)
	s.tenantNames = make(map[string]string)
	s.indexPeak = 0
	s.recent, s.recentBytes = nil, 0
	for _, record := range records {
		if record.sequence <= s.ack.Sequence {
			continue
		}
		if len(s.pending) > 0 && record.sequence != s.pending[len(s.pending)-1].sequence+1 {
			return ErrCorruptState
		}
		if err := s.pushPendingLocked(record); err != nil {
			return err
		}
	}
	s.indexed = true
	return nil
}

// mergeIndexLocked applies a scan to the index: drops what the ack covers,
// checks re-read records against their entries and appends new ones. It
// reports false when the index cannot be reconciled with the segments.
func (s *Spool) mergeIndexLocked(records []pendingRecord, metas []segmentMeta) bool {
	s.trimPendingLocked(s.ack.Sequence)
	for _, record := range records {
		if record.sequence <= s.ack.Sequence {
			continue
		}
		if index, known := s.pendingIndexLocked(record.sequence); known {
			if s.pending[index].eventID != record.eventID || s.pending[index].digest != record.digest ||
				s.pending[index].offset != record.offset || s.pending[index].size != record.size {
				return false
			}
			continue
		}
		if (len(s.pending) > 0 && record.sequence != s.pending[len(s.pending)-1].sequence+1) || s.pushPendingLocked(record) != nil {
			return false
		}
	}
	// Every unacknowledged record on disk must be indexed, and only those.
	want := 0
	for _, meta := range metas {
		if meta.records == 0 || meta.max <= s.ack.Sequence {
			continue
		}
		first := max(meta.start, s.ack.Sequence+1)
		want += int(meta.max - first + 1)
	}
	return want == len(s.pending)
}

func (s *Spool) oldestOccurredAtLocked() time.Time {
	if len(s.oldest) == 0 {
		return time.Time{}
	}
	index, _ := s.pendingIndexLocked(s.oldest[0])
	return s.pending[index].occurredAt
}
