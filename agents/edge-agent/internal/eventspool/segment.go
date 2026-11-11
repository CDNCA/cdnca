package eventspool

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"syscall"
)

const (
	segmentHeaderSize      = 24
	recordHeaderSize       = 40
	segmentReadBufferBytes = 256 << 10
)

var (
	segmentMagic       = [8]byte{'C', 'D', 'N', 'E', 'V', 'T', '1', 0}
	segmentNamePattern = regexp.MustCompile(`^segment-([0-9]{20})\.(open|seg)$`)
	crcTable           = crc32.MakeTable(crc32.Castagnoli)
)

type segmentMeta struct {
	path    string
	name    string
	start   uint64
	max     uint64
	size    int64
	open    bool
	records int
}

func segmentName(start uint64, suffix string) string {
	return fmt.Sprintf("segment-%020d.%s", start, suffix)
}

func parseSegmentName(name string) (uint64, bool, bool) {
	matches := segmentNamePattern.FindStringSubmatch(name)
	if len(matches) != 3 {
		return 0, false, false
	}
	start, err := strconv.ParseUint(matches[1], 10, 64)
	return start, matches[2] == "open", err == nil && start > 0
}

func encodeSegmentHeader(start uint64) []byte {
	header := make([]byte, segmentHeaderSize)
	copy(header[:8], segmentMagic[:])
	binary.BigEndian.PutUint16(header[8:10], SchemaVersion)
	binary.BigEndian.PutUint64(header[16:24], start)
	return header
}

func encodeFrame(payload []byte) []byte {
	frame := make([]byte, recordHeaderSize+len(payload))
	binary.BigEndian.PutUint32(frame[0:4], uint32(len(payload)))
	binary.BigEndian.PutUint32(frame[4:8], crc32.Checksum(payload, crcTable))
	digest := sha256.Sum256(payload)
	copy(frame[8:40], digest[:])
	copy(frame[40:], payload)
	return frame
}

func decodeStoredEnvelope(payload []byte) (Envelope, error) {
	if len(payload) < 2 || payload[len(payload)-1] != '\n' || bytes.IndexByte(payload[:len(payload)-1], '\n') >= 0 || validateUniqueJSONKeys(payload[:len(payload)-1]) != nil {
		return Envelope{}, ErrCorruptState
	}
	envelope, err := decodeEncodedEnvelope(payload)
	if err != nil || validateEnvelope(envelope, identityStored) != nil {
		return Envelope{}, ErrCorruptState
	}
	return envelope, nil
}

// decodeEncodedEnvelope decodes a frame payload as stored (strict fields,
// numbers kept as written). Bytes this process just produced with
// encodeEnvelope need nothing more: json.Marshal of the struct writes no
// duplicate key, and encodeEnvelope validated the envelope. Bytes read back
// from a segment go through decodeStoredEnvelope.
func decodeEncodedEnvelope(payload []byte) (Envelope, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload[:len(payload)-1]))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	var envelope Envelope
	if err := decoder.Decode(&envelope); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return Envelope{}, ErrCorruptState
	}
	return envelope, nil
}

func contentDigest(envelope Envelope) [sha256.Size]byte {
	envelope.Sequence = 0
	encoded, _ := json.Marshal(envelope)
	return sha256.Sum256(encoded)
}

// scanSegmentsLocked lists the segments and returns the index entries it had
// to read: records of new or changed segments and the new tail of the open
// segment. Segments unchanged since the last scan are not read (their records
// are already indexed in s.pending).
func (s *Spool) scanSegmentsLocked(recoverOpen bool) ([]pendingRecord, []segmentMeta, int64, error) {
	entries, err := os.ReadDir(s.segmentsDir)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("read event spool segments: %w", err)
	}
	type namedSegment struct {
		name  string
		start uint64
		open  bool
	}
	named := make([]namedSegment, 0, len(entries))
	openCount := 0
	for _, entry := range entries {
		start, open, valid := parseSegmentName(entry.Name())
		if !valid || entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil, nil, 0, ErrCorruptState
		}
		if open {
			openCount++
		}
		named = append(named, namedSegment{name: entry.Name(), start: start, open: open})
	}
	if openCount > 1 {
		return nil, nil, 0, ErrCorruptState
	}
	sort.Slice(named, func(i, j int) bool { return named[i].start < named[j].start })
	for index, entry := range named {
		if entry.open && index != len(named)-1 {
			return nil, nil, 0, ErrCorruptState
		}
	}

	listedNames := make(map[string]struct{}, len(named))
	for _, entry := range named {
		listedNames[entry.name] = struct{}{}
	}
	var records []pendingRecord
	metas := make([]segmentMeta, 0, len(named))
	var total int64
	var previousSequence uint64
	seenSequence := false
	for _, entry := range named {
		path := filepath.Join(s.segmentsDir, entry.name)
		segmentRecords, meta, err := s.readSegmentLocked(path, entry, recoverOpen)
		if err != nil {
			return nil, nil, 0, err
		}
		// Each segment's records are contiguous from its start sequence
		// (readSegmentLocked), so contiguity across segments is a check on
		// the segment boundaries.
		if meta.records > 0 {
			if seenSequence && meta.start != previousSequence+1 {
				return nil, nil, 0, ErrCorruptState
			}
			seenSequence = true
			previousSequence = meta.max
		}
		records = append(records, segmentRecords...)
		metas = append(metas, meta)
		total += meta.size
	}
	for name := range s.segmentCache {
		if _, listed := listedNames[name]; !listed {
			delete(s.segmentCache, name)
		}
	}
	return records, metas, total, nil
}

func (s *Spool) readSegmentLocked(path string, named struct {
	name  string
	start uint64
	open  bool
}, recoverOpen bool) ([]pendingRecord, segmentMeta, error) {
	flags := os.O_RDONLY | syscall.O_NOFOLLOW
	if named.open && recoverOpen {
		flags = os.O_RDWR | syscall.O_NOFOLLOW
	}
	file, err := os.OpenFile(path, flags, 0)
	if err != nil {
		return nil, segmentMeta{}, fmt.Errorf("open event spool segment: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	identity, ok := info.Sys().(*syscall.Stat_t)
	if err != nil || !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || identity.Nlink != 1 || uint64(identity.Dev) != s.device {
		return nil, segmentMeta{}, ErrUnsafePath
	}
	changedSec, changedNSec := statChangeTime(identity)
	key := sealedSegmentKey{device: uint64(identity.Dev), inode: uint64(identity.Ino), size: info.Size(),
		modified: info.ModTime().UnixNano(), changedSec: changedSec, changedNSec: changedNSec}
	cached, haveCache := s.segmentCache[named.name]
	if haveCache && !named.open && cached.key == key {
		return nil, cached.meta, nil
	}
	// This handle sealed its open segment by renaming it: the same file at
	// the size already verified (or written) under the open name is adopted
	// without reading it again.
	openName := segmentName(named.start, "open")
	if prior, renamed := s.segmentCache[openName]; !haveCache && !named.open && renamed && prior.meta.open &&
		prior.meta.records > 0 && prior.key.device == key.device && prior.key.inode == key.inode && prior.meta.size == key.size {
		meta := prior.meta
		meta.path, meta.name, meta.open = path, named.name, false
		s.segmentCache[named.name] = cachedSegment{key: key, meta: meta}
		delete(s.segmentCache, openName)
		return nil, meta, nil
	}
	// An open segment only grows by appends (recovery truncates an
	// incomplete tail past the verified prefix), so a verified prefix of the
	// same file is kept and only the bytes after it are read.
	resume := haveCache && named.open && cached.meta.open && cached.key.device == key.device &&
		cached.key.inode == key.inode && cached.meta.size <= key.size
	meta := segmentMeta{path: path, name: named.name, start: named.start, size: info.Size(), open: named.open}
	position := int64(segmentHeaderSize)
	expected := named.start
	var records []pendingRecord
	if resume {
		if _, err := file.Seek(cached.meta.size, io.SeekStart); err != nil {
			return nil, segmentMeta{}, fmt.Errorf("seek event spool segment: %w", err)
		}
		position = cached.meta.size
		meta.max, meta.records = cached.meta.max, cached.meta.records
		expected = named.start + uint64(cached.meta.records)
	}
	// One buffered reader per segment: two unbuffered reads per record made
	// every rebuild syscall-bound.
	reader := bufio.NewReaderSize(file, segmentReadBufferBytes)
	if !resume {
		header := make([]byte, segmentHeaderSize)
		if _, err := io.ReadFull(reader, header); err != nil || !bytes.Equal(header[:8], segmentMagic[:]) ||
			binary.BigEndian.Uint16(header[8:10]) != SchemaVersion || binary.BigEndian.Uint64(header[16:24]) != named.start {
			return nil, segmentMeta{}, ErrCorruptState
		}
	}
	recordHeader := make([]byte, recordHeaderSize)
	for {
		recordStart := position
		read, readErr := io.ReadFull(reader, recordHeader)
		if errors.Is(readErr, io.EOF) && read == 0 {
			break
		}
		if readErr != nil {
			if named.open && recoverOpen && (errors.Is(readErr, io.ErrUnexpectedEOF) || errors.Is(readErr, io.EOF)) {
				if err := truncateRecoveredTail(file, recordStart); err != nil {
					return nil, segmentMeta{}, err
				}
				meta.size = recordStart
				break
			}
			return nil, segmentMeta{}, ErrCorruptState
		}
		length := binary.BigEndian.Uint32(recordHeader[0:4])
		if length == 0 || int(length) > s.config.MaxEventBytes {
			return nil, segmentMeta{}, ErrCorruptState
		}
		payload := make([]byte, int(length))
		if _, err := io.ReadFull(reader, payload); err != nil {
			if named.open && recoverOpen && (errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF)) {
				if err := truncateRecoveredTail(file, recordStart); err != nil {
					return nil, segmentMeta{}, err
				}
				meta.size = recordStart
				break
			}
			return nil, segmentMeta{}, ErrCorruptState
		}
		if crc32.Checksum(payload, crcTable) != binary.BigEndian.Uint32(recordHeader[4:8]) {
			return nil, segmentMeta{}, ErrCorruptState
		}
		digest := sha256.Sum256(payload)
		if !bytes.Equal(digest[:], recordHeader[8:40]) {
			return nil, segmentMeta{}, ErrCorruptState
		}
		envelope, err := decodeStoredEnvelope(payload)
		if err != nil || envelope.Sequence != expected {
			return nil, segmentMeta{}, ErrCorruptState
		}
		frameSize := int64(recordHeaderSize + len(payload))
		records = append(records, pendingRecord{
			sequence: envelope.Sequence, eventID: envelope.EventID, tenantID: envelope.TenantID,
			occurredAt: envelope.OccurredAt, offset: recordStart, size: frameSize, digest: contentDigest(envelope),
		})
		meta.max = envelope.Sequence
		meta.records++
		expected++
		position += frameSize
	}
	if meta.records == 0 && !meta.open {
		return nil, segmentMeta{}, ErrCorruptState
	}
	if s.segmentCache == nil {
		s.segmentCache = make(map[string]cachedSegment)
	}
	key.size = meta.size
	s.segmentCache[named.name] = cachedSegment{key: key, meta: meta}
	return records, meta, nil
}

// Verified segments are not read again across rebuilds. Only their metadata
// is kept (caching every decoded record made memory grow with the backlog);
// their records live in the s.pending index. A sealed segment is never
// rewritten (only removed once acknowledged), so it is reused while its
// identity, size, mtime and ctime are unchanged.
type sealedSegmentKey struct {
	device, inode           uint64
	size, modified          int64
	changedSec, changedNSec int64
}

type cachedSegment struct {
	key  sealedSegmentKey
	meta segmentMeta
}

// readPendingLocked reads the first count pending records back from their
// segments (payloads are not kept in memory). Each frame is
// verified again (length, CRC, SHA-256, sequence and event ID) since it was
// read from disk once more.
func (s *Spool) readPendingLocked(count int) ([]Record, error) {
	result := make([]Record, 0, count)
	metaIndex := 0
	for len(result) < count {
		first := s.pending[len(result)]
		if cached, ok := s.recentLocked(first.sequence); ok {
			cached.Payload = append([]byte(nil), cached.Payload...)
			result = append(result, cached)
			continue
		}
		for metaIndex < len(s.metas) && (s.metas[metaIndex].records == 0 || s.metas[metaIndex].max < first.sequence) {
			metaIndex++
		}
		if metaIndex == len(s.metas) || s.metas[metaIndex].start > first.sequence {
			return nil, ErrCorruptState
		}
		meta := s.metas[metaIndex]
		end := len(result)
		for end < count && s.pending[end].sequence <= meta.max {
			if _, ok := s.recentLocked(s.pending[end].sequence); ok {
				break
			}
			end++
		}
		records, err := s.readSegmentRecordsLocked(meta, s.pending[len(result):end])
		if err != nil {
			return nil, err
		}
		result = append(result, records...)
	}
	return result, nil
}

// readSegmentRecordsLocked reads the given contiguous entries of one segment.
func (s *Spool) readSegmentRecordsLocked(meta segmentMeta, entries []pendingRecord) ([]Record, error) {
	file, err := os.OpenFile(meta.path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open event spool segment: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	identity, ok := infoSys(info)
	if err != nil || !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || identity.Nlink != 1 || uint64(identity.Dev) != s.device {
		return nil, ErrUnsafePath
	}
	last := entries[len(entries)-1]
	span := last.offset + last.size - entries[0].offset
	reader := bufio.NewReaderSize(io.NewSectionReader(file, entries[0].offset, span), int(min(span, segmentReadBufferBytes)))
	records := make([]Record, 0, len(entries))
	header := make([]byte, recordHeaderSize)
	position := entries[0].offset
	for _, entry := range entries {
		if entry.offset != position {
			return nil, ErrCorruptState
		}
		if _, err := io.ReadFull(reader, header); err != nil {
			return nil, ErrCorruptState
		}
		length := binary.BigEndian.Uint32(header[0:4])
		if int64(length)+recordHeaderSize != entry.size {
			return nil, ErrCorruptState
		}
		payload := make([]byte, int(length))
		if _, err := io.ReadFull(reader, payload); err != nil ||
			crc32.Checksum(payload, crcTable) != binary.BigEndian.Uint32(header[4:8]) {
			return nil, ErrCorruptState
		}
		if digest := sha256.Sum256(payload); !bytes.Equal(digest[:], header[8:40]) {
			return nil, ErrCorruptState
		}
		envelope, err := decodeStoredEnvelope(payload)
		if err != nil || envelope.Sequence != entry.sequence || envelope.EventID != entry.eventID {
			return nil, ErrCorruptState
		}
		records = append(records, Record{
			Sequence: envelope.Sequence, EventID: envelope.EventID, TenantID: envelope.TenantID,
			NodeID: envelope.NodeID, Type: envelope.Type, OccurredAt: envelope.OccurredAt,
			Payload: payload, Size: entry.size, digest: entry.digest, envelope: envelope,
		})
		position += entry.size
	}
	return records, nil
}

func truncateRecoveredTail(file *os.File, size int64) error {
	if err := file.Truncate(size); err != nil {
		return fmt.Errorf("truncate incomplete event spool tail: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync recovered event spool segment: %w", err)
	}
	return nil
}

func safeErrorCode(err error) string {
	switch {
	case errors.Is(err, syscall.ENOSPC), errors.Is(err, syscall.EDQUOT):
		return "SPOOL_DISK_FULL"
	default:
		return "SPOOL_WRITE_FAILED"
	}
}
