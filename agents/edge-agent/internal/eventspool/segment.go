package eventspool

import (
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
	segmentHeaderSize = 24
	recordHeaderSize  = 40
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
	decoder := json.NewDecoder(bytes.NewReader(payload[:len(payload)-1]))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	var envelope Envelope
	if err := decoder.Decode(&envelope); err != nil || decoder.Decode(&struct{}{}) != io.EOF || validateEnvelope(envelope, identityStored) != nil {
		return Envelope{}, ErrCorruptState
	}
	return envelope, nil
}

func contentDigest(envelope Envelope) [sha256.Size]byte {
	envelope.Sequence = 0
	encoded, _ := json.Marshal(envelope)
	return sha256.Sum256(encoded)
}

func (s *Spool) scanSegmentsLocked(recoverOpen bool) ([]Record, []segmentMeta, int64, error) {
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

	var records []Record
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
		for _, record := range segmentRecords {
			if seenSequence && record.Sequence != previousSequence+1 {
				return nil, nil, 0, ErrCorruptState
			}
			seenSequence = true
			previousSequence = record.Sequence
			records = append(records, record)
		}
		metas = append(metas, meta)
		total += meta.size
	}
	return records, metas, total, nil
}

func (s *Spool) readSegmentLocked(path string, named struct {
	name  string
	start uint64
	open  bool
}, recoverOpen bool) ([]Record, segmentMeta, error) {
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
	header := make([]byte, segmentHeaderSize)
	if _, err := io.ReadFull(file, header); err != nil || !bytes.Equal(header[:8], segmentMagic[:]) ||
		binary.BigEndian.Uint16(header[8:10]) != SchemaVersion || binary.BigEndian.Uint64(header[16:24]) != named.start {
		return nil, segmentMeta{}, ErrCorruptState
	}
	meta := segmentMeta{path: path, name: named.name, start: named.start, size: info.Size(), open: named.open}
	position := int64(segmentHeaderSize)
	expected := named.start
	var records []Record
	for {
		recordStart := position
		recordHeader := make([]byte, recordHeaderSize)
		read, readErr := io.ReadFull(file, recordHeader)
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
		if _, err := io.ReadFull(file, payload); err != nil {
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
		records = append(records, Record{
			Sequence: envelope.Sequence, EventID: envelope.EventID, TenantID: envelope.TenantID,
			NodeID: envelope.NodeID, Type: envelope.Type, OccurredAt: envelope.OccurredAt,
			Payload: append([]byte(nil), payload...), Size: frameSize, digest: contentDigest(envelope), envelope: envelope,
		})
		meta.max = envelope.Sequence
		meta.records++
		expected++
		position += frameSize
	}
	if meta.records == 0 && !meta.open {
		return nil, segmentMeta{}, ErrCorruptState
	}
	return records, meta, nil
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
