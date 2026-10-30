// Package siteindex is the node's dynamic routing site index (ADR 0009 §8.2,
// docs/edge/dynroute-contract.md): the map (public port, host name) -> site
// object digest that the request path looks up in a shared dictionary.
//
// The agent builds an Index from the site objects (cdnca.edge.site/v2) of
// every scope the node serves, writes it as a whole-generation index file
// (the cold start source, contract §5.1) and activates it in the running
// OpenResty as a change set against the active generation (contract §5.2,
// §4.3) over the local control socket.
package siteindex

import (
	"bytes"
	"crypto/md5" //nolint:gosec // index key, see edgesite.IndexKey
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
)

var ErrFormat = errors.New("site index: invalid format")

const (
	KeySize    = md5.Size    // 16
	DigestSize = sha256.Size // 32

	indexMagic     = "CDNCAIX1"
	changeSetMagic = "CDNCACS1"

	// MaxChangeEntries bounds one change set (contract §4.4).
	MaxChangeEntries = 65536
	// MaxPorts bounds the port table of a generation.
	MaxPorts = 65535

	OpSet    byte = 1
	OpDelete byte = 2
)

type Key [KeySize]byte
type Digest [DigestSize]byte

func (k Key) String() string    { return hex.EncodeToString(k[:]) }
func (d Digest) String() string { return hex.EncodeToString(d[:]) }

// ParseDigest parses a lower-case hex SHA-256.
func ParseDigest(text string) (Digest, error) {
	var digest Digest
	if len(text) != 2*DigestSize {
		return digest, fmt.Errorf("%w: digest %q", ErrFormat, text)
	}
	raw, err := hex.DecodeString(text)
	if err != nil || hex.EncodeToString(raw) != text {
		return digest, fmt.Errorf("%w: digest %q", ErrFormat, text)
	}
	copy(digest[:], raw)
	return digest, nil
}

// Entry is one index key and the digest of the site object it routes to.
type Entry struct {
	Key    Key
	Digest Digest
}

// Index is one generation: every index entry, sorted by key and unique, and
// the generation's public HTTP ports (sorted, unique).
type Index struct {
	Generation uint64
	Ports      []uint16
	Entries    []Entry
}

func compareKeys(a, b Key) int { return bytes.Compare(a[:], b[:]) }

func checkPorts(ports []uint16) error {
	if len(ports) > MaxPorts {
		return fmt.Errorf("%w: %d ports", ErrFormat, len(ports))
	}
	for index, port := range ports {
		if port == 0 || index > 0 && ports[index-1] >= port {
			return fmt.Errorf("%w: ports must be ascending, unique, non-zero", ErrFormat)
		}
	}
	return nil
}

func (index Index) check() error {
	if index.Generation == 0 {
		return fmt.Errorf("%w: generation 0", ErrFormat)
	}
	if err := checkPorts(index.Ports); err != nil {
		return err
	}
	for position := 1; position < len(index.Entries); position++ {
		if compareKeys(index.Entries[position-1].Key, index.Entries[position].Key) >= 0 {
			return fmt.Errorf("%w: entries must be sorted by key and unique", ErrFormat)
		}
	}
	if uint64(len(index.Entries)) > uint64(^uint32(0)) {
		return fmt.Errorf("%w: too many entries", ErrFormat)
	}
	return nil
}

func appendPorts(out []byte, ports []uint16) []byte {
	out = binary.BigEndian.AppendUint16(out, uint16(len(ports)))
	for _, port := range ports {
		out = binary.BigEndian.AppendUint16(out, port)
	}
	return out
}

func appendTrailer(out []byte) []byte {
	sum := sha256.Sum256(out)
	return append(out, sum[:]...)
}

// MarshalIndex encodes the whole-generation index file (contract §5.1).
func MarshalIndex(index Index) ([]byte, error) {
	if err := index.check(); err != nil {
		return nil, err
	}
	out := make([]byte, 0, 8+8+4+2+2*len(index.Ports)+len(index.Entries)*(KeySize+DigestSize)+DigestSize)
	out = append(out, indexMagic...)
	out = binary.BigEndian.AppendUint64(out, index.Generation)
	out = binary.BigEndian.AppendUint32(out, uint32(len(index.Entries)))
	out = appendPorts(out, index.Ports)
	for _, entry := range index.Entries {
		out = append(out, entry.Key[:]...)
		out = append(out, entry.Digest[:]...)
	}
	return appendTrailer(out), nil
}

type reader struct {
	raw    []byte
	offset int
	err    error
}

func (r *reader) take(n int) []byte {
	if r.err != nil || n < 0 || len(r.raw)-r.offset < n {
		r.err = fmt.Errorf("%w: truncated", ErrFormat)
		return nil
	}
	part := r.raw[r.offset : r.offset+n]
	r.offset += n
	return part
}

func (r *reader) u16() uint16 {
	if part := r.take(2); part != nil {
		return binary.BigEndian.Uint16(part)
	}
	return 0
}

func (r *reader) u32() uint32 {
	if part := r.take(4); part != nil {
		return binary.BigEndian.Uint32(part)
	}
	return 0
}

func (r *reader) u64() uint64 {
	if part := r.take(8); part != nil {
		return binary.BigEndian.Uint64(part)
	}
	return 0
}

func (r *reader) ports() []uint16 {
	count := int(r.u16())
	ports := make([]uint16, 0, count)
	for range count {
		ports = append(ports, r.u16())
	}
	return ports
}

func openTrailer(raw []byte, magic string) (*reader, error) {
	if len(raw) < len(magic)+DigestSize || string(raw[:len(magic)]) != magic {
		return nil, fmt.Errorf("%w: magic", ErrFormat)
	}
	body := raw[:len(raw)-DigestSize]
	sum := sha256.Sum256(body)
	if !bytes.Equal(sum[:], raw[len(body):]) {
		return nil, fmt.Errorf("%w: trailer digest", ErrFormat)
	}
	return &reader{raw: body, offset: len(magic)}, nil
}

// UnmarshalIndex decodes and checks an index file.
func UnmarshalIndex(raw []byte) (Index, error) {
	r, err := openTrailer(raw, indexMagic)
	if err != nil {
		return Index{}, err
	}
	index := Index{Generation: r.u64()}
	count := r.u32()
	index.Ports = r.ports()
	if r.err == nil && uint64(len(r.raw)-r.offset) != uint64(count)*(KeySize+DigestSize) {
		return Index{}, fmt.Errorf("%w: entry count", ErrFormat)
	}
	if r.err != nil {
		return Index{}, r.err
	}
	index.Entries = make([]Entry, count)
	for position := range index.Entries {
		copy(index.Entries[position].Key[:], r.take(KeySize))
		copy(index.Entries[position].Digest[:], r.take(DigestSize))
	}
	if err := index.check(); err != nil {
		return Index{}, err
	}
	return index, nil
}

// Change is one change set entry: OpSet with the new digest, or OpDelete.
type Change struct {
	Op     byte
	Key    Key
	Digest Digest
}

// ChangeSet moves the node from generation Base to Generation (contract §5.2).
type ChangeSet struct {
	Generation uint64
	Base       uint64
	Ports      []uint16
	Changes    []Change
}

func (set ChangeSet) check() error {
	if set.Generation == 0 || set.Generation <= set.Base {
		return fmt.Errorf("%w: generation %d after base %d", ErrFormat, set.Generation, set.Base)
	}
	if err := checkPorts(set.Ports); err != nil {
		return err
	}
	if len(set.Changes) > MaxChangeEntries {
		return fmt.Errorf("%w: %d changes exceed %d", ErrFormat, len(set.Changes), MaxChangeEntries)
	}
	for position, change := range set.Changes {
		if change.Op != OpSet && change.Op != OpDelete {
			return fmt.Errorf("%w: op %d", ErrFormat, change.Op)
		}
		if position > 0 && compareKeys(set.Changes[position-1].Key, change.Key) >= 0 {
			return fmt.Errorf("%w: changes must be sorted by key and unique", ErrFormat)
		}
	}
	return nil
}

// MarshalChangeSet encodes a change set.
func MarshalChangeSet(set ChangeSet) ([]byte, error) {
	if err := set.check(); err != nil {
		return nil, err
	}
	out := make([]byte, 0, 8+8+8+2+2*len(set.Ports)+4+len(set.Changes)*(1+KeySize+DigestSize)+DigestSize)
	out = append(out, changeSetMagic...)
	out = binary.BigEndian.AppendUint64(out, set.Generation)
	out = binary.BigEndian.AppendUint64(out, set.Base)
	out = appendPorts(out, set.Ports)
	out = binary.BigEndian.AppendUint32(out, uint32(len(set.Changes)))
	for _, change := range set.Changes {
		out = append(out, change.Op)
		out = append(out, change.Key[:]...)
		if change.Op == OpSet {
			out = append(out, change.Digest[:]...)
		}
	}
	return appendTrailer(out), nil
}

// UnmarshalChangeSet decodes and checks a change set.
func UnmarshalChangeSet(raw []byte) (ChangeSet, error) {
	r, err := openTrailer(raw, changeSetMagic)
	if err != nil {
		return ChangeSet{}, err
	}
	set := ChangeSet{Generation: r.u64(), Base: r.u64()}
	set.Ports = r.ports()
	count := r.u32()
	if r.err == nil && count > MaxChangeEntries {
		return ChangeSet{}, fmt.Errorf("%w: %d changes", ErrFormat, count)
	}
	for range count {
		var change Change
		op := r.take(1)
		if r.err != nil {
			break
		}
		change.Op = op[0]
		copy(change.Key[:], r.take(KeySize))
		if change.Op == OpSet {
			copy(change.Digest[:], r.take(DigestSize))
		}
		set.Changes = append(set.Changes, change)
	}
	if r.err != nil {
		return ChangeSet{}, r.err
	}
	if r.offset != len(r.raw) {
		return ChangeSet{}, fmt.Errorf("%w: trailing data", ErrFormat)
	}
	if err := set.check(); err != nil {
		return ChangeSet{}, err
	}
	return set, nil
}

// Diff is the change from old to next, in key order. Ports and generations
// are the caller's.
func Diff(old, next []Entry) []Change {
	changes := make([]Change, 0)
	i, j := 0, 0
	for i < len(old) || j < len(next) {
		switch {
		case j == len(next) || i < len(old) && compareKeys(old[i].Key, next[j].Key) < 0:
			changes = append(changes, Change{Op: OpDelete, Key: old[i].Key})
			i++
		case i == len(old) || compareKeys(old[i].Key, next[j].Key) > 0:
			changes = append(changes, Change{Op: OpSet, Key: next[j].Key, Digest: next[j].Digest})
			j++
		default:
			if old[i].Digest != next[j].Digest {
				changes = append(changes, Change{Op: OpSet, Key: next[j].Key, Digest: next[j].Digest})
			}
			i++
			j++
		}
	}
	return changes
}

func sortEntries(entries []Entry) {
	sort.Slice(entries, func(i, j int) bool { return compareKeys(entries[i].Key, entries[j].Key) < 0 })
}
