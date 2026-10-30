package nodescheduler

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"slices"
	"sort"

	"github.com/google/uuid"
)

const targetNodeSetSchema = "cdnca.edge.target-node-set/v1"

// CanonicalNodeSetDigest returns the stable digest used by target snapshots.
// UUIDs are sorted by their binary form and duplicates are removed before encoding.
func CanonicalNodeSetDigest(nodeIDs []uuid.UUID) [32]byte {
	canonical := slices.Clone(nodeIDs)
	sort.Slice(canonical, func(left, right int) bool {
		return bytes.Compare(canonical[left][:], canonical[right][:]) < 0
	})
	canonical = slices.Compact(canonical)
	hash := sha256.New()
	_, _ = hash.Write([]byte(targetNodeSetSchema))
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], uint32(len(canonical)))
	_, _ = hash.Write(count[:])
	for _, nodeID := range canonical {
		_, _ = hash.Write(nodeID[:])
	}
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

func uuidString(value uuid.UUID) string {
	if value == uuid.Nil {
		return ""
	}
	return value.String()
}
