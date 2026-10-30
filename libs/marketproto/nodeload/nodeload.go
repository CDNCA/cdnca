// Package nodeload is the leaf controller's signed node load report (ADR 0012
// §6.1): once a minute, per node of every supplied node pool, the mean CPU and
// memory use of the last minute. The market removes a node from a supply whose
// load thresholds it exceeds. Signed with the same member ed25519 key as usage
// reports, under its own domain, so a load report is accountable like usage.
package nodeload

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"

	"github.com/cdnca/cdnca/libs/marketproto/spec"
	"github.com/google/uuid"
)

const (
	SchemaV1       = "cdnca.market.nodeload/v1"
	Domain         = SchemaV1 + "\n"
	WindowSeconds  = 60
	MaxItems       = 10_000
	MaxNodePoolRef = 128 // same bound as grant.NodePoolRef
	MaxSamples     = 3_600
	MaxPayload     = 4 << 20
)

var (
	ErrSignature = errors.New("node load report signature rejected")
	ErrInvalid   = errors.New("invalid node load report")
)

// Item is one node's load over the minute ending at ObservedAt. Memory is
// (total - available) / total, as the agent already samples it.
type Item struct {
	NodePoolRef   string    `json:"node_pool_ref"`
	NodeID        uuid.UUID `json:"node_id"`
	ObservedAt    int64     `json:"observed_at"` // unix seconds, multiple of 60
	CPUPercent    float64   `json:"cpu_percent"`
	MemoryPercent float64   `json:"memory_percent"`
	SampleCount   int64     `json:"sample_count"`
}

// Over reports whether the item reaches the given thresholds (>=).
func (it Item) Over(t spec.LoadThresholds) bool {
	return it.CPUPercent >= float64(t.CPUPercent) || it.MemoryPercent >= float64(t.MemoryPercent)
}

type Report struct {
	Schema       string    `json:"schema"`
	ReportID     uuid.UUID `json:"report_id"`
	LeafMemberID uuid.UUID `json:"leaf_member_id"`
	CreatedAt    int64     `json:"created_at"`
	Items        []Item    `json:"items"`
}

func (r Report) Validate() error {
	if r.Schema != SchemaV1 || r.ReportID == uuid.Nil || r.LeafMemberID == uuid.Nil || r.CreatedAt <= 0 ||
		len(r.Items) == 0 || len(r.Items) > MaxItems {
		return ErrInvalid
	}
	type key struct {
		pool string
		node uuid.UUID
		at   int64
	}
	seen := make(map[key]struct{}, len(r.Items))
	for _, it := range r.Items {
		if it.NodePoolRef == "" || len(it.NodePoolRef) > MaxNodePoolRef || it.NodeID == uuid.Nil ||
			it.ObservedAt <= 0 || it.ObservedAt%WindowSeconds != 0 || it.ObservedAt > r.CreatedAt+WindowSeconds ||
			!percent(it.CPUPercent) || !percent(it.MemoryPercent) || it.SampleCount < 1 || it.SampleCount > MaxSamples {
			return ErrInvalid
		}
		k := key{it.NodePoolRef, it.NodeID, it.ObservedAt}
		if _, dup := seen[k]; dup {
			return ErrInvalid
		}
		seen[k] = struct{}{}
	}
	return nil
}

func percent(v float64) bool { return !math.IsNaN(v) && v >= 0 && v <= 100 }

type Signed struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

func Sign(r Report, key ed25519.PrivateKey) (Signed, error) {
	if len(key) != ed25519.PrivateKeySize {
		return Signed{}, ErrInvalid
	}
	if err := r.Validate(); err != nil {
		return Signed{}, err
	}
	payload, err := json.Marshal(r)
	if err != nil {
		return Signed{}, err
	}
	if len(payload) > MaxPayload {
		return Signed{}, ErrInvalid
	}
	return Signed{Payload: base64.StdEncoding.EncodeToString(payload),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, append([]byte(Domain), payload...)))}, nil
}

// Verify checks the report against the leaf's registered signing key and
// returns it with the exact signed bytes. Unknown fields are rejected.
func Verify(public ed25519.PublicKey, s Signed) (Report, []byte, error) {
	if len(public) != ed25519.PublicKeySize {
		return Report{}, nil, ErrSignature
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(s.Payload)
	if err != nil || len(payload) > MaxPayload {
		return Report{}, nil, ErrInvalid
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(s.Signature)
	if err != nil || !ed25519.Verify(public, append([]byte(Domain), payload...), signature) {
		return Report{}, nil, ErrSignature
	}
	var r Report
	if err := spec.DecodeStrict(payload, &r); err != nil {
		return Report{}, nil, ErrInvalid
	}
	if err := r.Validate(); err != nil {
		return Report{}, nil, err
	}
	return r, payload, nil
}
