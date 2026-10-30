// Package usage is the leaf supplier's signed usage report: egress bytes,
// requests and the realtime peaks of ADR 0012 §5 per grant per 5-minute bucket. The signature (the leaf's member
// signing key) makes a report non-repudiable in billing disputes
// (docs/marketplace/04-billing.md §5).
package usage

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/cdnca/cdnca/libs/marketproto/spec"
	"github.com/google/uuid"
)

const (
	// SchemaV2 (1.0.35) adds the per-bucket peaks; v1 reports are rejected.
	SchemaV2      = "cdnca.market.usage-report/v2"
	Domain        = SchemaV2 + "\n"
	BucketSeconds = 300
	MaxItems      = 10_000
	MaxPayload    = 4 << 20
)

var (
	ErrSignature = errors.New("usage report signature rejected")
	ErrInvalid   = errors.New("invalid usage report")
)

// Item is one grant's 5-minute bucket. The peaks are the largest 1-minute
// value in the bucket, summed across the leaf's nodes per minute; they are
// what the market compares with the realtime limits (spec.Metric.Realtime).
type Item struct {
	GrantID       uuid.UUID `json:"grant_id"`
	BucketStart   int64     `json:"bucket_start"` // unix seconds, multiple of 300
	BytesOut      int64     `json:"bytes_out"`
	Requests      int64     `json:"requests"`
	PeakBPS       int64     `json:"peak_bps"`       // bandwidth_peak_bps
	MaxConcurrent int64     `json:"max_concurrent"` // concurrent_connections (TCP connections / L4 sessions)
	MaxRequests   int64     `json:"max_requests"`   // concurrent_requests (L7 requests in flight)
	MaxQPS        int64     `json:"max_qps"`        // qps
	MaxNewCPS     int64     `json:"max_new_cps"`    // new_connections_per_second
}

// Peak returns the item's value for a realtime metric.
func (it Item) Peak(m spec.Metric) (int64, bool) {
	switch m {
	case spec.MetricBandwidthPeakBPS:
		return it.PeakBPS, true
	case spec.MetricConcurrentConnections:
		return it.MaxConcurrent, true
	case spec.MetricConcurrentRequests:
		return it.MaxRequests, true
	case spec.MetricQPS:
		return it.MaxQPS, true
	case spec.MetricNewConnectionsPerSecond:
		return it.MaxNewCPS, true
	}
	return 0, false
}

type Report struct {
	Schema       string    `json:"schema"`
	ReportID     uuid.UUID `json:"report_id"`
	LeafMemberID uuid.UUID `json:"leaf_member_id"`
	CreatedAt    int64     `json:"created_at"`
	Items        []Item    `json:"items"`
}

func (r Report) Validate() error {
	if r.Schema != SchemaV2 || r.ReportID == uuid.Nil || r.LeafMemberID == uuid.Nil || r.CreatedAt <= 0 || len(r.Items) == 0 || len(r.Items) > MaxItems {
		return ErrInvalid
	}
	for _, it := range r.Items {
		if it.GrantID == uuid.Nil || it.BucketStart <= 0 || it.BucketStart%BucketSeconds != 0 || it.BytesOut < 0 || it.Requests < 0 {
			return ErrInvalid
		}
		for _, m := range []spec.Metric{spec.MetricBandwidthPeakBPS, spec.MetricConcurrentConnections,
			spec.MetricConcurrentRequests, spec.MetricQPS, spec.MetricNewConnectionsPerSecond} {
			if v, _ := it.Peak(m); v < 0 || v > m.MaxCap() {
				return ErrInvalid
			}
		}
	}
	return nil
}

type Signed struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

func Sign(r Report, key ed25519.PrivateKey) (Signed, error) {
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
// returns it with the exact signed bytes (kept as dispute evidence).
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
	// Strict: an unknown field is a measurement this market would drop.
	var r Report
	if err := spec.DecodeStrict(payload, &r); err != nil {
		return Report{}, nil, ErrInvalid
	}
	return r, payload, r.Validate()
}
