// Package nodeaction is the leaf controller's signed report of whole-node
// security actions on nodes of supplied node pools (ADR 0012 §19.3): kernel
// level actions that affect every site on the node. The market notifies every
// subscriber of a supply containing the node, without the attacked site or any
// client address. Items that the leaf can attribute to a market site (an
// automatic defence L4/L5 verdict) also carry grant_id and leaf_site_id; only
// those count towards same-site automatic pause (§19.4, U8).
//
// Posted to POST /v1/node-actions/reports, signed with the member ed25519 key
// like usage and node load reports; Operation names it in audit records.
package nodeaction

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"slices"

	"github.com/cdnca/cdnca/libs/marketproto/spec"
	"github.com/google/uuid"
)

const (
	SchemaV1       = "cdnca.market.nodeaction/v1"
	Domain         = SchemaV1 + "\n"
	Operation      = "market.node_action"
	MaxItems       = 1_000
	MaxNodePoolRef = 128 // same bound as grant.NodePoolRef
	MaxCount       = 1_000_000
	MaxPayload     = 1 << 20

	// SiteLevel is the lowest automatic defence level that acts on the whole
	// node (L4 kernel ban, L5 XDP; autodefense contract §3.5).
	SiteLevel = 4
	maxLevel  = 5
	maxSkew   = 60
	maxSlug   = 64
)

// Sources of the autodefense contract §5 node_event, plus autodefense
// verdicts (which carry a site).
const (
	SourceAutoDefense = "autodefense"
	SourceDDoS        = "ddos"
	SourceL4Guard     = "l4guard"
	SourceXDP         = "xdp"
)

var (
	ErrSignature = errors.New("node action report signature rejected")
	ErrInvalid   = errors.New("invalid node action report")

	// kind is an open slug (contract §5: unknown values shown verbatim).
	kindPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	sources     = []string{SourceAutoDefense, SourceDDoS, SourceL4Guard, SourceXDP}
)

// Item is one whole-node action, or Count identical ones (same node, source,
// kind, level and site) aggregated by the leaf. No client address.
type Item struct {
	NodePoolRef string     `json:"node_pool_ref"`
	NodeID      uuid.UUID  `json:"node_id"`
	At          int64      `json:"at"` // unix seconds of the first action
	Source      string     `json:"source"`
	Kind        string     `json:"kind"`
	Level       int        `json:"level"`
	Count       int64      `json:"count"`
	GrantID     *uuid.UUID `json:"grant_id,omitempty"`
	LeafSiteID  *uuid.UUID `json:"leaf_site_id,omitempty"`
}

// SiteAttributable reports whether the item counts towards same-site pause:
// an automatic defence verdict at L4 or higher on a market site (U8).
func (it Item) SiteAttributable() bool { return it.GrantID != nil && it.LeafSiteID != nil }

func (it Item) validate(createdAt int64) bool {
	if it.NodePoolRef == "" || len(it.NodePoolRef) > MaxNodePoolRef || it.NodeID == uuid.Nil ||
		it.At <= 0 || it.At > createdAt+maxSkew || !slices.Contains(sources, it.Source) ||
		len(it.Kind) > maxSlug || !kindPattern.MatchString(it.Kind) ||
		it.Level < 0 || it.Level > maxLevel || it.Count < 1 || it.Count > MaxCount {
		return false
	}
	if (it.GrantID == nil) != (it.LeafSiteID == nil) {
		return false
	}
	if it.SiteAttributable() {
		return *it.GrantID != uuid.Nil && *it.LeafSiteID != uuid.Nil &&
			it.Source == SourceAutoDefense && it.Level >= SiteLevel
	}
	return true
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
		pool         string
		node         uuid.UUID
		at           int64
		source, kind string
		level        int
		site         uuid.UUID
	}
	seen := make(map[key]struct{}, len(r.Items))
	for _, it := range r.Items {
		if !it.validate(r.CreatedAt) {
			return ErrInvalid
		}
		k := key{it.NodePoolRef, it.NodeID, it.At, it.Source, it.Kind, it.Level, uuid.Nil}
		if it.LeafSiteID != nil {
			k.site = *it.LeafSiteID
		}
		if _, dup := seen[k]; dup {
			return ErrInvalid
		}
		seen[k] = struct{}{}
	}
	return nil
}

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
