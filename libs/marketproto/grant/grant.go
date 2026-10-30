// Package grant signs and verifies supply grants: the market-issued credential
// a leaf supplier's controller relies on to open a restricted tenant and
// enforce its allocation (docs/marketplace/03-supply-api.md §2).
package grant

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/spec"
	"github.com/google/uuid"
)

const (
	// SchemaV2 (1.0.35, ADR 0012) carries supply limits, seller tags and the
	// effective node load thresholds. v1 grants are rejected.
	SchemaV2      = "cdnca.market.supply-grant/v2"
	signingDomain = SchemaV2 + "\n"

	maxEnvelopeBytes   = 64 << 10
	MaxPathLength      = 1024
	maxDownstreamRef   = 64
	maxNodePoolRef     = 128
	maxValidityWindow  = 366 * 24 * time.Hour
	maxGraceWindow     = 30 * 24 * time.Hour
	maxKeyIDLength     = 128
	offerDigestHexSize = 64
)

var (
	ErrInvalid    = errors.New("invalid supply grant")
	ErrSignature  = errors.New("supply grant signature rejected")
	ErrUnknownKey = errors.New("supply grant signing key unknown")

	keyIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
)

// Grant binds one leaf supply path. Path runs from the root subscription (the
// buyer's) to the subscription bought directly from the leaf supplier; the last
// element is the leaf-side quota pool every grant under it is charged against.
type Grant struct {
	Schema              string          `json:"schema"`
	GrantID             uuid.UUID       `json:"grant_id"`
	LeafMemberID        uuid.UUID       `json:"leaf_member_id"`
	SubscriptionPath    []uuid.UUID     `json:"subscription_path"`
	DownstreamRef       string          `json:"downstream_ref"`
	OfferSnapshotDigest string          `json:"offer_snapshot_digest"`
	NodePoolRef         string          `json:"node_pool_ref"`
	Allocation          spec.Allocation `json:"allocation"`
	// Limits is the path-minimum of every hop's limits (spec.LimitSet.Min)
	// without node_* metrics; empty means unlimited. Realtime caps are the
	// supply total; the leaf splits them across its serving nodes.
	Limits spec.LimitSet `json:"limits"`
	// Tags are the leaf offer's self-declared features (display only).
	Tags spec.Tags `json:"tags"`
	// LoadThresholds = min(path node_* caps, platform floor); the market
	// removes a node from this supply above them (ADR 0012 §6.1).
	LoadThresholds spec.LoadThresholds `json:"load_thresholds"`
	// AutoDefenseCaps is the path-strictest supplier cap on the sites'
	// automatic defence (spec.MinAutoDefenseCaps, ADR 0012 §19.2, U7); nil =
	// unconstrained. The leaf clamps a site's auto_defense block to it.
	AutoDefenseCaps *spec.AutoDefenseCaps `json:"autodefense_caps,omitempty"`
	// SitePause tells the leaf whether same-site automatic pause is on for
	// this supply (§19.4); the market counts and pauses, the leaf only shows
	// it. nil = off.
	SitePause    *SitePause      `json:"site_pause,omitempty"`
	Compliance   spec.Compliance `json:"compliance"`
	IssuedAt     int64           `json:"issued_at"`
	NotBefore    int64           `json:"not_before"`
	NotAfter     int64           `json:"not_after"`
	GraceSeconds int64           `json:"grace_seconds"`
}

// Pool is the subscription bought directly from the leaf supplier.
func (g Grant) Pool() uuid.UUID { return g.SubscriptionPath[len(g.SubscriptionPath)-1] }

func (g Grant) Validate() error {
	if g.Schema != SchemaV2 || g.GrantID == uuid.Nil || g.LeafMemberID == uuid.Nil {
		return ErrInvalid
	}
	if len(g.SubscriptionPath) == 0 || len(g.SubscriptionPath) > MaxPathLength {
		return ErrInvalid
	}
	seen := make(map[uuid.UUID]struct{}, len(g.SubscriptionPath))
	for _, id := range g.SubscriptionPath {
		if id == uuid.Nil {
			return ErrInvalid
		}
		if _, dup := seen[id]; dup {
			return ErrInvalid
		}
		seen[id] = struct{}{}
	}
	if len(g.DownstreamRef) > maxDownstreamRef || g.NodePoolRef == "" || len(g.NodePoolRef) > maxNodePoolRef {
		return ErrInvalid
	}
	if len(g.OfferSnapshotDigest) != offerDigestHexSize {
		return ErrInvalid
	}
	if _, err := hex.DecodeString(g.OfferSnapshotDigest); err != nil {
		return ErrInvalid
	}
	if err := g.Allocation.Validate(); err != nil {
		return ErrInvalid
	}
	if err := g.Limits.Validate(); err != nil {
		return ErrInvalid
	}
	for _, l := range g.Limits {
		if l.Metric.NodeLoad() {
			return ErrInvalid
		}
	}
	if g.Tags.Validate() != nil || g.LoadThresholds.Validate() != nil {
		return ErrInvalid
	}
	if g.AutoDefenseCaps != nil && g.AutoDefenseCaps.Validate() != nil {
		return ErrInvalid
	}
	if g.SitePause != nil && g.SitePause.Validate() != nil {
		return ErrInvalid
	}
	if g.IssuedAt <= 0 || g.NotBefore <= 0 || g.NotAfter <= g.NotBefore {
		return ErrInvalid
	}
	if time.Duration(g.NotAfter-g.NotBefore)*time.Second > maxValidityWindow {
		return ErrInvalid
	}
	if g.GraceSeconds < 0 || time.Duration(g.GraceSeconds)*time.Second > maxGraceWindow {
		return ErrInvalid
	}
	return nil
}

// SitePause is same-site automatic pause (ADR 0012 §19.4, U9): when on, a
// site of this supply hit by more than AfterActions site-attributable
// whole-node actions in 24 hours stops being scheduled here. AfterActions is
// always the platform value (suppliers cannot change N).
type SitePause struct {
	Enabled      bool `json:"enabled"`
	AfterActions int  `json:"after_actions"`
}

const (
	MinSitePauseAfter = 1
	MaxSitePauseAfter = 100
)

func (p SitePause) Validate() error {
	if p.AfterActions < MinSitePauseAfter || p.AfterActions > MaxSitePauseAfter {
		return ErrInvalid
	}
	return nil
}

// Exceeded reports whether count actions in the window trigger the pause:
// "more than N" is the N+1st action (U8).
func (p SitePause) Exceeded(count int) bool { return p.Enabled && count > p.AfterActions }

// CombineSitePause merges two hops: on if either hop turned it on (each
// supplier protects its own nodes), with the smaller N of the hops that
// turned it on. nil = off.
func CombineSitePause(a, b *SitePause) *SitePause {
	switch {
	case a == nil && b == nil:
		return nil
	case a == nil:
		out := *b
		return &out
	case b == nil:
		out := *a
		return &out
	}
	switch {
	case a.Enabled == b.Enabled:
		return &SitePause{Enabled: a.Enabled, AfterActions: min(a.AfterActions, b.AfterActions)}
	case a.Enabled:
		out := *a
		return &out
	default:
		out := *b
		return &out
	}
}

type Status string

const (
	StatusNotYetValid Status = "not_yet_valid"
	StatusActive      Status = "active"
	// StatusGrace keeps serving while the market cannot renew the grant
	// (docs/marketplace/01-architecture.md §5).
	StatusGrace   Status = "grace"
	StatusExpired Status = "expired"
)

func (g Grant) StatusAt(now time.Time) Status {
	at := now.Unix()
	switch {
	case at < g.NotBefore:
		return StatusNotYetValid
	case at < g.NotAfter:
		return StatusActive
	case at < g.NotAfter+g.GraceSeconds:
		return StatusGrace
	default:
		return StatusExpired
	}
}

// Signed is the wire form. Payload is the exact signed byte string; verifiers
// never re-encode it before checking the signature.
type Signed struct {
	KeyID     string `json:"key_id"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

func Sign(g Grant, keyID string, key ed25519.PrivateKey) (Signed, error) {
	if !validKeyID(keyID) || len(key) != ed25519.PrivateKeySize {
		return Signed{}, ErrInvalid
	}
	if err := g.Validate(); err != nil {
		return Signed{}, err
	}
	payload, err := json.Marshal(g)
	if err != nil {
		return Signed{}, fmt.Errorf("encode supply grant: %w", err)
	}
	signature := ed25519.Sign(key, signedMessage(payload))
	return Signed{
		KeyID:     keyID,
		Payload:   base64.StdEncoding.EncodeToString(payload),
		Signature: base64.StdEncoding.EncodeToString(signature),
	}, nil
}

// Keyring maps market signing key IDs to public keys. Members receive it via
// the platform policy channel; current and previous keys coexist during rotation.
type Keyring map[string]ed25519.PublicKey

func (k Keyring) Verify(s Signed) (Grant, error) {
	if !validKeyID(s.KeyID) || len(s.Payload) > maxEnvelopeBytes {
		return Grant{}, ErrInvalid
	}
	public, ok := k[s.KeyID]
	if !ok || len(public) != ed25519.PublicKeySize {
		return Grant{}, ErrUnknownKey
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(s.Payload)
	if err != nil {
		return Grant{}, ErrInvalid
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(s.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Grant{}, ErrInvalid
	}
	if !ed25519.Verify(public, signedMessage(payload), signature) {
		return Grant{}, ErrSignature
	}
	// Strict: a field this leaf does not know may be a limit it would fail
	// to enforce, so it rejects the grant (a new field needs a new Schema).
	var g Grant
	if err := spec.DecodeStrict(payload, &g); err != nil {
		return Grant{}, ErrInvalid
	}
	if err := g.Validate(); err != nil {
		return Grant{}, err
	}
	return g, nil
}

func signedMessage(payload []byte) []byte {
	message := make([]byte, 0, len(signingDomain)+len(payload))
	message = append(message, signingDomain...)
	return append(message, payload...)
}

func validKeyID(id string) bool {
	return len(id) > 0 && len(id) <= maxKeyIDLength && keyIDPattern.MatchString(id)
}
