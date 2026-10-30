package analyticsgeo

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const AuthoritySchemaV1 = "analyticsgeo.authority.v1"

var (
	ErrAuthorityConfiguration = errors.New("analytics geo authority configuration invalid")
	ErrAuthoritySnapshot      = errors.New("analytics geo authority snapshot invalid")
	ErrAuthoritySignature     = errors.New("analytics geo authority signature invalid")
	ErrAuthorityRevision      = errors.New("analytics geo authority revision invalid")
	ErrAuthorityExpired       = errors.New("analytics geo authority expired")
	ErrAuthorityCapacity      = errors.New("analytics geo authority capacity exceeded")
	ErrAuthorityUnavailable   = errors.New("analytics geo authority unavailable")
)

type AuthorityState string

const (
	AuthorityStateActive     AuthorityState = "active"
	AuthorityStateLKG        AuthorityState = "lkg"
	AuthorityStateLKGExpired AuthorityState = "lkg_expired"
)

type AuthorityReason string

const (
	AuthorityReasonNone              AuthorityReason = ""
	AuthorityReasonSnapshotRejected  AuthorityReason = "snapshot_rejected"
	AuthorityReasonSignatureRejected AuthorityReason = "signature_rejected"
	AuthorityReasonRevisionRejected  AuthorityReason = "revision_rejected"
	AuthorityReasonCandidateExpired  AuthorityReason = "candidate_expired"
	AuthorityReasonCapacityRejected  AuthorityReason = "capacity_rejected"
	AuthorityReasonLKGExpired        AuthorityReason = "lkg_expired"
)

type SignedAuthoritySnapshot struct {
	SchemaVersion         string
	Revision              uint64
	KeyID                 string
	CurrentCatalogVersion string
	ExpiresAt             time.Time
	Catalogs              []CatalogInput
	Signature             []byte
}

type AuthorityManifest struct {
	SchemaVersion         string   `json:"schema_version"`
	Revision              uint64   `json:"revision"`
	KeyID                 string   `json:"key_id"`
	CurrentCatalogVersion string   `json:"current_catalog_version"`
	ExpiresAt             string   `json:"expires_at"`
	CatalogSHA256         []string `json:"catalog_sha256"`
}

type AuthorityConfig struct {
	KeyID             string
	PublicKey         ed25519.PublicKey
	Now               func() time.Time
	MaxAggregateBytes int
}

type AuthorityLookup struct {
	Attribution Attribution
	Provenance  Provenance
	Revision    uint64
	ExpiresAt   time.Time
	State       AuthorityState
	Reason      AuthorityReason
}

type Authority struct {
	mu                sync.RWMutex
	keyID             string
	publicKey         ed25519.PublicKey
	now               func() time.Time
	maxAggregateBytes int
	catalog           *Catalog
	revision          uint64
	expiresAt         time.Time
	rejectedReason    AuthorityReason
}

func NewAuthority(config AuthorityConfig) (*Authority, error) {
	if !validVersion(config.KeyID) || len(config.PublicKey) != ed25519.PublicKeySize || config.Now == nil ||
		config.MaxAggregateBytes <= 0 || config.MaxAggregateBytes > maximumCatalogDocuments*maximumCatalogBytes {
		return nil, ErrAuthorityConfiguration
	}
	return &Authority{
		keyID: config.KeyID, publicKey: bytes.Clone(config.PublicKey), now: config.Now,
		maxAggregateBytes: config.MaxAggregateBytes,
	}, nil
}

func (authority *Authority) Reload(ctx context.Context, snapshot SignedAuthoritySnapshot) error {
	if authority == nil || authority.now == nil || ctx == nil {
		return ErrAuthorityConfiguration
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if snapshot.Revision == 0 || !authority.revisionCanAdvance(snapshot.Revision) {
		authority.rememberRejection(AuthorityReasonRevisionRejected)
		return ErrAuthorityRevision
	}
	catalog, reason, err := authority.verifyCandidate(snapshot)
	if err != nil {
		authority.rememberRejection(reason)
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	authority.mu.Lock()
	defer authority.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if authority.catalog != nil && snapshot.Revision <= authority.revision {
		authority.rejectedReason = AuthorityReasonRevisionRejected
		return ErrAuthorityRevision
	}
	authority.catalog = catalog
	authority.revision = snapshot.Revision
	authority.expiresAt = snapshot.ExpiresAt
	authority.rejectedReason = AuthorityReasonNone
	return nil
}

func (authority *Authority) Lookup(ctx context.Context, version string, address netip.Addr) (AuthorityLookup, error) {
	if authority == nil || authority.now == nil || ctx == nil {
		return AuthorityLookup{}, ErrAuthorityUnavailable
	}
	if err := ctx.Err(); err != nil {
		return AuthorityLookup{}, err
	}
	authority.mu.RLock()
	catalog, revision, expiresAt, rejected := authority.catalog, authority.revision, authority.expiresAt, authority.rejectedReason
	authority.mu.RUnlock()
	if catalog == nil {
		return AuthorityLookup{}, ErrAuthorityUnavailable
	}
	attribution, provenance, err := catalog.Resolve(version, address)
	if err != nil {
		return AuthorityLookup{}, err
	}
	if err := ctx.Err(); err != nil {
		return AuthorityLookup{}, err
	}
	state, reason := AuthorityStateActive, AuthorityReasonNone
	if !authority.now().Before(expiresAt) {
		state, reason = AuthorityStateLKGExpired, AuthorityReasonLKGExpired
	} else if rejected != AuthorityReasonNone {
		state, reason = AuthorityStateLKG, rejected
	}
	return AuthorityLookup{
		Attribution: attribution, Provenance: provenance, Revision: revision, ExpiresAt: expiresAt,
		State: state, Reason: reason,
	}, nil
}

func (authority *Authority) verifyCandidate(snapshot SignedAuthoritySnapshot) (*Catalog, AuthorityReason, error) {
	if snapshot.SchemaVersion != AuthoritySchemaV1 || snapshot.KeyID != authority.keyID ||
		!validVersion(snapshot.CurrentCatalogVersion) || !canonicalAuthorityTime(snapshot.ExpiresAt) ||
		len(snapshot.Signature) != ed25519.SignatureSize {
		return nil, AuthorityReasonSnapshotRejected, ErrAuthoritySnapshot
	}
	if len(snapshot.Catalogs) == 0 || len(snapshot.Catalogs) > maximumCatalogDocuments {
		return nil, AuthorityReasonCapacityRejected, ErrAuthorityCapacity
	}
	totalBytes := 0
	for _, input := range snapshot.Catalogs {
		if len(input.Data) > authority.maxAggregateBytes-totalBytes {
			return nil, AuthorityReasonCapacityRejected, ErrAuthorityCapacity
		}
		totalBytes += len(input.Data)
	}
	manifest, err := authorityManifest(snapshot)
	if err != nil {
		return nil, AuthorityReasonSnapshotRejected, ErrAuthoritySnapshot
	}
	if !ed25519.Verify(authority.publicKey, manifest, snapshot.Signature) {
		return nil, AuthorityReasonSignatureRejected, ErrAuthoritySignature
	}
	if !snapshot.ExpiresAt.After(authority.now()) {
		return nil, AuthorityReasonCandidateExpired, ErrAuthorityExpired
	}
	catalog, err := NewCatalog(snapshot.Catalogs, snapshot.CurrentCatalogVersion)
	if err != nil {
		return nil, AuthorityReasonSnapshotRejected, ErrAuthoritySnapshot
	}
	return catalog, AuthorityReasonNone, nil
}

func authorityManifest(snapshot SignedAuthoritySnapshot) ([]byte, error) {
	digests := make([]string, len(snapshot.Catalogs))
	for index, input := range snapshot.Catalogs {
		if len(input.ExpectedSHA256) != sha256.Size*2 || input.ExpectedSHA256 != strings.ToLower(input.ExpectedSHA256) {
			return nil, ErrAuthoritySnapshot
		}
		digests[index] = input.ExpectedSHA256
	}
	return json.Marshal(AuthorityManifest{
		SchemaVersion: snapshot.SchemaVersion, Revision: snapshot.Revision, KeyID: snapshot.KeyID,
		CurrentCatalogVersion: snapshot.CurrentCatalogVersion,
		ExpiresAt:             snapshot.ExpiresAt.UTC().Format(time.RFC3339Nano), CatalogSHA256: digests,
	})
}

func canonicalAuthorityTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Equal(value.Truncate(time.Millisecond))
}

func (authority *Authority) revisionCanAdvance(revision uint64) bool {
	authority.mu.RLock()
	defer authority.mu.RUnlock()
	return authority.catalog == nil || revision > authority.revision
}

func (authority *Authority) rememberRejection(reason AuthorityReason) {
	authority.mu.Lock()
	if authority.catalog != nil {
		authority.rejectedReason = reason
	}
	authority.mu.Unlock()
}

type AuthorityReader interface {
	Lookup(context.Context, string, netip.Addr) (AuthorityLookup, error)
}
