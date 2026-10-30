package signerrevocation

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementsync"
	"github.com/google/uuid"
)

const (
	ManifestSchema = "cdnca.signer-revocation-manifest/v1"
	EnvelopeSchema = "cdnca.signer-revocation-envelope/v1"
	Algorithm      = "Ed25519"

	ArtifactLease   ArtifactClass = "lease"
	ArtifactPolicy  ArtifactClass = "policy"
	ArtifactRelease ArtifactClass = "release"

	AuthorityLineage     AuthorityKind = "lineage"
	AuthorityOfflineRoot AuthorityKind = "offline_root"

	ReasonAllowed                    = "allowed"
	ReasonSignerRevoked              = "signer_revoked"
	ReasonSignerIdentityUntrusted    = "signer_identity_untrusted"
	ReasonArtifactClassUntrusted     = "artifact_class_untrusted"
	ReasonRevocationStateUnavailable = "revocation_state_unavailable"

	ReasonFetchReceived        = "fetch_received"
	ReasonTransportUnavailable = "transport_unavailable_lkg_retained"
	ReasonVerified             = "verified"
	ReasonApplied              = "applied"
	ReasonSameReplay           = "same_replay"
	ReasonInvalidETag          = "invalid_etag"
	ReasonInvalidManifest      = "invalid_manifest"
	ReasonInvalidSignature     = "invalid_signature"
	ReasonSequenceReplay       = "sequence_replay"
	ReasonSequenceConflict     = "sequence_conflict"
	ReasonChainBranch          = "chain_branch"
	ReasonManifestNotCurrent   = "manifest_not_current"
	ReasonAuthorityUntrusted   = "authority_untrusted"
	ReasonAuthorityRevoked     = "authority_revoked"
	ReasonAuthorityGeneration  = "authority_generation"
	ReasonInvalidKeyset        = "invalid_keyset"
	ReasonKeysetRollback       = "keyset_rollback"
	ReasonObservedAtOutOfRange = "observed_at_out_of_range"
	ReasonStorageFailure       = "storage_failure"
)

var (
	ErrInvalidInput         = errors.New("invalid signer revocation input")
	ErrNoSnapshot           = errors.New("no signer trust snapshot")
	ErrInvalidETag          = errors.New("invalid strong ETag")
	ErrInvalidManifest      = errors.New("invalid signer revocation manifest")
	ErrInvalidSignature     = errors.New("invalid signer revocation signature")
	ErrSequenceReplay       = errors.New("signer revocation sequence is stale")
	ErrSequenceConflict     = errors.New("signer revocation sequence has a different payload")
	ErrChainBranch          = errors.New("signer revocation does not extend the accepted chain")
	ErrManifestNotCurrent   = errors.New("signer revocation manifest is not currently acceptable")
	ErrAuthorityUntrusted   = errors.New("signer revocation authority is not trusted")
	ErrAuthorityRevoked     = errors.New("signer revocation authority is revoked")
	ErrAuthorityGeneration  = errors.New("signer revocation authority generation is invalid")
	ErrInvalidStoredState   = errors.New("stored signer revocation state is invalid")
	ErrSnapshotRollback     = errors.New("signer trust snapshot rollback detected")
	ErrSnapshotConflict     = errors.New("signer trust snapshot revision conflict")
	ErrObservedAtOutOfRange = errors.New("signer revocation observation time is outside the trusted clock window")
)

type ArtifactClass string
type AuthorityKind string

type Manifest struct {
	Schema                 string          `json:"schema"`
	Sequence               uint64          `json:"sequence"`
	PreviousSequence       *uint64         `json:"previous_sequence"`
	PreviousManifestSHA256 *string         `json:"previous_manifest_sha256"`
	RevokedKeyID           string          `json:"revoked_key_id"`
	RevokedKeyGeneration   uint64          `json:"revoked_key_generation"`
	ArtifactClasses        []ArtifactClass `json:"artifact_classes"`
	EffectiveNotBefore     string          `json:"effective_not_before"`
	Reason                 string          `json:"reason"`
	IssuedAt               string          `json:"issued_at"`
	ExpiresAt              string          `json:"expires_at"`
}

type Envelope struct {
	Schema                 string        `json:"schema"`
	Algorithm              string        `json:"algorithm"`
	AuthorityKind          AuthorityKind `json:"authority_kind"`
	AuthorityKeyID         string        `json:"authority_key_id"`
	AuthorityKeyGeneration uint64        `json:"authority_key_generation"`
	ManifestSHA256         string        `json:"manifest_sha256"`
}

type SignedManifest struct {
	Manifest  Manifest `json:"manifest"`
	Envelope  Envelope `json:"envelope"`
	Signature string   `json:"signature"`
}

type AuthorityRef struct {
	Kind       AuthorityKind
	KeyID      string
	Generation uint64
}

// DeploymentTrustSource is the only authority for root pins. Candidate
// manifests and transport metadata cannot introduce trust anchors.
type DeploymentTrustSource interface {
	KeysetPins(context.Context) ([]entitlementguard.VerificationKey, error)
	OfflineRoot(context.Context, AuthorityRef) (ed25519.PublicKey, error)
}

type Candidate struct {
	OperationID       uuid.UUID
	KeysetPayload     []byte
	KeysetETag        string
	RevocationPayload []byte
	RevocationETag    string
	ObservedAt        time.Time
}

type ChainState struct {
	Sequence       uint64
	ManifestSHA256 string
}

type Revocation struct {
	Sequence             uint64
	ManifestSHA256       string
	ETag                 string
	RevokedKeyID         string
	RevokedKeyGeneration uint64
	ArtifactClasses      []ArtifactClass
	EffectiveNotBefore   time.Time
	Authority            AuthorityRef
	Encoded              []byte
	AcceptedAt           time.Time
}

type Snapshot struct {
	Revision       uint64
	Keyset         *entitlementsync.VerifiedKeyset
	KeysetETag     string
	KeysetPayload  []byte
	RevocationHead ChainState
	RevocationETag string
	Revocations    []Revocation
	AcceptedAt     time.Time
}

type SignerIdentity struct {
	KeyID      string
	Generation uint64
}

type Decision struct {
	Allowed bool
	Reason  string
}

type DecisionSource interface {
	DecideLease(SignerIdentity, time.Time) Decision
	DecidePolicy(SignerIdentity, time.Time) Decision
	DecideRelease(SignerIdentity, time.Time) Decision
	DecideUpgradeGrant(SignerIdentity, time.Time) Decision
}

type SnapshotSource interface {
	Restore(context.Context) (Snapshot, error)
	Accept(context.Context, Candidate) (Snapshot, error)
}
