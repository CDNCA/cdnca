package signercheckpoint

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
)

const (
	CheckpointSchema       = "cdnca.signer-revocation-checkpoint/v2"
	EnvelopeSchema         = "cdnca.signer-revocation-checkpoint-envelope/v2"
	ManifestSchema         = "cdnca.signer-revocation-manifest/v1"
	ManifestEnvelopeSchema = "cdnca.signer-revocation-envelope/v1"
	Algorithm              = "Ed25519"
	AuthorityLineage       = "lineage"
	AuthorityOfflineRoot   = "offline_root"
	ReasonCompromise       = "signer_compromise"
	ArtifactLease          = "lease"
	ArtifactPolicy         = "policy"
	ArtifactRelease        = "release"
	DefaultCheckpointTTL   = 15 * time.Minute
	// MaxOfflineCheckpointTTL bounds the outer validity of a checkpoint the
	// offline root signs by hand (signer-offline-root sign-checkpoint). It is
	// the default acceptance limit: revision, prefix and keyset rollback are
	// rejected independently of freshness, so a long outer TTL only lengthens
	// how long a withheld newer checkpoint looks like an outage.
	MaxOfflineCheckpointTTL = 31 * 24 * time.Hour
	MaxCheckpointBytes      = 8 << 20
	MaxManifestCount        = 10000
	MaxKeysetBytes          = 1 << 20
)

var (
	ErrInvalidInput         = errors.New("invalid signer revocation checkpoint input")
	ErrInvalidCheckpoint    = errors.New("invalid signer revocation checkpoint")
	ErrInvalidEnvelope      = errors.New("invalid signer revocation checkpoint envelope")
	ErrInvalidSignature     = errors.New("invalid signer revocation checkpoint signature")
	ErrWrongAuthority       = errors.New("signer revocation checkpoint requires offline root authority")
	ErrAuthorityUntrusted   = errors.New("signer revocation checkpoint authority is not trusted")
	ErrAuthorityRevoked     = errors.New("signer revocation manifest authority is revoked")
	ErrAuthorityGeneration  = errors.New("signer revocation manifest authority generation is invalid")
	ErrCheckpointNotCurrent = errors.New("signer revocation checkpoint is not currently acceptable")
	ErrManifestNotCurrent   = errors.New("signer revocation checkpoint manifest is from the future")
	ErrChainInvalid         = errors.New("signer revocation checkpoint contains an invalid chain")
	ErrDigestMismatch       = errors.New("signer revocation checkpoint digest mismatch")
	ErrRevisionRollback     = errors.New("signer revocation checkpoint revision rolled back")
	ErrRevisionConflict     = errors.New("signer revocation checkpoint revision conflict")
	ErrRevisionGap          = errors.New("signer revocation checkpoint revision is not the next revision")
	ErrLineage              = errors.New("signer revocation checkpoint outer lineage is invalid")
	ErrPrefixFork           = errors.New("signer revocation checkpoint forks the accepted prefix")
	ErrInvalidKeyset        = errors.New("signer revocation checkpoint keyset is invalid")
	ErrKeysetRollback       = errors.New("signer revocation checkpoint keyset rolled back")
	ErrTTLExceeded          = errors.New("signer revocation checkpoint TTL exceeds limit")
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

type ManifestEnvelope struct {
	Schema                 string        `json:"schema"`
	Algorithm              string        `json:"algorithm"`
	AuthorityKind          AuthorityKind `json:"authority_kind"`
	AuthorityKeyID         string        `json:"authority_key_id"`
	AuthorityKeyGeneration uint64        `json:"authority_key_generation"`
	ManifestSHA256         string        `json:"manifest_sha256"`
}

type SignedSignerRevocationManifest struct {
	Manifest  Manifest         `json:"manifest"`
	Envelope  ManifestEnvelope `json:"envelope"`
	Signature string           `json:"signature"`
}

type SignerRevocationManifest = Manifest
type SignedManifest = SignedSignerRevocationManifest

type AuthorityRef struct {
	Kind       AuthorityKind
	KeyID      string
	Generation uint64
}

type TrustSource interface {
	KeysetPins(context.Context) ([]entitlementguard.VerificationKey, error)
	OfflineRoot(context.Context, AuthorityRef) (ed25519.PublicKey, error)
}

type Snapshot struct {
	Revision           uint64
	CheckpointSHA256   string
	Encoded            []byte
	KeysetPayload      []byte
	HeadSequence       uint64
	HeadManifestSHA256 string
	Manifests          []SignedSignerRevocationManifest
}

type Checkpoint struct {
	Schema                   string                           `json:"schema"`
	Revision                 uint64                           `json:"revision"`
	PreviousRevision         *uint64                          `json:"previous_revision"`
	PreviousCheckpointSHA256 *string                          `json:"previous_checkpoint_sha256"`
	Keyset                   json.RawMessage                  `json:"keyset"`
	KeysetSHA256             string                           `json:"keyset_sha256"`
	HeadSequence             uint64                           `json:"head_sequence"`
	HeadManifestSHA256       string                           `json:"head_manifest_sha256"`
	Manifests                []SignedSignerRevocationManifest `json:"manifests"`
	IssuedAt                 string                           `json:"issued_at"`
	ExpiresAt                string                           `json:"expires_at"`
}

type Envelope struct {
	Schema                 string        `json:"schema"`
	Algorithm              string        `json:"algorithm"`
	AuthorityKind          AuthorityKind `json:"authority_kind"`
	AuthorityKeyID         string        `json:"authority_key_id"`
	AuthorityKeyGeneration uint64        `json:"authority_key_generation"`
	CheckpointSHA256       string        `json:"checkpoint_sha256"`
}

type SignedCheckpoint struct {
	Checkpoint Checkpoint `json:"checkpoint"`
	Envelope   Envelope   `json:"envelope"`
	Signature  string     `json:"signature"`
}

type Projection struct {
	Snapshot Snapshot
	Signed   SignedCheckpoint
	Encoded  []byte
	Replayed bool
}

type Options struct {
	MaxTTL time.Duration
}

func (options Options) maxTTL() (time.Duration, error) {
	if options.MaxTTL == 0 {
		return MaxOfflineCheckpointTTL, nil
	}
	if options.MaxTTL <= 0 {
		return 0, ErrInvalidInput
	}
	return options.MaxTTL, nil
}
