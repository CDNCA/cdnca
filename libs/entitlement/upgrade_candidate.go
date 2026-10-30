package entitlement

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strconv"
	"time"
)

const (
	UpgradeCandidateRequestSchema  = "cdnca.upgrade.candidate.request/v1"
	UpgradeCandidateSnapshotSchema = "cdnca.upgrade.candidate-snapshot/v1"
	UpgradeCandidateAudience       = "cdnca-control-plane-upgrade-candidate"
	UpgradeCandidatePurpose        = "cdnca-upgrade-candidate-read"
	UpgradeCandidateTTL            = time.Minute
	UpgradeCandidateProofSkew      = 5 * time.Minute
)

var (
	ErrInvalidUpgradeCandidate  = errors.New("invalid upgrade candidate snapshot")
	ErrUpgradeCandidateMismatch = errors.New("upgrade candidate request binding mismatch")
	ErrUpgradeCandidateExpired  = errors.New("upgrade candidate snapshot expired")
)

type UpgradeCandidateRequest struct {
	Schema          string `json:"schema"`
	Component       string `json:"component"`
	CurrentVersion  string `json:"current_version"`
	ProtocolVersion int    `json:"protocol_version"`
}

type UpgradeCandidateAuthority struct {
	LicenseRevision uint64       `json:"license_revision"`
	Version         VersionRange `json:"version"`
	TargetMode      string       `json:"target_mode"`
	TargetRevision  *uint64      `json:"target_revision,omitempty"`
	ChannelRevision *uint64      `json:"channel_revision,omitempty"`
}

type UpgradeCandidateArtifact struct {
	Manifest                     ArtifactManifestV2 `json:"manifest"`
	SignatureAlgorithm           string             `json:"signature_algorithm"`
	SignatureKeyID               string             `json:"signature_key_id"`
	ManifestSignature            string             `json:"manifest_signature"`
	Revision                     uint64             `json:"revision"`
	PublishedAt                  int64              `json:"published_at"`
	AttestedAt                   int64              `json:"attested_at"`
	RepositoryVerificationSHA256 string             `json:"repository_verification_sha256"`
	RepositoryVerifiedAt         int64              `json:"repository_verified_at"`
	VerifiedUntil                int64              `json:"verified_until"`
}

// A candidate is a fresh read of release policy, never an execution authorization.
type UpgradeCandidateSnapshot struct {
	Schema          string                     `json:"schema"`
	Audience        string                     `json:"audience"`
	Purpose         string                     `json:"purpose"`
	InstallationID  string                     `json:"installation_id"`
	RequestID       string                     `json:"request_id"`
	RequestSHA256   string                     `json:"request_sha256"`
	Component       string                     `json:"component"`
	CurrentVersion  string                     `json:"current_version"`
	ProtocolVersion int                        `json:"protocol_version"`
	Status          string                     `json:"status"`
	Reason          string                     `json:"reason"`
	Authority       *UpgradeCandidateAuthority `json:"authority,omitempty"`
	Candidate       *UpgradeCandidateArtifact  `json:"candidate,omitempty"`
	IssuedAt        int64                      `json:"issued_at"`
	ExpiresAt       int64                      `json:"expires_at"`
}

type SignedUpgradeCandidate struct {
	Algorithm string                   `json:"algorithm"`
	KeyID     string                   `json:"key_id"`
	Snapshot  UpgradeCandidateSnapshot `json:"snapshot"`
	Signature string                   `json:"signature"`
}

type UpgradeCandidateVerifyOptions struct {
	Now                     time.Time
	ExpectedInstallationID  string
	ExpectedRequestID       string
	ExpectedRequestSHA256   string
	ExpectedComponent       string
	ExpectedCurrentVersion  string
	ExpectedProtocolVersion int
}

func CanonicalUpgradeCandidateRequest(request UpgradeCandidateRequest) ([]byte, error) {
	if request.Schema != UpgradeCandidateRequestSchema || !upgradeGrantCodePattern.MatchString(request.Component) ||
		!validCanonicalSemver(request.CurrentVersion) || request.ProtocolVersion < 1 {
		return nil, ErrInvalidUpgradeCandidate
	}
	return json.Marshal(request)
}

func UpgradeCandidateRequestProofMessage(installationID, requestID string, requestedAt int64, body []byte) ([]byte, error) {
	var request UpgradeCandidateRequest
	if !validCanonicalUUID(installationID) || !validCanonicalUUID(requestID) || requestedAt <= 0 || json.Unmarshal(body, &request) != nil {
		return nil, ErrInvalidUpgradeCandidate
	}
	canonical, err := CanonicalUpgradeCandidateRequest(request)
	if err != nil || !bytes.Equal(body, canonical) {
		return nil, ErrInvalidUpgradeCandidate
	}
	digest := sha256.Sum256(body)
	fields := []string{"cdnca-upgrade-candidate-request-proof/v1", "POST",
		"/activation/v1/installations/" + installationID + "/upgrade-candidates:resolve", requestID, installationID,
		strconv.FormatInt(requestedAt, 10), base64.RawURLEncoding.EncodeToString(digest[:])}
	hash := sha256.New()
	var size [4]byte
	for _, field := range fields {
		binary.BigEndian.PutUint32(size[:], uint32(len(field)))
		_, _ = hash.Write(size[:])
		_, _ = hash.Write([]byte(field))
	}
	return hash.Sum(nil), nil
}

func (snapshot UpgradeCandidateSnapshot) Validate() error {
	if snapshot.Schema != UpgradeCandidateSnapshotSchema || snapshot.Audience != UpgradeCandidateAudience ||
		snapshot.Purpose != UpgradeCandidatePurpose || !validCanonicalUUID(snapshot.InstallationID) ||
		!validCanonicalUUID(snapshot.RequestID) || !validRawDigest(snapshot.RequestSHA256) || snapshot.IssuedAt <= 0 ||
		snapshot.ExpiresAt <= snapshot.IssuedAt || snapshot.ExpiresAt-snapshot.IssuedAt > int64(UpgradeCandidateTTL/time.Second) {
		return ErrInvalidUpgradeCandidate
	}
	if _, err := CanonicalUpgradeCandidateRequest(UpgradeCandidateRequest{Schema: UpgradeCandidateRequestSchema,
		Component: snapshot.Component, CurrentVersion: snapshot.CurrentVersion, ProtocolVersion: snapshot.ProtocolVersion}); err != nil {
		return err
	}
	if snapshot.Status == "unavailable" {
		if snapshot.Authority != nil || snapshot.Candidate != nil {
			return ErrInvalidUpgradeCandidate
		}
		switch snapshot.Reason {
		case "target_unset", "license_inactive", "customer_inactive", "channel_inactive", "target_not_allowed",
			"artifact_unavailable", "artifact_unverified", "protocol_incompatible", "version_not_allowed", "signing_key_unavailable":
			return nil
		default:
			return ErrInvalidUpgradeCandidate
		}
	}
	if snapshot.Authority == nil || snapshot.Candidate == nil {
		return ErrInvalidUpgradeCandidate
	}
	authority, artifact := snapshot.Authority, snapshot.Candidate
	if authority.LicenseRevision == 0 || !upgradeGrantCodePattern.MatchString(authority.Version.Channel) ||
		authority.ChannelRevision == nil || *authority.ChannelRevision == 0 ||
		(authority.TargetMode != "follow_channel" && authority.TargetMode != "pinned") ||
		(authority.TargetRevision != nil && *authority.TargetRevision == 0) ||
		(authority.TargetMode == "pinned" && authority.TargetRevision == nil) ||
		!(Lease{Version: authority.Version}).AllowsVersion(authority.Version.Channel, artifact.Manifest.Version) ||
		artifact.Manifest.Schema != ArtifactManifestV2Schema || artifact.Manifest.Validate() != nil ||
		artifact.Manifest.Component != snapshot.Component || artifact.SignatureAlgorithm != Algorithm ||
		ValidateKeyID(artifact.SignatureKeyID) != nil || !validCandidateSignature(artifact.ManifestSignature) || artifact.Revision < 2 ||
		artifact.PublishedAt <= 0 || artifact.PublishedAt > snapshot.IssuedAt || artifact.AttestedAt <= 0 ||
		artifact.AttestedAt > artifact.PublishedAt || !validRawDigest(artifact.RepositoryVerificationSHA256) ||
		artifact.RepositoryVerifiedAt < artifact.AttestedAt || artifact.RepositoryVerifiedAt > artifact.PublishedAt ||
		artifact.VerifiedUntil < snapshot.ExpiresAt || snapshot.ProtocolVersion < artifact.Manifest.ProtocolMin ||
		snapshot.ProtocolVersion > artifact.Manifest.ProtocolMax {
		return ErrInvalidUpgradeCandidate
	}
	status, reason := "available", "upgrade_available"
	switch upgradeOperation(snapshot.CurrentVersion, artifact.Manifest.Version) {
	case ReinstallOperation:
		status, reason = "up_to_date", "same_version"
	case RollbackOperation:
		status, reason = "rollback_required", "target_is_older"
	}
	if snapshot.Status != status || snapshot.Reason != reason {
		return ErrInvalidUpgradeCandidate
	}
	return nil
}

func validCandidateSignature(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == ed25519.SignatureSize && base64.RawURLEncoding.EncodeToString(decoded) == value
}

// Includes the envelope identity and a domain distinct from all executable grants.
func UpgradeCandidateSigningMessage(signed SignedUpgradeCandidate) ([]byte, error) {
	if signed.Algorithm != Algorithm || ValidateKeyID(signed.KeyID) != nil || signed.Snapshot.Validate() != nil {
		return nil, ErrInvalidUpgradeCandidate
	}
	return json.Marshal(struct {
		Domain    string                   `json:"domain"`
		Algorithm string                   `json:"algorithm"`
		KeyID     string                   `json:"key_id"`
		Snapshot  UpgradeCandidateSnapshot `json:"snapshot"`
	}{"cdnca-upgrade-candidate-signature/v1", signed.Algorithm, signed.KeyID, signed.Snapshot})
}

// Use with TrustStore.VerifyDetached to apply artifact-key lifetime checks too.
func UpgradeCandidateArtifactSigningMessage(artifact UpgradeCandidateArtifact) ([]byte, error) {
	if artifact.Manifest.Schema != ArtifactManifestV2Schema || artifact.Manifest.Validate() != nil {
		return nil, ErrInvalidUpgradeCandidate
	}
	return json.Marshal(artifactManifestV2SigningDocument{Domain: artifactManifestV2SignatureDomain, Manifest: artifact.Manifest})
}

func SignUpgradeCandidate(ctx context.Context, snapshot UpgradeCandidateSnapshot, signer Signer) (SignedUpgradeCandidate, error) {
	if signer == nil {
		return SignedUpgradeCandidate{}, ErrInvalidUpgradeCandidate
	}
	signed := SignedUpgradeCandidate{Algorithm: Algorithm, KeyID: signer.KeyID(), Snapshot: snapshot}
	message, err := UpgradeCandidateSigningMessage(signed)
	if err != nil {
		return SignedUpgradeCandidate{}, err
	}
	signature, err := signer.Sign(ctx, message)
	if err != nil {
		return SignedUpgradeCandidate{}, err
	}
	if len(signature) != ed25519.SignatureSize {
		return SignedUpgradeCandidate{}, ErrInvalidSignature
	}
	signed.Signature = base64.RawURLEncoding.EncodeToString(signature)
	return signed, nil
}

func (signed SignedUpgradeCandidate) Encode() ([]byte, error) {
	if _, err := UpgradeCandidateSigningMessage(signed); err != nil {
		return nil, err
	}
	if !validCandidateSignature(signed.Signature) {
		return nil, ErrInvalidUpgradeCandidate
	}
	return json.Marshal(signed)
}

func DecodeUpgradeCandidate(encoded []byte) (SignedUpgradeCandidate, error) {
	var signed SignedUpgradeCandidate
	if len(encoded) == 0 || len(encoded) > 64*1024 || json.Unmarshal(encoded, &signed) != nil {
		return signed, ErrInvalidUpgradeCandidate
	}
	canonical, err := signed.Encode()
	if err != nil || !bytes.Equal(canonical, encoded) {
		return SignedUpgradeCandidate{}, ErrInvalidUpgradeCandidate
	}
	return signed, nil
}

func (ring *KeyRing) VerifyUpgradeCandidate(signed SignedUpgradeCandidate, options UpgradeCandidateVerifyOptions) error {
	message, err := UpgradeCandidateSigningMessage(signed)
	if err != nil || !validCandidateSignature(signed.Signature) {
		return ErrInvalidUpgradeCandidate
	}
	if ring == nil {
		return ErrUnknownKey
	}
	key, found := ring.keys[signed.KeyID]
	if !found {
		return ErrUnknownKey
	}
	signature, _ := base64.RawURLEncoding.DecodeString(signed.Signature)
	if !ed25519.Verify(key, message, signature) {
		return ErrInvalidSignature
	}
	snapshot := signed.Snapshot
	if options.Now.IsZero() || snapshot.IssuedAt > options.Now.UTC().Unix()+5 {
		return ErrNotYetValid
	}
	if options.Now.UTC().Unix() >= snapshot.ExpiresAt {
		return ErrUpgradeCandidateExpired
	}
	if snapshot.InstallationID != options.ExpectedInstallationID || snapshot.RequestID != options.ExpectedRequestID ||
		snapshot.RequestSHA256 != options.ExpectedRequestSHA256 || snapshot.Component != options.ExpectedComponent ||
		snapshot.CurrentVersion != options.ExpectedCurrentVersion || snapshot.ProtocolVersion != options.ExpectedProtocolVersion {
		return ErrUpgradeCandidateMismatch
	}
	if artifact := snapshot.Candidate; artifact != nil {
		artifactKey, found := ring.keys[artifact.SignatureKeyID]
		if !found {
			return ErrUnknownKey
		}
		artifactSignature, _ := base64.RawURLEncoding.DecodeString(artifact.ManifestSignature)
		return VerifyArtifactManifestV2Signature(artifact.Manifest, artifactKey, artifactSignature)
	}
	return nil
}
