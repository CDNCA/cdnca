package ipintel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"time"
)

const (
	// ReleaseSchema names the signed release envelope.
	ReleaseSchema = "cdnca.ip-intel.release/v2"
	// SignatureDomain separates these signatures from every other document
	// signed by the same license signing key.
	SignatureDomain = "cdnca-ip-intel-release-signature/v1"
	// MaxSignedReleaseBytes bounds an encoded SignedRelease.
	MaxSignedReleaseBytes = 16 << 10

	maxRevision = 1<<53 - 1
	signingSkew = 5 * time.Minute
)

var (
	ErrInvalidRelease   = errors.New("ip intel release invalid")
	ErrInvalidSignature = errors.New("ip intel release signature invalid")
	ErrArtifactMismatch = errors.New("ip intel artifact does not match release")

	keyIDPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Release is the signed description of one artifact. Fields are in
// alphabetical JSON order so the canonical encoding is plain json.Marshal.
type Release struct {
	ArtifactBytes     int64  `json:"artifact_bytes"`
	ArtifactSHA256    string `json:"artifact_sha256"`
	BuildID           string `json:"build_id"`
	Capability        string `json:"capability"`
	CapabilityVersion int    `json:"capability_version"`
	Counts            Counts `json:"counts"`
	DataSHA256        string `json:"data_sha256"`
	DataUpdatedAt     int64  `json:"data_updated_at"`
	Domain            string `json:"domain"`
	FormatVersion     int    `json:"format_version"`
	GeneratedAt       int64  `json:"generated_at"`
	KeyID             string `json:"key_id"`
	Revision          uint64 `json:"revision"`
	Schema            string `json:"schema"`
	SignedAt          int64  `json:"signed_at"`
	SourceRelease     string `json:"source_release,omitempty"`
	StaleAfter        int64  `json:"stale_after"`
}

// SignedRelease is the wire form: the release and a raw Ed25519 signature
// (base64url, no padding) over CanonicalRelease(release).
type SignedRelease struct {
	Release   Release `json:"release"`
	Signature string  `json:"signature"`
}

// Signer matches entitlement.Signer (the license service signing key).
type Signer interface {
	KeyID() string
	Sign(context.Context, []byte) ([]byte, error)
}

// Verifier matches the control-api entitlementguard trust store.
type Verifier interface {
	VerifyDetached(keyID string, payload, signature []byte, signedAt, now time.Time) error
}

// NewRelease describes a built artifact; Sign fills the signing fields.
func NewRelease(artifact Artifact) (Release, error) {
	metadata := artifact.Metadata
	generatedAt, err := time.Parse(time.RFC3339, metadata.GeneratedAt)
	if err != nil {
		return Release{}, ErrInvalidRelease
	}
	dataUpdatedAt, err := time.Parse(time.RFC3339, metadata.DataUpdatedAt)
	if err != nil {
		return Release{}, ErrInvalidRelease
	}
	staleAfter, err := time.Parse(time.RFC3339, metadata.StaleAfter)
	if err != nil {
		return Release{}, ErrInvalidRelease
	}
	return Release{
		ArtifactBytes: int64(len(artifact.Bytes)), ArtifactSHA256: artifact.SHA256, BuildID: metadata.BuildID,
		Capability: Capability, CapabilityVersion: CapabilityVersion, Counts: metadata.Counts,
		DataSHA256: artifact.DataSHA256, DataUpdatedAt: dataUpdatedAt.Unix(), FormatVersion: FormatVersion,
		GeneratedAt: generatedAt.Unix(), Revision: metadata.Revision, SourceRelease: metadata.SourceRelease,
		StaleAfter: staleAfter.Unix(),
	}, nil
}

// Fresh reports whether a verified release may still be used at now. A
// stale library is not "ready": consumers keep it for display but must
// not publish (and nodes must not enforce) carrier / IDC rules from it.
func (release Release) Fresh(now time.Time) bool {
	return now.Unix() < release.StaleAfter
}

// Sign signs release with signer at signedAt.
func Sign(ctx context.Context, release Release, signer Signer, signedAt time.Time) (SignedRelease, error) {
	if signer == nil || !keyIDPattern.MatchString(signer.KeyID()) {
		return SignedRelease{}, ErrInvalidRelease
	}
	release.Domain, release.Schema, release.KeyID, release.SignedAt = SignatureDomain, ReleaseSchema, signer.KeyID(), signedAt.Unix()
	payload, err := CanonicalRelease(release)
	if err != nil {
		return SignedRelease{}, err
	}
	signature, err := signer.Sign(ctx, payload)
	if err != nil {
		return SignedRelease{}, err
	}
	if len(signature) != ed25519.SignatureSize {
		return SignedRelease{}, ErrInvalidSignature
	}
	return SignedRelease{Release: release, Signature: base64.RawURLEncoding.EncodeToString(signature)}, nil
}

// CanonicalRelease is the exact signed payload.
func CanonicalRelease(release Release) ([]byte, error) {
	if !validRelease(release) {
		return nil, ErrInvalidRelease
	}
	return json.Marshal(release)
}

func validRelease(release Release) bool {
	return release.Schema == ReleaseSchema && release.Domain == SignatureDomain && keyIDPattern.MatchString(release.KeyID) &&
		release.Revision > 0 && release.Revision <= maxRevision && buildIDPattern.MatchString(release.BuildID) &&
		sha256Pattern.MatchString(release.ArtifactSHA256) && sha256Pattern.MatchString(release.DataSHA256) &&
		release.ArtifactBytes > HeaderSize && release.ArtifactBytes <= MaxArtifactBytes &&
		release.Counts.Attrs > 0 && uint64(release.Counts.IPv4Ranges)+uint64(release.Counts.IPv6Ranges) > 0 &&
		release.FormatVersion == FormatVersion && release.Capability == Capability && release.CapabilityVersion >= 1 &&
		release.GeneratedAt > 0 && release.DataUpdatedAt > 0 && release.DataUpdatedAt <= release.GeneratedAt &&
		release.StaleAfter > release.GeneratedAt && release.StaleAfter <= 253402300799 &&
		len(release.SourceRelease) <= maxSourceRelease &&
		release.SignedAt > 0 && release.SignedAt <= 253402300799
}

// Encode returns the canonical wire bytes.
func (signed SignedRelease) Encode() ([]byte, error) {
	if err := validShape(signed); err != nil {
		return nil, err
	}
	return json.Marshal(signed)
}

// DecodeSignedRelease accepts only the canonical encoding (as produced by
// Encode): no unknown or duplicate fields, no whitespace, one document.
func DecodeSignedRelease(encoded []byte) (SignedRelease, error) {
	if len(encoded) < 2 || len(encoded) > MaxSignedReleaseBytes {
		return SignedRelease{}, ErrInvalidRelease
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var signed SignedRelease
	if err := decoder.Decode(&signed); err != nil || decoder.More() {
		return SignedRelease{}, ErrInvalidRelease
	}
	canonical, err := signed.Encode()
	if err != nil || !bytes.Equal(canonical, encoded) {
		return SignedRelease{}, ErrInvalidRelease
	}
	return signed, nil
}

func validShape(signed SignedRelease) error {
	if !validRelease(signed.Release) {
		return ErrInvalidRelease
	}
	signature, err := base64.RawURLEncoding.DecodeString(signed.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(signature) != signed.Signature {
		return ErrInvalidRelease
	}
	return nil
}

// VerifyEd25519 checks the signature with a raw public key (license service
// self-check before persisting).
func VerifyEd25519(signed SignedRelease, publicKey ed25519.PublicKey) error {
	if err := validShape(signed); err != nil || len(publicKey) != ed25519.PublicKeySize {
		return ErrInvalidRelease
	}
	payload, _ := CanonicalRelease(signed.Release)
	signature, _ := base64.RawURLEncoding.DecodeString(signed.Signature)
	if !ed25519.Verify(publicKey, payload, signature) {
		return ErrInvalidSignature
	}
	return nil
}

// Verify is the consumer check: shape, signing time not in the future and
// the detached signature through the deployment trust chain (key id and key
// validity window). Verify does not check StaleAfter: consumers keep the
// last verified library (LKG) and use Release.Fresh to decide readiness.
func Verify(signed SignedRelease, trust Verifier, now time.Time) error {
	if trust == nil || now.IsZero() {
		return ErrInvalidRelease
	}
	if err := validShape(signed); err != nil {
		return err
	}
	signedAt := time.Unix(signed.Release.SignedAt, 0).UTC()
	if signedAt.After(now.UTC().Add(signingSkew)) {
		return ErrInvalidRelease
	}
	payload, _ := CanonicalRelease(signed.Release)
	signature, _ := base64.RawURLEncoding.DecodeString(signed.Signature)
	if err := trust.VerifyDetached(signed.Release.KeyID, payload, signature, signedAt, now.UTC()); err != nil {
		return errors.Join(ErrInvalidSignature, err)
	}
	return nil
}

// VerifyArtifact checks that data is exactly the artifact release describes
// and opens it. Call it only with a release that passed Verify.
func VerifyArtifact(release Release, data []byte) (*Table, error) {
	if int64(len(data)) != release.ArtifactBytes {
		return nil, ErrArtifactMismatch
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != release.ArtifactSHA256 {
		return nil, ErrArtifactMismatch
	}
	table, err := Open(data)
	if err != nil {
		return nil, err
	}
	metadata := table.Metadata
	generatedAt, _ := time.Parse(time.RFC3339, metadata.GeneratedAt)
	dataUpdatedAt, _ := time.Parse(time.RFC3339, metadata.DataUpdatedAt)
	staleAfter, _ := time.Parse(time.RFC3339, metadata.StaleAfter)
	if metadata.Revision != release.Revision || metadata.BuildID != release.BuildID ||
		metadata.DataSHA256 != release.DataSHA256 || metadata.Counts != release.Counts ||
		generatedAt.Unix() != release.GeneratedAt || dataUpdatedAt.Unix() != release.DataUpdatedAt ||
		staleAfter.Unix() != release.StaleAfter || metadata.SourceRelease != release.SourceRelease ||
		metadata.CapabilityVersion != release.CapabilityVersion {
		return nil, ErrArtifactMismatch
	}
	return table, nil
}
