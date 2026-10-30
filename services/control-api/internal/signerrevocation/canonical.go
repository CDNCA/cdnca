package signerrevocation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
)

const (
	maxSignedManifestBytes = 128 * 1024
	reasonCompromise       = "signer_compromise"
)

func CanonicalManifest(manifest Manifest) ([]byte, error) {
	if validateManifest(manifest) != nil {
		return nil, ErrInvalidManifest
	}
	return json.Marshal(manifest)
}

func CanonicalEnvelope(envelope Envelope) ([]byte, error) {
	if validateEnvelope(envelope) != nil {
		return nil, ErrInvalidManifest
	}
	return json.Marshal(envelope)
}

func Encode(signed SignedManifest) ([]byte, error) {
	if _, err := CanonicalManifest(signed.Manifest); err != nil {
		return nil, err
	}
	if _, err := CanonicalEnvelope(signed.Envelope); err != nil {
		return nil, err
	}
	if _, err := decodeFixed(signed.Signature, ed25519.SignatureSize); err != nil {
		return nil, ErrInvalidManifest
	}
	return json.Marshal(signed)
}

func Decode(encoded []byte) (SignedManifest, error) {
	if len(encoded) == 0 || len(encoded) > maxSignedManifestBytes {
		return SignedManifest{}, ErrInvalidManifest
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var signed SignedManifest
	if decoder.Decode(&signed) != nil || ensureEOF(decoder) != nil {
		return SignedManifest{}, ErrInvalidManifest
	}
	canonical, err := Encode(signed)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return SignedManifest{}, ErrInvalidManifest
	}
	return signed, nil
}

func validateManifest(manifest Manifest) error {
	if manifest.Schema != ManifestSchema || manifest.Sequence == 0 ||
		entitlement.ValidateKeyID(manifest.RevokedKeyID) != nil || manifest.RevokedKeyGeneration == 0 ||
		manifest.Reason != reasonCompromise || !validArtifactClasses(manifest.ArtifactClasses) {
		return ErrInvalidManifest
	}
	if manifest.Sequence == 1 {
		if manifest.PreviousSequence != nil || manifest.PreviousManifestSHA256 != nil {
			return ErrInvalidManifest
		}
	} else if manifest.PreviousSequence == nil || *manifest.PreviousSequence != manifest.Sequence-1 ||
		manifest.PreviousManifestSHA256 == nil {
		return ErrInvalidManifest
	} else if _, err := decodeFixed(*manifest.PreviousManifestSHA256, sha256.Size); err != nil {
		return ErrInvalidManifest
	}
	effectiveAt, err := parseCanonicalTime(manifest.EffectiveNotBefore)
	if err != nil {
		return err
	}
	issuedAt, err := parseCanonicalTime(manifest.IssuedAt)
	if err != nil {
		return err
	}
	expiresAt, err := parseCanonicalTime(manifest.ExpiresAt)
	if err != nil || !expiresAt.After(issuedAt) || !expiresAt.After(effectiveAt) {
		return ErrInvalidManifest
	}
	return nil
}

func validateEnvelope(envelope Envelope) error {
	if envelope.Schema != EnvelopeSchema || envelope.Algorithm != Algorithm ||
		(envelope.AuthorityKind != AuthorityLineage && envelope.AuthorityKind != AuthorityOfflineRoot) ||
		entitlement.ValidateKeyID(envelope.AuthorityKeyID) != nil || envelope.AuthorityKeyGeneration == 0 {
		return ErrInvalidManifest
	}
	if _, err := decodeFixed(envelope.ManifestSHA256, sha256.Size); err != nil {
		return ErrInvalidManifest
	}
	return nil
}

func validArtifactClasses(classes []ArtifactClass) bool {
	if len(classes) == 0 || len(classes) > 3 {
		return false
	}
	previous := ""
	for _, class := range classes {
		value := string(class)
		if value != string(ArtifactLease) && value != string(ArtifactPolicy) && value != string(ArtifactRelease) ||
			(previous != "" && previous >= value) {
			return false
		}
		previous = value
	}
	return true
}

func canonicalTime(value time.Time) string {
	return value.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano)
}

func parseCanonicalTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || canonicalTime(parsed) != value {
		return time.Time{}, ErrInvalidManifest
	}
	return parsed, nil
}

func encodeDigest(digest [sha256.Size]byte) string {
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func decodeFixed(value string, size int) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != size || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, ErrInvalidManifest
	}
	return decoded, nil
}

func strongETag(payload []byte) string {
	digest := sha256.Sum256(payload)
	return `"` + encodeDigest(digest) + `"`
}

func validStrongETag(etag string, payload []byte) bool {
	return len(payload) > 0 && etag == strongETag(payload)
}

func ensureEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return ErrInvalidManifest
	}
	return nil
}
