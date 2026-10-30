package signercheckpoint

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementsync"
)

type keysetHeader struct {
	Schema      string            `json:"schema"`
	ActiveKeyID string            `json:"active_key_id"`
	Keys        []json.RawMessage `json:"keys"`
	Rotations   []json.RawMessage `json:"rotations"`
}

func CanonicalCheckpoint(checkpoint Checkpoint) ([]byte, error) {
	if err := validateCheckpoint(checkpoint); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(checkpoint)
	if err != nil || len(encoded) > MaxCheckpointBytes {
		return nil, ErrInvalidCheckpoint
	}
	return encoded, nil
}

func CanonicalEnvelope(envelope Envelope) ([]byte, error) {
	if envelope.AuthorityKind != AuthorityOfflineRoot {
		return nil, ErrWrongAuthority
	}
	if envelope.Schema != EnvelopeSchema || envelope.Algorithm != Algorithm ||
		entitlement.ValidateKeyID(envelope.AuthorityKeyID) != nil || envelope.AuthorityKeyGeneration == 0 ||
		decodeDigest(envelope.CheckpointSHA256) == nil {
		return nil, ErrInvalidEnvelope
	}
	return json.Marshal(envelope)
}

func Encode(signed SignedCheckpoint) ([]byte, error) {
	checkpoint, err := CanonicalCheckpoint(signed.Checkpoint)
	if err != nil {
		return nil, err
	}
	if _, err := CanonicalEnvelope(signed.Envelope); err != nil {
		return nil, err
	}
	if decodeSignature(signed.Signature) == nil {
		return nil, ErrInvalidSignature
	}
	digest := sha256.Sum256(checkpoint)
	if !bytes.Equal(decodeDigest(signed.Envelope.CheckpointSHA256), digest[:]) {
		return nil, ErrDigestMismatch
	}
	return json.Marshal(signed)
}

func Decode(encoded []byte) (SignedCheckpoint, error) {
	if len(encoded) == 0 || len(encoded) > MaxCheckpointBytes || strictJSON(encoded) != nil {
		return SignedCheckpoint{}, ErrInvalidCheckpoint
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var signed SignedCheckpoint
	if err := decoder.Decode(&signed); err != nil || ensureEOF(decoder) != nil {
		return SignedCheckpoint{}, ErrInvalidCheckpoint
	}
	canonical, err := Encode(signed)
	if err != nil {
		return SignedCheckpoint{}, err
	}
	if !bytes.Equal(canonical, encoded) {
		return SignedCheckpoint{}, ErrInvalidCheckpoint
	}
	return signed, nil
}

func CanonicalManifest(manifest Manifest) ([]byte, error) {
	if manifest.Schema != ManifestSchema || manifest.Sequence == 0 || entitlement.ValidateKeyID(manifest.RevokedKeyID) != nil ||
		manifest.RevokedKeyGeneration == 0 || manifest.Reason != ReasonCompromise || !validArtifactClasses(manifest.ArtifactClasses) {
		return nil, ErrInvalidCheckpoint
	}
	if manifest.Sequence == 1 {
		if manifest.PreviousSequence != nil || manifest.PreviousManifestSHA256 != nil {
			return nil, ErrInvalidCheckpoint
		}
	} else if manifest.PreviousSequence == nil || *manifest.PreviousSequence != manifest.Sequence-1 || manifest.PreviousManifestSHA256 == nil ||
		decodeDigest(*manifest.PreviousManifestSHA256) == nil {
		return nil, ErrInvalidCheckpoint
	}
	effective, err := parseTime(manifest.EffectiveNotBefore)
	if err != nil {
		return nil, err
	}
	issued, err := parseTime(manifest.IssuedAt)
	if err != nil {
		return nil, err
	}
	expires, err := parseTime(manifest.ExpiresAt)
	if err != nil || !expires.After(issued) || !expires.After(effective) {
		return nil, ErrInvalidCheckpoint
	}
	return json.Marshal(manifest)
}

func CanonicalManifestEnvelope(envelope ManifestEnvelope) ([]byte, error) {
	if envelope.Schema != ManifestEnvelopeSchema || envelope.Algorithm != Algorithm ||
		(envelope.AuthorityKind != AuthorityLineage && envelope.AuthorityKind != AuthorityOfflineRoot) ||
		entitlement.ValidateKeyID(envelope.AuthorityKeyID) != nil || envelope.AuthorityKeyGeneration == 0 ||
		decodeDigest(envelope.ManifestSHA256) == nil {
		return nil, ErrInvalidCheckpoint
	}
	return json.Marshal(envelope)
}

func EncodeManifest(signed SignedSignerRevocationManifest) ([]byte, error) {
	manifest, err := CanonicalManifest(signed.Manifest)
	if err != nil {
		return nil, err
	}
	if _, err := CanonicalManifestEnvelope(signed.Envelope); err != nil {
		return nil, err
	}
	if decodeSignature(signed.Signature) == nil {
		return nil, ErrInvalidSignature
	}
	digest := sha256.Sum256(manifest)
	if !bytes.Equal(decodeDigest(signed.Envelope.ManifestSHA256), digest[:]) {
		return nil, ErrDigestMismatch
	}
	return json.Marshal(signed)
}

func validateCheckpoint(checkpoint Checkpoint) error {
	if checkpoint.Schema != CheckpointSchema || checkpoint.Revision == 0 || decodeDigest(checkpoint.KeysetSHA256) == nil ||
		len(checkpoint.Keyset) == 0 || len(checkpoint.Keyset) > MaxKeysetBytes || checkpoint.HeadSequence > MaxManifestCount ||
		len(checkpoint.Manifests) != int(checkpoint.HeadSequence) {
		return ErrInvalidCheckpoint
	}
	if checkpoint.Revision == 1 {
		if checkpoint.PreviousRevision != nil || checkpoint.PreviousCheckpointSHA256 != nil {
			return ErrInvalidCheckpoint
		}
	} else if checkpoint.PreviousRevision == nil || *checkpoint.PreviousRevision != checkpoint.Revision-1 || checkpoint.PreviousCheckpointSHA256 == nil ||
		decodeDigest(*checkpoint.PreviousCheckpointSHA256) == nil {
		return ErrInvalidCheckpoint
	}
	keyset, err := canonicalKeyset(checkpoint.Keyset)
	if err != nil || !bytes.Equal(keyset, checkpoint.Keyset) {
		return ErrInvalidCheckpoint
	}
	digest := sha256.Sum256(keyset)
	if !bytes.Equal(decodeDigest(checkpoint.KeysetSHA256), digest[:]) {
		return ErrDigestMismatch
	}
	issued, err := parseTime(checkpoint.IssuedAt)
	if err != nil {
		return err
	}
	expires, err := parseTime(checkpoint.ExpiresAt)
	if err != nil || !expires.After(issued) {
		return ErrInvalidCheckpoint
	}
	if checkpoint.HeadSequence == 0 {
		if checkpoint.Manifests == nil || checkpoint.HeadManifestSHA256 != "" {
			return ErrInvalidCheckpoint
		}
		return nil
	}
	if decodeDigest(checkpoint.HeadManifestSHA256) == nil {
		return ErrInvalidCheckpoint
	}
	previous := ""
	for index, manifest := range checkpoint.Manifests {
		if manifest.Manifest.Sequence != uint64(index+1) {
			return ErrChainInvalid
		}
		if _, err := EncodeManifest(manifest); err != nil {
			return ErrChainInvalid
		}
		canonical, _ := CanonicalManifest(manifest.Manifest)
		digest := sha256.Sum256(canonical)
		if index == 0 {
			if manifest.Manifest.PreviousSequence != nil || manifest.Manifest.PreviousManifestSHA256 != nil {
				return ErrChainInvalid
			}
		} else if manifest.Manifest.PreviousSequence == nil || *manifest.Manifest.PreviousSequence != uint64(index) ||
			manifest.Manifest.PreviousManifestSHA256 == nil || *manifest.Manifest.PreviousManifestSHA256 != previous {
			return ErrChainInvalid
		}
		previous = encodeDigest(digest)
	}
	if previous != checkpoint.HeadManifestSHA256 {
		return ErrChainInvalid
	}
	return nil
}

func canonicalKeyset(encoded []byte) ([]byte, error) {
	if len(encoded) == 0 || len(encoded) > MaxKeysetBytes || strictJSON(encoded) != nil {
		return nil, ErrInvalidCheckpoint
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var header keysetHeader
	if err := decoder.Decode(&header); err != nil || ensureEOF(decoder) != nil || header.Schema != "cdnca.signing-keyset/v2" ||
		entitlement.ValidateKeyID(header.ActiveKeyID) != nil || len(header.Keys) == 0 || len(header.Rotations) != len(header.Keys)-1 {
		return nil, ErrInvalidCheckpoint
	}
	canonical, err := json.Marshal(header)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return nil, ErrInvalidCheckpoint
	}
	return canonical, nil
}

func strictJSON(encoded []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err := walkJSON(decoder); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON value")
	}
	return nil
}

func walkJSON(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if delim == '{' {
		keys := map[string]struct{}{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, exists := keys[name]; exists {
				return errors.New("duplicate JSON key")
			}
			keys[name] = struct{}{}
			if err := walkJSON(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	}
	if delim == '[' {
		for decoder.More() {
			if err := walkJSON(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	}
	return errors.New("invalid JSON delimiter")
}

func parseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.IsZero() || parsed.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano) != value {
		return time.Time{}, ErrInvalidCheckpoint
	}
	return parsed.UTC(), nil
}

func validArtifactClasses(classes []ArtifactClass) bool {
	if len(classes) == 0 || len(classes) > 3 {
		return false
	}
	previous := ""
	for _, class := range classes {
		value := string(class)
		if value != ArtifactLease && value != ArtifactPolicy && value != ArtifactRelease || (previous != "" && previous >= value) {
			return false
		}
		previous = value
	}
	return true
}

func encodeDigest(digest [32]byte) string { return base64.RawURLEncoding.EncodeToString(digest[:]) }
func decodeDigest(value string) []byte {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil
	}
	return decoded
}
func decodeSignature(value string) []byte {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil
	}
	return decoded
}
func ensureEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return ErrInvalidCheckpoint
	}
	return nil
}

func verifyKeyset(encoded []byte, pins []entitlementguard.VerificationKey, previous []byte, now time.Time) error {
	var prior *entitlementsync.VerifiedKeyset
	if len(previous) != 0 {
		verified, err := entitlementsync.VerifyPublicKeyset(previous, pins, nil, now)
		if err != nil {
			return errors.Join(ErrInvalidKeyset, err)
		}
		prior = verified
	}
	if _, err := entitlementsync.VerifyPublicKeyset(encoded, pins, prior, now); err != nil {
		if errors.Is(err, entitlementsync.ErrKeysetRollback) {
			return errors.Join(ErrKeysetRollback, err)
		}
		return errors.Join(ErrInvalidKeyset, err)
	}
	return nil
}
