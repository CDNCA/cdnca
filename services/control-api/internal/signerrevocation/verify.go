package signerrevocation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
)

type verifiedManifest struct {
	signed     SignedManifest
	digest     [sha256.Size]byte
	authority  AuthorityRef
	replayed   bool
	acceptedAt time.Time
}

func verifyManifest(ctx context.Context, encoded []byte, pre Snapshot, trust DeploymentTrustSource,
	verifyAt time.Time) (verifiedManifest, error) {
	signed, err := Decode(encoded)
	if err != nil || trust == nil || verifyAt.IsZero() {
		return verifiedManifest{}, ErrInvalidManifest
	}
	canonical, err := CanonicalManifest(signed.Manifest)
	if err != nil {
		return verifiedManifest{}, err
	}
	digest := sha256.Sum256(canonical)
	declared, err := decodeFixed(signed.Envelope.ManifestSHA256, sha256.Size)
	if err != nil || subtle.ConstantTimeCompare(declared, digest[:]) != 1 {
		return verifiedManifest{}, ErrInvalidManifest
	}
	replayed, err := validateNext(signed.Manifest, digest, pre.RevocationHead)
	if err != nil {
		return verifiedManifest{}, err
	}
	issuedAt, _ := parseCanonicalTime(signed.Manifest.IssuedAt)
	expiresAt, _ := parseCanonicalTime(signed.Manifest.ExpiresAt)
	verifyAt = verifyAt.UTC().Truncate(time.Microsecond)
	if issuedAt.After(verifyAt) || !expiresAt.After(verifyAt) {
		return verifiedManifest{}, ErrManifestNotCurrent
	}
	if _, found := lineageKey(pre, signed.Manifest.RevokedKeyID, signed.Manifest.RevokedKeyGeneration); !found {
		return verifiedManifest{}, ErrAuthorityGeneration
	}
	ref := AuthorityRef{Kind: signed.Envelope.AuthorityKind, KeyID: signed.Envelope.AuthorityKeyID,
		Generation: signed.Envelope.AuthorityKeyGeneration}
	if ref.Kind == AuthorityLineage && ref.Generation <= signed.Manifest.RevokedKeyGeneration {
		return verifiedManifest{}, ErrAuthorityGeneration
	}
	publicKey, err := resolveAuthority(ctx, pre, trust, ref, issuedAt)
	if err != nil {
		return verifiedManifest{}, err
	}
	envelope, err := CanonicalEnvelope(signed.Envelope)
	if err != nil {
		return verifiedManifest{}, err
	}
	signature, err := decodeFixed(signed.Signature, ed25519.SignatureSize)
	if err != nil || !ed25519.Verify(publicKey, envelope, signature) {
		return verifiedManifest{}, ErrInvalidSignature
	}
	return verifiedManifest{signed: signed, digest: digest, authority: ref, replayed: replayed,
		acceptedAt: verifyAt}, nil
}

func validateNext(manifest Manifest, digest [sha256.Size]byte, state ChainState) (bool, error) {
	if state.Sequence > 0 {
		if _, err := decodeFixed(state.ManifestSHA256, sha256.Size); err != nil {
			return false, ErrChainBranch
		}
	}
	if manifest.Sequence <= state.Sequence {
		if manifest.Sequence == state.Sequence && state.ManifestSHA256 == encodeDigest(digest) {
			return true, nil
		}
		if manifest.Sequence == state.Sequence {
			return false, ErrSequenceConflict
		}
		return false, ErrSequenceReplay
	}
	if manifest.Sequence != state.Sequence+1 {
		return false, ErrChainBranch
	}
	if state.Sequence == 0 {
		if manifest.PreviousSequence != nil || manifest.PreviousManifestSHA256 != nil {
			return false, ErrChainBranch
		}
		return false, nil
	}
	if manifest.PreviousSequence == nil || *manifest.PreviousSequence != state.Sequence ||
		manifest.PreviousManifestSHA256 == nil || *manifest.PreviousManifestSHA256 != state.ManifestSHA256 {
		return false, ErrChainBranch
	}
	return false, nil
}

func resolveAuthority(ctx context.Context, pre Snapshot, trust DeploymentTrustSource, ref AuthorityRef,
	issuedAt time.Time) (ed25519.PublicKey, error) {
	if ref.Kind == AuthorityOfflineRoot {
		publicKey, err := trust.OfflineRoot(ctx, ref)
		if err != nil || len(publicKey) != ed25519.PublicKeySize {
			return nil, errors.Join(ErrAuthorityUntrusted, err)
		}
		return append(ed25519.PublicKey(nil), publicKey...), nil
	}
	if ref.Kind != AuthorityLineage {
		return nil, ErrAuthorityUntrusted
	}
	key, found := lineageKey(pre, ref.KeyID, ref.Generation)
	if !found || !lineageCurrentAt(pre, ref, issuedAt) {
		return nil, ErrAuthorityGeneration
	}
	for _, revoked := range pre.Revocations {
		if revoked.RevokedKeyID == ref.KeyID && revoked.RevokedKeyGeneration == ref.Generation &&
			!issuedAt.Before(revoked.EffectiveNotBefore) {
			return nil, ErrAuthorityRevoked
		}
	}
	return append(ed25519.PublicKey(nil), key.PublicKey...), nil
}

func lineageKey(snapshot Snapshot, keyID string, generation uint64) (entitlementguard.VerificationKey, bool) {
	if snapshot.Keyset == nil || generation == 0 || generation > uint64(len(snapshot.Keyset.Chain)) ||
		snapshot.Keyset.Chain[generation-1] != keyID {
		return entitlementguard.VerificationKey{}, false
	}
	for _, key := range snapshot.Keyset.Keys {
		if key.KeyID == keyID {
			return key, true
		}
	}
	return entitlementguard.VerificationKey{}, false
}

type keysetHistoryWire struct {
	Keys []struct {
		KeyID     string `json:"key_id"`
		NotBefore string `json:"not_before"`
	} `json:"keys"`
	Rotations []struct {
		NewKeyID    string `json:"new_key_id"`
		ActivatedAt string `json:"activated_at"`
	} `json:"rotations"`
}

func lineageCurrentAt(snapshot Snapshot, ref AuthorityRef, issuedAt time.Time) bool {
	if snapshot.Keyset == nil || ref.Generation == 0 || ref.Generation > uint64(len(snapshot.Keyset.Chain)) {
		return false
	}
	var wire keysetHistoryWire
	if json.Unmarshal(snapshot.KeysetPayload, &wire) != nil {
		return false
	}
	activations := make(map[string]time.Time, len(wire.Keys))
	for _, key := range wire.Keys {
		activation, err := time.Parse(time.RFC3339Nano, key.NotBefore)
		if err != nil {
			return false
		}
		activations[key.KeyID] = activation.UTC()
	}
	for _, rotation := range wire.Rotations {
		activation, err := time.Parse(time.RFC3339Nano, rotation.ActivatedAt)
		if err != nil {
			return false
		}
		activations[rotation.NewKeyID] = activation.UTC()
	}
	index := int(ref.Generation - 1)
	if snapshot.Keyset.Chain[index] != ref.KeyID || issuedAt.Before(activations[ref.KeyID]) {
		return false
	}
	return index+1 == len(snapshot.Keyset.Chain) || issuedAt.Before(activations[snapshot.Keyset.Chain[index+1]])
}

func manifestRevocation(verified verifiedManifest, etag string, encoded []byte) Revocation {
	manifest := verified.signed.Manifest
	effectiveAt, _ := parseCanonicalTime(manifest.EffectiveNotBefore)
	return Revocation{Sequence: manifest.Sequence, ManifestSHA256: encodeDigest(verified.digest), ETag: etag,
		RevokedKeyID: manifest.RevokedKeyID, RevokedKeyGeneration: manifest.RevokedKeyGeneration,
		ArtifactClasses: append([]ArtifactClass(nil), manifest.ArtifactClasses...), EffectiveNotBefore: effectiveAt,
		Authority: verified.authority, Encoded: append([]byte(nil), encoded...), AcceptedAt: verified.acceptedAt}
}

func equalPayloadDigest(payload, digest []byte) bool {
	expected := sha256.Sum256(payload)
	return len(digest) == sha256.Size && subtle.ConstantTimeCompare(digest, expected[:]) == 1
}

func decodedDigest(value string) []byte {
	decoded, _ := base64.RawURLEncoding.DecodeString(value)
	return decoded
}

func equalBytes(left, right []byte) bool { return bytes.Equal(left, right) }
