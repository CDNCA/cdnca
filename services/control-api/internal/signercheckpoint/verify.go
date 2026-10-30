package signercheckpoint

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementsync"
)

func VerifyCandidate(ctx context.Context, encoded []byte, previous Snapshot, trust TrustSource, now time.Time) (Projection, error) {
	return VerifyCandidateWithOptions(ctx, encoded, previous, trust, now, Options{})
}

func VerifyCandidateWithOptions(ctx context.Context, encoded []byte, previous Snapshot, trust TrustSource, now time.Time, options Options) (Projection, error) {
	if trust == nil || now.IsZero() {
		return Projection{}, ErrInvalidInput
	}
	signed, err := Decode(encoded)
	if err != nil {
		return Projection{}, err
	}
	now = now.UTC().Truncate(time.Microsecond)
	issued, err := parseTime(signed.Checkpoint.IssuedAt)
	if err != nil {
		return Projection{}, err
	}
	expires, err := parseTime(signed.Checkpoint.ExpiresAt)
	if err != nil || issued.After(now) || !expires.After(now) {
		return Projection{}, ErrCheckpointNotCurrent
	}
	maxTTL, err := options.maxTTL()
	if err != nil || expires.Sub(issued) > maxTTL {
		return Projection{}, ErrTTLExceeded
	}
	ref := AuthorityRef{Kind: signed.Envelope.AuthorityKind, KeyID: signed.Envelope.AuthorityKeyID,
		Generation: signed.Envelope.AuthorityKeyGeneration}
	if ref.Kind != AuthorityOfflineRoot {
		return Projection{}, ErrWrongAuthority
	}
	publicKey, err := trust.OfflineRoot(ctx, ref)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return Projection{}, errors.Join(ErrAuthorityUntrusted, err)
	}
	envelope, err := CanonicalEnvelope(signed.Envelope)
	if err != nil || !ed25519.Verify(publicKey, envelope, decodeSignature(signed.Signature)) {
		return Projection{}, ErrInvalidSignature
	}
	if err := validateRevision(signed, encoded, previous); err != nil {
		return Projection{}, err
	}
	pins, err := trust.KeysetPins(ctx)
	if err != nil || len(pins) == 0 {
		return Projection{}, ErrAuthorityUntrusted
	}
	if err := verifyKeyset(signed.Checkpoint.Keyset, pins, previous.KeysetPayload, now); err != nil {
		return Projection{}, err
	}
	keyset, err := entitlementsync.VerifyPublicKeyset(signed.Checkpoint.Keyset, pins, nil, now)
	if err != nil {
		return Projection{}, err
	}
	if err := verifyInnerChain(ctx, signed.Checkpoint, keyset, trust, now); err != nil {
		return Projection{}, err
	}
	checkpointCanonical, _ := CanonicalCheckpoint(signed.Checkpoint)
	checkpointDigest := sha256.Sum256(checkpointCanonical)
	result := Projection{Signed: cloneSignedCheckpoint(signed), Encoded: append([]byte(nil), encoded...), Replayed: signed.Checkpoint.Revision == previous.Revision}
	result.Snapshot = Snapshot{Revision: signed.Checkpoint.Revision, CheckpointSHA256: encodeDigest(checkpointDigest),
		Encoded: append([]byte(nil), encoded...), KeysetPayload: append([]byte(nil), signed.Checkpoint.Keyset...),
		HeadSequence: signed.Checkpoint.HeadSequence, HeadManifestSHA256: signed.Checkpoint.HeadManifestSHA256,
		Manifests: cloneManifestSlice(signed.Checkpoint.Manifests)}
	return result, nil
}

func Verify(ctx context.Context, encoded []byte, previous Snapshot, trust TrustSource, now time.Time) (Projection, error) {
	return VerifyCandidate(ctx, encoded, previous, trust, now)
}

func validateRevision(signed SignedCheckpoint, encoded []byte, previous Snapshot) error {
	cp := signed.Checkpoint
	if previous.Revision == 0 {
		return nil
	}
	if decodeDigest(previous.CheckpointSHA256) == nil || previous.HeadSequence > MaxManifestCount ||
		len(previous.Manifests) != int(previous.HeadSequence) {
		return ErrPrefixFork
	}
	if previous.HeadSequence == 0 {
		if previous.HeadManifestSHA256 != "" {
			return ErrPrefixFork
		}
	} else {
		last, err := CanonicalManifest(previous.Manifests[previous.HeadSequence-1].Manifest)
		if err != nil {
			return ErrPrefixFork
		}
		digest := sha256.Sum256(last)
		if previous.HeadManifestSHA256 != encodeDigest(digest) {
			return ErrPrefixFork
		}
	}
	if cp.Revision < previous.Revision {
		return ErrRevisionRollback
	}
	if cp.Revision == previous.Revision {
		if len(previous.Encoded) != 0 && bytes.Equal(previous.Encoded, encoded) {
			return nil
		}
		return ErrRevisionConflict
	}
	if cp.HeadSequence < previous.HeadSequence {
		return ErrRevisionRollback
	}
	for index := uint64(0); index < previous.HeadSequence; index++ {
		left, err := EncodeManifest(previous.Manifests[index])
		if err != nil {
			return ErrPrefixFork
		}
		right, err := EncodeManifest(cp.Manifests[index])
		if err != nil || !bytes.Equal(left, right) {
			return ErrPrefixFork
		}
	}
	return nil
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

func verifyInnerChain(ctx context.Context, checkpoint Checkpoint, keyset *entitlementsync.VerifiedKeyset, trust TrustSource, now time.Time) error {
	if keyset == nil {
		return ErrInvalidCheckpoint
	}
	var history keysetHistoryWire
	decoder := json.NewDecoder(bytes.NewReader(checkpoint.Keyset))
	if err := decoder.Decode(&history); err != nil {
		return ErrInvalidCheckpoint
	}
	activations := make(map[string]time.Time, len(history.Keys)+len(history.Rotations))
	for _, key := range history.Keys {
		at, err := parseTime(key.NotBefore)
		if err != nil {
			return ErrInvalidCheckpoint
		}
		activations[key.KeyID] = at
	}
	for _, rotation := range history.Rotations {
		at, err := parseTime(rotation.ActivatedAt)
		if err != nil {
			return ErrInvalidCheckpoint
		}
		activations[rotation.NewKeyID] = at
	}
	for index, signed := range checkpoint.Manifests {
		if _, err := EncodeManifest(signed); err != nil || signed.Manifest.Sequence != uint64(index+1) {
			return ErrChainInvalid
		}
		issued, _ := parseTime(signed.Manifest.IssuedAt)
		if issued.After(now) {
			return ErrManifestNotCurrent
		}
		if _, found := lineageKey(keyset, signed.Manifest.RevokedKeyID, signed.Manifest.RevokedKeyGeneration); !found {
			return ErrAuthorityGeneration
		}
		ref := AuthorityRef{Kind: signed.Envelope.AuthorityKind, KeyID: signed.Envelope.AuthorityKeyID,
			Generation: signed.Envelope.AuthorityKeyGeneration}
		if ref.Kind == AuthorityLineage && ref.Generation <= signed.Manifest.RevokedKeyGeneration {
			return ErrAuthorityGeneration
		}
		publicKey, err := resolveAuthority(ctx, ref, issued, now, keyset, checkpoint.Manifests[:index], activations, trust)
		if err != nil {
			return err
		}
		envelope, _ := CanonicalManifestEnvelope(signed.Envelope)
		if !ed25519.Verify(publicKey, envelope, decodeSignature(signed.Signature)) {
			return ErrInvalidSignature
		}
	}
	return nil
}

func lineageKey(keyset *entitlementsync.VerifiedKeyset, keyID string, generation uint64) (entitlementguard.VerificationKey, bool) {
	if generation == 0 || generation > uint64(len(keyset.Chain)) || keyset.Chain[generation-1] != keyID {
		return entitlementguard.VerificationKey{}, false
	}
	for _, key := range keyset.Keys {
		if key.KeyID == keyID {
			return key, true
		}
	}
	return entitlementguard.VerificationKey{}, false
}

// Lineage signatures must be issued inside the key's signing window; VerifyUntil
// is evaluated at the fresh outer acceptance time, so inner expiry is the only
// historical field that the checkpoint bootstrap can exempt.
func resolveAuthority(ctx context.Context, ref AuthorityRef, issued, now time.Time, keyset *entitlementsync.VerifiedKeyset,
	prior []SignedSignerRevocationManifest, activations map[string]time.Time, trust TrustSource) (ed25519.PublicKey, error) {
	if ref.Kind == AuthorityOfflineRoot {
		key, err := trust.OfflineRoot(ctx, ref)
		if err != nil || len(key) != ed25519.PublicKeySize {
			return nil, errors.Join(ErrAuthorityUntrusted, err)
		}
		return key, nil
	}
	if ref.Kind != AuthorityLineage {
		return nil, ErrAuthorityUntrusted
	}
	key, found := lineageKey(keyset, ref.KeyID, ref.Generation)
	activation, activated := activations[ref.KeyID]
	if !found || !activated || issued.Before(activation) || issued.Before(key.NotBefore) || key.SignUntil == nil ||
		!issued.Before(*key.SignUntil) || (key.VerifyUntil != nil && !now.Before(*key.VerifyUntil)) ||
		(ref.Generation < uint64(len(keyset.Chain)) && !issued.Before(activations[keyset.Chain[ref.Generation]])) {
		return nil, ErrAuthorityGeneration
	}
	for _, priorManifest := range prior {
		effective, _ := parseTime(priorManifest.Manifest.EffectiveNotBefore)
		if priorManifest.Manifest.RevokedKeyID == ref.KeyID && priorManifest.Manifest.RevokedKeyGeneration == ref.Generation && !issued.Before(effective) {
			return nil, ErrAuthorityRevoked
		}
	}
	return append(ed25519.PublicKey(nil), key.PublicKey...), nil
}

func cloneSignedCheckpoint(signed SignedCheckpoint) SignedCheckpoint {
	signed.Checkpoint.PreviousRevision = cloneUint64(signed.Checkpoint.PreviousRevision)
	signed.Checkpoint.PreviousCheckpointSHA256 = cloneString(signed.Checkpoint.PreviousCheckpointSHA256)
	signed.Checkpoint.Keyset = append(json.RawMessage(nil), signed.Checkpoint.Keyset...)
	signed.Checkpoint.Manifests = cloneManifestSlice(signed.Checkpoint.Manifests)
	return signed
}

func cloneManifestSlice(manifests []SignedSignerRevocationManifest) []SignedSignerRevocationManifest {
	cloned := make([]SignedSignerRevocationManifest, len(manifests))
	for index, signed := range manifests {
		signed.Manifest.PreviousSequence = cloneUint64(signed.Manifest.PreviousSequence)
		signed.Manifest.PreviousManifestSHA256 = cloneString(signed.Manifest.PreviousManifestSHA256)
		signed.Manifest.ArtifactClasses = append([]ArtifactClass(nil), signed.Manifest.ArtifactClasses...)
		cloned[index] = signed
	}
	return cloned
}

func cloneUint64(value *uint64) *uint64 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func CanonicalKeyset(encoded []byte, pins []entitlementguard.VerificationKey, now time.Time) (*entitlementsync.VerifiedKeyset, error) {
	if err := verifyKeyset(encoded, pins, nil, now); err != nil {
		return nil, err
	}
	return entitlementsync.VerifyPublicKeyset(encoded, pins, nil, now)
}

func Digest(encoded []byte) (string, error) {
	if len(encoded) == 0 {
		return "", ErrInvalidInput
	}
	digest := sha256.Sum256(encoded)
	return encodeDigest(digest), nil
}
