package signerrevocation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementsync"
	"github.com/google/uuid"
)

var fixedNow = time.Date(2026, 7, 23, 12, 34, 56, 123456000, time.UTC)

func TestManifestVerificationSequenceTamperAndExpiry(t *testing.T) {
	fixture := makeTrustFixture(t, "root", "middle", "current")
	pre := fixture.snapshot(t)
	genesis := testManifest(1, nil, nil, "root", 1)
	encoded := signManifest(t, genesis, AuthorityRef{Kind: AuthorityLineage, KeyID: "current", Generation: 3},
		fixture.privateKeys["current"])
	verified, err := verifyManifest(t.Context(), encoded, pre, fixture, fixedNow)
	if err != nil || verified.replayed {
		t.Fatalf("verify genesis = (%#v, %v)", verified, err)
	}
	if !validStrongETag(strongETag(encoded), encoded) || validStrongETag(`"wrong"`, encoded) {
		t.Fatal("strong ETag validation result is incorrect")
	}

	replayed, err := verifyManifest(t.Context(), encoded, withHead(pre, verified), fixture, fixedNow)
	if err != nil || !replayed.replayed {
		t.Fatalf("same replay = (%#v, %v)", replayed, err)
	}
	sibling := genesis
	sibling.ArtifactClasses = []ArtifactClass{ArtifactLease}
	siblingEncoded := signManifest(t, sibling, verified.authority, fixture.privateKeys["current"])
	if _, err := verifyManifest(t.Context(), siblingEncoded, withHead(pre, verified), fixture, fixedNow); !errors.Is(err, ErrSequenceConflict) {
		t.Fatalf("sibling error = %v", err)
	}

	previous := uint64(1)
	previousDigest := encodeDigest(verified.digest)
	successor := testManifest(2, &previous, &previousDigest, "middle", 2)
	successorEncoded := signManifest(t, successor, verified.authority, fixture.privateKeys["current"])
	second, err := verifyManifest(t.Context(), successorEncoded, withHead(pre, verified), fixture, fixedNow)
	if err != nil {
		t.Fatalf("verify successor: %v", err)
	}
	stateTwo := withHead(withRevocation(pre, verified, encoded), second)
	stateTwo = withRevocation(stateTwo, second, successorEncoded)
	if _, err := verifyManifest(t.Context(), encoded, stateTwo, fixture, fixedNow); !errors.Is(err, ErrSequenceReplay) {
		t.Fatalf("lower sequence error = %v", err)
	}
	gapPrevious := uint64(2)
	gap := testManifest(3, &gapPrevious, &previousDigest, "root", 1)
	gapEncoded := signManifest(t, gap, verified.authority, fixture.privateKeys["current"])
	if _, err := verifyManifest(t.Context(), gapEncoded, withHead(pre, verified), fixture, fixedNow); !errors.Is(err, ErrChainBranch) {
		t.Fatalf("gap error = %v", err)
	}

	noncanonical := append([]byte{' '}, encoded...)
	if _, err := verifyManifest(t.Context(), noncanonical, pre, fixture, fixedNow); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("noncanonical error = %v", err)
	}
	tampered, _ := Decode(encoded)
	signature, _ := base64.RawURLEncoding.DecodeString(tampered.Signature)
	signature[0] ^= 0xff
	tampered.Signature = base64.RawURLEncoding.EncodeToString(signature)
	tamperedEncoded, _ := Encode(tampered)
	if _, err := verifyManifest(t.Context(), tamperedEncoded, pre, fixture, fixedNow); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("signature tamper error = %v", err)
	}
	if _, err := verifyManifest(t.Context(), encoded, pre, fixture, fixedNow.Add(time.Hour)); !errors.Is(err, ErrManifestNotCurrent) {
		t.Fatalf("expired transport error = %v", err)
	}
}

func TestOfflineRootLineageAndArtifactDecisions(t *testing.T) {
	fixture := makeTrustFixture(t, "root", "current")
	pre := fixture.snapshot(t)
	offlinePublic, offlinePrivate := deterministicKey("offline-root")
	manifest := testManifest(1, nil, nil, "root", 1)
	manifest.EffectiveNotBefore = canonicalTime(fixedNow.Add(time.Minute))
	ref := AuthorityRef{Kind: AuthorityOfflineRoot, KeyID: "offline-root", Generation: 1}
	encoded := signManifest(t, manifest, ref, offlinePrivate)
	if _, err := verifyManifest(t.Context(), encoded, pre, fixture, fixedNow); !errors.Is(err, ErrAuthorityUntrusted) {
		t.Fatalf("unconfigured offline root error = %v", err)
	}
	fixture.offline[ref] = offlinePublic
	verified, err := verifyManifest(t.Context(), encoded, pre, fixture, fixedNow)
	if err != nil {
		t.Fatalf("offline root verify: %v", err)
	}
	snapshot := withRevocation(withHead(pre, verified), verified, encoded)
	snapshot.Revision = 2
	runtime, err := NewRuntime(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	signer := SignerIdentity{KeyID: "root", Generation: 1}
	if decision := runtime.DecideLease(signer, fixedNow); !decision.Allowed || decision.Reason != ReasonAllowed {
		t.Fatalf("pre-effective decision = %#v", decision)
	}
	for name, decide := range map[string]func() Decision{
		"lease":         func() Decision { return runtime.DecideLease(signer, fixedNow.Add(time.Minute)) },
		"policy":        func() Decision { return runtime.DecidePolicy(signer, fixedNow.Add(time.Minute)) },
		"release":       func() Decision { return runtime.DecideRelease(signer, fixedNow.Add(time.Minute)) },
		"upgrade grant": func() Decision { return runtime.DecideUpgradeGrant(signer, fixedNow.Add(24*time.Hour)) },
	} {
		t.Run(name, func(t *testing.T) {
			decision := decide()
			if decision.Allowed || decision.Reason != ReasonSignerRevoked {
				t.Fatalf("decision = %#v", decision)
			}
		})
	}
	if decision := runtime.DecideLease(SignerIdentity{KeyID: "root", Generation: 2}, fixedNow.Add(time.Hour)); decision.Allowed || decision.Reason != ReasonSignerIdentityUntrusted {
		t.Fatalf("generation mismatch decision = %#v", decision)
	}

	lineageRef := AuthorityRef{Kind: AuthorityLineage, KeyID: "root", Generation: 1}
	lineageEncoded := signManifest(t, testManifest(1, nil, nil, "root", 1), lineageRef, fixture.privateKeys["root"])
	if _, err := verifyManifest(t.Context(), lineageEncoded, pre, fixture, fixedNow); !errors.Is(err, ErrAuthorityGeneration) {
		t.Fatalf("non-current lineage signer error = %v", err)
	}
	self := testManifest(1, nil, nil, "current", 2)
	selfEncoded := signManifest(t, self, AuthorityRef{Kind: AuthorityLineage, KeyID: "current", Generation: 2},
		fixture.privateKeys["current"])
	if _, err := verifyManifest(t.Context(), selfEncoded, pre, fixture, fixedNow); !errors.Is(err, ErrAuthorityGeneration) {
		t.Fatalf("same-generation authority error = %v", err)
	}
}

func TestRuntimeReplaceIsWholeSnapshot(t *testing.T) {
	fixture := makeTrustFixture(t, "root", "current")
	first := fixture.snapshot(t)
	first.Revision = 1
	runtime, err := NewRuntime(first)
	if err != nil {
		t.Fatal(err)
	}
	manifest := testManifest(1, nil, nil, "root", 1)
	encoded := signManifest(t, manifest, AuthorityRef{Kind: AuthorityLineage, KeyID: "current", Generation: 2},
		fixture.privateKeys["current"])
	verified, err := verifyManifest(t.Context(), encoded, first, fixture, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	second := withRevocation(withHead(first, verified), verified, encoded)
	second.Revision = 2
	if err := runtime.Replace(second); err != nil {
		t.Fatal(err)
	}
	loaded, ok := runtime.Snapshot()
	if !ok || loaded.Revision != 2 || loaded.RevocationHead.Sequence != 1 || len(loaded.Revocations) != 1 {
		t.Fatalf("runtime snapshot = %#v", loaded)
	}
}

type trustFixture struct {
	body        []byte
	pins        []entitlementguard.VerificationKey
	privateKeys map[string]ed25519.PrivateKey
	offline     map[AuthorityRef]ed25519.PublicKey
}

func (fixture trustFixture) KeysetPins(context.Context) ([]entitlementguard.VerificationKey, error) {
	return fixture.pins, nil
}

func (fixture trustFixture) OfflineRoot(_ context.Context, ref AuthorityRef) (ed25519.PublicKey, error) {
	key := fixture.offline[ref]
	if len(key) == 0 {
		return nil, ErrAuthorityUntrusted
	}
	return key, nil
}

func (fixture trustFixture) snapshot(t *testing.T) Snapshot {
	t.Helper()
	verified, err := entitlementsync.VerifyPublicKeyset(fixture.body, fixture.pins, nil, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	return Snapshot{Revision: 1, Keyset: verified, KeysetETag: strongETag(fixture.body),
		KeysetPayload: fixture.body, AcceptedAt: fixedNow}
}

type testKeysetWire struct {
	Schema      string             `json:"schema"`
	ActiveKeyID string             `json:"active_key_id"`
	Keys        []testKeyWire      `json:"keys"`
	Rotations   []testRotationWire `json:"rotations"`
}

type testKeyWire struct {
	KeyID       string  `json:"key_id"`
	Algorithm   string  `json:"algorithm"`
	PublicKey   string  `json:"public_key"`
	Fingerprint string  `json:"fingerprint"`
	Status      string  `json:"status"`
	NotBefore   string  `json:"not_before"`
	SignUntil   *string `json:"sign_until,omitempty"`
}

type testRotationWire struct {
	RotationID             string `json:"rotation_id"`
	NewKeyID               string `json:"new_key_id"`
	AuthorizedByKeyID      string `json:"authorized_by_key_id"`
	ChallengeDocument      string `json:"challenge_document"`
	PoPSignature           string `json:"pop_signature"`
	PoPVerifiedAt          string `json:"pop_verified_at"`
	AuthorizationDocument  string `json:"authorization_document"`
	AuthorizationSignature string `json:"authorization_signature"`
	AuthorizedAt           string `json:"authorized_at"`
	AuthorizationExpiresAt string `json:"authorization_expires_at"`
	ActivatedAt            string `json:"activated_at"`
}

type testPoPDocument struct {
	Domain               string  `json:"domain"`
	RotationID           string  `json:"rotation_id"`
	NewKeyID             string  `json:"new_key_id"`
	PublicKeyFingerprint string  `json:"public_key_fingerprint"`
	NotBefore            string  `json:"not_before"`
	SignUntil            string  `json:"sign_until"`
	VerifyUntil          *string `json:"verify_until"`
	Nonce                string  `json:"nonce"`
	ChallengeExpiresAt   string  `json:"challenge_expires_at"`
}

type testAuthorizationDocument struct {
	Domain                 string  `json:"domain"`
	RotationID             string  `json:"rotation_id"`
	OldKeyID               string  `json:"old_key_id"`
	NewKeyID               string  `json:"new_key_id"`
	PublicKeyFingerprint   string  `json:"public_key_fingerprint"`
	NotBefore              string  `json:"not_before"`
	SignUntil              string  `json:"sign_until"`
	VerifyUntil            *string `json:"verify_until"`
	AuthorizedAt           string  `json:"authorized_at"`
	AuthorizationExpiresAt string  `json:"authorization_expires_at"`
}

func makeTrustFixture(t *testing.T, keyIDs ...string) trustFixture {
	t.Helper()
	base := fixedNow.Add(-6 * time.Hour)
	privateKeys := make(map[string]ed25519.PrivateKey, len(keyIDs))
	publicKeys := make(map[string]ed25519.PublicKey, len(keyIDs))
	wire := testKeysetWire{Schema: "cdnca.signing-keyset/v2", ActiveKeyID: keyIDs[len(keyIDs)-1],
		Keys: make([]testKeyWire, 0, len(keyIDs)), Rotations: make([]testRotationWire, 0, len(keyIDs)-1)}
	for index, keyID := range keyIDs {
		publicKey, privateKey := deterministicKey(keyID)
		privateKeys[keyID], publicKeys[keyID] = privateKey, publicKey
		fingerprint := sha256.Sum256(publicKey)
		status := "verify_only"
		if index == len(keyIDs)-1 {
			status = "active"
		}
		var signUntil *string
		if index > 0 {
			value := base.Add(time.Duration(index)*time.Hour + 30*24*time.Hour).Format(time.RFC3339Nano)
			signUntil = &value
		}
		wire.Keys = append(wire.Keys, testKeyWire{KeyID: keyID, Algorithm: entitlement.Algorithm,
			PublicKey:   base64.RawURLEncoding.EncodeToString(publicKey),
			Fingerprint: base64.RawURLEncoding.EncodeToString(fingerprint[:]), Status: status,
			NotBefore: base.Add(time.Duration(index) * time.Hour).Format(time.RFC3339Nano), SignUntil: signUntil})
	}
	for index := 1; index < len(keyIDs); index++ {
		oldKeyID, newKeyID := keyIDs[index-1], keyIDs[index]
		newKey := wire.Keys[index]
		rotationID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(oldKeyID+"->"+newKeyID)).String()
		authorizedAt := base.Add(time.Duration(index)*time.Hour + 5*time.Minute)
		expiresAt := authorizedAt.Add(24 * time.Hour)
		nonce := sha256.Sum256([]byte(rotationID))
		challenge := testPoPDocument{Domain: "cdnca.signing-key-rotation-pop/v1", RotationID: rotationID,
			NewKeyID: newKeyID, PublicKeyFingerprint: newKey.Fingerprint, NotBefore: newKey.NotBefore,
			SignUntil: *newKey.SignUntil, Nonce: base64.RawURLEncoding.EncodeToString(nonce[:]),
			ChallengeExpiresAt: authorizedAt.Add(10 * time.Minute).Format(time.RFC3339Nano)}
		authorization := testAuthorizationDocument{Domain: "cdnca.signing-key-rotation-authorization/v1",
			RotationID: rotationID, OldKeyID: oldKeyID, NewKeyID: newKeyID,
			PublicKeyFingerprint: newKey.Fingerprint, NotBefore: newKey.NotBefore, SignUntil: *newKey.SignUntil,
			AuthorizedAt:           authorizedAt.Format(time.RFC3339Nano),
			AuthorizationExpiresAt: expiresAt.Format(time.RFC3339Nano)}
		challengeBytes, _ := json.Marshal(challenge)
		authorizationBytes, _ := json.Marshal(authorization)
		wire.Rotations = append(wire.Rotations, testRotationWire{RotationID: rotationID, NewKeyID: newKeyID,
			AuthorizedByKeyID: oldKeyID, ChallengeDocument: base64.RawURLEncoding.EncodeToString(challengeBytes),
			PoPSignature:           base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKeys[newKeyID], challengeBytes)),
			PoPVerifiedAt:          authorizedAt.Format(time.RFC3339Nano),
			AuthorizationDocument:  base64.RawURLEncoding.EncodeToString(authorizationBytes),
			AuthorizationSignature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKeys[oldKeyID], authorizationBytes)),
			AuthorizedAt:           authorizedAt.Format(time.RFC3339Nano), AuthorizationExpiresAt: expiresAt.Format(time.RFC3339Nano),
			ActivatedAt: authorizedAt.Add(time.Minute).Format(time.RFC3339Nano)})
	}
	body, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	return trustFixture{body: body, pins: []entitlementguard.VerificationKey{{KeyID: keyIDs[0],
		PublicKey: publicKeys[keyIDs[0]]}}, privateKeys: privateKeys, offline: make(map[AuthorityRef]ed25519.PublicKey)}
}

func deterministicKey(id string) (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := sha256.Sum256([]byte("signer-revocation-test:" + id))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	return privateKey.Public().(ed25519.PublicKey), privateKey
}

func testManifest(sequence uint64, previous *uint64, previousDigest *string, keyID string, generation uint64) Manifest {
	return Manifest{Schema: ManifestSchema, Sequence: sequence, PreviousSequence: previous,
		PreviousManifestSHA256: previousDigest, RevokedKeyID: keyID, RevokedKeyGeneration: generation,
		ArtifactClasses:    []ArtifactClass{ArtifactLease, ArtifactPolicy, ArtifactRelease},
		EffectiveNotBefore: canonicalTime(fixedNow), Reason: reasonCompromise,
		IssuedAt: canonicalTime(fixedNow), ExpiresAt: canonicalTime(fixedNow.Add(time.Hour))}
}

func signManifest(t *testing.T, manifest Manifest, authority AuthorityRef, privateKey ed25519.PrivateKey) []byte {
	t.Helper()
	canonical, err := CanonicalManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	envelope := Envelope{Schema: EnvelopeSchema, Algorithm: Algorithm, AuthorityKind: authority.Kind,
		AuthorityKeyID: authority.KeyID, AuthorityKeyGeneration: authority.Generation,
		ManifestSHA256: encodeDigest(digest)}
	canonicalEnvelope, _ := CanonicalEnvelope(envelope)
	encoded, err := Encode(SignedManifest{Manifest: manifest, Envelope: envelope,
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, canonicalEnvelope))})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func withHead(snapshot Snapshot, verified verifiedManifest) Snapshot {
	snapshot.RevocationHead = ChainState{Sequence: verified.signed.Manifest.Sequence,
		ManifestSHA256: encodeDigest(verified.digest)}
	return snapshot
}

func withRevocation(snapshot Snapshot, verified verifiedManifest, encoded []byte) Snapshot {
	snapshot.RevocationETag = strongETag(encoded)
	snapshot.Revocations = append(snapshot.Revocations, manifestRevocation(verified, snapshot.RevocationETag, encoded))
	return snapshot
}

func TestCanonicalManifestMatchesProducerContract(t *testing.T) {
	encoded, err := CanonicalManifest(testManifest(1, nil, nil, "root", 1))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"schema":"cdnca.signer-revocation-manifest/v1"`)) ||
		bytes.HasSuffix(encoded, []byte("\n")) {
		t.Fatalf("canonical manifest = %q", encoded)
	}
}

var _ DecisionSource = (*Runtime)(nil)
var _ SnapshotSource = (*Store)(nil)
