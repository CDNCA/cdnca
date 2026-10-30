package signercheckpoint

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/google/uuid"
)

type goldenContract struct {
	Schema              string          `json:"schema"`
	CanonicalCheckpoint json.RawMessage `json:"canonical_checkpoint"`
	CanonicalEnvelope   json.RawMessage `json:"canonical_envelope"`
	Signed              json.RawMessage `json:"signed"`
	CheckpointSHA256    string          `json:"checkpoint_sha256"`
	Signature           string          `json:"signature"`
}

type testTrust struct {
	pins  []entitlementguard.VerificationKey
	roots map[AuthorityRef]ed25519.PublicKey
}

func (trust testTrust) KeysetPins(context.Context) ([]entitlementguard.VerificationKey, error) {
	return trust.pins, nil
}
func (trust testTrust) OfflineRoot(_ context.Context, ref AuthorityRef) (ed25519.PublicKey, error) {
	key := trust.roots[ref]
	if len(key) == 0 {
		return nil, ErrAuthorityUntrusted
	}
	return key, nil
}

func readGolden(t *testing.T) goldenContract {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	encoded, err := os.ReadFile(filepath.Join(filepath.Dir(file), "../../../../tests/contracts/signer-revocation-checkpoint-v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture goldenContract
	if err := json.Unmarshal(encoded, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func goldenSigned(t *testing.T, fixture goldenContract) SignedCheckpoint {
	t.Helper()
	var signed SignedCheckpoint
	if err := json.Unmarshal(fixture.Signed, &signed); err != nil {
		t.Fatal(err)
	}
	return signed
}

func goldenTrust(t *testing.T, signed SignedCheckpoint) (testTrust, ed25519.PrivateKey) {
	t.Helper()
	var keyset struct {
		Keys []struct {
			KeyID     string `json:"key_id"`
			PublicKey string `json:"public_key"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(signed.Checkpoint.Keyset, &keyset); err != nil {
		t.Fatal(err)
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(keyset.Keys[0].PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	seed := sha256.Sum256([]byte("cdnca-checkpoint-golden-offline-root"))
	private := ed25519.NewKeyFromSeed(seed[:])
	ref := AuthorityRef{Kind: AuthorityOfflineRoot, KeyID: "offline-root", Generation: 7}
	return testTrust{pins: []entitlementguard.VerificationKey{{KeyID: keyset.Keys[0].KeyID, PublicKey: publicKey}}, roots: map[AuthorityRef]ed25519.PublicKey{ref: private.Public().(ed25519.PublicKey)}}, private
}

func signCheckpoint(t *testing.T, checkpoint Checkpoint, ref AuthorityRef, private ed25519.PrivateKey) []byte {
	t.Helper()
	canonical, err := CanonicalCheckpoint(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	envelope := Envelope{Schema: EnvelopeSchema, Algorithm: Algorithm, AuthorityKind: ref.Kind, AuthorityKeyID: ref.KeyID,
		AuthorityKeyGeneration: ref.Generation, CheckpointSHA256: encodeDigest(digest)}
	envelopeBytes, err := CanonicalEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := Encode(SignedCheckpoint{Checkpoint: checkpoint, Envelope: envelope,
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, envelopeBytes))})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func cloneCheckpoint(t *testing.T, source Checkpoint) Checkpoint {
	t.Helper()
	encoded, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	var copy Checkpoint
	if err := json.Unmarshal(encoded, &copy); err != nil {
		t.Fatal(err)
	}
	return copy
}

func TestGoldenCanonicalWireAndFreshOuterExpiredInner(t *testing.T) {
	fixture := readGolden(t)
	if fixture.Schema != CheckpointSchema {
		t.Fatalf("fixture schema = %q", fixture.Schema)
	}
	signed := goldenSigned(t, fixture)
	canonical, err := CanonicalCheckpoint(signed.Checkpoint)
	if err != nil || !bytes.Equal(canonical, fixture.CanonicalCheckpoint) {
		t.Fatalf("canonical checkpoint drift: %v\n%s\nwant:\n%s", err, canonical, fixture.CanonicalCheckpoint)
	}
	envelope, err := CanonicalEnvelope(signed.Envelope)
	if err != nil || !bytes.Equal(envelope, fixture.CanonicalEnvelope) {
		t.Fatalf("canonical envelope drift: %v\n%s\nwant:\n%s", err, envelope, fixture.CanonicalEnvelope)
	}
	trust, _ := goldenTrust(t, signed)
	now := time.Date(2026, 7, 23, 1, 10, 0, 123456000, time.UTC)
	projection, err := VerifyCandidate(context.Background(), fixture.Signed, Snapshot{}, trust, now)
	if err != nil {
		t.Fatal(err)
	}
	if projection.Snapshot.Revision != 1 || projection.Snapshot.HeadSequence != 1 || projection.Replayed {
		t.Fatalf("projection = %#v", projection)
	}
	replay, err := VerifyCandidate(context.Background(), fixture.Signed, projection.Snapshot, trust, now)
	if err != nil || !replay.Replayed {
		t.Fatalf("replay = %#v, err=%v", replay, err)
	}

	// The inner v1 expiry is deliberately in the past. Only the fresh outer
	// checkpoint permits this historical import.
	expired := cloneCheckpoint(t, signed.Checkpoint)
	expired.Manifests[0].Manifest.IssuedAt = "2026-07-23T00:02:03.123456Z"
	expired.Manifests[0].Manifest.EffectiveNotBefore = "2026-07-23T00:02:03.123456Z"
	expired.Manifests[0].Manifest.ExpiresAt = "2026-07-23T00:03:03.123456Z"
	innerCanonical, _ := CanonicalManifest(expired.Manifests[0].Manifest)
	innerDigest := sha256.Sum256(innerCanonical)
	expired.Manifests[0].Envelope.ManifestSHA256 = encodeDigest(innerDigest)
	innerEnvelope, _ := CanonicalManifestEnvelope(expired.Manifests[0].Envelope)
	_, private := goldenTrust(t, signed)
	expired.Manifests[0].Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, innerEnvelope))
	expired.HeadManifestSHA256 = encodeDigest(innerDigest)
	expiredBytes := signCheckpoint(t, expired, AuthorityRef{Kind: AuthorityOfflineRoot, KeyID: "offline-root", Generation: 7}, private)
	if _, err := VerifyCandidate(context.Background(), expiredBytes, Snapshot{}, trust, now); err != nil {
		t.Fatalf("expired inner import = %v", err)
	}
}

func TestRevisionPrefixReplayRenewalRollbackAndTamper(t *testing.T) {
	fixture := readGolden(t)
	signed := goldenSigned(t, fixture)
	trust, private := goldenTrust(t, signed)
	now := time.Date(2026, 7, 23, 1, 10, 0, 123456000, time.UTC)
	first, err := VerifyCandidate(context.Background(), fixture.Signed, Snapshot{}, trust, now)
	if err != nil {
		t.Fatal(err)
	}
	next := cloneCheckpoint(t, signed.Checkpoint)
	next.Revision = 2
	previousDigest := first.Snapshot.CheckpointSHA256
	next.PreviousRevision = uint64Ptr(1)
	next.PreviousCheckpointSHA256 = stringPtr(previousDigest)
	next.ExpiresAt = "2026-07-23T01:16:00.123456Z"
	nextBytes := signCheckpoint(t, next, AuthorityRef{Kind: AuthorityOfflineRoot, KeyID: "offline-root", Generation: 7}, private)
	second, err := VerifyCandidate(context.Background(), nextBytes, first.Snapshot, trust, now)
	if err != nil || second.Snapshot.Revision != 2 || second.Snapshot.HeadSequence != 1 {
		t.Fatalf("same-head renewal = %#v, err=%v", second, err)
	}
	if _, err := VerifyCandidate(context.Background(), fixture.Signed, second.Snapshot, trust, now); !errors.Is(err, ErrRevisionRollback) {
		t.Fatalf("rollback error = %v", err)
	}
	conflict := cloneCheckpoint(t, signed.Checkpoint)
	conflict.ExpiresAt = "2026-07-23T01:16:00.123456Z"
	conflictBytes := signCheckpoint(t, conflict, AuthorityRef{Kind: AuthorityOfflineRoot, KeyID: "offline-root", Generation: 7}, private)
	if _, err := VerifyCandidate(context.Background(), conflictBytes, first.Snapshot, trust, now); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("same revision conflict error = %v", err)
	}
	wrongPrevious := cloneCheckpoint(t, next)
	wrongDigest := sha256.Sum256([]byte("wrong previous checkpoint"))
	wrongPrevious.PreviousCheckpointSHA256 = stringPtr(encodeDigest(wrongDigest))
	wrongPreviousBytes := signCheckpoint(t, wrongPrevious, AuthorityRef{Kind: AuthorityOfflineRoot, KeyID: "offline-root", Generation: 7}, private)
	if projection, err := VerifyCandidate(context.Background(), wrongPreviousBytes, first.Snapshot, trust, now); err != nil ||
		projection.Snapshot.Revision != 2 {
		t.Fatalf("fresh complete checkpoint with unobserved outer predecessor = (%#v, %v)", projection, err)
	}
	headRollback := cloneCheckpoint(t, next)
	headRollback.Revision = 3
	headRollback.PreviousRevision = uint64Ptr(2)
	headRollback.PreviousCheckpointSHA256 = stringPtr(second.Snapshot.CheckpointSHA256)
	headRollback.HeadSequence, headRollback.HeadManifestSHA256, headRollback.Manifests = 0, "", []SignedSignerRevocationManifest{}
	headRollbackBytes := signCheckpoint(t, headRollback, AuthorityRef{Kind: AuthorityOfflineRoot, KeyID: "offline-root", Generation: 7}, private)
	if _, err := VerifyCandidate(context.Background(), headRollbackBytes, second.Snapshot, trust, now); !errors.Is(err, ErrRevisionRollback) {
		t.Fatalf("head rollback error = %v", err)
	}
	gap := cloneCheckpoint(t, next)
	gap.Revision = 4
	gap.PreviousRevision = uint64Ptr(3)
	gapBytes := signCheckpoint(t, gap, AuthorityRef{Kind: AuthorityOfflineRoot, KeyID: "offline-root", Generation: 7}, private)
	if projection, err := VerifyCandidate(context.Background(), gapBytes, first.Snapshot, trust, now); err != nil ||
		projection.Snapshot.Revision != 4 {
		t.Fatalf("revision gap checkpoint = (%#v, %v)", projection, err)
	}
	fork := cloneCheckpoint(t, next)
	fork.Manifests[0].Manifest.RevokedKeyID = "other-key"
	resignInner(t, &fork.Manifests[0], private)
	fork.HeadManifestSHA256 = manifestDigest(t, fork.Manifests[0].Manifest)
	forkBytes := signCheckpoint(t, fork, AuthorityRef{Kind: AuthorityOfflineRoot, KeyID: "offline-root", Generation: 7}, private)
	if _, err := VerifyCandidate(context.Background(), forkBytes, first.Snapshot, trust, now); !errors.Is(err, ErrPrefixFork) {
		t.Fatalf("prefix fork error = %v", err)
	}
	badInner := cloneCheckpoint(t, signed.Checkpoint)
	badInner.Manifests[0].Signature = strings.Repeat("A", 86)
	badInnerBytes := signCheckpoint(t, badInner, AuthorityRef{Kind: AuthorityOfflineRoot, KeyID: "offline-root", Generation: 7}, private)
	if _, err := VerifyCandidate(context.Background(), badInnerBytes, Snapshot{}, trust, now); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("inner signature error = %v", err)
	}
	for _, candidate := range [][]byte{[]byte(" " + string(fixture.Signed)), append(append([]byte(nil), fixture.Signed...), []byte("{}")...)} {
		if _, err := VerifyCandidate(context.Background(), candidate, Snapshot{}, trust, now); !errors.Is(err, ErrInvalidCheckpoint) {
			t.Fatalf("noncanonical error = %v", err)
		}
	}
	duplicate := bytes.Replace(fixture.Signed, []byte(`"revision":1`), []byte(`"revision":1,"revision":1`), 1)
	if _, err := VerifyCandidate(context.Background(), duplicate, Snapshot{}, trust, now); !errors.Is(err, ErrInvalidCheckpoint) {
		t.Fatalf("duplicate field error = %v", err)
	}
}

func TestRevisionCanBootstrapOrAdvanceAcrossPublicationGaps(t *testing.T) {
	fixture := readGolden(t)
	signed := goldenSigned(t, fixture)
	trust, private := goldenTrust(t, signed)
	now := time.Date(2026, 7, 23, 1, 10, 0, 123456000, time.UTC)

	bootstrap := cloneCheckpoint(t, signed.Checkpoint)
	bootstrap.Revision = 5
	bootstrap.PreviousRevision = uint64Ptr(4)
	previousDigest := sha256.Sum256([]byte("unobserved checkpoint revision 4"))
	bootstrap.PreviousCheckpointSHA256 = stringPtr(encodeDigest(previousDigest))
	bootstrapBytes := signCheckpoint(t, bootstrap,
		AuthorityRef{Kind: AuthorityOfflineRoot, KeyID: "offline-root", Generation: 7}, private)
	first, err := VerifyCandidate(context.Background(), bootstrapBytes, Snapshot{}, trust, now)
	if err != nil || first.Snapshot.Revision != 5 {
		t.Fatalf("revision 5 bootstrap = (%#v, %v)", first, err)
	}

	successor := cloneCheckpoint(t, signed.Checkpoint)
	successor.Revision = 9
	successor.PreviousRevision = uint64Ptr(8)
	previousDigest = sha256.Sum256([]byte("unobserved checkpoint revision 8"))
	successor.PreviousCheckpointSHA256 = stringPtr(encodeDigest(previousDigest))
	successor.ExpiresAt = "2026-07-23T01:16:00.123456Z"
	successorBytes := signCheckpoint(t, successor,
		AuthorityRef{Kind: AuthorityOfflineRoot, KeyID: "offline-root", Generation: 7}, private)
	next, err := VerifyCandidate(context.Background(), successorBytes, first.Snapshot, trust, now)
	if err != nil || next.Snapshot.Revision != 9 || next.Snapshot.HeadSequence != first.Snapshot.HeadSequence {
		t.Fatalf("revision 5 to 9 = (%#v, %v)", next, err)
	}
}

func TestOuterFreshnessAuthorityAndHeadZero(t *testing.T) {
	fixture := readGolden(t)
	signed := goldenSigned(t, fixture)
	trust, private := goldenTrust(t, signed)
	now := time.Date(2026, 7, 23, 1, 10, 0, 123456000, time.UTC)
	for name, mutate := range map[string]func(*Checkpoint){
		"expired": func(cp *Checkpoint) { cp.ExpiresAt = "2026-07-23T01:09:00.123456Z" },
		"future":  func(cp *Checkpoint) { cp.IssuedAt = "2026-07-23T01:11:00.123456Z" },
		"ttl":     func(cp *Checkpoint) { cp.ExpiresAt = "2026-08-24T01:02:03.123456Z" }, // > MaxOfflineCheckpointTTL
	} {
		t.Run(name, func(t *testing.T) {
			candidate := cloneCheckpoint(t, signed.Checkpoint)
			mutate(&candidate)
			encoded := signCheckpoint(t, candidate, AuthorityRef{Kind: AuthorityOfflineRoot, KeyID: "offline-root", Generation: 7}, private)
			_, err := VerifyCandidate(context.Background(), encoded, Snapshot{}, trust, now)
			if name == "ttl" {
				if !errors.Is(err, ErrTTLExceeded) {
					t.Fatalf("error = %v", err)
				}
			} else if !errors.Is(err, ErrCheckpointNotCurrent) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	wrongSigned := signed
	wrongSigned.Envelope.AuthorityKind = AuthorityLineage
	wrong, err := json.Marshal(wrongSigned)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(wrong); !errors.Is(err, ErrWrongAuthority) {
		t.Fatalf("wrong outer authority error = %v", err)
	}
	badOuter := signed
	badOuter.Signature = strings.Repeat("A", 86)
	badOuterBytes, err := json.Marshal(badOuter)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCandidate(context.Background(), badOuterBytes, Snapshot{}, trust, now); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("outer signature error = %v", err)
	}
	zero := cloneCheckpoint(t, signed.Checkpoint)
	zero.HeadSequence, zero.HeadManifestSHA256, zero.Manifests = 0, "", []SignedSignerRevocationManifest{}
	zeroBytes := signCheckpoint(t, zero, AuthorityRef{Kind: AuthorityOfflineRoot, KeyID: "offline-root", Generation: 7}, private)
	if projection, err := VerifyCandidate(context.Background(), zeroBytes, Snapshot{}, trust, now); err != nil || projection.Snapshot.HeadSequence != 0 {
		t.Fatalf("head zero = %#v, err=%v", projection, err)
	}
	nullManifests := bytes.Replace(zeroBytes, []byte(`"manifests":[]`), []byte(`"manifests":null`), 1)
	if _, err := VerifyCandidate(context.Background(), nullManifests, Snapshot{}, trust, now); !errors.Is(err, ErrInvalidCheckpoint) {
		t.Fatalf("head zero null manifests error = %v", err)
	}
	revisionOnePrevious := cloneCheckpoint(t, signed.Checkpoint)
	revisionOnePrevious.PreviousRevision = uint64Ptr(1)
	if _, err := CanonicalCheckpoint(revisionOnePrevious); !errors.Is(err, ErrInvalidCheckpoint) {
		t.Fatalf("revision one previous pointer error = %v", err)
	}
	revisionTwoMissing := cloneCheckpoint(t, signed.Checkpoint)
	revisionTwoMissing.Revision = 2
	if _, err := CanonicalCheckpoint(revisionTwoMissing); !errors.Is(err, ErrInvalidCheckpoint) {
		t.Fatalf("revision two missing previous pointer error = %v", err)
	}
	revisionTwoWrong := cloneCheckpoint(t, signed.Checkpoint)
	revisionTwoWrong.Revision = 2
	revisionTwoWrong.PreviousRevision = uint64Ptr(3)
	revisionTwoWrong.PreviousCheckpointSHA256 = stringPtr(signed.Envelope.CheckpointSHA256)
	if _, err := CanonicalCheckpoint(revisionTwoWrong); !errors.Is(err, ErrInvalidCheckpoint) {
		t.Fatalf("revision two wrong previous pointer error = %v", err)
	}
}

func TestSameHeadKeysetExtension(t *testing.T) {
	fixture := readGolden(t)
	signed := goldenSigned(t, fixture)
	trust, rootPrivate := goldenTrust(t, signed)
	now := time.Date(2026, 7, 23, 1, 10, 0, 123456000, time.UTC)
	first, err := VerifyCandidate(context.Background(), fixture.Signed, Snapshot{}, trust, now)
	if err != nil {
		t.Fatal(err)
	}
	extended := extensionKeyset(t, signed.Checkpoint.Keyset, rootPrivate)
	next := cloneCheckpoint(t, signed.Checkpoint)
	next.Revision = 2
	next.PreviousRevision = uint64Ptr(1)
	next.PreviousCheckpointSHA256 = stringPtr(first.Snapshot.CheckpointSHA256)
	next.Keyset = extended
	digest := sha256.Sum256(extended)
	next.KeysetSHA256 = encodeDigest(digest)
	next.ExpiresAt = "2026-07-23T01:16:00.123456Z"
	encoded := signCheckpoint(t, next, AuthorityRef{Kind: AuthorityOfflineRoot, KeyID: "offline-root", Generation: 7}, rootPrivate)
	projection, err := VerifyCandidate(context.Background(), encoded, first.Snapshot, trust, now)
	if err != nil || projection.Snapshot.Revision != 2 || projection.Snapshot.HeadSequence != first.Snapshot.HeadSequence {
		t.Fatalf("keyset extension = %#v, err=%v", projection, err)
	}
	rollback := cloneCheckpoint(t, next)
	rollback.Revision = 3
	rollback.PreviousRevision = uint64Ptr(2)
	rollback.PreviousCheckpointSHA256 = stringPtr(projection.Snapshot.CheckpointSHA256)
	rollback.Keyset = append([]byte(nil), signed.Checkpoint.Keyset...)
	rollbackDigest := sha256.Sum256(rollback.Keyset)
	rollback.KeysetSHA256 = encodeDigest(rollbackDigest)
	rollbackBytes := signCheckpoint(t, rollback, AuthorityRef{Kind: AuthorityOfflineRoot, KeyID: "offline-root", Generation: 7}, rootPrivate)
	if _, err := VerifyCandidate(context.Background(), rollbackBytes, projection.Snapshot, trust, now); !errors.Is(err, ErrKeysetRollback) {
		t.Fatalf("keyset rollback error = %v", err)
	}
	tampered := cloneCheckpoint(t, signed.Checkpoint)
	tampered.Keyset = bytes.Replace(tampered.Keyset, []byte(`"public_key":"GQH`), []byte(`"public_key":"AQH`), 1)
	tamperedDigest := sha256.Sum256(tampered.Keyset)
	tampered.KeysetSHA256 = encodeDigest(tamperedDigest)
	tamperedBytes := signCheckpoint(t, tampered, AuthorityRef{Kind: AuthorityOfflineRoot, KeyID: "offline-root", Generation: 7}, rootPrivate)
	if _, err := VerifyCandidate(context.Background(), tamperedBytes, Snapshot{}, trust, now); !errors.Is(err, ErrInvalidKeyset) {
		t.Fatalf("tampered keyset error = %v", err)
	}
}

func TestProjectionDeepCopiesMutableValues(t *testing.T) {
	fixture := readGolden(t)
	signed := goldenSigned(t, fixture)
	trust, private := goldenTrust(t, signed)
	now := time.Date(2026, 7, 23, 1, 10, 0, 123456000, time.UTC)
	first, err := VerifyCandidate(context.Background(), fixture.Signed, Snapshot{}, trust, now)
	if err != nil {
		t.Fatal(err)
	}
	candidate := checkpointWithTwoManifests(t, signed.Checkpoint, private)
	candidate.Revision = 2
	candidate.PreviousRevision = uint64Ptr(first.Snapshot.Revision)
	candidate.PreviousCheckpointSHA256 = stringPtr(first.Snapshot.CheckpointSHA256)
	encoded := signCheckpoint(t, candidate, AuthorityRef{Kind: AuthorityOfflineRoot, KeyID: "offline-root", Generation: 7}, private)
	projection, err := VerifyCandidate(context.Background(), encoded, first.Snapshot, trust, now)
	if err != nil {
		t.Fatal(err)
	}
	if &projection.Signed.Checkpoint.Keyset[0] == &projection.Snapshot.KeysetPayload[0] ||
		&projection.Signed.Checkpoint.Manifests[0].Manifest.ArtifactClasses[0] == &projection.Snapshot.Manifests[0].Manifest.ArtifactClasses[0] ||
		projection.Signed.Checkpoint.PreviousRevision == candidate.PreviousRevision ||
		projection.Signed.Checkpoint.PreviousCheckpointSHA256 == candidate.PreviousCheckpointSHA256 ||
		projection.Signed.Checkpoint.Manifests[1].Manifest.PreviousSequence == candidate.Manifests[1].Manifest.PreviousSequence ||
		projection.Signed.Checkpoint.Manifests[1].Manifest.PreviousManifestSHA256 == candidate.Manifests[1].Manifest.PreviousManifestSHA256 ||
		projection.Signed.Checkpoint.Manifests[1].Manifest.PreviousSequence == projection.Snapshot.Manifests[1].Manifest.PreviousSequence ||
		projection.Signed.Checkpoint.Manifests[1].Manifest.PreviousManifestSHA256 == projection.Snapshot.Manifests[1].Manifest.PreviousManifestSHA256 {
		t.Fatal("projection retained mutable aliases")
	}
	signedArtifact := projection.Signed.Checkpoint.Manifests[0].Manifest.ArtifactClasses[0]
	signedPrevious := *projection.Signed.Checkpoint.Manifests[1].Manifest.PreviousSequence
	candidatePreviousRevision := *candidate.PreviousRevision
	candidatePreviousDigest := *candidate.PreviousCheckpointSHA256
	candidateManifestPreviousDigest := *candidate.Manifests[1].Manifest.PreviousManifestSHA256
	signedKeyset := append([]byte(nil), projection.Signed.Checkpoint.Keyset...)
	projection.Signed.Checkpoint.Keyset[0] ^= 0xff
	projection.Signed.Checkpoint.Manifests[0].Manifest.ArtifactClasses[0] = ArtifactClass("policy")
	*projection.Signed.Checkpoint.PreviousRevision = 77
	*projection.Signed.Checkpoint.PreviousCheckpointSHA256 = "signed checkpoint digest"
	*projection.Signed.Checkpoint.Manifests[1].Manifest.PreviousSequence = 77
	*projection.Signed.Checkpoint.Manifests[1].Manifest.PreviousManifestSHA256 = "signed manifest digest"
	if bytes.Equal(projection.Signed.Checkpoint.Keyset, projection.Snapshot.KeysetPayload) ||
		projection.Snapshot.Manifests[0].Manifest.ArtifactClasses[0] != signedArtifact ||
		*projection.Snapshot.Manifests[1].Manifest.PreviousSequence != signedPrevious ||
		*candidate.PreviousRevision != candidatePreviousRevision ||
		*candidate.PreviousCheckpointSHA256 != candidatePreviousDigest ||
		*candidate.Manifests[1].Manifest.PreviousManifestSHA256 != candidateManifestPreviousDigest {
		t.Fatal("snapshot changed after signed projection mutation")
	}
	projection.Snapshot.KeysetPayload[0] ^= 0x01
	projection.Snapshot.Manifests[0].Manifest.ArtifactClasses[0] = ArtifactClass("release")
	*projection.Snapshot.Manifests[1].Manifest.PreviousSequence = 88
	*projection.Snapshot.Manifests[1].Manifest.PreviousManifestSHA256 = "snapshot manifest digest"
	*candidate.PreviousRevision = 88
	*candidate.PreviousCheckpointSHA256 = "candidate checkpoint digest"
	*candidate.Manifests[1].Manifest.PreviousManifestSHA256 = "candidate manifest digest"
	if bytes.Equal(signedKeyset, projection.Snapshot.KeysetPayload) ||
		bytes.Equal(projection.Signed.Checkpoint.Keyset, projection.Snapshot.KeysetPayload) ||
		projection.Signed.Checkpoint.Manifests[0].Manifest.ArtifactClasses[0] != ArtifactClass("policy") ||
		*projection.Signed.Checkpoint.Manifests[1].Manifest.PreviousSequence != 77 ||
		*projection.Signed.Checkpoint.PreviousRevision != 77 ||
		*projection.Signed.Checkpoint.PreviousCheckpointSHA256 != "signed checkpoint digest" ||
		*projection.Signed.Checkpoint.Manifests[1].Manifest.PreviousManifestSHA256 != "signed manifest digest" {
		t.Fatal("signed projection changed after snapshot mutation")
	}
}

func checkpointWithTwoManifests(t *testing.T, checkpoint Checkpoint, private ed25519.PrivateKey) Checkpoint {
	t.Helper()
	checkpoint = cloneCheckpoint(t, checkpoint)
	second := checkpoint.Manifests[0]
	second.Manifest.Sequence = 2
	previousSequence := uint64(1)
	previousDigest := checkpoint.HeadManifestSHA256
	second.Manifest.PreviousSequence = &previousSequence
	second.Manifest.PreviousManifestSHA256 = &previousDigest
	resignInner(t, &second, private)
	checkpoint.Manifests = append(checkpoint.Manifests, second)
	checkpoint.HeadSequence = 2
	checkpoint.HeadManifestSHA256 = manifestDigest(t, second.Manifest)
	return checkpoint
}

func TestLineageSigningAndVerificationWindows(t *testing.T) {
	fixture := readGolden(t)
	signed := goldenSigned(t, fixture)
	trust, rootPrivate := goldenTrust(t, signed)
	leafSeed := sha256.Sum256([]byte("cdnca-checkpoint-extension-leaf"))
	leafPrivate := ed25519.NewKeyFromSeed(leafSeed[:])
	keyNotBefore := time.Date(2026, 7, 22, 2, 0, 0, 0, time.UTC)
	lineageNotBefore := keyNotBefore.Add(6 * time.Minute)
	signUntil := keyNotBefore.Add(24 * time.Hour)
	verifyUntil := signUntil.Add(time.Hour)
	outerNow := signUntil.Add(time.Minute)

	for name, testCase := range map[string]struct {
		issued       time.Time
		now          time.Time
		verifyWindow bool
		wantErr      error
	}{
		"not-before-boundary":   {issued: lineageNotBefore, now: outerNow},
		"before-not-before":     {issued: lineageNotBefore.Add(-time.Microsecond), now: outerNow, wantErr: ErrAuthorityGeneration},
		"before-sign-until":     {issued: signUntil.Add(-time.Microsecond), now: outerNow},
		"sign-until-boundary":   {issued: signUntil, now: outerNow, wantErr: ErrAuthorityGeneration},
		"before-verify-until":   {issued: signUntil.Add(-time.Minute), now: verifyUntil.Add(-time.Microsecond), verifyWindow: true},
		"verify-until-boundary": {issued: signUntil.Add(-time.Minute), now: verifyUntil, verifyWindow: true, wantErr: ErrAuthorityGeneration},
	} {
		t.Run(name, func(t *testing.T) {
			keyset := extensionKeyset(t, signed.Checkpoint.Keyset, rootPrivate)
			if testCase.verifyWindow {
				keyset = extensionKeysetWithVerifyUntil(t, signed.Checkpoint.Keyset, rootPrivate, &verifyUntil)
			}
			candidate := cloneCheckpoint(t, signed.Checkpoint)
			candidate.Keyset = keyset
			keysetDigest := sha256.Sum256(keyset)
			candidate.KeysetSHA256 = encodeDigest(keysetDigest)
			candidate.Manifests[0].Manifest.IssuedAt = testCase.issued.Format(time.RFC3339Nano)
			candidate.Manifests[0].Manifest.EffectiveNotBefore = candidate.Manifests[0].Manifest.IssuedAt
			candidate.Manifests[0].Manifest.ExpiresAt = testCase.issued.Add(time.Hour).Format(time.RFC3339Nano)
			candidate.Manifests[0].Envelope.AuthorityKind = AuthorityLineage
			candidate.Manifests[0].Envelope.AuthorityKeyID = "checkpoint-leaf"
			candidate.Manifests[0].Envelope.AuthorityKeyGeneration = 2
			resignInner(t, &candidate.Manifests[0], leafPrivate)
			candidate.HeadManifestSHA256 = manifestDigest(t, candidate.Manifests[0].Manifest)
			candidate.IssuedAt = testCase.now.Add(-time.Minute).Format(time.RFC3339Nano)
			candidate.ExpiresAt = testCase.now.Add(14 * time.Minute).Format(time.RFC3339Nano)
			encoded := signCheckpoint(t, candidate, AuthorityRef{Kind: AuthorityOfflineRoot, KeyID: "offline-root", Generation: 7}, rootPrivate)
			_, err := VerifyCandidate(context.Background(), encoded, Snapshot{}, trust, testCase.now)
			if testCase.wantErr == nil {
				if err != nil {
					t.Fatalf("verification error = %v", err)
				}
			} else if !errors.Is(err, testCase.wantErr) {
				t.Fatalf("verification error = %v, want %v", err, testCase.wantErr)
			}
		})
	}
}

func extensionKeyset(t *testing.T, previous []byte, rootPrivate ed25519.PrivateKey) []byte {
	return extensionKeysetWithVerifyUntil(t, previous, rootPrivate, nil)
}

func extensionKeysetWithVerifyUntil(t *testing.T, previous []byte, rootPrivate ed25519.PrivateKey, verifyUntil *time.Time) []byte {
	t.Helper()
	var old struct {
		Keys []struct {
			KeyID     string `json:"key_id"`
			PublicKey string `json:"public_key"`
			NotBefore string `json:"not_before"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(previous, &old); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 7, 22, 0, 0, 0, 0, time.UTC)
	leafSeed := sha256.Sum256([]byte("cdnca-checkpoint-extension-leaf"))
	leafPrivate := ed25519.NewKeyFromSeed(leafSeed[:])
	leafPublic := leafPrivate.Public().(ed25519.PublicKey)
	fingerprint := sha256.Sum256(leafPublic)
	leafNotBefore := base.Add(2 * time.Hour)
	signUntil := leafNotBefore.Add(24 * time.Hour)
	authorizedAt := leafNotBefore.Add(5 * time.Minute)
	authorizationExpiresAt := authorizedAt.Add(24 * time.Hour)
	rotationID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("offline-root->checkpoint-leaf"))
	nonceDigest := sha256.Sum256([]byte(rotationID.String()))
	nonce := base64.RawURLEncoding.EncodeToString(nonceDigest[:])
	notBefore := leafNotBefore.Format(time.RFC3339Nano)
	signUntilText := signUntil.Format(time.RFC3339Nano)
	authorizedAtText := authorizedAt.Format(time.RFC3339Nano)
	authorizationExpiresText := authorizationExpiresAt.Format(time.RFC3339Nano)
	var verifyUntilText *string
	if verifyUntil != nil {
		value := verifyUntil.Format(time.RFC3339Nano)
		verifyUntilText = &value
	}
	challenge := struct {
		Domain               string  `json:"domain"`
		RotationID           string  `json:"rotation_id"`
		NewKeyID             string  `json:"new_key_id"`
		PublicKeyFingerprint string  `json:"public_key_fingerprint"`
		NotBefore            string  `json:"not_before"`
		SignUntil            string  `json:"sign_until"`
		VerifyUntil          *string `json:"verify_until"`
		Nonce                string  `json:"nonce"`
		ChallengeExpiresAt   string  `json:"challenge_expires_at"`
	}{"cdnca.signing-key-rotation-pop/v1", rotationID.String(), "checkpoint-leaf", base64.RawURLEncoding.EncodeToString(fingerprint[:]), notBefore, signUntilText, verifyUntilText, nonce, authorizedAt.Add(10 * time.Minute).Format(time.RFC3339Nano)}
	authorization := struct {
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
	}{"cdnca.signing-key-rotation-authorization/v1", rotationID.String(), "offline-root", "checkpoint-leaf", base64.RawURLEncoding.EncodeToString(fingerprint[:]), notBefore, signUntilText, verifyUntilText, authorizedAtText, authorizationExpiresText}
	challengeBytes, _ := json.Marshal(challenge)
	authorizationBytes, _ := json.Marshal(authorization)
	rotation := struct {
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
	}{rotationID.String(), "checkpoint-leaf", "offline-root", base64.RawURLEncoding.EncodeToString(challengeBytes), base64.RawURLEncoding.EncodeToString(ed25519.Sign(leafPrivate, challengeBytes)), authorizedAt.Add(time.Minute).Format(time.RFC3339Nano), base64.RawURLEncoding.EncodeToString(authorizationBytes), base64.RawURLEncoding.EncodeToString(ed25519.Sign(rootPrivate, authorizationBytes)), authorizedAtText, authorizationExpiresText, authorizedAt.Add(time.Minute).Format(time.RFC3339Nano)}
	rootPublic, _ := base64.RawURLEncoding.DecodeString(old.Keys[0].PublicKey)
	rootFingerprint := sha256.Sum256(rootPublic)
	wire := struct {
		Schema      string `json:"schema"`
		ActiveKeyID string `json:"active_key_id"`
		Keys        []struct {
			KeyID       string  `json:"key_id"`
			Algorithm   string  `json:"algorithm"`
			PublicKey   string  `json:"public_key"`
			Fingerprint string  `json:"fingerprint"`
			Status      string  `json:"status"`
			NotBefore   string  `json:"not_before"`
			SignUntil   *string `json:"sign_until,omitempty"`
			VerifyUntil *string `json:"verify_until,omitempty"`
		} `json:"keys"`
		Rotations []struct {
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
		} `json:"rotations"`
	}{Schema: "cdnca.signing-keyset/v2", ActiveKeyID: "checkpoint-leaf"}
	rootNotBefore := old.Keys[0].NotBefore
	wire.Keys = append(wire.Keys, struct {
		KeyID       string  `json:"key_id"`
		Algorithm   string  `json:"algorithm"`
		PublicKey   string  `json:"public_key"`
		Fingerprint string  `json:"fingerprint"`
		Status      string  `json:"status"`
		NotBefore   string  `json:"not_before"`
		SignUntil   *string `json:"sign_until,omitempty"`
		VerifyUntil *string `json:"verify_until,omitempty"`
	}{"offline-root", Algorithm, base64.RawURLEncoding.EncodeToString(rootPublic), base64.RawURLEncoding.EncodeToString(rootFingerprint[:]), "verify_only", rootNotBefore, nil, nil})
	wire.Keys = append(wire.Keys, struct {
		KeyID       string  `json:"key_id"`
		Algorithm   string  `json:"algorithm"`
		PublicKey   string  `json:"public_key"`
		Fingerprint string  `json:"fingerprint"`
		Status      string  `json:"status"`
		NotBefore   string  `json:"not_before"`
		SignUntil   *string `json:"sign_until,omitempty"`
		VerifyUntil *string `json:"verify_until,omitempty"`
	}{"checkpoint-leaf", Algorithm, base64.RawURLEncoding.EncodeToString(leafPublic), base64.RawURLEncoding.EncodeToString(fingerprint[:]), "active", notBefore, &signUntilText, verifyUntilText})
	wire.Rotations = append(wire.Rotations, rotation)
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func uint64Ptr(value uint64) *uint64 { return &value }
func stringPtr(value string) *string { return &value }

func manifestDigest(t *testing.T, manifest Manifest) string {
	t.Helper()
	canonical, err := CanonicalManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	return encodeDigest(digest)
}

func resignInner(t *testing.T, signed *SignedSignerRevocationManifest, private ed25519.PrivateKey) {
	t.Helper()
	signed.Envelope.ManifestSHA256 = manifestDigest(t, signed.Manifest)
	envelope, err := CanonicalManifestEnvelope(signed.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	signed.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, envelope))
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte("{}"))
	f.Add([]byte(strings.Repeat("x", MaxCheckpointBytes+1)))
	f.Fuzz(func(t *testing.T, input []byte) { _, _ = Decode(input) })
}
