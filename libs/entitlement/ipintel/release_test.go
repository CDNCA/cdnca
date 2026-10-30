package ipintel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"
)

type testSigner struct {
	id      string
	private ed25519.PrivateKey
}

func (signer testSigner) KeyID() string { return signer.id }
func (signer testSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(signer.private, payload), nil
}

type testTrust map[string]ed25519.PublicKey

func (trust testTrust) VerifyDetached(keyID string, payload, signature []byte, _, _ time.Time) error {
	key, ok := trust[keyID]
	if !ok {
		return errors.New("unknown key")
	}
	if !ed25519.Verify(key, payload, signature) {
		return errors.New("bad signature")
	}
	return nil
}

func testKey(t *testing.T, seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	return private.Public().(ed25519.PublicKey), private
}

func signedSample(t *testing.T) (Artifact, SignedRelease, ed25519.PublicKey) {
	t.Helper()
	artifact := buildSample(t, sampleFacts(), testSources())
	public, private := testKey(t, 7)
	release, err := NewRelease(artifact)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := Sign(context.Background(), release, testSigner{id: "license-test-key", private: private}, testGeneratedAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	return artifact, signed, public
}

func TestReleaseSignVerifyRoundTrip(t *testing.T) {
	artifact, signed, public := signedSample(t)
	if err := VerifyEd25519(signed, public); err != nil {
		t.Fatalf("self check: %v", err)
	}
	encoded, err := signed.Encode()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeSignedRelease(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	trust := testTrust{"license-test-key": public}
	if err := Verify(decoded, trust, testGeneratedAt.Add(time.Hour)); err != nil {
		t.Fatalf("verify: %v", err)
	}
	table, err := VerifyArtifact(decoded.Release, artifact.Bytes)
	if err != nil {
		t.Fatalf("verify artifact: %v", err)
	}
	if table.Metadata.Revision != 7 || decoded.Release.Counts != table.Metadata.Counts ||
		decoded.Release.CapabilityVersion != CapabilityVersion || decoded.Release.Capability != "IP_INTEL" {
		t.Fatalf("release = %+v", decoded.Release)
	}
	if decoded.Release.SourceRelease != "ipx-0123456789abcdef01234567" || decoded.Release.DataUpdatedAt != testGeneratedAt.Add(-time.Hour).Unix() ||
		!decoded.Release.Fresh(testGeneratedAt.Add(29*24*time.Hour)) || decoded.Release.Fresh(testGeneratedAt.Add(30*24*time.Hour)) {
		t.Fatalf("freshness fields = %+v", decoded.Release)
	}
	// Signing is deterministic (Ed25519) so equal inputs give an equal envelope.
	_, again, _ := signedSample(t)
	againEncoded, _ := again.Encode()
	if !bytes.Equal(encoded, againEncoded) {
		t.Fatal("signed release is not deterministic")
	}
}

func TestReleaseRejectsTamperingAndUnknownKeys(t *testing.T) {
	artifact, signed, public := signedSample(t)
	trust := testTrust{"license-test-key": public}
	now := testGeneratedAt.Add(time.Hour)
	tampered := signed
	tampered.Release.Revision++
	if err := Verify(tampered, trust, now); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tampered revision: %v", err)
	}
	tampered = signed
	tampered.Release.StaleAfter += 86400
	if err := Verify(tampered, trust, now); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tampered stale_after: %v", err)
	}
	tampered = signed
	tampered.Release.ArtifactSHA256 = strings.Repeat("0", 64)
	if err := Verify(tampered, trust, now); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tampered digest: %v", err)
	}
	otherPublic, _ := testKey(t, 9)
	if err := Verify(signed, testTrust{"license-test-key": otherPublic}, now); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("wrong key: %v", err)
	}
	if err := Verify(signed, testTrust{}, now); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("unknown key: %v", err)
	}
	if err := Verify(signed, trust, testGeneratedAt.Add(-time.Hour)); !errors.Is(err, ErrInvalidRelease) {
		t.Fatalf("future signed_at: %v", err)
	}
	// Artifact bytes must be exactly what the release describes.
	changed := bytes.Clone(artifact.Bytes)
	changed[len(changed)-3] ^= 1
	if _, err := VerifyArtifact(signed.Release, changed); !errors.Is(err, ErrArtifactMismatch) {
		t.Fatalf("changed artifact: %v", err)
	}
	if _, err := VerifyArtifact(signed.Release, artifact.Bytes[:len(artifact.Bytes)-1]); !errors.Is(err, ErrArtifactMismatch) {
		t.Fatalf("short artifact: %v", err)
	}
	other := buildSample(t, sampleFacts()[:3], testSources())
	if _, err := VerifyArtifact(signed.Release, other.Bytes); !errors.Is(err, ErrArtifactMismatch) {
		t.Fatalf("other artifact: %v", err)
	}
}

func TestDecodeSignedReleaseIsStrict(t *testing.T) {
	_, signed, _ := signedSample(t)
	encoded, _ := signed.Encode()
	for name, input := range map[string][]byte{
		"unknown field": bytes.Replace(encoded, []byte(`{"release":`), []byte(`{"extra":1,"release":`), 1),
		"duplicate key": bytes.Replace(encoded, []byte(`"signature":`), []byte(`"signature":"x","signature":`), 1),
		"whitespace":    append([]byte(" "), encoded...),
		"two documents": append(append([]byte(nil), encoded...), encoded...),
		"bad schema":    bytes.Replace(encoded, []byte(ReleaseSchema), []byte("cdnca.ip-intel.release/v1"), 1),
		"bad domain":    bytes.Replace(encoded, []byte(SignatureDomain), []byte("cdnca-security-rule-catalog-signature/v1"), 1),
	} {
		if _, err := DecodeSignedRelease(input); !errors.Is(err, ErrInvalidRelease) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}
