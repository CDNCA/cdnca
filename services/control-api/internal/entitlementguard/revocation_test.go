package entitlementguard

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
)

type revocationTestSigner struct {
	id      string
	private ed25519.PrivateKey
}

func (signer revocationTestSigner) KeyID() string { return signer.id }

func (signer revocationTestSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(signer.private, payload), nil
}

func TestVerifyRevocationArtifactAndProvenance(t *testing.T) {
	issuedAt := time.Unix(1_900_000_000, 0).UTC()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifyUntil := issuedAt.Add(24 * time.Hour)
	trust := mustTrustStore(t, VerificationKey{KeyID: "revocation-key-1", PublicKey: publicKey,
		NotBefore: issuedAt.Add(-time.Hour), SignUntil: &verifyUntil, VerifyUntil: &verifyUntil})
	body := entitlement.RevocationSet{
		Schema: entitlement.RevocationSetSchemaV2, Audience: entitlement.RevocationSetAudience,
		CustomerID:     "11111111-1111-4111-8111-111111111111",
		InstallationID: "22222222-2222-4222-8222-222222222222",
		LicenseID:      "33333333-3333-4333-8333-333333333333", Revision: 7,
		IssuedAt: issuedAt.Unix(), ExpiresAt: issuedAt.Add(entitlement.RevocationSetWindow).Unix(),
		RevokedSerials: []uint64{2, 9, 101},
	}
	signed, err := entitlement.SignRevocationSet(t.Context(), body,
		revocationTestSigner{id: "revocation-key-1", private: privateKey}, entitlement.RevocationKeyWindow{
			NotBefore: issuedAt.Add(-time.Hour), SignUntil: &verifyUntil, VerifyUntil: &verifyUntil,
		})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := signed.Encode()
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := verifyRevocationArtifact(trust, artifact, issuedAt.Add(time.Second),
		body.CustomerID, body.InstallationID, body.LicenseID)
	if err != nil {
		t.Fatalf("verifyRevocationArtifact() error = %v", err)
	}
	if snapshot.Revision != body.Revision || snapshot.KeyID != signed.KeyID ||
		snapshot.ArtifactSHA256 != entitlement.RevocationSetDigest(artifact) ||
		snapshot.ETag != entitlement.RevocationSetETag(artifact) ||
		!snapshot.IssuedAt.Equal(issuedAt) || !snapshot.ExpiresAt.Equal(issuedAt.Add(entitlement.RevocationSetWindow)) ||
		len(snapshot.RevokedSerials) != 3 || snapshot.RevokedSerials[2] != 101 {
		t.Fatalf("verified snapshot = %#v", snapshot)
	}
	if _, err := verifyRevocationArtifact(trust, artifact, bodyTime(body).Add(entitlement.RevocationSetWindow),
		body.CustomerID, body.InstallationID, body.LicenseID); !errors.Is(err, ErrRevocationExpired) {
		t.Fatalf("expired artifact error = %v", err)
	}
	if _, err := verifyRevocationArtifact(trust, artifact, issuedAt.Add(time.Second),
		body.CustomerID, body.InstallationID, "44444444-4444-4444-8444-444444444444"); !errors.Is(err, ErrRevocationInvalid) {
		t.Fatalf("license mismatch error = %v", err)
	}

	// The install script provisions root signing pins before a keyset LKG exists;
	// those pins intentionally have no lifecycle window. The initial signed
	// revocation artifact must still be accepted against that trust anchor.
	rootPinnedTrust := mustTrustStore(t, VerificationKey{KeyID: "revocation-key-1", PublicKey: publicKey})
	if _, err := verifyRevocationArtifact(rootPinnedTrust, artifact, issuedAt.Add(time.Second),
		body.CustomerID, body.InstallationID, body.LicenseID); err != nil {
		t.Fatalf("root-pinned revocation artifact was rejected: %v", err)
	}
}

func TestValidateRevocationAdvanceIsMonotonicAndSuperset(t *testing.T) {
	issuedAt := time.Unix(1_900_000_000, 0).UTC()
	base := RevocationSnapshot{
		InstallationID: "22222222-2222-4222-8222-222222222222",
		CustomerID:     "11111111-1111-4111-8111-111111111111",
		LicenseID:      "33333333-3333-4333-8333-333333333333",
		Revision:       7, KeyID: "revocation-key-1", Artifact: []byte("seven"),
		ArtifactSHA256: [32]byte{7}, ETag: `"sha256-seven"`, IssuedAt: issuedAt,
		ExpiresAt: issuedAt.Add(entitlement.RevocationSetWindow), RevokedSerials: []uint64{2, 9},
	}
	exact := cloneRevocationSnapshot(base)
	if replay, err := validateRevocationAdvance(&base, exact); err != nil || !replay {
		t.Fatalf("exact replay = (%v, %v)", replay, err)
	}
	higher := cloneRevocationSnapshot(base)
	higher.Revision++
	higher.Artifact = []byte("eight")
	higher.ArtifactSHA256 = [32]byte{8}
	higher.ETag = `"sha256-eight"`
	higher.IssuedAt = base.IssuedAt.Add(time.Minute)
	higher.ExpiresAt = base.ExpiresAt.Add(time.Minute)
	higher.RevokedSerials = []uint64{2, 9, 10}
	if replay, err := validateRevocationAdvance(&base, higher); err != nil || replay {
		t.Fatalf("higher superset = (%v, %v)", replay, err)
	}

	conflict := cloneRevocationSnapshot(base)
	conflict.ArtifactSHA256 = [32]byte{99}
	if _, err := validateRevocationAdvance(&base, conflict); !errors.Is(err, ErrRevocationConflict) {
		t.Fatalf("same revision conflict error = %v", err)
	}
	lower := cloneRevocationSnapshot(base)
	lower.Revision--
	if _, err := validateRevocationAdvance(&base, lower); !errors.Is(err, ErrRevocationRollback) {
		t.Fatalf("lower revision error = %v", err)
	}
	shrink := cloneRevocationSnapshot(higher)
	shrink.RevokedSerials = []uint64{2, 10}
	if _, err := validateRevocationAdvance(&base, shrink); !errors.Is(err, ErrRevocationShrink) {
		t.Fatalf("shrinking set error = %v", err)
	}
	otherLicense := cloneRevocationSnapshot(higher)
	otherLicense.LicenseID = "44444444-4444-4444-8444-444444444444"
	if _, err := validateRevocationAdvance(&base, otherLicense); !errors.Is(err, ErrRevocationInvalid) {
		t.Fatalf("binding change error = %v", err)
	}
}

func TestRevocationSnapshotCurrentUsesExactExpiry(t *testing.T) {
	issuedAt := time.Unix(1_900_000_000, 0).UTC()
	snapshot := RevocationSnapshot{Revision: 1, IssuedAt: issuedAt,
		ExpiresAt: issuedAt.Add(entitlement.RevocationSetWindow), Artifact: []byte("artifact")}
	if err := snapshot.requireCurrent(snapshot.ExpiresAt.Add(-time.Nanosecond)); err != nil {
		t.Fatalf("pre-expiry current error = %v", err)
	}
	if err := snapshot.requireCurrent(snapshot.ExpiresAt); !errors.Is(err, ErrRevocationExpired) {
		t.Fatalf("exact expiry error = %v", err)
	}
}

func TestRevocationDenialReasonsAreStable(t *testing.T) {
	tests := []struct {
		err    error
		want   error
		reason string
	}{
		{ErrRevocationUnavailable, ErrRevocationUnavailable, "revocation_state_unavailable"},
		{ErrRevocationExpired, ErrRevocationExpired, "revocation_state_expired"},
		{ErrRevocationInvalid, ErrRevocationInvalid, "revocation_state_invalid"},
	}
	for _, test := range tests {
		denial, reason := revocationDenial(test.err)
		if !errors.Is(denial, test.want) || reason != test.reason || !IsDenial(denial) {
			t.Fatalf("revocationDenial(%v) = (%v, %q)", test.err, denial, reason)
		}
	}
}

func bodyTime(body entitlement.RevocationSet) time.Time {
	return time.Unix(body.IssuedAt, 0).UTC()
}
