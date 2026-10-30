package controlupgrade

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
)

func TestVerifyGrantRejectsNonCanonicalWireBeforeTrustLookup(t *testing.T) {
	_, err := VerifyGrant([]byte(" {}"), entitlement.NewKeyRing(), entitlement.UpgradeGrantVerifyOptions{
		Now: time.Unix(1_800_000_000, 0), ExpectedAudience: entitlement.UpgradeGrantAudience,
		ExpectedInstallationID: "00000000-0000-4000-8000-000000000004",
	})
	if !errors.Is(err, entitlement.ErrInvalidUpgradeGrantEnvelope) {
		t.Fatalf("VerifyGrant() error = %v", err)
	}
}

func TestVerifyGrantReturnsBoundCanonicalGrant(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x51}, ed25519.SeedSize))
	publicKey := privateKey.Public().(ed25519.PublicKey)
	signer := grantTestSigner{privateKey: privateKey}
	manifest := entitlement.ArtifactManifest{
		Schema: entitlement.ArtifactManifestSchema, Audience: entitlement.ArtifactManifestAudience,
		Purpose: entitlement.ArtifactManifestPurpose, ArtifactID: "00000000-0000-4000-8000-000000000010",
		Component: "control-api", Version: "2.0.0", ProtocolMin: 1, ProtocolMax: 3,
		DigestAlgorithm: "sha256", SHA256Digest: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32)),
		DownloadURL: "https://cdn.example/releases/control-api-2.0.0",
	}
	artifactSignature, err := entitlement.SignArtifactManifest(context.Background(), manifest, signer)
	if err != nil {
		t.Fatal(err)
	}
	grant := entitlement.UpgradeGrant{
		Schema: entitlement.UpgradeGrantSchema, Audience: entitlement.UpgradeGrantAudience,
		Purpose: entitlement.UpgradeGrantPurpose, GrantID: "00000000-0000-4000-8000-000000000001",
		Nonce: "00000000-0000-4000-8000-000000000002", CustomerID: "00000000-0000-4000-8000-000000000003",
		InstallationID: "00000000-0000-4000-8000-000000000004", LicenseID: "00000000-0000-4000-8000-000000000005",
		Channel: "stable", ChannelRevision: 1, Component: manifest.Component, Operation: entitlement.UpgradeOperation,
		CurrentVersion: "1.0.0", Version: manifest.Version, ProtocolVersion: 2, ArtifactID: manifest.ArtifactID,
		ArtifactProtocolMin: manifest.ProtocolMin, ArtifactProtocolMax: manifest.ProtocolMax,
		DownloadURL: manifest.DownloadURL, DigestAlgorithm: manifest.DigestAlgorithm, SHA256Digest: manifest.SHA256Digest,
		ArtifactSignatureAlgorithm: entitlement.Algorithm, ArtifactSignatureKeyID: signer.KeyID(),
		ArtifactManifestSignature: base64.RawURLEncoding.EncodeToString(artifactSignature),
		IssuedAt:                  now.Unix(), ExpiresAt: now.Add(15 * time.Minute).Unix(),
	}
	signed, err := entitlement.SignUpgradeGrant(context.Background(), grant, signer)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := signed.Encode()
	ring := entitlement.NewKeyRing()
	_ = ring.Add(signer.KeyID(), publicKey)
	verified, err := VerifyGrant(encoded, ring, entitlement.UpgradeGrantVerifyOptions{
		Now: now.Add(time.Minute), ExpectedAudience: entitlement.UpgradeGrantAudience,
		ExpectedInstallationID: grant.InstallationID,
	})
	if err != nil || verified != grant {
		t.Fatalf("VerifyGrant() = (%#v, %v), want %#v", verified, err, grant)
	}
	options := entitlement.UpgradeGrantVerifyOptions{Now: now.Add(time.Minute),
		ExpectedAudience: entitlement.UpgradeGrantAudience, ExpectedInstallationID: grant.InstallationID}
	if _, err := VerifyGrantWithRevocation(encoded, ring, options, nil); err != nil {
		t.Fatalf("nil revocation checker = %v", err)
	}
	if _, err := VerifyGrantWithRevocation(encoded, ring, options,
		grantRevocations{entitlementguard.SignerArtifactLease: signer.KeyID()}); err != nil {
		t.Fatalf("lease-only revocation affected upgrade grant: %v", err)
	}
	if _, err := VerifyGrantWithRevocation(encoded, ring, options,
		grantRevocations{entitlementguard.SignerArtifactRelease: signer.KeyID()}); !errors.Is(err, entitlementguard.ErrSignerRevoked) {
		t.Fatalf("revoked release signer = %v, want ErrSignerRevoked", err)
	}
	tampered := append([]byte(nil), encoded...)
	tampered[len(tampered)-3] ^= 1
	checker := grantRevocations{entitlementguard.SignerArtifactRelease: signer.KeyID()}
	if _, err := VerifyGrantWithRevocation(tampered, ring, options, checker); errors.Is(err, entitlementguard.ErrSignerRevoked) {
		t.Fatal("revocation consulted before signature verification")
	}
}

type grantRevocations map[entitlementguard.SignerArtifactClass]string

func (revoked grantRevocations) CheckSignerRevocation(class entitlementguard.SignerArtifactClass, keyID string) error {
	if revoked[class] == keyID {
		return &entitlementguard.SignerRevokedError{Class: class, KeyID: keyID}
	}
	return nil
}

type grantTestSigner struct{ privateKey ed25519.PrivateKey }

func (grantTestSigner) KeyID() string { return "release-key-1" }

func (signer grantTestSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(signer.privateKey, payload), nil
}
