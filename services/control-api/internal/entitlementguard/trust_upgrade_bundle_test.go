package entitlementguard

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
)

func TestTrustStoreVerifiesCanonicalUpgradePlanArtifactBundle(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize))
	signer := bundleTrustTestSigner{privateKey: privateKey}
	signed := signedTrustTestBundle(t, now, signer)
	encoded, err := signed.Encode()
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewTrustStore([]VerificationKey{{KeyID: signer.KeyID(), PublicKey: privateKey.Public().(ed25519.PublicKey)}})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := store.VerifyUpgradePlanArtifactBundle(encoded, entitlement.UpgradePlanArtifactBundleVerifyOptions{
		Now: now.Add(time.Minute), ExpectedAudience: entitlement.UpgradePlanArtifactBundleAudience,
		ExpectedInstallationID: signed.Bundle.InstallationID, ExpectedPlanID: signed.Bundle.PlanID,
		ExpectedInitialPlanRevision: 1,
	})
	if err != nil || verified != signed.Bundle {
		t.Fatalf("VerifyUpgradePlanArtifactBundle() = (%#v, %v)", verified, err)
	}

	tampered := append([]byte(nil), encoded...)
	tampered[len(tampered)-2] ^= 1
	if _, err := store.VerifyUpgradePlanArtifactBundle(tampered, entitlement.UpgradePlanArtifactBundleVerifyOptions{
		Now: now.Add(time.Minute), ExpectedAudience: entitlement.UpgradePlanArtifactBundleAudience,
		ExpectedInstallationID: signed.Bundle.InstallationID, ExpectedPlanID: signed.Bundle.PlanID,
		ExpectedInitialPlanRevision: 1,
	}); !errors.Is(err, entitlement.ErrInvalidUpgradePlanArtifactBundleEnvelope) {
		t.Fatalf("tampered bundle error = %v", err)
	}
}

type bundleTrustTestSigner struct{ privateKey ed25519.PrivateKey }

func (bundleTrustTestSigner) KeyID() string { return "license-release-1" }

func (signer bundleTrustTestSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(signer.privateKey, payload), nil
}

func signedTrustTestBundle(t *testing.T, now time.Time, signer bundleTrustTestSigner) entitlement.SignedUpgradePlanArtifactBundle {
	t.Helper()
	manifest := func(id, version string, digestByte byte, sequence uint64) entitlement.UpgradePlanArtifact {
		body := entitlement.ArtifactManifestV2{
			Schema: entitlement.ArtifactManifestV3Schema, Audience: entitlement.ArtifactManifestAudience,
			Purpose: entitlement.ArtifactManifestPurpose, ArtifactID: id, Component: "control-api", Version: version,
			ProtocolMin: 1, ProtocolMax: 3, ArtifactSizeBytes: 4096, ReleaseSequence: sequence,
			DigestAlgorithm: "sha256", SHA256Digest: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{digestByte}, 32)),
			DownloadURL: "https://releases.example.invalid/control-api/" + version,
		}
		signature, err := entitlement.SignArtifactManifestV3(t.Context(), body, signer)
		if err != nil {
			t.Fatal(err)
		}
		return entitlement.UpgradePlanArtifact{Manifest: body, SignatureAlgorithm: entitlement.Algorithm,
			SignatureKeyID: signer.KeyID(), ManifestSignature: base64.RawURLEncoding.EncodeToString(signature)}
	}
	bundle := entitlement.UpgradePlanArtifactBundle{
		Schema: entitlement.UpgradePlanArtifactBundleV2Schema, Audience: entitlement.UpgradePlanArtifactBundleAudience,
		Purpose: entitlement.UpgradePlanArtifactBundlePurpose, BundleID: "00000000-0000-4000-8000-000000000001",
		PlanID: "00000000-0000-4000-8000-000000000002", InitialPlanRevision: 1,
		ParentGrantID:       "00000000-0000-4000-8000-000000000003",
		ParentGrantSHA256:   base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, 32)),
		ParentGrantIssuedAt: now.Add(-time.Minute).Unix(), ParentGrantExpiresAt: now.Add(48 * time.Hour).Unix(),
		CustomerID:     "00000000-0000-4000-8000-000000000004",
		InstallationID: "00000000-0000-4000-8000-000000000005",
		LicenseID:      "00000000-0000-4000-8000-000000000006", Channel: "stable", ChannelRevision: 7,
		Component: "control-api", CurrentVersion: "1.4.0", Version: "1.5.0", ProtocolVersion: 2,
		Forward:  manifest("00000000-0000-4000-8000-000000000007", "1.5.0", 0x51, 42),
		Rollback: manifest("00000000-0000-4000-8000-000000000008", "1.4.0", 0x52, 41),
		IssuedAt: now.Unix(), CommandIssuanceNotAfter: now.Add(24 * time.Hour).Unix(),
	}
	signed, err := entitlement.SignUpgradePlanArtifactBundle(t.Context(), bundle, signer)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}
