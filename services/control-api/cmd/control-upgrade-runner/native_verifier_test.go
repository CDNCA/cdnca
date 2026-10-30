package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgrade"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/google/uuid"
)

func TestNativeVerifierTracksLiveVersionAndOnlyResumesExactDurablePlan(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	installationID := uuid.NewString()
	signer := nativeVerifierSigner{ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))}
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{KeyID: signer.KeyID(), PublicKey: signer.private.Public().(ed25519.PublicKey)}})
	if err != nil {
		t.Fatal(err)
	}
	store, err := controlplaneupgrade.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	status := controlplaneupgrade.NativeStandaloneStatus{Ready: true, Reason: "ready", Phase: "idle",
		InstallationID: installationID, ProtocolVersion: 2, ArtifactFormat: controlplaneupgrade.NativeManifestSchema, CurrentVersion: "1.4.0"}
	runner := nativeVerifierRunner{probe: func(context.Context) (controlplaneupgrade.NativeStandaloneStatus, error) { return status, nil }}
	verify := newNativePlanVerifier(t.Context(), trust, installationID, 2, store, runner, func() time.Time { return now })
	first := nativeSignedPlan(t, signer, installationID, "1.4.0", "1.5.0", 42, now)
	if err := verify(first); err != nil {
		t.Fatalf("first version rejected: %v", err)
	}
	status.CurrentVersion = "1.5.0"
	second := nativeSignedPlan(t, signer, installationID, "1.5.0", "1.6.0", 43, now)
	if err := verify(second); err != nil {
		t.Fatalf("next plan still pinned to startup version: %v", err)
	}
	if err := verify(first); err == nil {
		t.Fatal("new plan with outdated current version accepted")
	}
	status.Ready, status.Busy, status.Phase = false, true, "draining"
	if err := verify(second); err == nil {
		t.Fatal("new plan accepted during drain")
	}
	signed, err := entitlement.DecodeUpgradePlanArtifactBundle(first)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(controlplaneupgrade.State{Schema: controlplaneupgrade.StateSchema, PlanID: signed.Bundle.PlanID,
		BundleSHA256: fmt.Sprintf("%x", sha256.Sum256(first)), Sequence: 42, Phase: controlplaneupgrade.PhaseDrained}); err != nil {
		t.Fatal(err)
	}
	if err := verify(first); err != nil {
		t.Fatalf("exact durable drain recovery rejected: %v", err)
	}
	if err := verify(append(append([]byte{}, first...), '\n')); err == nil {
		t.Fatal("different raw bundle bypassed drain")
	}
	now = now.Add(72 * time.Hour)
	if err := verify(first); err == nil {
		t.Fatal("expired authorization bypassed signature validation during recovery")
	}
}

type nativeVerifierRunner struct {
	nativeStatusStub
	probe func(context.Context) (controlplaneupgrade.NativeStandaloneStatus, error)
}

func (runner nativeVerifierRunner) Probe(ctx context.Context) (controlplaneupgrade.NativeStandaloneStatus, error) {
	return runner.probe(ctx)
}

type nativeVerifierSigner struct{ private ed25519.PrivateKey }

func (nativeVerifierSigner) KeyID() string { return "native-runner-test" }
func (signer nativeVerifierSigner) Sign(_ context.Context, value []byte) ([]byte, error) {
	return ed25519.Sign(signer.private, value), nil
}

func nativeSignedPlan(t *testing.T, signer nativeVerifierSigner, installationID, current, target string, sequence uint64, now time.Time) []byte {
	t.Helper()
	artifact := func(version string, fill byte, release uint64) entitlement.UpgradePlanArtifact {
		manifest := entitlement.ArtifactManifestV2{Schema: entitlement.ArtifactManifestV3Schema,
			Audience: entitlement.ArtifactManifestAudience, Purpose: entitlement.ArtifactManifestPurpose,
			ArtifactID: uuid.NewString(), Component: "control-api", Version: version, ProtocolMin: 1, ProtocolMax: 3,
			ArtifactSizeBytes: 4096, ReleaseSequence: release, DigestAlgorithm: "sha256",
			SHA256Digest: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 32)), DownloadURL: "https://releases.example.invalid/" + version}
		signature, err := entitlement.SignArtifactManifestV3(t.Context(), manifest, signer)
		if err != nil {
			t.Fatal(err)
		}
		return entitlement.UpgradePlanArtifact{Manifest: manifest, SignatureAlgorithm: entitlement.Algorithm,
			SignatureKeyID: signer.KeyID(), ManifestSignature: base64.RawURLEncoding.EncodeToString(signature)}
	}
	bundle := entitlement.UpgradePlanArtifactBundle{Schema: entitlement.UpgradePlanArtifactBundleV2Schema,
		Audience: entitlement.UpgradePlanArtifactBundleAudience, Purpose: entitlement.UpgradePlanArtifactBundlePurpose,
		BundleID: uuid.NewString(), PlanID: uuid.NewString(), InitialPlanRevision: 1, ParentGrantID: uuid.NewString(),
		ParentGrantSHA256:   base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, 32)),
		ParentGrantIssuedAt: now.Add(-time.Minute).Unix(), ParentGrantExpiresAt: now.Add(48 * time.Hour).Unix(),
		CustomerID: uuid.NewString(), InstallationID: installationID, LicenseID: uuid.NewString(), Channel: "stable", ChannelRevision: 7,
		Component: "control-api", CurrentVersion: current, Version: target, ProtocolVersion: 2,
		Forward: artifact(target, 0x51, sequence), Rollback: artifact(current, 0x52, sequence-1),
		IssuedAt: now.Unix(), CommandIssuanceNotAfter: now.Add(24 * time.Hour).Unix()}
	signed, err := entitlement.SignUpgradePlanArtifactBundle(t.Context(), bundle, signer)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := signed.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
