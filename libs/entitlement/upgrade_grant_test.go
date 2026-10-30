package entitlement

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestUpgradeGrantCanonicalSignEncodeDecodeAndVerify(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	publicKey, privateKey := upgradeGrantTestKey(1)
	manifest := validArtifactManifest()
	artifactSignature, err := SignArtifactManifest(context.Background(), manifest,
		testSigner{id: "release-key-1", private: privateKey})
	if err != nil {
		t.Fatalf("SignArtifactManifest() error = %v", err)
	}
	grant := validUpgradeGrant(now, artifactSignature)
	grant.ArtifactSignatureKeyID = "release-key-1"
	signed, err := SignUpgradeGrant(context.Background(), grant, testSigner{id: "release-key-1", private: privateKey})
	if err != nil {
		t.Fatalf("SignUpgradeGrant() error = %v", err)
	}
	repeated, err := SignUpgradeGrant(context.Background(), grant, testSigner{id: "release-key-1", private: privateKey})
	if err != nil || repeated.Signature != signed.Signature {
		t.Fatalf("repeated signature = (%q, %v), want %q", repeated.Signature, err, signed.Signature)
	}
	encoded, err := signed.Encode()
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	decoded, err := DecodeUpgradeGrant(encoded)
	if err != nil {
		t.Fatalf("DecodeUpgradeGrant() error = %v", err)
	}
	reencoded, err := decoded.Encode()
	if err != nil || !bytes.Equal(reencoded, encoded) {
		t.Fatalf("canonical roundtrip = (%q, %v), want %q", reencoded, err, encoded)
	}

	ring := NewKeyRing()
	if err := ring.Add("release-key-1", publicKey); err != nil {
		t.Fatal(err)
	}
	err = ring.VerifyUpgradeGrant(decoded, UpgradeGrantVerifyOptions{
		Now: now.Add(time.Minute), ExpectedAudience: UpgradeGrantAudience,
		ExpectedInstallationID: grant.InstallationID,
	})
	if err != nil {
		t.Fatalf("VerifyUpgradeGrant() error = %v", err)
	}
}

func TestUpgradeGrantStrictDecodeAndSemanticValidation(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	_, privateKey := upgradeGrantTestKey(2)
	manifest := validArtifactManifest()
	artifactSignature, _ := SignArtifactManifest(context.Background(), manifest,
		testSigner{id: "release-key-2", private: privateKey})
	grant := validUpgradeGrant(now, artifactSignature)
	signed, _ := SignUpgradeGrant(context.Background(), grant, testSigner{id: "release-key-2", private: privateKey})
	encoded, _ := signed.Encode()

	var object map[string]any
	if err := json.Unmarshal(encoded, &object); err != nil {
		t.Fatal(err)
	}
	object["unknown"] = true
	unknown, _ := json.Marshal(object)
	for name, candidate := range map[string][]byte{
		"leading whitespace": append([]byte(" "), encoded...),
		"trailing value":     append(append([]byte(nil), encoded...), []byte("{}")...),
		"unknown field":      unknown,
		"empty":              nil,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeUpgradeGrant(candidate); !errors.Is(err, ErrInvalidUpgradeGrantEnvelope) {
				t.Fatalf("DecodeUpgradeGrant() error = %v", err)
			}
		})
	}

	cases := []struct {
		name   string
		mutate func(*UpgradeGrant)
	}{
		{name: "noncanonical UUID", mutate: func(value *UpgradeGrant) { value.GrantID = "{00000000-0000-4000-8000-000000000001}" }},
		{name: "noncanonical semver", mutate: func(value *UpgradeGrant) { value.Version = "v2.0.0" }},
		{name: "build metadata", mutate: func(value *UpgradeGrant) { value.Version = "2.0.0+build" }},
		{name: "wrong operation", mutate: func(value *UpgradeGrant) { value.Operation = ReinstallOperation }},
		{name: "uppercase URL host", mutate: func(value *UpgradeGrant) { value.DownloadURL = "https://CDN.example/releases/control-api-2.0.0" }},
		{name: "TTL too long", mutate: func(value *UpgradeGrant) { value.ExpiresAt = value.IssuedAt + 901 }},
		{name: "noncanonical digest", mutate: func(value *UpgradeGrant) { value.SHA256Digest += "=" }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			candidate := grant
			test.mutate(&candidate)
			if err := candidate.Validate(); !errors.Is(err, ErrInvalidUpgradeGrant) {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}

func TestUpgradeGrantVerificationTypedFailures(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	publicKey, privateKey := upgradeGrantTestKey(3)
	manifest := validArtifactManifest()
	artifactSignature, _ := SignArtifactManifest(context.Background(), manifest,
		testSigner{id: "release-key-3", private: privateKey})
	grant := validUpgradeGrant(now, artifactSignature)
	signed, _ := SignUpgradeGrant(context.Background(), grant, testSigner{id: "release-key-3", private: privateKey})
	ring := NewKeyRing()
	_ = ring.Add("release-key-3", publicKey)
	base := UpgradeGrantVerifyOptions{Now: now.Add(time.Minute), ExpectedAudience: UpgradeGrantAudience,
		ExpectedInstallationID: grant.InstallationID}

	wrongAudience := base
	wrongAudience.ExpectedAudience = "another-audience"
	wrongInstallation := base
	wrongInstallation.ExpectedInstallationID = "00000000-0000-4000-8000-000000000099"
	notYetValid := base
	notYetValid.Now = now.Add(-VerifierClockSkew - time.Second)
	expired := base
	expired.Now = time.Unix(grant.ExpiresAt, 0)
	for _, test := range []struct {
		name    string
		ring    *KeyRing
		signed  SignedUpgradeGrant
		options UpgradeGrantVerifyOptions
		want    error
	}{
		{name: "nil ring", options: base, signed: signed, want: ErrUnknownUpgradeGrantKey},
		{name: "wrong audience", ring: ring, options: wrongAudience, signed: signed, want: ErrUpgradeGrantAudienceMismatch},
		{name: "wrong installation", ring: ring, options: wrongInstallation, signed: signed, want: ErrUpgradeGrantInstallationMismatch},
		{name: "not yet valid", ring: ring, options: notYetValid, signed: signed, want: ErrUpgradeGrantNotYetValid},
		{name: "expired", ring: ring, options: expired, signed: signed, want: ErrUpgradeGrantExpired},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.ring.VerifyUpgradeGrant(test.signed, test.options); !errors.Is(err, test.want) {
				t.Fatalf("VerifyUpgradeGrant() error = %v, want %v", err, test.want)
			}
		})
	}

	tamperedOuter := signed
	tamperedOuter.Grant.ChannelRevision++
	if err := ring.VerifyUpgradeGrant(tamperedOuter, base); !errors.Is(err, ErrInvalidUpgradeGrantSignature) {
		t.Fatalf("outer tamper error = %v", err)
	}
	tamperedArtifact := signed.Grant
	tamperedArtifact.ArtifactManifestSignature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	resigned, err := SignUpgradeGrant(context.Background(), tamperedArtifact,
		testSigner{id: "release-key-3", private: privateKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := ring.VerifyUpgradeGrant(resigned, base); !errors.Is(err, ErrInvalidArtifactManifestSignature) {
		t.Fatalf("artifact tamper error = %v", err)
	}
}

func TestUpgradeGrantReinstallOperation(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	_, privateKey := upgradeGrantTestKey(4)
	manifest := validArtifactManifest()
	manifest.Version = "1.0.0"
	artifactSignature, _ := SignArtifactManifest(context.Background(), manifest,
		testSigner{id: "release-key-4", private: privateKey})
	grant := validUpgradeGrant(now, artifactSignature)
	grant.CurrentVersion = grant.Version
	grant.Operation = ReinstallOperation
	if err := grant.Validate(); err != nil {
		t.Fatalf("reinstall Validate() error = %v", err)
	}
}

func TestArtifactManifestV2SignatureBindsAttestedSize(t *testing.T) {
	publicKey, privateKey := upgradeGrantTestKey(0x51)
	manifest := validArtifactManifestV2()
	signature, err := SignArtifactManifestV2(context.Background(), manifest,
		testSigner{id: "release-key-v2", private: privateKey})
	if err != nil {
		t.Fatalf("SignArtifactManifestV2() error = %v", err)
	}
	if err := VerifyArtifactManifestV2Signature(manifest, publicKey, signature); err != nil {
		t.Fatalf("VerifyArtifactManifestV2Signature() error = %v", err)
	}
	tampered := manifest
	tampered.ArtifactSizeBytes++
	if err := VerifyArtifactManifestV2Signature(tampered, publicKey, signature); !errors.Is(err, ErrInvalidArtifactManifestSignature) {
		t.Fatalf("size tamper error = %v", err)
	}
	for _, size := range []int64{0, MaxUpgradeArtifactBytes + 1} {
		candidate := manifest
		candidate.ArtifactSizeBytes = size
		if err := candidate.Validate(); !errors.Is(err, ErrInvalidArtifactManifest) {
			t.Fatalf("size %d validation error = %v", size, err)
		}
	}
}

func TestUpgradeCommandGrantCanonicalRoundTripAndVerification(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	publicKey, privateKey := upgradeGrantTestKey(0x52)
	grant := validUpgradeCommandGrant(t, now, privateKey)
	signed, err := SignUpgradeCommandGrant(context.Background(), grant,
		testSigner{id: "release-command-key", private: privateKey})
	if err != nil {
		t.Fatalf("SignUpgradeCommandGrant() error = %v", err)
	}
	encoded, err := signed.Encode()
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	wireDigest := sha256.Sum256(encoded)
	if got := hex.EncodeToString(wireDigest[:]); got != "8c0e233c29814864f0297894747db2fda85986c4f2224eceb9e657a36da9195a" {
		t.Fatalf("canonical v1 command-grant sha256 = %s", got)
	}
	decoded, err := DecodeUpgradeCommandGrant(encoded)
	if err != nil {
		t.Fatalf("DecodeUpgradeCommandGrant() error = %v", err)
	}
	reencoded, err := decoded.Encode()
	if err != nil || !bytes.Equal(reencoded, encoded) {
		t.Fatalf("canonical roundtrip = (%q, %v), want %q", reencoded, err, encoded)
	}
	ring := NewKeyRing()
	_ = ring.Add("release-command-key", publicKey)
	verified, err := ring.VerifyUpgradeCommandGrant(decoded, UpgradeCommandGrantVerifyOptions{
		Now: now.Add(time.Minute), ExpectedAudience: UpgradeCommandGrantAudience,
		ExpectedInstallationID: grant.InstallationID, ExpectedNodeID: grant.NodeID,
		ExpectedCommandID: grant.CommandID,
	})
	if err != nil || !reflect.DeepEqual(verified, grant) {
		t.Fatalf("VerifyUpgradeCommandGrant() = (%#v, %v), want %#v", verified, err, grant)
	}

	tampered := decoded
	tampered.Grant.ArtifactSizeBytes++
	if _, err := ring.VerifyUpgradeCommandGrant(tampered, UpgradeCommandGrantVerifyOptions{
		Now: now.Add(time.Minute), ExpectedAudience: UpgradeCommandGrantAudience,
		ExpectedInstallationID: grant.InstallationID, ExpectedNodeID: grant.NodeID,
		ExpectedCommandID: grant.CommandID,
	}); !errors.Is(err, ErrInvalidUpgradeCommandGrantSignature) {
		t.Fatalf("tampered command grant error = %v", err)
	}

	for name, candidate := range map[string][]byte{
		"leading whitespace": append([]byte(" "), encoded...),
		"trailing value":     append(append([]byte(nil), encoded...), []byte("{}")...),
		"duplicate field": bytes.Replace(encoded, []byte(`{"algorithm":`),
			[]byte(`{"algorithm":"Ed25519","algorithm":`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeUpgradeCommandGrant(candidate); !errors.Is(err, ErrInvalidUpgradeCommandGrantEnvelope) {
				t.Fatalf("DecodeUpgradeCommandGrant() error = %v", err)
			}
		})
	}
}

func TestUpgradeCommandGrantV2BindsPlanBundleAndUsesIndependentDomain(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	publicKey, privateKey := upgradeGrantTestKey(0x55)
	grant := validUpgradeCommandGrantV2(t, now, privateKey)
	grant.PlanRevision = 2
	signed, err := SignUpgradeCommandGrant(context.Background(), grant,
		testSigner{id: "release-command-key", private: privateKey})
	if err != nil {
		t.Fatalf("SignUpgradeCommandGrant(v2) error = %v", err)
	}
	encoded, err := signed.Encode()
	if err != nil {
		t.Fatalf("Encode(v2) error = %v", err)
	}
	for _, field := range [][]byte{[]byte(`"plan_id"`), []byte(`"plan_revision"`), []byte(`"batch_id"`),
		[]byte(`"artifact_bundle_id"`), []byte(`"artifact_bundle_sha256"`), []byte(`"command_issuance_not_after"`)} {
		if !bytes.Contains(encoded, field) {
			t.Fatalf("v2 command grant omitted %s", field)
		}
	}
	v2SigningBytes, err := signed.signingBytes()
	if err != nil || !bytes.Contains(v2SigningBytes, []byte(upgradeCommandGrantV2SignatureDomain)) ||
		bytes.Contains(v2SigningBytes, []byte(upgradeCommandGrantSignatureDomain)) {
		t.Fatalf("v2 signing domain bytes = (%q, %v)", v2SigningBytes, err)
	}

	ring := NewKeyRing()
	_ = ring.Add("release-command-key", publicKey)
	options := UpgradeCommandGrantVerifyOptions{Now: now.Add(time.Minute),
		ExpectedAudience: UpgradeCommandGrantAudience, ExpectedInstallationID: grant.InstallationID,
		ExpectedNodeID: grant.NodeID, ExpectedCommandID: grant.CommandID, ExpectedPlanID: grant.PlanID,
		ExpectedPlanRevision: grant.PlanRevision, ExpectedBatchID: grant.BatchID}
	if verified, err := ring.VerifyUpgradeCommandGrant(signed, options); err != nil || !reflect.DeepEqual(verified, grant) {
		t.Fatalf("VerifyUpgradeCommandGrant(v2) = (%#v, %v)", verified, err)
	}
	for name, mutate := range map[string]func(*UpgradeCommandGrantVerifyOptions){
		"plan": func(value *UpgradeCommandGrantVerifyOptions) {
			value.ExpectedPlanID = "00000000-0000-4000-8000-000000000099"
		},
		"revision": func(value *UpgradeCommandGrantVerifyOptions) { value.ExpectedPlanRevision++ },
		"batch": func(value *UpgradeCommandGrantVerifyOptions) {
			value.ExpectedBatchID = "00000000-0000-4000-8000-000000000098"
		},
	} {
		t.Run("wrong "+name, func(t *testing.T) {
			candidate := options
			mutate(&candidate)
			if _, err := ring.VerifyUpgradeCommandGrant(signed, candidate); !errors.Is(err, ErrUpgradeCommandGrantTargetMismatch) {
				t.Fatalf("target substitution error = %v", err)
			}
		})
	}
	tampered := signed
	tampered.Grant.PlanRevision++
	tamperedOptions := options
	tamperedOptions.ExpectedPlanRevision = tampered.Grant.PlanRevision
	if _, err := ring.VerifyUpgradeCommandGrant(tampered, tamperedOptions); !errors.Is(err, ErrInvalidUpgradeCommandGrantSignature) {
		t.Fatalf("signed plan revision substitution error = %v", err)
	}
}

func TestUpgradePlanArtifactBundleCanonicalRoundTripAndVerification(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	publicKey, privateKey := upgradeGrantTestKey(0x53)
	bundle := validUpgradePlanArtifactBundle(t, now, privateKey)
	signed, err := SignUpgradePlanArtifactBundle(context.Background(), bundle,
		testSigner{id: "release-bundle-key", private: privateKey})
	if err != nil {
		t.Fatalf("SignUpgradePlanArtifactBundle() error = %v", err)
	}
	encoded, err := signed.Encode()
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	decoded, err := DecodeUpgradePlanArtifactBundle(encoded)
	if err != nil {
		t.Fatalf("DecodeUpgradePlanArtifactBundle() error = %v", err)
	}
	reencoded, err := decoded.Encode()
	if err != nil || !bytes.Equal(reencoded, encoded) {
		t.Fatalf("canonical roundtrip = (%q, %v), want %q", reencoded, err, encoded)
	}

	ring := NewKeyRing()
	_ = ring.Add("release-bundle-key", publicKey)
	verified, err := ring.VerifyUpgradePlanArtifactBundle(decoded, UpgradePlanArtifactBundleVerifyOptions{
		Now: now.Add(time.Hour), ExpectedAudience: UpgradePlanArtifactBundleAudience,
		ExpectedInstallationID: bundle.InstallationID, ExpectedPlanID: bundle.PlanID,
		ExpectedInitialPlanRevision: bundle.InitialPlanRevision,
	})
	if err != nil || !reflect.DeepEqual(verified, bundle) {
		t.Fatalf("VerifyUpgradePlanArtifactBundle() = (%#v, %v), want %#v", verified, err, bundle)
	}

	tampered := decoded
	tampered.Bundle.Forward.Manifest.ArtifactSizeBytes++
	if _, err := ring.VerifyUpgradePlanArtifactBundle(tampered, UpgradePlanArtifactBundleVerifyOptions{
		Now: now.Add(time.Hour), ExpectedAudience: UpgradePlanArtifactBundleAudience,
		ExpectedInstallationID: bundle.InstallationID, ExpectedPlanID: bundle.PlanID,
		ExpectedInitialPlanRevision: bundle.InitialPlanRevision,
	}); !errors.Is(err, ErrInvalidUpgradePlanArtifactBundleSignature) {
		t.Fatalf("tampered bundle error = %v", err)
	}

	afterDeadline := UpgradePlanArtifactBundleVerifyOptions{Now: time.Unix(bundle.CommandIssuanceNotAfter, 0),
		ExpectedAudience: UpgradePlanArtifactBundleAudience, ExpectedInstallationID: bundle.InstallationID,
		ExpectedPlanID: bundle.PlanID, ExpectedInitialPlanRevision: bundle.InitialPlanRevision}
	if _, err := ring.VerifyUpgradePlanArtifactBundle(decoded, afterDeadline); !errors.Is(err, ErrUpgradePlanArtifactBundleExpired) {
		t.Fatalf("expired bundle error = %v", err)
	}
	for _, revision := range []uint64{0, 2} {
		candidate := bundle
		candidate.InitialPlanRevision = revision
		if err := candidate.Validate(); !errors.Is(err, ErrInvalidUpgradePlanArtifactBundle) {
			t.Fatalf("initial plan revision %d error = %v", revision, err)
		}
	}
	candidate := bundle
	candidate.CommandIssuanceNotAfter++
	if err := candidate.Validate(); !errors.Is(err, ErrInvalidUpgradePlanArtifactBundle) {
		t.Fatalf("bundle deadline beyond seven days error = %v", err)
	}
}

func TestUpgradeCommandGrantUsesBundleDeadlineAfterParentExpiry(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	_, privateKey := upgradeGrantTestKey(0x54)
	grant := validUpgradeCommandGrantV2(t, now, privateKey)
	grant.ParentGrantIssuedAt = now.Add(-20 * time.Minute).Unix()
	grant.ParentGrantExpiresAt = now.Add(-5 * time.Minute).Unix()
	grant.CommandIssuanceNotAfter = now.Add(time.Hour).Unix()
	grant.IssuedAt = now.Unix()
	grant.NotBefore = now.Unix()
	grant.ExpiresAt = now.Add(15 * time.Minute).Unix()
	if err := grant.Validate(); err != nil {
		t.Fatalf("fresh bundle-bound command after parent expiry error = %v", err)
	}

	grant.ExpiresAt = grant.CommandIssuanceNotAfter + 1
	if err := grant.Validate(); !errors.Is(err, ErrInvalidUpgradeCommandGrant) {
		t.Fatalf("command beyond bundle deadline error = %v", err)
	}
	grant = validUpgradeCommandGrantV2(t, now, privateKey)
	grant.PlanRevision = MaxUpgradePlanRevision + 1
	if err := grant.Validate(); !errors.Is(err, ErrInvalidUpgradeCommandGrant) {
		t.Fatalf("command plan revision beyond PostgreSQL bigint error = %v", err)
	}
}

func TestArtifactManifestV3SignatureBindsReleaseSequence(t *testing.T) {
	publicKey, privateKey := upgradeGrantTestKey(0xa1)
	manifest := validArtifactManifestV2()
	manifest.Schema = ArtifactManifestV3Schema
	manifest.ReleaseSequence = 17
	signature, err := SignArtifactManifestV3(context.Background(), manifest,
		testSigner{id: "release-key-v3", private: privateKey})
	if err != nil {
		t.Fatalf("SignArtifactManifestV3() error = %v", err)
	}
	if err := VerifyArtifactManifestV3Signature(manifest, publicKey, signature); err != nil {
		t.Fatalf("VerifyArtifactManifestV3Signature() error = %v", err)
	}
	tampered := manifest
	tampered.ReleaseSequence++
	if err := VerifyArtifactManifestV3Signature(tampered, publicKey, signature); !errors.Is(err, ErrInvalidArtifactManifestSignature) {
		t.Fatalf("release sequence tamper error = %v", err)
	}
	legacy := manifest
	legacy.Schema = ArtifactManifestV2Schema
	if err := legacy.Validate(); !errors.Is(err, ErrInvalidArtifactManifest) {
		t.Fatalf("v2 manifest accepted v3 release sequence: %v", err)
	}
}

func TestUpgradePlanArtifactBundleV2BindsDistinctReleaseSequences(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	publicKey, privateKey := upgradeGrantTestKey(0xa2)
	bundle := validUpgradePlanArtifactBundle(t, now, privateKey)
	bundle.Schema = UpgradePlanArtifactBundleV2Schema
	bundle.Forward.Manifest.Schema = ArtifactManifestV3Schema
	bundle.Forward.Manifest.ReleaseSequence = 21
	bundle.Rollback.Manifest.Schema = ArtifactManifestV3Schema
	bundle.Rollback.Manifest.ReleaseSequence = 8
	forwardSignature, err := SignArtifactManifestV3(context.Background(), bundle.Forward.Manifest,
		testSigner{id: "release-bundle-key", private: privateKey})
	if err != nil {
		t.Fatal(err)
	}
	rollbackSignature, err := SignArtifactManifestV3(context.Background(), bundle.Rollback.Manifest,
		testSigner{id: "release-bundle-key", private: privateKey})
	if err != nil {
		t.Fatal(err)
	}
	bundle.Forward.ManifestSignature = base64.RawURLEncoding.EncodeToString(forwardSignature)
	bundle.Rollback.ManifestSignature = base64.RawURLEncoding.EncodeToString(rollbackSignature)
	if err := bundle.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	signed, err := SignUpgradePlanArtifactBundle(context.Background(), bundle,
		testSigner{id: "release-bundle-key", private: privateKey})
	if err != nil {
		t.Fatal(err)
	}
	ring := NewKeyRing()
	_ = ring.Add("release-bundle-key", publicKey)
	if _, err := ring.VerifyUpgradePlanArtifactBundle(signed, UpgradePlanArtifactBundleVerifyOptions{
		Now: now.Add(time.Minute), ExpectedAudience: UpgradePlanArtifactBundleAudience,
		ExpectedInstallationID: bundle.InstallationID, ExpectedPlanID: bundle.PlanID,
		ExpectedInitialPlanRevision: bundle.InitialPlanRevision,
	}); err != nil {
		t.Fatalf("VerifyUpgradePlanArtifactBundle() error = %v", err)
	}
}

func TestUpgradeCommandGrantV3BindsDualSequenceAndLegacyRejectsFields(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	publicKey, privateKey := upgradeGrantTestKey(0xa3)
	grant := validUpgradeCommandGrantV2(t, now, privateKey)
	grant.Schema = UpgradeCommandGrantV3Schema
	grant.ExecutionSequence = 22
	grant.ReleaseSequence = 8
	manifest := ArtifactManifestV2{
		Schema: ArtifactManifestV3Schema, Audience: ArtifactManifestAudience, Purpose: ArtifactManifestPurpose,
		ArtifactID: grant.ArtifactID, Component: grant.Component, Version: grant.Version,
		ProtocolMin: grant.ArtifactProtocolMin, ProtocolMax: grant.ArtifactProtocolMax,
		ArtifactSizeBytes: grant.ArtifactSizeBytes, ReleaseSequence: grant.ReleaseSequence,
		DigestAlgorithm: grant.DigestAlgorithm, SHA256Digest: grant.SHA256Digest, DownloadURL: grant.DownloadURL,
	}
	artifactSignature, err := SignArtifactManifestV3(context.Background(), manifest,
		testSigner{id: "release-command-key", private: privateKey})
	if err != nil {
		t.Fatal(err)
	}
	grant.ArtifactManifestSignature = base64.RawURLEncoding.EncodeToString(artifactSignature)
	signed, err := SignUpgradeCommandGrant(context.Background(), grant,
		testSigner{id: "release-command-key", private: privateKey})
	if err != nil {
		t.Fatalf("SignUpgradeCommandGrant() error = %v", err)
	}
	ring := NewKeyRing()
	_ = ring.Add("release-command-key", publicKey)
	options := UpgradeCommandGrantVerifyOptions{Now: now.Add(time.Minute), ExpectedAudience: UpgradeCommandGrantAudience,
		ExpectedInstallationID: grant.InstallationID, ExpectedNodeID: grant.NodeID, ExpectedCommandID: grant.CommandID,
		ExpectedPlanID: grant.PlanID, ExpectedPlanRevision: grant.PlanRevision, ExpectedBatchID: grant.BatchID}
	if _, err := ring.VerifyUpgradeCommandGrant(signed, options); err != nil {
		t.Fatalf("VerifyUpgradeCommandGrant() error = %v", err)
	}
	for _, mutate := range []func(*UpgradeCommandGrant){
		func(value *UpgradeCommandGrant) { value.ExecutionSequence++ },
		func(value *UpgradeCommandGrant) { value.ReleaseSequence++ },
	} {
		tampered := signed
		mutate(&tampered.Grant)
		if _, err := ring.VerifyUpgradeCommandGrant(tampered, options); !errors.Is(err, ErrInvalidUpgradeCommandGrantSignature) {
			t.Fatalf("dual-sequence tamper error = %v", err)
		}
	}
	for _, schema := range []string{UpgradeCommandGrantSchema, UpgradeCommandGrantV2Schema} {
		legacy := grant
		legacy.Schema = schema
		if err := legacy.Validate(); !errors.Is(err, ErrInvalidUpgradeCommandGrant) {
			t.Fatalf("legacy schema %q accepted v3 fields: %v", schema, err)
		}
	}
}

func upgradeGrantTestKey(fill byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := bytes.Repeat([]byte{fill}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	return privateKey.Public().(ed25519.PublicKey), privateKey
}

func validArtifactManifest() ArtifactManifest {
	return ArtifactManifest{
		Schema: ArtifactManifestSchema, Audience: ArtifactManifestAudience, Purpose: ArtifactManifestPurpose,
		ArtifactID: "00000000-0000-4000-8000-000000000010", Component: "control-api", Version: "2.0.0",
		ProtocolMin: 1, ProtocolMax: 3, DigestAlgorithm: "sha256",
		SHA256Digest: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32)),
		DownloadURL:  "https://cdn.example/releases/control-api-2.0.0",
	}
}

func validArtifactManifestV2() ArtifactManifestV2 {
	manifest := validArtifactManifest()
	return ArtifactManifestV2{
		Schema: ArtifactManifestV2Schema, Audience: manifest.Audience, Purpose: manifest.Purpose,
		ArtifactID: manifest.ArtifactID, Component: manifest.Component, Version: manifest.Version,
		ProtocolMin: manifest.ProtocolMin, ProtocolMax: manifest.ProtocolMax, ArtifactSizeBytes: 1024,
		DigestAlgorithm: manifest.DigestAlgorithm, SHA256Digest: manifest.SHA256Digest, DownloadURL: manifest.DownloadURL,
	}
}

func validUpgradeCommandGrant(t *testing.T, now time.Time, privateKey ed25519.PrivateKey) UpgradeCommandGrant {
	t.Helper()
	manifest := validArtifactManifestV2()
	artifactSignature, err := SignArtifactManifestV2(context.Background(), manifest,
		testSigner{id: "release-command-key", private: privateKey})
	if err != nil {
		t.Fatal(err)
	}
	return UpgradeCommandGrant{
		Schema: UpgradeCommandGrantSchema, Audience: UpgradeCommandGrantAudience, Purpose: UpgradeCommandGrantPurpose,
		CommandID: "00000000-0000-4000-8000-000000000031", Nonce: "00000000-0000-4000-8000-000000000032",
		ParentGrantID:       "00000000-0000-4000-8000-000000000001",
		ParentGrantSHA256:   base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x61}, 32)),
		ParentGrantIssuedAt: now.Add(-time.Minute).Unix(), ParentGrantExpiresAt: now.Add(14 * time.Minute).Unix(),
		CustomerID:     "00000000-0000-4000-8000-000000000003",
		InstallationID: "00000000-0000-4000-8000-000000000004",
		LicenseID:      "00000000-0000-4000-8000-000000000005", Channel: "stable", ChannelRevision: 7,
		Component: manifest.Component, Operation: UpgradeOperation, CurrentVersion: "1.0.0", Version: manifest.Version,
		ProtocolVersion: 2, ArtifactID: manifest.ArtifactID, ArtifactProtocolMin: manifest.ProtocolMin,
		ArtifactProtocolMax: manifest.ProtocolMax, ArtifactSizeBytes: manifest.ArtifactSizeBytes,
		DownloadURL: manifest.DownloadURL, DigestAlgorithm: manifest.DigestAlgorithm, SHA256Digest: manifest.SHA256Digest,
		ArtifactSignatureAlgorithm: Algorithm, ArtifactSignatureKeyID: "release-command-key",
		ArtifactManifestSignature: base64.RawURLEncoding.EncodeToString(artifactSignature),
		NodeID:                    "00000000-0000-4000-8000-000000000021", Platform: "linux", Architecture: "amd64",
		Compatibility: UpgradeExecutionCompatibility{MinAgentVersion: "1.0.0", MaxAgentVersion: "2.0.0"},
		Health: UpgradeExecutionHealthPolicy{Command: []string{"{artifact}", "health"},
			ActivationTimeoutNanoseconds: int64(30 * time.Second), ObservationWindowNanoseconds: int64(time.Minute),
			IntervalNanoseconds: int64(time.Second), ProbeTimeoutNanoseconds: int64(500 * time.Millisecond),
			RequiredConsecutiveSuccesses: 3},
		Rollout: UpgradeExecutionRolloutPolicy{Percentage: 100}, Rollback: UpgradeExecutionRollbackPolicy{Automatic: true},
		IssuedAt: now.Unix(), NotBefore: now.Add(time.Minute).Unix(), ExpiresAt: now.Add(10 * time.Minute).Unix(),
	}
}

func validUpgradeCommandGrantV2(t *testing.T, now time.Time, privateKey ed25519.PrivateKey) UpgradeCommandGrant {
	t.Helper()
	grant := validUpgradeCommandGrant(t, now, privateKey)
	grant.Schema = UpgradeCommandGrantV2Schema
	grant.PlanID = "00000000-0000-4000-8000-000000000034"
	grant.PlanRevision = 1
	grant.BatchID = "00000000-0000-4000-8000-000000000035"
	grant.ArtifactBundleID = "00000000-0000-4000-8000-000000000033"
	grant.ArtifactBundleSHA256 = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x62}, 32))
	grant.CommandIssuanceNotAfter = now.Add(24 * time.Hour).Unix()
	return grant
}

func validUpgradePlanArtifactBundle(t *testing.T, now time.Time,
	privateKey ed25519.PrivateKey) UpgradePlanArtifactBundle {
	t.Helper()
	forward := validArtifactManifestV2()
	rollback := forward
	rollback.ArtifactID = "00000000-0000-4000-8000-000000000011"
	rollback.Version = "1.0.0"
	rollback.ArtifactSizeBytes = 512
	rollback.SHA256Digest = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x43}, 32))
	rollback.DownloadURL = "https://cdn.example/releases/control-api-1.0.0"
	forwardSignature, err := SignArtifactManifestV2(context.Background(), forward,
		testSigner{id: "release-bundle-key", private: privateKey})
	if err != nil {
		t.Fatal(err)
	}
	rollbackSignature, err := SignArtifactManifestV2(context.Background(), rollback,
		testSigner{id: "release-bundle-key", private: privateKey})
	if err != nil {
		t.Fatal(err)
	}
	return UpgradePlanArtifactBundle{
		Schema: UpgradePlanArtifactBundleSchema, Audience: UpgradePlanArtifactBundleAudience,
		Purpose:  UpgradePlanArtifactBundlePurpose,
		BundleID: "00000000-0000-4000-8000-000000000033",
		PlanID:   "00000000-0000-4000-8000-000000000034", InitialPlanRevision: 1,
		ParentGrantID:       "00000000-0000-4000-8000-000000000001",
		ParentGrantSHA256:   base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x61}, 32)),
		ParentGrantIssuedAt: now.Unix(), ParentGrantExpiresAt: now.Add(15 * time.Minute).Unix(),
		CustomerID:     "00000000-0000-4000-8000-000000000003",
		InstallationID: "00000000-0000-4000-8000-000000000004",
		LicenseID:      "00000000-0000-4000-8000-000000000005", Channel: "stable", ChannelRevision: 7,
		Component: "control-api", CurrentVersion: rollback.Version, Version: forward.Version, ProtocolVersion: 2,
		Forward: UpgradePlanArtifact{Manifest: forward, SignatureAlgorithm: Algorithm,
			SignatureKeyID:    "release-bundle-key",
			ManifestSignature: base64.RawURLEncoding.EncodeToString(forwardSignature)},
		Rollback: UpgradePlanArtifact{Manifest: rollback, SignatureAlgorithm: Algorithm,
			SignatureKeyID:    "release-bundle-key",
			ManifestSignature: base64.RawURLEncoding.EncodeToString(rollbackSignature)},
		IssuedAt: now.Unix(), CommandIssuanceNotAfter: now.Add(7 * 24 * time.Hour).Unix(),
	}
}

func validUpgradeGrant(now time.Time, artifactSignature []byte) UpgradeGrant {
	manifest := validArtifactManifest()
	return UpgradeGrant{
		Schema: UpgradeGrantSchema, Audience: UpgradeGrantAudience, Purpose: UpgradeGrantPurpose,
		GrantID: "00000000-0000-4000-8000-000000000001", Nonce: "00000000-0000-4000-8000-000000000002",
		CustomerID: "00000000-0000-4000-8000-000000000003", InstallationID: "00000000-0000-4000-8000-000000000004",
		LicenseID: "00000000-0000-4000-8000-000000000005", Channel: "stable", ChannelRevision: 1,
		Component: manifest.Component, Operation: UpgradeOperation, CurrentVersion: "1.0.0", Version: manifest.Version,
		ProtocolVersion: 2, ArtifactID: manifest.ArtifactID, ArtifactProtocolMin: manifest.ProtocolMin,
		ArtifactProtocolMax: manifest.ProtocolMax, DownloadURL: manifest.DownloadURL,
		DigestAlgorithm: manifest.DigestAlgorithm, SHA256Digest: manifest.SHA256Digest,
		ArtifactSignatureAlgorithm: Algorithm, ArtifactSignatureKeyID: "release-key-3",
		ArtifactManifestSignature: base64.RawURLEncoding.EncodeToString(artifactSignature),
		IssuedAt:                  now.Unix(), ExpiresAt: now.Add(15 * time.Minute).Unix(),
	}
}
