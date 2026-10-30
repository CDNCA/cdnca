package entitlement

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func candidateFixture(t *testing.T) (SignedUpgradeCandidate, *KeyRing, UpgradeCandidateVerifyOptions, testSigner) {
	t.Helper()
	now := time.Unix(1_800_000_000, 0).UTC()
	signer := testSigner{id: "candidate-key", private: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x53}, ed25519.SeedSize))}
	ring := NewKeyRing()
	if err := ring.Add(signer.id, signer.private.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	request := UpgradeCandidateRequest{Schema: UpgradeCandidateRequestSchema, Component: "control-api", CurrentVersion: "1.0.0", ProtocolVersion: 1}
	body, err := CanonicalUpgradeCandidateRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	installation, requestID := "00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002"
	proof, err := UpgradeCandidateRequestProofMessage(installation, requestID, now.Unix(), body)
	if err != nil {
		t.Fatal(err)
	}
	manifest := ArtifactManifestV2{Schema: ArtifactManifestV2Schema, Audience: ArtifactManifestAudience, Purpose: ArtifactManifestPurpose,
		ArtifactID: "00000000-0000-4000-8000-000000000003", Component: "control-api", Version: "1.1.0", ProtocolMin: 1,
		ProtocolMax: 2, ArtifactSizeBytes: 1024, DigestAlgorithm: "sha256", SHA256Digest: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32)),
		DownloadURL: "https://release.example.test/control-api/1.1.0"}
	signature, err := SignArtifactManifestV2(t.Context(), manifest, signer)
	if err != nil {
		t.Fatal(err)
	}
	revision := uint64(2)
	snapshot := UpgradeCandidateSnapshot{Schema: UpgradeCandidateSnapshotSchema, Audience: UpgradeCandidateAudience, Purpose: UpgradeCandidatePurpose,
		InstallationID: installation, RequestID: requestID, RequestSHA256: base64.RawURLEncoding.EncodeToString(proof), Component: request.Component,
		CurrentVersion: request.CurrentVersion, ProtocolVersion: request.ProtocolVersion, Status: "available", Reason: "upgrade_available",
		Authority: &UpgradeCandidateAuthority{LicenseRevision: 1, Version: VersionRange{Channel: "stable", Min: "1.0.0", Max: "2.0.0"},
			TargetMode: "follow_channel", ChannelRevision: &revision},
		Candidate: &UpgradeCandidateArtifact{Manifest: manifest, SignatureAlgorithm: Algorithm, SignatureKeyID: signer.id,
			ManifestSignature: base64.RawURLEncoding.EncodeToString(signature), Revision: 2, PublishedAt: now.Unix() - 10, AttestedAt: now.Unix() - 20,
			RepositoryVerificationSHA256: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32)), RepositoryVerifiedAt: now.Unix() - 15,
			VerifiedUntil: now.Add(15 * time.Minute).Unix()}, IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix()}
	signed, err := SignUpgradeCandidate(t.Context(), snapshot, signer)
	if err != nil {
		t.Fatal(err)
	}
	options := UpgradeCandidateVerifyOptions{Now: now, ExpectedInstallationID: installation, ExpectedRequestID: requestID,
		ExpectedRequestSHA256: snapshot.RequestSHA256, ExpectedComponent: request.Component, ExpectedCurrentVersion: request.CurrentVersion,
		ExpectedProtocolVersion: request.ProtocolVersion}
	return signed, ring, options, signer
}

func TestUpgradeCandidateSignatureAndRequestBinding(t *testing.T) {
	signed, ring, options, _ := candidateFixture(t)
	encoded, err := signed.Encode()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeUpgradeCandidate(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := ring.VerifyUpgradeCandidate(decoded, options); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeUpgradeGrant(encoded); err == nil {
		t.Fatal("candidate accepted as executable grant")
	}
	for name, mutate := range map[string]func(*UpgradeCandidateVerifyOptions){
		"installation": func(o *UpgradeCandidateVerifyOptions) {
			o.ExpectedInstallationID = "00000000-0000-4000-8000-000000000004"
		},
		"request":   func(o *UpgradeCandidateVerifyOptions) { o.ExpectedRequestID = "00000000-0000-4000-8000-000000000004" },
		"digest":    func(o *UpgradeCandidateVerifyOptions) { o.ExpectedRequestSHA256 = "other" },
		"component": func(o *UpgradeCandidateVerifyOptions) { o.ExpectedComponent = "edge-agent" },
		"version":   func(o *UpgradeCandidateVerifyOptions) { o.ExpectedCurrentVersion = "1.0.1" },
		"protocol":  func(o *UpgradeCandidateVerifyOptions) { o.ExpectedProtocolVersion = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := options
			mutate(&changed)
			if !errors.Is(ring.VerifyUpgradeCandidate(decoded, changed), ErrUpgradeCandidateMismatch) {
				t.Fatal("request binding accepted")
			}
		})
	}
	for name, change := range map[string]func(*SignedUpgradeCandidate){
		"envelope-key": func(s *SignedUpgradeCandidate) { s.KeyID = "other-key" },
		"request-digest": func(s *SignedUpgradeCandidate) {
			s.Snapshot.RequestSHA256 = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{6}, 32))
		},
		"repository": func(s *SignedUpgradeCandidate) {
			s.Snapshot.Candidate.RepositoryVerificationSHA256 = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{6}, 32))
		},
		"channel": func(s *SignedUpgradeCandidate) { s.Snapshot.Authority.Version.Channel = "beta" },
	} {
		t.Run("tamper-"+name, func(t *testing.T) {
			changed, _ := DecodeUpgradeCandidate(encoded)
			change(&changed)
			if ring.VerifyUpgradeCandidate(changed, options) == nil {
				t.Fatal("tampered snapshot accepted")
			}
		})
	}
	if !errors.Is(NewKeyRing().VerifyUpgradeCandidate(decoded, options), ErrUnknownKey) {
		t.Fatal("unknown key accepted")
	}
	for _, invalid := range [][]byte{append(append([]byte{}, encoded...), '\n'), append([]byte(" "), encoded...), bytes.Replace(encoded, []byte(`"algorithm":"Ed25519"`), []byte(`"unknown":true,"algorithm":"Ed25519"`), 1), bytes.Replace(encoded, []byte(`"algorithm":"Ed25519"`), []byte(`"algorithm":"Ed25519","algorithm":"Ed25519"`), 1)} {
		if _, err := DecodeUpgradeCandidate(invalid); err == nil {
			t.Fatal("noncanonical envelope accepted")
		}
	}
}

func TestUpgradeCandidateClockAndEvidence(t *testing.T) {
	signed, ring, options, signer := candidateFixture(t)
	for _, test := range []struct {
		offset time.Duration
		want   error
	}{{59 * time.Second, nil}, {60 * time.Second, ErrUpgradeCandidateExpired}, {-5 * time.Second, nil}, {-6 * time.Second, ErrNotYetValid}} {
		o := options
		o.Now = o.Now.Add(test.offset)
		if err := ring.VerifyUpgradeCandidate(signed, o); !errors.Is(err, test.want) {
			t.Fatalf("offset %s: %v want %v", test.offset, err, test.want)
		}
	}
	encoded, _ := signed.Encode()
	for name, change := range map[string]func(*UpgradeCandidateSnapshot){
		"too-long":            func(s *UpgradeCandidateSnapshot) { s.ExpiresAt++ },
		"no-authority":        func(s *UpgradeCandidateSnapshot) { s.Authority = nil },
		"no-size":             func(s *UpgradeCandidateSnapshot) { s.Candidate.Manifest.ArtifactSizeBytes = 0 },
		"no-channel-revision": func(s *UpgradeCandidateSnapshot) { s.Authority.ChannelRevision = nil },
		"expired-evidence":    func(s *UpgradeCandidateSnapshot) { s.Candidate.VerifiedUntil = s.ExpiresAt - 1 },
		"false-state":         func(s *UpgradeCandidateSnapshot) { s.Status = "up_to_date"; s.Reason = "same_version" },
		"out-of-range":        func(s *UpgradeCandidateSnapshot) { s.Authority.Version.Max = "1.0.0" },
	} {
		t.Run(name, func(t *testing.T) {
			c, _ := DecodeUpgradeCandidate(encoded)
			change(&c.Snapshot)
			if _, err := SignUpgradeCandidate(t.Context(), c.Snapshot, signer); err == nil {
				t.Fatal("invalid evidence signed")
			}
		})
	}
	artifactMessage, err := UpgradeCandidateArtifactSigningMessage(*signed.Snapshot.Candidate)
	artifactSignature, _ := base64.RawURLEncoding.DecodeString(signed.Snapshot.Candidate.ManifestSignature)
	if err != nil || !ed25519.Verify(signer.private.Public().(ed25519.PublicKey), artifactMessage, artifactSignature) {
		t.Fatal("detached artifact signing message drift")
	}
}

func TestUpgradeCandidateStatusesAndNegativeSnapshots(t *testing.T) {
	signed, ring, options, signer := candidateFixture(t)
	for _, test := range []struct{ version, status, reason string }{{"1.0.0", "available", "upgrade_available"}, {"1.1.0", "up_to_date", "same_version"}, {"1.2.0", "rollback_required", "target_is_older"}} {
		snapshot := signed.Snapshot
		snapshot.CurrentVersion = test.version
		snapshot.Status = test.status
		snapshot.Reason = test.reason
		candidate, err := SignUpgradeCandidate(t.Context(), snapshot, signer)
		if err != nil {
			t.Fatal(err)
		}
		expected := options
		expected.ExpectedCurrentVersion = test.version
		if err := ring.VerifyUpgradeCandidate(candidate, expected); err != nil {
			t.Fatal(err)
		}
	}
	for _, reason := range []string{"target_unset", "license_inactive", "customer_inactive", "channel_inactive", "target_not_allowed", "artifact_unavailable", "artifact_unverified", "protocol_incompatible", "version_not_allowed", "signing_key_unavailable"} {
		snapshot := signed.Snapshot
		snapshot.Status = "unavailable"
		snapshot.Reason = reason
		snapshot.Authority = nil
		snapshot.Candidate = nil
		candidate, err := SignUpgradeCandidate(t.Context(), snapshot, signer)
		if err != nil {
			t.Fatal(err)
		}
		if err := ring.VerifyUpgradeCandidate(candidate, options); err != nil {
			t.Fatal(err)
		}
		snapshot.Authority = signed.Snapshot.Authority
		if _, err := SignUpgradeCandidate(t.Context(), snapshot, signer); err == nil {
			t.Fatal("negative snapshot fabricated authority")
		}
	}
}

func TestUpgradeCandidateRequestProof(t *testing.T) {
	signed, _, options, _ := candidateFixture(t)
	request := UpgradeCandidateRequest{Schema: UpgradeCandidateRequestSchema, Component: options.ExpectedComponent, CurrentVersion: options.ExpectedCurrentVersion, ProtocolVersion: options.ExpectedProtocolVersion}
	body, _ := CanonicalUpgradeCandidateRequest(request)
	baseline, err := UpgradeCandidateRequestProofMessage(options.ExpectedInstallationID, options.ExpectedRequestID, signed.Snapshot.IssuedAt, body)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		installation, request string
		at                    int64
		body                  []byte
	}{
		{"00000000-0000-4000-8000-000000000005", options.ExpectedRequestID, signed.Snapshot.IssuedAt, body},
		{options.ExpectedInstallationID, "00000000-0000-4000-8000-000000000006", signed.Snapshot.IssuedAt, body},
		{options.ExpectedInstallationID, options.ExpectedRequestID, signed.Snapshot.IssuedAt + 1, body},
	} {
		changed, err := UpgradeCandidateRequestProofMessage(test.installation, test.request, test.at, test.body)
		if err != nil || bytes.Equal(changed, baseline) {
			t.Fatal("proof does not bind headers")
		}
	}
	request.CurrentVersion = "1.0.1"
	changedBody, _ := CanonicalUpgradeCandidateRequest(request)
	changed, _ := UpgradeCandidateRequestProofMessage(options.ExpectedInstallationID, options.ExpectedRequestID, signed.Snapshot.IssuedAt, changedBody)
	if bytes.Equal(changed, baseline) {
		t.Fatal("body not bound")
	}
	for _, bad := range [][]byte{append(append([]byte{}, body...), '\n'), bytes.Replace(body, []byte(`"component":"control-api"`), []byte(`"component":"control-api","channel":"beta"`), 1), []byte(`{}`)} {
		if _, err := UpgradeCandidateRequestProofMessage(options.ExpectedInstallationID, options.ExpectedRequestID, signed.Snapshot.IssuedAt, bad); err == nil {
			t.Fatal("noncanonical request accepted")
		}
	}
	var unknown map[string]any
	_ = json.Unmarshal(body, &unknown)
	unknown["protocol_version"] = 0
	invalid, _ := json.Marshal(unknown)
	if _, err := UpgradeCandidateRequestProofMessage(options.ExpectedInstallationID, options.ExpectedRequestID, signed.Snapshot.IssuedAt, invalid); err == nil {
		t.Fatal("invalid protocol accepted")
	}
}
