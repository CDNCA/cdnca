package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/controlupgrade"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/google/uuid"
)

type maintenanceCandidateTransport func(*http.Request) (*http.Response, error)

func (transport maintenanceCandidateTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

type maintenanceCandidateFixture struct {
	now          time.Time
	installation uuid.UUID
	privateKey   ed25519.PrivateKey
	signer       *controlUpgradeEd25519Signer
	artifact     *controlUpgradeEd25519Signer
	trust        *entitlementguard.TrustStore
}

func newMaintenanceCandidateFixture(t *testing.T) maintenanceCandidateFixture {
	t.Helper()
	fixture := maintenanceCandidateFixture{now: time.Unix(1_800_000_000, 0).UTC(), installation: uuid.New(),
		privateKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x61}, ed25519.SeedSize)),
		signer:     &controlUpgradeEd25519Signer{keyID: "candidate-key", privateKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x62}, ed25519.SeedSize))},
		artifact:   &controlUpgradeEd25519Signer{keyID: "artifact-key", privateKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x63}, ed25519.SeedSize))}}
	var err error
	fixture.trust, err = entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{
		{KeyID: fixture.signer.KeyID(), PublicKey: fixture.signer.PublicKey()},
		{KeyID: fixture.artifact.KeyID(), PublicKey: fixture.artifact.PublicKey()},
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (fixture maintenanceCandidateFixture) response(t *testing.T, request *http.Request) entitlement.SignedUpgradeCandidate {
	t.Helper()
	if request.Method != http.MethodPost || request.URL.Path != "/activation/v1/installations/"+fixture.installation.String()+"/upgrade-candidates:resolve" {
		t.Fatalf("unexpected candidate request: %s %s", request.Method, request.URL.Path)
	}
	for _, name := range []string{"Content-Type", "X-CDNCA-Installation-ID", "X-Request-ID", "X-CDNCA-Requested-At", "X-CDNCA-Proof"} {
		if len(request.Header.Values(name)) != 1 {
			t.Fatalf("header %s was not sent exactly once", name)
		}
	}
	if request.Header.Get("Content-Type") != "application/json" || request.Header.Get("X-CDNCA-Installation-ID") != fixture.installation.String() ||
		request.Header.Get("Authorization") != "" || request.Header.Get("Idempotency-Key") != "" || request.Header.Get("Cookie") != "" {
		t.Fatal("candidate request used an unexpected identity or write credential")
	}
	body, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	requestID := request.Header.Get("X-Request-ID")
	requestedAt, err := strconv.ParseInt(request.Header.Get("X-CDNCA-Requested-At"), 10, 64)
	if err != nil || requestedAt != fixture.now.Unix() {
		t.Fatalf("request timestamp = %d, %v", requestedAt, err)
	}
	proofMessage, err := entitlement.UpgradeCandidateRequestProofMessage(fixture.installation.String(), requestID, requestedAt, body)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := base64.RawURLEncoding.DecodeString(request.Header.Get("X-CDNCA-Proof"))
	if err != nil || !ed25519.Verify(fixture.privateKey.Public().(ed25519.PublicKey), proofMessage, proof) {
		t.Fatal("installation proof was not verified")
	}
	var input entitlement.UpgradeCandidateRequest
	if err := json.Unmarshal(body, &input); err != nil {
		t.Fatal(err)
	}
	manifest := entitlement.ArtifactManifestV2{Schema: entitlement.ArtifactManifestV2Schema, Audience: entitlement.ArtifactManifestAudience,
		Purpose: entitlement.ArtifactManifestPurpose, ArtifactID: uuid.NewString(), Component: input.Component, Version: "1.1.0",
		ProtocolMin: 1, ProtocolMax: 3, ArtifactSizeBytes: 1024, DigestAlgorithm: "sha256",
		SHA256Digest: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32)), DownloadURL: "https://release.example.test/private-control-api"}
	signature, err := entitlement.SignArtifactManifestV2(t.Context(), manifest, fixture.artifact)
	if err != nil {
		t.Fatal(err)
	}
	revision := uint64(2)
	snapshot := entitlement.UpgradeCandidateSnapshot{Schema: entitlement.UpgradeCandidateSnapshotSchema, Audience: entitlement.UpgradeCandidateAudience,
		Purpose: entitlement.UpgradeCandidatePurpose, InstallationID: fixture.installation.String(), RequestID: requestID,
		RequestSHA256: base64.RawURLEncoding.EncodeToString(proofMessage), Component: input.Component, CurrentVersion: input.CurrentVersion,
		ProtocolVersion: input.ProtocolVersion, Status: "available", Reason: "upgrade_available",
		Authority: &entitlement.UpgradeCandidateAuthority{LicenseRevision: 1, Version: entitlement.VersionRange{Channel: "stable", Min: "1.0.0", Max: "2.0.0"}, TargetMode: "follow_channel", ChannelRevision: &revision},
		Candidate: &entitlement.UpgradeCandidateArtifact{Manifest: manifest, SignatureAlgorithm: entitlement.Algorithm, SignatureKeyID: fixture.artifact.KeyID(),
			ManifestSignature: base64.RawURLEncoding.EncodeToString(signature), Revision: 2, PublishedAt: fixture.now.Unix() - 10, AttestedAt: fixture.now.Unix() - 20,
			RepositoryVerificationSHA256: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32)), RepositoryVerifiedAt: fixture.now.Unix() - 15, VerifiedUntil: fixture.now.Add(time.Hour).Unix()},
		IssuedAt: fixture.now.Unix(), ExpiresAt: fixture.now.Add(time.Minute).Unix()}
	if input.CurrentVersion == "1.1.0" {
		snapshot.Status, snapshot.Reason = "up_to_date", "same_version"
	} else if input.CurrentVersion == "1.2.0" {
		snapshot.Status, snapshot.Reason = "rollback_required", "target_is_older"
	}
	signed, err := entitlement.SignUpgradeCandidate(t.Context(), snapshot, fixture.signer)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func (fixture maintenanceCandidateFixture) client(t *testing.T, transport http.RoundTripper) *maintenanceUpgradeClient {
	t.Helper()
	client, err := newMaintenanceUpgradeClient("https://license.example.test", fixture.installation, fixture.privateKey, fixture.trust, transport, func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

func maintenanceCandidateHTTPResponse(t *testing.T, signed entitlement.SignedUpgradeCandidate) *http.Response {
	t.Helper()
	encoded, err := signed.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(encoded))}
}

func TestMaintenanceUpgradeClientSignedCandidateAndPrivateProjection(t *testing.T) {
	for _, state := range []string{"available", "up_to_date", "rollback_required", "unavailable"} {
		t.Run(state, func(t *testing.T) {
			fixture := newMaintenanceCandidateFixture(t)
			client := fixture.client(t, maintenanceCandidateTransport(func(request *http.Request) (*http.Response, error) {
				signed := fixture.response(t, request)
				signed.Snapshot.Status = state
				switch state {
				case "up_to_date":
					signed.Snapshot.Reason = "same_version"
				case "rollback_required":
					signed.Snapshot.Reason = "target_is_older"
				case "unavailable":
					signed.Snapshot.Reason = "target_unset"
					signed.Snapshot.Candidate = nil
					signed.Snapshot.Authority = nil
				}
				signed, err := entitlement.SignUpgradeCandidate(t.Context(), signed.Snapshot, fixture.signer)
				if err != nil {
					t.Fatal(err)
				}
				return maintenanceCandidateHTTPResponse(t, signed), nil
			}))
			version := "1.0.0"
			if state == "up_to_date" {
				version = "1.1.0"
			}
			if state == "rollback_required" {
				version = "1.2.0"
			}
			got, err := client.ReadCandidate(t.Context(), "control-api", version, 2)
			if err != nil || got.State != state || got.ExpiresAt == nil || !got.ExpiresAt.Equal(fixture.now.Add(time.Minute)) {
				t.Fatalf("candidate = (%+v,%v)", got, err)
			}
			if state != "unavailable" && (got.Version == nil || *got.Version != "1.1.0" || got.Channel != "stable") {
				t.Fatalf("candidate projection = %+v", got)
			}
			if state == "unavailable" && (got.Version != nil || got.Channel != "") {
				t.Fatalf("unavailable candidate exposed a release: %+v", got)
			}
			encoded, _ := json.Marshal(got)
			for _, forbidden := range []string{"private-control-api", "signature", "manifest", "stable"} {
				if bytes.Contains(encoded, []byte(forbidden)) {
					t.Fatalf("private release evidence exposed: %s", encoded)
				}
			}
		})
	}
}

func TestMaintenanceUpgradeClientRejectsTamperingBindingAndExpiry(t *testing.T) {
	for name, mutate := range map[string]func(*entitlement.SignedUpgradeCandidate){
		"installation": func(s *entitlement.SignedUpgradeCandidate) { s.Snapshot.InstallationID = uuid.NewString() },
		"request":      func(s *entitlement.SignedUpgradeCandidate) { s.Snapshot.RequestID = uuid.NewString() },
		"body digest instead of proof": func(s *entitlement.SignedUpgradeCandidate) {
			body, _ := entitlement.CanonicalUpgradeCandidateRequest(entitlement.UpgradeCandidateRequest{Schema: entitlement.UpgradeCandidateRequestSchema, Component: "control-api", CurrentVersion: "1.0.0", ProtocolVersion: 2})
			digest := sha256.Sum256(body)
			s.Snapshot.RequestSHA256 = base64.RawURLEncoding.EncodeToString(digest[:])
		},
		"current version": func(s *entitlement.SignedUpgradeCandidate) { s.Snapshot.CurrentVersion = "1.0.1" },
		"protocol":        func(s *entitlement.SignedUpgradeCandidate) { s.Snapshot.ProtocolVersion = 3 },
		"component": func(s *entitlement.SignedUpgradeCandidate) {
			s.Snapshot.Component = "edge-agent"
			s.Snapshot.Status = "unavailable"
			s.Snapshot.Reason = "target_unset"
			s.Snapshot.Authority = nil
			s.Snapshot.Candidate = nil
		},
		"expired": func(s *entitlement.SignedUpgradeCandidate) {
			s.Snapshot.IssuedAt -= 60
			s.Snapshot.ExpiresAt -= 60
			s.Snapshot.Candidate.AttestedAt -= 60
			s.Snapshot.Candidate.PublishedAt -= 60
			s.Snapshot.Candidate.RepositoryVerifiedAt -= 60
		},
		"future": func(s *entitlement.SignedUpgradeCandidate) { s.Snapshot.IssuedAt += 6; s.Snapshot.ExpiresAt += 6 },
		"artifact tampered": func(s *entitlement.SignedUpgradeCandidate) {
			s.Snapshot.Candidate.Manifest.DownloadURL = "https://release.example.test/tampered"
		},
		"envelope tampered": func(s *entitlement.SignedUpgradeCandidate) {
			s.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newMaintenanceCandidateFixture(t)
			client := fixture.client(t, maintenanceCandidateTransport(func(request *http.Request) (*http.Response, error) {
				signed := fixture.response(t, request)
				mutate(&signed)
				if name != "envelope tampered" {
					var err error
					signed, err = entitlement.SignUpgradeCandidate(t.Context(), signed.Snapshot, fixture.signer)
					if err != nil {
						t.Fatal(err)
					}
				}
				return maintenanceCandidateHTTPResponse(t, signed), nil
			}))
			if got, err := client.ReadCandidate(t.Context(), "control-api", "1.0.0", 2); err == nil || !reflect.DeepEqual(got, controlupgrade.MaintenanceCandidate{}) {
				t.Fatalf("invalid candidate = (%+v,%v)", got, err)
			}
		})
	}
}

func TestMaintenanceUpgradeClientVerifiesBothSigningKeyWindows(t *testing.T) {
	for _, name := range []string{"envelope not before", "envelope sign until", "envelope verify until", "artifact not before", "artifact sign until", "artifact verify until", "retired artifact still verifiable"} {
		t.Run(name, func(t *testing.T) {
			fixture := newMaintenanceCandidateFixture(t)
			keys := []entitlementguard.VerificationKey{{KeyID: fixture.signer.KeyID(), PublicKey: fixture.signer.PublicKey()}, {KeyID: fixture.artifact.KeyID(), PublicKey: fixture.artifact.PublicKey()}}
			now, attested := fixture.now, fixture.now.Add(-20*time.Second)
			switch name {
			case "envelope not before":
				keys[0].NotBefore = now.Add(time.Second)
			case "envelope sign until":
				keys[0].SignUntil = &now
			case "envelope verify until":
				keys[0].VerifyUntil = &now
			case "artifact not before":
				keys[1].NotBefore = attested.Add(time.Second)
			case "artifact sign until":
				keys[1].SignUntil = &attested
			case "artifact verify until":
				keys[1].VerifyUntil = &now
			case "retired artifact still verifiable":
				until := attested.Add(time.Second)
				keys[1].SignUntil = &until
			}
			if err := fixture.trust.ApplyVerifiedKeys(keys); err != nil {
				t.Fatal(err)
			}
			client := fixture.client(t, maintenanceCandidateTransport(func(request *http.Request) (*http.Response, error) {
				return maintenanceCandidateHTTPResponse(t, fixture.response(t, request)), nil
			}))
			got, err := client.ReadCandidate(t.Context(), "control-api", "1.0.0", 2)
			if name == "retired artifact still verifiable" {
				if err != nil || got.State != "available" {
					t.Fatalf("attestation-time verification = (%+v,%v)", got, err)
				}
			} else if !errors.Is(err, entitlementguard.ErrKeyOutsideWindow) || got.State != "" {
				t.Fatalf("outside-window candidate = (%+v,%v)", got, err)
			}
		})
	}
}

type maintenanceRevokedSigner string

func (keyID maintenanceRevokedSigner) CheckSigner(class entitlementguard.SignerArtifactClass, candidate string) error {
	if class == entitlementguard.SignerArtifactRelease && candidate == string(keyID) {
		return &entitlementguard.SignerRevokedError{Class: class, KeyID: candidate}
	}
	return nil
}

func TestMaintenanceUpgradeClientRejectsRevokedReleaseSigners(t *testing.T) {
	for _, role := range []string{"envelope", "artifact"} {
		t.Run(role, func(t *testing.T) {
			fixture := newMaintenanceCandidateFixture(t)
			revoked := fixture.signer.KeyID()
			if role == "artifact" {
				revoked = fixture.artifact.KeyID()
			}
			fixture.trust.SetSignerRevocationGate(maintenanceRevokedSigner(revoked))
			client := fixture.client(t, maintenanceCandidateTransport(func(request *http.Request) (*http.Response, error) {
				return maintenanceCandidateHTTPResponse(t, fixture.response(t, request)), nil
			}))
			got, err := client.ReadCandidate(t.Context(), "control-api", "1.0.0", 2)
			if !errors.Is(err, entitlementguard.ErrSignerRevoked) || got.State != "" {
				t.Fatalf("revoked %s signer candidate = (%+v,%v)", role, got, err)
			}
		})
	}
}

func TestMaintenanceUpgradeClientBoundsTransportAndClearsKey(t *testing.T) {
	fixture := newMaintenanceCandidateFixture(t)
	for _, name := range []string{"offline", "oversize length", "oversize stream", "wrong content type", "upstream unavailable", "deadline"} {
		t.Run(name, func(t *testing.T) {
			client := fixture.client(t, maintenanceCandidateTransport(func(request *http.Request) (*http.Response, error) {
				deadline, ok := request.Context().Deadline()
				if !ok || time.Until(deadline) > 5*time.Second {
					t.Fatal("candidate request is not bounded to five seconds")
				}
				response := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", maintenanceCandidateResponseLimit+1)))}
				switch name {
				case "offline":
					return nil, errors.New("private upstream details")
				case "oversize length":
					response.ContentLength = maintenanceCandidateResponseLimit + 1
				case "oversize stream":
					response.ContentLength = -1
				case "wrong content type":
					response.Header.Set("Content-Type", "text/html")
				case "upstream unavailable":
					response.StatusCode = http.StatusServiceUnavailable
				case "deadline":
					<-request.Context().Done()
					return nil, request.Context().Err()
				}
				return response, nil
			}))
			if client.http.Timeout != 5*time.Second {
				t.Fatal("client timeout drift")
			}
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
			defer cancel()
			if got, err := client.ReadCandidate(ctx, "control-api", "1.0.0", 2); !errors.Is(err, errMaintenanceCandidateUnavailable) || got.State != "" {
				t.Fatalf("failed transport = (%+v,%v)", got, err)
			}
		})
	}
	client := fixture.client(t, maintenanceCandidateTransport(func(*http.Request) (*http.Response, error) {
		t.Fatal("closed client contacted license service")
		return nil, nil
	}))
	owned := client.privateKey
	client.Close()
	client.Close()
	if !bytes.Equal(owned, make([]byte, ed25519.PrivateKeySize)) || bytes.Equal(fixture.privateKey, owned) {
		t.Fatal("client key ownership was not cleared independently")
	}
	if _, err := client.ReadCandidate(t.Context(), "control-api", "1.0.0", 2); err == nil {
		t.Fatal("closed client remained usable")
	}
}

func TestMaintenanceUpgradeClientRejectsRedirectAndUnsafeOrigin(t *testing.T) {
	fixture := newMaintenanceCandidateFixture(t)
	var hits atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Location", "/redirected")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	t.Cleanup(server.Close)
	client, err := newMaintenanceUpgradeClient(server.URL, fixture.installation, fixture.privateKey, fixture.trust, server.Client().Transport, func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	if _, err := client.ReadCandidate(t.Context(), "control-api", "1.0.0", 2); err == nil || hits.Load() != 1 {
		t.Fatalf("redirect: err=%v requests=%d", err, hits.Load())
	}
	for _, origin := range []string{"http://license.example.test", "https://user:password@license.example.test", "https://license.example.test/", "https://license.example.test?", "https://license.example.test?key=value", "https://license.example.test#fragment"} {
		if client, err := newMaintenanceUpgradeClient(origin, fixture.installation, fixture.privateKey, fixture.trust, nil, time.Now); err == nil || client != nil {
			t.Fatalf("unsafe origin accepted: %s", origin)
		}
	}
	if client, err := openMaintenanceUpgradeClient(config.Config{ControlInstallationKeyFile: "/does/not/exist"}, nil); err != nil || client != nil {
		t.Fatalf("unconfigured client = (%v,%v)", client, err)
	}
}

func TestMaintenanceUpgradeClientMainComposition(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"openMaintenanceUpgradeClient(cfg, trust)", "defer maintenanceUpgradeClient.Close()", "CurrentVersion: controlVersion, ConfiguredVersion: cfg.ControlVersion", "maintenanceUpgradeRuntime.NodeReady = controlUpgradeRuntime.Ready", "maintenanceUpgradeRuntime.ProtocolVersion, err = positiveEnvironmentInt(\"CONTROL_UPGRADE_PROTOCOL_VERSION\")", "MaintenanceUpgradeRuntime:", "openControlPlaneUpgradeRuntimeWithDatabase(cfg, identityService, trust, pool)", "configureMaintenanceUpgradeRuntime(&maintenanceUpgradeRuntime, controlPlaneUpgradeHandler)"} {
		if !bytes.Contains(source, []byte(required)) {
			t.Fatalf("maintenance runtime composition missing %q", required)
		}
	}
	if !strings.Contains(strings.Join(strings.Fields(string(source)), " "), "CurrentVersion: controlVersion, ConfiguredVersion: cfg.ControlVersion, OfflineAfter: cfg.NodePresenceOfflineAfter,") {
		t.Fatal("maintenance runtime must use the configured node inventory offline threshold")
	}
	if !bytes.Contains(source, []byte("policyConfig, err := controlPlaneUpgradeEffectiveConfig(cfg)")) ||
		!bytes.Contains(source, []byte("newPlatformPolicySyncer(ctx, policyConfig, pool, trust, entitlementKeysets, policyState)")) {
		t.Fatal("native policy synchronization must follow the compiled version without rewriting configured diagnostics")
	}
}
