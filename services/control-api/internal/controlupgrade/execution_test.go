package controlupgrade

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
)

func TestIssueCommandExecutionVerifiesGrantBeforeEitherExecutionSignature(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	grantWire, grantKeys, grant := executionCommandGrantFixture(t, now)
	controlSigner := &executionCountingSigner{id: "control-execution-1", privateKey: executionPrivateKey(0x72)}
	edgeSigner := &executionCountingSigner{id: "edge-consumption-1", privateKey: executionPrivateKey(0x73)}
	options := executionCommandGrantOptions(now.Add(time.Minute), grant)

	signedGrant, _ := entitlement.DecodeUpgradeCommandGrant(grantWire)
	signedGrant.Grant.ArtifactManifestSignature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	signedGrant, _ = entitlement.SignUpgradeCommandGrant(context.Background(), signedGrant.Grant,
		grantTestSigner{privateKey: executionPrivateKey(0x71)})
	invalidArtifactWire, _ := signedGrant.Encode()
	for name, candidate := range map[string][]byte{
		"noncanonical":               append([]byte(" "), grantWire...),
		"invalid":                    []byte(`{"algorithm":"Ed25519"}`),
		"invalid artifact signature": invalidArtifactWire,
	} {
		t.Run(name, func(t *testing.T) {
			controlSigner.calls = 0
			edgeSigner.calls = 0
			if _, err := IssueCommandExecution(t.Context(), candidate, grantKeys, options,
				controlSigner, edgeSigner); err == nil {
				t.Fatal("IssueCommandExecution() error = nil")
			}
			if controlSigner.calls != 0 || edgeSigner.calls != 0 {
				t.Fatalf("signer calls = (%d, %d), want (0, 0)", controlSigner.calls, edgeSigner.calls)
			}
		})
	}

	expired := executionCommandGrantOptions(time.Unix(grant.ExpiresAt, 0), grant)
	if _, err := IssueCommandExecution(t.Context(), grantWire, grantKeys, expired,
		controlSigner, edgeSigner); !errors.Is(err, entitlement.ErrUpgradeCommandGrantExpired) {
		t.Fatalf("expired IssueCommandExecution() error = %v", err)
	}
}

func TestIssueCommandExecutionDerivesEveryFieldFromVerifiedCommandGrant(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	grantWire, grantKeys, grant := executionCommandGrantFixture(t, now)
	controlPrivate := executionPrivateKey(0x74)
	edgePrivate := executionPrivateKey(0x75)
	encoded, err := IssueCommandExecution(t.Context(), grantWire, grantKeys,
		executionCommandGrantOptions(now.Add(time.Minute), grant),
		&executionCountingSigner{id: "control-execution-1", privateKey: controlPrivate},
		&executionCountingSigner{id: "edge-consumption-1", privateKey: edgePrivate})
	if err != nil {
		t.Fatalf("IssueCommandExecution() error = %v", err)
	}
	signed, err := entitlement.DecodeUpgradeExecution(encoded)
	if err != nil {
		t.Fatalf("DecodeUpgradeExecution() error = %v", err)
	}
	digest, _ := entitlement.CanonicalUpgradeCommandGrantDigest(grantWire)
	execution := signed.Execution
	if execution.GrantDigest != digest || execution.GrantExpiresAt != grant.ExpiresAt ||
		execution.InstallationID != grant.InstallationID || execution.NodeID != grant.NodeID ||
		execution.CommandID != grant.CommandID || execution.Nonce != grant.Nonce ||
		execution.ReleaseSequence != grant.ChannelRevision || execution.Component != grant.Component ||
		execution.Operation != grant.Operation || execution.CurrentVersion != grant.CurrentVersion ||
		execution.TargetVersion != grant.Version || execution.ArtifactID != grant.ArtifactID ||
		execution.SHA256Digest != grant.SHA256Digest || execution.DownloadURL != grant.DownloadURL ||
		execution.ArtifactSizeBytes != grant.ArtifactSizeBytes || execution.Platform != grant.Platform ||
		execution.Architecture != grant.Architecture || !reflect.DeepEqual(execution.Compatibility, grant.Compatibility) ||
		!reflect.DeepEqual(execution.Health, grant.Health) || execution.Rollout != grant.Rollout ||
		execution.Rollback != grant.Rollback || execution.IssuedAt != grant.IssuedAt ||
		execution.NotBefore != grant.NotBefore || execution.ExpiresAt != grant.ExpiresAt {
		t.Fatalf("execution did not derive frozen command grant: %#v", execution)
	}

	controlKeys, edgeKeys := entitlement.NewKeyRing(), entitlement.NewKeyRing()
	_ = controlKeys.Add("control-execution-1", controlPrivate.Public().(ed25519.PublicKey))
	_ = edgeKeys.Add("edge-consumption-1", edgePrivate.Public().(ed25519.PublicKey))
	verified, err := entitlement.VerifyUpgradeExecution(signed, controlKeys, edgeKeys,
		entitlement.UpgradeExecutionVerifyOptions{Now: now.Add(2 * time.Minute),
			ExpectedAudience: entitlement.UpgradeExecutionAudience, ExpectedInstallationID: grant.InstallationID,
			ExpectedNodeID: grant.NodeID, ExpectedCommandID: grant.CommandID, ExpectedNonce: grant.Nonce,
			ExpectedCurrentVersion: grant.CurrentVersion, ExpectedTargetVersion: grant.Version})
	if err != nil || !reflect.DeepEqual(verified, execution) {
		t.Fatalf("VerifyUpgradeExecution() = (%#v, %v)", verified, err)
	}
}

func executionCommandGrantFixture(t *testing.T, now time.Time) ([]byte, *entitlement.KeyRing,
	entitlement.UpgradeCommandGrant) {
	t.Helper()
	privateKey := executionPrivateKey(0x71)
	signer := grantTestSigner{privateKey: privateKey}
	artifact := entitlement.ArtifactManifestV2{Schema: entitlement.ArtifactManifestV2Schema,
		Audience: entitlement.ArtifactManifestAudience, Purpose: entitlement.ArtifactManifestPurpose,
		ArtifactID: "00000000-0000-4000-8000-000000000010", Component: "edge-agent", Version: "2.0.0",
		ProtocolMin: 1, ProtocolMax: 3, ArtifactSizeBytes: 4096, DigestAlgorithm: "sha256",
		SHA256Digest: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, sha256.Size)),
		DownloadURL:  "https://cdn.example/releases/edge-agent-2.0.0"}
	artifactSignature, err := entitlement.SignArtifactManifestV2(t.Context(), artifact, signer)
	if err != nil {
		t.Fatal(err)
	}
	grant := entitlement.UpgradeCommandGrant{Schema: entitlement.UpgradeCommandGrantSchema,
		Audience: entitlement.UpgradeCommandGrantAudience, Purpose: entitlement.UpgradeCommandGrantPurpose,
		CommandID: "00000000-0000-4000-8000-000000000022", Nonce: "00000000-0000-4000-8000-000000000023",
		ParentGrantID:       "00000000-0000-4000-8000-000000000001",
		ParentGrantSHA256:   base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, sha256.Size)),
		ParentGrantIssuedAt: now.Unix(), ParentGrantExpiresAt: now.Add(15 * time.Minute).Unix(),
		CustomerID:     "00000000-0000-4000-8000-000000000003",
		InstallationID: "00000000-0000-4000-8000-000000000004",
		LicenseID:      "00000000-0000-4000-8000-000000000005", Channel: "stable", ChannelRevision: 7,
		Component: artifact.Component, Operation: entitlement.UpgradeOperation, CurrentVersion: "1.0.0",
		Version: artifact.Version, ProtocolVersion: 2, ArtifactID: artifact.ArtifactID,
		ArtifactProtocolMin: artifact.ProtocolMin, ArtifactProtocolMax: artifact.ProtocolMax,
		ArtifactSizeBytes: artifact.ArtifactSizeBytes, DownloadURL: artifact.DownloadURL,
		DigestAlgorithm: artifact.DigestAlgorithm, SHA256Digest: artifact.SHA256Digest,
		ArtifactSignatureAlgorithm: entitlement.Algorithm, ArtifactSignatureKeyID: signer.KeyID(),
		ArtifactManifestSignature: base64.RawURLEncoding.EncodeToString(artifactSignature),
		NodeID:                    "00000000-0000-4000-8000-000000000021", Platform: "linux", Architecture: "amd64",
		Compatibility: entitlement.UpgradeExecutionCompatibility{MinAgentVersion: "1.0.0", MaxAgentVersion: "2.0.0"},
		Health: entitlement.UpgradeExecutionHealthPolicy{Command: []string{"{artifact}", "--version"},
			ActivationTimeoutNanoseconds: int64(30 * time.Second), ObservationWindowNanoseconds: int64(time.Minute),
			IntervalNanoseconds: int64(time.Second), ProbeTimeoutNanoseconds: int64(500 * time.Millisecond),
			RequiredConsecutiveSuccesses: 3},
		Rollout:  entitlement.UpgradeExecutionRolloutPolicy{Percentage: 100},
		Rollback: entitlement.UpgradeExecutionRollbackPolicy{Automatic: true},
		IssuedAt: now.Unix(), NotBefore: now.Unix(), ExpiresAt: now.Add(10 * time.Minute).Unix()}
	signed, err := entitlement.SignUpgradeCommandGrant(t.Context(), grant, signer)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := signed.Encode()
	keys := entitlement.NewKeyRing()
	_ = keys.Add(signer.KeyID(), privateKey.Public().(ed25519.PublicKey))
	return encoded, keys, grant
}

func executionCommandGrantOptions(now time.Time, grant entitlement.UpgradeCommandGrant) entitlement.UpgradeCommandGrantVerifyOptions {
	return entitlement.UpgradeCommandGrantVerifyOptions{Now: now, ExpectedAudience: entitlement.UpgradeCommandGrantAudience,
		ExpectedInstallationID: grant.InstallationID, ExpectedNodeID: grant.NodeID, ExpectedCommandID: grant.CommandID}
}

type executionCountingSigner struct {
	id         string
	privateKey ed25519.PrivateKey
	calls      int
}

func (signer *executionCountingSigner) KeyID() string { return signer.id }

func (signer *executionCountingSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	signer.calls++
	return ed25519.Sign(signer.privateKey, payload), nil
}

func executionPrivateKey(fill byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{fill}, ed25519.SeedSize))
}

// Nodes download from the control plane cache: only the URL changes; the
// signed digest and size the node verifies still come from the license grant.
func TestIssueCachedCommandExecutionPointsAtControlCacheAndKeepsSignedDigest(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	grantWire, grantKeys, grant := executionCommandGrantFixture(t, now)
	cached := "https://cdnca.com/downloads/edge-agent/upgrades/sha256/" + strings.Repeat("ab", 32)
	encoded, err := IssueCachedCommandExecution(t.Context(), grantWire, grantKeys,
		executionCommandGrantOptions(now.Add(time.Minute), grant),
		&executionCountingSigner{id: "control-execution-1", privateKey: executionPrivateKey(0x76)},
		&executionCountingSigner{id: "edge-consumption-1", privateKey: executionPrivateKey(0x77)}, cached, nil)
	if err != nil {
		t.Fatalf("IssueCachedCommandExecution() error = %v", err)
	}
	signed, err := entitlement.DecodeUpgradeExecution(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if signed.Execution.DownloadURL != cached || signed.Execution.DownloadURL == grant.DownloadURL ||
		signed.Execution.SHA256Digest != grant.SHA256Digest || signed.Execution.ArtifactSizeBytes != grant.ArtifactSizeBytes {
		t.Fatalf("cached execution = url %q digest %q size %d", signed.Execution.DownloadURL,
			signed.Execution.SHA256Digest, signed.Execution.ArtifactSizeBytes)
	}
	for _, invalid := range []string{"http://cdnca.com/a", "https://CDNCA.com/a", " https://cdnca.com/a"} {
		if _, err := IssueCachedCommandExecution(t.Context(), grantWire, grantKeys,
			executionCommandGrantOptions(now.Add(time.Minute), grant),
			&executionCountingSigner{id: "control-execution-1", privateKey: executionPrivateKey(0x76)},
			&executionCountingSigner{id: "edge-consumption-1", privateKey: executionPrivateKey(0x77)}, invalid, nil); err == nil {
			t.Fatalf("invalid cache URL %q accepted", invalid)
		}
	}
}

// fix-btenv3: the execution carries the control plane's current download
// endpoint (host/port of the cache URL, addresses resolved now, its root).
func TestIssueCachedCommandExecutionSignsCurrentDownloadPolicy(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	grantWire, grantKeys, grant := executionCommandGrantFixture(t, now)
	root := filepath.Join(t.TempDir(), "root-ca.pem")
	rootPEM := "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n"
	if err := os.WriteFile(root, []byte(rootPEM), 0o644); err != nil {
		t.Fatal(err)
	}
	cached := "https://cdnca.com:19445/downloads/edge-agent/upgrades/sha256/" + strings.Repeat("ab", 32)
	source := DownloadPolicySource{RootCAFile: root, LookupHost: func(_ context.Context, host string) ([]string, error) {
		if host != "cdnca.com" {
			t.Fatalf("lookup %q", host)
		}
		return []string{"203.0.113.9", "127.0.0.1", "2001:db8::9", "203.0.113.9", "::ffff:198.51.100.1"}, nil
	}}
	policy := source.Policy(t.Context(), cached)
	if policy == nil || policy.Host != "cdnca.com" || policy.Port != 19445 || policy.RootCA != rootPEM ||
		strings.Join(policy.Addresses, ",") != "2001:db8::9,203.0.113.9" {
		t.Fatalf("policy = %+v", policy)
	}
	encoded, err := IssueCachedCommandExecution(t.Context(), grantWire, grantKeys,
		executionCommandGrantOptions(now.Add(time.Minute), grant),
		&executionCountingSigner{id: "control-execution-1", privateKey: executionPrivateKey(0x76)},
		&executionCountingSigner{id: "edge-consumption-1", privateKey: executionPrivateKey(0x77)}, cached, policy)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := entitlement.DecodeUpgradeExecution(encoded)
	if err != nil || signed.Execution.DownloadPolicy == nil || signed.Execution.DownloadPolicy.Port != 19445 {
		t.Fatalf("signed policy = %+v, %v", signed.Execution.DownloadPolicy, err)
	}
	// Plain layout without a private root: the node keeps its system root.
	if policy := (DownloadPolicySource{LookupHost: source.LookupHost}).Policy(t.Context(), "https://cdnca.com/x"); policy == nil ||
		policy.Port != 443 || policy.RootCA != entitlement.UpgradeDownloadSystemRoot {
		t.Fatalf("plain policy = %+v", policy)
	}
	// Resolution failure or an unreadable root: no policy, nodes keep theirs.
	failing := DownloadPolicySource{LookupHost: func(context.Context, string) ([]string, error) { return nil, errors.New("nxdomain") }}
	if policy := failing.Policy(t.Context(), cached); policy != nil {
		t.Fatalf("lookup failure gave %+v", policy)
	}
	if policy := (DownloadPolicySource{RootCAFile: root + ".missing", LookupHost: source.LookupHost}).Policy(t.Context(), cached); policy != nil {
		t.Fatalf("missing root gave %+v", policy)
	}
	if policy := (DownloadPolicySource{}).Policy(t.Context(), "https://203.0.113.9:19445/x"); policy == nil ||
		strings.Join(policy.Addresses, ",") != "203.0.113.9" {
		t.Fatalf("IP literal policy = %+v", policy)
	}
}
