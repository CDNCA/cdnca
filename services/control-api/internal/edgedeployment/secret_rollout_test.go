package edgedeployment

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

func TestNormalizeSecretRolloutRequestRejectsSensitiveOrMissingIdentity(t *testing.T) {
	now := time.Date(2026, 7, 28, 1, 0, 0, 0, time.UTC)
	scopeID := uuid.New()
	actor, err := NewSessionActor(uuid.New(), scopeID, ScopeKindTenant, uuid.New(), "secret-rollout-test-token")
	if err != nil {
		t.Fatal(err)
	}
	firstNode, secondNode := uuid.New(), uuid.New()
	valid := SecretRolloutRequest{
		Actor: actor, ConfigurationScopeID: scopeID, NodeIDs: []uuid.UUID{secondNode, firstNode},
		CanonicalSnapshot: []byte(`{"certificate_revision":7}`),
		GeneratorName:     "certificate-publication", GeneratorVersion: "1",
		PayloadDigest: sha256.Sum256([]byte("certificate-revision-7")),
		HealthCheck: HealthCheckPolicy{
			ActivationTimeout: time.Minute, ObservationWindow: time.Second,
			RequiredConsecutiveSuccesses: 1,
		},
		Deadline: now.Add(time.Hour), IdempotencyKey: "certificate-publication-7",
		RequestID: uuid.NewString(), CorrelationID: uuid.NewString(),
	}
	tests := []struct {
		name   string
		mutate func(*SecretRolloutRequest)
	}{
		{name: "missing payload digest", mutate: func(value *SecretRolloutRequest) { value.PayloadDigest = [32]byte{} }},
		{name: "PEM private key", mutate: func(value *SecretRolloutRequest) {
			value.CanonicalSnapshot = []byte("-----BEGIN PRIVATE KEY-----")
		}},
		{name: "private key JSON field", mutate: func(value *SecretRolloutRequest) {
			value.CanonicalSnapshot = []byte(`{"private_key_pem":"forbidden"}`)
		}},
		{name: "KEK JSON field", mutate: func(value *SecretRolloutRequest) {
			value.CanonicalSnapshot = []byte(`{"kek":"forbidden"}`)
		}},
		{name: "missing nodes", mutate: func(value *SecretRolloutRequest) { value.NodeIDs = nil }},
		{name: "nil node", mutate: func(value *SecretRolloutRequest) { value.NodeIDs = []uuid.UUID{uuid.Nil} }},
		{name: "duplicate node", mutate: func(value *SecretRolloutRequest) { value.NodeIDs = []uuid.UUID{firstNode, firstNode} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := valid
			test.mutate(&request)
			if _, err := normalizeSecretRolloutRequest(request, now); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("normalize error=%v", err)
			}
		})
	}
	if normalized, err := normalizeSecretRolloutRequest(valid, now); err != nil ||
		normalized.Digest == ([32]byte{}) || bytes.Compare(normalized.NodeIDs[0][:], normalized.NodeIDs[1][:]) >= 0 {
		t.Fatalf("valid normalization=%+v error=%v", normalized, err)
	}
}

func TestNormalizeSecretReplacementDigestExcludesActorAndBindsMaterial(t *testing.T) {
	now := time.Date(2026, 7, 28, 1, 0, 0, 0, time.UTC)
	scopeID := uuid.New()
	firstActor, err := NewSessionActor(uuid.New(), scopeID, ScopeKindTenant, uuid.New(), "replacement-first-token")
	if err != nil {
		t.Fatal(err)
	}
	secondActor, err := NewSessionActor(uuid.New(), scopeID, ScopeKindTenant, uuid.New(), "replacement-second-token")
	if err != nil {
		t.Fatal(err)
	}
	request := SecretReplacementRequest{
		Actor: firstActor, ConfigurationScopeID: scopeID, NodeIDs: []uuid.UUID{uuid.New()},
		OriginalRolloutID: uuid.New(), ExpectedRevision: 1,
		GeneratorName: "certificate-publication", GeneratorVersion: "1",
		RequiredCapabilities: []*agentv1.Capability{{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE, ApiVersion: 1,
		}},
		HealthCheck: HealthCheckPolicy{
			ActivationTimeout: time.Minute, ObservationWindow: time.Second,
			RequiredConsecutiveSuccesses: 1,
		},
		Deadline: now.Add(time.Hour), IdempotencyKey: "replacement-semantic-digest",
		RequestID: uuid.NewString(), CorrelationID: uuid.NewString(),
	}
	first, err := normalizeSecretReplacementRequest(request, now)
	if err != nil {
		t.Fatal(err)
	}
	request.Actor = secondActor
	second, err := normalizeSecretReplacementRequest(request, now)
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest != second.Digest {
		t.Fatal("replacement semantic digest depends on actor/session")
	}
	material := SecretReplacementMaterial{
		CanonicalSnapshot: []byte(`{"certificate_revisions":[1]}`),
		PayloadDigest:     sha256.Sum256([]byte("replacement-material")),
	}
	firstMaterialDigest := secretReplacementPublicationDigest(first.Digest, material)
	material.PayloadDigest = sha256.Sum256([]byte("changed-replacement-material"))
	if firstMaterialDigest == secretReplacementPublicationDigest(first.Digest, material) {
		t.Fatal("replacement publication digest does not bind source material")
	}
}

func TestValidateSecretArtifactBindingRejectsEveryIdentityMismatch(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binding := SecretArtifactBinding{
		EventID: uuid.New(), DeploymentID: uuid.New(), RolloutID: uuid.New(), Attempt: 1,
		ConfigVersionID: uuid.New(), ArtifactID: uuid.New(), NodeID: uuid.New(),
		RecipientKeyID: "x25519:" + string(bytes.Repeat([]byte{'a'}, 64)),
	}
	wire := bytes.Repeat([]byte{0x5a}, 64)
	digest := sha256.Sum256(wire)
	recipientID := binding.RecipientKeyID
	valid := ArtifactInput{
		ID: binding.ArtifactID, Kind: agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE,
		WireBytes: wire, SizeBytes: uint64(len(wire)), SHA256: digest[:], Signature: ed25519.Sign(privateKey, wire),
		SigningKeyID: "certificate-test-signer", SigningPublicKey: publicKey,
		SignatureAlgorithm:  agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519,
		Compression:         agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE,
		MediaType:           "application/vnd.cdnca.edge-certificate-bundle+json;version=1",
		EncryptionAlgorithm: agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM,
		RecipientKeyID:      &recipientID,
	}
	if _, err := validateSecretArtifactBinding(valid, binding); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*ArtifactInput)
	}{
		{name: "artifact ID", mutate: func(value *ArtifactInput) { value.ID = uuid.New() }},
		{name: "recipient ID", mutate: func(value *ArtifactInput) { changed := *value.RecipientKeyID + "x"; value.RecipientKeyID = &changed }},
		{name: "kind", mutate: func(value *ArtifactInput) { value.Kind = agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION }},
		{name: "encryption", mutate: func(value *ArtifactInput) {
			value.EncryptionAlgorithm = agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_NONE
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			artifact := valid
			test.mutate(&artifact)
			if _, err := validateSecretArtifactBinding(artifact, binding); err == nil {
				t.Fatal("mismatched artifact was accepted")
			}
		})
	}
}
