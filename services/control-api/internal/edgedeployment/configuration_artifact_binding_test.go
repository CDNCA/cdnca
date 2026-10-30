package edgedeployment

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

func TestConfigurationArtifactValidationRequiresHPKEForCurrentRuntime(t *testing.T) {
	artifact := validEncryptedConfigurationArtifact(t)
	if _, err := validateArtifact(artifact); err != nil {
		t.Fatalf("encrypted current configuration rejected: %v", err)
	}
	plaintext := artifact
	plaintext.EncryptionAlgorithm = agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_NONE
	plaintext.RecipientKeyID = nil
	if _, err := validateArtifact(plaintext); err == nil {
		t.Fatal("plaintext current configuration accepted")
	}
	legacy := plaintext
	legacy.MediaType = "application/vnd.cdnca.edgeconfig"
	if _, err := validateArtifact(legacy); err != nil {
		t.Fatalf("explicit legacy plaintext compatibility rejected: %v", err)
	}
}

func TestRolloutNodeArtifactBindingsAreExactAndDigestBound(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	nodes := []uuid.UUID{uuid.New(), uuid.New()}
	configID := uuid.New()
	bindings := []NodeArtifactBinding{
		testNodeArtifactBinding(nodes[0], configID), testNodeArtifactBinding(nodes[1], configID),
	}
	bindings[1].RecipientKeyID = "x25519:" + string(bytes.Repeat([]byte{'b'}, 64))
	request := CreateRolloutRequest{
		ConfigurationScopeID: uuid.New(), ConfigVersionID: configID,
		Action: agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY, NodeIDs: nodes,
		NodeArtifactBindings: bindings,
		HealthCheck:          HealthCheckPolicy{ActivationTimeout: time.Minute, ObservationWindow: time.Minute, RequiredConsecutiveSuccesses: 1},
		Deadline:             now.Add(time.Hour), IdempotencyKey: "configuration-hpke-binding",
		RequestID: uuid.NewString(), CorrelationID: uuid.NewString(), MaxAttempts: 1, ContractVersion: 1,
	}
	first, err := normalizeRolloutRequest(request, now)
	if err != nil {
		t.Fatal(err)
	}
	changed := request
	changed.NodeArtifactBindings = append([]NodeArtifactBinding(nil), bindings...)
	changed.NodeArtifactBindings[0].RecipientKeyID = "x25519:" + string(bytes.Repeat([]byte{'0'}, 64))
	second, err := normalizeRolloutRequest(changed, now)
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest == second.Digest {
		t.Fatal("rollout digest ignored recipient binding")
	}
	for _, mutate := range []func(*CreateRolloutRequest){
		func(value *CreateRolloutRequest) { value.NodeArtifactBindings = value.NodeArtifactBindings[:1] },
		func(value *CreateRolloutRequest) { value.NodeArtifactBindings[0].NodeID = uuid.New() },
		func(value *CreateRolloutRequest) {
			value.NodeArtifactBindings[1].ArtifactID = value.NodeArtifactBindings[0].ArtifactID
		},
		func(value *CreateRolloutRequest) {
			value.NodeArtifactBindings[1].DeploymentID = value.NodeArtifactBindings[0].DeploymentID
		},
		func(value *CreateRolloutRequest) {
			value.NodeArtifactBindings[1].EventID = value.NodeArtifactBindings[0].EventID
		},
		func(value *CreateRolloutRequest) {
			value.NodeArtifactBindings[1].RecipientKeyID = value.NodeArtifactBindings[0].RecipientKeyID
		},
		func(value *CreateRolloutRequest) { value.NodeArtifactBindings[0].Attempt = 2 },
		func(value *CreateRolloutRequest) { value.MaxAttempts = 2 },
	} {
		candidate := request
		candidate.NodeArtifactBindings = append([]NodeArtifactBinding(nil), bindings...)
		mutate(&candidate)
		if _, err := normalizeRolloutRequest(candidate, now); err == nil {
			t.Fatal("invalid per-node binding accepted")
		}
	}
}

func validEncryptedConfigurationArtifact(t *testing.T) ArtifactInput {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wire := bytes.Repeat([]byte{0x5a}, 80)
	digest := sha256.Sum256(wire)
	recipient := "x25519:" + string(bytes.Repeat([]byte{'1'}, 64))
	return ArtifactInput{
		ID: uuid.New(), Kind: agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION,
		WireBytes: wire, SizeBytes: uint64(len(wire)), SHA256: digest[:], Signature: ed25519.Sign(privateKey, wire),
		SigningKeyID: "configuration-artifact-test-key", SigningPublicKey: publicKey,
		SignatureAlgorithm: agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519,
		Compression:        agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE, MediaType: siteRuntimeV2MediaType,
		EncryptionAlgorithm: agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM,
		RecipientKeyID:      &recipient,
	}
}

func testNodeArtifactBinding(nodeID, configID uuid.UUID) NodeArtifactBinding {
	return NodeArtifactBinding{
		NodeID: nodeID, DeploymentID: uuid.New(), EventID: uuid.New(), Attempt: 1,
		ConfigVersionID: configID, ArtifactID: uuid.New(),
		RecipientKeyID: "x25519:" + string(bytes.Repeat([]byte{'a'}, 64)),
	}
}
