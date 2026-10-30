package originauth

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

func TestControlOriginAuthProducerMatchesAgentInstaller(t *testing.T) {
	output := t.TempDir()
	if err := os.Chmod(output, 0o700); err != nil {
		t.Fatal(err)
	}
	producer := exec.CommandContext(t.Context(), "go", "test", "./internal/edgepublish", "-run", "^TestOriginAuthProducerConsumerContract$", "-count=1")
	producer.Dir = "../../../../services/control-api"
	producer.Env = append(os.Environ(), "GOWORK=off", "CDNCA_SECRET_ARTIFACT_CONTRACT_OUTPUT="+output)
	if result, err := producer.CombinedOutput(); err != nil {
		t.Fatalf("Control producer failed: %v\n%s", err, result)
	}
	path := filepath.Join(output, "origin-auth.json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatal("producer fixture is not a private regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	var fixture map[string][]byte
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	defer clear(fixture["recipient_private_key"])
	command := new(agentv1.DeploymentCommand)
	if err := proto.Unmarshal(fixture["command"], command); err != nil {
		t.Fatal(err)
	}
	if len(command.Artifacts) != 1 || !ed25519.Verify(ed25519.PublicKey(fixture["signing_public_key"]), fixture["wire"], command.Artifacts[0].Signature) {
		t.Fatal("Control did not produce a signed artifact")
	}
	descriptor := command.Artifacts[0]
	base := EncryptedProductionSnapshot{ProductionArtifactTransport: ProductionArtifactTransport{
		EventID: command.Event.EventId, DeploymentID: command.DeploymentId, Attempt: command.Attempt,
		ConfigVersionID: command.ConfigVersionId, ArtifactID: descriptor.ArtifactId, NodeID: string(fixture["node_id"]),
		RecipientKeyID: descriptor.GetRecipientKeyId(), SigningKeyID: descriptor.SigningKeyId, MediaType: descriptor.MediaType,
		Kind: descriptor.Kind, SizeBytes: descriptor.SizeBytes, SHA256: descriptor.Sha256, Signature: descriptor.Signature,
		SigningPublicKey: ed25519.PublicKey(fixture["signing_public_key"]), SignatureAlgorithm: descriptor.SignatureAlgorithm,
		Compression: descriptor.Compression, EncryptionAlgorithm: descriptor.EncryptionAlgorithm,
	}, WireBytes: fixture["wire"], RecipientPrivateKey: fixture["recipient_private_key"],
		ExpectedNodeID: string(fixture["node_id"]), ExpectedTenantScopeID: string(fixture["tenant_scope_id"]), ExpectedPublicationRevision: 9}
	for _, scenario := range []string{"valid", "bad-signature", "tampered-wire", "wrong-recipient", "event-replay", "attempt-replay", "configuration-replay", "node-binding-replay", "wrong-scope", "wrong-node", "wrong-revision"} {
		t.Run(scenario, func(t *testing.T) {
			candidate := base
			candidate.Signature = bytes.Clone(base.Signature)
			candidate.WireBytes = bytes.Clone(base.WireBytes)
			switch scenario {
			case "bad-signature":
				candidate.Signature[0] ^= 0x80
			case "tampered-wire":
				candidate.WireBytes[len(candidate.WireBytes)-1] ^= 0x80
			case "wrong-recipient":
				_, candidate.RecipientPrivateKey = site09Recipient(t)
				defer clear(candidate.RecipientPrivateKey)
			case "event-replay":
				candidate.EventID = uuid.NewString()
			case "attempt-replay":
				candidate.Attempt++
			case "configuration-replay":
				candidate.ConfigVersionID = uuid.NewString()
			case "node-binding-replay":
				candidate.NodeID = uuid.NewString()
				candidate.ExpectedNodeID = candidate.NodeID
			case "wrong-scope":
				candidate.ExpectedTenantScopeID = uuid.NewString()
			case "wrong-node":
				candidate.ExpectedNodeID = uuid.NewString()
			case "wrong-revision":
				candidate.ExpectedPublicationRevision++
			}
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			runtime := &site09Runtime{}
			installer, err := NewProductionSnapshotInstaller(filepath.Join(root, "policy"), filepath.Join(root, "credentials"), runtime)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "valid" {
				plaintext, openErr := openProductionArtifact(candidate)
				if openErr != nil {
					t.Fatalf("Control origin artifact cannot be opened by Agent: %v", openErr)
				}
				defer clear(plaintext)
				document, decodeErr := decodeProductionSnapshot(plaintext)
				if decodeErr != nil {
					t.Fatalf("Control origin snapshot cannot be decoded by Agent: %v", decodeErr)
				}
				defer clearProductionCredentials(document.Credentials)
				if bindErr := validateProductionActivation(document, candidate); bindErr != nil {
					t.Fatalf("Control origin activation cannot be bound by Agent: %v", bindErr)
				}
			}
			// The production installer verifies, decrypts, decodes and binds
			// this actual Control artifact before persisting policy/credentials.
			publication, err := installer.Install(t.Context(), candidate)
			if scenario != "valid" {
				if err == nil || len(runtime.activations) != 0 {
					t.Fatal("invalid artifact reached activation")
				}
				if _, statErr := os.Stat(filepath.Join(root, "policy", "current.json")); !os.IsNotExist(statErr) {
					t.Fatal("rejected artifact advanced the current policy")
				}
				return
			}
			if err != nil {
				t.Fatalf("Control artifact rejected by Agent installer: %v", err)
			}
			if publication.PolicyVersion != 9 || len(runtime.activations) != 1 {
				t.Fatal("origin auth revision was not activated")
			}
			policy, err := os.ReadFile(publication.CurrentPath)
			if err != nil || bytes.Contains(policy, []byte("AKIA-SITE09")) || !bytes.Contains(policy, fixture["credential_revision_ref"]) {
				t.Fatal("origin auth policy identity changed or contains credentials")
			}
			keyPath := filepath.Join(root, "credentials", base.ExpectedTenantScopeID, string(fixture["credential_revision_ref"])+".json")
			keyInfo, err := os.Stat(keyPath)
			if err != nil || keyInfo.Mode().Perm() != 0o600 {
				t.Fatal("origin credentials are missing or not private")
			}
		})
	}
}
