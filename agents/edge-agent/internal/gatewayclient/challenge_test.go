package gatewayclient

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/challenge"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

func TestChallengeGatewayFetchesVerifiesInstallsAndRecordsTerminalStatus(t *testing.T) {
	root := secureTempDir(t)
	publicKey, signingKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, recipientID := newArtifactRecipient(t)
	trust, err := NewTrustStore(map[string]crypto.PublicKey{"test-signing-key": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	stateRoot := filepath.Join(root, "state")
	if err := os.Mkdir(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	installer, err := challenge.NewArtifactInstaller(stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	config := testClientConfig(filepath.Join(root, "journal"))
	config.ArtifactEncryptionKeyID = recipientID
	config.ArtifactDecryptionPrivateKey = privateKey
	client, err := New(config, &failingDialer{}, noOpManager{}, trust, WithChallengeConsumer(installer))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	command, wire := encryptedChallengeCommand(t, signingKey, privateKey, recipientID, nil)
	record, _, err := client.store.putCommand(command, deliveredStatus(command))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.executeRecord(t.Context(), newFetchGatewayClient(t, wire), record.RecordKey, 1<<20); err != nil {
		t.Fatal(err)
	}
	persisted, err := client.store.record(record.RecordKey)
	if err != nil {
		t.Fatal(err)
	}
	statuses, err := statusesFromRecord(persisted)
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 5 || statuses[4].State != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY || !persisted.ExecutionDone {
		t.Fatalf("terminal challenge status mismatch: statuses=%v done=%v", statuses, persisted.ExecutionDone)
	}
	policy := filepath.Join(root, "state", "challenge", "policies", "01990000-0000-7000-8000-000000000005", "versions", "00000000000000000007.json")
	if info, err := os.Lstat(policy); err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("sealed challenge policy is missing or unsafe: info=%v err=%v", info, err)
	}
}

func TestChallengeGatewayRejectsMismatchedActivationWithoutChangingInstalledLKG(t *testing.T) {
	root := secureTempDir(t)
	publicKey, signingKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, recipientID := newArtifactRecipient(t)
	trust, err := NewTrustStore(map[string]crypto.PublicKey{"test-signing-key": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	stateRoot := filepath.Join(root, "state")
	if err := os.Mkdir(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	installer, err := challenge.NewArtifactInstaller(stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	config := testClientConfig(filepath.Join(root, "journal"))
	config.ArtifactEncryptionKeyID = recipientID
	config.ArtifactDecryptionPrivateKey = privateKey
	client, err := New(config, &failingDialer{}, noOpManager{}, trust, WithChallengeConsumer(installer))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	command, wire := encryptedChallengeCommand(t, signingKey, privateKey, recipientID, func(document *challenge.ArtifactDocument) {
		document.Activation.DeploymentID = uuid.NewString()
	})
	record, _, err := client.store.putCommand(command, deliveredStatus(command))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.executeRecord(context.Background(), newFetchGatewayClient(t, wire), record.RecordKey, 1<<20); err != nil {
		t.Fatal(err)
	}
	persisted, err := client.store.record(record.RecordKey)
	if err != nil {
		t.Fatal(err)
	}
	statuses, err := statusesFromRecord(persisted)
	if err != nil {
		t.Fatal(err)
	}
	last := statuses[len(statuses)-1]
	if last.State != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED || !last.RunningConfigUnchanged {
		t.Fatalf("invalid activation was not rejected fail-closed: %+v", last)
	}
}

func TestClientAutomaticallyUsesDeploymentStateRootForChallengeArtifacts(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := NewTrustStore(map[string]crypto.PublicKey{"test-signing-key": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	root := secureTempDir(t)
	stateRoot := filepath.Join(root, "state")
	if err := os.Mkdir(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	client, err := New(testClientConfig(filepath.Join(root, "journal")), &failingDialer{}, stateRootManager{root: stateRoot}, trust)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if client.challenge == nil {
		t.Fatal("deployment state root did not install the production challenge consumer")
	}
}

type stateRootManager struct {
	noOpManager
	root string
}

func (manager stateRootManager) StateRoot() string { return manager.root }

var _ interface{ StateRoot() string } = (*deployment.Manager)(nil)

func encryptedChallengeCommand(t *testing.T, signingKey ed25519.PrivateKey, privateKey []byte, recipientID string, mutate func(*challenge.ArtifactDocument)) (*agentv1.DeploymentCommand, []byte) {
	t.Helper()
	command, _ := signedBundleTestCommand(t, signingKey)
	command.ConfigVersionId = "01990000-0000-7000-8000-000000000003"
	descriptor := command.Artifacts[0]
	descriptor.Kind = agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE
	descriptor.MediaType = ChallengeArtifactMediaType
	document := challenge.ArtifactDocument{
		SchemaVersion: challenge.ArtifactSchemaVersion,
		Activation: challenge.ArtifactActivation{
			SchemaVersion: challenge.ActivationSchemaVersion, EventID: command.Event.EventId, DeploymentID: command.DeploymentId,
			Attempt: command.Attempt, ConfigVersionID: command.ConfigVersionId, ArtifactID: descriptor.ArtifactId,
			RecipientKeyID: recipientID, PolicyID: "01990000-0000-7000-8000-000000000005",
			TenantID: "01990000-0000-7000-8000-000000000006", PolicyVersion: 7,
		},
		Policy: challenge.Policy{
			SchemaVersion: challenge.SchemaVersion, PolicyVersion: 7, Algorithm: challenge.AlgorithmHMACSHA256,
			CookieName: "__Host-cdnca_challenge", TrustedProxies: []string{}, BypassRoutes: []challenge.BypassRoute{},
			CurrentKey: challenge.KeyRef{KeyID: "key-current"}, PreviousKey: &challenge.KeyRef{KeyID: "key-previous"},
			Rules: []challenge.Rule{{RuleID: "01990000-0000-7000-8000-000000000007", Priority: 10,
				TenantID: "01990000-0000-7000-8000-000000000006", SiteID: "01990000-0000-7000-8000-000000000008",
				Host: "edge.example.test", Mode: challenge.ModeClick, ChallengeTTLSeconds: 60, PassTTLSeconds: 300,
				ClockSkewSeconds: 10, AttemptsPerNonce: 1, FailureWindowSeconds: 60, MaxFailuresPerWindow: 5,
				IPBinding: challenge.IPBindingExact, BindUserAgent: true}},
		},
		Keys: []challenge.ArtifactKey{{KeyID: "key-current", Secret: []byte("current-challenge-secret-material-01")},
			{KeyID: "key-previous", Secret: []byte("previous-challenge-secret-material-1")}},
	}
	if mutate != nil {
		mutate(&document)
	}
	plaintext, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return command, encryptTestArtifact(t, command, descriptor, plaintext, privateKey, recipientID, signingKey)
}
