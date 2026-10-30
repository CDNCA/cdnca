package gatewayclient

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/urlauth"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

func TestURLAuthGatewayFetchesVerifiesDecryptsInstallsAndPreservesLKG(t *testing.T) {
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
	runtimeRoot := filepath.Join(root, "state", "urlauth")
	runtime, err := urlauth.NewArtifactRuntime(runtimeRoot)
	if err != nil {
		t.Fatal(err)
	}
	config := testClientConfig(filepath.Join(root, "journal"))
	config.ArtifactEncryptionKeyID = recipientID
	config.ArtifactDecryptionPrivateKey = privateKey
	client, err := New(config, &failingDialer{}, noOpManager{}, trust, WithURLAuthArtifactConsumer(runtime))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	command, wire := encryptedURLAuthCommand(t, signingKey, privateKey, recipientID, runtimeRoot, 7)
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
		t.Fatalf("terminal URL auth status mismatch: statuses=%v done=%v", statuses, persisted.ExecutionDone)
	}
	policyID := "01990000-0000-7000-8000-000000000005"
	currentPath := filepath.Join(runtimeRoot, "policies", policyID, "current.json")
	baseline, err := os.ReadFile(currentPath)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(filepath.Join(runtimeRoot, "keys", policyID, "k-current-7.key")); err != nil ||
		!info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("installed URL auth key is missing or unsafe: info=%v err=%v", info, err)
	}

	rejected, rejectedWire := encryptedURLAuthCommand(t, signingKey, privateKey, recipientID, runtimeRoot, 8)
	wrongScope := uuid.NewString()
	rejected.ConfigurationScopeId = &wrongScope
	rejectedRecord, _, err := client.store.putCommand(rejected, deliveredStatus(rejected))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.executeRecord(t.Context(), newFetchGatewayClient(t, rejectedWire), rejectedRecord.RecordKey, 1<<20); err != nil {
		t.Fatal(err)
	}
	rejectedRecord, err = client.store.record(rejectedRecord.RecordKey)
	if err != nil {
		t.Fatal(err)
	}
	rejectedStatuses, err := statusesFromRecord(rejectedRecord)
	if err != nil {
		t.Fatal(err)
	}
	last := rejectedStatuses[len(rejectedStatuses)-1]
	if last.State != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED || !last.RunningConfigUnchanged {
		t.Fatalf("cross-tenant URL auth artifact was not rejected fail-closed: %+v", last)
	}
	current, err := os.ReadFile(currentPath)
	if err != nil || string(current) != string(baseline) {
		t.Fatalf("URL auth LKG changed after rejection: err=%v", err)
	}
}

func encryptedURLAuthCommand(t *testing.T, signingKey ed25519.PrivateKey, privateKey []byte, recipientID, runtimeRoot string, policyVersion uint64) (*agentv1.DeploymentCommand, []byte) {
	t.Helper()
	command, _ := signedBundleTestCommand(t, signingKey)
	command.ConfigVersionId = uuid.NewString()
	tenantID := "01990000-0000-7000-8000-000000000006"
	scopeID := "01990000-0000-7000-8000-000000000016"
	command.ConfigurationScopeId = &scopeID
	descriptor := command.Artifacts[0]
	descriptor.Kind = agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE
	descriptor.MediaType = URLAuthArtifactMediaType
	descriptor.Compression = agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE
	policyID := "01990000-0000-7000-8000-000000000005"
	siteID := "01990000-0000-7000-8000-000000000007"
	keyID := "k-current-" + strconv.FormatUint(policyVersion, 10)
	keyFile := filepath.Join(runtimeRoot, "keys", policyID, keyID+".key")
	document := urlauth.ArtifactDocument{
		SchemaVersion: urlauth.ArtifactSchemaVersion,
		Activation: urlauth.ArtifactActivation{
			SchemaVersion: urlauth.ActivationSchemaVersion, EventID: command.Event.EventId, DeploymentID: command.DeploymentId,
			Attempt: command.Attempt, ConfigVersionID: command.ConfigVersionId, ArtifactID: descriptor.ArtifactId,
			RecipientKeyID: recipientID, PolicyID: policyID, TenantID: tenantID, SiteID: siteID, PolicyVersion: policyVersion,
			ConfigurationScopeID: scopeID,
		},
		Policy: urlauth.Policy{
			SchemaVersion: urlauth.SchemaVersion, PolicyVersion: policyVersion, TenantID: tenantID, SiteID: siteID,
			Algorithm: urlauth.AlgorithmHMACSHA256, SignatureParameter: "sig", ExpirationParameter: "exp", KeyIDParameter: "kid",
			MaxValiditySeconds: 300, ExcludedQueryParameters: []string{}, TrustedProxies: []string{},
			CurrentKey: urlauth.KeyRef{KeyID: keyID, KeyFile: keyFile},
		},
		Keys: []urlauth.ArtifactKey{{KeyID: keyID, KeyFile: keyFile, Secret: []byte("secret-current-32-bytes-exactly!")}},
	}
	plaintext, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return command, encryptTestArtifact(t, command, descriptor, plaintext, privateKey, recipientID, signingKey)
}
