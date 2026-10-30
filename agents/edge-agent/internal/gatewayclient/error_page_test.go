package gatewayclient

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/errorpage"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type site13ErrorPageConsumer struct {
	reconciled int
	installed  int
	binding    errorpage.ProductionSnapshotBinding
}

func (consumer *site13ErrorPageConsumer) Reconcile(context.Context) (errorpage.ReconcileReceipt, error) {
	consumer.reconciled++
	return errorpage.ReconcileReceipt{}, nil
}

func (consumer *site13ErrorPageConsumer) Install(_ context.Context, bundle errorpage.SignedProductionSnapshot, expected errorpage.ProductionSnapshotBinding) (errorpage.ProductionSnapshotActivationReceipt, error) {
	consumer.installed++
	consumer.binding = expected
	return errorpage.ProductionSnapshotActivationReceipt{
		Schema: errorpage.ProductionSnapshotActivationReceiptSchema, State: errorpage.ActivationStateActivated,
		Binding: expected, BundleSHA256: bundle.SHA256, ActiveDigest: bundle.SHA256,
	}, nil
}

func TestSITE13ErrorPageGatewayFetchesInstallsReconcilesAndPersistsStatuses(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := NewTrustStore(map[string]crypto.PublicKey{"test-signing-key": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	consumer := new(site13ErrorPageConsumer)
	client, err := New(site13ClientConfig(filepath.Join(site13SecureTempDir(t), "journal")), site13FailingDialer{}, site13NoOpManager{}, trust,
		WithErrorPageArtifactConsumer(consumer))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if consumer.reconciled != 1 {
		t.Fatalf("startup reconcile count=%d", consumer.reconciled)
	}
	command, wire, binding := signedErrorPageCommand(t, privateKey)
	record, _, err := client.store.putCommand(command, deliveredStatus(command))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.executeRecord(t.Context(), site13FetchGatewayClient(t, wire), record.RecordKey, 1<<20); err != nil {
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
	if consumer.installed != 1 || consumer.binding != binding || len(statuses) != 5 ||
		statuses[4].State != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY || !persisted.ExecutionDone {
		t.Fatalf("installed=%d binding=%+v statuses=%+v done=%t", consumer.installed, consumer.binding, statuses, persisted.ExecutionDone)
	}
}

func TestSITE13ErrorPageCommandBindingRejectsCrossConfigBeforeInstall(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := NewTrustStore(map[string]crypto.PublicKey{"test-signing-key": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	consumer := new(site13ErrorPageConsumer)
	client, err := New(site13ClientConfig(filepath.Join(site13SecureTempDir(t), "journal")), site13FailingDialer{}, site13NoOpManager{}, trust,
		WithErrorPageArtifactConsumer(consumer))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	command, wire, _ := signedErrorPageCommand(t, privateKey)
	command.ConfigVersionId = uuid.NewString()
	record, _, err := client.store.putCommand(command, deliveredStatus(command))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.executeRecord(t.Context(), site13FetchGatewayClient(t, wire), record.RecordKey, 1<<20); err != nil {
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
	if consumer.installed != 0 || statuses[len(statuses)-1].State != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED ||
		!statuses[len(statuses)-1].RunningConfigUnchanged {
		t.Fatalf("installed=%d statuses=%+v", consumer.installed, statuses)
	}
}

func signedErrorPageCommand(t *testing.T, privateKey ed25519.PrivateKey) (*agentv1.DeploymentCommand, []byte, errorpage.ProductionSnapshotBinding) {
	t.Helper()
	body := []byte("custom not found\n")
	bodyDigest := sha256.Sum256(body)
	configurationScopeID := uuid.NewString()
	siteID := uuid.NewString()
	binding := errorpage.ProductionSnapshotBinding{
		TenantID: uuid.NewString(), ConfigurationScopeID: configurationScopeID, PublicationRevision: 7,
	}
	document := errorpage.ProductionSnapshotDocument{
		Schema: errorpage.ProductionSnapshotSchema, Binding: binding,
		Global: errorpage.ProductionSnapshotScope{Rules: []errorpage.ProductionSnapshotRule{}},
		Sites: []errorpage.ProductionSnapshotSite{{SiteKey: siteID, Rules: []errorpage.ProductionSnapshotRule{{
			ID: uuid.NewString(), Category: errorpage.CategoryEdgeRoute, Match: errorpage.StatusMatch{Codes: []int{404}},
			Resource: errorpage.ProductionSnapshotResource{MIMEType: "text/plain", Size: int64(len(body)), SHA256: hex.EncodeToString(bodyDigest[:]), Body: body},
		}}}},
	}
	wire, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(wire)
	command := &agentv1.DeploymentCommand{
		Event: &commonv1.EventMetadata{
			EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now(), CorrelationId: uuid.NewString(),
		},
		DeploymentId: uuid.NewString(), Attempt: 1, RolloutId: uuid.NewString(),
		Action: agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY,
		Artifacts: []*agentv1.ArtifactDescriptor{{
			Kind: agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION, SigningKeyId: "test-signing-key",
			SignatureAlgorithm:  agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519,
			Compression:         agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE,
			EncryptionAlgorithm: agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_NONE,
		}},
		RequiredCapabilities: []*agentv1.Capability{
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE, ApiVersion: 1},
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_CONFIG_PRECHECK, ApiVersion: 1},
		},
		HealthCheck: &agentv1.HealthCheckPolicy{
			ActivationTimeoutDuration: durationpb.New(time.Second), ObservationWindowDuration: durationpb.New(time.Second),
			RequiredConsecutiveSuccesses: 1,
		},
		DeadlineTime: timestamppb.New(time.Now().Add(time.Hour)),
	}
	command.ConfigurationScopeId = &configurationScopeID
	command.ConfigVersionId, command.Artifacts[0].ArtifactId = errorPageCommandIdentity(configurationScopeID, binding, digest)
	descriptor := command.Artifacts[0]
	descriptor.MediaType = ErrorPageArtifactMediaType
	descriptor.SizeBytes = uint64(len(wire))
	descriptor.Sha256 = bytes.Clone(digest[:])
	descriptor.Signature = ed25519.Sign(privateKey, wire)
	return command, wire, binding
}

type site13FailingDialer struct{}

func (site13FailingDialer) Dial(context.Context) (Connection, error) {
	return nil, errors.New("unused")
}

type site13NoOpManager struct{}

func (site13NoOpManager) Process(context.Context, deployment.Command) (deployment.Result, error) {
	return deployment.Result{}, nil
}

func (site13NoOpManager) Pointers() (deployment.Pointers, error) { return deployment.Pointers{}, nil }

func site13ClientConfig(journalDir string) Config {
	config := DefaultConfig()
	config.NodeID = uuid.NewString()
	config.BootID = uuid.NewString()
	config.ArtifactEncryptionKeyID = "artifact-key"
	config.JournalDir = journalDir
	config.Capabilities = &agentv1.AgentCapabilities{
		AgentVersion: "site13-test",
		Features: []*agentv1.Capability{
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE, ApiVersion: 1},
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_CONFIG_PRECHECK, ApiVersion: 1},
		},
	}
	return config
}

func site13SecureTempDir(t *testing.T) string {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

type site13ArtifactServer struct {
	agentv1.UnimplementedAgentGatewayServiceServer
	wire []byte
}

func (server *site13ArtifactServer) FetchArtifact(request *agentv1.FetchArtifactRequest, stream grpc.ServerStreamingServer[agentv1.FetchArtifactResponse]) error {
	content := server.wire[request.Offset:]
	digest := sha256.Sum256(content)
	return stream.Send(&agentv1.FetchArtifactResponse{Chunk: &agentv1.ArtifactChunk{
		RequestId: request.Request.RequestId, ArtifactId: request.ArtifactId, Offset: request.Offset,
		Data: content, ChunkSha256: digest[:], TotalSizeBytes: uint64(len(server.wire)), EndOfArtifact: true,
	}})
}

func site13FetchGatewayClient(t *testing.T, wire []byte) agentv1.AgentGatewayServiceClient {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	agentv1.RegisterAgentGatewayServiceServer(server, &site13ArtifactServer{wire: wire})
	go func() { _ = server.Serve(listener) }()
	connection, err := grpc.NewClient("passthrough:///site13", grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = connection.Close()
		server.Stop()
		_ = listener.Close()
	})
	return agentv1.NewAgentGatewayServiceClient(connection)
}
