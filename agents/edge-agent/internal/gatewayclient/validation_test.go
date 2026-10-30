package gatewayclient

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestUnsupportedCommandsFailClosed(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	command, _ := signedTestCommand(t, privateKey)
	config := testClientConfig(filepath.Join(secureTempDir(t), "journal"))
	tests := []struct {
		name   string
		change func(*agentv1.DeploymentCommand)
	}{
		{name: "extra artifact", change: func(value *agentv1.DeploymentCommand) {
			value.Artifacts = append(value.Artifacts, proto.Clone(value.Artifacts[0]).(*agentv1.ArtifactDescriptor))
		}},
		{name: "secret bundle", change: func(value *agentv1.DeploymentCommand) {
			value.Artifacts[0].Kind = agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE
		}},
		{name: "encrypted", change: func(value *agentv1.DeploymentCommand) {
			value.Artifacts[0].EncryptionAlgorithm = agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM
		}},
		{name: "unknown media", change: func(value *agentv1.DeploymentCommand) { value.Artifacts[0].MediaType = "application/octet-stream" }},
		{name: "missing capability", change: func(value *agentv1.DeploymentCommand) { value.RequiredCapabilities[0].ApiVersion = 2 }},
		{name: "expired", change: func(value *agentv1.DeploymentCommand) {
			value.DeadlineTime = timestamppb.New(time.Now().Add(-time.Second))
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := proto.Clone(command).(*agentv1.DeploymentCommand)
			test.change(value)
			if err := validateRoutedCommand(value, config, time.Now()); err == nil {
				t.Fatal("validateCommand() accepted unsupported input")
			}
		})
	}
}

func TestRollbackValidationRequiresBaselineAndRejectsArtifacts(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	command, _ := signedTestCommand(t, privateKey)
	baseline := "cfg-v2"
	command.Action = agentv1.DeploymentAction_DEPLOYMENT_ACTION_ROLLBACK
	command.PreviousConfigVersionId = &baseline
	command.Artifacts = nil
	config := testClientConfig(filepath.Join(secureTempDir(t), "journal"))
	if err := validateRoutedCommand(command, config, time.Now()); err != nil {
		t.Fatalf("validateCommand(rollback) error = %v", err)
	}
	command.Artifacts = []*agentv1.ArtifactDescriptor{{
		ArtifactId: "not-a-uuid", Sha256: []byte("not-a-digest"), Signature: []byte("forged"),
	}}
	if err := validateRoutedCommand(command, config, time.Now()); err == nil {
		t.Fatal("validateCommand() accepted rollback artifacts")
	}
	command.Artifacts = nil
	command.PreviousConfigVersionId = nil
	if err := validateRoutedCommand(command, config, time.Now()); err == nil {
		t.Fatal("validateCommand() accepted rollback without a baseline")
	}
}

func TestValidateCommandReconcileReusesApplyPolicy(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	command, _ := signedTestCommand(t, privateKey)
	command.Action = agentv1.DeploymentAction_DEPLOYMENT_ACTION_RECONCILE
	config := testClientConfig(filepath.Join(secureTempDir(t), "journal"))
	if err := validateRoutedCommand(command, config, time.Now()); err != nil {
		t.Fatalf("validateCommand(reconcile) error = %v", err)
	}

	tests := []struct {
		name   string
		change func(*agentv1.DeploymentCommand, *Config)
	}{
		{name: "missing artifact", change: func(value *agentv1.DeploymentCommand, _ *Config) {
			value.Artifacts = nil
		}},
		{name: "extra artifact", change: func(value *agentv1.DeploymentCommand, _ *Config) {
			value.Artifacts = append(value.Artifacts, proto.Clone(value.Artifacts[0]).(*agentv1.ArtifactDescriptor))
		}},
		{name: "wrong kind", change: func(value *agentv1.DeploymentCommand, _ *Config) {
			value.Artifacts[0].Kind = agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE
		}},
		{name: "wrong media type", change: func(value *agentv1.DeploymentCommand, _ *Config) {
			value.Artifacts[0].MediaType = "application/octet-stream"
		}},
		{name: "plaintext recipient", change: func(value *agentv1.DeploymentCommand, _ *Config) {
			value.Artifacts[0].RecipientKeyId = proto.String("unexpected-key")
		}},
		{name: "encrypted recipient unavailable", change: func(value *agentv1.DeploymentCommand, _ *Config) {
			value.Artifacts[0].EncryptionAlgorithm = agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM
			value.Artifacts[0].RecipientKeyId = proto.String("missing-key")
		}},
		{name: "zero size", change: func(value *agentv1.DeploymentCommand, _ *Config) {
			value.Artifacts[0].SizeBytes = 0
		}},
		{name: "oversized key envelope", change: func(value *agentv1.DeploymentCommand, config *Config) {
			config.MaxArtifactBytes = value.Artifacts[1].SizeBytes - 1
		}},
		{name: "missing digest", change: func(value *agentv1.DeploymentCommand, _ *Config) {
			value.Artifacts[0].Sha256 = nil
		}},
		{name: "missing signature", change: func(value *agentv1.DeploymentCommand, _ *Config) {
			value.Artifacts[0].Signature = nil
		}},
		{name: "invalid signing key", change: func(value *agentv1.DeploymentCommand, _ *Config) {
			value.Artifacts[0].SigningKeyId = "bad/key"
		}},
		{name: "unsupported signature", change: func(value *agentv1.DeploymentCommand, _ *Config) {
			value.Artifacts[0].SignatureAlgorithm = agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_UNSPECIFIED
		}},
		{name: "unsupported compression", change: func(value *agentv1.DeploymentCommand, _ *Config) {
			value.Artifacts[0].Compression = agentv1.ArtifactCompression(99)
		}},
		{name: "missing health policy", change: func(value *agentv1.DeploymentCommand, _ *Config) {
			value.HealthCheck = nil
		}},
		{name: "expired deadline", change: func(value *agentv1.DeploymentCommand, _ *Config) {
			value.DeadlineTime = timestamppb.New(time.Now().Add(-time.Second))
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := proto.Clone(command).(*agentv1.DeploymentCommand)
			caseConfig := config
			test.change(value, &caseConfig)
			if err := validateRoutedCommand(value, caseConfig, time.Now()); err == nil {
				t.Fatal("validateCommand(reconcile) accepted invalid input")
			}
		})
	}
}

func TestStrictBundleAndChunkValidation(t *testing.T) {
	if err := rejectDuplicateJSONKeys([]byte(`{"version":1,"version":1}`)); err == nil {
		t.Fatal("duplicate JSON object key was accepted")
	}
	content := []byte("chunk")
	digest := sha256.Sum256(content)
	descriptor := &agentv1.ArtifactDescriptor{ArtifactId: uuid.NewString(), SizeBytes: uint64(len(content))}
	chunk := &agentv1.ArtifactChunk{
		RequestId: uuid.NewString(), ArtifactId: descriptor.ArtifactId, Data: content,
		ChunkSha256: digest[:], TotalSizeBytes: descriptor.SizeBytes, EndOfArtifact: true,
	}
	if err := validateArtifactChunk(chunk, chunk.RequestId, descriptor, 0, uint32(len(content))); err != nil {
		t.Fatalf("valid chunk error = %v", err)
	}
	corrupt := proto.Clone(chunk).(*agentv1.ArtifactChunk)
	corrupt.ChunkSha256[0] ^= 0xff
	if err := validateArtifactChunk(corrupt, chunk.RequestId, descriptor, 0, uint32(len(content))); !errors.Is(err, ErrArtifactIntegrity) {
		t.Fatalf("corrupt chunk error = %v, want artifact integrity error", err)
	}
}

type failingDialer struct {
	calls atomic.Int32
}

func (d *failingDialer) Dial(context.Context) (Connection, error) {
	d.calls.Add(1)
	return nil, errors.New("unavailable")
}

type noOpManager struct{}

func (noOpManager) Process(context.Context, deployment.Command) (deployment.Result, error) {
	return deployment.Result{}, nil
}

func (noOpManager) Pointers() (deployment.Pointers, error) { return deployment.Pointers{}, nil }

func TestReconnectBackoffIsContextCancelable(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := NewTrustStore(map[string]crypto.PublicKey{"key": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	config := testClientConfig(filepath.Join(secureTempDir(t), "journal"))
	config.InitialBackoff = time.Second
	config.MaximumBackoff = time.Second
	dialer := &failingDialer{}
	client, err := New(config, dialer, noOpManager{}, trust)
	if err != nil {
		t.Fatal(err)
	}
	client.jitter = func(value time.Duration) time.Duration { return value }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	deadline := time.Now().Add(time.Second)
	for dialer.calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	started := time.Now()
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context canceled", err)
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("Run() cancellation took %v", elapsed)
	}
}

// blockingDialer models a gateway that stays unreachable: a blocking gRPC dial
// only returns when its context ends.
type blockingDialer struct {
	calls     atomic.Int32
	deadlines atomic.Int32
}

func (d *blockingDialer) Dial(ctx context.Context) (Connection, error) {
	d.calls.Add(1)
	if _, ok := ctx.Deadline(); ok {
		d.deadlines.Add(1)
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

// A dial against an unreachable gateway must give up after HandshakeTimeout so
// the client's own MaximumBackoff bounds reconnect latency once the gateway
// returns, instead of gRPC's internal backoff growing for the whole outage.
func TestReconnectDialIsBoundedByHandshakeTimeout(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := NewTrustStore(map[string]crypto.PublicKey{"key": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	config := testClientConfig(filepath.Join(secureTempDir(t), "journal"))
	config.HandshakeTimeout = 20 * time.Millisecond
	config.InitialBackoff = 5 * time.Millisecond
	config.MaximumBackoff = 5 * time.Millisecond
	dialer := &blockingDialer{}
	client, err := New(config, dialer, noOpManager{}, trust)
	if err != nil {
		t.Fatal(err)
	}
	client.jitter = func(value time.Duration) time.Duration { return value }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for dialer.calls.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context canceled", err)
	}
	if calls := dialer.calls.Load(); calls < 3 {
		t.Fatalf("dial attempts during outage = %d, want repeated bounded attempts", calls)
	}
	if dialer.deadlines.Load() != dialer.calls.Load() {
		t.Fatalf("dial attempts with deadline = %d of %d", dialer.deadlines.Load(), dialer.calls.Load())
	}
}

type testConnectStream struct {
	ctx     context.Context
	sendErr error
	sent    []*agentv1.ConnectRequest
}

func (s *testConnectStream) Send(request *agentv1.ConnectRequest) error {
	if s.sendErr != nil {
		return s.sendErr
	}
	s.sent = append(s.sent, proto.Clone(request).(*agentv1.ConnectRequest))
	return nil
}

func (*testConnectStream) Recv() (*agentv1.ConnectResponse, error) { return nil, io.EOF }
func (*testConnectStream) Header() (metadata.MD, error)            { return nil, nil }
func (*testConnectStream) Trailer() metadata.MD                    { return nil }
func (*testConnectStream) CloseSend() error                        { return nil }
func (s *testConnectStream) Context() context.Context              { return s.ctx }
func (s *testConnectStream) SendMsg(value any) error {
	return s.Send(value.(*agentv1.ConnectRequest))
}
func (*testConnectStream) RecvMsg(any) error { return io.EOF }

func TestStatusSendFailureRetainsDurableReplay(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := NewTrustStore(map[string]crypto.PublicKey{"key": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	config := testClientConfig(filepath.Join(secureTempDir(t), "journal"))
	client, err := New(config, &failingDialer{}, noOpManager{}, trust)
	if err != nil {
		t.Fatal(err)
	}
	command, _ := signedTestCommand(t, privateKey)
	record, _, err := client.store.putCommand(command, deliveredStatus(command))
	if err != nil {
		t.Fatal(err)
	}
	failure := &testConnectStream{ctx: context.Background(), sendErr: errors.New("connection closed")}
	if _, err := client.sendRecordStatuses(failure, 1, record, map[string]struct{}{}, false); err == nil {
		t.Fatal("sendRecordStatuses() unexpectedly succeeded")
	}
	persisted, err := client.store.record(record.RecordKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(persisted.Statuses) != 1 {
		t.Fatalf("persisted status count = %d, want 1", len(persisted.Statuses))
	}
	replay := &testConnectStream{ctx: context.Background()}
	if _, err := client.sendRecordStatuses(replay, 1, persisted, map[string]struct{}{}, false); err != nil {
		t.Fatal(err)
	}
	if len(replay.sent) != 1 || replay.sent[0].GetDeploymentStatus().Event.EventId != deliveredStatus(command).Event.EventId {
		t.Fatal("durable status was not replayed with its stable event ID")
	}
}
