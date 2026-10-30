package gatewayclient

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/nodemonitoring"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type fakeNodeMonitoringRuntime struct {
	applied    [][]byte
	runErr     error
	runStarted chan struct{}
	runRelease <-chan struct{}
}

func (runtime *fakeNodeMonitoringRuntime) Apply(_ context.Context, payload []byte) (nodemonitoring.ApplyResult, error) {
	runtime.applied = append(runtime.applied, append([]byte(nil), payload...))
	var config nodemonitoring.Config
	_ = json.Unmarshal(payload, &config)
	return nodemonitoring.ApplyResult{ConfigRevision: config.ConfigRevision}, nil
}

func (runtime *fakeNodeMonitoringRuntime) Run(ctx context.Context, _ nodemonitoring.MetricSink) error {
	if runtime.runStarted != nil {
		close(runtime.runStarted)
	}
	if runtime.runRelease != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-runtime.runRelease:
			return runtime.runErr
		}
	}
	<-ctx.Done()
	return ctx.Err()
}

func (*fakeNodeMonitoringRuntime) Status() nodemonitoring.Status {
	return nodemonitoring.Status{ConfigRevision: 7, Healthy: true}
}

func TestNodeMonitoringBridgeValidatesArtifactAndDurablyReplaysUntilAck(t *testing.T) {
	nodeID := "01990000-0000-7000-8000-000000000007"
	stateDir := t.TempDir()
	runtime := &fakeNodeMonitoringRuntime{}
	bridge, err := NewNodeMonitoringBridge(stateDir, nodeID)
	if err != nil {
		t.Fatalf("NewNodeMonitoringBridge() error = %v", err)
	}
	if err := bridge.AttachRuntime(runtime); err != nil {
		t.Fatalf("AttachRuntime() error = %v", err)
	}
	config := []byte(`{"schema_version":"cdnca.node-monitoring/v1","config_revision":7,"port_mode":"default","probe_interval_ms":10000,"probe_timeout_ms":3000,"failure_threshold":3,"recovery_threshold":3,"failure_debounce_ms":0,"recovery_debounce_ms":0,"recovery_notification_enabled":true}`)
	digest := sha256.Sum256(config)
	artifact := &agentv1.NodeMonitoringArtifact{
		Event:  testNodeMonitoringEvent("01990000-0000-7000-8000-000000000011"),
		Schema: agentv1.NodeMonitoringSchema_NODE_MONITORING_SCHEMA_V1, NodeId: nodeID,
		ConfigRevision: 7, PublicationSequence: 7, CanonicalConfigJson: config, ConfigSha256: digest[:],
	}
	if err := bridge.ApplyArtifact(t.Context(), artifact); err != nil || len(runtime.applied) != 1 {
		t.Fatalf("ApplyArtifact() error = %v, calls = %d", err, len(runtime.applied))
	}
	unsupported := proto.Clone(artifact).(*agentv1.NodeMonitoringArtifact)
	unsupported.Schema = agentv1.NodeMonitoringSchema_NODE_MONITORING_SCHEMA_UNSPECIFIED
	if err := bridge.ApplyArtifact(t.Context(), unsupported); !errors.Is(err, ErrInvalidMessage) || len(runtime.applied) != 1 {
		t.Fatalf("unsupported ApplyArtifact() error = %v, calls = %d", err, len(runtime.applied))
	}

	report := nodemonitoring.MetricReport{SchemaVersion: 1, ObservedAt: time.Now().UTC(), NodeID: nodeID,
		ConfigRevision: 7, ActiveConfigRevision: 7, ProbePort: 80, Healthy: true, ProbeSucceeded: true}
	if err := bridge.ReportNodeMonitoring(t.Context(), report); err != nil {
		t.Fatalf("ReportNodeMonitoring() error = %v", err)
	}
	event := nodemonitoring.RecoveryEvent{NodeID: nodeID, ConfigRevision: 7, RecoveredAt: time.Now().UTC()}
	if err := bridge.NotifyRecovery(t.Context(), event); err != nil {
		t.Fatalf("NotifyRecovery() error = %v", err)
	}
	pending := bridge.Pending()
	if len(pending) != 2 || pending[0].PublicationSequence != 1 || pending[1].PublicationSequence != 2 ||
		pending[1].Kind != agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_RECOVERY_NOTIFICATION {
		t.Fatalf("pending = %#v", pending)
	}

	restarted, err := NewNodeMonitoringBridge(stateDir, nodeID)
	if err != nil {
		t.Fatalf("NewNodeMonitoringBridge(restart) error = %v", err)
	}
	replayed := restarted.Pending()
	if len(replayed) != 2 || replayed[1].Event.EventId != pending[1].Event.EventId {
		t.Fatalf("replayed = %#v", replayed)
	}
	if err := restarted.Acknowledge(&agentv1.NodeMonitoringAck{
		EventId: pending[0].Event.EventId, NodeId: nodeID, ConfigRevision: 7,
		PublicationSequence: 1, PublishedStream: "NODE_MONITORING_STATUS", PublishedSequence: 21,
		AcceptedTime: timestamppb.Now(),
	}); err != nil {
		t.Fatalf("Acknowledge() error = %v", err)
	}
	if remaining := restarted.Pending(); len(remaining) != 1 || remaining[0].PublicationSequence != 2 {
		t.Fatalf("remaining = %#v", remaining)
	}
}

func TestNodeMonitoringBridgePersistsDeterministicStopReceiptRequest(t *testing.T) {
	nodeID := "01990000-0000-7000-8000-000000000007"
	bridge, err := NewNodeMonitoringBridge(t.TempDir(), nodeID)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := bridge.ReportNodeMonitoring(t.Context(), nodemonitoring.MetricReport{
		SchemaVersion: 1, ObservedAt: now, NodeID: nodeID, AppliedConfigRevision: 9,
		LoadMetrics: &nodemonitoring.LoadMetrics{ObservedAt: now, CPUPercent: 1, MemoryTotalBytes: 1},
	}); err != nil {
		t.Fatal(err)
	}
	pending := bridge.Pending()
	if len(pending) != 1 {
		t.Fatalf("pending = %d", len(pending))
	}
	want := uuid.NewSHA1(uuid.MustParse(nodeID), []byte("node-monitoring-stop-receipt/9")).String()
	if pending[0].Event.GetRequestId() != want {
		t.Fatalf("request id = %s, want %s", pending[0].Event.GetRequestId(), want)
	}
}

func testNodeMonitoringEvent(eventID string) *commonv1.EventMetadata {
	return &commonv1.EventMetadata{EventId: eventID, RequestId: "01990000-0000-7000-8000-000000000012", OccurredTime: timestamppb.Now()}
}

func TestNodeMonitoringBridgeRejectsMalformedOutbox(t *testing.T) {
	nodeID := "01990000-0000-7000-8000-000000000007"
	encode := func(sequence uint64) []byte {
		record := &agentv1.NodeMonitoringReport{NodeId: nodeID, PublicationSequence: sequence}
		payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		return payload
	}
	marshalOutbox := func(next uint64, records ...[]byte) []byte {
		payload, err := json.Marshal(nodeMonitoringOutbox{Version: nodeMonitoringCarrierVersion, NextSequence: next, Encoded: records})
		if err != nil {
			t.Fatal(err)
		}
		return payload
	}
	unknownRecord := append(append([]byte(nil), encode(1)...), 0xf8, 0x07, 0x01)
	tests := []struct {
		name    string
		payload []byte
	}{
		{name: "unknown outer field", payload: []byte(`{"version":1,"next_sequence":0,"records":[],"unknown":true}`)},
		{name: "unknown record field", payload: marshalOutbox(1, unknownRecord)},
		{name: "non-contiguous records", payload: marshalOutbox(3, encode(1), encode(3))},
		{name: "truncated tail", payload: marshalOutbox(2, encode(1))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stateRoot := t.TempDir()
			stateDir := filepath.Join(stateRoot, "node-monitoring-carrier")
			if err := os.MkdirAll(stateDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(stateDir, nodeMonitoringOutboxFile), test.payload, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := NewNodeMonitoringBridge(stateRoot, nodeID); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("NewNodeMonitoringBridge() error = %v, want invalid configuration", err)
			}
		})
	}
}

type nodeMonitoringTestConnection struct {
	client agentv1.AgentGatewayServiceClient
}

func (connection *nodeMonitoringTestConnection) Client() agentv1.AgentGatewayServiceClient {
	return connection.client
}

func (*nodeMonitoringTestConnection) Close() error { return nil }

type nodeMonitoringTestDialer struct {
	client agentv1.AgentGatewayServiceClient
}

func (dialer *nodeMonitoringTestDialer) Dial(context.Context) (Connection, error) {
	return &nodeMonitoringTestConnection{client: dialer.client}, nil
}

type blockingNodeMonitoringGatewayClient struct {
	agentv1.AgentGatewayServiceClient
	connected chan struct{}
}

func (client *blockingNodeMonitoringGatewayClient) Connect(ctx context.Context, _ ...grpc.CallOption) (grpc.BidiStreamingClient[agentv1.ConnectRequest, agentv1.ConnectResponse], error) {
	close(client.connected)
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestClientRunPrefersNodeMonitoringFailureOverCancellation(t *testing.T) {
	runtimeFailure := errors.New("node monitoring probe failed")
	tests := []struct {
		name string
		run  func(*testing.T, *fakeNodeMonitoringRuntime, <-chan struct{}) Dialer
	}{
		{
			name: "blocked session",
			run: func(t *testing.T, _ *fakeNodeMonitoringRuntime, _ <-chan struct{}) Dialer {
				return &nodeMonitoringTestDialer{client: &blockingNodeMonitoringGatewayClient{connected: make(chan struct{})}}
			},
		},
		{name: "reconnect timer", run: func(*testing.T, *fakeNodeMonitoringRuntime, <-chan struct{}) Dialer { return &failingDialer{} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			release := make(chan struct{})
			runtime := &fakeNodeMonitoringRuntime{runErr: runtimeFailure, runStarted: make(chan struct{}), runRelease: release}
			dialer := test.run(t, runtime, release)
			client := newNodeMonitoringRunClient(t, dialer, runtime)
			ready := make(chan struct{})
			switch value := dialer.(type) {
			case *nodeMonitoringTestDialer:
				ready = value.client.(*blockingNodeMonitoringGatewayClient).connected
			case *failingDialer:
				client.jitter = func(time.Duration) time.Duration {
					close(ready)
					return time.Hour
				}
			}
			done := make(chan error, 1)
			go func() { done <- client.Run(context.Background()) }()
			select {
			case <-runtime.runStarted:
			case <-time.After(time.Second):
				t.Fatal("node monitoring runtime did not start")
			}
			select {
			case <-ready:
			case <-time.After(time.Second):
				t.Fatal("gateway client did not reach the cancellation path")
			}
			close(release)
			select {
			case err := <-done:
				if !errors.Is(err, runtimeFailure) {
					t.Fatalf("Run() error = %v, want node monitoring failure", err)
				}
			case <-time.After(time.Second):
				t.Fatal("Run() did not return")
			}
		})
	}
}

func newNodeMonitoringRunClient(t *testing.T, dialer Dialer, runtime *fakeNodeMonitoringRuntime) *Client {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := NewTrustStore(map[string]crypto.PublicKey{"key": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	config := testClientConfig(filepath.Join(secureTempDir(t), "journal"))
	bridge, err := NewNodeMonitoringBridge(secureTempDir(t), config.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	if err := bridge.AttachRuntime(runtime); err != nil {
		t.Fatal(err)
	}
	client, err := New(config, dialer, noOpManager{}, trust, WithNodeMonitoringBridge(bridge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}
