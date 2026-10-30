package gatewayclient

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/acmehttp01"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type fakeACMEHTTP01Consumer struct {
	mu      sync.Mutex
	ready   bool
	calls   int
	current acmehttp01.Pointer
	apply   func(context.Context, acmehttp01.Command) (acmehttp01.Result, error)
}

func (consumer *fakeACMEHTTP01Consumer) Ready() bool {
	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	return consumer.ready
}

func (consumer *fakeACMEHTTP01Consumer) Current() (acmehttp01.Pointer, error) {
	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	return consumer.current, nil
}

func (consumer *fakeACMEHTTP01Consumer) Apply(ctx context.Context, command acmehttp01.Command) (acmehttp01.Result, error) {
	consumer.mu.Lock()
	consumer.calls++
	apply := consumer.apply
	consumer.mu.Unlock()
	if apply != nil {
		return apply(ctx, command)
	}
	now := time.Now().UTC()
	active := acmehttp01.Pointer{VersionID: command.OverlayVersionID, Revision: command.OverlayRevision, SHA256: "digest"}
	result := acmehttp01.Result{
		DeploymentID: command.DeploymentID, Attempt: command.Attempt, VersionID: command.OverlayVersionID,
		Revision: command.OverlayRevision, State: acmehttp01.StateHealthy, Active: active,
		Transitions: []acmehttp01.Transition{
			{Sequence: 2, State: acmehttp01.StateStaged, At: now, ResultCode: "OK", Summary: "overlay artifact staged", ActiveUnchanged: true},
			{Sequence: 3, State: acmehttp01.StatePrechecked, At: now, ResultCode: "OK", Summary: "overlay release precheck passed", ActiveUnchanged: true},
			{Sequence: 4, State: acmehttp01.StateActivated, At: now, ResultCode: "OK", Summary: "overlay version activated"},
			{Sequence: 5, State: acmehttp01.StateHealthy, At: now, ResultCode: "OK", Summary: "overlay activation is healthy"},
		},
	}
	consumer.mu.Lock()
	consumer.current = active
	consumer.mu.Unlock()
	return result, nil
}

func (consumer *fakeACMEHTTP01Consumer) callCount() int {
	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	return consumer.calls
}

func TestACMEHTTP01OverlayGatewayReplayAndRestartDoNotReactivate(t *testing.T) {
	harness := newACMEHTTP01GatewayHarness(t)
	command, wire, token, exactValue := signedACMEHTTP01Command(t, harness.signingKey, time.Now().UTC(), nil)
	record, created, err := harness.client.overlayStore.putCommand(command, acmeHTTP01DeliveredStatus(command, acmehttp01.Pointer{}))
	if err != nil || !created {
		t.Fatalf("putCommand() = (%v, %v)", created, err)
	}
	if err := harness.client.executeACMEHTTP01OverlayRecord(context.Background(), newFetchGatewayClient(t, wire), record.RecordKey, 1<<20); err != nil {
		t.Fatal(err)
	}
	if calls := harness.consumer.callCount(); calls != 1 {
		t.Fatalf("consumer calls = %d, want 1", calls)
	}
	replayed, created, err := harness.client.overlayStore.putCommand(command, acmeHTTP01DeliveredStatus(command, acmehttp01.Pointer{}))
	if err != nil || created || !replayed.ExecutionDone {
		t.Fatalf("duplicate put = (%+v, %v, %v)", replayed, created, err)
	}
	if err := harness.client.executeACMEHTTP01OverlayRecord(context.Background(), newFetchGatewayClient(t, wire), record.RecordKey, 1<<20); err != nil {
		t.Fatal(err)
	}
	closeGatewayClientForRestart(t, harness.client)
	restarted, err := New(harness.config, &failingDialer{}, noOpManager{}, harness.trust, WithACMEHTTP01OverlayConsumer(harness.consumer))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	restartRecord, err := restarted.overlayStore.record(record.RecordKey)
	if err != nil || restartRecord == nil || !restartRecord.ExecutionDone {
		t.Fatalf("restart record = (%+v, %v)", restartRecord, err)
	}
	if err := restarted.executeACMEHTTP01OverlayRecord(context.Background(), newFetchGatewayClient(t, wire), record.RecordKey, 1<<20); err != nil {
		t.Fatal(err)
	}
	if calls := harness.consumer.callCount(); calls != 1 {
		t.Fatalf("replay/reactivation calls = %d, want 1", calls)
	}
	statuses, err := overlayStatusesFromRecord(restartRecord)
	if err != nil || statuses[len(statuses)-1].State != agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_HEALTHY {
		t.Fatalf("statuses = (%+v, %v)", statuses, err)
	}
	for _, status := range statuses {
		if strings.Contains(status.ActivationSummary, token) || strings.Contains(status.ActivationSummary, exactValue) ||
			status.Error != nil && (strings.Contains(status.Error.Message, token) || strings.Contains(status.Error.Message, exactValue)) {
			t.Fatal("overlay status leaked challenge material")
		}
	}
}

func TestACMEHTTP01OverlayGatewayFailsClosedForTamperExpiryAndBinding(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*agentv1.AcmeHTTP01OverlayCommand, []byte) []byte
		code   agentv1.AcmeHTTP01OverlayResultCode
	}{
		{"wire tamper", func(_ *agentv1.AcmeHTTP01OverlayCommand, wire []byte) []byte {
			copyWire := append([]byte(nil), wire...)
			copyWire[len(copyWire)-2] ^= 1
			return copyWire
		}, agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_INVALID_ARTIFACT},
		{"wrong kind", func(command *agentv1.AcmeHTTP01OverlayCommand, wire []byte) []byte {
			command.Artifact.Kind = agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION
			return wire
		}, agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_UNSPECIFIED},
		{"version binding", func(command *agentv1.AcmeHTTP01OverlayCommand, wire []byte) []byte {
			command.OverlayVersionId = uuid.NewString()
			return wire
		}, agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_INVALID_ARTIFACT},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newACMEHTTP01GatewayHarness(t)
			command, wire, _, _ := signedACMEHTTP01Command(t, harness.signingKey, time.Now().UTC(), nil)
			wire = test.mutate(command, wire)
			record, _, err := harness.client.overlayStore.putCommand(command, acmeHTTP01DeliveredStatus(command, acmehttp01.Pointer{}))
			if err != nil {
				t.Fatal(err)
			}
			if err := harness.client.executeACMEHTTP01OverlayRecord(context.Background(), newFetchGatewayClient(t, wire), record.RecordKey, 1<<20); err != nil {
				t.Fatal(err)
			}
			stored, err := harness.client.overlayStore.record(record.RecordKey)
			if err != nil {
				t.Fatal(err)
			}
			statuses, err := overlayStatusesFromRecord(stored)
			if err != nil {
				t.Fatal(err)
			}
			last := statuses[len(statuses)-1]
			if last.State != agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_FAILED {
				t.Fatalf("state = %s", last.State)
			}
			if test.code != agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_UNSPECIFIED && last.ResultCode != test.code {
				t.Fatalf("result code = %s, want %s", last.ResultCode, test.code)
			}
			if calls := harness.consumer.callCount(); calls != 0 {
				t.Fatalf("consumer calls = %d, want 0", calls)
			}
		})
	}

	// ADR-0003: the command's purpose must be the signed snapshot's.
	for name, mutate := range map[string]func(*agentv1.AcmeHTTP01OverlayCommand){
		"cleanup_only relabeled apply": func(command *agentv1.AcmeHTTP01OverlayCommand) {
			command.Purpose = agentv1.AcmeHTTP01OverlayPurpose_ACME_HTTP01_OVERLAY_PURPOSE_APPLY
		},
		"cleanup_only without purpose": func(command *agentv1.AcmeHTTP01OverlayCommand) {
			command.Purpose = agentv1.AcmeHTTP01OverlayPurpose_ACME_HTTP01_OVERLAY_PURPOSE_UNSPECIFIED
		},
	} {
		t.Run(name, func(t *testing.T) {
			harness := newACMEHTTP01GatewayHarness(t)
			command, wire, _, _ := signedACMEHTTP01CommandWithPurpose(t, harness.signingKey, time.Now().UTC(), nil, true)
			mutate(command)
			record, _, err := harness.client.overlayStore.putCommand(command, acmeHTTP01DeliveredStatus(command, acmehttp01.Pointer{}))
			if err != nil {
				t.Fatal(err)
			}
			if err := harness.client.executeACMEHTTP01OverlayRecord(context.Background(), newFetchGatewayClient(t, wire), record.RecordKey, 1<<20); err != nil {
				t.Fatal(err)
			}
			stored, _ := harness.client.overlayStore.record(record.RecordKey)
			statuses, _ := overlayStatusesFromRecord(stored)
			if last := statuses[len(statuses)-1]; last.State != agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_FAILED {
				t.Fatalf("state = %s", last.State)
			}
			if calls := harness.consumer.callCount(); calls != 0 {
				t.Fatalf("consumer calls = %d, want 0", calls)
			}
		})
	}
	t.Run("apply relabeled cleanup_only", func(t *testing.T) {
		harness := newACMEHTTP01GatewayHarness(t)
		command, wire, _, _ := signedACMEHTTP01Command(t, harness.signingKey, time.Now().UTC(), nil)
		command.Purpose = agentv1.AcmeHTTP01OverlayPurpose_ACME_HTTP01_OVERLAY_PURPOSE_CLEANUP_ONLY
		record, _, err := harness.client.overlayStore.putCommand(command, acmeHTTP01DeliveredStatus(command, acmehttp01.Pointer{}))
		if err != nil {
			t.Fatal(err)
		}
		if err := harness.client.executeACMEHTTP01OverlayRecord(context.Background(), newFetchGatewayClient(t, wire), record.RecordKey, 1<<20); err != nil {
			t.Fatal(err)
		}
		stored, _ := harness.client.overlayStore.record(record.RecordKey)
		statuses, _ := overlayStatusesFromRecord(stored)
		if got := statuses[len(statuses)-1].ResultCode; got != agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_INVALID_ARTIFACT {
			t.Fatalf("result code = %s", got)
		}
		if calls := harness.consumer.callCount(); calls != 0 {
			t.Fatalf("consumer calls = %d, want 0", calls)
		}
	})

	t.Run("expired", func(t *testing.T) {
		harness := newACMEHTTP01GatewayHarness(t)
		command, wire, _, _ := signedACMEHTTP01Command(t, harness.signingKey, time.Now().UTC().Add(-2*time.Hour), nil)
		command.DeadlineTime = timestamppb.New(time.Now().Add(time.Hour))
		record, _, err := harness.client.overlayStore.putCommand(command, acmeHTTP01DeliveredStatus(command, acmehttp01.Pointer{}))
		if err != nil {
			t.Fatal(err)
		}
		if err := harness.client.executeACMEHTTP01OverlayRecord(context.Background(), newFetchGatewayClient(t, wire), record.RecordKey, 1<<20); err != nil {
			t.Fatal(err)
		}
		stored, _ := harness.client.overlayStore.record(record.RecordKey)
		statuses, _ := overlayStatusesFromRecord(stored)
		if got := statuses[len(statuses)-1].ResultCode; got != agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_EXPIRED {
			t.Fatalf("result code = %s", got)
		}
	})
}

// A CLEANUP_ONLY overlay reaches the consumer with its purpose.
func TestACMEHTTP01OverlayGatewayPassesCleanupOnlyPurpose(t *testing.T) {
	harness := newACMEHTTP01GatewayHarness(t)
	var got acmehttp01.Command
	harness.consumer.apply = func(_ context.Context, command acmehttp01.Command) (acmehttp01.Result, error) {
		got = command
		return acmehttp01.Result{}, acmehttp01.ErrActivationFailed
	}
	command, wire, _, _ := signedACMEHTTP01CommandWithPurpose(t, harness.signingKey, time.Now().UTC(), nil, true)
	record, _, err := harness.client.overlayStore.putCommand(command, acmeHTTP01DeliveredStatus(command, acmehttp01.Pointer{}))
	if err != nil {
		t.Fatal(err)
	}
	if err := harness.client.executeACMEHTTP01OverlayRecord(context.Background(), newFetchGatewayClient(t, wire), record.RecordKey, 1<<20); err != nil {
		t.Fatal(err)
	}
	if got.Purpose != acmehttp01.PurposeCleanupOnly || got.Snapshot.Purpose != acmehttp01.PurposeCleanupOnly ||
		len(got.Snapshot.Entries) != 0 {
		t.Fatalf("consumer command purpose=%q snapshot=%q entries=%d", got.Purpose, got.Snapshot.Purpose, len(got.Snapshot.Entries))
	}
}

func TestACMEHTTP01OverlayGatewayResumesOnlyCompleteArtifactAfterDeadline(t *testing.T) {
	base := time.Now().UTC().Truncate(time.Second)
	for _, complete := range []bool{false, true} {
		t.Run(map[bool]string{false: "incomplete fails", true: "complete resumes"}[complete], func(t *testing.T) {
			harness := newACMEHTTP01GatewayHarness(t)
			command, wire, _, _ := signedACMEHTTP01Command(t, harness.signingKey, base, nil)
			command.DeadlineTime = timestamppb.New(base.Add(time.Minute))
			record, _, err := harness.client.overlayStore.putCommand(command, acmeHTTP01DeliveredStatus(command, acmehttp01.Pointer{}))
			if err != nil {
				t.Fatal(err)
			}
			if complete {
				file, err := harness.client.overlayStore.openArtifact(record.RecordKey, 0)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := file.Write(wire); err != nil {
					t.Fatal(err)
				}
				if err := file.Sync(); err != nil {
					t.Fatal(err)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
				if err := harness.client.overlayStore.setArtifactOffset(record.RecordKey, uint64(len(wire))); err != nil {
					t.Fatal(err)
				}
			}
			harness.client.now = func() time.Time { return base.Add(2 * time.Hour) }
			if err := harness.client.executeACMEHTTP01OverlayRecord(context.Background(), newFetchGatewayClient(t, wire), record.RecordKey, 1<<20); err != nil {
				t.Fatal(err)
			}
			wantCalls := 0
			wantCode := agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_EXPIRED
			if complete {
				wantCalls = 1
				wantCode = agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_OK
			}
			if calls := harness.consumer.callCount(); calls != wantCalls {
				t.Fatalf("consumer calls = %d, want %d", calls, wantCalls)
			}
			stored, err := harness.client.overlayStore.record(record.RecordKey)
			if err != nil || !stored.ExecutionDone {
				t.Fatalf("record = (%+v, %v)", stored, err)
			}
			statuses, err := overlayStatusesFromRecord(stored)
			if err != nil || statuses[len(statuses)-1].ResultCode != wantCode {
				t.Fatalf("statuses = (%+v, %v), want code %s", statuses, err, wantCode)
			}
		})
	}
}

func TestAgentHelloAdvertisesACMEHTTP01OnlyWhenRouteConsumerReady(t *testing.T) {
	harness := newACMEHTTP01GatewayHarness(t)
	harness.consumer.mu.Lock()
	harness.consumer.ready = false
	harness.consumer.mu.Unlock()
	hello, err := harness.client.agentHello()
	if err != nil {
		t.Fatal(err)
	}
	if hasCapability(hello.Capabilities, agentv1.CapabilityName_CAPABILITY_NAME_ACME_HTTP01_OVERLAY) {
		t.Fatal("unready overlay capability was advertised")
	}
	harness.consumer.mu.Lock()
	harness.consumer.ready = true
	harness.consumer.mu.Unlock()
	hello, err = harness.client.agentHello()
	if err != nil {
		t.Fatal(err)
	}
	if !hasCapability(hello.Capabilities, agentv1.CapabilityName_CAPABILITY_NAME_ACME_HTTP01_OVERLAY) {
		t.Fatal("ready overlay capability was not advertised")
	}
}

type sharedActivationGuard struct {
	mu      sync.Mutex
	current int
	maximum int
	entered chan string
	release chan struct{}
}

func (guard *sharedActivationGuard) run(ctx context.Context, kind string) error {
	guard.mu.Lock()
	guard.current++
	if guard.current > guard.maximum {
		guard.maximum = guard.current
	}
	guard.mu.Unlock()
	defer func() {
		guard.mu.Lock()
		guard.current--
		guard.mu.Unlock()
	}()
	guard.entered <- kind
	select {
	case <-guard.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (guard *sharedActivationGuard) maxConcurrent() int {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	return guard.maximum
}

type guardedDeploymentManager struct{ guard *sharedActivationGuard }

func (manager guardedDeploymentManager) Process(ctx context.Context, command deployment.Command) (deployment.Result, error) {
	if err := manager.guard.run(ctx, "deployment"); err != nil {
		return deployment.Result{}, err
	}
	now := time.Now().UTC()
	return deployment.Result{
		DeploymentID: command.DeploymentID, Attempt: command.Attempt, Action: command.Action,
		ConfigVersionID: command.ConfigVersionID, State: deployment.StateHealthy, Sequence: 2,
		Transitions: []deployment.Transition{
			{Sequence: 1, State: deployment.StateDelivered, At: now},
			{Sequence: 2, State: deployment.StateHealthy, At: now},
		},
	}, nil
}

func (manager guardedDeploymentManager) ApplyDynamicRouting(ctx context.Context, deploymentID string, attempt uint32,
	release DynamicRoutingRelease) (deployment.Result, error) {
	return manager.Process(ctx, deployment.Command{DeploymentID: deploymentID, Attempt: attempt, Action: deployment.ActionApply,
		ConfigVersionID: release.ConfigVersionID})
}

func (guardedDeploymentManager) Pointers() (deployment.Pointers, error) {
	return deployment.Pointers{}, nil
}

type dualCommandGateway struct {
	agentv1.UnimplementedAgentGatewayServiceServer
	deploymentCommand *agentv1.DeploymentCommand
	overlayCommand    *agentv1.AcmeHTTP01OverlayCommand
	artifacts         map[string][]byte
	release           *siteObjectTestRelease
	deploymentDone    chan struct{}
	overlayDone       chan struct{}
	deploymentOnce    sync.Once
	overlayOnce       sync.Once
}

func (gateway *dualCommandGateway) Connect(stream grpc.BidiStreamingServer[agentv1.ConnectRequest, agentv1.ConnectResponse]) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	if first.GetHello() == nil || first.Stream == nil || first.Stream.Sequence != 1 {
		return status.Error(codes.InvalidArgument, "invalid hello")
	}
	if err := stream.Send(&agentv1.ConnectResponse{
		Stream: responseMetadata(1),
		Payload: &agentv1.ConnectResponse_Hello{Hello: &agentv1.GatewayHello{
			SelectedProtocolVersion: &commonv1.ProtocolVersion{Major: 1}, GatewayVersion: "test",
			SessionId: uuid.NewString(), SessionEpoch: 1, ServerTime: timestamppb.Now(),
			HeartbeatIntervalDuration: durationpb.New(20 * time.Millisecond), OfflineAfterDuration: durationpb.New(time.Second),
			MaximumArtifactChunkBytes: 1 << 20, MessageIdReplayWindow: 128,
		}},
	}); err != nil {
		return err
	}
	if err := stream.Send(&agentv1.ConnectResponse{
		Stream: responseMetadata(2), Payload: &agentv1.ConnectResponse_DeploymentCommand{DeploymentCommand: gateway.deploymentCommand},
	}); err != nil {
		return err
	}
	if err := stream.Send(&agentv1.ConnectResponse{
		Stream: responseMetadata(3), Payload: &agentv1.ConnectResponse_AcmeHttp01OverlayCommand{AcmeHttp01OverlayCommand: gateway.overlayCommand},
	}); err != nil {
		return err
	}
	responseSequence := uint64(3)
	for {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		if value := request.GetDeploymentStatus(); value != nil {
			if value.State == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY {
				gateway.deploymentOnce.Do(func() { close(gateway.deploymentDone) })
			}
			continue
		}
		if value := request.GetAcmeHttp01OverlayStatus(); value != nil {
			if value.State == agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_HEALTHY {
				gateway.overlayOnce.Do(func() { close(gateway.overlayDone) })
			}
			continue
		}
		if heartbeat := request.GetHeartbeat(); heartbeat != nil {
			responseSequence++
			if err := stream.Send(&agentv1.ConnectResponse{
				Stream: responseMetadata(responseSequence),
				Payload: &agentv1.ConnectResponse_HeartbeatAck{HeartbeatAck: &agentv1.HeartbeatAck{
					HeartbeatEventId: heartbeat.Event.EventId, SessionEpoch: 1, ReceivedTime: timestamppb.Now(),
				}},
			}); err != nil {
				return err
			}
		}
	}
}

func (gateway *dualCommandGateway) FetchSiteObjects(request *agentv1.FetchSiteObjectsRequest, stream grpc.ServerStreamingServer[agentv1.FetchSiteObjectsResponse]) error {
	return serveSiteObjects(gateway.release, request, stream)
}

func (gateway *dualCommandGateway) FetchArtifact(request *agentv1.FetchArtifactRequest, stream grpc.ServerStreamingServer[agentv1.FetchArtifactResponse]) error {
	artifact, exists := gateway.artifacts[request.ArtifactId]
	if !exists || request.Offset >= uint64(len(artifact)) {
		return status.Error(codes.NotFound, "artifact not found")
	}
	content := artifact[request.Offset:]
	digest := sha256.Sum256(content)
	return stream.Send(&agentv1.FetchArtifactResponse{Chunk: &agentv1.ArtifactChunk{
		RequestId: request.Request.RequestId, ArtifactId: request.ArtifactId, Offset: request.Offset,
		Data: content, ChunkSha256: digest[:], TotalSizeBytes: uint64(len(artifact)), EndOfArtifact: true,
	}})
}

func TestDeploymentAndACMEHTTP01OverlayShareOneWorker(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	release := signedTestRelease(t, privateKey)
	deploymentCommand := release.command
	overlayCommand, overlayArtifact, _, _ := signedACMEHTTP01Command(t, privateKey, time.Now().UTC(), nil)
	artifacts := map[string][]byte{overlayCommand.Artifact.ArtifactId: overlayArtifact}
	for id, wire := range release.artifacts {
		artifacts[id] = wire
	}
	gateway := &dualCommandGateway{
		deploymentCommand: deploymentCommand, overlayCommand: overlayCommand, artifacts: artifacts, release: release,
		deploymentDone: make(chan struct{}), overlayDone: make(chan struct{}),
	}
	listener := bufconnListen(t)
	server := grpc.NewServer()
	agentv1.RegisterAgentGatewayServiceServer(server, gateway)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})

	root := secureTempDir(t)
	t.Cleanup(func() { makeTestTreeWritable(root) })
	guard := &sharedActivationGuard{entered: make(chan string, 2), release: make(chan struct{})}
	consumer := &fakeACMEHTTP01Consumer{ready: true}
	consumer.apply = func(ctx context.Context, command acmehttp01.Command) (acmehttp01.Result, error) {
		if err := guard.run(ctx, "overlay"); err != nil {
			return acmehttp01.Result{}, err
		}
		now := time.Now().UTC()
		return acmehttp01.Result{
			DeploymentID: command.DeploymentID, Attempt: command.Attempt, VersionID: command.OverlayVersionID,
			Revision: command.OverlayRevision, State: acmehttp01.StateHealthy,
			Transitions: []acmehttp01.Transition{
				{Sequence: 2, State: acmehttp01.StateStaged, At: now, ResultCode: "OK"},
				{Sequence: 3, State: acmehttp01.StateHealthy, At: now, ResultCode: "OK"},
			},
		}, nil
	}
	trust, err := NewTrustStore(map[string]crypto.PublicKey{"test-signing-key": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	config := testClientConfig(root + "/journal")
	manager := guardedDeploymentManager{guard: guard}
	client, err := New(config, &bufDialer{listener: listener}, manager, trust,
		append(dynamicTestOptions(t, root, manager), WithACMEHTTP01OverlayConsumer(consumer))...)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()

	select {
	case <-guard.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("neither activation entered the shared worker")
	}
	select {
	case kind := <-guard.entered:
		t.Fatalf("second activation %q entered while the first was blocked", kind)
	case <-time.After(50 * time.Millisecond):
	}
	close(guard.release)
	select {
	case <-guard.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("second activation did not run after the first completed")
	}
	for name, completed := range map[string]<-chan struct{}{"deployment": gateway.deploymentDone, "overlay": gateway.overlayDone} {
		select {
		case <-completed:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s command did not complete", name)
		}
	}
	cancel()
	if err := <-done; err != context.Canceled {
		t.Fatalf("Run() error = %v, want context canceled", err)
	}
	if maximum := guard.maxConcurrent(); maximum != 1 {
		t.Fatalf("maximum concurrent activations = %d, want 1", maximum)
	}
}

type acmeHTTP01GatewayHarness struct {
	config     Config
	client     *Client
	consumer   *fakeACMEHTTP01Consumer
	trust      *TrustStore
	signingKey ed25519.PrivateKey
}

func newACMEHTTP01GatewayHarness(t *testing.T) *acmeHTTP01GatewayHarness {
	t.Helper()
	root := secureTempDir(t)
	t.Cleanup(func() { makeTestTreeWritable(root) })
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := NewTrustStore(map[string]crypto.PublicKey{"test-signing-key": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	config := testClientConfig(root + "/journal")
	consumer := &fakeACMEHTTP01Consumer{ready: true}
	client, err := New(config, &failingDialer{}, noOpManager{}, trust, WithACMEHTTP01OverlayConsumer(consumer))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return &acmeHTTP01GatewayHarness{config: config, client: client, consumer: consumer, trust: trust, signingKey: privateKey}
}

func signedACMEHTTP01Command(t *testing.T, privateKey ed25519.PrivateKey, generatedAt time.Time, previous *acmehttp01.Pointer) (*agentv1.AcmeHTTP01OverlayCommand, []byte, string, string) {
	t.Helper()
	return signedACMEHTTP01CommandWithPurpose(t, privateKey, generatedAt, previous, false)
}

// signedACMEHTTP01CommandWithPurpose signs an APPLY snapshot with one token or,
// with cleanupOnly, an empty CLEANUP_ONLY snapshot naming its purpose.
func signedACMEHTTP01CommandWithPurpose(t *testing.T, privateKey ed25519.PrivateKey, generatedAt time.Time, previous *acmehttp01.Pointer, cleanupOnly bool) (*agentv1.AcmeHTTP01OverlayCommand, []byte, string, string) {
	t.Helper()
	token := "abcdefghijklmnopqrstuvwxyzABCDE_1234567890-ab"
	exactValue := token + ".abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
	document := acmehttp01.Snapshot{
		SchemaVersion: acmehttp01.ArtifactSchemaVersion, OverlayVersionID: uuid.NewString(), OverlayRevision: 1,
		GeneratedAt: generatedAt, Entries: []acmehttp01.Entry{{
			Host: "a.example.test", Token: token, Value: exactValue, ExpiresAt: generatedAt.Add(time.Hour),
		}},
	}
	purpose := agentv1.AcmeHTTP01OverlayPurpose_ACME_HTTP01_OVERLAY_PURPOSE_APPLY
	if cleanupOnly {
		document.Purpose, document.Entries = acmehttp01.PurposeCleanupOnly, []acmehttp01.Entry{}
		purpose = agentv1.AcmeHTTP01OverlayPurpose_ACME_HTTP01_OVERLAY_PURPOSE_CLEANUP_ONLY
	}
	if previous != nil {
		document.OverlayRevision = previous.Revision + 1
	}
	wire, err := acmehttp01.CanonicalSnapshot(document)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(wire)
	command := &agentv1.AcmeHTTP01OverlayCommand{
		Event: &commonv1.EventMetadata{
			EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now(), CorrelationId: uuid.NewString(),
		},
		OverlayDeploymentId: uuid.NewString(), Attempt: 1, OverlayVersionId: document.OverlayVersionID,
		OverlayRevision: document.OverlayRevision,
		Artifact: &agentv1.ArtifactDescriptor{
			ArtifactId: uuid.NewString(), Kind: agentv1.ArtifactKind_ARTIFACT_KIND_ACME_HTTP01_OVERLAY,
			SizeBytes: uint64(len(wire)), Sha256: digest[:], Signature: ed25519.Sign(privateKey, wire), SigningKeyId: "test-signing-key",
			SignatureAlgorithm: agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519,
			Compression:        agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE, MediaType: ACMEHTTP01OverlayArtifactMediaType,
			EncryptionAlgorithm: agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_NONE,
		},
		HealthCheck: &agentv1.HealthCheckPolicy{
			ActivationTimeoutDuration: durationpb.New(time.Second), ObservationWindowDuration: durationpb.New(0), RequiredConsecutiveSuccesses: 1,
		},
		DeadlineTime: timestamppb.New(time.Now().Add(time.Hour)),
		Purpose:      purpose,
	}
	if previous != nil {
		command.PreviousOverlayVersionId = &previous.VersionID
		command.PreviousOverlayRevision = &previous.Revision
	}
	return command, wire, token, exactValue
}
