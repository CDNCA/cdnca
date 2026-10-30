package gatewayclient

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/objectstore"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type testPrechecker struct{}

func (testPrechecker) Precheck(context.Context, string, string) error { return nil }

type testRuntime struct {
	mu          sync.Mutex
	activations int
}

func (r *testRuntime) Reload(context.Context, string, string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.activations++
	return nil
}

func (*testRuntime) Healthy(context.Context, string) error { return nil }

func (r *testRuntime) activationCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.activations
}

type heartbeatPointerManager struct {
	noOpManager
	pointers deployment.Pointers
}

func (m heartbeatPointerManager) Pointers() (deployment.Pointers, error) { return m.pointers, nil }

type terminalMaintenanceErrorManager struct {
	err error
}

func (m terminalMaintenanceErrorManager) Process(_ context.Context, command deployment.Command) (deployment.Result, error) {
	started := time.Now().UTC()
	transitions := []deployment.Transition{
		{Sequence: 1, State: deployment.StateDelivered, At: started},
		{Sequence: 2, State: deployment.StateStaged, At: started.Add(time.Millisecond)},
		{Sequence: 3, State: deployment.StatePrechecked, At: started.Add(2 * time.Millisecond)},
		{Sequence: 4, State: deployment.StateActivated, At: started.Add(3 * time.Millisecond)},
		{Sequence: 5, State: deployment.StateHealthy, At: started.Add(4 * time.Millisecond)},
	}
	return deployment.Result{
		DeploymentID: command.DeploymentID, Attempt: command.Attempt, Action: command.Action,
		ConfigVersionID: command.ConfigVersionID, State: deployment.StateHealthy, Sequence: 5, Transitions: transitions,
	}, m.err
}

func (m terminalMaintenanceErrorManager) ApplyDynamicRouting(ctx context.Context, deploymentID string, attempt uint32,
	release DynamicRoutingRelease) (deployment.Result, error) {
	return m.Process(ctx, deployment.Command{DeploymentID: deploymentID, Attempt: attempt, Action: deployment.ActionApply,
		ConfigVersionID: release.ConfigVersionID})
}

func (terminalMaintenanceErrorManager) Pointers() (deployment.Pointers, error) {
	return deployment.Pointers{}, nil
}

type fakeGateway struct {
	agentv1.UnimplementedAgentGatewayServiceServer
	command  *agentv1.DeploymentCommand
	artifact []byte
	// release (when set) serves a site object release's artifacts and objects.
	release              *siteObjectTestRelease
	dropFirstFetch       atomic.Bool
	connects             atomic.Int32
	mu                   sync.Mutex
	offsets              []uint64
	requestIDs           []string
	statuses             []*agentv1.DeploymentStatus
	statusEvents         chan *agentv1.DeploymentStatus
	suppressHeartbeatAck bool
	offlineAfter         time.Duration
}

func TestTerminalDeploymentResultSurvivesPostCommitMaintenanceError(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	release := signedTestRelease(t, privateKey)
	command := release.command
	maintenanceErr := errors.New("prune historical release: permission denied")
	trust, err := NewTrustStore(map[string]crypto.PublicKey{"test-signing-key": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	root := secureTempDir(t)
	config := testClientConfig(filepath.Join(root, "journal"))
	manager := terminalMaintenanceErrorManager{err: maintenanceErr}
	client, err := New(config, &failingDialer{}, manager, trust, dynamicTestOptions(t, root, manager)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	record, _, err := client.store.putCommand(command, deliveredStatus(command))
	if err != nil {
		t.Fatal(err)
	}
	err = client.executeRecord(t.Context(), newSiteObjectGatewayClient(t, &siteObjectGateway{release: release}), record.RecordKey, 1<<20)
	if !errors.Is(err, maintenanceErr) {
		t.Fatalf("executeRecord() error = %v, want maintenance error", err)
	}
	persisted, err := client.store.record(record.RecordKey)
	if err != nil {
		t.Fatal(err)
	}
	statuses, err := statusesFromRecord(persisted)
	if err != nil {
		t.Fatal(err)
	}
	if !persisted.ExecutionDone || len(statuses) != 5 {
		t.Fatalf("persisted terminal record = done %t, statuses %d", persisted.ExecutionDone, len(statuses))
	}
	for _, status := range statuses {
		if status.State == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED {
			t.Fatalf("post-commit maintenance error emitted a false failed status: %+v", status)
		}
	}
	if got := statuses[len(statuses)-1].State; got != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY {
		t.Fatalf("terminal state = %s, want healthy", got)
	}
}

func TestHeartbeatReportsHelloAgentVersion(t *testing.T) {
	root := secureTempDir(t)
	t.Cleanup(func() { makeTestTreeWritable(root) })
	config := testClientConfig(filepath.Join(root, "journal"))
	store, err := newDurableStore(config.JournalDir, config.MaxCommandBytes, config.MaxStatusBytes)
	if err != nil {
		t.Fatal(err)
	}
	fixedNow := time.Date(2026, time.July, 22, 1, 2, 3, 0, time.UTC)
	client := &Client{config: config, manager: noOpManager{}, store: store, now: func() time.Time { return fixedNow }}
	heartbeat, err := client.heartbeat(7, 11)
	if err != nil {
		t.Fatal(err)
	}
	if heartbeat.AgentVersion == nil || heartbeat.GetAgentVersion() != config.Capabilities.AgentVersion {
		t.Fatalf("heartbeat agent version = %v, want %q", heartbeat.AgentVersion, config.Capabilities.AgentVersion)
	}
}

func TestHeartbeatReportsRuntimeProbeState(t *testing.T) {
	tests := []struct {
		name              string
		current           string
		configureProbe    bool
		configureFirewall bool
		openRestyError    error
		firewallError     error
		wantOpenResty     agentv1.RuntimeState
		wantFirewall      agentv1.RuntimeState
		wantOpenCalls     int
		wantFirewallCalls int
	}{
		{name: "no current configuration", configureProbe: true, configureFirewall: true, wantOpenResty: agentv1.RuntimeState_RUNTIME_STATE_STOPPED, wantFirewall: agentv1.RuntimeState_RUNTIME_STATE_RUNNING, wantFirewallCalls: 1},
		{name: "conservative defaults", current: "cfg-v1", wantOpenResty: agentv1.RuntimeState_RUNTIME_STATE_DEGRADED, wantFirewall: agentv1.RuntimeState_RUNTIME_STATE_STOPPED},
		{name: "healthy runtimes", current: "cfg-v1", configureProbe: true, configureFirewall: true, wantOpenResty: agentv1.RuntimeState_RUNTIME_STATE_RUNNING, wantFirewall: agentv1.RuntimeState_RUNTIME_STATE_RUNNING, wantOpenCalls: 1, wantFirewallCalls: 1},
		{name: "failed probes", current: "cfg-v1", configureProbe: true, configureFirewall: true, openRestyError: errors.New("unhealthy"), firewallError: errors.New("unavailable"), wantOpenResty: agentv1.RuntimeState_RUNTIME_STATE_DEGRADED, wantFirewall: agentv1.RuntimeState_RUNTIME_STATE_DEGRADED, wantOpenCalls: 1, wantFirewallCalls: 1},
		{name: "firewall disabled", current: "cfg-v1", configureProbe: true, wantOpenResty: agentv1.RuntimeState_RUNTIME_STATE_RUNNING, wantFirewall: agentv1.RuntimeState_RUNTIME_STATE_STOPPED, wantOpenCalls: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := secureTempDir(t)
			t.Cleanup(func() { makeTestTreeWritable(root) })
			config := testClientConfig(filepath.Join(root, "journal"))
			store, err := newDurableStore(config.JournalDir, config.MaxCommandBytes, config.MaxStatusBytes)
			if err != nil {
				t.Fatal(err)
			}
			openCalls := 0
			firewallCalls := 0
			client := &Client{
				config:  config,
				manager: heartbeatPointerManager{pointers: deployment.Pointers{Current: test.current}},
				store:   store,
				now:     time.Now,
			}
			if test.configureProbe {
				probe := RuntimeStatusProbe{OpenResty: func(_ context.Context, versionID string) error {
					openCalls++
					if versionID != test.current {
						return errors.New("unexpected configuration version")
					}
					return test.openRestyError
				}}
				if test.configureFirewall {
					probe.Firewall = func(context.Context) error {
						firewallCalls++
						return test.firewallError
					}
				}
				if err := WithRuntimeStatusProbe(probe)(client); err != nil {
					t.Fatal(err)
				}
			}
			heartbeat, err := client.heartbeatWithContext(context.Background(), 7, 11)
			if err != nil {
				t.Fatal(err)
			}
			if heartbeat.Runtime.GetOpenrestyState() != test.wantOpenResty || heartbeat.Runtime.GetFirewallState() != test.wantFirewall {
				t.Fatalf("runtime states = (%s, %s), want (%s, %s)", heartbeat.Runtime.GetOpenrestyState(), heartbeat.Runtime.GetFirewallState(), test.wantOpenResty, test.wantFirewall)
			}
			if openCalls != test.wantOpenCalls || firewallCalls != test.wantFirewallCalls {
				t.Fatalf("probe calls = (%d, %d), want (%d, %d)", openCalls, firewallCalls, test.wantOpenCalls, test.wantFirewallCalls)
			}
		})
	}
}

func TestRuntimeStatusProbeRequiresOpenRestyProbe(t *testing.T) {
	if err := WithRuntimeStatusProbe(RuntimeStatusProbe{})(&Client{}); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("WithRuntimeStatusProbe() error = %v, want invalid configuration", err)
	}
}

func TestHeartbeatReportsCanonicalRuntimeStates(t *testing.T) {
	client, manager, previous, previousWire, _, privateKey := activeIdentityClient(t)
	previousRecord := persistActiveIdentityCommand(t, client, previous, previousWire)
	completeDeploymentWithoutAck(t, client, manager, previousRecord)
	current, currentWire := nextActiveIdentityDeployment(t, previous, privateKey)
	currentBundle, err := decodeConfigurationBundle(currentWire)
	if err != nil {
		t.Fatal(err)
	}
	result, err := manager.Process(context.Background(), deployment.Command{
		DeploymentID: current.DeploymentId, Attempt: current.Attempt, Action: deployment.ActionApply,
		ConfigVersionID: current.ConfigVersionId, PreviousVersionID: previous.ConfigVersionId, Bundle: currentBundle,
	})
	if err != nil || result.State != deployment.StateHealthy {
		t.Fatalf("Process(current) = (%+v, %v)", result, err)
	}
	currentRecord := persistActiveIdentityCommand(t, client, current, currentWire)
	completeDeploymentWithoutAck(t, client, manager, currentRecord)
	config := client.config
	fixedNow := time.Date(2026, time.July, 22, 1, 2, 3, 0, time.UTC)
	client.now = func() time.Time { return fixedNow }
	const (
		epoch    = uint64(7)
		sequence = uint64(11)
	)
	type wireField struct {
		typeID protowire.Type
		value  []byte
	}
	decodeFields := func(t *testing.T, message []byte) map[protowire.Number]wireField {
		t.Helper()
		fields := make(map[protowire.Number]wireField)
		for len(message) != 0 {
			number, typeID, tagLength := protowire.ConsumeTag(message)
			if tagLength < 0 {
				t.Fatalf("consume protobuf tag: %v", protowire.ParseError(tagLength))
			}
			valueBytes := message[tagLength:]
			valueLength := protowire.ConsumeFieldValue(number, typeID, valueBytes)
			if valueLength < 0 {
				t.Fatalf("consume protobuf field %d: %v", number, protowire.ParseError(valueLength))
			}
			value := append([]byte(nil), valueBytes[:valueLength]...)
			if typeID == protowire.BytesType {
				decoded, length := protowire.ConsumeBytes(valueBytes)
				if length < 0 {
					t.Fatalf("consume protobuf bytes field %d: %v", number, protowire.ParseError(length))
				}
				value = append([]byte(nil), decoded...)
			}
			fields[number] = wireField{typeID: typeID, value: value}
			message = valueBytes[valueLength:]
		}
		return fields
	}
	canonicalRuntimeStateWire := []byte{0x08, 0x02, 0x10, 0x03}
	canonicalIdentityCapabilityWire := []byte{0x08, 0x12, 0x10, 0x01}
	acceptsCanonicalRuntimeStateWire := func(runtimeWire []byte) bool {
		return bytes.HasPrefix(runtimeWire, canonicalRuntimeStateWire)
	}
	oldUnspecifiedRuntimeWire, err := proto.MarshalOptions{Deterministic: true}.Marshal(&agentv1.EdgeRuntimeStatus{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(oldUnspecifiedRuntimeWire, []byte{}) {
		t.Fatalf("zero-state runtime wire = %x, want empty", oldUnspecifiedRuntimeWire)
	}
	oldUnspecifiedRuntime := &agentv1.EdgeRuntimeStatus{}
	if err := proto.Unmarshal(oldUnspecifiedRuntimeWire, oldUnspecifiedRuntime); err != nil {
		t.Fatal(err)
	}
	if int32(oldUnspecifiedRuntime.GetOpenrestyState()) != 0 || int32(oldUnspecifiedRuntime.GetFirewallState()) != 0 {
		t.Fatalf("zero-state runtime decoded states = (%d, %d), want (0, 0)", oldUnspecifiedRuntime.GetOpenrestyState(), oldUnspecifiedRuntime.GetFirewallState())
	}
	if acceptsCanonicalRuntimeStateWire(oldUnspecifiedRuntimeWire) {
		t.Fatalf("old UNSPECIFIED runtime wire unexpectedly satisfied canonical state vector: %x", oldUnspecifiedRuntimeWire)
	}
	wantCurrentDigest := sha256.Sum256(currentWire)
	wantPreviousDigest := sha256.Sum256(previousWire)
	assertIdentity := func(t *testing.T, label string, identity *agentv1.ActiveConfigIdentity, wantConfigVersion string, wantDigest [sha256.Size]byte) {
		t.Helper()
		if identity == nil || identity.GetConfigVersionId() != wantConfigVersion || len(identity.GetArtifactSha256()) != sha256.Size || !bytes.Equal(identity.GetArtifactSha256(), wantDigest[:]) || int32(identity.GetSchema()) != 1 {
			t.Errorf("%s identity = %+v, want config=%q digest=%x schema=1", label, identity, wantConfigVersion, wantDigest)
		}
	}
	assertIdentityWire := func(t *testing.T, label string, identityWire wireField, wantConfigVersion string, wantDigest [sha256.Size]byte) {
		t.Helper()
		if identityWire.typeID != protowire.BytesType {
			t.Errorf("%s identity wire type = %d, want bytes", label, identityWire.typeID)
			return
		}
		fields := decodeFields(t, identityWire.value)
		configField, configPresent := fields[1]
		if !configPresent || configField.typeID != protowire.BytesType || string(configField.value) != wantConfigVersion {
			t.Errorf("%s identity config field 1 = (%x, %t), want %q", label, configField.value, configPresent, wantConfigVersion)
		}
		digestField, digestPresent := fields[2]
		if !digestPresent || digestField.typeID != protowire.BytesType || len(digestField.value) != sha256.Size || !bytes.Equal(digestField.value, wantDigest[:]) {
			t.Errorf("%s identity digest field 2 = (%x, %t), want %x", label, digestField.value, digestPresent, wantDigest)
		}
		schemaField, schemaPresent := fields[3]
		if !schemaPresent || schemaField.typeID != protowire.VarintType || !bytes.Equal(schemaField.value, []byte{0x01}) {
			t.Errorf("%s identity schema field 3 = (%x, %t), want 01", label, schemaField.value, schemaPresent)
		}
	}

	for _, test := range []struct {
		name                  string
		activeIdentityEnabled bool
	}{
		{name: "legacy"},
		{name: "active identity", activeIdentityEnabled: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var heartbeat *agentv1.Heartbeat
			var heartbeatErr error
			if test.activeIdentityEnabled {
				heartbeat, heartbeatErr = client.heartbeat(epoch, sequence, true)
			} else {
				heartbeat, heartbeatErr = client.heartbeat(epoch, sequence)
			}
			if heartbeatErr != nil {
				t.Fatal(heartbeatErr)
			}
			wire, err := proto.MarshalOptions{Deterministic: true}.Marshal(heartbeat)
			if err != nil {
				t.Fatal(err)
			}
			decoded := &agentv1.Heartbeat{}
			if err := proto.Unmarshal(wire, decoded); err != nil {
				t.Fatal(err)
			}

			heartbeatFields := decodeFields(t, wire)
			runtimeWire, present := heartbeatFields[6]
			if !present || runtimeWire.typeID != protowire.BytesType {
				t.Fatalf("heartbeat wire field 6 = (%v, %v), want bytes", runtimeWire, present)
			}
			if !acceptsCanonicalRuntimeStateWire(runtimeWire.value) {
				t.Errorf("runtime wire = %x, want literal prefix %x", runtimeWire.value, canonicalRuntimeStateWire)
			}
			runtimeFields := decodeFields(t, runtimeWire.value)
			for _, number := range []protowire.Number{4, 5, 6, 9} {
				if _, present := heartbeatFields[number]; !present {
					t.Errorf("heartbeat wire field %d is absent", number)
				}
			}
			if _, present := runtimeFields[3]; !present {
				t.Errorf("runtime wire loaded config field 3 is absent")
			}
			for _, number := range []protowire.Number{10, 11, 12} {
				_, present := heartbeatFields[number]
				if present != test.activeIdentityEnabled {
					t.Errorf("heartbeat identity wire field %d presence = %t, want %t", number, present, test.activeIdentityEnabled)
				}
			}
			_, loadedIdentityPresent := runtimeFields[4]
			if loadedIdentityPresent != test.activeIdentityEnabled {
				t.Errorf("runtime loaded identity wire field 4 presence = %t, want %t", loadedIdentityPresent, test.activeIdentityEnabled)
			}
			if decoded.SessionEpoch != epoch || decoded.HeartbeatSequence != sequence || decoded.Event == nil || !proto.Equal(decoded.Event, heartbeat.Event) {
				t.Errorf("serialized heartbeat envelope changed: %+v", decoded)
			}
			if decoded.AgentVersion == nil || decoded.GetAgentVersion() != config.Capabilities.AgentVersion {
				t.Errorf("serialized heartbeat agent version = %v, want %q", decoded.AgentVersion, config.Capabilities.AgentVersion)
			}
			if decoded.CurrentConfigVersionId == nil || decoded.GetCurrentConfigVersionId() != current.ConfigVersionId || decoded.PreviousConfigVersionId == nil || decoded.GetPreviousConfigVersionId() != previous.ConfigVersionId || decoded.Runtime == nil || decoded.Runtime.LoadedConfigVersionId == nil || decoded.Runtime.GetLoadedConfigVersionId() != current.ConfigVersionId {
				t.Errorf("serialized config versions = current %v previous %v loaded %v, want (%q, %q, %q)", decoded.CurrentConfigVersionId, decoded.PreviousConfigVersionId, decoded.GetRuntime().LoadedConfigVersionId, current.ConfigVersionId, previous.ConfigVersionId, current.ConfigVersionId)
			}
			if test.activeIdentityEnabled {
				capabilityWire := heartbeatFields[10]
				if capabilityWire.typeID != protowire.BytesType || !bytes.Equal(capabilityWire.value, canonicalIdentityCapabilityWire) {
					t.Errorf("serialized active identity capability wire = %x, want %x", capabilityWire.value, canonicalIdentityCapabilityWire)
				}
				if decoded.ActiveConfigIdentityCapability == nil || int32(decoded.ActiveConfigIdentityCapability.GetName()) != 18 || decoded.ActiveConfigIdentityCapability.GetApiVersion() != 1 {
					t.Errorf("serialized active identity capability = %+v, want name=18 api=1", decoded.ActiveConfigIdentityCapability)
				}
				assertIdentity(t, "current", decoded.CurrentConfigIdentity, current.ConfigVersionId, wantCurrentDigest)
				assertIdentity(t, "previous", decoded.PreviousConfigIdentity, previous.ConfigVersionId, wantPreviousDigest)
				assertIdentity(t, "loaded", decoded.GetRuntime().LoadedConfigIdentity, current.ConfigVersionId, wantCurrentDigest)
				assertIdentityWire(t, "current", heartbeatFields[11], current.ConfigVersionId, wantCurrentDigest)
				assertIdentityWire(t, "previous", heartbeatFields[12], previous.ConfigVersionId, wantPreviousDigest)
				assertIdentityWire(t, "loaded", runtimeFields[4], current.ConfigVersionId, wantCurrentDigest)
			} else if decoded.ActiveConfigIdentityCapability != nil {
				t.Errorf("legacy heartbeat serialized active identity capability = %+v", decoded.ActiveConfigIdentityCapability)
			} else if decoded.CurrentConfigIdentity != nil || decoded.PreviousConfigIdentity != nil || decoded.GetRuntime().LoadedConfigIdentity != nil {
				t.Errorf("legacy heartbeat serialized active identity: %+v", decoded)
			}
		})
	}
}

func (g *fakeGateway) Connect(stream grpc.BidiStreamingServer[agentv1.ConnectRequest, agentv1.ConnectResponse]) error {
	session := g.connects.Add(1)
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	if first.GetHello() == nil || first.Stream == nil || first.Stream.Sequence != 1 {
		return status.Error(codes.InvalidArgument, "invalid hello")
	}
	offlineAfter := g.offlineAfter
	if offlineAfter == 0 {
		offlineAfter = 200 * time.Millisecond
	}
	if err := stream.Send(&agentv1.ConnectResponse{
		Stream: responseMetadata(1),
		Payload: &agentv1.ConnectResponse_Hello{Hello: &agentv1.GatewayHello{
			SelectedProtocolVersion:   &commonv1.ProtocolVersion{Major: 1},
			GatewayVersion:            "test",
			SessionId:                 uuid.NewString(),
			SessionEpoch:              uint64(session),
			ServerTime:                timestamppb.Now(),
			HeartbeatIntervalDuration: durationpb.New(20 * time.Millisecond),
			OfflineAfterDuration:      durationpb.New(offlineAfter),
			MaximumArtifactChunkBytes: 64 << 10,
			MessageIdReplayWindow:     128,
		}},
	}); err != nil {
		return err
	}
	if err := stream.Send(&agentv1.ConnectResponse{Stream: responseMetadata(2), Payload: &agentv1.ConnectResponse_DeploymentCommand{DeploymentCommand: g.command}}); err != nil {
		return err
	}
	responseSequence := uint64(2)
	for {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		if deploymentStatus := request.GetDeploymentStatus(); deploymentStatus != nil {
			g.mu.Lock()
			g.statuses = append(g.statuses, deploymentStatus)
			g.mu.Unlock()
			select {
			case g.statusEvents <- deploymentStatus:
			default:
			}
			continue
		}
		if heartbeat := request.GetHeartbeat(); heartbeat != nil {
			if g.suppressHeartbeatAck {
				continue
			}
			responseSequence++
			if err := stream.Send(&agentv1.ConnectResponse{
				Stream: responseMetadata(responseSequence),
				Payload: &agentv1.ConnectResponse_HeartbeatAck{HeartbeatAck: &agentv1.HeartbeatAck{
					HeartbeatEventId: heartbeat.Event.EventId,
					SessionEpoch:     uint64(session),
					ReceivedTime:     timestamppb.Now(),
				}},
			}); err != nil {
				return err
			}
		}
	}
}

func TestMissingHeartbeatAcknowledgementReconnects(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	command, artifact := signedTestCommand(t, privateKey)
	gateway := &fakeGateway{
		command: command, artifact: artifact, statusEvents: make(chan *agentv1.DeploymentStatus, 128),
		suppressHeartbeatAck: true, offlineAfter: 60 * time.Millisecond,
	}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	agentv1.RegisterAgentGatewayServiceServer(server, gateway)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})

	root := secureTempDir(t)
	t.Cleanup(func() { makeTestTreeWritable(root) })
	manager, err := deployment.NewManager(filepath.Join(root, "deployment"), testPrechecker{}, &testRuntime{})
	if err != nil {
		t.Fatal(err)
	}
	trust, err := NewTrustStore(map[string]crypto.PublicKey{"test-signing-key": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(testClientConfig(filepath.Join(root, "gateway-journal")), &bufDialer{listener: listener}, manager, trust)
	if err != nil {
		t.Fatal(err)
	}
	client.jitter = func(time.Duration) time.Duration { return time.Millisecond }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for gateway.connects.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context canceled", err)
	}
	if connections := gateway.connects.Load(); connections < 2 {
		t.Fatalf("gateway connection count = %d, want reconnect after missing heartbeat acknowledgements", connections)
	}
}

func (g *fakeGateway) FetchArtifact(request *agentv1.FetchArtifactRequest, stream grpc.ServerStreamingServer[agentv1.FetchArtifactResponse]) error {
	g.mu.Lock()
	g.offsets = append(g.offsets, request.Offset)
	g.requestIDs = append(g.requestIDs, request.Request.RequestId)
	g.mu.Unlock()
	artifact := g.artifact
	if g.release != nil {
		artifact = g.release.artifacts[request.ArtifactId]
	}
	if request.Offset > uint64(len(artifact)) {
		return status.Error(codes.OutOfRange, "artifact offset")
	}
	remaining := artifact[request.Offset:]
	length := len(remaining)
	if request.Offset == 0 && !g.dropFirstFetch.Swap(true) {
		length /= 2
	}
	if length == 0 {
		return status.Error(codes.Internal, "zero test chunk")
	}
	content := remaining[:length]
	digest := sha256.Sum256(content)
	end := request.Offset+uint64(length) == uint64(len(artifact))
	if err := stream.Send(&agentv1.FetchArtifactResponse{Chunk: &agentv1.ArtifactChunk{
		RequestId: request.Request.RequestId, ArtifactId: request.ArtifactId, Offset: request.Offset,
		Data: content, ChunkSha256: digest[:], TotalSizeBytes: uint64(len(artifact)), EndOfArtifact: end,
	}}); err != nil {
		return err
	}
	if !end {
		return status.Error(codes.Unavailable, "injected transfer interruption")
	}
	return nil
}

func (g *fakeGateway) FetchSiteObjects(request *agentv1.FetchSiteObjectsRequest, stream grpc.ServerStreamingServer[agentv1.FetchSiteObjectsResponse]) error {
	if g.release == nil {
		return status.Error(codes.NotFound, "site objects")
	}
	return serveSiteObjects(g.release, request, stream)
}

// serveSiteObjects sends each requested object of release as one chunk.
func serveSiteObjects(release *siteObjectTestRelease, request *agentv1.FetchSiteObjectsRequest, stream grpc.ServerStreamingServer[agentv1.FetchSiteObjectsResponse]) error {
	for _, digest := range request.Sha256 {
		wire, present := release.objects[digest]
		if !present {
			return status.Error(codes.NotFound, "site object")
		}
		if err := stream.Send(&agentv1.FetchSiteObjectsResponse{Chunk: &agentv1.SiteObjectChunk{
			RequestId: request.Request.RequestId, Sha256: digest, Data: wire, TotalSizeBytes: uint64(len(wire)), EndOfObject: true,
		}}); err != nil {
			return err
		}
	}
	return nil
}

// dynamicTestOptions enables site object delivery with an object store under
// root and applier as the dynamic routing runtime.
func dynamicTestOptions(t *testing.T, root string, applier DynamicRoutingApplier) []ClientOption {
	t.Helper()
	store, err := objectstore.Open(filepath.Join(root, "site-objects"))
	if err != nil {
		t.Fatal(err)
	}
	return []ClientOption{WithSiteObjectStore(store), WithDynamicRouting(applier)}
}

func (g *fakeGateway) transferRequests() ([]uint64, []string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]uint64(nil), g.offsets...), append([]string(nil), g.requestIDs...)
}

func (g *fakeGateway) eventCount(eventID string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	count := 0
	for _, value := range g.statuses {
		if value.Event.EventId == eventID {
			count++
		}
	}
	return count
}

type bufDialer struct {
	listener *bufconn.Listener
}

type runningClient struct{ cancel func() }

// startBufconnClient runs a production Client against gateway over an in-memory gRPC listener.
func startBufconnClient(t *testing.T, gateway agentv1.AgentGatewayServiceServer, config Config, trust *TrustStore,
	options ...ClientOption) runningClient {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	agentv1.RegisterAgentGatewayServiceServer(server, gateway)
	go func() { _ = server.Serve(listener) }()
	client, err := New(config, &bufDialer{listener: listener}, noOpManager{}, trust, options...)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = client.Run(ctx) }()
	return runningClient{cancel: func() {
		cancel()
		<-done
		_ = client.Close()
		server.Stop()
		_ = listener.Close()
	}}
}

type testConnection struct {
	connection *grpc.ClientConn
}

func (c *testConnection) Client() agentv1.AgentGatewayServiceClient {
	return agentv1.NewAgentGatewayServiceClient(c.connection)
}

func (c *testConnection) Close() error { return c.connection.Close() }

func (d *bufDialer) Dial(ctx context.Context) (Connection, error) {
	connection, err := grpc.DialContext(ctx, "passthrough:///bufnet",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return d.listener.Dial() }),
		grpc.WithBlock(),
	)
	if err != nil {
		return nil, err
	}
	return &testConnection{connection: connection}, nil
}

func TestReconnectResumeDuplicateAndRestart(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	release := signedTestRelease(t, privateKey)
	command := release.command
	gateway := &fakeGateway{command: command, release: release, statusEvents: make(chan *agentv1.DeploymentStatus, 128)}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	agentv1.RegisterAgentGatewayServiceServer(server, gateway)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})

	root := secureTempDir(t)
	t.Cleanup(func() { makeTestTreeWritable(root) })
	runtime := &fakeDynamicRouting{DeploymentManager: noOpManager{}}
	manager := runtime
	trust, err := NewTrustStore(map[string]crypto.PublicKey{"test-signing-key": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	config := testClientConfig(filepath.Join(root, "gateway-journal"))
	client, err := New(config, &bufDialer{listener: listener}, manager, trust, dynamicTestOptions(t, root, runtime)...)
	if err != nil {
		t.Fatal(err)
	}
	client.jitter = func(time.Duration) time.Duration { return time.Millisecond }

	firstCtx, firstCancel := context.WithCancel(context.Background())
	firstDone := make(chan error, 1)
	go func() { firstDone <- client.Run(firstCtx) }()
	waitForState(t, gateway.statusEvents, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY)
	firstCancel()
	if err := <-firstDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context canceled", err)
	}
	if runtime.activationCount() != 1 {
		t.Fatalf("activation count = %d, want 1", runtime.activationCount())
	}
	offsets, requestIDs := gateway.transferRequests()
	if len(offsets) < 2 || offsets[0] != 0 || offsets[1] == 0 {
		t.Fatalf("artifact offsets = %v, want zero followed by resumed offset", offsets)
	}
	if requestIDs[0] == requestIDs[1] {
		t.Fatal("resumed artifact request reused request_id")
	}
	deliveredID := deliveredStatus(command).Event.EventId
	if gateway.eventCount(deliveredID) < 2 {
		t.Fatalf("DELIVERED event count = %d, want replay after reconnect", gateway.eventCount(deliveredID))
	}

	closeGatewayClientForRestart(t, client)
	restarted, err := New(config, &bufDialer{listener: listener}, manager, trust, dynamicTestOptions(t, root, runtime)...)
	if err != nil {
		t.Fatal(err)
	}
	restarted.jitter = func(time.Duration) time.Duration { return time.Millisecond }
	restartCtx, restartCancel := context.WithCancel(context.Background())
	restartDone := make(chan error, 1)
	go func() { restartDone <- restarted.Run(restartCtx) }()
	waitForState(t, gateway.statusEvents, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY)
	restartCancel()
	if err := <-restartDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("restarted Run() error = %v", err)
	}
	if runtime.activationCount() != 1 {
		t.Fatalf("activation count after restart = %d, want 1", runtime.activationCount())
	}
}

func TestEncryptedArtifactIntegrityFailureNeverStages(t *testing.T) {
	for _, mode := range []string{"signature", "ciphertext"} {
		t.Run(mode, func(t *testing.T) {
			publicKey, signingKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			// The signed root or the HPKE key envelope is tampered.
			release := signedTestRelease(t, signingKey)
			command := release.command
			if mode == "signature" {
				command.Artifacts[0].Signature[0] ^= 0x80
			} else {
				key := command.Artifacts[1]
				artifact := release.artifacts[key.ArtifactId]
				artifact[len(artifact)-1] ^= 0x80
				digest := sha256.Sum256(artifact)
				key.Sha256 = digest[:]
				key.Signature = ed25519.Sign(signingKey, artifact)
			}
			gateway := &fakeGateway{command: command, release: release, statusEvents: make(chan *agentv1.DeploymentStatus, 128)}
			listener := bufconn.Listen(1 << 20)
			server := grpc.NewServer()
			agentv1.RegisterAgentGatewayServiceServer(server, gateway)
			go func() { _ = server.Serve(listener) }()
			t.Cleanup(func() {
				server.Stop()
				_ = listener.Close()
			})

			root := secureTempDir(t)
			t.Cleanup(func() { makeTestTreeWritable(root) })
			runtime := &fakeDynamicRouting{DeploymentManager: noOpManager{}}
			trust, err := NewTrustStore(map[string]crypto.PublicKey{"test-signing-key": publicKey})
			if err != nil {
				t.Fatal(err)
			}
			config := testClientConfig(filepath.Join(root, "gateway-journal"))
			client, err := New(config, &bufDialer{listener: listener}, runtime, trust, dynamicTestOptions(t, root, runtime)...)
			if err != nil {
				t.Fatal(err)
			}
			client.jitter = func(time.Duration) time.Duration { return time.Millisecond }
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- client.Run(ctx) }()
			waitForState(t, gateway.statusEvents, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED)
			cancel()
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Fatalf("Run() error = %v, want context canceled", err)
			}
			if runtime.activationCount() != 0 {
				t.Fatalf("integrity failure activated runtime %d times", runtime.activationCount())
			}
			gateway.mu.Lock()
			defer gateway.mu.Unlock()
			for _, status := range gateway.statuses {
				if status.State == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED || status.State == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY {
					t.Fatalf("integrity failure emitted forbidden state %s", status.State)
				}
			}
		})
	}
}

func TestGatewayRollbackUsesOnlyLocalReleaseAndReplaysAfterRestart(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	applyCommand, applyArtifact := signedBundleTestCommand(t, privateKey)
	bundle, err := decodeConfigurationBundle(applyArtifact)
	if err != nil {
		t.Fatalf("decodeConfigurationBundle(seed) error = %v", err)
	}
	root := secureTempDir(t)
	t.Cleanup(func() { makeTestTreeWritable(root) })
	deploymentRoot := filepath.Join(root, "deployment")
	runtime := &testRuntime{}
	manager, err := deployment.NewManager(deploymentRoot, testPrechecker{}, runtime)
	if err != nil {
		t.Fatal(err)
	}
	seedV1 := deployment.Command{
		DeploymentID: "seed-v1", Attempt: 1, Action: deployment.ActionApply,
		ConfigVersionID: "cfg-v1", Bundle: bundle,
	}
	if result, err := manager.Process(context.Background(), seedV1); err != nil || result.State != deployment.StateHealthy {
		t.Fatalf("Process(seed v1) = (%+v, %v)", result, err)
	}
	seedV2 := deployment.Command{
		DeploymentID: "seed-v2", Attempt: 1, Action: deployment.ActionApply,
		ConfigVersionID: "cfg-v2", PreviousVersionID: "cfg-v1", Bundle: bundle,
	}
	if result, err := manager.Process(context.Background(), seedV2); err != nil || result.State != deployment.StateHealthy {
		t.Fatalf("Process(seed v2) = (%+v, %v)", result, err)
	}

	rollback := proto.Clone(applyCommand).(*agentv1.DeploymentCommand)
	baseline := "cfg-v2"
	rollback.Event.EventId = uuid.NewString()
	rollback.Event.RequestId = uuid.NewString()
	rollback.DeploymentId = uuid.NewString()
	rollback.RolloutId = uuid.NewString()
	rollback.ConfigVersionId = "cfg-v1"
	rollback.PreviousConfigVersionId = &baseline
	rollback.Action = agentv1.DeploymentAction_DEPLOYMENT_ACTION_ROLLBACK
	rollback.Artifacts = nil

	gateway := &fakeGateway{
		command: rollback, statusEvents: make(chan *agentv1.DeploymentStatus, 128), suppressHeartbeatAck: true,
	}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	agentv1.RegisterAgentGatewayServiceServer(server, gateway)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})
	trust, err := NewTrustStore(map[string]crypto.PublicKey{"test-signing-key": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	config := testClientConfig(filepath.Join(root, "gateway-journal"))
	client, err := New(config, &bufDialer{listener: listener}, manager, trust)
	if err != nil {
		t.Fatal(err)
	}
	client.jitter = func(time.Duration) time.Duration { return time.Millisecond }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	waitForState(t, gateway.statusEvents, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTED)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context canceled", err)
	}
	if offsets, _ := gateway.transferRequests(); len(offsets) != 0 {
		t.Fatalf("rollback requested an artifact at offsets %v", offsets)
	}
	if runtime.activationCount() != 3 {
		t.Fatalf("activation count = %d, want two seeds plus one rollback", runtime.activationCount())
	}
	pointers, err := manager.Pointers()
	if err != nil || pointers.Current != "cfg-v1" || pointers.Previous != "cfg-v2" {
		t.Fatalf("Pointers() = (%+v, %v)", pointers, err)
	}
	record, err := client.store.record(recordKey(rollback.DeploymentId, rollback.Attempt))
	if err != nil || record == nil || !record.ExecutionDone || len(record.Statuses) < 2 {
		t.Fatalf("durable rollback record = (%+v, %v)", record, err)
	}

	restartedRuntime := &testRuntime{}
	restartedManager, err := deployment.NewManager(deploymentRoot, testPrechecker{}, restartedRuntime)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := New(config, &bufDialer{listener: listener}, restartedManager, trust)
	if err != nil {
		t.Fatal(err)
	}
	restarted.jitter = func(time.Duration) time.Duration { return time.Millisecond }
	restartCtx, restartCancel := context.WithCancel(context.Background())
	restartDone := make(chan error, 1)
	go func() { restartDone <- restarted.Run(restartCtx) }()
	waitForState(t, gateway.statusEvents, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTED)
	restartCancel()
	if err := <-restartDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("restarted Run() error = %v", err)
	}
	if restartedRuntime.activationCount() != 0 {
		t.Fatalf("restart replay repeated rollback activation %d times", restartedRuntime.activationCount())
	}
	if offsets, _ := gateway.transferRequests(); len(offsets) != 0 {
		t.Fatalf("restart replay requested an artifact at offsets %v", offsets)
	}
	if gateway.eventCount(deliveredStatus(rollback).Event.EventId) < 2 {
		t.Fatal("restart did not replay the stable durable DELIVERED event")
	}
}

// testRecipientKey/testRecipientID are the artifact recipient testClientConfig
// declares; signedTestCommand seals its site object key envelope to it.
var testRecipientKey, testRecipientID = func() ([]byte, string) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	digest := sha256.Sum256(key.PublicKey().Bytes())
	return key.Bytes(), "x25519:" + hex.EncodeToString(digest[:])
}()

// signedTestRelease is a signed site object release (v2 root + key envelope
// sealed to testRecipientKey, the only configuration release 1.0.35 accepts)
// with its artifacts and sealed objects.
func signedTestRelease(t *testing.T, privateKey ed25519.PrivateKey) *siteObjectTestRelease {
	t.Helper()
	contentKey := make([]byte, siteobject.ContentKeySize)
	if _, err := rand.Read(contentKey); err != nil {
		t.Fatal(err)
	}
	return newSiteObjectRelease(t, privateKey, testRecipientKey, testRecipientID, contentKey, uuid.NewString(), 1, []byte(`{"cc":1}`))
}

// signedTestCommand is signedTestRelease's command and its root wire bytes.
func signedTestCommand(t *testing.T, privateKey ed25519.PrivateKey) (*agentv1.DeploymentCommand, []byte) {
	t.Helper()
	release := signedTestRelease(t, privateKey)
	return release.command, release.artifacts[release.command.Artifacts[0].ArtifactId]
}

// signedBundleTestCommand is a signed single-artifact configuration bundle
// command. Nodes no longer execute it; it only seeds deployment managers and
// the active identity bundle checks.
func signedBundleTestCommand(t *testing.T, privateKey ed25519.PrivateKey) (*agentv1.DeploymentCommand, []byte) {
	t.Helper()
	scope, version := uuid.NewString(), uuid.NewString()
	artifact, err := edgeconfig.MarshalBundle(siteRuntimeRouteBundle(t, scope, version, 1))
	if err != nil {
		t.Fatal(err)
	}
	artifactDigest := sha256.Sum256(artifact)
	return &agentv1.DeploymentCommand{
		Event: &commonv1.EventMetadata{
			EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now(), CorrelationId: uuid.NewString(),
		},
		DeploymentId: uuid.NewString(), Attempt: 1, RolloutId: uuid.NewString(), ConfigVersionId: version,
		ConfigurationScopeId: proto.String(scope),
		Action:               agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY,
		Artifacts: []*agentv1.ArtifactDescriptor{{
			ArtifactId: uuid.NewString(), Kind: agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION,
			SizeBytes: uint64(len(artifact)), Sha256: artifactDigest[:], Signature: ed25519.Sign(privateKey, artifact), SigningKeyId: "test-signing-key",
			SignatureAlgorithm: agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519,
			Compression:        agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE, MediaType: ConfigurationBundleMediaType,
			EncryptionAlgorithm: agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_NONE,
		}},
		RequiredCapabilities: []*agentv1.Capability{
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1, ApiVersion: 1},
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_IPV4, ApiVersion: 1},
		},
		HealthCheck: &agentv1.HealthCheckPolicy{
			ActivationTimeoutDuration: durationpb.New(time.Second), ObservationWindowDuration: durationpb.New(time.Second), RequiredConsecutiveSuccesses: 1,
		},
		DeadlineTime: timestamppb.New(time.Now().Add(time.Hour)),
	}, artifact
}

func testClientConfig(journalDir string) Config {
	config := DefaultConfig()
	config.NodeID = uuid.NewString()
	config.BootID = uuid.NewString()
	config.ArtifactEncryptionKeyID, config.ArtifactDecryptionPrivateKey = testRecipientID, testRecipientKey
	config.JournalDir = journalDir
	config.Capabilities = &agentv1.AgentCapabilities{
		AgentVersion: "test", Features: []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE, ApiVersion: 1},
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME, ApiVersion: edgeconfig.MaxSiteRuntimeVersion},
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1, ApiVersion: 1}, {Name: agentv1.CapabilityName_CAPABILITY_NAME_IPV4, ApiVersion: 1}},
	}
	config.InitialBackoff = time.Millisecond
	config.MaximumBackoff = 10 * time.Millisecond
	return config
}

func responseMetadata(sequence uint64) *commonv1.StreamMetadata {
	return &commonv1.StreamMetadata{MessageId: uuid.NewString(), SentTime: timestamppb.Now(), Sequence: sequence}
}

func waitForState(t *testing.T, events <-chan *agentv1.DeploymentStatus, state agentv1.NodeDeploymentState) {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for {
		select {
		case status := <-events:
			if status.State == state {
				return
			}
		case <-timer.C:
			t.Fatalf("did not receive deployment state %s", state)
		}
	}
}

func makeTestTreeWritable(root string) {
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			_ = os.Chmod(path, 0o700)
		} else {
			_ = os.Chmod(path, 0o600)
		}
		return nil
	})
}

type testCertificateRenewer func(context.Context, agentv1.AgentGatewayServiceClient) (bool, string, error)

func (function testCertificateRenewer) Renew(ctx context.Context, gateway agentv1.AgentGatewayServiceClient) (bool, string, error) {
	return function(ctx, gateway)
}

func TestCertificateRenewalRefreshesRuntimeIdentityBeforeReconnect(t *testing.T) {
	digest := strings.Repeat("a", sha256.Size*2)
	observed := ""
	client := &Client{
		renewer: testCertificateRenewer(func(context.Context, agentv1.AgentGatewayServiceClient) (bool, string, error) {
			return true, digest, nil
		}),
		portTransition: &PortTransitionRuntime{certificateSHA: strings.Repeat("b", sha256.Size*2)},
		onRenewed:      func(value string) { observed = value },
	}
	renewed, err := client.renewCertificate(context.Background(), nil)
	if err != nil || !renewed || client.portTransition.certificateSHA != digest || observed != digest {
		t.Fatalf("renewCertificate() = %v, %v, transition=%q observed=%q", renewed, err, client.portTransition.certificateSHA, observed)
	}
}
