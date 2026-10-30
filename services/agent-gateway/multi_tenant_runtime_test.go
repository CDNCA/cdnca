package gateway

import (
	"bytes"
	"context"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func validProtocolErrorForTest() *commonv1.ProtocolError {
	return &commonv1.ProtocolError{Code: commonv1.ErrorCode_ERROR_CODE_UNAVAILABLE, Message: "deployment failed"}
}

func connectWithFeatures(t *testing.T, servers testServers, features []*agentv1.Capability) (grpc.BidiStreamingClient[agentv1.ConnectRequest, agentv1.ConnectResponse], *agentv1.GatewayHello, func()) {
	t.Helper()
	connection := dialGateway(t, servers.mtlsAddress, servers.pki.rootPool, servers.clientCertificate)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	cleanup := func() { cancel(); _ = connection.Close() }
	stream, err := agentv1.NewAgentGatewayServiceClient(connection).Connect(ctx)
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	request := validHello(testNodeID, versionRange(1, 0), 1)
	request.GetHello().Capabilities.Features = features
	if err := stream.Send(request); err != nil {
		cleanup()
		t.Fatal(err)
	}
	response, err := stream.Recv()
	if err != nil || response.GetHello() == nil {
		cleanup()
		t.Fatalf("GatewayHello = (%+v, %v)", response, err)
	}
	return stream, response.GetHello(), cleanup
}

func testMultiTenantCapability() *agentv1.Capability {
	return &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_MULTI_TENANT_RUNTIME, ApiVersion: 1}
}

func testScopedIdentity(scopeID, currentID string, previousID *string) *agentv1.ScopedConfigIdentity {
	entry := &agentv1.ScopedConfigIdentity{
		ConfigurationScopeId: scopeID, CurrentConfigVersionId: proto.String(currentID),
		CurrentConfigIdentity: testActiveIdentity(currentID, bytes.Repeat([]byte{0x61}, 32)),
	}
	if previousID != nil {
		entry.PreviousConfigVersionId = proto.String(*previousID)
		entry.PreviousConfigIdentity = testActiveIdentity(*previousID, bytes.Repeat([]byte{0x62}, 32))
	}
	return entry
}

func testApplyResult(state agentv1.NodeDeploymentState, code commonv1.ErrorCode) *agentv1.ScopedApplyResult {
	return &agentv1.ScopedApplyResult{
		DeploymentId: uuid.NewString(), Attempt: 1, ConfigVersionId: uuid.NewString(),
		State: state, FinishedTime: timestamppb.Now(), ErrorCode: code,
	}
}

func multiTenantHello(entries ...*agentv1.ScopedConfigIdentity) *agentv1.AgentHello {
	hello := validHello(testNodeID, versionRange(1, 0), 1).GetHello()
	hello.Capabilities.Features = []*agentv1.Capability{testActiveIdentityCapability(), testMultiTenantCapability()}
	hello.ScopedConfigIdentities = entries
	if len(entries) == 1 && entries[0].CurrentConfigVersionId != nil {
		hello.CurrentConfigVersionId = proto.String(entries[0].GetCurrentConfigVersionId())
		hello.CurrentConfigIdentity = proto.Clone(entries[0].CurrentConfigIdentity).(*agentv1.ActiveConfigIdentity)
		if entries[0].PreviousConfigVersionId != nil {
			hello.PreviousConfigVersionId = proto.String(entries[0].GetPreviousConfigVersionId())
			hello.PreviousConfigIdentity = proto.Clone(entries[0].PreviousConfigIdentity).(*agentv1.ActiveConfigIdentity)
		}
	}
	return hello
}

func TestMultiTenantRuntimeCapabilityNegotiation(t *testing.T) {
	gateway := newCommandGateway(t, defaultFakeControl(), &fakeCommandBus{}, nil)
	if err := gateway.validateHello(multiTenantHello()); err != nil {
		t.Fatalf("multi-tenant hello without scopes rejected: %v", err)
	}
	for _, test := range []struct {
		name     string
		features []*agentv1.Capability
	}{
		{name: "requires active identity", features: []*agentv1.Capability{testMultiTenantCapability()}},
		{name: "unsupported version", features: []*agentv1.Capability{testActiveIdentityCapability(), {Name: agentv1.CapabilityName_CAPABILITY_NAME_MULTI_TENANT_RUNTIME, ApiVersion: 2}}},
		{name: "duplicated", features: []*agentv1.Capability{testActiveIdentityCapability(), testMultiTenantCapability(), testMultiTenantCapability()}},
	} {
		t.Run(test.name, func(t *testing.T) {
			hello := multiTenantHello()
			hello.Capabilities.Features = test.features
			if err := gateway.validateHello(hello); err == nil {
				t.Fatal("invalid multi-tenant capability was accepted")
			}
		})
	}

	servers := startTestServers(t, defaultFakeControl())
	for _, test := range []struct {
		name     string
		features []*agentv1.Capability
		want     bool
	}{
		{name: "declared", features: []*agentv1.Capability{testActiveIdentityCapability(), testMultiTenantCapability()}, want: true},
		{name: "legacy", features: []*agentv1.Capability{testActiveIdentityCapability()}, want: false},
	} {
		t.Run("gateway hello "+test.name, func(t *testing.T) {
			stream, hello, cleanup := connectWithFeatures(t, servers, test.features)
			defer cleanup()
			if got := gatewayHelloHasMultiTenantRuntimeV1(hello); got != test.want {
				t.Fatalf("enabled capabilities = %+v, multi-tenant = %v, want %v", hello.EnabledCapabilities, got, test.want)
			}
			_ = stream.CloseSend()
		})
	}
}

func TestHelloScopedConfigIdentitiesValidation(t *testing.T) {
	gateway := newCommandGateway(t, defaultFakeControl(), &fakeCommandBus{}, nil)
	scopeA, scopeB := uuid.NewString(), uuid.NewString()
	previousA := uuid.NewString()
	healthyA := testScopedIdentity(scopeA, uuid.NewString(), &previousA)
	healthyA.LastApplyResult = testApplyResult(agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY, commonv1.ErrorCode_ERROR_CODE_UNSPECIFIED)
	firstFailedB := &agentv1.ScopedConfigIdentity{ConfigurationScopeId: scopeB,
		LastApplyResult: testApplyResult(agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED, commonv1.ErrorCode_ERROR_CODE_FAILED_PRECONDITION)}
	multi := multiTenantHello(healthyA, firstFailedB)
	if err := gateway.validateHello(multi); err != nil {
		t.Fatalf("valid multi-scope hello rejected: %v", err)
	}
	single := multiTenantHello(testScopedIdentity(scopeA, uuid.NewString(), &previousA))
	if err := gateway.validateHello(single); err != nil {
		t.Fatalf("valid mirrored single-scope hello rejected: %v", err)
	}
	resultOnly := multiTenantHello(proto.Clone(firstFailedB).(*agentv1.ScopedConfigIdentity))
	if err := gateway.validateHello(resultOnly); err != nil {
		t.Fatalf("valid result-only hello rejected: %v", err)
	}

	for _, test := range []struct {
		name   string
		base   *agentv1.AgentHello
		change func(*agentv1.AgentHello)
	}{
		{name: "scopes without capability", base: multi, change: func(value *agentv1.AgentHello) {
			value.Capabilities.Features = []*agentv1.Capability{testActiveIdentityCapability()}
		}},
		{name: "multi-scope with legacy current", base: multi, change: func(value *agentv1.AgentHello) {
			value.CurrentConfigVersionId = proto.String(value.ScopedConfigIdentities[0].GetCurrentConfigVersionId())
			value.CurrentConfigIdentity = proto.Clone(value.ScopedConfigIdentities[0].CurrentConfigIdentity).(*agentv1.ActiveConfigIdentity)
		}},
		{name: "result-only with legacy current", base: resultOnly, change: func(value *agentv1.AgentHello) {
			id := uuid.NewString()
			value.CurrentConfigVersionId = proto.String(id)
			value.CurrentConfigIdentity = testActiveIdentity(id, bytes.Repeat([]byte{0x63}, 32))
		}},
		{name: "single-scope legacy not mirrored", base: single, change: func(value *agentv1.AgentHello) {
			value.CurrentConfigVersionId = nil
			value.CurrentConfigIdentity = nil
		}},
		{name: "single-scope legacy digest differs", base: single, change: func(value *agentv1.AgentHello) {
			value.CurrentConfigIdentity.ArtifactSha256[0] ^= 0xff
		}},
		{name: "single-scope legacy previous differs", base: single, change: func(value *agentv1.AgentHello) {
			value.PreviousConfigVersionId = nil
			value.PreviousConfigIdentity = nil
		}},
		{name: "duplicate scope", base: multi, change: func(value *agentv1.AgentHello) {
			value.ScopedConfigIdentities[1].ConfigurationScopeId = value.ScopedConfigIdentities[0].ConfigurationScopeId
		}},
		{name: "nil entry", base: multi, change: func(value *agentv1.AgentHello) { value.ScopedConfigIdentities[1] = nil }},
		{name: "noncanonical scope", base: multi, change: func(value *agentv1.AgentHello) { value.ScopedConfigIdentities[0].ConfigurationScopeId = "SCOPE" }},
		{name: "nil scope", base: multi, change: func(value *agentv1.AgentHello) {
			value.ScopedConfigIdentities[0].ConfigurationScopeId = uuid.Nil.String()
		}},
		{name: "empty entry", base: multi, change: func(value *agentv1.AgentHello) { value.ScopedConfigIdentities[1].LastApplyResult = nil }},
		{name: "current version without identity", base: multi, change: func(value *agentv1.AgentHello) { value.ScopedConfigIdentities[0].CurrentConfigIdentity = nil }},
		{name: "current identity mismatch", base: multi, change: func(value *agentv1.AgentHello) {
			value.ScopedConfigIdentities[0].CurrentConfigIdentity.ConfigVersionId = uuid.NewString()
		}},
		{name: "previous without current", base: multi, change: func(value *agentv1.AgentHello) {
			id := uuid.NewString()
			value.ScopedConfigIdentities[1].PreviousConfigVersionId = proto.String(id)
			value.ScopedConfigIdentities[1].PreviousConfigIdentity = testActiveIdentity(id, bytes.Repeat([]byte{0x64}, 32))
		}},
		{name: "previous identity without version", base: multi, change: func(value *agentv1.AgentHello) {
			value.ScopedConfigIdentities[0].PreviousConfigVersionId = nil
		}},
		{name: "previous equals current", base: multi, change: func(value *agentv1.AgentHello) {
			entry := value.ScopedConfigIdentities[0]
			entry.PreviousConfigVersionId = proto.String(entry.GetCurrentConfigVersionId())
			entry.PreviousConfigIdentity = proto.Clone(entry.CurrentConfigIdentity).(*agentv1.ActiveConfigIdentity)
		}},
		{name: "short digest", base: multi, change: func(value *agentv1.AgentHello) {
			value.ScopedConfigIdentities[0].CurrentConfigIdentity.ArtifactSha256 = make([]byte, 31)
		}},
		{name: "nonterminal result", base: multi, change: func(value *agentv1.AgentHello) {
			value.ScopedConfigIdentities[0].LastApplyResult.State = agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STARTED
		}},
		{name: "failed result without error code", base: multi, change: func(value *agentv1.AgentHello) {
			value.ScopedConfigIdentities[1].LastApplyResult.ErrorCode = commonv1.ErrorCode_ERROR_CODE_UNSPECIFIED
		}},
		{name: "healthy result with error code", base: multi, change: func(value *agentv1.AgentHello) {
			value.ScopedConfigIdentities[0].LastApplyResult.ErrorCode = commonv1.ErrorCode_ERROR_CODE_INTERNAL
		}},
		{name: "result without finish time", base: multi, change: func(value *agentv1.AgentHello) {
			value.ScopedConfigIdentities[0].LastApplyResult.FinishedTime = nil
		}},
		{name: "result zero attempt", base: multi, change: func(value *agentv1.AgentHello) {
			value.ScopedConfigIdentities[0].LastApplyResult.Attempt = 0
		}},
		{name: "too many scopes", base: multi, change: func(value *agentv1.AgentHello) {
			for len(value.ScopedConfigIdentities) <= maxScopedConfigIdentities {
				value.ScopedConfigIdentities = append(value.ScopedConfigIdentities, testScopedIdentity(uuid.NewString(), uuid.NewString(), nil))
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := proto.Clone(test.base).(*agentv1.AgentHello)
			test.change(candidate)
			if err := gateway.validateHello(candidate); err == nil {
				t.Fatal("invalid scoped hello was accepted")
			}
		})
	}
}

func TestHeartbeatScopedConfigIdentitiesValidation(t *testing.T) {
	gateway := newHeartbeatGateway(t, &fakeHeartbeatSink{}, nil)
	scopeA, scopeB := uuid.NewString(), uuid.NewString()
	heartbeat := validHeartbeatRequest(1, 1, 2, uuid.NewString(), uuid.NewString()).GetHeartbeat()
	heartbeat.ActiveConfigIdentityCapability = testActiveIdentityCapability()
	heartbeat.Runtime = &agentv1.EdgeRuntimeStatus{}
	heartbeat.ScopedConfigIdentities = []*agentv1.ScopedConfigIdentity{
		testScopedIdentity(scopeA, uuid.NewString(), nil), testScopedIdentity(scopeB, uuid.NewString(), nil),
	}
	if err := gateway.validateHeartbeat(heartbeat, 1, 0, false, "", true, true); err != nil {
		t.Fatalf("valid multi-scope heartbeat rejected: %v", err)
	}
	if err := gateway.validateHeartbeat(heartbeat, 1, 0, false, "", true, false); err == nil {
		t.Fatal("scoped heartbeat was accepted without negotiated multi-tenant runtime")
	}
	legacy := proto.Clone(heartbeat).(*agentv1.Heartbeat)
	legacy.ScopedConfigIdentities = nil
	if err := gateway.validateHeartbeat(legacy, 1, 0, false, "", true, false); err != nil {
		t.Fatalf("legacy heartbeat rejected: %v", err)
	}
	loaded := proto.Clone(heartbeat).(*agentv1.Heartbeat)
	loaded.Runtime.LoadedConfigVersionId = proto.String(loaded.ScopedConfigIdentities[0].GetCurrentConfigVersionId())
	loaded.Runtime.LoadedConfigIdentity = proto.Clone(loaded.ScopedConfigIdentities[0].CurrentConfigIdentity).(*agentv1.ActiveConfigIdentity)
	if err := gateway.validateHeartbeat(loaded, 1, 0, false, "", true, true); err == nil {
		t.Fatal("multi-scope heartbeat with a node-wide loaded identity was accepted")
	}

	single := proto.Clone(heartbeat).(*agentv1.Heartbeat)
	single.ScopedConfigIdentities = single.ScopedConfigIdentities[:1]
	entry := single.ScopedConfigIdentities[0]
	single.CurrentConfigVersionId = proto.String(entry.GetCurrentConfigVersionId())
	single.CurrentConfigIdentity = proto.Clone(entry.CurrentConfigIdentity).(*agentv1.ActiveConfigIdentity)
	single.Runtime.LoadedConfigVersionId = proto.String(entry.GetCurrentConfigVersionId())
	single.Runtime.LoadedConfigIdentity = proto.Clone(entry.CurrentConfigIdentity).(*agentv1.ActiveConfigIdentity)
	if err := gateway.validateHeartbeat(single, 1, 0, false, "", true, true); err != nil {
		t.Fatalf("mirrored single-scope heartbeat rejected: %v", err)
	}
	unmirrored := proto.Clone(single).(*agentv1.Heartbeat)
	unmirrored.CurrentConfigVersionId = nil
	unmirrored.CurrentConfigIdentity = nil
	if err := gateway.validateHeartbeat(unmirrored, 1, 0, false, "", true, true); err == nil {
		t.Fatal("single-scope heartbeat without legacy mirror was accepted")
	}
}

func scopedStatus(t *testing.T, command *agentv1.DeploymentCommand, state agentv1.NodeDeploymentState, sequence uint64) *agentv1.DeploymentStatus {
	t.Helper()
	status := validDeploymentStatus(command)
	bindDeploymentStatusEvent(t, status, command)
	status.State = state
	status.TransitionSequence = sequence
	status.ConfigurationScopeId = proto.String(command.GetConfigurationScopeId())
	return status
}

func TestDeploymentStatusScopeValidation(t *testing.T) {
	gateway := newCommandGateway(t, defaultFakeControl(), &fakeCommandBus{}, nil)
	command := validDeploymentCommand()
	command.ConfigVersionId = uuid.NewString()
	command.ConfigurationScopeId = proto.String(uuid.NewString())

	for _, state := range []agentv1.NodeDeploymentState{
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_AGENT_QUEUED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STARTED,
	} {
		status := scopedStatus(t, command, state, 2)
		if err := gateway.validateDeploymentStatus(status, true, true); err != nil {
			t.Fatalf("%s scoped status rejected: %v", state, err)
		}
		if err := gateway.validateDeploymentStatus(status, true, false); err == nil {
			t.Fatalf("%s scoped status accepted without negotiated multi-tenant runtime", state)
		}
		if err := validateDeploymentStatusScopeCommandBinding(status, command); err != nil {
			t.Fatalf("%s binding rejected: %v", state, err)
		}
	}
	unscoped := scopedStatus(t, command, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STARTED, 3)
	unscoped.ConfigurationScopeId = nil
	if err := gateway.validateDeploymentStatus(unscoped, true, true); err == nil {
		t.Fatal("multi-tenant-only state without scope was accepted")
	}
	// A scoped command's ordinary status must still carry its scope.
	scopelessStaged := scopedStatus(t, command, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED, 4)
	scopelessStaged.ConfigurationScopeId = nil
	if err := gateway.validateDeploymentStatus(scopelessStaged, true, true); err != nil {
		t.Fatalf("scope-less ordinary status rejected by field validation: %v", err)
	}
	if err := validateDeploymentStatusScopeCommandBinding(scopelessStaged, command); err == nil {
		t.Fatal("scope-less status of a scoped command passed the command binding")
	}
	// An unscoped command on a multi-tenant session keeps scope-less statuses.
	legacyCommand := proto.Clone(command).(*agentv1.DeploymentCommand)
	legacyCommand.ConfigurationScopeId = nil
	legacyStatus := scopedStatus(t, legacyCommand, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED, 2)
	legacyStatus.ConfigurationScopeId = nil
	if err := gateway.validateDeploymentStatus(legacyStatus, true, true); err != nil {
		t.Fatalf("unscoped command status rejected: %v", err)
	}
	if err := validateDeploymentStatusScopeCommandBinding(legacyStatus, legacyCommand); err != nil {
		t.Fatalf("unscoped command status binding rejected: %v", err)
	}
	legacyState := scopedStatus(t, command, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_AGENT_QUEUED, 2)
	legacyState.ConfigurationScopeId = nil
	if err := gateway.validateDeploymentStatus(legacyState, true, false); err == nil {
		t.Fatal("multi-tenant-only state was accepted on a legacy session")
	}
	nilScope := scopedStatus(t, command, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STARTED, 3)
	nilScope.ConfigurationScopeId = proto.String(uuid.Nil.String())
	if err := gateway.validateDeploymentStatus(nilScope, true, true); err == nil {
		t.Fatal("nil status scope was accepted")
	}
	mismatch := scopedStatus(t, command, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STARTED, 3)
	mismatch.ConfigurationScopeId = proto.String(uuid.NewString())
	if err := validateDeploymentStatusScopeCommandBinding(mismatch, command); err == nil {
		t.Fatal("status scope differing from its command was accepted")
	}
	superseded := scopedStatus(t, command, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_SUPERSEDED, 3)
	if err := gateway.validateDeploymentStatus(superseded, true, true); err == nil {
		t.Fatal("superseded status that changed the running config was accepted")
	}
	superseded.RunningConfigUnchanged = true
	if err := gateway.validateDeploymentStatus(superseded, true, true); err != nil {
		t.Fatalf("valid superseded status rejected: %v", err)
	}
	if !terminalDeploymentStatus(superseded.State) {
		t.Fatal("superseded must be terminal")
	}
}

func TestSupersededStatusAcknowledgesCommand(t *testing.T) {
	bus := &fakeCommandBus{}
	gateway := newCommandGateway(t, defaultFakeControl(), bus, nil)
	command := validDeploymentCommand()
	command.ConfigVersionId = uuid.NewString()
	command.ConfigurationScopeId = proto.String(uuid.NewString())
	status := scopedStatus(t, command, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_SUPERSEDED, 3)
	status.RunningConfigUnchanged = true
	delivery := &fakeCommandDelivery{command: command}
	pending := pendingCommandSet{commandKey(command): {command: command, deliveries: []CommandDelivery{delivery}}}
	if err := gateway.persistStatusAndAckCommand(context.Background(), testNodeID, status, pending, true, false, true); err != nil {
		t.Fatalf("superseded status rejected: %v", err)
	}
	if len(pending) != 0 || delivery.acks.Load() != 1 || len(bus.published) != 1 {
		t.Fatalf("superseded status did not settle its command: pending=%d acks=%d published=%d", len(pending), delivery.acks.Load(), len(bus.published))
	}
	other := validDeploymentCommand()
	other.ConfigVersionId = uuid.NewString()
	other.ConfigurationScopeId = proto.String(uuid.NewString())
	wrong := scopedStatus(t, other, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STARTED, 3)
	wrong.ConfigurationScopeId = proto.String(uuid.NewString())
	pending = pendingCommandSet{commandKey(other): {command: other}}
	if err := gateway.persistStatusAndAckCommand(context.Background(), testNodeID, wrong, pending, true, false, true); err == nil {
		t.Fatal("status with a scope differing from its command was published")
	}
}

// Until the Gateway validates per-scope telemetry authorization it never
// echoes scoped_records, so a record naming a scope must not be published.
func TestTelemetryRejectsUnnegotiatedScopedRecord(t *testing.T) {
	batch := telemetryCaptureBatch(t, agentv1.TelemetryKind_TELEMETRY_KIND_ACCESS_V1, map[string]any{
		"capture_policy_revision": uint64(7), "capture_policy_digest": telemetryCapturePolicyDigest,
	})
	if _, err := validateTelemetryBatch(batch, 1, nodeIdentity{NodeID: testNodeID},
		telemetryTestAuthorization(), DefaultTelemetryConfig(), time.Now().UTC()); err != nil {
		t.Fatalf("baseline record rejected: %v", err)
	}
	batch.Records[0].ConfigurationScopeId = proto.String(uuid.NewString())
	if _, err := validateTelemetryBatch(batch, 1, nodeIdentity{NodeID: testNodeID},
		telemetryTestAuthorization(), DefaultTelemetryConfig(), time.Now().UTC()); err == nil {
		t.Fatal("unnegotiated scoped telemetry record was accepted")
	}
}
