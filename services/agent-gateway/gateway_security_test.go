package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type authorizationState struct {
	ttl                time.Duration
	connectionAllowed  bool
	revoked            bool
	administrative     controlv1.NodeAdministrativeState
	accepted           *commonv1.ProtocolVersionRange
	artifactKeyID      string
	deploymentsAllowed bool
	err                error
}

func allowedAuthorization(ttl time.Duration) authorizationState {
	return authorizationState{
		ttl:               ttl,
		connectionAllowed: true,
		administrative:    controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_ACTIVE,
		accepted:          versionRange(1, 0),
		artifactKeyID:     "artifact-key",
	}
}

type scriptedControl struct {
	*fakeControl
	mu             sync.Mutex
	states         []authorizationState
	authorizations int
	serials        []string
	digests        [][]byte
	fetchCalls     atomic.Int32
	cleanupOnly    []bool
	artifact       func(context.Context) ArtifactStream
}

func (c *scriptedControl) GetNodeAuthorization(_ context.Context, request *controlv1.GetNodeAuthorizationRequest) (*controlv1.GetNodeAuthorizationResponse, error) {
	c.mu.Lock()
	index := c.authorizations
	if index >= len(c.states) {
		index = len(c.states) - 1
	}
	state := c.states[index]
	c.authorizations++
	c.serials = append(c.serials, request.CertificateSerialNumber)
	c.digests = append(c.digests, bytes.Clone(request.GetCertificateSha256()))
	c.mu.Unlock()
	if state.err != nil {
		return nil, state.err
	}
	artifactKeyID := state.artifactKeyID
	if artifactKeyID == "" {
		artifactKeyID = "artifact-key"
	}
	return &controlv1.GetNodeAuthorizationResponse{
		NodeId:                   request.NodeId,
		AdministrativeState:      state.administrative,
		ConnectionAllowed:        state.connectionAllowed,
		CertificateRevoked:       state.revoked,
		AcceptedProtocolVersions: state.accepted,
		SnapshotExpirationTime:   timestamppb.New(time.Now().Add(state.ttl)),
		ArtifactEncryptionKeyId:  artifactKeyID,
		DeploymentsAllowed:       state.deploymentsAllowed,
	}, nil
}

func TestAuthorizationInitialAndRefreshCarryExactLeafCertificateDigest(t *testing.T) {
	control := &scriptedControl{
		fakeControl: defaultFakeControl(),
		states:      []authorizationState{allowedAuthorization(100 * time.Millisecond), allowedAuthorization(time.Hour)},
	}
	servers := startTestServersWithConfig(t, control, func(config *Config) {
		config.HeartbeatInterval = 10 * time.Millisecond
		config.OfflineAfter = 2 * time.Second
	})
	_, _, cleanup := establishSession(t, servers)
	defer cleanup()
	want := sha256.Sum256(servers.clientCertificate.Certificate[0])
	waitForTest(t, time.Second, func() bool {
		control.mu.Lock()
		defer control.mu.Unlock()
		return len(control.digests) >= 2
	})
	control.mu.Lock()
	digests := make([][]byte, len(control.digests))
	for index := range control.digests {
		digests[index] = bytes.Clone(control.digests[index])
	}
	control.mu.Unlock()
	for index, digest := range digests {
		if !bytes.Equal(digest, want[:]) {
			t.Fatalf("authorization digest %d = %x, want %x", index, digest, want)
		}
	}
}

func (c *scriptedControl) FetchArtifact(ctx context.Context, request *controlv1.FetchArtifactRequest) (ArtifactStream, error) {
	c.fetchCalls.Add(1)
	c.mu.Lock()
	c.cleanupOnly = append(c.cleanupOnly, request.GetCleanupOnly())
	c.mu.Unlock()
	if c.artifact != nil {
		return c.artifact(ctx), nil
	}
	return &fakeArtifactStream{}, nil
}

func TestAuthorizationRefreshClosesInvalidSession(t *testing.T) {
	tests := []struct {
		name     string
		second   authorizationState
		wantCode codes.Code
	}{
		{name: "disabled", second: authorizationState{ttl: time.Hour, connectionAllowed: true, administrative: controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_DISABLED, accepted: versionRange(1, 0)}, wantCode: codes.PermissionDenied},
		{name: "revoked", second: authorizationState{ttl: time.Hour, connectionAllowed: true, revoked: true, administrative: controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_ACTIVE, accepted: versionRange(1, 0)}, wantCode: codes.PermissionDenied},
		{name: "expired", second: authorizationState{ttl: -time.Second, connectionAllowed: true, administrative: controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_ACTIVE, accepted: versionRange(1, 0)}, wantCode: codes.Unavailable},
		{name: "protocol incompatible", second: authorizationState{ttl: time.Hour, connectionAllowed: true, administrative: controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_ACTIVE, accepted: versionRange(2, 0)}, wantCode: codes.FailedPrecondition},
		{name: "artifact key changed", second: authorizationState{ttl: time.Hour, connectionAllowed: true, administrative: controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_ACTIVE, accepted: versionRange(1, 0), artifactKeyID: "replacement-key"}, wantCode: codes.FailedPrecondition},
		// A deleted node has no row any more: the control plane answers
		// NotFound and the session ends on the next refresh.
		{name: "node deleted", second: authorizationState{err: status.Error(codes.NotFound, "requested identity record was not found")}, wantCode: codes.NotFound},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			control := &scriptedControl{
				fakeControl: defaultFakeControl(),
				states:      []authorizationState{allowedAuthorization(200 * time.Millisecond), test.second},
			}
			servers := startTestServersWithConfig(t, control, func(config *Config) {
				config.HeartbeatInterval = 10 * time.Millisecond
				config.OfflineAfter = 2 * time.Second
			})
			stream, _, cleanup := establishSession(t, servers)
			defer cleanup()
			_, err := stream.Recv()
			if status.Code(err) != test.wantCode {
				t.Fatalf("session code = %v, want %v", status.Code(err), test.wantCode)
			}
			control.mu.Lock()
			calls := control.authorizations
			control.mu.Unlock()
			if calls < 2 {
				t.Fatalf("authorization calls = %d, want at least 2", calls)
			}
		})
	}
}

func TestAuthorizeConnectionAdministrativeStateMatrix(t *testing.T) {
	tests := []struct {
		name            string
		state           authorizationState
		wantCode        codes.Code
		wantDeployments bool
	}{
		{name: "active", state: authorizationState{ttl: time.Hour, connectionAllowed: true, deploymentsAllowed: true, administrative: controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_ACTIVE, accepted: versionRange(1, 0)}, wantCode: codes.OK, wantDeployments: true},
		{name: "draining", state: authorizationState{ttl: time.Hour, connectionAllowed: true, deploymentsAllowed: true, administrative: controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_DRAINING, accepted: versionRange(1, 0)}, wantCode: codes.OK},
		{name: "draining connection denied", state: authorizationState{ttl: time.Hour, administrative: controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_DRAINING, accepted: versionRange(1, 0)}, wantCode: codes.PermissionDenied},
		{name: "active connection denied", state: authorizationState{ttl: time.Hour, administrative: controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_ACTIVE, accepted: versionRange(1, 0)}, wantCode: codes.PermissionDenied},
		{name: "active certificate revoked", state: authorizationState{ttl: time.Hour, connectionAllowed: true, revoked: true, administrative: controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_ACTIVE, accepted: versionRange(1, 0)}, wantCode: codes.PermissionDenied},
		// A self-registered node awaiting initialization keeps its session for
		// heartbeat and certificate renewal, but never receives deployments.
		{name: "pending", state: authorizationState{ttl: time.Hour, connectionAllowed: true, deploymentsAllowed: true, administrative: controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_PENDING, accepted: versionRange(1, 0)}, wantCode: codes.OK},
		{name: "pending connection denied", state: authorizationState{ttl: time.Hour, administrative: controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_PENDING, accepted: versionRange(1, 0)}, wantCode: codes.PermissionDenied},
		{name: "disabled", state: authorizationState{ttl: time.Hour, connectionAllowed: true, administrative: controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_DISABLED, accepted: versionRange(1, 0)}, wantCode: codes.PermissionDenied},
		{name: "retired", state: authorizationState{ttl: time.Hour, connectionAllowed: true, administrative: controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_RETIRED, accepted: versionRange(1, 0)}, wantCode: codes.PermissionDenied},
		{name: "unspecified", state: authorizationState{ttl: time.Hour, connectionAllowed: true, administrative: controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_UNSPECIFIED, accepted: versionRange(1, 0)}, wantCode: codes.PermissionDenied},
		{name: "unknown", state: authorizationState{ttl: time.Hour, connectionAllowed: true, administrative: controlv1.NodeAdministrativeState(99), accepted: versionRange(1, 0)}, wantCode: codes.PermissionDenied},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			control := &scriptedControl{fakeControl: defaultFakeControl(), states: []authorizationState{test.state}}
			config := DefaultConfig()
			config.GatewayInstanceID = "gateway-authorization-matrix"
			config.GatewayVersion = "test"
			gateway, err := New(config, control, NewMemorySessionCoordinator())
			if err != nil {
				t.Fatal(err)
			}
			response, err := gateway.authorizeConnection(context.Background(), nodeIdentity{NodeID: testNodeID, SerialNumber: "a"}, nil)
			if status.Code(err) != test.wantCode {
				t.Fatalf("authorizeConnection() code = %v, want %v", status.Code(err), test.wantCode)
			}
			if test.wantCode == codes.OK && (response == nil || response.DeploymentsAllowed != test.wantDeployments) {
				t.Fatalf("authorizeConnection() = %#v, want deployments_allowed=%t", response, test.wantDeployments)
			}
		})
	}
}

func TestAuthorizationRefreshKeepsDrainingSessionConnected(t *testing.T) {
	initial := allowedAuthorization(200 * time.Millisecond)
	initial.deploymentsAllowed = true
	draining := allowedAuthorization(time.Hour)
	draining.administrative = controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_DRAINING
	draining.deploymentsAllowed = false
	control := &scriptedControl{fakeControl: defaultFakeControl(), states: []authorizationState{initial, draining}}
	servers := startTestServersWithConfig(t, control, func(config *Config) {
		config.HeartbeatInterval = 10 * time.Millisecond
		config.OfflineAfter = 2 * time.Second
	})
	stream, hello, cleanup := establishSession(t, servers)
	defer cleanup()
	waitForTest(t, time.Second, func() bool {
		control.mu.Lock()
		defer control.mu.Unlock()
		return control.authorizations >= 2
	})
	if err := stream.Send(validHeartbeatRequest(hello.SessionEpoch, 1, 2, uuid.NewString(), uuid.NewString())); err != nil {
		t.Fatal(err)
	}
	response, err := stream.Recv()
	if err != nil || response.GetHeartbeatAck() == nil {
		t.Fatalf("draining session heartbeat = %#v, %v", response, err)
	}
}

func TestMessageReplayWindowContractAndBehavior(t *testing.T) {
	agentField := (&agentv1.GatewayHello{}).ProtoReflect().Descriptor().Fields().ByName(protoreflect.Name("message_id_replay_window"))
	if agentField == nil || agentField.Number() != 10 {
		t.Fatalf("GatewayHello replay field = %v, want field 10", agentField)
	}
	controlField := (&controlv1.GetNodeAuthorizationResponse{}).ProtoReflect().Descriptor().Fields().ByName(protoreflect.Name("artifact_encryption_key_id"))
	if controlField == nil || controlField.Number() != 10 {
		t.Fatalf("authorization artifact key field = %v, want field 10", controlField)
	}
	revokedField := (&controlv1.GetNodeAuthorizationResponse{}).ProtoReflect().Descriptor().Fields().ByName(protoreflect.Name("certificate_revoked"))
	if revokedField == nil || revokedField.Number() != 6 {
		t.Fatalf("authorization certificate revoked field = %v, want field 6", revokedField)
	}

	servers := startTestServers(t, defaultFakeControl())
	t.Run("identical retransmission", func(t *testing.T) {
		stream, hello, cleanup := establishSession(t, servers)
		defer cleanup()
		if hello.MessageIdReplayWindow != defaultMessageReplayWindow {
			t.Fatalf("replay window = %d, want %d", hello.MessageIdReplayWindow, defaultMessageReplayWindow)
		}
		request := validHeartbeatRequest(hello.SessionEpoch, 1, 2, uuid.NewString(), uuid.NewString())
		if err := stream.Send(request); err != nil {
			t.Fatal(err)
		}
		if _, err := stream.Recv(); err != nil {
			t.Fatal(err)
		}
		retransmission := proto.Clone(request).(*agentv1.ConnectRequest)
		if err := stream.Send(retransmission); err != nil {
			t.Fatal(err)
		}
		if response, err := stream.Recv(); err != nil || response.GetHeartbeatAck() == nil {
			t.Fatalf("retransmission ack = %v, %v", response, err)
		}
	})
	t.Run("same ID changed payload", func(t *testing.T) {
		stream, hello, cleanup := establishSession(t, servers)
		defer cleanup()
		request := validHeartbeatRequest(hello.SessionEpoch, 1, 2, uuid.NewString(), uuid.NewString())
		if err := stream.Send(request); err != nil {
			t.Fatal(err)
		}
		if _, err := stream.Recv(); err != nil {
			t.Fatal(err)
		}
		changed := proto.Clone(request).(*agentv1.ConnectRequest)
		changed.GetHeartbeat().CurrentConfigVersionId = proto.String(uuid.NewString())
		if err := stream.Send(changed); err != nil {
			t.Fatal(err)
		}
		_, err := stream.Recv()
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("changed replay code = %v, want FailedPrecondition", status.Code(err))
		}
	})

	window := newMessageReplayWindow(2)
	requests := []*agentv1.ConnectRequest{
		validHeartbeatRequest(1, 1, 1, uuid.NewString(), uuid.NewString()),
		validHeartbeatRequest(1, 2, 2, uuid.NewString(), uuid.NewString()),
		validHeartbeatRequest(1, 3, 3, uuid.NewString(), uuid.NewString()),
	}
	for index, request := range requests {
		if _, err := window.accept(request, uint64(index)); err != nil {
			t.Fatal(err)
		}
	}
	if len(window.entries) != 2 {
		t.Fatalf("retained message IDs = %d, want 2", len(window.entries))
	}
	if _, err := window.accept(requests[0], 3); !errors.Is(err, ErrStreamSequence) {
		t.Fatalf("evicted replay error = %v, want stream sequence", err)
	}
}

func TestNodeAuthorizationCertificateDigestContract(t *testing.T) {
	field := (&controlv1.GetNodeAuthorizationRequest{}).ProtoReflect().Descriptor().Fields().ByName("certificate_sha256")
	if field == nil || field.Number() != 5 || field.Kind() != protoreflect.BytesKind || field.Cardinality() != protoreflect.Optional {
		t.Fatalf("certificate_sha256 field = %v, want optional bytes field 5", field)
	}
	renewalField := (&controlv1.RenewNodeCertificateRequest{}).ProtoReflect().Descriptor().Fields().ByName("current_certificate_sha256")
	if renewalField == nil || renewalField.Number() != 6 || renewalField.Kind() != protoreflect.BytesKind || renewalField.Cardinality() != protoreflect.Optional {
		t.Fatalf("current_certificate_sha256 field = %v, want optional bytes field 6", renewalField)
	}
}

func TestConnectRejectsArtifactEncryptionKeyMismatch(t *testing.T) {
	state := allowedAuthorization(time.Hour)
	state.artifactKeyID = "different-key"
	control := &scriptedControl{fakeControl: defaultFakeControl(), states: []authorizationState{state}}
	servers := startTestServers(t, control)
	connection := dialGateway(t, servers.mtlsAddress, servers.pki.rootPool, servers.clientCertificate)
	defer connection.Close()
	client := agentv1.NewAgentGatewayServiceClient(connection)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream, err := client.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(validHello(testNodeID, versionRange(1, 0), 1)); err != nil {
		t.Fatal(err)
	}
	_, err = stream.Recv()
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("Connect code = %v, want FailedPrecondition", status.Code(err))
	}
}

func TestSessionFencingLinearizesSendAndTakeover(t *testing.T) {
	coordinator := NewMemorySessionCoordinator()
	oldLease, err := coordinator.Acquire(context.Background(), testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	sendStarted := make(chan struct{})
	releaseSend := make(chan struct{})
	sendDone := make(chan error, 1)
	go func() {
		sendDone <- oldLease.FencedSend(func() error {
			close(sendStarted)
			<-releaseSend
			return nil
		})
	}()
	<-sendStarted
	takeoverDone := make(chan SessionLease, 1)
	go func() {
		lease, _ := coordinator.Acquire(context.Background(), testNodeID)
		takeoverDone <- lease
	}()
	select {
	case <-takeoverDone:
		t.Fatal("takeover linearized before the in-flight send completed")
	case <-time.After(30 * time.Millisecond):
	}
	close(releaseSend)
	if err := <-sendDone; err != nil {
		t.Fatal(err)
	}
	newLease := <-takeoverDone
	defer newLease.Release()
	called := false
	if err := oldLease.FencedSend(func() error { called = true; return nil }); !errors.Is(err, ErrSessionSuperseded) {
		t.Fatalf("old lease send error = %v, want superseded", err)
	}
	if called {
		t.Fatal("old lease invoked a send callback after takeover")
	}
}

func TestSessionFencingIsScopedPerNode(t *testing.T) {
	coordinator := NewMemorySessionCoordinator()
	oldLease, err := coordinator.Acquire(context.Background(), uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	defer oldLease.Release()

	sendStarted := make(chan struct{})
	releaseSend := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseSend) }) }
	defer release()
	sendDone := make(chan error, 1)
	go func() {
		sendDone <- oldLease.FencedSend(func() error {
			close(sendStarted)
			<-releaseSend
			return nil
		})
	}()
	<-sendStarted

	type acquireResult struct {
		lease SessionLease
		err   error
	}
	acquired := make(chan acquireResult, 1)
	go func() {
		lease, err := coordinator.Acquire(context.Background(), uuid.NewString())
		acquired <- acquireResult{lease: lease, err: err}
	}()
	select {
	case result := <-acquired:
		if result.err != nil {
			t.Fatal(result.err)
		}
		result.lease.Release()
	case <-time.After(time.Second):
		t.Fatal("a blocked send for one node delayed another node's session")
	}

	release()
	if err := <-sendDone; err != nil {
		t.Fatal(err)
	}
}

func TestGatewayHelloUsesSessionFence(t *testing.T) {
	lease := &alwaysSupersededLease{done: make(chan struct{})}
	close(lease.done)
	config := DefaultConfig()
	config.GatewayInstanceID = "gateway-fence"
	config.GatewayVersion = "test"
	gateway, err := New(config, defaultFakeControl(), fixedSessionCoordinator{lease: lease})
	if err != nil {
		t.Fatal(err)
	}
	requests := make(chan *agentv1.ConnectRequest, 1)
	requests <- validHello(testNodeID, versionRange(1, 0), 1)
	ctx, cancel := context.WithCancel(authenticatedTestContext(t))
	stream := &fakeBidiStream{
		ctx: ctx,
		receive: func() (*agentv1.ConnectRequest, error) {
			select {
			case request := <-requests:
				return request, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
	}
	err = gateway.Connect(stream)
	cancel()
	if status.Code(err) != codes.Aborted {
		t.Fatalf("Connect code = %v, want Aborted", status.Code(err))
	}
	if lease.fences.Load() != 1 || stream.sends.Load() != 0 {
		t.Fatalf("GatewayHello fences = %d, sends = %d, want 1 and 0", lease.fences.Load(), stream.sends.Load())
	}
}

func TestContextErrorsUseCanonicalGRPCStatus(t *testing.T) {
	for _, test := range []struct {
		err  error
		code codes.Code
	}{{context.Canceled, codes.Canceled}, {context.DeadlineExceeded, codes.DeadlineExceeded}} {
		if code := status.Code(rpcError(test.err)); code != test.code {
			t.Fatalf("rpcError(%v) code = %v, want %v", test.err, code, test.code)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := receiveWithTimeout(ctx, make(chan connectReceive), time.Second)
	if status.Code(err) != codes.Canceled {
		t.Fatalf("receive cancellation code = %v, want Canceled", status.Code(err))
	}
	received := make(chan connectReceive, 1)
	received <- connectReceive{err: context.DeadlineExceeded}
	_, err = receiveWithTimeout(context.Background(), received, time.Second)
	if status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("receive result code = %v, want DeadlineExceeded", status.Code(err))
	}
}

func TestSessionClosesAfterOfflineDeadline(t *testing.T) {
	servers := startTestServersWithConfig(t, defaultFakeControl(), func(config *Config) {
		config.HeartbeatInterval = 10 * time.Millisecond
		config.OfflineAfter = 60 * time.Millisecond
	})
	stream, _, cleanup := establishSession(t, servers)
	defer cleanup()
	_, err := stream.Recv()
	if status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("session code = %v, want DeadlineExceeded", status.Code(err))
	}
}

func TestFetchArtifactReauthorizesCertificateBeforeFetch(t *testing.T) {
	tests := []struct {
		name      string
		state     authorizationState
		wantCode  codes.Code
		wantFetch int32
		// wantCleanupOnly: a session without deployments may only fetch a
		// CLEANUP_ONLY ACME HTTP-01 overlay; Control enforces the purpose.
		wantCleanupOnly bool
	}{
		{name: "active", state: authorizationState{ttl: time.Hour, connectionAllowed: true, deploymentsAllowed: true, administrative: controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_ACTIVE, accepted: versionRange(1, 0)}, wantCode: codes.OK, wantFetch: 1},
		{name: "active deployments denied", state: authorizationState{ttl: time.Hour, connectionAllowed: true, administrative: controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_ACTIVE, accepted: versionRange(1, 0)}, wantCode: codes.OK, wantFetch: 1, wantCleanupOnly: true},
		{name: "revoked", state: authorizationState{ttl: time.Hour, connectionAllowed: true, revoked: true, administrative: controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_ACTIVE, accepted: versionRange(1, 0)}, wantCode: codes.PermissionDenied},
		{name: "disabled", state: authorizationState{ttl: time.Hour, connectionAllowed: true, administrative: controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_DISABLED, accepted: versionRange(1, 0)}, wantCode: codes.PermissionDenied},
		{name: "expired snapshot", state: authorizationState{ttl: -time.Second, connectionAllowed: true, administrative: controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_ACTIVE, accepted: versionRange(1, 0)}, wantCode: codes.Unavailable},
		{name: "draining", state: authorizationState{ttl: time.Hour, connectionAllowed: true, deploymentsAllowed: true, administrative: controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_DRAINING, accepted: versionRange(1, 0)}, wantCode: codes.OK, wantFetch: 1, wantCleanupOnly: true},
		{name: "draining connection denied", state: authorizationState{ttl: time.Hour, administrative: controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_DRAINING, accepted: versionRange(1, 0)}, wantCode: codes.PermissionDenied},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			control := &scriptedControl{fakeControl: defaultFakeControl(), states: []authorizationState{test.state}}
			servers := startTestServers(t, control)
			connection := dialGateway(t, servers.mtlsAddress, servers.pki.rootPool, servers.clientCertificate)
			defer connection.Close()
			client := agentv1.NewAgentGatewayServiceClient(connection)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			artifact, err := client.FetchArtifact(ctx, validArtifactRequest())
			if err == nil {
				_, err = artifact.Recv()
			}
			if test.wantCode == codes.OK && errors.Is(err, io.EOF) {
				err = nil
			}
			if status.Code(err) != test.wantCode {
				t.Fatalf("FetchArtifact code = %v, want %v", status.Code(err), test.wantCode)
			}
			if calls := control.fetchCalls.Load(); calls != test.wantFetch {
				t.Fatalf("control FetchArtifact calls = %d, want %d", calls, test.wantFetch)
			}
			control.mu.Lock()
			serials := append([]string(nil), control.serials...)
			cleanupOnly := append([]bool(nil), control.cleanupOnly...)
			control.mu.Unlock()
			if test.wantFetch == 1 && (len(cleanupOnly) != 1 || cleanupOnly[0] != test.wantCleanupOnly) {
				t.Fatalf("control FetchArtifact cleanup_only = %v, want %v", cleanupOnly, test.wantCleanupOnly)
			}
			if len(serials) != 1 || serials[0] != "a" {
				t.Fatalf("authorization certificate serials = %v, want [a]", serials)
			}
		})
	}
}

func TestArtifactReceiveDeadlineCancelsBlockedReceive(t *testing.T) {
	done := make(chan struct{})
	state := allowedAuthorization(time.Hour)
	state.deploymentsAllowed = true
	control := &scriptedControl{
		fakeControl: defaultFakeControl(),
		states:      []authorizationState{state},
		artifact: func(ctx context.Context) ArtifactStream {
			return &blockingArtifactStream{ctx: ctx, done: done}
		},
	}
	gateway := newUnitGateway(t, control, func(config *Config) {
		config.ArtifactTransferTimeout = 30 * time.Millisecond
	})
	ctx := authenticatedTestContext(t)
	err := gateway.FetchArtifact(validArtifactRequest(), &fakeArtifactServerStream{ctx: ctx})
	if status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("FetchArtifact code = %v, want DeadlineExceeded", status.Code(err))
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("blocked artifact receive did not exit after cancellation")
	}
}

func TestArtifactSendDeadlineCancelsBlockedSend(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	err := sendArtifactWithContext(ctx, &agentv1.FetchArtifactResponse{}, func(ctx context.Context, _ *agentv1.FetchArtifactResponse) error {
		<-ctx.Done()
		close(done)
		return ctx.Err()
	})
	if status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("send code = %v, want DeadlineExceeded", status.Code(err))
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("blocked artifact send did not exit after cancellation")
	}
}

func TestConnectReceivePumpExitsWhenQueueIsFullAndContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	secondReceive := make(chan struct{})
	var calls atomic.Int32
	stream := &fakeBidiStream{
		ctx: ctx,
		receive: func() (*agentv1.ConnectRequest, error) {
			if calls.Add(1) == 2 {
				close(secondReceive)
			}
			return validHello(testNodeID, versionRange(1, 0), 1), nil
		},
	}
	_, done := pumpConnectRequests(stream)
	select {
	case <-secondReceive:
	case <-time.After(time.Second):
		t.Fatal("receive pump did not fill its output queue")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("receive pump did not exit after stream cancellation")
	}
}

func TestSupersededSessionDoesNotAckBufferedHeartbeat(t *testing.T) {
	control := defaultFakeControl()
	gateway := newUnitGateway(t, control, nil)
	coordinator := NewMemorySessionCoordinator()
	oldLease, err := coordinator.Acquire(context.Background(), testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan connectReceive, 1)
	received <- connectReceive{request: validHeartbeatRequest(oldLease.Epoch(), 1, 2, uuid.NewString(), uuid.NewString())}
	newLease, err := coordinator.Acquire(context.Background(), testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer newLease.Release()
	stream := &fakeBidiStream{ctx: context.Background()}
	err = gateway.serveSession(
		stream,
		received,
		oldLease,
		newMessageReplayWindow(defaultMessageReplayWindow),
		1,
		nodeIdentity{NodeID: testNodeID, SerialNumber: "10"},
		"",
		versionRange(1, 0),
		&commonv1.ProtocolVersion{Major: 1, Minor: 0},
		"artifact-key",
		time.Now().Add(time.Hour),
		false,
		false,
	)
	if status.Code(err) != codes.Aborted {
		t.Fatalf("session code = %v, want Aborted", status.Code(err))
	}
	if sends := stream.sends.Load(); sends != 0 {
		t.Fatalf("old session sent %d responses, want 0", sends)
	}
}

type blockingArtifactStream struct {
	ctx  context.Context
	done chan struct{}
	once sync.Once
}

func (s *blockingArtifactStream) Recv() (*controlv1.FetchArtifactResponse, error) {
	<-s.ctx.Done()
	s.once.Do(func() { close(s.done) })
	return nil, s.ctx.Err()
}

type fakeBidiStream struct {
	ctx     context.Context
	receive func() (*agentv1.ConnectRequest, error)
	sends   atomic.Int32
}

func (s *fakeBidiStream) Context() context.Context { return s.ctx }
func (s *fakeBidiStream) Recv() (*agentv1.ConnectRequest, error) {
	if s.receive == nil {
		return nil, io.EOF
	}
	return s.receive()
}
func (s *fakeBidiStream) Send(*agentv1.ConnectResponse) error { s.sends.Add(1); return nil }
func (s *fakeBidiStream) SetHeader(metadata.MD) error         { return nil }
func (s *fakeBidiStream) SendHeader(metadata.MD) error        { return nil }
func (s *fakeBidiStream) SetTrailer(metadata.MD)              {}
func (s *fakeBidiStream) SendMsg(any) error                   { return nil }
func (s *fakeBidiStream) RecvMsg(any) error                   { return io.EOF }

type fixedSessionCoordinator struct {
	lease SessionLease
}

func (c fixedSessionCoordinator) Acquire(context.Context, string) (SessionLease, error) {
	return c.lease, nil
}

type alwaysSupersededLease struct {
	done   chan struct{}
	fences atomic.Int32
}

func (l *alwaysSupersededLease) ID() string                  { return uuid.NewString() }
func (l *alwaysSupersededLease) Epoch() uint64               { return 1 }
func (l *alwaysSupersededLease) Superseded() <-chan struct{} { return l.done }
func (l *alwaysSupersededLease) Release()                    {}
func (l *alwaysSupersededLease) FencedSend(func() error) error {
	l.fences.Add(1)
	return ErrSessionSuperseded
}

type fakeArtifactServerStream struct {
	ctx context.Context
}

func (s *fakeArtifactServerStream) Context() context.Context                  { return s.ctx }
func (s *fakeArtifactServerStream) Send(*agentv1.FetchArtifactResponse) error { return nil }
func (s *fakeArtifactServerStream) SetHeader(metadata.MD) error               { return nil }
func (s *fakeArtifactServerStream) SendHeader(metadata.MD) error              { return nil }
func (s *fakeArtifactServerStream) SetTrailer(metadata.MD)                    {}
func (s *fakeArtifactServerStream) SendMsg(any) error                         { return nil }
func (s *fakeArtifactServerStream) RecvMsg(any) error                         { return io.EOF }

func newUnitGateway(t *testing.T, control ControlPlane, configure func(*Config)) *Gateway {
	t.Helper()
	config := DefaultConfig()
	config.GatewayInstanceID = "gateway-unit"
	config.GatewayVersion = "test"
	if configure != nil {
		configure(&config)
	}
	gateway, err := New(config, control, NewMemorySessionCoordinator())
	if err != nil {
		t.Fatal(err)
	}
	return gateway
}

func authenticatedTestContext(t *testing.T) context.Context {
	t.Helper()
	pki := newTestPKI(t)
	certificate := pki.client(t, 10, nodeSPIFFEPrefix+testNodeID, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	authInfo := credentials.TLSInfo{State: tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf}}}}
	return peer.NewContext(context.Background(), &peer.Peer{AuthInfo: authInfo})
}

func validArtifactRequest() *agentv1.FetchArtifactRequest {
	return &agentv1.FetchArtifactRequest{
		Request:      &commonv1.RequestMetadata{RequestId: uuid.NewString(), SentTime: timestamppb.Now()},
		EventId:      uuid.NewString(),
		DeploymentId: uuid.NewString(),
		Attempt:      1,
		ArtifactId:   uuid.NewString(),
	}
}
