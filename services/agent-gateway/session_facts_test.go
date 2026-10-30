package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"slices"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type sessionFactsControl struct {
	*fakeControl
	mu      sync.Mutex
	mode    string
	facts   []*controlv1.GatewaySessionFactsV1
	onFacts func()
}

type sessionFactsFailingHello struct{ *fakeBidiStream }

func (s *sessionFactsFailingHello) Send(*agentv1.ConnectResponse) error {
	return errors.New("fixture GatewayHello send failed")
}

func (c *sessionFactsControl) GetNodeAuthorization(ctx context.Context, request *controlv1.GetNodeAuthorizationRequest) (*controlv1.GetNodeAuthorizationResponse, error) {
	result, err := c.fakeControl.GetNodeAuthorization(ctx, request)
	if result != nil {
		result.DeploymentsAllowed = c.mode != "draining"
	}
	if err != nil || request.SessionFacts == nil {
		return result, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.facts = append(c.facts, proto.Clone(request.SessionFacts).(*controlv1.GatewaySessionFactsV1))
	if c.onFacts != nil {
		c.onFacts()
	}
	switch c.mode {
	case "old-control-reject":
		return nil, status.Error(codes.InvalidArgument, "unknown field")
	case "database-outage":
		return nil, status.Error(codes.Unavailable, "authority unavailable")
	case "legacy-no-receipt":
		return result, nil
	case "wrong-key":
		result.ArtifactEncryptionKeyId = "changed-key"
	case "wrong-protocol":
		result.AcceptedProtocolVersions = versionRange(2, 0)
	}
	encoded, _ := (proto.MarshalOptions{Deterministic: true}).Marshal(request.SessionFacts)
	hash := sha256.Sum256(encoded)
	result.SessionFactsSha256 = hash[:]
	if c.mode == "wrong-receipt" {
		result.SessionFactsSha256[0] ^= 1
	}
	return result, nil
}

func TestGatewaySessionFactsTLS(t *testing.T) {
	for _, item := range []struct {
		name string
		want codes.Code
	}{
		{"valid", codes.OK}, {"legacy-no-receipt", codes.OK}, {"draining", codes.OK}, {"old-control-reject", codes.InvalidArgument},
		{"database-outage", codes.Unavailable}, {"wrong-receipt", codes.FailedPrecondition},
		{"wrong-key", codes.FailedPrecondition}, {"wrong-protocol", codes.FailedPrecondition},
	} {
		t.Run(item.name, func(t *testing.T) {
			control := &sessionFactsControl{fakeControl: defaultFakeControl(), mode: item.name}
			servers := startTestServers(t, control)
			connection := dialGateway(t, servers.mtlsAddress, servers.pki.rootPool, servers.clientCertificate)
			defer connection.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			stream, err := agentv1.NewAgentGatewayServiceClient(connection).Connect(ctx)
			if err != nil {
				t.Fatal(err)
			}
			hello := validHello(testNodeID, versionRange(1, 0), 1)
			hello.GetHello().Capabilities = &agentv1.AgentCapabilities{AgentVersion: "1.0.22", BuildId: "build", OperatingSystem: "linux", Architecture: "amd64", Features: []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE, ApiVersion: 1}, {Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1, ApiVersion: 1}}}
			original := proto.Clone(hello)
			if err := stream.Send(hello); err != nil {
				t.Fatal(err)
			}
			response, err := stream.Recv()
			if status.Code(err) != item.want {
				t.Fatalf("handshake error=%v, want=%v", err, item.want)
			}
			if item.want == codes.OK && response.GetHello() == nil {
				t.Fatal("missing GatewayHello")
			}
			control.mu.Lock()
			defer control.mu.Unlock()
			// Paused deployments still report facts (capability-gated pushes read
			// them); upgrade authority stays off (TestGatewaySessionFactsTLS checks hello).
			if len(control.facts) != 1 {
				t.Fatalf("authenticated session facts calls=%d want1", len(control.facts))
			}
			facts := control.facts[0]
			certSHA := sha256.Sum256(servers.clientCertificate.Certificate[0])
			if facts.NodeId != testNodeID || facts.SessionEpoch != 1 || !bytes.Equal(facts.CertificateSha256, certSHA[:]) || facts.SelectedProtocolVersion.Major != 1 || facts.ArtifactEncryptionKeyId != "artifact-key" {
				t.Fatal("facts not bound to actual certificate/session")
			}
			if facts.Capabilities.Features[0].Name != agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1 || !proto.Equal(hello, original) {
				t.Fatal("facts were not immutable canonical clone")
			}
		})
	}
	for _, mode := range []string{"old-control-reject", "database-outage", "wrong-receipt", "committed-before-hello-fails"} {
		t.Run("lease-release/"+mode, func(t *testing.T) {
			control := &sessionFactsControl{fakeControl: defaultFakeControl(), mode: mode}
			coordinator := NewMemorySessionCoordinator()
			config := DefaultConfig()
			config.GatewayInstanceID = "session-test"
			config.GatewayVersion = "test"
			gateway, err := New(config, control, coordinator)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(authenticatedTestContext(t))
			defer cancel()
			hello := validHello(testNodeID, versionRange(1, 0), 1)
			hello.GetHello().Capabilities = &agentv1.AgentCapabilities{AgentVersion: "1.0.22", BuildId: "build", OperatingSystem: "linux", Architecture: "amd64", Features: []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE, ApiVersion: 1}}}
			first := true
			stream := &fakeBidiStream{ctx: ctx, receive: func() (*agentv1.ConnectRequest, error) {
				if first {
					first = false
					return hello, nil
				}
				return nil, io.EOF
			}}
			var connectErr error
			if mode == "committed-before-hello-fails" {
				connectErr = gateway.Connect(&sessionFactsFailingHello{stream})
			} else {
				connectErr = gateway.Connect(stream)
			}
			if connectErr == nil {
				t.Fatal("failed handshake returned success")
			}
			coordinator.mu.Lock()
			slot := coordinator.slots[testNodeID]
			coordinator.mu.Unlock()
			slot.mu.Lock()
			active := slot.current
			slot.mu.Unlock()
			if active != nil {
				t.Fatal("failed handshake leaked its lease")
			}
			next, err := coordinator.Acquire(t.Context(), testNodeID)
			if err != nil || next.Epoch() != 2 {
				t.Fatalf("reconnect lease: %v %v", next, err)
			}
			defer next.Release()
			identity, err := authenticatedNode(authenticatedTestContext(t))
			if err != nil {
				t.Fatal(err)
			}
			facts := newGatewaySessionFacts(identity, next.Epoch(), versionRange(1, 0).Minimum, hello.GetHello())
			control.mode = "legacy-no-receipt"
			previous, err := gateway.authorizeConnection(t.Context(), identity, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, confirmed, err := gateway.confirmSessionFacts(t.Context(), identity, next, facts, previous); err != nil || confirmed {
				t.Fatalf("legacy no receipt authorized upgrades: confirmed=%v err=%v", confirmed, err)
			}
			control.mode = "valid"
			control.onFacts = nil
			previous, err = gateway.authorizeConnection(t.Context(), identity, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, confirmed, err := gateway.confirmSessionFacts(t.Context(), identity, next, facts, previous); err != nil || !confirmed {
				t.Fatalf("reconnect facts: %v %v", confirmed, err)
			}
			newer, err := coordinator.Acquire(t.Context(), testNodeID)
			if err != nil {
				t.Fatal(err)
			}
			defer newer.Release()
			next.Release()
			if err := newer.FencedSend(func() error { return nil }); err != nil {
				t.Fatal("old release deleted newer epoch")
			}
		})
	}
}

// A newer Agent advertising a capability this Gateway build does not know
// keeps its session facts: the unknown name is left out, the rest confirmed.
func TestSessionFactsDropUnknownCapabilities(t *testing.T) {
	hello := &agentv1.AgentHello{Capabilities: &agentv1.AgentCapabilities{AgentVersion: "1.0.40", BuildId: "build", OperatingSystem: "linux",
		Architecture: "amd64", Features: []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_MARKET_PROBE, ApiVersion: 1},
			{Name: agentv1.CapabilityName(999), ApiVersion: 1}, {Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1, ApiVersion: 1}}},
		ArtifactEncryptionKeyId: "key-1"}
	facts := newGatewaySessionFacts(nodeIdentity{NodeID: testNodeID}, 1, &commonv1.ProtocolVersion{Major: 1}, hello)
	if facts == nil || len(facts.Capabilities.Features) != 2 {
		t.Fatalf("facts = %v", facts)
	}
	for _, f := range facts.Capabilities.Features {
		if f.Name == 999 {
			t.Fatal("unknown capability kept")
		}
	}
	if len(hello.Capabilities.Features) != 3 {
		t.Fatal("the hello itself was modified")
	}
	if known := knownCapabilities(); !slices.Contains(known, agentv1.CapabilityName_CAPABILITY_NAME_MARKET_BENCHMARK) ||
		slices.Contains(known, agentv1.CapabilityName_CAPABILITY_NAME_UNSPECIFIED) {
		t.Fatalf("known capabilities %v", known)
	}
}
