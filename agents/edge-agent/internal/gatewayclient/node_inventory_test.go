package gatewayclient

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type inventoryTestGateway struct {
	agentv1.UnimplementedAgentGatewayServiceServer
	heartbeats chan struct{}
	reports    atomic.Int32
	block      bool
}

func (g *inventoryTestGateway) ReportNodeNetworkInventoryV1(ctx context.Context, _ *agentv1.ReportNodeNetworkInventoryV1Request) (*agentv1.ReportNodeNetworkInventoryV1Response, error) {
	g.reports.Add(1)
	if g.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return nil, status.Error(codes.Unimplemented, "old Gateway")
}

func (g *inventoryTestGateway) Connect(stream grpc.BidiStreamingServer[agentv1.ConnectRequest, agentv1.ConnectResponse]) error {
	request, err := stream.Recv()
	if err != nil {
		return err
	}
	if request.GetHello() == nil {
		return status.Error(codes.InvalidArgument, "missing hello")
	}
	if err := stream.Send(&agentv1.ConnectResponse{Stream: responseMetadata(1), Payload: &agentv1.ConnectResponse_Hello{Hello: &agentv1.GatewayHello{SelectedProtocolVersion: &commonv1.ProtocolVersion{Major: 1}, GatewayVersion: "test", SessionId: uuid.NewString(), SessionEpoch: 1, ServerTime: timestamppb.Now(), HeartbeatIntervalDuration: durationpb.New(20 * time.Millisecond), OfflineAfterDuration: durationpb.New(time.Second), MaximumArtifactChunkBytes: 1024, MessageIdReplayWindow: 128}}}); err != nil {
		return err
	}
	sequence := uint64(1)
	for {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		if heartbeat := request.GetHeartbeat(); heartbeat != nil {
			sequence++
			if err := stream.Send(&agentv1.ConnectResponse{Stream: responseMetadata(sequence), Payload: &agentv1.ConnectResponse_HeartbeatAck{HeartbeatAck: &agentv1.HeartbeatAck{HeartbeatEventId: heartbeat.Event.EventId, SessionEpoch: 1, ReceivedTime: timestamppb.Now()}}}); err != nil {
				return err
			}
			select {
			case g.heartbeats <- struct{}{}:
			default:
			}
		}
	}
}

type inventoryRPCClient struct {
	agentv1.AgentGatewayServiceClient
	report func(context.Context, *agentv1.ReportNodeNetworkInventoryV1Request) (*agentv1.ReportNodeNetworkInventoryV1Response, error)
}

func (c inventoryRPCClient) ReportNodeNetworkInventoryV1(ctx context.Context, request *agentv1.ReportNodeNetworkInventoryV1Request, _ ...grpc.CallOption) (*agentv1.ReportNodeNetworkInventoryV1Response, error) {
	return c.report(ctx, request)
}

func TestNodeInventoryClientCompatibility(t *testing.T) {
	discover := func(context.Context) *agentv1.ReportNodeNetworkInventoryV1Request {
		return &agentv1.ReportNodeNetworkInventoryV1Request{SchemaVersion: 1, Ipv4Reason: "no_global_address", Ipv6Reason: "no_default_route"}
	}
	for _, legacy := range []bool{false, true} {
		name := "report-timeout"
		if legacy {
			name = "old-Gateway-method-absent"
		}
		t.Run(name, func(t *testing.T) {
			server := grpc.NewServer()
			listener := bufconn.Listen(1 << 20)
			gateway := &inventoryTestGateway{heartbeats: make(chan struct{}, 16), block: !legacy}
			description := agentv1.AgentGatewayService_ServiceDesc
			if legacy {
				description.Methods = nil
			}
			server.RegisterService(&description, gateway)
			go func() { _ = server.Serve(listener) }()
			t.Cleanup(func() { server.Stop(); _ = listener.Close() })
			public, _, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			trust, err := NewTrustStore(map[string]crypto.PublicKey{"test": public})
			if err != nil {
				t.Fatal(err)
			}
			config := testClientConfig(filepath.Join(secureTempDir(t), "journal"))
			client, err := New(config, &bufDialer{listener: listener}, noOpManager{}, trust, WithNodeInventoryDiscovery(discover))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- client.Run(ctx) }()
			for range 3 {
				select {
				case <-gateway.heartbeats:
				case err := <-done:
					t.Fatalf("inventory stopped session: %v", err)
				case <-time.After(2 * time.Second):
					t.Fatal("inventory blocked heartbeat")
				}
			}
			if legacy && gateway.reports.Load() != 0 {
				t.Fatal("old absent method was called")
			}
			if !legacy && gateway.reports.Load() != 1 {
				t.Fatal("new report never started")
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("stop=%v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("report leaked session on cancellation")
			}
		})
	}
	for _, test := range []struct {
		name  string
		code  codes.Code
		calls int
	}{
		{name: "unimplemented", code: codes.Unimplemented, calls: 1},
		{name: "permission-denied", code: codes.PermissionDenied, calls: 1},
		{name: "unavailable-bounded", code: codes.Unavailable, calls: 3},
		{name: "deadline-bounded", code: codes.DeadlineExceeded, calls: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := &Client{config: Config{NodeID: uuid.NewString()}, nodeInventory: discover, now: time.Now}
			var first *agentv1.ReportNodeNetworkInventoryV1Request
			calls := 0
			gateway := inventoryRPCClient{report: func(ctx context.Context, request *agentv1.ReportNodeNetworkInventoryV1Request) (*agentv1.ReportNodeNetworkInventoryV1Response, error) {
				calls++
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > 5*time.Second {
					t.Fatal("unbounded RPC")
				}
				if first == nil {
					first = proto.Clone(request).(*agentv1.ReportNodeNetworkInventoryV1Request)
				} else if !proto.Equal(first, request) {
					t.Fatal("retry changed idempotency body")
				}
				return nil, status.Error(test.code, "test failure")
			}}
			client.runNodeInventory(context.Background(), gateway, "")
			if calls != test.calls || first.Request.RequestId == "" || first.Request.SentTime.CheckValid() != nil {
				t.Fatalf("calls=%d want=%d", calls, test.calls)
			}
		})
	}
	for _, value := range []string{"not_reported", "arbitrary", "", "verified\nsecret"} {
		if inventoryReceiptState(value) {
			t.Fatalf("untrusted receipt state accepted: %q", value)
		}
	}
	client := &Client{}
	if err := WithNodeInventoryDiscovery(nil)(client); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("nil discovery accepted: %v", err)
	}
}

func TestUseObservedPeerOnlyFillsNATFamilies(t *testing.T) {
	nat := &agentv1.ReportNodeNetworkInventoryV1Request{Ipv4Reason: "no_global_address", Ipv6Reason: "no_default_route"}
	useObservedPeer(nat, "203.0.113.20")
	if nat.Ipv4.GetAddress() != "203.0.113.20" || nat.Ipv4Reason != "" || nat.Ipv6 != nil || nat.Ipv6Reason != "no_default_route" {
		t.Fatalf("NAT request = %v", nat)
	}
	public := &agentv1.ReportNodeNetworkInventoryV1Request{Ipv4: &agentv1.NodeNetworkCandidateV1{Address: "198.51.100.1", InterfaceName: "eth0"}}
	useObservedPeer(public, "203.0.113.20")
	if public.Ipv4.GetAddress() != "198.51.100.1" {
		t.Fatal("a detected public address was replaced")
	}
	for _, observed := range []string{"", "10.0.0.5", "127.0.0.1", "not-an-ip"} {
		request := &agentv1.ReportNodeNetworkInventoryV1Request{Ipv4Reason: "no_global_address"}
		useObservedPeer(request, observed)
		if request.Ipv4 != nil {
			t.Fatalf("observed %q became a candidate", observed)
		}
	}
}
