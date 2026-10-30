package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"net"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type inventoryTLSControl struct {
	*fakeControl
	report func(context.Context, *controlv1.ReportNodeNetworkInventoryV1Request) (*agentv1.ReportNodeNetworkInventoryV1Response, error)
}

func (c *inventoryTLSControl) ReportNodeNetworkInventoryV1(ctx context.Context, request *controlv1.ReportNodeNetworkInventoryV1Request) (*agentv1.ReportNodeNetworkInventoryV1Response, error) {
	return c.report(ctx, request)
}

func TestNodeInventoryTLSContract(t *testing.T) {
	requests := make(chan *controlv1.ReportNodeNetworkInventoryV1Request, 16)
	control := &inventoryTLSControl{fakeControl: defaultFakeControl(), report: func(_ context.Context, request *controlv1.ReportNodeNetworkInventoryV1Request) (*agentv1.ReportNodeNetworkInventoryV1Response, error) {
		requests <- proto.Clone(request).(*controlv1.ReportNodeNetworkInventoryV1Request)
		return &agentv1.ReportNodeNetworkInventoryV1Response{SchemaVersion: 1, NodeId: request.NodeId, Ipv4State: "peer_mismatch", Ipv6State: "no_default_route", ReceivedTime: timestamppb.Now()}, nil
	}}
	gatewayID := uuid.NewString()
	servers := startTestServersWithConfig(t, control, func(config *Config) { config.GatewayInstanceID = gatewayID })
	connection := dialGateway(t, servers.mtlsAddress, servers.pki.rootPool, servers.clientCertificate)
	t.Cleanup(func() { _ = connection.Close() })
	client := agentv1.NewAgentGatewayServiceClient(connection)
	request := &agentv1.ReportNodeNetworkInventoryV1Request{SchemaVersion: 1, Request: &commonv1.RequestMetadata{RequestId: uuid.NewString(), SentTime: timestamppb.Now()}, Ipv4: &agentv1.NodeNetworkCandidateV1{Address: "203.0.113.125", InterfaceName: "ens17"}, Ipv6Reason: "no_default_route"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("x-forwarded-for", "203.0.113.125", "x-node-id", uuid.NewString()))
	if _, err := client.ReportNodeNetworkInventoryV1(ctx, request); err != nil {
		t.Fatal(err)
	}
	forwarded := <-requests
	digest := sha256.Sum256(servers.clientCertificate.Certificate[0])
	if forwarded.NodeId != testNodeID || forwarded.CertificateSerialNumber != "a" || !bytes.Equal(forwarded.CertificateSha256, digest[:]) || forwarded.GatewayInstanceId != gatewayID || forwarded.GetPeerIp() != "127.0.0.1" || !proto.Equal(forwarded.Inventory, request) {
		t.Fatal("network report was not bound to real TLS identity/transport")
	}
	t.Run("IPv4-mapped-transport-normalization", func(t *testing.T) {
		// The live TLS test above proves identity/peer acquisition; this unit
		// case supplies the mapped address representation seen on dual-stack listeners.
		verified := authenticatedTestContext(t)
		remote, _ := peer.FromContext(verified)
		remote.Addr = &net.TCPAddr{IP: net.ParseIP("::ffff:203.0.113.125"), Port: 19444}
		gateway := newUnitGateway(t, control, func(config *Config) { config.GatewayInstanceID = gatewayID })
		if _, err := gateway.ReportNodeNetworkInventoryV1(verified, request); err != nil {
			t.Fatal(err)
		}
		if got := <-requests; got.GetPeerIp() != request.Ipv4.Address {
			t.Fatal("mapped IPv4 peer did not match canonical candidate")
		}
	})
	for name, mutate := range map[string]func(*agentv1.ReportNodeNetworkInventoryV1Request){
		"version":          func(r *agentv1.ReportNodeNetworkInventoryV1Request) { r.SchemaVersion = 2 },
		"missing-metadata": func(r *agentv1.ReportNodeNetworkInventoryV1Request) { r.Request = nil },
		"unknown-nested-field": func(r *agentv1.ReportNodeNetworkInventoryV1Request) {
			r.Ipv4.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := proto.Clone(request).(*agentv1.ReportNodeNetworkInventoryV1Request)
			mutate(bad)
			_, err := client.ReportNodeNetworkInventoryV1(ctx, bad)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("invalid payload code=%v", status.Code(err))
			}
			select {
			case <-requests:
				t.Fatal("invalid payload reached Control")
			default:
			}
		})
	}

	otherPKI := newTestPKI(t)
	for _, test := range []struct {
		name  string
		certs []tls.Certificate
		code  codes.Code
	}{
		{name: "missing-certificate", code: codes.Unavailable},
		{name: "wrong-CA", certs: []tls.Certificate{otherPKI.client(t, 11, nodeSPIFFEPrefix+testNodeID, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))}, code: codes.Unavailable},
		{name: "wrong-audience", certs: []tls.Certificate{servers.pki.client(t, 12, "spiffe://cdnca/control/not-node", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))}, code: codes.Unauthenticated},
		{name: "expired", certs: []tls.Certificate{servers.pki.client(t, 13, nodeSPIFFEPrefix+testNodeID, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))}, code: codes.Unavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn := dialGateway(t, servers.mtlsAddress, servers.pki.rootPool, test.certs...)
			defer conn.Close()
			callCtx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err := agentv1.NewAgentGatewayServiceClient(conn).ReportNodeNetworkInventoryV1(callCtx, request)
			if status.Code(err) != test.code {
				t.Fatalf("invalid certificate code=%v want=%v", status.Code(err), test.code)
			}
			select {
			case <-requests:
				t.Fatal("invalid certificate reached Control")
			default:
			}
		})
	}
	enrollConnection := dialGateway(t, servers.enrollmentAddress, servers.pki.rootPool)
	defer enrollConnection.Close()
	if _, err := agentv1.NewAgentGatewayServiceClient(enrollConnection).ReportNodeNetworkInventoryV1(ctx, request); status.Code(err) != codes.Unimplemented {
		t.Fatalf("enrollment exposed inventory: %v", err)
	}
	oldControl := startTestServers(t, defaultFakeControl())
	oldConnection := dialGateway(t, oldControl.mtlsAddress, oldControl.pki.rootPool, oldControl.clientCertificate)
	defer oldConnection.Close()
	if _, err := agentv1.NewAgentGatewayServiceClient(oldConnection).ReportNodeNetworkInventoryV1(ctx, request); status.Code(err) != codes.Unimplemented {
		t.Fatalf("old Control compatibility: %v", err)
	}
	for name, report := range map[string]func(context.Context, *controlv1.ReportNodeNetworkInventoryV1Request) (*agentv1.ReportNodeNetworkInventoryV1Response, error){
		"revoked-at-Control": func(context.Context, *controlv1.ReportNodeNetworkInventoryV1Request) (*agentv1.ReportNodeNetworkInventoryV1Response, error) {
			return nil, status.Error(codes.PermissionDenied, "revoked")
		},
		"invalid-receipt": func(context.Context, *controlv1.ReportNodeNetworkInventoryV1Request) (*agentv1.ReportNodeNetworkInventoryV1Response, error) {
			return &agentv1.ReportNodeNetworkInventoryV1Response{SchemaVersion: 1, NodeId: testNodeID, Ipv4State: "arbitrary", Ipv6State: "no_default_route", ReceivedTime: timestamppb.Now()}, nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			instance := startTestServers(t, &inventoryTLSControl{fakeControl: defaultFakeControl(), report: report})
			conn := dialGateway(t, instance.mtlsAddress, instance.pki.rootPool, instance.clientCertificate)
			defer conn.Close()
			_, err := agentv1.NewAgentGatewayServiceClient(conn).ReportNodeNetworkInventoryV1(ctx, request)
			want := codes.Internal
			if name == "revoked-at-Control" {
				want = codes.PermissionDenied
			}
			if status.Code(err) != want {
				t.Fatalf("receipt code=%v want=%v", status.Code(err), want)
			}
		})
	}
}
