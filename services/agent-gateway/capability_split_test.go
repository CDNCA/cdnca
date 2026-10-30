package gateway

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// AUTO_DEFENSE (session flag [16]) and security bans (WAF v2, session flag
// [17]) are negotiated independently: declaring one never enables the other.
func TestAutoDefenseAndSecurityBansNegotiateIndependently(t *testing.T) {
	wafV2 := []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_WAF, ApiVersion: securityBanWAFVersion}}
	t.Run("waf v2 only", func(t *testing.T) {
		bans := &securityBanBusStub{deliveries: make(chan SecurityBanDelivery, 1), subscribed: make(chan string, 1)}
		defense := newAutoDefenseBusStub()
		stream := connectSplitSession(t, bans, defense, wafV2)
		waitSubscribed(t, bans.subscribed, "security bans")
		command := testAutoDefenseCommand(t, testNodeID, 1)
		sendAutoDefense(t, stream, 2, &agentv1.ConnectRequest{Payload: &agentv1.ConnectRequest_AutoDefenseReceipt{AutoDefenseReceipt: testAutoDefenseReceipt(command)}})
		if _, err := stream.Recv(); err == nil || !strings.Contains(err.Error(), "auto defense receipt is not negotiated") {
			t.Fatalf("auto defense receipt with WAF v2 only: %v", err)
		}
		select {
		case nodeID := <-defense.subscribed:
			t.Fatalf("auto defense subscribed for %s with WAF v2 only", nodeID)
		default:
		}
	})
	t.Run("auto defense only", func(t *testing.T) {
		bans := &securityBanBusStub{deliveries: make(chan SecurityBanDelivery, 1), subscribed: make(chan string, 1)}
		defense := newAutoDefenseBusStub()
		stream := connectSplitSession(t, bans, defense, autoDefenseFeatures())
		waitSubscribed(t, defense.subscribed, "auto defense")
		command := testSecurityBanCommand(t, testNodeID, 1)
		sendAutoDefense(t, stream, 2, &agentv1.ConnectRequest{Payload: &agentv1.ConnectRequest_SecurityBanStatus{SecurityBanStatus: testSecurityBanStatus(command)}})
		if _, err := stream.Recv(); err == nil || !strings.Contains(err.Error(), "security ban status is not negotiated") {
			t.Fatalf("security ban status with AUTO_DEFENSE only: %v", err)
		}
		select {
		case nodeID := <-bans.subscribed:
			t.Fatalf("security bans subscribed for %s with AUTO_DEFENSE only", nodeID)
		default:
		}
	})
}

func waitSubscribed(t *testing.T, subscribed <-chan string, what string) {
	t.Helper()
	select {
	case <-subscribed:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s not subscribed", what)
	}
}

func connectSplitSession(t *testing.T, bans SecurityBanBus, defense AutoDefenseBus, features []*agentv1.Capability) agentv1.AgentGatewayService_ConnectClient {
	t.Helper()
	pki := newTestPKI(t)
	now := time.Now()
	clientCertificate := pki.client(t, 10, nodeSPIFFEPrefix+testNodeID, now.Add(-time.Hour), now.Add(time.Hour))
	config := DefaultConfig()
	config.GatewayInstanceID, config.GatewayVersion = "gateway-test", "test"
	service, err := New(config, defaultFakeControl(), NewMemorySessionCoordinator())
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ConfigureSecurityBans(bans); err != nil {
		t.Fatal(err)
	}
	if err := service.ConfigureAutoDefense(defense); err != nil {
		t.Fatal(err)
	}
	servers, err := NewServers(service, &tls.Config{Certificates: []tls.Certificate{pki.server}},
		&tls.Config{Certificates: []tls.Certificate{pki.server}, ClientCAs: pki.rootPool})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = servers.MTLS.Serve(listener) }()
	t.Cleanup(servers.MTLS.Stop)
	connection := dialGateway(t, listener.Addr().String(), pki.rootPool, clientCertificate)
	t.Cleanup(func() { _ = connection.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	stream, err := agentv1.NewAgentGatewayServiceClient(connection).Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hello := validHello(testNodeID, versionRange(1, 0), 1)
	hello.GetHello().Capabilities.Features = features
	if err := stream.Send(hello); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatal(err)
	}
	return stream
}
