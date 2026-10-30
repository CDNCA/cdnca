package gateway

import (
	"context"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The disabled flag of GetGatewaySettings drives GatewayDrain; re-enabling
// clears it (ADR 0013 §5.2).
func TestSettingsSyncFollowsDisabledFlag(t *testing.T) {
	shipped, _ := ParseTrustedProxyRanges(DefaultTrustedProxies)
	now := time.Date(2026, 10, 22, 8, 0, 0, 0, time.UTC)
	drain := &GatewayDrain{}
	client := &fakeSettingsClient{response: &controlv1.GetGatewaySettingsResponse{Disabled: true}}
	sync := SettingsSync{Client: client, InstanceID: "gw-1", Proxies: NewTrustedProxies(shipped), Endpoints: &NodeEndpoints{},
		Drain: drain, Now: func() time.Time { return now }}
	signal := drain.disabledSignal()
	if err := sync.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if disabled, evictAt := drain.Disabled(); !disabled || !evictAt.Equal(now.Add(DisabledEvictAfter)) {
		t.Fatalf("disabled = %v %v", disabled, evictAt)
	}
	select {
	case <-signal:
	default:
		t.Fatal("disable signal not raised")
	}
	// A later poll keeps the first disable time.
	now = now.Add(time.Minute)
	_ = sync.Poll(context.Background())
	if _, evictAt := drain.Disabled(); !evictAt.Equal(now.Add(-time.Minute).Add(DisabledEvictAfter)) {
		t.Fatalf("eviction time moved: %v", evictAt)
	}
	client.response = &controlv1.GetGatewaySettingsResponse{}
	_ = sync.Poll(context.Background())
	if disabled, _ := drain.Disabled(); disabled {
		t.Fatal("re-enabled gateway still disabled")
	}
	select {
	case <-drain.disabledSignal():
		t.Fatal("re-enabled gateway signals disabled")
	default:
	}
	// enrollment_address only on grpc entries.
	client.response = &controlv1.GetGatewaySettingsResponse{Endpoints: []*agentv1.GatewayEndpointV1{{Address: "cdn.example.com:443",
		ServerName: "gw.example.com", Transport: "ws", EnrollmentAddress: "cdn.example.com:443"}}}
	if err := sync.Poll(context.Background()); err == nil {
		t.Fatal("ws entry with an enrollment address accepted")
	}
}

func migrationHello() *agentv1.ConnectRequest {
	hello := validHello(testNodeID, versionRange(1, 0), 1)
	hello.GetHello().Capabilities.Features = append(hello.GetHello().Capabilities.Features,
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_GATEWAY_ENDPOINT_MIGRATION, ApiVersion: 1})
	return hello
}

func connectStream(t *testing.T, connection *grpc.ClientConn, hello *agentv1.ConnectRequest) (agentv1.AgentGatewayService_ConnectClient, *agentv1.GatewayHello) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	stream, err := agentv1.NewAgentGatewayServiceClient(connection).Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(hello); err != nil {
		t.Fatal(err)
	}
	response, err := stream.Recv()
	if err != nil {
		t.Fatalf("Connect hello: %v", err)
	}
	return stream, response.GetHello()
}

// Disabled: a connected node that negotiated GATEWAY_ENDPOINT_MIGRATION gets
// the current list (without this Gateway) once; the session is closed at the
// eviction time; new sessions and enrollments are refused.
func TestDisabledGatewayMigratesThenEvictsSessions(t *testing.T) {
	endpoints := &NodeEndpoints{}
	endpoints.set([]*agentv1.GatewayEndpointV1{{Address: "gw-b.example.com:21444", ServerName: "gw-b.example.com", Transport: "grpc",
		EnrollmentAddress: "gw-b.example.com:21443"}}, "v2")
	drain := &GatewayDrain{}
	g := startSharedTestServersWith(t, func(gateway *Gateway) {
		if err := gateway.ConfigureNodeEndpoints(endpoints); err != nil {
			t.Fatal(err)
		}
		if err := gateway.ConfigureDrain(drain); err != nil {
			t.Fatal(err)
		}
	})
	connection := dialGateway(t, g.agent, g.pki.rootPool, g.node.certificate)
	defer connection.Close()
	stream, hello := connectStream(t, connection, migrationHello())
	enabled := false
	for _, capability := range hello.GetEnabledCapabilities() {
		enabled = enabled || capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_GATEWAY_ENDPOINT_MIGRATION
	}
	if !enabled {
		t.Fatalf("migration capability not enabled: %v", hello.GetEnabledCapabilities())
	}
	// Eviction already due: the migration goes out, then the session ends.
	drain.set(true, time.Now().Add(-DisabledEvictAfter))
	response, err := stream.Recv()
	if err != nil {
		t.Fatalf("migration: %v", err)
	}
	migration := response.GetGatewayEndpointMigration()
	if migration == nil || migration.GetEndpointsVersion() != "v2" || len(migration.GetEndpoints()) != 1 ||
		migration.GetEndpoints()[0].GetEnrollmentAddress() != "gw-b.example.com:21443" {
		t.Fatalf("migration = %v", response)
	}
	for {
		if _, err = stream.Recv(); err != nil {
			break
		}
	}
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("evicted session ended with %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	refused, err := agentv1.NewAgentGatewayServiceClient(connection).Connect(ctx)
	if err == nil {
		_ = refused.Send(migrationHello())
		_, err = refused.Recv()
	}
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("new session on a disabled gateway: %v", err)
	}
}

// A node without the capability gets no migration message; it is closed at
// the eviction time like the others.
func TestDisabledGatewayDoesNotSendMigrationToOlderNodes(t *testing.T) {
	endpoints := &NodeEndpoints{}
	endpoints.set([]*agentv1.GatewayEndpointV1{{Address: "gw-b.example.com:21444", ServerName: "gw-b.example.com", Transport: "grpc"}}, "v2")
	drain := &GatewayDrain{}
	g := startSharedTestServersWith(t, func(gateway *Gateway) {
		_ = gateway.ConfigureNodeEndpoints(endpoints)
		_ = gateway.ConfigureDrain(drain)
	})
	connection := dialGateway(t, g.agent, g.pki.rootPool, g.node.certificate)
	defer connection.Close()
	stream, _ := connectStream(t, connection, validHello(testNodeID, versionRange(1, 0), 1))
	drain.set(true, time.Now().Add(-DisabledEvictAfter))
	for {
		response, err := stream.Recv()
		if err != nil {
			if status.Code(err) != codes.Unavailable {
				t.Fatalf("session ended with %v", err)
			}
			return
		}
		if response.GetGatewayEndpointMigration() != nil {
			t.Fatal("migration sent to a node that did not negotiate it")
		}
	}
}
