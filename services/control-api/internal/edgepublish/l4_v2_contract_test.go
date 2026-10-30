package edgepublish

import (
	"encoding/json"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

func l4V2ContractStream(protocol string) edgeconfig.L4StreamRuntimeV2 {
	stream := edgeconfig.L4StreamRuntimeV2{
		SchemaVersion: "cdnca.edge.l4/v2", TenantID: "11111111-1111-4111-8111-111111111111", StreamID: "33333333-3333-4333-8333-333333333333", Revision: 3,
		Listener:         edgeconfig.L4ListenerV2{Protocol: protocol, Address: "*", Port: 18443},
		Endpoint:         edgeconfig.L4EndpointV2{Address: "8.8.8.8", Port: 443},
		ConnectTimeoutMS: 1000, ResponseTimeoutMS: 30000, MaxConnectionsPerClient: 100, DrainTimeoutMS: 30000,
		ProxyProtocolOutbound: protocol == "tcp",
	}
	stream.Geo = edgeconfig.L4GeoPolicyV2{TenantID: stream.TenantID,
		StreamID: stream.StreamID, Revision: stream.Revision, UnknownRegionAction: "allow"}
	return stream
}

func TestL4V2ContractRequiredCapabilitiesIncludeRuntimeV2(t *testing.T) {
	for _, test := range []struct {
		name, protocol    string
		inbound, outbound bool
	}{
		{name: "tcp", protocol: "tcp"},
		{name: "tcp inbound proxy", protocol: "tcp", inbound: true},
		{name: "tcp outbound proxy", protocol: "tcp", outbound: true},
		{name: "tcp bidirectional proxy", protocol: "tcp", inbound: true, outbound: true},
		{name: "udp", protocol: "udp"},
	} {
		t.Run(test.name, func(t *testing.T) {
			stream := l4V2ContractStream(test.protocol)
			stream.ProxyProtocolInbound, stream.ProxyProtocolOutbound = test.inbound, test.outbound
			if test.inbound {
				stream.Geo.Enabled = true
				stream.Geo.TrustedProxyCIDRs = []string{"203.0.113.0/24"}
			}
			if err := siteRuntimeV2StreamsFragmentError(stream.TenantID, 18080, stream); err != nil {
				t.Fatalf("valid runtime fixture failed compilation: %v", err)
			}
			capabilities := make(map[agentv1.CapabilityName]uint32)
			for _, capability := range siteRuntimeV2StreamsRequired([]edgeconfig.L4StreamRuntimeV2{stream}) {
				if capabilities[capability.Name] != 0 {
					t.Fatalf("invalid or duplicate capability: %+v", capability)
				}
				capabilities[capability.Name] = capability.ApiVersion
			}
			want := map[agentv1.CapabilityName]uint32{}
			if test.protocol == "tcp" {
				// Every v2 stream requires v12 (no website, migration 506).
				want[agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY] = 12
			} else {
				want[agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY] = 12
			}
			if test.inbound || test.outbound {
				want[agentv1.CapabilityName_CAPABILITY_NAME_PROXY_PROTOCOL] = 1
			}
			if len(capabilities) != len(want) {
				t.Errorf("capabilities=%v want=%v", capabilities, want)
			}
			for name, version := range want {
				if capabilities[name] != version {
					t.Errorf("compiled %s v2 runtime lacks required capability %s; actual=%v", test.protocol, name, capabilities)
				}
			}
		})
	}
}

func TestL4V2ContractBuildPreservesIndependentRevisions(t *testing.T) {
	stream := l4V2ContractStream("tcp")
	_, files, err := edgeconfig.RenderSharedStreamFragment("l4-contract-9", 9,
		edgeconfig.StreamRuntime{TenantID: stream.TenantID, StreamsV2: []edgeconfig.L4StreamRuntimeV2{stream}}, 18080, nil)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Revision int64                          `json:"revision"`
		Streams  []edgeconfig.L4StreamRuntimeV2 `json:"streams"`
	}
	if err := json.Unmarshal(files[edgeconfig.L4RuntimeV2ArtifactPath], &wire); err != nil {
		t.Fatal(err)
	}
	if wire.Revision != 9 || len(wire.Streams) != 1 || wire.Streams[0].Revision != 3 || wire.Streams[0].Geo.Revision != 3 {
		t.Fatalf("independent source/resource revisions changed: %+v", wire)
	}
	t.Logf("compiled wire revisions: source=%d stream=%d geo=%d", wire.Revision, wire.Streams[0].Revision, wire.Streams[0].Geo.Revision)
}
