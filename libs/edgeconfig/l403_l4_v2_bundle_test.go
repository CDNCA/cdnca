package edgeconfig

import (
	"encoding/json"
	"testing"
)

func TestL403StreamFragmentCarriesScopedL4V2(t *testing.T) {
	stream := L4StreamRuntimeV2{
		SchemaVersion: l4RuntimeV2Schema,
		TenantID:      "11111111-1111-4111-8111-111111111111",
		StreamID:      "33333333-3333-4333-8333-333333333333", Revision: 7,
		Listener: L4ListenerV2{Protocol: "tcp", Address: "*", Port: 18443},
		Endpoint: L4EndpointV2{Host: "xn--bcher-kva.example", Port: 9443},
		DNS: L4DNSPolicyV2{PositiveMinTTLSeconds: 5, PositiveMaxTTLSeconds: 300,
			NegativeTTLSeconds: 30, StaleIfErrorSeconds: 600},
		Geo: L4GeoPolicyV2{TenantID: "11111111-1111-4111-8111-111111111111",
			StreamID: "33333333-3333-4333-8333-333333333333", Revision: 7, UnknownRegionAction: "allow", TrustedProxyCIDRs: []string{},
			BlockedRegions: []string{}, RegionCIDRs: []L4RegionCIDRsV2{}},
		ConnectTimeoutMS: 1000, ResponseTimeoutMS: 3000, MaxConnectionsPerClient: 20, DrainTimeoutMS: 30000,
	}
	bundle, err := buildStreams(Spec{ConfigVersionID: "l4-v2-7", ConfigRevision: 7, TenantID: stream.TenantID,
		StateRoot: "/var/lib/cdnca-edge", HealthPort: 18080, L4StreamsV2: []L4StreamRuntimeV2{stream}})
	if err != nil {
		t.Fatalf("buildStreams() error = %v", err)
	}
	content := bundle.Files[L4RuntimeV2ArtifactPath]
	var document l4StreamSetV2
	if err := json.Unmarshal(content, &document); err != nil || document.SchemaVersion != l4StreamSetV2Schema ||
		document.VersionID != "l4-v2-7" || document.Revision != 7 || len(document.Streams) != 1 ||
		document.Streams[0].TenantID != stream.TenantID ||
		document.Streams[0].StreamID != stream.StreamID || document.Streams[0].Endpoint.Host != stream.Endpoint.Host {
		t.Fatalf("unexpected signed L4 v2 artifact: %s", content)
	}

}

func TestL403StreamFragmentRejectsCrossScopeL4V2(t *testing.T) {
	stream := L4StreamRuntimeV2{SchemaVersion: l4RuntimeV2Schema,
		TenantID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		StreamID: "33333333-3333-4333-8333-333333333333", Revision: 1,
		Listener: L4ListenerV2{Protocol: "tcp", Address: "*", Port: 18443},
		Endpoint: L4EndpointV2{Address: "93.184.216.34", Port: 9443},
		Geo: L4GeoPolicyV2{TenantID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
			StreamID: "33333333-3333-4333-8333-333333333333", Revision: 1, UnknownRegionAction: "allow"},
		ConnectTimeoutMS: 1000, ResponseTimeoutMS: 3000, MaxConnectionsPerClient: 20, DrainTimeoutMS: 30000}
	if _, err := buildStreams(Spec{ConfigVersionID: "l4-v2-1", ConfigRevision: 1,
		TenantID: "11111111-1111-4111-8111-111111111111", StateRoot: "/var/lib/cdnca-edge", HealthPort: 18080,
		L4StreamsV2: []L4StreamRuntimeV2{stream}}); err != ErrInvalidConfig {
		t.Fatalf("buildStreams() error = %v, want %v", err, ErrInvalidConfig)
	}
}
