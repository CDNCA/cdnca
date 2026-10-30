package edgeconfig

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
)

func multiListenerBundleSpec() Spec {
	stream := L4StreamRuntimeV2{SchemaVersion: l4RuntimeV2Schema,
		TenantID: "11111111-1111-4111-8111-111111111111",
		StreamID: "33333333-3333-4333-8333-333333333333", Revision: 3,
		Listener: L4ListenerV2{Protocol: "tcp", Address: "*", Port: 18443}, Endpoint: L4EndpointV2{Address: "192.0.2.1", Port: 9443},
		AdditionalListeners: []L4AdditionalListenerV2{
			{ID: "55555555-5555-4555-8555-555555555555", Protocol: "udp", Address: "*", Port: 18443},
			{ID: "44444444-4444-4444-8444-444444444444", Protocol: "tcp", Address: "*", Port: 18444},
		},
		Geo: L4GeoPolicyV2{TenantID: "11111111-1111-4111-8111-111111111111",
			StreamID: "33333333-3333-4333-8333-333333333333", Revision: 3, UnknownRegionAction: "allow"},
		ConnectTimeoutMS: 1000, ResponseTimeoutMS: 3000, MaxConnectionsPerClient: 20, DrainTimeoutMS: 30000}
	return Spec{ConfigVersionID: "multi-v2", ConfigRevision: 9, TenantID: stream.TenantID,
		StateRoot: "/var/lib/cdnca-edge", HealthPort: 18080, L4StreamsV2: []L4StreamRuntimeV2{stream}}
}

func TestAdditionalListenersBundleCanonicalAndLegacyOmission(t *testing.T) {
	spec := multiListenerBundleSpec()
	bundle, err := buildStreams(spec)
	if err != nil {
		t.Fatal(err)
	}
	var set l4StreamSetV2
	if err := json.Unmarshal(bundle.Files[L4RuntimeV2ArtifactPath], &set); err != nil || len(set.Streams) != 1 || len(set.Streams[0].AdditionalListeners) != 2 || set.Streams[0].Revision != 3 || set.Revision != 9 {
		t.Fatalf("signed resource changed identity: %+v %v", set, err)
	}
	if set.Streams[0].AdditionalListeners[0].ID != spec.L4StreamsV2[0].AdditionalListeners[1].ID {
		t.Fatal("extra sockets not canonical by ID, or mutated caller")
	}

	spec.L4StreamsV2[0].AdditionalListeners[0], spec.L4StreamsV2[0].AdditionalListeners[1] = spec.L4StreamsV2[0].AdditionalListeners[1], spec.L4StreamsV2[0].AdditionalListeners[0]
	reordered, err := buildStreams(spec)
	if err != nil || !bytes.Equal(bundle.Files[L4RuntimeV2ArtifactPath], reordered.Files[L4RuntimeV2ArtifactPath]) || bundle.ManifestSHA256 != reordered.ManifestSHA256 {
		t.Fatalf("reordering changed signed artifact: %v", err)
	}
	spec.L4StreamsV2[0].AdditionalListeners = nil
	legacy, err := buildStreams(spec)
	if err != nil {
		t.Fatal(err)
	}
	spec.L4StreamsV2[0].AdditionalListeners = []L4AdditionalListenerV2{}
	empty, err := buildStreams(spec)
	if err != nil || legacy.ManifestSHA256 != empty.ManifestSHA256 || bytes.Contains(empty.Files[L4RuntimeV2ArtifactPath], []byte("additional_listeners")) {
		t.Fatalf("empty optional extension changed old bytes: %v", err)
	}
}

func TestAdditionalListenersBundleRejectsInvalidAndOccupiedSockets(t *testing.T) {
	for name, change := range map[string]func(*Spec){
		"invalid UUID":       func(s *Spec) { s.L4StreamsV2[0].AdditionalListeners[0].ID = "invalid" },
		"stream identity":    func(s *Spec) { s.L4StreamsV2[0].AdditionalListeners[0].ID = s.L4StreamsV2[0].StreamID },
		"duplicate identity": func(s *Spec) { s.L4StreamsV2[0].AdditionalListeners[0].ID = s.L4StreamsV2[0].AdditionalListeners[1].ID },
		"protocol":           func(s *Spec) { s.L4StreamsV2[0].AdditionalListeners[0].Protocol = "http" },
		"port":               func(s *Spec) { s.L4StreamsV2[0].AdditionalListeners[0].Port = 65536 },
		"bind":               func(s *Spec) { s.L4StreamsV2[0].AdditionalListeners[0].Address = "0.0.0.0" },
		"primary overlap":    func(s *Spec) { s.L4StreamsV2[0].AdditionalListeners[1].Port = 18443 },
		"health port":        func(s *Spec) { s.L4StreamsV2[0].AdditionalListeners[1].Port = 18080 },
		"UDP PROXY":          func(s *Spec) { s.L4StreamsV2[0].ProxyProtocolOutbound = true },
		"stream limit":       func(s *Spec) { s.L4StreamsV2[0].AdditionalListeners = make([]L4AdditionalListenerV2, 64) },
		"another stream identity": func(s *Spec) {
			second := s.L4StreamsV2[0]
			second.StreamID = second.AdditionalListeners[0].ID
			second.Geo.StreamID = second.StreamID
			second.Listener.Port = 20443
			second.AdditionalListeners = nil
			s.L4StreamsV2 = append(s.L4StreamsV2, second)
		},
	} {
		t.Run(name, func(t *testing.T) {
			spec := multiListenerBundleSpec()
			change(&spec)
			if _, err := buildStreams(spec); err != ErrInvalidConfig {
				t.Fatalf("invalid signed sockets accepted: %v", err)
			}
		})
	}
	for _, count := range []int{256, 257} {
		spec := multiListenerBundleSpec()
		spec.L4StreamsV2 = nil
		for start := 0; start < count; start += 64 {
			stream := multiListenerBundleSpec().L4StreamsV2[0]
			stream.StreamID = fmt.Sprintf("aaaaaaaa-aaaa-4aaa-8aaa-%012d", start)
			stream.Geo.StreamID = stream.StreamID
			stream.Listener.Port = 30000 + start
			stream.AdditionalListeners = nil
			for i := start + 1; i < min(start+64, count); i++ {
				stream.AdditionalListeners = append(stream.AdditionalListeners, L4AdditionalListenerV2{ID: fmt.Sprintf("bbbbbbbb-bbbb-4bbb-8bbb-%012d", i), Protocol: "tcp", Address: "*", Port: 30000 + i})
			}
			spec.L4StreamsV2 = append(spec.L4StreamsV2, stream)
		}
		_, err := buildStreams(spec)
		if (err == nil) != (count == 256) {
			t.Fatalf("socket budget %d: %v", count, err)
		}
	}
}
