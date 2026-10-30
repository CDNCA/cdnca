package edgeconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

// port_end / follow_port (tcp/udp v9) are optional: unset keeps the signed
// artifact byte-identical; set, they follow port on the wire.
func TestL4PortRangeIsOptionalAndOrdered(t *testing.T) {
	unset, err := buildStreams(multiListenerBundleSpec())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(unset.Files[L4RuntimeV2ArtifactPath], []byte("port_end")) ||
		bytes.Contains(unset.Files[L4RuntimeV2ArtifactPath], []byte("follow_port")) {
		t.Fatal("unset port range changed the signed L4 artifact")
	}
	spec := multiListenerBundleSpec()
	stream := &spec.L4StreamsV2[0]
	stream.Listener.Port, stream.Listener.PortEnd = 20000, 20999
	stream.AdditionalListeners[0].Port, stream.AdditionalListeners[0].PortEnd = 30000, 30010
	stream.Endpoint.Port, stream.Endpoint.FollowPort = 20000, true
	bundle, err := buildStreams(spec)
	if err != nil {
		t.Fatal(err)
	}
	content := bundle.Files[L4RuntimeV2ArtifactPath]
	for _, want := range []string{
		`"listener":{"protocol":"tcp","address":"*","port":20000,"port_end":20999}`,
		`"port":30000,"port_end":30010}`,
		`"endpoint":{"address":"192.0.2.1","port":20000,"follow_port":true}`,
	} {
		if !bytes.Contains(content, []byte(want)) {
			t.Fatalf("missing %s in %s", want, content)
		}
	}
	var set l4StreamSetV2
	if err := json.Unmarshal(content, &set); err != nil || set.Streams[0].Listener.PortEnd != 20999 {
		t.Fatalf("port_end not carried: %+v %v", set.Streams, err)
	}
}

func TestL4PortRangeRejectsInvalidRanges(t *testing.T) {
	for name, change := range map[string]func(*L4StreamRuntimeV2){
		"end equals start": func(s *L4StreamRuntimeV2) { s.Listener.PortEnd = s.Listener.Port },
		"end below start":  func(s *L4StreamRuntimeV2) { s.Listener.Port, s.Listener.PortEnd = 20000, 19999 },
		"over 1000 ports":  func(s *L4StreamRuntimeV2) { s.Listener.Port, s.Listener.PortEnd = 20000, 21000 },
		"end over 65535":   func(s *L4StreamRuntimeV2) { s.Listener.Port, s.Listener.PortEnd = 65000, 65536 },
		"negative end":     func(s *L4StreamRuntimeV2) { s.Listener.PortEnd = -1 },
		"extra over 1000": func(s *L4StreamRuntimeV2) {
			s.AdditionalListeners[1].Port, s.AdditionalListeners[1].PortEnd = 1000, 2000
		},
		"covers health port": func(s *L4StreamRuntimeV2) { s.Listener.Port, s.Listener.PortEnd = 18000, 18100 },
		"covers 443":         func(s *L4StreamRuntimeV2) { s.Listener.Port, s.Listener.PortEnd = 400, 500 },
		"covers 80":          func(s *L4StreamRuntimeV2) { s.AdditionalListeners[1].Port, s.AdditionalListeners[1].PortEnd = 1, 100 },
		"covers 18443": func(s *L4StreamRuntimeV2) {
			s.AdditionalListeners = nil
			s.Listener.Port, s.Listener.PortEnd = 18440, 18450
		},
		"overlaps own extra": func(s *L4StreamRuntimeV2) { s.Listener.Port, s.Listener.PortEnd = 18444, 18500 },
		"follow port mismatch": func(s *L4StreamRuntimeV2) {
			s.Endpoint.FollowPort = true
		},
		"passthrough range": func(s *L4StreamRuntimeV2) {
			s.AdditionalListeners = nil
			s.TLSPassthrough, s.ServerNames = true, []string{"a.example.com"}
			s.Listener.Port, s.Listener.PortEnd = 20000, 20010
		},
	} {
		spec := multiListenerBundleSpec()
		change(&spec.L4StreamsV2[0])
		if _, err := buildStreams(spec); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("%s accepted: %v", name, err)
		}
	}
	spec := multiListenerBundleSpec()
	spec.L4StreamsV2[0].Listener.Port, spec.L4StreamsV2[0].Listener.PortEnd = 20000, 20999
	if _, err := buildStreams(spec); err != nil {
		t.Fatalf("1000-port range refused: %v", err)
	}
}

// A range claims every port in it: it conflicts with a single-port claim
// inside it whatever the kinds (a range is never split by SNI), and only on
// its own protocol.
func TestFindPortConflictsComparesRanges(t *testing.T) {
	ranged := PortClaim{Owner: "a", ID: "ranged", Kind: PortClaimPlainL4, Protocol: StreamProtocolTCP, Port: 20000, PortEnd: 20100}
	for name, other := range map[string]PortClaim{
		"plain inside":   {Owner: "b", ID: "x", Kind: PortClaimPlainL4, Protocol: StreamProtocolTCP, Port: 20050},
		"tls site":       {Owner: "b", ID: "x", Kind: PortClaimTLSSite, Protocol: StreamProtocolTCP, Port: 20100, Names: []string{"a.com"}},
		"tls stream":     {Owner: "b", ID: "x", Kind: PortClaimTLSL4, Protocol: StreamProtocolTCP, Port: 20000, Names: []string{"a.com"}},
		"range overlap":  {Owner: "b", ID: "x", Kind: PortClaimPlainL4, Protocol: StreamProtocolTCP, Port: 19990, PortEnd: 20000},
		"reserved udp":   {Owner: "b", ID: "x", Kind: PortClaimReserved, Protocol: StreamProtocolUDP, Port: 20001},
		"earlier range":  {Owner: "b", ID: "x", Kind: PortClaimPlainL4, Protocol: StreamProtocolTCP, Port: 100, PortEnd: 20010},
		"plain http in":  {Owner: "b", ID: "x", Kind: PortClaimPlainHTTP, Protocol: StreamProtocolTCP, Port: 20020},
		"covering range": {Owner: "b", ID: "x", Kind: PortClaimPlainL4, Protocol: StreamProtocolTCP, Port: 19000, PortEnd: 21000},
	} {
		conflicts := FindPortConflicts([]PortClaim{other, ranged})
		if len(conflicts) != 1 {
			t.Fatalf("%s: %d conflicts", name, len(conflicts))
		}
		start, end := conflicts[0].Overlap()
		if start < 20000 || end > 20100 || start > end {
			t.Fatalf("%s: overlap %d-%d", name, start, end)
		}
	}
	for name, other := range map[string]PortClaim{
		"below":          {Owner: "b", ID: "x", Kind: PortClaimPlainL4, Protocol: StreamProtocolTCP, Port: 19999},
		"above":          {Owner: "b", ID: "x", Kind: PortClaimPlainL4, Protocol: StreamProtocolTCP, Port: 20101, PortEnd: 20200},
		"other protocol": {Owner: "b", ID: "x", Kind: PortClaimPlainL4, Protocol: StreamProtocolUDP, Port: 20050},
		"same stream":    {Owner: "a", ID: "ranged", Kind: PortClaimPlainL4, Protocol: StreamProtocolTCP, Port: 20050},
	} {
		if conflicts := FindPortConflicts([]PortClaim{other, ranged}); len(conflicts) != 0 {
			t.Fatalf("%s: %+v", name, conflicts)
		}
	}
	conflicts := FindPortConflicts([]PortClaim{ranged, {Owner: "b", ID: "x", Kind: PortClaimPlainL4, Protocol: StreamProtocolTCP, Port: 20050, PortEnd: 20300}})
	if start, end := conflicts[0].Overlap(); start != 20050 || end != 20100 {
		t.Fatalf("overlap %d-%d, want 20050-20100", start, end)
	}
}

// Two streams' ranges on one node: refused when they overlap, also on a
// shared-port node where single plain ports are checked by FindPortConflicts.
func TestL4PortRangesConflictAcrossStreams(t *testing.T) {
	for _, shared := range []bool{false, true} {
		spec := multiListenerBundleSpec()
		spec.SharedL4Ports = shared
		first := spec.L4StreamsV2[0]
		first.AdditionalListeners = nil
		first.Listener.Port, first.Listener.PortEnd = 20000, 20100
		second := first
		second.StreamID = "66666666-6666-4666-8666-666666666666"
		second.Geo.StreamID = second.StreamID
		second.Listener.Port, second.Listener.PortEnd = 20100, 0
		spec.L4StreamsV2 = []L4StreamRuntimeV2{first, second}
		if _, err := buildStreams(spec); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("shared=%t: overlapping ranges accepted: %v", shared, err)
		}
		spec.L4StreamsV2[1].Listener.Port = 20101
		if _, err := buildStreams(spec); err != nil {
			t.Fatalf("shared=%t: adjacent ranges refused: %v", shared, err)
		}
		spec.L4StreamsV2[1].Listener.Protocol = "udp"
		spec.L4StreamsV2[1].Listener.Port = 20050
		if _, err := buildStreams(spec); err != nil {
			t.Fatalf("shared=%t: other protocol refused: %v", shared, err)
		}
	}
}
