package l4forward

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
)

func rangeFields() Fields {
	fields := validFields()
	fields.ListenPort, fields.ListenPortEnd = 20000, 20999
	fields.UpstreamFollowPort, fields.UpstreamPort = true, 0
	return fields
}

// 端口范围 / 跟随端口回源 (migration 334): follow-port stores listen_port as
// the upstream port; unset fields leave request digests unchanged.
func TestPortRangeFieldsNormalize(t *testing.T) {
	if encoded, err := json.Marshal(Fields{}); err != nil || strings.Contains(string(encoded), "listen_port_end") ||
		strings.Contains(string(encoded), "follow_port") {
		t.Fatalf("request digest changed: %s %v", encoded, err)
	}
	fields := rangeFields()
	if err := normalizeFields(&fields); err != nil || fields.UpstreamPort != 20000 {
		t.Fatalf("range fields: %v upstream=%d", err, fields.UpstreamPort)
	}
	fields = rangeFields()
	fields.UpstreamPort = 9000 // follow-port overrides an explicit port
	if err := normalizeFields(&fields); err != nil || fields.UpstreamPort != 20000 {
		t.Fatalf("follow-port with a port: %v upstream=%d", err, fields.UpstreamPort)
	}
	for name, change := range map[string]func(*Fields){
		"end equals start": func(f *Fields) { f.ListenPortEnd = f.ListenPort },
		"end below start":  func(f *Fields) { f.ListenPortEnd = 19999 },
		"over 1000 ports":  func(f *Fields) { f.ListenPortEnd = 21000 },
		"extra over 1000": func(f *Fields) {
			f.AdditionalListeners = &[]AdditionalListener{{ID: uuid.New(), Protocol: ProtocolUDP, Address: "*", Port: 30000, PortEnd: 31000}}
		},
		"passthrough range": func(f *Fields) {
			f.UpstreamFollowPort = false
			f.UpstreamPort = 443
			f.TLSPassthrough, f.ServerNames = true, []string{"a.example.com"}
		},
	} {
		fields := rangeFields()
		change(&fields)
		if err := normalizeFields(&fields); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// A range may not cover the node's own ports nor overlap the forward's own
// sockets; the refusal says where.
func TestPortRangeConflictsAreLocated(t *testing.T) {
	for name, check := range map[string]struct {
		change func(*Fields)
		want   PortConflictError
	}{
		"covers 443": {func(f *Fields) { f.ListenPort, f.ListenPortEnd = 400, 500 },
			PortConflictError{Protocol: ProtocolTCP, Port: 443, With: PortConflictReserved}},
		"covers 18080": {func(f *Fields) { f.ListenPort, f.ListenPortEnd = 18000, 18100 },
			PortConflictError{Protocol: ProtocolTCP, Port: 18080, With: PortConflictReserved}},
		"extra inside range": {func(f *Fields) {
			f.AdditionalListeners = &[]AdditionalListener{{ID: uuid.New(), Protocol: ProtocolTCP, Address: "*", Port: 20990, PortEnd: 21010}}
		}, PortConflictError{Protocol: ProtocolTCP, Port: 20990, PortEnd: 20999, With: PortConflictSelf}},
	} {
		fields := rangeFields()
		check.change(&fields)
		err := normalizeFields(&fields)
		var located *PortConflictError
		if !errors.As(err, &located) || !errors.Is(err, ErrPortConflict) || *located != check.want {
			t.Fatalf("%s: %v (%+v)", name, err, located)
		}
	}
	fields := rangeFields()
	fields.AdditionalListeners = &[]AdditionalListener{{ID: uuid.New(), Protocol: ProtocolUDP, Address: "*", Port: 20000, PortEnd: 20999}}
	if err := normalizeFields(&fields); err != nil {
		t.Fatalf("same range on UDP refused: %v", err)
	}
	if text := (&PortConflictError{Protocol: "tcp", Port: 20000, PortEnd: 20100, With: PortConflictStream, Name: "game"}).Error(); text != "tcp listen ports 20000-20100 conflict with stream game" {
		t.Fatalf("message %q", text)
	}
}

// The runtime intent carries port_end / follow_port in the edge contract's
// places only when used.
func TestPortRangeReachesTheRuntimeIntent(t *testing.T) {
	item := Forward{ID: uuid.New(), ScopeID: uuid.New(), Protocol: ProtocolTCP, ListenAddress: "*",
		ListenPort: 20000, UpstreamAddress: "192.0.2.10", UpstreamPort: 20000, MaxConnectionsPerClient: 100, Revision: 1}
	plain, err := json.Marshal(runtimeSpec(item))
	if err != nil || strings.Contains(string(plain), "port_end") || strings.Contains(string(plain), "follow_port") {
		t.Fatalf("single-port intent changed: %s %v", plain, err)
	}
	item.ListenPortEnd, item.UpstreamFollowPort = 20999, true
	item.AdditionalListeners = []AdditionalListener{{ID: uuid.New(), Protocol: ProtocolUDP, Address: "*", Port: 30000, PortEnd: 30010}}
	ranged, err := json.Marshal(runtimeSpec(item))
	if err != nil || !strings.Contains(string(ranged), `"listener":{"protocol":"tcp","address":"*","port":20000,"port_end":20999}`) ||
		!strings.Contains(string(ranged), `"port":30000,"port_end":30010}`) ||
		!strings.Contains(string(ranged), `"port":20000,"follow_port":true}`) {
		t.Fatalf("ranged intent: %s %v", ranged, err)
	}
	var wire edgeconfig.L4StreamRuntimeV2
	if err := json.Unmarshal(ranged, &wire); err != nil || wire.Listener.PortEnd != 20999 || !wire.Endpoint.FollowPort ||
		wire.AdditionalListeners[0].PortEnd != 30010 || !edgeconfig.L4PortRangesUsed(wire) {
		t.Fatalf("intent does not decode into the edge contract: %+v %v", wire, err)
	}
	if encoded, err := json.Marshal(Forward{}); err != nil || !strings.Contains(string(encoded), `"listen_port_end":0`) ||
		!strings.Contains(string(encoded), `"upstream_follow_port":false`) {
		t.Fatalf("stream response must carry the range fields: %s %v", encoded, err)
	}
	if ports := socketPorts(20000, 20999) + socketPorts(30000, 0); ports != 1001 {
		t.Fatalf("socket ports %d", ports)
	}
}
