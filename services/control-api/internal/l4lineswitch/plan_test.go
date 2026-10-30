package l4lineswitch

import (
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
)

func planTestStream(protocol string) edgeconfig.L4StreamRuntimeV2 {
	return edgeconfig.L4StreamRuntimeV2{
		StreamID: "018f47a2-5b9c-7d31-8a60-104c9c0b7101", Revision: 3,
		Listener: edgeconfig.L4ListenerV2{Protocol: protocol, Address: "*", Port: 18080},
		Endpoint: edgeconfig.L4EndpointV2{Address: "192.0.2.10", Port: 8080},
	}
}

func planTestSnapshot(streams ...edgeconfig.L4StreamRuntimeV2) publishedConfigSnapshot {
	return publishedConfigSnapshot{Streams: &edgeconfig.StreamRuntime{StreamsV2: streams}}
}

func TestPlanForNodeRetiresIPv4AndIPv6TCPListeners(t *testing.T) {
	value := Switch{ID: uuid.New(), Drain: DrainPolicy{HealthTimeout: 1500 * time.Millisecond, MaxDrain: 2500 * time.Millisecond}}
	nodeID, configID := uuid.New(), uuid.New()
	plan, err := planForNode(value, nodeID, configID, planTestSnapshot(planTestStream("tcp")), 7)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Revision != 7 || plan.Old.VersionID != configID.String() || len(plan.Old.Listeners) != 2 ||
		len(plan.New.Listeners) != 0 || len(plan.HealthChecks) != 0 || plan.HealthTimeoutSeconds != 2 ||
		plan.Drain.MaxDrainSeconds != 3 || plan.Drain.Force != "never" {
		t.Fatalf("plan = %+v", plan)
	}
	if plan.Old.Listeners[0].Address != "0.0.0.0" || plan.Old.Listeners[1].Address != "::" ||
		plan.Old.Listeners[0].Port != 18080 || plan.Old.Listeners[0].UpstreamAddress != "192.0.2.10" ||
		plan.Old.Listeners[0].UpstreamPort != 8080 {
		t.Fatalf("listeners = %+v", plan.Old.Listeners)
	}
}

func TestPlanForNodeFailsClosedForStreamsTheDrainRuntimeCannotRetire(t *testing.T) {
	value := Switch{ID: uuid.New(), Drain: DrainPolicy{HealthTimeout: time.Second, MaxDrain: time.Minute}}
	for name, mutate := range map[string]func(*edgeconfig.L4StreamRuntimeV2){
		"udp":         func(stream *edgeconfig.L4StreamRuntimeV2) { stream.Listener.Protocol = "udp" },
		"port range":  func(stream *edgeconfig.L4StreamRuntimeV2) { stream.Listener.PortEnd = 18090 },
		"follow port": func(stream *edgeconfig.L4StreamRuntimeV2) { stream.Endpoint.FollowPort = true },
		"DNS endpoint": func(stream *edgeconfig.L4StreamRuntimeV2) {
			stream.Endpoint.Address, stream.Endpoint.Host = "", "origin.example"
		},
		"SNI": func(stream *edgeconfig.L4StreamRuntimeV2) { stream.TLSPassthrough = true },
		"extra listener": func(stream *edgeconfig.L4StreamRuntimeV2) {
			stream.AdditionalListeners = []edgeconfig.L4AdditionalListenerV2{{Protocol: "tcp", Address: "*", Port: 18081}}
		},
	} {
		stream := planTestStream("tcp")
		mutate(&stream)
		if _, err := planForNode(value, uuid.New(), uuid.New(), planTestSnapshot(stream), 1); !errors.Is(err, ErrConflict) {
			t.Fatalf("%s: error=%v", name, err)
		}
	}
	stream := planTestStream("tcp")
	if _, err := planForNode(value, uuid.New(), uuid.New(), planTestSnapshot(stream, stream), 1); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate stream: error=%v", err)
	}
}

func TestPlanForNodeRejectsEmptyPublishedL4Facts(t *testing.T) {
	value := Switch{ID: uuid.New(), Drain: DrainPolicy{HealthTimeout: time.Second, MaxDrain: time.Minute}}
	for _, snapshot := range []publishedConfigSnapshot{{}, planTestSnapshot()} {
		if _, err := planForNode(value, uuid.New(), uuid.New(), snapshot, 1); !errors.Is(err, ErrConflict) {
			t.Fatalf("error = %v", err)
		}
	}
}

func TestDecodePublishedConfigSnapshotReadsSiteRuntimeStreams(t *testing.T) {
	valid := `{"schema":"cdnca.edge.site-runtime/v2","configuration_scope_id":"` + uuid.NewString() +
		`","config_version_id":"` + uuid.NewString() + `","source_revision":1,"sites":[],` +
		`"streams":{"tenant_id":"` + uuid.NewString() + `","streams_v2":[{"stream_id":"s","listener":{"protocol":"tcp","address":"*","port":1}}]}}`
	snapshot, err := decodePublishedConfigSnapshot([]byte(valid))
	if err != nil || len(snapshot.streams()) != 1 || snapshot.streams()[0].Listener.Port != 1 {
		t.Fatalf("snapshot = %+v, %v", snapshot, err)
	}
	if _, err := decodePublishedConfigSnapshot([]byte(valid + `{}`)); !errors.Is(err, ErrConflict) {
		t.Fatalf("trailing data error=%v", err)
	}
}
