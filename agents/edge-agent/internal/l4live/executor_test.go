package l4live

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4runtime"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	tenant = "11111111-1111-4111-8111-111111111111"
	site   = "22222222-2222-4222-8222-222222222222"
	logged = "66666666-6666-4666-8666-000000000001"
	plain  = "66666666-6666-4666-8666-000000000002"
)

type fakeRuntime struct{ config *l4runtime.ConfigV2 }

func (runtime fakeRuntime) ActiveConfigV2(context.Context) (*l4runtime.ConfigV2, error) {
	return runtime.config, nil
}
func (fakeRuntime) WorkerPIDs() ([]int, error) { return []int{11, 12}, nil }

type fakeKernel struct {
	sockets []Socket
	closed  []uint64
	ports   []uint16
}

func (kernel *fakeKernel) Established(_ context.Context, ports []uint16) ([]Socket, error) {
	kernel.ports = ports
	return kernel.sockets, nil
}

func (kernel *fakeKernel) Close(_ context.Context, pids []int, inode uint64) error {
	if len(pids) != 2 {
		return ErrSocketGone
	}
	if inode == 99 {
		return ErrSocketGone
	}
	kernel.closed = append(kernel.closed, inode)
	return nil
}

type fakeRegistry struct {
	values map[string]string
	killed []string
}

func (registry *fakeRegistry) Get(_ context.Context, keys []string) (map[string]string, error) {
	result := map[string]string{}
	for _, key := range keys {
		if value, ok := registry.values[key]; ok {
			result[key] = value
		}
	}
	return result, nil
}

func (registry *fakeRegistry) Kill(_ context.Context, keys []string) error {
	registry.killed = append(registry.killed, keys...)
	return nil
}

func stream(id string, port int, sessionLog bool, trusted []string) l4runtime.StreamRuntimeSpecV2 {
	return l4runtime.StreamRuntimeSpecV2{
		SchemaVersion: l4runtime.SchemaVersionV2, TenantID: tenant, StreamID: id, Revision: 1,
		Listener: l4runtime.ListenerSocketV2{Protocol: l4runtime.ProtocolTCP, Address: "0.0.0.0", Port: port},
		Endpoint: l4runtime.EndpointV2{Address: "10.0.0.9", Port: 443},
		Geo: l4runtime.GeoPolicyV2{Enabled: true, TenantID: tenant, StreamID: id, Revision: 1,
			UnknownRegionAction: l4runtime.GeoActionAllow, TrustedProxyCIDRs: trusted},
		ConnectTimeoutMS: 1000, ResponseTimeoutMS: 5000, MaxConnectionsPerClient: 100, DrainTimeoutMS: 30000,
		ProxyProtocolInbound: len(trusted) != 0, SessionLog: sessionLog,
	}
}

func socket(local, peer string, inode uint64) Socket {
	received, sent := uint64(10*inode), uint64(20*inode)
	return Socket{Local: netip.MustParseAddrPort(local), Peer: netip.MustParseAddrPort(peer), Inode: inode,
		BytesReceived: &received, BytesSent: &sent}
}

func command(streamID string) *agentv1.L4LiveConnectionsCommand {
	return &agentv1.L4LiveConnectionsCommand{Event: &commonv1.EventMetadata{EventId: "33333333-3333-4333-8333-333333333333"},
		NodeId: "44444444-4444-4444-8444-444444444444", StreamId: streamID, Limit: 10,
		ExpireTime: timestamppb.New(time.Now().Add(time.Minute))}
}

func TestExecutorListsFiltersAndCloses(t *testing.T) {
	config, err := l4runtime.AggregateStreamRuntimeSpecsV2("v", 1, []l4runtime.StreamRuntimeSpecV2{
		stream(logged, 18480, true, []string{"192.0.2.0/24"}), stream(plain, 18481, false, nil)})
	if err != nil {
		t.Fatal(err)
	}
	kernel := &fakeKernel{sockets: []Socket{
		socket("10.0.0.1:18480", "192.0.2.9:50000", 1),    // via a trusted proxy, tracked
		socket("10.0.0.1:18480", "198.51.100.7:40001", 2), // tracked direct
		socket("10.0.0.1:18480", "198.51.100.8:40002", 3), // untracked (registry evicted)
		socket("10.0.0.1:18481", "198.51.100.7:40003", 4), // the other stream's port
	}}
	registry := &fakeRegistry{values: map[string]string{
		"10.0.0.1|18480|192.0.2.9|50000":    logged + "|" + logged + "|203.0.113.10|61000|1700000000.500|1:1|0",
		"10.0.0.1|18480|198.51.100.7|40001": logged + "|" + logged + "|198.51.100.7|40001|1700000001.000|1:2|0",
	}}
	executor, err := New(fakeRuntime{config: &config}, kernel, registry, true)
	if err != nil || executor.APIVersion() != APIVersionClose {
		t.Fatal(err)
	}
	list := command(logged)
	if err := executor.Validate(list); err != nil {
		t.Fatal(err)
	}
	result := executor.Execute(t.Context(), list)
	if result.ErrorCode != "" || result.Matched != 3 || len(result.Connections) != 3 || len(kernel.ports) != 1 || kernel.ports[0] != 18480 {
		t.Fatalf("list = %+v ports=%v", result, kernel.ports)
	}
	proxied := result.Connections[0]
	if proxied.ClientIp != "203.0.113.10" || proxied.ClientPort != 61000 || proxied.PeerIp != "192.0.2.9" ||
		proxied.Upstream != "10.0.0.9:443" || proxied.StartedAt.AsTime().UnixMilli() != 1700000000500 || proxied.GetBytesReceived() != 10 {
		t.Fatalf("proxied = %+v", proxied)
	}
	if untracked := result.Connections[2]; untracked.StartedAt != nil || untracked.ClientIp != "198.51.100.8" {
		t.Fatalf("untracked = %+v", untracked)
	}
	filtered := command(logged)
	filtered.ClientIp, filtered.Limit = "203.0.113.0/24", 1
	if result := executor.Execute(t.Context(), filtered); result.Matched != 1 || result.Connections[0].ClientIp != "203.0.113.10" {
		t.Fatalf("filtered = %+v", result)
	}
	limited := command(logged)
	limited.Limit = 1
	if result := executor.Execute(t.Context(), limited); result.Matched != 3 || len(result.Connections) != 1 {
		t.Fatalf("limited = %+v", result)
	}

	closing := command(logged)
	closing.CloseSessionKeys = []string{"10.0.0.1|18480|198.51.100.7|40001", "10.0.0.1|18481|198.51.100.7|40003", "10.0.0.1|18480|198.51.100.8|40002"}
	if err := executor.Validate(closing); err != nil {
		t.Fatal(err)
	}
	result = executor.Execute(t.Context(), closing)
	if len(result.Closed) != 3 || result.Closed[0].ErrorCode != "" || result.Closed[1].ErrorCode != "not_found" || result.Closed[2].ErrorCode != "" ||
		len(kernel.closed) != 2 || kernel.closed[0] != 2 || len(registry.killed) != 1 || registry.killed[0] != closing.CloseSessionKeys[0] {
		t.Fatalf("close = %+v closed=%v killed=%v", result.Closed, kernel.closed, registry.killed)
	}
	// List-only agents refuse to close.
	viewer, _ := New(fakeRuntime{config: &config}, kernel, registry, false)
	if viewer.APIVersion() != APIVersionList || viewer.Execute(t.Context(), closing).Closed[0].ErrorCode != "unsupported" {
		t.Fatal("list-only agent closed a session")
	}
	// A stream without a session log lists the kernel's view only.
	if result := executor.Execute(t.Context(), command(plain)); result.Matched != 1 || result.Connections[0].StartedAt != nil {
		t.Fatalf("plain = %+v", result)
	}
	expired := command(logged)
	expired.ExpireTime = timestamppb.New(time.Now().Add(-time.Second))
	if executor.Execute(t.Context(), expired).ErrorCode != "expired" {
		t.Fatal("expired command executed")
	}
	if executor.Execute(t.Context(), command("66666666-6666-4666-8666-000000000009")).Matched != 0 {
		t.Fatal("unknown stream listed connections")
	}
	for name, bad := range map[string]func(*agentv1.L4LiveConnectionsCommand){
		"limit":  func(c *agentv1.L4LiveConnectionsCommand) { c.Limit = 1001 },
		"client": func(c *agentv1.L4LiveConnectionsCommand) { c.ClientIp = "nope" },
		"key":    func(c *agentv1.L4LiveConnectionsCommand) { c.CloseSessionKeys = []string{"a|b"} },
		"key spaces": func(c *agentv1.L4LiveConnectionsCommand) {
			c.CloseSessionKeys = []string{"10.0.0.1|1|10.0.0.2|2\nkill"}
		},
		"stream": func(c *agentv1.L4LiveConnectionsCommand) { c.StreamId = "x" },
	} {
		value := command(logged)
		bad(value)
		if executor.Validate(value) == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

// A port range lists connections on every port of it; a follow_port origin
// is shown on the port the client connected to. Ranges too long for the
// inet_diag filter dump every socket and filter by port here.
func TestExecutorListsPortRanges(t *testing.T) {
	ranged := stream(logged, 20000, false, nil)
	ranged.Listener.PortEnd = 20009
	ranged.Endpoint.Port, ranged.Endpoint.FollowPort = 20000, true
	config, err := l4runtime.AggregateStreamRuntimeSpecsV2("v", 1, []l4runtime.StreamRuntimeSpecV2{ranged})
	if err != nil {
		t.Fatal(err)
	}
	kernel := &fakeKernel{sockets: []Socket{
		socket("10.0.0.1:20000", "198.51.100.7:40001", 1),
		socket("10.0.0.1:20009", "198.51.100.7:40002", 2),
		socket("10.0.0.1:20010", "198.51.100.7:40003", 3), // outside the range
	}}
	executor, err := New(fakeRuntime{config: &config}, kernel, &fakeRegistry{}, true)
	if err != nil {
		t.Fatal(err)
	}
	result := executor.Execute(t.Context(), command(logged))
	if result.ErrorCode != "" || len(kernel.ports) != 10 || kernel.ports[0] != 20000 || kernel.ports[9] != 20009 {
		t.Fatalf("ports = %v result = %+v", kernel.ports, result)
	}
	if len(result.Connections) != 2 || result.Connections[0].Upstream != "10.0.0.9:20000" || result.Connections[1].Upstream != "10.0.0.9:20009" {
		t.Fatalf("connections = %+v", result.Connections)
	}
	wide := stream(logged, 10000, false, nil)
	wide.Listener.PortEnd = 10999
	wide.AdditionalListeners = make([]l4runtime.AdditionalListenerV2, 0, 5)
	for index, start := range []int{11000, 12000, 13000, 14000, 15000} {
		wide.AdditionalListeners = append(wide.AdditionalListeners, l4runtime.AdditionalListenerV2{
			ID: fmt.Sprintf("55555555-5555-4555-8555-55555555555%d", index), Protocol: l4runtime.ProtocolTCP, Address: "*",
			Port: start, PortEnd: start + 999})
	}
	config, err = l4runtime.AggregateStreamRuntimeSpecsV2("v", 1, []l4runtime.StreamRuntimeSpecV2{wide})
	if err != nil {
		t.Fatal(err)
	}
	kernel = &fakeKernel{sockets: []Socket{socket("10.0.0.1:15999", "198.51.100.7:40001", 1), socket("10.0.0.1:16000", "198.51.100.7:40002", 2)}}
	executor, err = New(fakeRuntime{config: &config}, kernel, &fakeRegistry{}, true)
	if err != nil {
		t.Fatal(err)
	}
	result = executor.Execute(t.Context(), command(logged))
	if kernel.ports != nil || len(result.Connections) != 1 || result.Connections[0].ListenPort != 15999 || result.Connections[0].Upstream != "10.0.0.9:443" {
		t.Fatalf("wide: ports=%d result=%+v", len(kernel.ports), result)
	}
}
