//go:build integration && linux

package l4runtime_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4live"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4runtime"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type liveRuntime struct {
	manager   *l4runtime.Manager
	openResty *l4runtime.OpenResty
}

func (runtime liveRuntime) ActiveConfigV2(ctx context.Context) (*l4runtime.ConfigV2, error) {
	return runtime.manager.ActiveConfigV2(ctx)
}
func (runtime liveRuntime) WorkerPIDs() ([]int, error) { return runtime.openResty.WorkerPIDs() }

// The live connection list against a real kernel and L4 OpenResty: sock_diag
// with the port bytecode finds the stream's sessions (not another stream's),
// the registry names the PROXY protocol client and start, and closing one
// through pidfd_getfd ends it (its log says killed). Run as root with
// CAP_SYS_PTRACE, like the node agent.
func TestV2LiveConnectionsListAndCloseInOpenResty(t *testing.T) {
	binary := os.Getenv("L4_V2_OPENRESTY")
	if binary == "" || os.Geteuid() != 0 {
		t.Skip("L4_V2_OPENRESTY as root requires an isolated Linux runtime")
	}
	if !l4live.CanClose() {
		t.Fatal("root cannot take sockets: pidfd_getfd unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	root := filepath.Join(t.TempDir(), "state")
	controller, err := l4runtime.NewOpenResty(binary, filepath.Join(root, "run", "nginx.pid"), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := l4runtime.NewManager(root, controller)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stopCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		_ = controller.Stop(stopCtx, filepath.Join(root, "current"))
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err == nil && info != nil && info.Mode()&os.ModeSymlink == 0 {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
	})
	dns, err := l4runtime.NewDNSCoordinator(filepath.Join(root, "dns"), unusedProcessDNS{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	startRateEchoOrigins(t, 19580, 19581)
	const tenant, site = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	spec := func(index, port int, trusted []string) l4runtime.StreamRuntimeSpecV2 {
		id := fmt.Sprintf("77777777-7777-4777-8777-%012d", index)
		return l4runtime.StreamRuntimeSpecV2{
			SchemaVersion: l4runtime.SchemaVersionV2, TenantID: tenant, StreamID: id, Revision: 1,
			Listener: l4runtime.ListenerSocketV2{Protocol: l4runtime.ProtocolTCP, Address: "0.0.0.0", Port: port},
			Endpoint: l4runtime.EndpointV2{Address: "127.0.0.1", Port: 19580},
			Geo: l4runtime.GeoPolicyV2{Enabled: true, TenantID: tenant, StreamID: id, Revision: 1,
				UnknownRegionAction: l4runtime.GeoActionAllow, TrustedProxyCIDRs: trusted},
			ConnectTimeoutMS: 1000, ResponseTimeoutMS: 60000, MaxConnectionsPerClient: 100, DrainTimeoutMS: 30000,
			ProxyProtocolInbound: len(trusted) != 0, SessionLog: true,
		}
	}
	config, err := l4runtime.AggregateStreamRuntimeSpecsV2("live-v1", 1, []l4runtime.StreamRuntimeSpecV2{
		spec(1, 18580, []string{"127.0.0.0/8"}), spec(2, 18581, nil)})
	if err != nil {
		t.Fatal(err)
	}
	logs := map[string]string{}
	for _, listener := range config.Listeners {
		path, _ := l4runtime.L4TelemetryLogPathForConfigListener("/var/lib/cdnca-edge", config.VersionID, listener)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		logs[listener.StreamID] = path
	}
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Join("/var/lib/cdnca-edge/shared/telemetry", config.VersionID)) })
	if result, err := manager.ApplyV2(ctx, config, dns); err != nil || result.State != l4runtime.StateApplied {
		t.Fatalf("ApplyV2 = %+v, %v", result, err)
	}
	hold := func(port int, proxyClient string) net.Conn {
		connection, err := net.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			t.Fatal(err)
		}
		if proxyClient != "" {
			local := connection.LocalAddr().(*net.TCPAddr)
			fmt.Fprintf(connection, "PROXY TCP4 %s 127.0.0.1 %d %d\r\n", proxyClient, local.Port, port)
		}
		if _, err := connection.Write([]byte("live")); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(connection, make([]byte, 4)); err != nil {
			for _, path := range logs {
				content, _ := os.ReadFile(path)
				t.Logf("%s:\n%s", path, content)
			}
			t.Fatal(err)
		}
		return connection
	}
	proxied, direct, other := hold(18580, "203.0.113.10"), hold(18580, "203.0.113.11"), hold(18581, "")
	defer direct.Close()
	defer other.Close()
	executor, err := l4live.New(liveRuntime{manager: manager, openResty: controller}, l4live.LinuxKernel{},
		l4live.ControlRegistry{Path: l4runtime.L4ControlSocketPath}, true)
	if err != nil {
		t.Fatal(err)
	}
	command := func(keys ...string) *agentv1.L4LiveConnectionsCommand {
		return &agentv1.L4LiveConnectionsCommand{Event: &commonv1.EventMetadata{EventId: uuid.NewString()},
			StreamId: config.Listeners[0].StreamID, Limit: 100, CloseSessionKeys: keys,
			ExpireTime: timestamppb.New(time.Now().Add(time.Minute))}
	}
	result := executor.Execute(ctx, command())
	if result.ErrorCode != "" || result.Matched != 2 {
		t.Fatalf("list = %+v", result)
	}
	var proxiedKey string
	for _, connection := range result.Connections {
		if connection.StartedAt == nil || connection.ListenPort != 18580 || connection.GetBytesReceived() == 0 ||
			connection.Upstream != "127.0.0.1:19580" {
			t.Fatalf("connection = %+v", connection)
		}
		if connection.ClientIp == "203.0.113.10" {
			proxiedKey = connection.SessionKey
			if connection.PeerIp != "127.0.0.1" {
				t.Fatalf("proxied peer = %+v", connection)
			}
		}
	}
	if proxiedKey == "" {
		t.Fatalf("PROXY client not named: %+v", result.Connections)
	}
	closed := executor.Execute(ctx, command(proxiedKey, "127.0.0.1|18580|127.0.0.1|1"))
	if len(closed.Closed) != 2 || closed.Closed[0].ErrorCode != "" || closed.Closed[1].ErrorCode != "not_found" {
		t.Fatalf("close = %+v", closed.Closed)
	}
	_ = proxied.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := proxied.Read(make([]byte, 1)); err == nil {
		t.Fatal("closed session still open")
	}
	time.Sleep(300 * time.Millisecond)
	if result := executor.Execute(ctx, command()); result.Matched != 1 {
		t.Fatalf("after close = %+v", result)
	}
	content, _ := os.ReadFile(logs[config.Listeners[0].StreamID])
	if !strings.Contains(string(content), `"end_reason":"killed"`) || !strings.Contains(string(content), `"client":"203.0.113.10"`) {
		t.Fatalf("log after close:\n%s", content)
	}
	t.Logf("sock_diag listed 2 (other stream excluded), PROXY client named, pidfd close ended the session, log killed")
}
