//go:build integration && linux

package l4runtime_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4runtime"
)

// 端口范围 / 跟随端口回源 (tcp/udp v9) in a real L4 OpenResty: every port of
// a TCP and a UDP range is served and the ports past the range are not; with
// follow_port each client port reaches the same origin port, without it the
// whole range reaches the one origin port. Listeners bind 0.0.0.0, origins
// [::1] on the same ports (no bind collision; the IPv6 peer also checks the
// bracketed balancer address).
func TestV2PortRangeAndFollowPortInOpenResty(t *testing.T) {
	binary := os.Getenv("L4_V2_OPENRESTY")
	if binary == "" {
		t.Skip("L4_V2_OPENRESTY requires an isolated Linux runtime")
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
			if err != nil || info == nil || info.Mode()&os.ModeSymlink != 0 {
				return nil
			}
			if info.IsDir() {
				return os.Chmod(path, 0o700)
			}
			return os.Chmod(path, 0o600)
		})
	})
	dns, err := l4runtime.NewDNSCoordinator(filepath.Join(root, "dns"), unusedProcessDNS{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Origins answer "<protocol>:<their port>" so the test sees which origin
	// port a client port reached.
	for port := 18400; port <= 18405; port++ {
		startPortNamingTCPOrigin(t, port)
	}
	for port := 18410; port <= 18412; port++ {
		startPortNamingUDPOrigin(t, port)
	}
	startPortNamingTCPOrigin(t, 19420)

	const tenant, site = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	stream := func(index int, protocol l4runtime.Protocol, port, end, origin int, follow bool) l4runtime.StreamRuntimeSpecV2 {
		id := fmt.Sprintf("66666666-6666-4666-8666-%012d", index)
		return l4runtime.StreamRuntimeSpecV2{
			SchemaVersion: l4runtime.SchemaVersionV2, TenantID: tenant, StreamID: id, Revision: 1,
			Listener: l4runtime.ListenerSocketV2{Protocol: protocol, Address: "0.0.0.0", Port: port, PortEnd: end},
			Endpoint: l4runtime.EndpointV2{Address: "::1", Port: origin, FollowPort: follow},
			Geo: l4runtime.GeoPolicyV2{TenantID: tenant, StreamID: id, Revision: 1,
				UnknownRegionAction: l4runtime.GeoActionAllow},
			ConnectTimeoutMS: 1000, ResponseTimeoutMS: 5000, MaxConnectionsPerClient: 100, DrainTimeoutMS: 30000,
		}
	}
	config, err := l4runtime.AggregateStreamRuntimeSpecsV2("range-v1", 1, []l4runtime.StreamRuntimeSpecV2{
		stream(1, l4runtime.ProtocolTCP, 18400, 18405, 18400, true),
		stream(2, l4runtime.ProtocolUDP, 18410, 18412, 18410, true),
		stream(3, l4runtime.ProtocolTCP, 18420, 18422, 19420, false),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, listener := range config.Listeners {
		path, err := l4runtime.L4TelemetryLogPathForConfigListener("/var/lib/cdnca-edge", config.VersionID, listener)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Join("/var/lib/cdnca-edge/shared/telemetry", config.VersionID)) })
	if result, err := manager.ApplyV2(ctx, config, dns); err != nil || result.State != l4runtime.StateApplied {
		t.Fatalf("ApplyV2 = %+v, %v", result, err)
	}

	for port := 18400; port <= 18405; port++ {
		if got := tcpPortReply(t, port); got != fmt.Sprintf("tcp:%d", port) {
			t.Fatalf("TCP range port %d reached %q, want its own origin port", port, got)
		}
	}
	for _, port := range []int{18399, 18406} {
		if got := tcpPortReply(t, port); got != "" {
			t.Fatalf("TCP port %d outside the range answered %q", port, got)
		}
	}
	for port := 18410; port <= 18412; port++ {
		if got := udpPortReply(t, port); got != fmt.Sprintf("udp:%d", port) {
			t.Fatalf("UDP range port %d reached %q, want its own origin port", port, got)
		}
	}
	if got := udpPortReply(t, 18413); got != "" {
		t.Fatalf("UDP port 18413 outside the range answered %q", got)
	}
	for port := 18420; port <= 18422; port++ {
		if got := tcpPortReply(t, port); got != "tcp:19420" {
			t.Fatalf("fixed-origin range port %d reached %q, want tcp:19420", port, got)
		}
	}
	t.Logf("TCP 18400-18405 follow, UDP 18410-18412 follow, TCP 18420-18422 -> 19420; version=%s", config.VersionID)
}

func startPortNamingTCPOrigin(t *testing.T, port int) {
	t.Helper()
	listener, err := net.Listen("tcp6", fmt.Sprintf("[::1]:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				_, _ = fmt.Fprintf(connection, "tcp:%d\n", port)
			}()
		}
	}()
}

func startPortNamingUDPOrigin(t *testing.T, port int) {
	t.Helper()
	connection, err := net.ListenPacket("udp6", fmt.Sprintf("[::1]:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	go func() {
		buffer := make([]byte, 64)
		for {
			_, peer, err := connection.ReadFrom(buffer)
			if err != nil {
				return
			}
			_, _ = connection.WriteTo([]byte(fmt.Sprintf("udp:%d", port)), peer)
		}
	}()
}

// tcpPortReply is the origin's first line through the runtime, "" when the
// port refuses or nothing answers.
func tcpPortReply(t *testing.T, port int) string {
	t.Helper()
	connection, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		return ""
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	line, _ := bufio.NewReader(connection).ReadString('\n')
	return strings.TrimSpace(line)
}

func udpPortReply(t *testing.T, port int) string {
	t.Helper()
	connection, err := net.Dial("udp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return ""
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := connection.Write([]byte("ping")); err != nil {
		return ""
	}
	buffer := make([]byte, 64)
	count, err := connection.Read(buffer)
	if err != nil {
		return ""
	}
	return string(buffer[:count])
}
