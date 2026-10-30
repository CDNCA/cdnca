//go:build integration && linux

package l4runtime_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4runtime"
)

// new_conn_rate in a real L4 OpenResty: one client over its rate is refused
// while another is not; UDP counts sessions; behind PROXY protocol from a
// trusted proxy the real client is counted, not the proxy.
func TestV2NewConnRateLimitsEachClientInOpenResty(t *testing.T) {
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
	startRateEchoOrigins(t, 19380, 19381)

	const tenant, site = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	stream := func(index int, protocol l4runtime.Protocol, port, origin int, rate l4runtime.NewConnRateV2, trusted []string) l4runtime.StreamRuntimeSpecV2 {
		id := fmt.Sprintf("55555555-5555-4555-8555-%012d", index)
		return l4runtime.StreamRuntimeSpecV2{
			SchemaVersion: l4runtime.SchemaVersionV2, TenantID: tenant, StreamID: id, Revision: 1,
			Listener: l4runtime.ListenerSocketV2{Protocol: protocol, Address: "0.0.0.0", Port: port},
			Endpoint: l4runtime.EndpointV2{Address: "127.0.0.1", Port: origin},
			Geo: l4runtime.GeoPolicyV2{Enabled: true, TenantID: tenant, StreamID: id, Revision: 1,
				UnknownRegionAction: l4runtime.GeoActionAllow, TrustedProxyCIDRs: trusted},
			ConnectTimeoutMS: 1000, ResponseTimeoutMS: 5000, MaxConnectionsPerClient: 100, DrainTimeoutMS: 30000,
			ProxyProtocolInbound: len(trusted) != 0, NewConnRate: &rate,
		}
	}
	config, err := l4runtime.AggregateStreamRuntimeSpecsV2("rate-v1", 1, []l4runtime.StreamRuntimeSpecV2{
		stream(1, l4runtime.ProtocolTCP, 18380, 19380, l4runtime.NewConnRateV2{RatePerSecond: 1, Burst: 2}, nil),
		stream(2, l4runtime.ProtocolUDP, 18381, 19381, l4runtime.NewConnRateV2{RatePerSecond: 1, Burst: 1, BanSeconds: 60}, nil),
		stream(3, l4runtime.ProtocolTCP, 18382, 19380, l4runtime.NewConnRateV2{RatePerSecond: 1}, []string{"127.0.0.0/8"}),
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

	// TCP rate 1/s, burst 2: three at once, then one per second; per client.
	if got := countAdmitted(5, func() bool { return tcpExchange(t, "127.0.0.1", 18380, "") }); got != 3 {
		t.Fatalf("TCP client 127.0.0.1 admitted %d of 5, want 3 (rate+burst)", got)
	}
	if got := countAdmitted(4, func() bool { return tcpExchange(t, "127.0.0.2", 18380, "") }); got != 3 {
		t.Fatalf("TCP client 127.0.0.2 admitted %d of 4 after 127.0.0.1 was limited, want 3", got)
	}
	time.Sleep(1100 * time.Millisecond)
	if got := countAdmitted(3, func() bool { return tcpExchange(t, "127.0.0.1", 18380, "") }); got != 1 {
		t.Fatalf("TCP client 127.0.0.1 admitted %d after one second, want 1 (refill)", got)
	}

	// UDP rate 1/s, burst 1, ban 60 s: each new session counts; the first
	// refusal bans the client, which stays refused after the bucket refills.
	if got := countAdmitted(3, func() bool { return udpExchange(t, "127.0.0.1", 18381) }); got != 2 {
		t.Fatalf("UDP client 127.0.0.1 admitted %d of 3 sessions, want 2", got)
	}
	time.Sleep(1100 * time.Millisecond)
	if udpExchange(t, "127.0.0.1", 18381) {
		t.Fatal("banned UDP client admitted after the bucket refilled")
	}
	if !udpExchange(t, "127.0.0.2", 18381) {
		t.Fatal("UDP client 127.0.0.2 refused by another client's ban")
	}

	// PROXY protocol from a trusted proxy: the real client is counted. One
	// proxy (127.0.0.1) carries two clients; rate 1, burst 0.
	if !tcpExchange(t, "127.0.0.1", 18382, "203.0.113.10") {
		t.Fatal("first connection of real client 203.0.113.10 refused")
	}
	if tcpExchange(t, "127.0.0.1", 18382, "203.0.113.10") {
		t.Fatal("second connection of real client 203.0.113.10 admitted (rate 1, burst 0)")
	}
	if !tcpExchange(t, "127.0.0.1", 18382, "203.0.113.11") {
		t.Fatal("real client 203.0.113.11 behind the same proxy refused: the proxy was counted")
	}
	t.Logf("TCP 3/5 + per-client + refill; UDP 2/3 + ban + per-client; PROXY real-client buckets; version=%s", config.VersionID)
}

func countAdmitted(attempts int, try func() bool) int {
	admitted := 0
	for range attempts {
		if try() {
			admitted++
		}
	}
	return admitted
}

// tcpExchange connects from source (a loopback address) and reports whether
// an echo came back; proxyClient, when set, is sent as a PROXY v1 header.
func tcpExchange(t *testing.T, source string, port int, proxyClient string) bool {
	t.Helper()
	dialer := net.Dialer{Timeout: time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}}
	connection, err := dialer.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return false
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	if proxyClient != "" {
		local := connection.LocalAddr().(*net.TCPAddr)
		if _, err := fmt.Fprintf(connection, "PROXY TCP4 %s 127.0.0.1 %d %d\r\n", proxyClient, local.Port, port); err != nil {
			return false
		}
	}
	if _, err := connection.Write([]byte("rate")); err != nil {
		return false
	}
	buffer := make([]byte, 4)
	_, err = io.ReadFull(connection, buffer)
	return err == nil && string(buffer) == "rate"
}

// udpExchange sends one datagram from a new socket (a new session).
func udpExchange(t *testing.T, source string, port int) bool {
	t.Helper()
	connection, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP(source)}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		return false
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(700 * time.Millisecond))
	if _, err := connection.Write([]byte("rate")); err != nil {
		return false
	}
	buffer := make([]byte, 16)
	n, err := connection.Read(buffer)
	return err == nil && string(buffer[:n]) == "rate"
}

func startRateEchoOrigins(t *testing.T, tcpPort, udpPort int) {
	t.Helper()
	tcp, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", tcpPort))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tcp.Close() })
	go func() {
		for {
			connection, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() { defer connection.Close(); _, _ = io.Copy(connection, connection) }()
		}
	}()
	udp, err := net.ListenPacket("udp4", fmt.Sprintf("127.0.0.1:%d", udpPort))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udp.Close() })
	go func() {
		buffer := make([]byte, 256)
		for {
			n, address, err := udp.ReadFrom(buffer)
			if err != nil {
				return
			}
			_, _ = udp.WriteTo(buffer[:n], address)
		}
	}()
}
