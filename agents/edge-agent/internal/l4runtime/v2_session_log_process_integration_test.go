//go:build integration && linux

package l4runtime_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4runtime"
)

// session_log in a real L4 OpenResty: a live TCP session is in the registry
// (read through the control socket) while open and gone after; its log line
// carries the client and end reason; a rate refusal logs rate_limited; a
// killed session logs killed; UDP sessions are logged without tracking.
func TestV2SessionLogTracksAndLogsInOpenResty(t *testing.T) {
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
	startRateEchoOrigins(t, 19480, 19481)
	const tenant, site = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	stream := func(index int, protocol l4runtime.Protocol, port, origin int, rate *l4runtime.NewConnRateV2, trusted []string) l4runtime.StreamRuntimeSpecV2 {
		id := fmt.Sprintf("66666666-6666-4666-8666-%012d", index)
		return l4runtime.StreamRuntimeSpecV2{
			SchemaVersion: l4runtime.SchemaVersionV2, TenantID: tenant, StreamID: id, Revision: 1,
			Listener: l4runtime.ListenerSocketV2{Protocol: protocol, Address: "0.0.0.0", Port: port},
			Endpoint: l4runtime.EndpointV2{Address: "127.0.0.1", Port: origin},
			Geo: l4runtime.GeoPolicyV2{Enabled: true, TenantID: tenant, StreamID: id, Revision: 1,
				UnknownRegionAction: l4runtime.GeoActionAllow, TrustedProxyCIDRs: trusted},
			ConnectTimeoutMS: 1000, ResponseTimeoutMS: 5000, MaxConnectionsPerClient: 100, DrainTimeoutMS: 30000,
			ProxyProtocolInbound: len(trusted) != 0, NewConnRate: rate, SessionLog: true,
		}
	}
	config, err := l4runtime.AggregateStreamRuntimeSpecsV2("session-log-v1", 1, []l4runtime.StreamRuntimeSpecV2{
		stream(1, l4runtime.ProtocolTCP, 18480, 19480, &l4runtime.NewConnRateV2{RatePerSecond: 1, Burst: 1}, nil),
		stream(2, l4runtime.ProtocolUDP, 18481, 19481, nil, nil),
		stream(3, l4runtime.ProtocolTCP, 18482, 19480, nil, []string{"127.0.0.0/8"}),
	})
	if err != nil {
		t.Fatal(err)
	}
	logs := map[string]string{}
	for _, listener := range config.Listeners {
		path, err := l4runtime.L4TelemetryLogPathForConfigListener("/var/lib/cdnca-edge", config.VersionID, listener)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		logs[listener.StreamID] = path
	}
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Join("/var/lib/cdnca-edge/shared/telemetry", config.VersionID)) })
	if result, err := manager.ApplyV2(ctx, config, dns); err != nil || result.State != l4runtime.StateApplied {
		t.Fatalf("ApplyV2 = %+v, %v", result, err)
	}
	if info, err := os.Stat(l4runtime.L4ControlDirectory); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("control directory = %v, %v", info, err)
	}

	// A held TCP session is tracked by its kernel tuple.
	held, err := net.Dial("tcp4", "127.0.0.1:18480")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := held.Write([]byte("live")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(held, make([]byte, 4)); err != nil {
		t.Fatal(err)
	}
	local := held.LocalAddr().(*net.TCPAddr)
	key := fmt.Sprintf("127.0.0.1|18480|127.0.0.1|%d", local.Port)
	reply := control(t, "get", key)
	if !strings.HasPrefix(reply[key], config.Listeners[0].StreamID+"|"+config.Listeners[0].StreamID+"|127.0.0.1|") {
		t.Fatalf("live session not tracked: %q", reply)
	}
	// Rate 1 burst 1: the held session and one more pass, the third is refused.
	tcpExchange(t, "127.0.0.1", 18480, "")
	if tcpExchange(t, "127.0.0.1", 18480, "") {
		t.Fatal("third connection admitted over rate 1 burst 1")
	}
	// kill marks the session; closing it then logs killed.
	if reply := control(t, "kill", key); !strings.HasSuffix(reply[key], "|1") {
		t.Fatalf("kill reply %q", reply)
	}
	_ = held.Close()
	time.Sleep(300 * time.Millisecond)
	if reply := control(t, "get", key); reply[key] != "-" {
		t.Fatalf("ended session still tracked: %q", reply)
	}

	// PROXY protocol from a trusted proxy: the client is the real address.
	if !tcpExchange(t, "127.0.0.1", 18482, "203.0.113.10") {
		t.Fatal("PROXY session refused")
	}
	if !udpExchange(t, "127.0.0.1", 18481) {
		t.Fatal("UDP session refused")
	}
	time.Sleep(500 * time.Millisecond)

	reasons := readSessionLog(t, logs[config.Listeners[0].StreamID])
	if reasons["killed"] != 1 || reasons["rate_limited"] != 1 || reasons[""] != 1 {
		t.Fatalf("TCP end reasons = %v", reasons)
	}
	proxied := readSessionLines(t, logs[config.Listeners[2].StreamID])
	if len(proxied) != 1 || proxied[0]["client"] != "203.0.113.10" || proxied[0]["remote_addr"] != "127.0.0.1" ||
		proxied[0]["upstream_addr"] != "127.0.0.1:19480" {
		t.Fatalf("PROXY session line = %v", proxied)
	}
	udp := readSessionLines(t, logs[config.Listeners[1].StreamID])
	if len(udp) != 1 || udp[0]["client"] != "127.0.0.1" || udp[0]["protocol"] != "UDP" {
		t.Fatalf("UDP session line = %v", udp)
	}
	t.Logf("tracked+removed, killed/rate_limited/closed reasons, PROXY client, UDP logged; version=%s", config.VersionID)
}

// control sends one command with keys to the control socket.
func control(t *testing.T, command string, keys ...string) map[string]string {
	t.Helper()
	connection, err := net.DialTimeout("unix", l4runtime.L4ControlSocketPath, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintf(connection, "%s\n%s\nend\n", command, strings.Join(keys, "\n"))
	result := map[string]string{}
	scanner := bufio.NewScanner(connection)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "end" {
			return result
		}
		key, value, _ := strings.Cut(line, "\t")
		result[key] = value
	}
	t.Fatalf("control reply ended without end: %v %v", result, scanner.Err())
	return nil
}

func readSessionLines(t *testing.T, path string) []map[string]any {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var lines []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(content)), "\n") {
		var value map[string]any
		if err := json.Unmarshal([]byte(line), &value); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		lines = append(lines, value)
	}
	return lines
}

func readSessionLog(t *testing.T, path string) map[string]int {
	reasons := map[string]int{}
	for _, line := range readSessionLines(t, path) {
		reasons[fmt.Sprint(line["end_reason"])]++
	}
	return reasons
}
