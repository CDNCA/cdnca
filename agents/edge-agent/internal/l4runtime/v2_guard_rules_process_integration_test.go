//go:build integration && linux

package l4runtime_test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/firewall"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4guard"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4runtime"
	"github.com/cdnca/cdnca/libs/edgeconfig"
)

const (
	guardTenant = "11111111-1111-4111-8111-111111111111"
	guardSite   = "22222222-2222-4222-8222-222222222222"
)

func guardStream(index int, protocol l4runtime.Protocol, port, origin int, rules []l4runtime.GuardRuleV2) l4runtime.StreamRuntimeSpecV2 {
	id := fmt.Sprintf("77777777-7777-4777-8777-%012d", index)
	return l4runtime.StreamRuntimeSpecV2{
		SchemaVersion: l4runtime.SchemaVersionV2, TenantID: guardTenant, StreamID: id, Revision: 1,
		Listener: l4runtime.ListenerSocketV2{Protocol: protocol, Address: "0.0.0.0", Port: port},
		Endpoint: l4runtime.EndpointV2{Address: "127.0.0.1", Port: origin},
		Geo: l4runtime.GeoPolicyV2{TenantID: guardTenant, StreamID: id, Revision: 1,
			UnknownRegionAction: l4runtime.GeoActionAllow},
		ConnectTimeoutMS: 1000, ResponseTimeoutMS: 8000, MaxConnectionsPerClient: 100, DrainTimeoutMS: 30000,
		GuardRules: rules,
	}
}

func guardRule(index int, action string) l4runtime.GuardRuleV2 {
	return l4runtime.GuardRuleV2{ID: fmt.Sprintf("66666666-6666-4666-8666-%012d", index), Action: action}
}

// startGuardRuntime applies config to a fresh L4 OpenResty and returns its
// manager.
func startGuardRuntime(t *testing.T, ctx context.Context, binary string, config l4runtime.ConfigV2) *l4runtime.Manager {
	t.Helper()
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
	return manager
}

// guardTCP connects from source, sends payload after delay and reports
// whether it came back (echo origin).
func guardTCP(source string, port int, payload string, delay time.Duration) bool {
	dialer := net.Dialer{Timeout: time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}}
	connection, err := dialer.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return false
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(delay + 4*time.Second))
	time.Sleep(delay)
	if _, err := connection.Write([]byte(payload)); err != nil {
		return false
	}
	buffer := make([]byte, len(payload))
	_, err = io.ReadFull(connection, buffer)
	return err == nil && string(buffer) == payload
}

func guardUDP(port int, payload string) bool {
	connection, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		return false
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(700 * time.Millisecond))
	if _, err := connection.Write([]byte(payload)); err != nil {
		return false
	}
	buffer := make([]byte, 64)
	n, err := connection.Read(buffer)
	return err == nil && string(buffer[:n]) == payload
}

// startGreetingOrigin speaks first (a server-first protocol such as SSH).
func startGreetingOrigin(t *testing.T, port int) {
	t.Helper()
	listener, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
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
				_, _ = connection.Write([]byte("HELLO\n"))
				_, _ = io.Copy(connection, connection)
			}()
		}
	}()
}

// clientHello is the first TLS record crypto/tls sends for serverName.
func clientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	client, server := net.Pipe()
	go func() {
		_ = tls.Client(client, &tls.Config{ServerName: serverName, InsecureSkipVerify: true}).Handshake() //nolint:gosec // only the hello is used
	}()
	defer client.Close()
	defer server.Close()
	header := make([]byte, 5)
	if _, err := io.ReadFull(server, header); err != nil || header[0] != 0x16 {
		t.Fatalf("client hello header %x %v", header, err)
	}
	body := make([]byte, int(header[3])<<8|int(header[4]))
	if _, err := io.ReadFull(server, body); err != nil {
		t.Fatal(err)
	}
	return append(header, body...)
}

// guardTLS sends a ClientHello for serverName to a passthrough port whose
// origin echoes: admitted, the hello comes back; refused, the node closes.
func guardTLS(t *testing.T, port int, serverName string) bool {
	t.Helper()
	hello := clientHello(t, serverName)
	connection, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		return false
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := connection.Write(hello); err != nil {
		return false
	}
	echo := make([]byte, len(hello))
	_, err = io.ReadFull(connection, echo)
	return err == nil && string(echo) == string(hello)
}

// guard_rules in a real L4 OpenResty: first packet prefix with a hit
// threshold before the ban, a client IP range, a server-first protocol and
// a slow client never cut off by the first packet wait, the first UDP
// datagram, SNI on a passthrough port, and the kernel ban queue.
func TestV2GuardRulesInOpenResty(t *testing.T) {
	binary := os.Getenv("L4_V2_OPENRESTY")
	if binary == "" {
		t.Skip("L4_V2_OPENRESTY requires an isolated Linux runtime")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	startRateEchoOrigins(t, 19480, 19481)
	startGreetingOrigin(t, 19482)
	startRateEchoOrigins(t, 19483, 19484)

	ban := guardRule(1, edgeconfig.L4GuardActionBan)
	ban.BanSeconds, ban.Threshold, ban.WindowSeconds = 60, 3, 60
	ban.FirstPacket = &edgeconfig.L4GuardFirstPacket{Match: edgeconfig.L4GuardMatchPrefixHex, Value: "4241444b"} // "BADK"
	rangeDrop := guardRule(2, edgeconfig.L4GuardActionDrop)
	rangeDrop.ClientIP = &edgeconfig.L4GuardClientIP{CIDRs: []string{"127.0.0.3/32"}}
	contains := guardRule(3, edgeconfig.L4GuardActionDrop)
	contains.FirstPacket = &edgeconfig.L4GuardFirstPacket{Match: edgeconfig.L4GuardMatchContains, Value: "DROPME"}
	regex := guardRule(4, edgeconfig.L4GuardActionDrop)
	regex.FirstPacket = &edgeconfig.L4GuardFirstPacket{Match: edgeconfig.L4GuardMatchRegex, Value: `^BAD[0-9]+$`}
	sni := guardRule(5, edgeconfig.L4GuardActionDrop)
	sni.ServerNames = []string{"bad.example.com"}
	passthrough := guardStream(5, l4runtime.ProtocolTCP, 18483, 19483, []l4runtime.GuardRuleV2{sni})
	passthrough.TLSPassthrough, passthrough.ServerNames = true, []string{"*.example.com"}
	// Two passthrough streams on one port: behind the dispatcher.
	sharedSNI := guardRule(6, edgeconfig.L4GuardActionDrop)
	sharedSNI.ServerNames = []string{"bad.a.example"}
	sharedA := guardStream(6, l4runtime.ProtocolTCP, 18485, 19483, []l4runtime.GuardRuleV2{sharedSNI})
	sharedA.TLSPassthrough, sharedA.ServerNames = true, []string{"*.a.example"}
	sharedB := guardStream(7, l4runtime.ProtocolTCP, 18485, 19483, nil)
	sharedB.TLSPassthrough, sharedB.ServerNames = true, []string{"b.example"}
	config, err := l4runtime.AggregateStreamRuntimeSpecsV2("guard-v1", 1, []l4runtime.StreamRuntimeSpecV2{
		guardStream(1, l4runtime.ProtocolTCP, 18480, 19480, []l4runtime.GuardRuleV2{ban, rangeDrop}),
		guardStream(2, l4runtime.ProtocolUDP, 18481, 19481, []l4runtime.GuardRuleV2{regex}),
		guardStream(3, l4runtime.ProtocolTCP, 18482, 19482, []l4runtime.GuardRuleV2{contains}),
		passthrough, sharedA, sharedB,
	})
	if err != nil {
		t.Fatal(err)
	}
	// L4F-E04: as root the workers are nobody, and the telemetry paths make
	// /var/lib/cdnca-edge and shared/ 0700, so the default dispatch
	// directory there is unreachable (every dispatched connection reset).
	// Like the dynamic routing node (its mux root, 0711), keep the internal
	// sockets under a traversable directory.
	config.DispatchDirectory = "/run/cdnca-test/mux/l4"
	t.Cleanup(func() { _ = os.RemoveAll("/run/cdnca-test") })
	startGuardRuntime(t, ctx, binary, config)

	// First packet prefix: two hits only disconnect, the third bans.
	if !guardTCP("127.0.0.1", 18480, "GOOD", 0) {
		t.Fatal("clean first packet refused")
	}
	for hit := 1; hit <= 2; hit++ {
		if guardTCP("127.0.0.1", 18480, "BADK", 0) {
			t.Fatalf("matching first packet (hit %d) admitted", hit)
		}
	}
	if !guardTCP("127.0.0.1", 18480, "GOOD", 0) {
		t.Fatal("client banned before the threshold (2 of 3 hits)")
	}
	if guardTCP("127.0.0.1", 18480, "BADK", 0) {
		t.Fatal("third matching first packet admitted")
	}
	if guardTCP("127.0.0.1", 18480, "GOOD", 0) {
		t.Fatal("banned client admitted")
	}
	if !guardTCP("127.0.0.2", 18480, "GOOD", 0) {
		t.Fatal("another client refused by 127.0.0.1's ban")
	}
	if guardTCP("127.0.0.3", 18480, "GOOD", 0) {
		t.Fatal("client in the dropped range admitted")
	}
	// A slow client: its first data after 1 s is still judged.
	if !guardTCP("127.0.0.2", 18480, "GOOD", time.Second) || guardTCP("127.0.0.4", 18480, "BADK", time.Second) {
		t.Fatal("late first packet not judged")
	}

	// The ban reached the kernel queue (exclusive socket, peer = client).
	bans, err := l4guard.ControlBans{Path: l4runtime.L4ControlSocketPath}.Bans(ctx)
	if err != nil || len(bans) != 1 {
		t.Fatalf("kernel ban queue = %q, %v", bans, err)
	}
	parts := strings.Split(bans[0], "|")
	until, _ := strconv.ParseInt(parts[len(parts)-1], 10, 64)
	if len(parts) != 3 || parts[0] != config.Listeners[0].StreamID || parts[1] != "127.0.0.1" ||
		until < time.Now().Unix()+50 || until > time.Now().Unix()+62 {
		t.Fatalf("kernel ban entry %q", bans[0])
	}
	if again, err := (l4guard.ControlBans{Path: l4runtime.L4ControlSocketPath}).Bans(ctx); err != nil || len(again) != 0 {
		t.Fatalf("queue not drained: %q %v", again, err)
	}

	// A server-first protocol: the client sends nothing; after the 2.5 s
	// first packet wait it is forwarded, not cut off at preread_timeout.
	started := time.Now()
	connection, err := net.DialTimeout("tcp4", "127.0.0.1:18482", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.SetDeadline(time.Now().Add(6 * time.Second))
	greeting := make([]byte, 6)
	if _, err := io.ReadFull(connection, greeting); err != nil || string(greeting) != "HELLO\n" {
		t.Fatalf("server-first origin after %v: %q %v", time.Since(started), greeting, err)
	}
	waited := time.Since(started)
	_ = connection.Close()
	if waited < 2*time.Second || waited > 3500*time.Millisecond {
		t.Fatalf("server-first greeting after %v, want about 2.5 s", waited)
	}
	if guardTCPGreeting(18482, "xxDROPMExx") {
		t.Fatal("first packet containing the pattern admitted")
	}

	// UDP: the first datagram, not consumed when admitted.
	if !guardUDP(18481, "GOOD") || guardUDP(18481, "BAD42") || !guardUDP(18481, "BAD") {
		t.Fatal("UDP first datagram regex")
	}

	// SNI on a passthrough port held alone.
	if !guardTLS(t, 18483, "good.example.com") {
		t.Fatal("good.example.com refused")
	}
	if guardTLS(t, 18483, "bad.example.com") {
		t.Fatal("bad.example.com admitted")
	}
	// SNI behind a shared port's dispatcher.
	if !guardTLS(t, 18485, "ok.a.example") || guardTLS(t, 18485, "bad.a.example") || !guardTLS(t, 18485, "b.example") {
		t.Fatal("SNI guard rule behind the dispatcher")
	}
	t.Logf("prefix threshold 3 + ban + per client + range + late data; queue %s; server-first after %v; UDP regex; SNI", bans[0], waited.Round(time.Millisecond))
}

// guardTCPGreeting sends payload to a greeting origin and reports whether
// the greeting came back.
func guardTCPGreeting(port int, payload string) bool {
	connection, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		return false
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := connection.Write([]byte(payload)); err != nil {
		return false
	}
	greeting := make([]byte, 6)
	_, err = io.ReadFull(connection, greeting)
	return err == nil && string(greeting) == "HELLO\n"
}

// A guard ban raised to the kernel: as root with nft, the queued ban becomes
// an nftables deny of the client on the stream's port, so its SYN is dropped
// (the dial times out) while other clients and other ports still work.
func TestV2GuardKernelBanInOpenResty(t *testing.T) {
	binary := os.Getenv("L4_V2_OPENRESTY")
	nft, lookErr := exec.LookPath("nft")
	if binary == "" || os.Geteuid() != 0 || lookErr != nil {
		t.Skip("L4_V2_OPENRESTY as root with nft requires an isolated Linux runtime")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	startRateEchoOrigins(t, 19490, 19491)
	startRateEchoOrigins(t, 19492, 19493)
	ban := guardRule(11, edgeconfig.L4GuardActionBan)
	ban.BanSeconds, ban.Threshold = 120, 1
	ban.FirstPacket = &edgeconfig.L4GuardFirstPacket{Match: edgeconfig.L4GuardMatchContains, Value: "BAD"}
	config, err := l4runtime.AggregateStreamRuntimeSpecsV2("guard-kernel-v1", 1, []l4runtime.StreamRuntimeSpecV2{
		guardStream(11, l4runtime.ProtocolTCP, 18490, 19490, []l4runtime.GuardRuleV2{ban}),
		guardStream(12, l4runtime.ProtocolTCP, 18492, 19492, nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	manager := startGuardRuntime(t, ctx, binary, config)
	firewallRoot := filepath.Join(t.TempDir(), "firewall")
	firewallManager, err := firewall.NewManager(firewallRoot, nft)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = exec.Command(nft, "destroy", "table", firewall.TableFamily, firewall.TableName).Run() })
	kernel, err := l4guard.New(l4guard.ControlBans{Path: l4runtime.L4ControlSocketPath}, manager, firewallManager, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if guardTCP("127.0.0.1", 18490, "BAD!", 0) {
		t.Fatal("matching first packet admitted")
	}
	if err := kernel.Step(ctx); err != nil {
		t.Fatalf("kernel ban step: %v", err)
	}
	listing, err := exec.Command(nft, "list", "table", firewall.TableFamily, firewall.TableName).CombinedOutput()
	if err != nil || !strings.Contains(string(listing), "ip saddr 127.0.0.1 tcp dport 18490") {
		t.Fatalf("nftables after the ban:\n%s %v", listing, err)
	}
	dialer := net.Dialer{Timeout: time.Second, LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}}
	if connection, err := dialer.Dial("tcp4", "127.0.0.1:18490"); err == nil {
		_ = connection.Close()
		t.Fatal("banned client completed a TCP handshake: the kernel did not drop its SYN")
	} else if netErr := net.Error(nil); !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("banned client dial: %v, want a timeout (SYN dropped)", err)
	}
	if !guardTCP("127.0.0.2", 18490, "GOOD", 0) {
		t.Fatal("another client dropped by the kernel ban")
	}
	if !guardTCP("127.0.0.1", 18492, "GOOD", 0) {
		t.Fatal("the banned client lost another stream's port")
	}
	t.Logf("kernel ban:\n%s", listing)
}
