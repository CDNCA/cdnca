//go:build linux

package ddos

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// udpClient sends count datagrams from new source ports (each one a new conntrack flow) and counts the answers.
const udpClient = `
import socket, sys
src, dst, port, count = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
replies = 0
for _ in range(count):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((src, 0))
    s.settimeout(0.3)
    s.sendto(b"ping-cdnca", (dst, port))
    try:
        s.recvfrom(64)
        replies += 1
    except OSError:
        pass
    s.close()
print("replies=%d" % replies)
`

func udpEchoServer(t *testing.T) uint16 {
	t.Helper()
	conn, err := net.ListenPacket("udp4", flagServer+":0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buffer := make([]byte, 64)
		for {
			n, addr, err := conn.ReadFrom(buffer)
			if err != nil {
				return
			}
			_, _ = conn.WriteTo(buffer[:n], addr)
		}
	}()
	return uint16(conn.LocalAddr().(*net.UDPAddr).Port)
}

// ad-16c on a real kernel: a UDP group's new flow limit drops the excess (UDP never reaches guard), exempt
// networks pass, and a group ban drops the client on that group's port only (TCP and UDP), not on the node's
// other ports.
func TestKernelAutoDefenseUDPLimitsAndGroupBans(t *testing.T) {
	manager, _ := kernelManager(t)
	script := setupFlagNamespace(t)
	udpScript := filepath.Join(t.TempDir(), "udp.py")
	if err := os.WriteFile(udpScript, []byte(udpClient), 0o600); err != nil {
		t.Fatal(err)
	}
	udp := func(source string, port uint16, count int) string {
		return run(t, "ip", "netns", "exec", flagNamespace, "python3", udpScript, source, flagServer, strconv.Itoa(int(port)), strconv.Itoa(count))
	}
	web := echoServer(t)
	other := echoServer(t)
	dnsPort := udpEchoServer(t)
	// A protection with something on (the null flag filter): without any, there is no table to run groups in.
	spec := spec(t, edgeconfig.DDoSProtection{TCPFlagFilter: true, TCPFlagTypes: []string{edgeconfig.DDoSTCPFlagNull},
		AllowNetworks: []string{flagExemptClient + "/32"}}, web)
	spec.Ports = MergePorts([]PortRange{{web, web}, {other, other}})
	if err := manager.Apply(t.Context(), spec); err != nil {
		t.Fatal(err)
	}
	dns := AutoGroup{ID: "dns", Protocol: "udp", Ports: []PortRange{{dnsPort, dnsPort}}}
	webGroup := AutoGroup{ID: "web", Protocol: "tcp", Ports: []PortRange{{web, web}}}
	auto := &AutoDefense{Groups: []AutoGroup{dns, webGroup}}
	if err := manager.SetAutoDefense(t.Context(), auto); err != nil {
		t.Fatal(err)
	}
	if out := udp(flagClient, dnsPort, 5); out != "replies=5" {
		t.Fatalf("UDP without limits: %s", out)
	}
	// 2 new flows a minute per client: the rest of the burst is dropped and counted.
	auto.Groups[0].NewPerMinute = 2
	if err := manager.SetAutoDefense(t.Context(), auto); err != nil {
		t.Fatal(err)
	}
	if out := udp(flagClient, dnsPort, 6); out != "replies=2" {
		t.Fatalf("limited UDP burst: %s, want 2 (burst) answered", out)
	}
	counters, err := manager.AutoCounters(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if n := counters[AutoCounterName(GroupToken("dns"), AutoDrops)].Packets; n < 4 {
		t.Fatalf("UDP limit drops %d, want >= 4", n)
	}
	if out := udp(flagExemptClient, dnsPort, 4); out != "replies=4" {
		t.Fatalf("exempt client limited on UDP: %s", out)
	}
	// Group bans: the client is cut on the web group's port and on the dns group, not on the other port.
	auto.Groups[0].NewPerMinute = 0
	if err := manager.SetAutoDefense(t.Context(), auto); err != nil {
		t.Fatal(err)
	}
	banned := []netip.Addr{netip.MustParseAddr(flagClient)}
	for _, group := range []string{"web", "dns"} {
		if n, err := manager.BanGroup(t.Context(), group, banned, time.Minute); err != nil || n != 1 {
			t.Fatalf("ban on %s: %d %v", group, n, err)
		}
	}
	if out := client(t, script, "syn", flagClient, web, 2); !strings.Contains(out, "replies=0") {
		t.Fatalf("group banned client answered on the group's port: %s", out)
	}
	if out := client(t, script, "session", flagClient, other, 1); !strings.Contains(out, "echo=ping-cdnca") {
		t.Fatalf("group ban leaked to another port: %s", out)
	}
	if out := udp(flagClient, dnsPort, 3); out != "replies=0" {
		t.Fatalf("group banned client answered on UDP: %s", out)
	}
	if out := client(t, script, "syn", flagExemptClient, web, 2); !strings.Contains(out, "replies=2") {
		t.Fatalf("other client cut by a group ban: %s", out)
	}
	listing := run(t, "nft", "list", "set", TableFamily, TableName, "ad_b4_"+GroupToken("web"))
	if !strings.Contains(listing, flagClient) {
		t.Fatalf("group ban set:\n%s", listing)
	}
	if strings.Contains(run(t, "nft", "list", "set", TableFamily, TableName, BanSetIPv4), flagClient) {
		t.Fatal("a group ban wrote the node ban set")
	}
	// Removing the auto defense part deletes the group ban sets too.
	if err := manager.SetAutoDefense(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if listing := run(t, "nft", "list", "table", TableFamily, TableName); strings.Contains(listing, "ad_b4_") {
		t.Fatalf("group ban sets left:\n%s", listing)
	}
}
