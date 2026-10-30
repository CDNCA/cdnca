//go:build linux

package ddos

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/xdp"
	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// Real kernel test of the packet filters (TCP flag classes, conntrack
// INVALID): a privileged disposable container with python3-scapy
// (scripts/edge-ddos-tcpflags-smoke.sh). Packets must arrive on a real
// interface (the filters skip lo), so the client is a network namespace on
// a veth pair; scapy crafts the malformed packets there.
const (
	flagNamespace    = "ddosflags"
	flagServer       = "10.78.0.1"
	flagClient       = "10.78.0.2"
	flagExemptClient = "10.78.0.3"
)

const scapyClient = `
import socket, sys
from scapy.all import IP, TCP, RandShort, conf, send, sr1
conf.verb = 0
mode, src, dst, port, count = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5])
if mode == "session":
    # A normal connection: handshake, data both ways, FIN close.
    s = socket.create_connection((dst, port), timeout=3, source_address=(src, 0))
    s.sendall(b"ping-cdnca")
    data = s.recv(64)
    s.shutdown(socket.SHUT_WR)
    rest = s.recv(64)
    s.close()
    print("echo=%s eof=%s" % (data.decode(), rest == b""))
    sys.exit(0)
flags = {"null": "", "xmas": "FPU", "syn_fin": "SF", "syn_rst": "SR", "fin": "F", "all": "FSRPAU", "rst": "R", "syn": "S"}[mode]
replies = 0
for _ in range(count):
    reply = sr1(IP(src=src, dst=dst)/TCP(sport=RandShort(), dport=port, flags=flags, seq=1000), timeout=0.5)
    if reply is not None:
        replies += 1
print("replies=%d" % replies)
`

func run(t *testing.T, command ...string) string {
	t.Helper()
	output, err := exec.Command(command[0], command[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %v %s", command, err, output)
	}
	return strings.TrimSpace(string(output))
}

func setupFlagNamespace(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 (scapy) is not installed")
	}
	remove := func() {
		_ = exec.Command("ip", "netns", "del", flagNamespace).Run()
		_ = exec.Command("ip", "link", "del", "ddosf0").Run()
	}
	remove()
	run(t, "ip", "netns", "add", flagNamespace)
	t.Cleanup(remove)
	run(t, "ip", "link", "add", "ddosf0", "type", "veth", "peer", "name", "ddosf1")
	run(t, "ip", "link", "set", "ddosf1", "netns", flagNamespace)
	run(t, "ip", "addr", "add", flagServer+"/24", "dev", "ddosf0")
	run(t, "ip", "link", "set", "ddosf0", "up")
	for _, address := range []string{flagClient, flagExemptClient} {
		run(t, "ip", "netns", "exec", flagNamespace, "ip", "addr", "add", address+"/24", "dev", "ddosf1")
	}
	run(t, "ip", "netns", "exec", flagNamespace, "ip", "link", "set", "ddosf1", "up")
	run(t, "ip", "netns", "exec", flagNamespace, "ip", "link", "set", "lo", "up")
	script := filepath.Join(t.TempDir(), "client.py")
	if err := os.WriteFile(script, []byte(scapyClient), 0o600); err != nil {
		t.Fatal(err)
	}
	return script
}

// echoServer echoes until the client closes, then closes its side.
func echoServer(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp4", flagServer+":0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				_, _ = io.Copy(connection, bufio.NewReader(connection))
			}()
		}
	}()
	return uint16(listener.Addr().(*net.TCPAddr).Port)
}

func client(t *testing.T, script, mode, source string, port uint16, count int) string {
	t.Helper()
	return run(t, "ip", "netns", "exec", flagNamespace, "python3", script, mode, source, flagServer,
		strconv.Itoa(int(port)), strconv.Itoa(count))
}

func dropCounts(t *testing.T, manager *Manager) map[string]uint64 {
	t.Helper()
	counters, err := manager.DropCounters(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	result := map[string]uint64{}
	for _, counter := range counters {
		result[counter.Kind] = counter.Packets
	}
	return result
}

func flagProtection(filter bool, types []string, invalid bool) edgeconfig.DDoSProtection {
	return edgeconfig.DDoSProtection{TCPFlagFilter: filter, TCPFlagTypes: types, DropInvalid: invalid,
		AllowNetworks: []string{flagExemptClient + "/32"}}
}

// kernelFlagSpec protects port and port+1 (closed: the kernel answers a
// probe there with RST, which is what a scan reads).
func kernelFlagSpec(t *testing.T, protection edgeconfig.DDoSProtection, port uint16) *Spec {
	t.Helper()
	protection.CCKernelBan = edgeconfig.CCKernelBanOff
	value, err := edgeconfig.NewSiteRuntimeDDoS(protection, []string{"10.78.0.250"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := NewSpec(&value, []PortRange{{port, port + 1}})
	if err != nil || result == nil {
		t.Fatal(err)
	}
	return result
}

// Every malformed class is dropped and counted under its own counter; the
// replies the kernel would send without the filter never come.
func TestKernelTCPFlagFiltersDropAndCountEveryClass(t *testing.T) {
	manager, _ := kernelManager(t)
	script := setupFlagNamespace(t)
	port := echoServer(t)
	closed := port + 1
	// Without the filter a probe of a closed port is answered (RST).
	for _, mode := range []string{"null", "xmas", "syn_fin", "fin"} {
		if got := client(t, script, mode, flagClient, closed, 1); got != "replies=1" {
			t.Fatalf("baseline %s: %s", mode, got)
		}
	}
	if err := manager.Apply(t.Context(), kernelFlagSpec(t, flagProtection(true, edgeconfig.DDoSTCPFlagTypes, true), port)); err != nil {
		t.Fatal(err)
	}
	const sent = 3
	for _, test := range []struct{ mode, kind string }{
		{"null", DropTCPNull}, {"xmas", DropTCPXmas}, {"syn_fin", DropTCPSynFin}, {"syn_rst", DropTCPSynRst},
		{"fin", DropTCPFin}, {"all", DropTCPAll}, {"rst", DropInvalid},
	} {
		before := dropCounts(t, manager)
		if got := client(t, script, test.mode, flagClient, closed, sent); got != "replies=0" {
			t.Errorf("%s answered through the filter: %s", test.mode, got)
		}
		after := dropCounts(t, manager)
		if after[test.kind]-before[test.kind] < sent {
			t.Errorf("%s: %s counter %d -> %d", test.mode, test.kind, before[test.kind], after[test.kind])
		}
		for kind, count := range after {
			if kind != test.kind && count != before[kind] {
				t.Errorf("%s also counted under %s (%d -> %d)", test.mode, kind, before[kind], count)
			}
		}
		t.Logf("%s: %s %d -> %d", test.mode, test.kind, before[test.kind], after[test.kind])
	}

	// A normal connection (handshake, data, FIN|ACK close) is untouched and
	// counts nowhere.
	before := dropCounts(t, manager)
	for range 5 {
		if got := client(t, script, "session", flagClient, port, 0); got != "echo=ping-cdnca eof=True" {
			t.Fatalf("normal session: %s", got)
		}
	}
	time.Sleep(200 * time.Millisecond)
	if after := dropCounts(t, manager); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatalf("normal sessions counted: %v -> %v", before, after)
	}
	// A plain SYN still opens.
	if got := client(t, script, "syn", flagClient, port, 1); got != "replies=1" {
		t.Fatalf("SYN through the filter: %s", got)
	}
	// The allow list is exempt from the filters.
	before = dropCounts(t, manager)
	if got := client(t, script, "syn_fin", flagExemptClient, closed, 1); got != "replies=1" {
		t.Fatalf("exempt client SYN+FIN: %s", got)
	}
	if after := dropCounts(t, manager); after[DropTCPSynFin] != before[DropTCPSynFin] {
		t.Fatal("exempt client counted")
	}
	t.Logf("final counters %v", dropCounts(t, manager))
}

// Only INVALID on: a NULL packet (conntrack calls invalid flags INVALID) is
// dropped as ct_invalid; turning everything off removes the rules and the
// counters, and the answer comes back.
func TestKernelDropInvalidAloneAndRemoval(t *testing.T) {
	manager, runner := kernelManager(t)
	script := setupFlagNamespace(t)
	port := echoServer(t)
	if err := manager.Apply(t.Context(), kernelFlagSpec(t, flagProtection(false, []string{"null"}, true), port)); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"null", "syn_fin", "rst"} {
		if got := client(t, script, mode, flagClient, port+1, 2); got != "replies=0" {
			t.Errorf("%s answered with INVALID dropped: %s", mode, got)
		}
	}
	if got := client(t, script, "session", flagClient, port, 0); got != "echo=ping-cdnca eof=True" {
		t.Fatalf("normal session with INVALID dropped: %s", got)
	}
	if counts := dropCounts(t, manager); counts[DropInvalid] < 6 || len(counts) != 1 {
		t.Fatalf("invalid only: %v", counts)
	}
	if err := manager.Apply(t.Context(), kernelFlagSpec(t, edgeconfig.DDoSProtection{AllowNetworks: []string{},
		MaxConnectionsPerIP: 100}, port)); err != nil {
		t.Fatal(err)
	}
	listing, _ := runner.Run(t.Context(), "list", "table", TableFamily, TableName)
	if strings.Contains(string(listing), "drop_") || strings.Contains(string(listing), "ct state invalid") {
		t.Fatalf("filters left behind:\n%s", listing)
	}
	if got := client(t, script, "null", flagClient, port+1, 1); got != "replies=1" {
		t.Fatalf("NULL after removal: %s", got)
	}
}

// With the XDP filter in front (generic, on the veth) malformed packets and
// banned clients drop at the NIC and never reach the table's counters; after
// a fallback the table drops them itself: no gap.
func TestKernelXDPFrontDropsFirstAndFallbackLeavesNoGap(t *testing.T) {
	manager, _ := kernelManager(t)
	script := setupFlagNamespace(t)
	front := xdp.Probe(xdp.Options{Interfaces: []string{"ddosf0"}, Modes: []xdp.Mode{xdp.ModeGeneric}})
	defer front.Close()
	if !front.Running() {
		t.Skipf("XDP not available here: %+v", front.Status())
	}
	manager.SetFront(front)
	port := echoServer(t)
	closed := port + 1
	if err := manager.Apply(t.Context(), kernelFlagSpec(t, flagProtection(true, edgeconfig.DDoSDefaultTCPFlagTypes, true), port)); err != nil {
		t.Fatal(err)
	}
	xdpCounts := func() map[string]uint64 {
		counters, err := front.Counters()
		if err != nil {
			t.Fatal(err)
		}
		result := map[string]uint64{}
		for _, counter := range counters {
			result[counter.Kind] = counter.Packets
		}
		return result
	}
	if got := client(t, script, "null", flagClient, closed, 3); got != "replies=0" {
		t.Fatalf("NULL answered with XDP in front: %s", got)
	}
	if xdpCounts()[DropTCPNull] != 3 || dropCounts(t, manager)[DropTCPNull] != 0 {
		t.Fatalf("NULL counted xdp %v nft %v", xdpCounts(), dropCounts(t, manager))
	}
	if got := client(t, script, "session", flagClient, port, 0); got != "echo=ping-cdnca eof=True" {
		t.Fatalf("normal session with XDP in front: %s", got)
	}
	// A ban through the DDoS manager lands in both; XDP drops it first.
	if banned, err := manager.Ban(t.Context(), []netip.Addr{netip.MustParseAddr(flagClient)}, time.Minute); err != nil || banned != 1 {
		t.Fatalf("ban = %d, %v", banned, err)
	}
	if got := client(t, script, "syn", flagClient, port, 2); got != "replies=0" {
		t.Fatalf("banned client answered: %s", got)
	}
	if xdpCounts()[xdp.DropBan] != 2 {
		t.Fatalf("xdp ban counters %v", xdpCounts())
	}
	if _, err := exec.Command("nft", "flush", "set", TableFamily, TableName, BanSetIPv4).CombinedOutput(); err != nil {
		t.Fatal(err)
	}
	front.Fallback(xdp.ReasonVerifyFailed, nil)
	if front.Running() || front.Status().Mode != xdp.ModeNFTables {
		t.Fatalf("after fallback %+v", front.Status())
	}
	if got := client(t, script, "null", flagClient, closed, 3); got != "replies=0" {
		t.Fatalf("NULL answered after fallback: %s", got)
	}
	if dropCounts(t, manager)[DropTCPNull] != 3 {
		t.Fatalf("nft did not take over: %v", dropCounts(t, manager))
	}
	t.Logf("fallback: %+v, nft %v", front.Status(), dropCounts(t, manager))
}
