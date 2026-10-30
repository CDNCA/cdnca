//go:build linux

package xdp

import (
	"errors"
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

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// Real kernel tests (scripts/edge-xdp-smoke.sh: a privileged disposable
// debian:12 container, never the host). The program is attached in generic
// mode to the server end of a veth pair; scapy in a network namespace on the
// other end crafts the traffic.
//
//	CDNCA_XDP_KERNEL_TEST=1 go test -run Kernel ./internal/xdp/
//
// CDNCA_XDP_EXPECT=nftables runs only the fallback check (the container
// refuses bpf(2) by seccomp: a node without BPF).
const (
	kernelNamespace = "xdptest"
	kernelHostLink  = "xdpx0"
	kernelPeerLink  = "xdpx1"
	serverV4        = "10.79.0.1"
	flagsClient     = "10.79.0.2"
	banClient       = "10.79.0.3"
	rateClient      = "10.79.0.4"
	blockClient     = "10.79.0.5"
	portBanClient   = "10.79.0.6"
	exemptClient    = "10.79.0.7"
	serverV6        = "fd79::1"
	clientV6        = "fd79::2"
)

const scapyClient = `
import socket, sys
from scapy.all import IP, IPv6, TCP, UDP, ICMP, RandShort, conf, sr
conf.verb = 0
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
mode, src, dst, port, count = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5])
if mode == "session":
    family = socket.AF_INET6 if ":" in dst else socket.AF_INET
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(3)
    s.bind((src, 0))
    try:
        s.connect((dst, port))
        s.sendall(b"ping-cdnca")
        print("echo=%s" % s.recv(64).decode())
    except OSError as error:
        print("error=%s" % type(error).__name__)
    s.close()
    sys.exit(0)
ip = IPv6(src=src, dst=dst) if ":" in dst else IP(src=src, dst=dst)
if mode == "ping":
    packets = [ip/ICMP(id=i) for i in range(count)]
elif mode == "udp":
    packets = [ip/UDP(sport=40000+i, dport=port) for i in range(count)]
else:
    flags = {"null": "", "xmas": "FPU", "syn_fin": "SF", "syn_rst": "SR", "all": "FSRPAU", "syn": "S"}[mode]
    packets = [ip/TCP(sport=20000+i, dport=port, flags=flags, seq=1000) for i in range(count)]
answered, _ = sr(packets, timeout=1, inter=0)
print("replies=%d" % len(answered))
`

func kernelTest(t *testing.T) {
	t.Helper()
	if os.Getenv("CDNCA_XDP_KERNEL_TEST") != "1" {
		t.Skip("CDNCA_XDP_KERNEL_TEST is not set (privileged disposable container only)")
	}
}

func sh(t *testing.T, command ...string) string {
	t.Helper()
	output, err := exec.Command(command[0], command[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %v %s", command, err, output)
	}
	return strings.TrimSpace(string(output))
}

// setupVeth: the server end in the root namespace, every client address on
// the namespace end. Returns the scapy script.
func setupVeth(t *testing.T) string {
	t.Helper()
	remove := func() {
		_ = exec.Command("ip", "netns", "del", kernelNamespace).Run()
		_ = exec.Command("ip", "link", "del", kernelHostLink).Run()
	}
	remove()
	t.Cleanup(remove)
	sh(t, "ip", "netns", "add", kernelNamespace)
	sh(t, "ip", "link", "add", kernelHostLink, "type", "veth", "peer", "name", kernelPeerLink)
	sh(t, "ip", "link", "set", kernelPeerLink, "netns", kernelNamespace)
	sh(t, "ip", "addr", "add", serverV4+"/24", "dev", kernelHostLink)
	sh(t, "ip", "-6", "addr", "add", serverV6+"/64", "dev", kernelHostLink, "nodad")
	sh(t, "ip", "link", "set", kernelHostLink, "up")
	inside := func(command ...string) {
		sh(t, append([]string{"ip", "netns", "exec", kernelNamespace}, command...)...)
	}
	for _, address := range []string{flagsClient, banClient, rateClient, blockClient, portBanClient, exemptClient} {
		inside("ip", "addr", "add", address+"/24", "dev", kernelPeerLink)
	}
	inside("ip", "-6", "addr", "add", clientV6+"/64", "dev", kernelPeerLink, "nodad")
	inside("ip", "link", "set", kernelPeerLink, "up")
	inside("ip", "link", "set", "lo", "up")
	script := filepath.Join(t.TempDir(), "client.py")
	if err := os.WriteFile(script, []byte(scapyClient), 0o600); err != nil {
		t.Fatal(err)
	}
	return script
}

func echo(t *testing.T, network, address string) uint16 {
	t.Helper()
	listener, err := net.Listen(network, net.JoinHostPort(address, "0"))
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
			go func() { defer connection.Close(); _, _ = io.Copy(connection, connection) }()
		}
	}()
	return uint16(listener.Addr().(*net.TCPAddr).Port)
}

func scapy(t *testing.T, script, mode, source, destination string, port uint16, count int) string {
	t.Helper()
	return sh(t, "ip", "netns", "exec", kernelNamespace, "python3", script, mode, source, destination,
		strconv.Itoa(int(port)), strconv.Itoa(count))
}

func replies(t *testing.T, output string) int {
	t.Helper()
	// scapy may warn first (IPv6 neighbour discovery); the result is last.
	lines := strings.Split(output, "\n")
	count, err := strconv.Atoi(strings.TrimPrefix(lines[len(lines)-1], "replies="))
	if err != nil {
		t.Fatalf("scapy output %q", output)
	}
	return count
}

func counts(t *testing.T, manager *Manager) map[string]uint64 {
	t.Helper()
	counters, err := manager.Counters()
	if err != nil {
		t.Fatal(err)
	}
	result := map[string]uint64{}
	for _, counter := range counters {
		result[counter.Kind] = counter.Packets
	}
	return result
}

func probeGeneric(t *testing.T) *Manager {
	t.Helper()
	manager := Probe(Options{Interfaces: []string{kernelHostLink}, Modes: []Mode{ModeGeneric}})
	t.Cleanup(manager.Close)
	status := manager.Status()
	if status.Mode != ModeGeneric || len(status.Interfaces) != 1 || status.Interfaces[0] != kernelHostLink+"=generic" {
		t.Fatalf("probe = %+v", status)
	}
	t.Logf("probe: %+v", status)
	return manager
}

// The program enforces every class it owns on real traffic, counts each
// under its own counter, and leaves normal traffic alone.
func TestKernelGenericXDPEnforcesAndCounts(t *testing.T) {
	kernelTest(t)
	if os.Getenv("CDNCA_XDP_EXPECT") == "nftables" {
		t.Skip("fallback run")
	}
	script := setupVeth(t)
	port := echo(t, "tcp4", serverV4)
	closed := port + 1
	port6 := echo(t, "tcp6", serverV6)
	manager := probeGeneric(t)
	// Baseline with the zero config: probes of a closed port are answered.
	for _, mode := range []string{"null", "xmas", "syn_fin"} {
		if got := replies(t, scapy(t, script, mode, flagsClient, serverV4, closed, 2)); got != 2 {
			t.Fatalf("baseline %s: %d replies", mode, got)
		}
	}
	protection := edgeconfig.DDoSProtection{TCPFlagFilter: true, TCPFlagTypes: edgeconfig.DDoSTCPFlagTypes,
		NewConnectionsPerSecond: 5, RateBanSeconds: 30}
	config := ConfigOf(protection, []PortRange{{port, port + 1}, {port6, port6}},
		[]netip.Prefix{netip.MustParsePrefix(exemptClient + "/32")})
	if err := manager.Configure(config); err != nil {
		t.Fatal(err)
	}
	if err := manager.Verify(); err != nil {
		t.Fatal(err)
	}

	t.Run("normal traffic passes", func(t *testing.T) {
		before := counts(t, manager)
		for range 3 {
			if got := scapy(t, script, "session", flagsClient, serverV4, port, 0); got != "echo=ping-cdnca" {
				t.Fatalf("v4 session: %s", got)
			}
		}
		if got := scapy(t, script, "session", clientV6, serverV6, port6, 0); got != "echo=ping-cdnca" {
			t.Fatalf("v6 session: %s", got)
		}
		if got := replies(t, scapy(t, script, "ping", flagsClient, serverV4, 0, 3)); got != 3 {
			t.Fatalf("ping: %d", got)
		}
		if after := counts(t, manager); len(after) != len(before) {
			t.Fatalf("normal traffic counted: %v -> %v", before, after)
		}
	})

	t.Run("malformed flags", func(t *testing.T) {
		const sent = 3
		for _, test := range []struct{ mode, kind string }{
			{"null", "tcp_null"}, {"xmas", "tcp_xmas"}, {"syn_fin", "tcp_syn_fin"}, {"syn_rst", "tcp_syn_rst"}, {"all", "tcp_all"},
		} {
			before := counts(t, manager)
			if got := replies(t, scapy(t, script, test.mode, flagsClient, serverV4, closed, sent)); got != 0 {
				t.Errorf("%s answered: %d", test.mode, got)
			}
			after := counts(t, manager)
			if after[test.kind]-before[test.kind] != sent {
				t.Errorf("%s: %d -> %d", test.kind, before[test.kind], after[test.kind])
			}
			t.Logf("%s: %d -> %d", test.kind, before[test.kind], after[test.kind])
		}
		// The allow list is exempt.
		if got := replies(t, scapy(t, script, "syn_fin", exemptClient, serverV4, closed, 2)); got != 2 {
			t.Errorf("exempt client filtered: %d", got)
		}
		// An unprotected port is not filtered.
		if got := replies(t, scapy(t, script, "null", flagsClient, serverV4, port+2, 1)); got != 1 {
			t.Errorf("unprotected port filtered: %d", got)
		}
	})

	t.Run("ban on protected ports", func(t *testing.T) {
		if err := manager.Ban([]netip.Addr{netip.MustParseAddr(banClient), netip.MustParseAddr(clientV6)}, time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		before := counts(t, manager)["xdp_ban"]
		if got := replies(t, scapy(t, script, "syn", banClient, serverV4, port, 3)); got != 0 {
			t.Errorf("banned v4 client answered: %d", got)
		}
		if got := replies(t, scapy(t, script, "syn", clientV6, serverV6, port6, 2)); got != 0 {
			t.Errorf("banned v6 client answered: %d", got)
		}
		// A ban is the protected ports only (like the nft ban sets).
		if got := replies(t, scapy(t, script, "ping", banClient, serverV4, 0, 1)); got != 1 {
			t.Errorf("banned client lost ping: %d", got)
		}
		if after := counts(t, manager)["xdp_ban"]; after-before != 5 {
			t.Errorf("xdp_ban %d -> %d", before, after)
		}
	})

	t.Run("per client SYN rate", func(t *testing.T) {
		before := counts(t, manager)["xdp_rate"]
		got := replies(t, scapy(t, script, "syn", rateClient, serverV4, port, 30))
		if got > 6 || got < 4 {
			t.Errorf("30 SYNs at rate 5: %d answered", got)
		}
		// Over the rate the client is banned for RateBanSeconds.
		time.Sleep(1100 * time.Millisecond)
		if got := replies(t, scapy(t, script, "syn", rateClient, serverV4, port, 2)); got != 0 {
			t.Errorf("rate banned client answered: %d", got)
		}
		after := counts(t, manager)["xdp_rate"]
		if after-before < 26 {
			t.Errorf("xdp_rate %d -> %d", before, after)
		}
		t.Logf("rate: answered %d, xdp_rate %d -> %d", got, before, after)
		// Another client keeps its own budget.
		if got := scapy(t, script, "session", flagsClient, serverV4, port, 0); got != "echo=ping-cdnca" {
			t.Fatalf("other client: %s", got)
		}
	})

	t.Run("port ban", func(t *testing.T) {
		if err := manager.BanPorts([]netip.Addr{netip.MustParseAddr(portBanClient)}, []uint16{port}, time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if got := replies(t, scapy(t, script, "syn", portBanClient, serverV4, port, 2)); got != 0 {
			t.Errorf("port banned client answered on its port: %d", got)
		}
		if got := replies(t, scapy(t, script, "syn", portBanClient, serverV4, closed, 1)); got != 1 {
			t.Errorf("port ban reached another port: %d", got)
		}
		if counts(t, manager)["xdp_port_ban"] != 2 {
			t.Errorf("xdp_port_ban = %d", counts(t, manager)["xdp_port_ban"])
		}
		// Card 5: a narrowed kernel ban withdraws the port ban.
		if err := manager.UnbanPorts(netip.MustParseAddr(portBanClient), []uint16{port, closed}); err != nil {
			t.Fatal(err)
		}
		if got := replies(t, scapy(t, script, "syn", portBanClient, serverV4, port, 1)); got != 1 {
			t.Errorf("withdrawn port ban still drops: %d", got)
		}
	})

	t.Run("L5 block drops everything, TTL and unblock", func(t *testing.T) {
		block := netip.MustParsePrefix(blockClient + "/32")
		// Each scapy run takes seconds: the TTL must outlast the three probes below.
		const ttl = 10 * time.Second
		blockedAt := time.Now()
		if err := manager.Block([]Block{{Prefix: block, TTL: ttl}}); err != nil {
			t.Fatal(err)
		}
		before := counts(t, manager)["xdp_block"]
		if got := replies(t, scapy(t, script, "ping", blockClient, serverV4, 0, 2)); got != 0 {
			t.Errorf("blocked ping answered: %d", got)
		}
		if got := replies(t, scapy(t, script, "syn", blockClient, serverV4, port+2, 1)); got != 0 {
			t.Errorf("blocked SYN on an unprotected port answered: %d", got)
		}
		if after := counts(t, manager)["xdp_block"]; after-before != 3 {
			t.Errorf("xdp_block %d -> %d", before, after)
		}
		time.Sleep(time.Until(blockedAt.Add(ttl + 500*time.Millisecond)))
		if got := replies(t, scapy(t, script, "ping", blockClient, serverV4, 0, 1)); got != 1 {
			t.Errorf("expired block still drops: %d", got)
		}
		if removed, err := manager.Sweep(); err != nil || removed < 1 {
			t.Errorf("sweep removed %d, %v", removed, err)
		}
		if err := manager.Block([]Block{{Prefix: netip.MustParsePrefix("10.79.0.0/24"), TTL: time.Hour}}); err != nil {
			t.Fatal(err)
		}
		if got := replies(t, scapy(t, script, "ping", blockClient, serverV4, 0, 1)); got != 0 {
			t.Errorf("/24 block answered: %d", got)
		}
		// Exempt networks win over blocks.
		if got := replies(t, scapy(t, script, "ping", exemptClient, serverV4, 0, 1)); got != 1 {
			t.Errorf("exempt client blocked: %d", got)
		}
		if err := manager.Unblock([]netip.Prefix{netip.MustParsePrefix("10.79.0.0/24")}); err != nil {
			t.Fatal(err)
		}
		if got := replies(t, scapy(t, script, "ping", blockClient, serverV4, 0, 1)); got != 1 {
			t.Errorf("unblocked client dropped: %d", got)
		}
		if err := manager.Block([]Block{{Prefix: netip.MustParsePrefix("fd79::/64"), TTL: time.Hour}}); err != nil {
			t.Fatal(err)
		}
		if got := replies(t, scapy(t, script, "udp", clientV6, serverV6, 9, 2)); got != 0 {
			t.Errorf("blocked v6 UDP answered: %d", got)
		}
	})
	t.Logf("counters %v", counts(t, manager))

	t.Run("verify failure falls back", func(t *testing.T) {
		sh(t, "ip", "link", "del", kernelHostLink)
		if err := manager.Verify(); err == nil {
			t.Fatal("verify passed without the interface")
		}
		status := manager.Status()
		if status.Mode != ModeNFTables || status.Reason != ReasonVerifyFailed || status.Detail == "" || manager.Running() {
			t.Fatalf("after verify failure = %+v", status)
		}
		if err := manager.Block([]Block{{Prefix: netip.MustParsePrefix(blockClient + "/32"), TTL: time.Hour}}); err != ErrNotRunning {
			t.Fatalf("block after fallback: %v", err)
		}
		t.Logf("fell back: %+v", status)
	})
}

// A NIC without native XDP (a dummy) falls back to nftables when only
// native is allowed, and runs generic with the default order.
func TestKernelInterfaceWithoutNativeXDP(t *testing.T) {
	kernelTest(t)
	if os.Getenv("CDNCA_XDP_EXPECT") == "nftables" {
		t.Skip("fallback run")
	}
	_ = exec.Command("ip", "link", "del", "xdpdummy0").Run()
	sh(t, "ip", "link", "add", "xdpdummy0", "type", "dummy")
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", "xdpdummy0").Run() })
	sh(t, "ip", "link", "set", "xdpdummy0", "up")
	native := Probe(Options{Interfaces: []string{"xdpdummy0"}, Modes: []Mode{ModeNative}})
	defer native.Close()
	if status := native.Status(); status.Mode != ModeNFTables || status.Reason != ReasonAttachFailed {
		t.Fatalf("native only on a dummy = %+v", status)
	} else {
		t.Logf("native only: %+v", status)
	}
	auto := Probe(Options{Interfaces: []string{"xdpdummy0"}})
	defer auto.Close()
	if status := auto.Status(); status.Mode != ModeGeneric || status.Interfaces[0] != "xdpdummy0=generic" {
		t.Fatalf("default order on a dummy = %+v", status)
	} else {
		t.Logf("default order: %+v", status)
	}
}

// Without bpf(2) (CDNCA_XDP_EXPECT=nftables: seccomp refuses it) the probe
// reports nftables with the reason.
func TestKernelProbeWithoutBPFFallsBack(t *testing.T) {
	kernelTest(t)
	if os.Getenv("CDNCA_XDP_EXPECT") != "nftables" {
		t.Skip("needs a container that refuses bpf(2)")
	}
	manager := Probe(Options{})
	status := manager.Status()
	if status.Mode != ModeNFTables || status.Reason != ReasonBPFUnavailable || manager.Running() {
		t.Fatalf("probe without bpf = %+v", status)
	}
	t.Logf("probe without bpf: %+v", status)
}

// A run time fallback detaches; Reattach attaches again and replays the L5
// blocks that have not ended, including one written while on nftables, but
// not one unblocked meanwhile.
func TestKernelReattachAfterFallbackReplaysBlocks(t *testing.T) {
	kernelTest(t)
	if os.Getenv("CDNCA_XDP_EXPECT") == "nftables" {
		t.Skip("fallback run")
	}
	script := setupVeth(t)
	manager := probeGeneric(t)
	if err := manager.Reattach(); err != nil {
		t.Fatalf("reattach while running: %v", err)
	}
	block := func(address string) {
		t.Helper()
		if err := manager.Block([]Block{{Prefix: netip.MustParsePrefix(address + "/32"), TTL: time.Hour}}); err != nil {
			t.Fatal(err)
		}
	}
	ping := func(address string) int {
		t.Helper()
		return replies(t, scapy(t, script, "ping", address, serverV4, 0, 1))
	}
	block(blockClient)
	if got := ping(blockClient); got != 0 {
		t.Fatalf("blocked ping answered: %d", got)
	}
	manager.Fallback(ReasonVerifyFailed, nil)
	if manager.Running() || ping(blockClient) != 1 {
		t.Fatalf("after fallback the program still drops: %+v", manager.Status())
	}
	if err := manager.Block([]Block{{Prefix: netip.MustParsePrefix(banClient + "/32"), TTL: time.Hour}}); err != ErrNotRunning {
		t.Fatalf("block on nftables: %v", err)
	}
	block2 := netip.MustParsePrefix(portBanClient + "/32")
	if err := manager.Block([]Block{{Prefix: block2, TTL: time.Hour}}); err != ErrNotRunning {
		t.Fatal(err)
	}
	if err := manager.Unblock([]netip.Prefix{block2}); err != ErrNotRunning {
		t.Fatal(err)
	}
	if err := manager.Reattach(); err != nil {
		t.Fatalf("reattach: %v (%+v)", err, manager.Status())
	}
	status := manager.Status()
	if status.Mode != ModeGeneric || status.Reason != "" || len(status.Interfaces) != 1 {
		t.Fatalf("reattached status %+v", status)
	}
	if got := ping(blockClient); got != 0 {
		t.Errorf("block from before the fallback not replayed: %d", got)
	}
	if got := ping(banClient); got != 0 {
		t.Errorf("block written on nftables not replayed: %d", got)
	}
	if got := ping(portBanClient); got != 1 {
		t.Errorf("unblocked client replayed: %d", got)
	}
	if err := manager.Verify(); err != nil {
		t.Fatal(err)
	}
	// The interface is gone: the retry fails, the node stays on nftables
	// with the attach reason, and may be retried later.
	manager.Fallback(ReasonVerifyFailed, nil)
	sh(t, "ip", "link", "del", kernelHostLink)
	if err := manager.Reattach(); err == nil {
		t.Fatal("reattach without the interface")
	}
	if status := manager.Status(); status.Mode != ModeNFTables || status.Reason != ReasonAttachFailed || manager.Running() {
		t.Fatalf("failed reattach status %+v", status)
	}
	if err := manager.Reattach(); err == nil || errors.Is(err, ErrNoRetry) {
		t.Fatalf("second retry: %v", err)
	}
	manager.Close()
	if err := manager.Reattach(); !errors.Is(err, ErrNoRetry) {
		t.Fatalf("reattach after close: %v", err)
	}
	t.Logf("reattach: %+v", status)
}
