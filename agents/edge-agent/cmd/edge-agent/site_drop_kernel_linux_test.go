//go:build linux

package main

import (
	"context"
	"crypto/ed25519"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/ddos"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/xdp"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/edgeconfig/sitedrop"
)

// Real kernel case of the level D site drop (攻击自动升级 D 级, esc-node §3;
// scripts/edge-site-drop-smoke.sh, privileged disposable debian:12 container
// only): the Agent's siteDropRuntime with the real executor, XDP filter
// (generic, on a veth) and inet cdnca_ddos. scapy in a namespace on the
// other end sends SYNs and TLS ClientHellos (one segment, SNI).
//
//	CDNCA_XDP_KERNEL_TEST=1 go test -run KernelSiteDrop ./cmd/edge-agent/
//
// CDNCA_XDP_EXPECT=nftables (bpf(2) refused): the exclusive ports drop by
// nftables, the shared TLS port answers every name (receipt sni_unavailable).
const (
	siteDropNamespace = "sdtest"
	siteDropLink      = "sdx0"
	siteDropPeer      = "sdx1"
	siteDropServer    = "10.81.0.1"
	siteDropClient    = "10.81.0.2"
	siteDropServer6   = "fd81::1"
	siteDropClient6   = "fd81::2"
)

const siteDropScapy = `
import sys
from scapy.all import IP, IPv6, TCP, Raw, conf, sr1, send, RandShort
conf.verb = 0
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
mode, src, dst, port, name = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5]
ip = IPv6(src=src, dst=dst) if ":" in dst else IP(src=src, dst=dst)

def hello(server):
    sni = server.encode()
    entry = b"\x00" + len(sni).to_bytes(2, "big") + sni
    sni_list = len(entry).to_bytes(2, "big") + entry
    ext = b"\x00\x0a\x00\x04\x00\x02\x00\x1d"  # supported_groups first
    ext += b"\x00\x00" + len(sni_list).to_bytes(2, "big") + sni_list
    body = b"\x03\x03" + b"\x11" * 32 + b"\x20" + b"\x22" * 32
    body += b"\x00\x04\x13\x01\x13\x02" + b"\x01\x00"
    body += len(ext).to_bytes(2, "big") + ext
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake

sport = int(RandShort()) | 0x8000
syn = sr1(ip/TCP(sport=sport, dport=port, flags="S", seq=1000), timeout=1)
if syn is None or not syn.haslayer(TCP) or (syn[TCP].flags & 0x12) != 0x12:
    print("result=syn_dropped")
    sys.exit(0)
if mode == "syn":
    send(ip/TCP(sport=sport, dport=port, flags="R", seq=1001))
    print("result=open")
    sys.exit(0)
ack = syn[TCP].seq + 1
send(ip/TCP(sport=sport, dport=port, flags="A", seq=1001, ack=ack))
payload = hello(name)
reply = sr1(ip/TCP(sport=sport, dport=port, flags="PA", seq=1001, ack=ack)/Raw(payload), timeout=1)
# In window either way (hello acknowledged or not): the server closes.
send(ip/TCP(sport=sport, dport=port, flags="R", seq=1001))
send(ip/TCP(sport=sport, dport=port, flags="R", seq=1001 + len(payload)))
if reply is not None and reply.haslayer(TCP) and (reply[TCP].flags & 0x10) and reply[TCP].ack > 1001:
    print("result=answered")
else:
    print("result=hello_dropped")
`

func TestKernelSiteDropXDPAndNFTables(t *testing.T) {
	if os.Getenv("CDNCA_XDP_KERNEL_TEST") != "1" {
		t.Skip("CDNCA_XDP_KERNEL_TEST is not set (privileged disposable container only)")
	}
	expectNFT := os.Getenv("CDNCA_XDP_EXPECT") == "nftables"
	script := setupSiteDropVeth(t)
	// The ports: exclusive (D only), shared TLS (D + normal), a normal one.
	exclusive := siteDropEcho(t, "tcp4", siteDropServer)
	shared := siteDropEcho(t, "tcp4", siteDropServer)
	normal := siteDropEcho(t, "tcp4", siteDropServer)
	exclusive6 := siteDropEcho(t, "tcp6", siteDropServer6)
	// The kernel answers these itself (the scapy client is a raw socket in
	// the namespace: keep its kernel from resetting the handshakes).
	siteDropRun(t, "ip", "netns", "exec", siteDropNamespace, "iptables-nft", "-A", "OUTPUT", "-p", "tcp",
		"--tcp-flags", "RST", "RST", "-j", "DROP")
	siteDropRun(t, "ip", "netns", "exec", siteDropNamespace, "ip6tables-nft", "-A", "OUTPUT", "-p", "tcp",
		"--tcp-flags", "RST", "RST", "-j", "DROP")

	filter := xdp.Probe(xdp.Options{Interfaces: []string{siteDropLink}, Modes: []xdp.Mode{xdp.ModeGeneric}})
	t.Cleanup(filter.Close)
	if got := filter.Running(); got == expectNFT {
		t.Fatalf("XDP running = %v (expect nftables %v): %+v", got, expectNFT, filter.Status())
	}
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal(err)
	}
	runner, err := ddos.NewSystemRunner(nft)
	if err != nil {
		t.Fatal(err)
	}
	table, err := ddos.NewManager(t.Context(), runner, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = table.SetSiteDropPorts(context.Background(), nil) })
	hosts := &fakeSiteDropHosts{}

	tls := &edgesite.TLS{CertificateVersionID: "cert"}
	sites := []edgesite.Site{
		{SiteID: dropSiteA, TenantID: dropTestTenant,
			Hosts:     edgesite.Hosts{Primary: "a.example", Aliases: []string{"*.wild.example"}},
			Listeners: []edgesite.Listener{{Port: int(exclusive), TLS: tls}, {Port: int(exclusive6), TLS: tls}, {Port: int(shared), TLS: tls}}},
		// keep.wild.example is the normal site's exact name inside A's wildcard.
		{SiteID: dropSiteB, TenantID: dropTestTenant, Hosts: edgesite.Hosts{Primary: "b.example", Aliases: []string{"keep.wild.example"}},
			Listeners: []edgesite.Listener{{Port: int(shared), TLS: tls}, {Port: int(normal), TLS: tls}}},
	}
	public, private, _ := ed25519.GenerateKey(nil)
	now := time.Now()
	runtime := newSiteDropRuntime(dropTestNode, func(string) (ed25519.PublicKey, bool) { return public, true },
		func() ([]edgesite.Site, []ddos.PortRange) { return sites, nil }, filter.Running,
		kernelSiteDropExecutor{xdp: filter, nft: table, hosts: hosts}, time.Now)

	check := func(t *testing.T, mode, source, destination string, port uint16, name, want string) {
		t.Helper()
		output := siteDropRun(t, "ip", "netns", "exec", siteDropNamespace, "python3", script, mode, source, destination,
			strconv.Itoa(int(port)), name)
		lines := strings.Split(output, "\n")
		if got := strings.TrimPrefix(lines[len(lines)-1], "result="); got != want {
			t.Errorf("%s %s:%d %q = %s, want %s", mode, destination, port, name, got, want)
		}
	}
	baseline := func(t *testing.T) {
		check(t, "syn", siteDropClient, siteDropServer, exclusive, "", "open")
		check(t, "syn", siteDropClient6, siteDropServer6, exclusive6, "", "open")
		for _, name := range []string{"a.example", "x.wild.example", "b.example", "keep.wild.example"} {
			check(t, "hello", siteDropClient, siteDropServer, shared, name, "answered")
		}
		check(t, "hello", siteDropClient, siteDropServer, normal, "a.example", "answered")
	}
	t.Run("before", baseline)

	t.Run("drop", func(t *testing.T) {
		result := runtime.ApplySiteDrop(signedDropList(t, private, dropTestNode, 1, now, dropSite(dropSiteA, now, time.Hour)))
		if !result.Applied {
			t.Fatalf("apply = %+v", result)
		}
		t.Logf("receipt: %+v", result)
		if result.Ports != 2 || result.Sites != 1 {
			t.Errorf("receipt counts = %+v", result)
		}
		check(t, "syn", siteDropClient, siteDropServer, exclusive, "", "syn_dropped")
		check(t, "syn", siteDropClient6, siteDropServer6, exclusive6, "", "syn_dropped")
		check(t, "hello", siteDropClient, siteDropServer, normal, "a.example", "answered")
		check(t, "hello", siteDropClient, siteDropServer, shared, "b.example", "answered")
		check(t, "hello", siteDropClient, siteDropServer, shared, "keep.wild.example", "answered")
		if expectNFT {
			if result.Mode != siteDropModeNFTables || result.ServerNames != 0 || len(result.Rejected) != 1 ||
				result.Rejected[0].Reason != sitedrop.RejectSNIUnavailable || result.Rejected[0].Port != shared {
				t.Errorf("nftables receipt = %+v", result)
			}
			// Without XDP the shared port answers every name (OpenResty
			// closes the D names, §4).
			check(t, "hello", siteDropClient, siteDropServer, shared, "a.example", "answered")
		} else {
			if result.Mode != siteDropModeXDP || result.ServerNames != 2 || len(result.Rejected) != 0 {
				t.Errorf("xdp receipt = %+v", result)
			}
			check(t, "hello", siteDropClient, siteDropServer, shared, "a.example", "hello_dropped")
			check(t, "hello", siteDropClient, siteDropServer, shared, "A.Example", "hello_dropped")
			check(t, "hello", siteDropClient, siteDropServer, shared, "x.wild.example", "hello_dropped")
			check(t, "hello", siteDropClient, siteDropServer, shared, "deep.x.wild.example", "hello_dropped")
			// The wildcard does not cover its own apex.
			check(t, "hello", siteDropClient, siteDropServer, shared, "wild.example", "answered")
			counters, err := filter.SiteDropCounters()
			if err != nil || counters.Port.Packets == 0 || counters.SNI.Packets < 4 {
				t.Errorf("counters = %+v, %v", counters, err)
			}
			t.Logf("xdp counters: %+v", counters)
		}
		// nftables holds the exclusive ports in both modes.
		listing := siteDropRun(t, "nft", "list", "set", "inet", "cdnca_ddos", ddos.SiteDropSet)
		for _, port := range []uint16{exclusive, exclusive6} {
			if !strings.Contains(listing, strconv.Itoa(int(port))) {
				t.Errorf("nft set lacks %d:\n%s", port, listing)
			}
		}
		if len(hosts.pushed) == 0 {
			t.Error("hosts not pushed")
		}
	})

	if !expectNFT {
		// XDP falls back at run time: nftables still drops the exclusive
		// ports (no gap), the next refresh re-derives for nftables.
		t.Run("xdp fallback", func(t *testing.T) {
			filter.Fallback(xdp.ReasonVerifyFailed, nil)
			check(t, "syn", siteDropClient, siteDropServer, exclusive, "", "syn_dropped")
			runtime.refresh(t.Context())
			check(t, "syn", siteDropClient, siteDropServer, exclusive, "", "syn_dropped")
			check(t, "hello", siteDropClient, siteDropServer, shared, "a.example", "answered")
			if err := filter.Reattach(); err != nil {
				t.Fatal(err)
			}
			runtime.refresh(t.Context())
			check(t, "hello", siteDropClient, siteDropServer, shared, "a.example", "hello_dropped")
		})
	}

	t.Run("lift", func(t *testing.T) {
		result := runtime.ApplySiteDrop(signedDropList(t, private, dropTestNode, 2, now))
		if !result.Applied {
			t.Fatalf("lift = %+v", result)
		}
		baseline(t)
		if output, err := exec.Command("nft", "list", "table", "inet", "cdnca_ddos").CombinedOutput(); err == nil {
			t.Errorf("table left after lift:\n%s", output)
		}
		if hosts.clears == 0 {
			t.Error("hosts not cleared")
		}
	})
}

func siteDropRun(t *testing.T, command ...string) string {
	t.Helper()
	output, err := exec.Command(command[0], command[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %v %s", command, err, output)
	}
	return strings.TrimSpace(string(output))
}

func setupSiteDropVeth(t *testing.T) string {
	t.Helper()
	remove := func() {
		_ = exec.Command("ip", "netns", "del", siteDropNamespace).Run()
		_ = exec.Command("ip", "link", "del", siteDropLink).Run()
	}
	remove()
	t.Cleanup(remove)
	siteDropRun(t, "ip", "netns", "add", siteDropNamespace)
	siteDropRun(t, "ip", "link", "add", siteDropLink, "type", "veth", "peer", "name", siteDropPeer)
	siteDropRun(t, "ip", "link", "set", siteDropPeer, "netns", siteDropNamespace)
	siteDropRun(t, "ip", "addr", "add", siteDropServer+"/24", "dev", siteDropLink)
	siteDropRun(t, "ip", "-6", "addr", "add", siteDropServer6+"/64", "dev", siteDropLink, "nodad")
	siteDropRun(t, "ip", "link", "set", siteDropLink, "up")
	inside := func(command ...string) {
		siteDropRun(t, append([]string{"ip", "netns", "exec", siteDropNamespace}, command...)...)
	}
	inside("ip", "addr", "add", siteDropClient+"/24", "dev", siteDropPeer)
	inside("ip", "-6", "addr", "add", siteDropClient6+"/64", "dev", siteDropPeer, "nodad")
	inside("ip", "link", "set", siteDropPeer, "up")
	inside("ip", "link", "set", "lo", "up")
	script := filepath.Join(t.TempDir(), "client.py")
	if err := os.WriteFile(script, []byte(siteDropScapy), 0o600); err != nil {
		t.Fatal(err)
	}
	return script
}

// siteDropEcho accepts and echoes; a ClientHello is acknowledged by the
// kernel whatever the server does with it.
func siteDropEcho(t *testing.T, network, address string) uint16 {
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
			go func() { defer connection.Close(); _, _ = io.Copy(io.Discard, connection) }()
		}
	}()
	return uint16(listener.Addr().(*net.TCPAddr).Port)
}
