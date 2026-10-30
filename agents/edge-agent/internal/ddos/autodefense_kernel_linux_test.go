//go:build linux

package ddos

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// Real kernel test of the auto defense part (AD-06): group counters and per
// source sets count real packets, the override's per client limits drop and
// count, updates in place keep the counters, removal deletes every ad_
// object. scripts/edge-ddos-tcpflags-smoke.sh -test.run KernelAutoDefense.
func TestKernelAutoDefenseCountsLimitsAndRemoves(t *testing.T) {
	manager, _ := kernelManager(t)
	script := setupFlagNamespace(t)
	port := echoServer(t)
	other := echoServer(t)
	spec := spec(t, edgeconfig.DDoSProtection{TCPFlagFilter: true, TCPFlagTypes: []string{edgeconfig.DDoSTCPFlagNull},
		AllowNetworks: []string{flagExemptClient + "/32"}}, port)
	spec.Ports = MergePorts([]PortRange{{port, port}, {other, other}})
	if err := manager.Apply(t.Context(), spec); err != nil {
		t.Fatal(err)
	}
	group := AutoGroup{ID: "web", Protocol: "tcp", Ports: []PortRange{{port, port}}}
	udp := AutoGroup{ID: "dns", Protocol: "udp", Ports: []PortRange{{5353, 5353}}}
	if err := manager.SetAutoDefense(t.Context(), &AutoDefense{Groups: []AutoGroup{group, udp}}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if out := client(t, script, "session", flagClient, port, 1); !strings.Contains(out, "echo=ping-cdnca") {
			t.Fatalf("session %d: %s", i, out)
		}
	}
	client(t, script, "session", flagClient, other, 1) // another port: not the group's
	token := GroupToken("web")
	counters, err := manager.AutoCounters(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if n := counters[AutoCounterName(token, AutoNew)].Packets; n != 3 {
		t.Fatalf("new connections %d, want 3 (counters %v)", n, counters)
	}
	if n := counters[AutoCounterName(token, AutoSYN)].Packets; n != 3 {
		t.Fatalf("SYN %d, want 3", n)
	}
	var lengths uint64
	for i := range AutoLengthBounds {
		lengths += counters[AutoCounterName(token, AutoLength+string(rune('0'+i)))].Packets
	}
	if pkt := counters[AutoCounterName(token, AutoPackets)]; pkt.Packets < 9 || lengths != pkt.Packets || pkt.Bytes == 0 {
		t.Fatalf("packets %+v, length buckets sum %d (every packet in exactly one bucket)", pkt, lengths)
	}
	sources, err := manager.AutoSources(t.Context(), "web")
	if err != nil || len(sources) != 1 || sources[0].Client.String() != flagClient || sources[0].Packets != 3 {
		t.Fatalf("sources %+v %v", sources, err)
	}
	// Override: 2 new connections a minute per client (a minute: the bucket does not refill while scapy waits for
	// the dropped SYNs); the third SYN on is dropped and counted.
	group.NewPerMinute = 2
	if err := manager.SetAutoDefense(t.Context(), &AutoDefense{Groups: []AutoGroup{group}, Invalid: true}); err != nil {
		t.Fatal(err)
	}
	if out := client(t, script, "syn", flagClient, port, 8); !strings.Contains(out, "replies=2") {
		t.Fatalf("limited burst: %s, want 2 (burst) answered", out)
	}
	counters, _ = manager.AutoCounters(t.Context())
	if counters[AutoCounterName(token, AutoDrops)].Packets < 5 {
		t.Fatalf("override drops %v", counters[AutoCounterName(token, AutoDrops)])
	}
	if counters[AutoCounterName(token, AutoNew)].Packets < 3+8 {
		t.Fatal("an in-place update reset the group counters")
	}
	if !strings.Contains(run(t, "nft", "list", "table", TableFamily, TableName), "ct state invalid") {
		t.Fatal("the override's INVALID drop is not in the table")
	}
	if out := client(t, script, "syn", flagExemptClient, port, 6); !strings.Contains(out, "replies=6") {
		t.Fatalf("exempt client limited by the override: %s", out)
	}
	// Kernel ban of a source (L4): Ban writes the shared ban set the guard chain drops.
	if banned, err := manager.Ban(t.Context(), []netip.Addr{netip.MustParseAddr(flagClient)}, time.Minute); err != nil || banned != 1 {
		t.Fatalf("ban %d %v", banned, err)
	}
	if out := client(t, script, "syn", flagClient, other, 2); !strings.Contains(out, "replies=0") {
		t.Fatalf("banned source answered: %s", out)
	}
	// Removing the part deletes every ad_ chain, set and counter; the platform table stays.
	if err := manager.SetAutoDefense(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	listing := run(t, "nft", "list", "table", TableFamily, TableName)
	if strings.Contains(listing, " ad_") || strings.Contains(listing, "@ad_") {
		t.Fatalf("auto defense objects left:\n%s", listing)
	}
	if !strings.Contains(listing, "drop_tcp_null") || !strings.Contains(listing, BanSetIPv4) {
		t.Fatal("platform objects lost with the auto defense part")
	}
}
