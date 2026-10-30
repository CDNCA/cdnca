package ddos

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

type fakeSockets struct {
	sockets   []EmptySocket
	destroyed []EmptySocket
	idle      time.Duration
}

func (source *fakeSockets) EmptySockets(_ context.Context, _ []PortRange, idle time.Duration) ([]EmptySocket, error) {
	source.idle = idle
	return source.sockets, nil
}

func (source *fakeSockets) Destroy(_ context.Context, sockets []EmptySocket) error {
	source.destroyed = append(source.destroyed, sockets...)
	return nil
}

func emptySocketOf(client string, cookie uint64) EmptySocket {
	address := netip.MustParseAddr(client)
	return EmptySocket{Client: address, Cookie: cookie, Local: netip.MustParseAddrPort("10.0.0.1:443"),
		Remote: netip.AddrPortFrom(address, uint16(40000+cookie)), Idle: 15 * time.Second}
}

func TestEmptyConnectionsBansAClientOverTheThresholdOnce(t *testing.T) {
	runner := &fakeRunner{}
	manager, _ := NewManager(t.Context(), runner, t.TempDir())
	value, err := edgeconfig.NewSiteRuntimeDDoS(edgeconfig.DDoSProtection{
		EmptyConnection: &edgeconfig.DDoSEmptyConnection{IdleSeconds: 10, Threshold: 3, WindowSeconds: 60, BanSeconds: 900},
		AllowNetworks:   []string{"192.0.2.0/24"}, CCKernelBan: edgeconfig.CCKernelBanOff}, []string{})
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := NewSpec(&value, []PortRange{{443, 443}})
	if err := manager.Apply(t.Context(), spec); err != nil {
		t.Fatal(err)
	}
	clock := time.Unix(1_800_000_000, 0)
	source := &fakeSockets{}
	detector := NewEmptyConnections(manager, source, func() time.Time { return clock })
	var bans []string
	detector.OnBan = func(client netip.Addr, count int, ban time.Duration) {
		bans = append(bans, client.String())
		if count != 3 || ban != 15*time.Minute {
			t.Errorf("ban of %s: count %d for %v", client, count, ban)
		}
	}
	// Two empty connections, seen twice: counted once each.
	source.sockets = []EmptySocket{emptySocketOf("198.51.100.7", 1), emptySocketOf("198.51.100.7", 2), emptySocketOf("192.0.2.9", 3),
		emptySocketOf("2001:db8:1::1", 4), emptySocketOf("2001:db8:1::2", 5)}
	for range 2 {
		if err := detector.Step(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if source.idle != 10*time.Second || len(bans) != 0 {
		t.Fatalf("idle %v, bans %v", source.idle, bans)
	}
	// A third: banned, its empty connections closed. The /64 neighbours
	// together reach the threshold too.
	clock = clock.Add(5 * time.Second)
	source.sockets = append(source.sockets, emptySocketOf("198.51.100.7", 6), emptySocketOf("2001:db8:1::3", 7))
	if err := detector.Step(t.Context()); err != nil {
		t.Fatal(err)
	}
	if strings.Join(bans, ",") != "198.51.100.7,2001:db8:1::" {
		t.Fatalf("bans = %v", bans)
	}
	if len(source.destroyed) != 6 {
		t.Fatalf("destroyed %d sockets: %+v", len(source.destroyed), source.destroyed)
	}
	last := runner.batches[len(runner.batches)-1]
	if !strings.Contains(last, "ban_v4 { 198.51.100.7 timeout 900s }") || !strings.Contains(last, "ban_v6 { 2001:db8:1:: timeout 900s }") || strings.Contains(last, "192.0.2.9") {
		t.Fatalf("ban batch:\n%s", last)
	}
	// Outside the window the count starts over.
	clock = clock.Add(2 * time.Minute)
	source.sockets = []EmptySocket{emptySocketOf("203.0.113.5", 8)}
	if err := detector.Step(t.Context()); err != nil || len(detector.windows) != 1 {
		t.Fatalf("windows = %v, %v", detector.windows, err)
	}
}
