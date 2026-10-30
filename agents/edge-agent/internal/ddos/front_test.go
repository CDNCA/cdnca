package ddos

import (
	"net/netip"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/xdp"
	"github.com/cdnca/cdnca/libs/edgeconfig"
)

type fakeFront struct {
	running bool
	configs []xdp.Config
	bans    []netip.Addr
	unbans  []netip.Addr
}

func (front *fakeFront) Unban(clients []netip.Addr) error {
	front.unbans = append(front.unbans, clients...)
	return nil
}

func (front *fakeFront) Running() bool { return front.running }
func (front *fakeFront) Configure(config xdp.Config) error {
	front.configs = append(front.configs, config)
	return nil
}
func (front *fakeFront) Ban(clients []netip.Addr, until time.Time) error {
	front.bans = append(front.bans, clients...)
	return nil
}

// The XDP front follows every Apply (the zero config on removal) and
// every ban; a front that is not running is left alone.
func TestManagerMirrorsTheSpecAndBansToTheXDPFront(t *testing.T) {
	runner := &fakeRunner{}
	manager, err := NewManager(t.Context(), runner, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	front := &fakeFront{running: true}
	manager.SetFront(front)
	if len(front.configs) != 1 || front.configs[0].Ports != nil {
		t.Fatalf("initial config %+v", front.configs)
	}
	value := testDDoS(t)
	value.Protection.TCPFlagFilter, value.Protection.TCPFlagTypes = true, []string{edgeconfig.DDoSTCPFlagNull}
	spec, _ := NewSpec(value, []PortRange{{80, 80}, {443, 443}})
	if err := manager.Apply(t.Context(), spec); err != nil {
		t.Fatal(err)
	}
	config := front.configs[len(front.configs)-1]
	if len(config.Ports) != 2 || config.Ports[1] != (xdp.PortRange{First: 443, Last: 443}) || config.SYNRate != 50 ||
		config.SYNBan != 600*time.Second || config.TCPFlags != xdp.FlagNull || len(config.Exempt) != len(spec.Exempt) {
		t.Fatalf("front config %+v", config)
	}
	if _, err := manager.Ban(t.Context(), []netip.Addr{netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("192.0.2.5"),
		netip.MustParseAddr("2001:db8:5::2")}, time.Minute); err != nil {
		t.Fatal(err)
	}
	if len(front.bans) != 2 || front.bans[0] != netip.MustParseAddr("198.51.100.1") || front.bans[1] != netip.MustParseAddr("2001:db8:5::") {
		t.Fatalf("front bans %v", front.bans)
	}
	if err := manager.Apply(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if last := front.configs[len(front.configs)-1]; last.Ports != nil || last.SYNRate != 0 {
		t.Fatalf("config after removal %+v", last)
	}
	stopped := &fakeFront{}
	manager.SetFront(stopped)
	if err := manager.Apply(t.Context(), spec); err != nil || len(stopped.configs) != 0 {
		t.Fatalf("stopped front configured: %v", stopped.configs)
	}
}
