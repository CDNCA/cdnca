package edgeconfig

import (
	"slices"
	"testing"
)

func validDDoS() DDoSProtection {
	return DDoSProtection{MaxConnectionsPerIP: 200, NewConnectionsPerSecond: 50, NewConnectionsPerMinute: 600,
		RateBanSeconds: 600, MaxConnectionsPerPort: 100000,
		EmptyConnection: &DDoSEmptyConnection{IdleSeconds: 10, Threshold: 20, WindowSeconds: 60, BanSeconds: 1800},
		AllowNetworks:   []string{"192.0.2.9", "2001:db8::1/48", "192.0.2.0/24", "192.0.2.0/24"}, CCKernelBan: CCKernelBanExclusivePorts}
}

func TestNormalizeDDoSProtectionCanonicalizesAllowNetworks(t *testing.T) {
	normalized, err := NormalizeDDoSProtection(validDDoS())
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"192.0.2.0/24", "192.0.2.9/32", "2001:db8::/48"}; !slices.Equal(normalized.AllowNetworks, want) {
		t.Fatalf("allow networks = %v, want %v", normalized.AllowNetworks, want)
	}
	if normalized.Validate() != nil {
		t.Fatal("normalized value must validate")
	}
	if validDDoS().Validate() == nil {
		t.Fatal("non-canonical value must not validate")
	}
	if !normalized.Enabled() || (DDoSProtection{AllowNetworks: []string{}, CCKernelBan: CCKernelBanOff}).Enabled() {
		t.Fatal("Enabled reports any limit")
	}
}

func TestNormalizeDDoSProtectionRejectsOutOfBounds(t *testing.T) {
	for name, mutate := range map[string]func(*DDoSProtection){
		"ban without rate":    func(value *DDoSProtection) { value.NewConnectionsPerSecond, value.NewConnectionsPerMinute = 0, 0 },
		"ban too long":        func(value *DDoSProtection) { value.RateBanSeconds = DDoSMaxBanSeconds + 1 },
		"per ip too high":     func(value *DDoSProtection) { value.MaxConnectionsPerIP = DDoSMaxConnectionsPerIPLimit + 1 },
		"empty idle too low":  func(value *DDoSProtection) { value.EmptyConnection.IdleSeconds = 1 },
		"empty no ban":        func(value *DDoSProtection) { value.EmptyConnection.BanSeconds = 0 },
		"bad network":         func(value *DDoSProtection) { value.AllowNetworks = []string{"example.com"} },
		"zone":                func(value *DDoSProtection) { value.AllowNetworks = []string{"fe80::1%eth0"} },
		"mapped":              func(value *DDoSProtection) { value.AllowNetworks = []string{"::ffff:192.0.2.1"} },
		"nil networks":        func(value *DDoSProtection) { value.AllowNetworks = nil },
		"unknown cc ban mode": func(value *DDoSProtection) { value.CCKernelBan = "global" },
	} {
		value := validDDoS()
		empty := *value.EmptyConnection
		value.EmptyConnection = &empty
		mutate(&value)
		if _, err := NormalizeDDoSProtection(value); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestSiteRuntimeSystemCarriesCanonicalDDoS(t *testing.T) {
	system := testSystem(t, 2, "b")
	ddos, err := NewSiteRuntimeDDoS(validDDoS(), []string{"203.0.113.2", "198.51.100.1", "203.0.113.2"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ddos.NodeNetworks, []string{"198.51.100.1/32", "203.0.113.2/32"}) {
		t.Fatalf("node networks = %v", ddos.NodeNetworks)
	}
	system.DDoS = &ddos
	if system.Validate() != nil {
		t.Fatal("system with DDoS rejected")
	}
	off := ddos
	off.Protection = DDoSProtection{AllowNetworks: []string{}, CCKernelBan: CCKernelBanOff}
	system.DDoS = &off
	// every limit off still carries the node networks: an L2 node tells an
	// L1's hop from a visitor by them (fix-l2trust)
	if system.Validate() != nil {
		t.Fatal("a DDoS block with every limit off (node networks only) rejected")
	}
}

func TestDDoSTCPFlagFilterNormalizesAndDefaultsSafely(t *testing.T) {
	defaults := DefaultDDoSProtection()
	if defaults.Validate() != nil || !defaults.Enabled() || !defaults.DropInvalid ||
		!slices.Equal(defaults.TCPFlagTypes, []string{"null", "xmas", "syn_fin", "syn_rst"}) ||
		defaults.FiltersTCPFlag(DDoSTCPFlagFin) || defaults.FiltersTCPFlag(DDoSTCPFlagAll) {
		t.Fatalf("defaults = %+v", defaults)
	}
	value := DDoSProtection{AllowNetworks: []string{}, CCKernelBan: CCKernelBanOff, TCPFlagFilter: true,
		TCPFlagTypes: []string{"all", "syn_rst", "null", "all"}}
	normalized, err := NormalizeDDoSProtection(value)
	if err != nil || !slices.Equal(normalized.TCPFlagTypes, []string{"null", "syn_rst", "all"}) || value.Validate() == nil || normalized.Validate() != nil {
		t.Fatalf("normalized = %+v, %v", normalized, err)
	}
	kept := DDoSProtection{AllowNetworks: []string{}, CCKernelBan: CCKernelBanOff, TCPFlagTypes: []string{"fin"}}
	if kept.Validate() != nil || kept.Enabled() || kept.FiltersTCPFlag(DDoSTCPFlagFin) {
		t.Fatal("types with the switch off must be valid and inert")
	}
	if !(DDoSProtection{AllowNetworks: []string{}, CCKernelBan: CCKernelBanOff, DropInvalid: true}).Enabled() {
		t.Fatal("drop_invalid alone installs the table")
	}
	for name, bad := range map[string]DDoSProtection{
		"switch without types": {AllowNetworks: []string{}, CCKernelBan: CCKernelBanOff, TCPFlagFilter: true},
		"unknown type":         {AllowNetworks: []string{}, CCKernelBan: CCKernelBanOff, TCPFlagTypes: []string{"ack"}},
	} {
		if _, err := NormalizeDDoSProtection(bad); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
