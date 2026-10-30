package ddos

import (
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

func autoSpec(t *testing.T) *Spec {
	t.Helper()
	spec, err := NewSpec(testDDoS(t), []PortRange{{80, 80}, {443, 443}, {10000, 10100}})
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

func TestAutoDefenseRendersGroupCountersAndLimits(t *testing.T) {
	spec := autoSpec(t)
	plain := spec.Digest()
	spec.Auto = &AutoDefense{Groups: []AutoGroup{
		{ID: "web", Protocol: "tcp", Ports: []PortRange{{80, 80}, {443, 443}}},
		{ID: "game", Protocol: "tcp", Ports: []PortRange{{10000, 10100}}, MaxConnsPerIP: 8, NewPerSecond: 20, CIDRPerSecond: 200},
		{ID: "dns", Protocol: "udp", Ports: []PortRange{{53, 53}}, NewPerSecond: 30},
	}}
	if spec.Digest() == plain {
		t.Fatal("the auto defense part does not change the digest")
	}
	batch := string(spec.Batch(nil, nil, nil))
	web, game, dns := GroupToken("web"), GroupToken("game"), GroupToken("dns")
	for _, want := range []string{
		"add counter inet cdnca_ddos ad_syn_" + web,
		"add counter inet cdnca_ddos ad_len7_" + game,
		"add chain inet cdnca_ddos ad_c_" + web,
		"add chain inet cdnca_ddos ad_l_" + game,
		"add set inet cdnca_ddos ad_s4_" + web + " { type ipv4_addr; flags dynamic,timeout; timeout 60s; size 8192; }",
		"add rule inet cdnca_ddos input meta l4proto tcp tcp dport vmap { 10000-10100 : jump ad_c_" + game + ", 80 : jump ad_c_" + web + ", 443 : jump ad_c_" + web + " }",
		"add rule inet cdnca_ddos input meta l4proto udp udp dport vmap { 53 : jump ad_c_" + dns + " }",
		"add rule inet cdnca_ddos ad_c_" + web + " tcp flags & (syn|ack) == syn counter name \"ad_syn_" + web + "\"",
		"add rule inet cdnca_ddos ad_c_" + web + " ct state new update @ad_s4_" + web + " { ip saddr counter }",
		"add rule inet cdnca_ddos ad_c_" + web + " meta length 1500-65535 counter name \"ad_len7_" + web + "\"",
		"add rule inet cdnca_ddos ad_l_" + game + " update @ad_rs_" + game + "_20_v4 { ip saddr limit rate over 20/second burst 20 packets } counter name \"ad_drop_" + game + "\" drop",
		"add rule inet cdnca_ddos ad_l_" + game + " update @ad_cr_" + game + "_200_v4 { ip saddr & 255.255.255.0 limit rate over 200/second burst 200 packets }",
		"add rule inet cdnca_ddos ad_l_" + game + " add @ad_cn_" + game + "_8_v6 { ip6 saddr & ffff:ffff:ffff:ffff:: ct count over 8 }",
		"add rule inet cdnca_ddos guard tcp dport vmap { 10000-10100 : jump ad_l_" + game + " }",
		// UDP limits: own chain (exempt, new flows only) dispatched from input; never from guard.
		"add rule inet cdnca_ddos ad_l_" + dns + " ip saddr @exempt_v4 return",
		"add rule inet cdnca_ddos ad_l_" + dns + " ct state != new return",
		"add rule inet cdnca_ddos ad_l_" + dns + " update @ad_rs_" + dns + "_30_v4 { ip saddr limit rate over 30/second burst 30 packets } counter name \"ad_drop_" + dns + "\" drop",
		"add rule inet cdnca_ddos input meta l4proto udp udp dport vmap { 53 : jump ad_l_" + dns + " }",
		// Group bans: per group sets dropped at the end of the group's counter chain.
		"add set inet cdnca_ddos ad_b4_" + web + " { type ipv4_addr; flags timeout; size 65536; }",
		"add rule inet cdnca_ddos ad_c_" + dns + " ip saddr @ad_b4_" + dns + " counter drop",
		"add rule inet cdnca_ddos ad_c_" + web + " ip6 saddr & ffff:ffff:ffff:ffff:: @ad_b6_" + web + " counter drop",
	} {
		if !strings.Contains(batch, want) {
			t.Errorf("batch lacks %q", want)
		}
	}
	if strings.Contains(batch, "ad_l_"+web) || strings.Contains(batch, "ad_syn_"+dns) {
		t.Error("a group without limits got a limit chain, or UDP a SYN counter")
	}
	// Order: the auto limits come after the bans and before the platform's own rate rules; the counter dispatch
	// before the guard jump.
	if !(strings.Index(batch, "guard ct state != new return") < strings.Index(batch, "guard tcp dport vmap") &&
		strings.Index(batch, "guard tcp dport vmap") < strings.Index(batch, "update @meter_rate_s_50_v4")) {
		t.Error("auto limits out of order in the guard chain")
	}
	if strings.Contains(batch, "guard udp dport") || strings.Contains(batch, "ad_l_"+dns+" add @ad_cn_") {
		t.Error("UDP dispatched from guard, or given a concurrency limit")
	}
	if !(strings.Index(batch, "udp dport vmap { 53 : jump ad_c_"+dns) < strings.Index(batch, "udp dport vmap { 53 : jump ad_l_"+dns)) {
		t.Error("UDP limits must come after the group counters")
	}
	if !(strings.Index(batch, "input meta l4proto udp udp dport vmap") < strings.Index(batch, "jump guard comment")) {
		t.Error("the counter dispatch must precede the guard jump")
	}
}

func TestAutoDefenseRemovesStaleChainsSetsAndCounters(t *testing.T) {
	spec := autoSpec(t)
	old := GroupToken("old")
	batch := string(spec.Batch([]string{"ad_s4_" + old, "ad_rs_" + old + "_5_v4", BanSetIPv4},
		[]string{"ad_pkt_" + old}, []string{"input", "guard", "ad_c_" + old, "ad_l_" + old}))
	for _, want := range []string{
		"flush chain inet cdnca_ddos ad_c_" + old, "delete chain inet cdnca_ddos ad_c_" + old,
		"delete chain inet cdnca_ddos ad_l_" + old, "delete set inet cdnca_ddos ad_s4_" + old,
		"delete set inet cdnca_ddos ad_rs_" + old + "_5_v4", "delete counter inet cdnca_ddos ad_pkt_" + old,
	} {
		if !strings.Contains(batch, want) {
			t.Errorf("batch lacks %q", want)
		}
	}
	if strings.Contains(batch, "delete chain inet cdnca_ddos guard") || strings.Contains(batch, "delete set inet cdnca_ddos ban_v4") {
		t.Error("deleted a platform object")
	}
	// Chain deletion must come after the flushes of input and guard (nothing references the chain any more).
	if strings.Index(batch, "delete chain inet cdnca_ddos ad_c_"+old) < strings.Index(batch, "flush chain inet cdnca_ddos guard") {
		t.Error("stale chain deleted while still referenced")
	}
}

func TestAutoDefenseOnlyTightensTheNodeSetting(t *testing.T) {
	spec := autoSpec(t)
	spec.Protection.TCPFlagFilter, spec.Protection.TCPFlagTypes = true, []string{edgeconfig.DDoSTCPFlagFin}
	spec.Protection.EmptyConnection = &edgeconfig.DDoSEmptyConnection{IdleSeconds: 30, Threshold: 5, WindowSeconds: 60, BanSeconds: 900}
	spec.Auto = &AutoDefense{Malformed: true, Invalid: true, IdleSeconds: 10}
	protection := spec.EffectiveProtection()
	if want := []string{"null", "xmas", "syn_fin", "syn_rst", "fin"}; strings.Join(protection.TCPFlagTypes, ",") != strings.Join(want, ",") {
		t.Fatalf("flag types %v, want %v (platform's fin kept, defaults added, canonical order)", protection.TCPFlagTypes, want)
	}
	if !protection.DropInvalid || protection.EmptyConnection.IdleSeconds != 10 || protection.EmptyConnection.Threshold != 5 {
		t.Fatalf("invalid/idle not tightened: %+v %+v", protection.DropInvalid, protection.EmptyConnection)
	}
	if spec.Protection.EmptyConnection.IdleSeconds != 30 {
		t.Fatal("the user's setting was modified")
	}
	spec.Auto.IdleSeconds = 60 // longer than the platform's: no relaxing
	if spec.EffectiveProtection().EmptyConnection.IdleSeconds != 30 {
		t.Fatal("the override relaxed the idle time")
	}
	spec.Protection.EmptyConnection = nil
	if empty := spec.EffectiveProtection().EmptyConnection; empty == nil || empty.IdleSeconds != 60 || empty.Threshold != AutoEmptyThreshold {
		t.Fatalf("no platform policy: the override turns one on, got %+v", empty)
	}
	if batch := string(spec.Batch(nil, nil, nil)); !strings.Contains(batch, "drop_tcp_null") || !strings.Contains(batch, "drop_ct_invalid") {
		t.Fatal("tightened filters not rendered")
	}
}

func TestManagerKeepsAutoDefenseAcrossApplyAndRestart(t *testing.T) {
	runner := &fakeRunner{}
	root := t.TempDir()
	manager, err := NewManager(t.Context(), runner, root)
	if err != nil {
		t.Fatal(err)
	}
	auto := &AutoDefense{Groups: []AutoGroup{{ID: "web", Protocol: "tcp", Ports: []PortRange{{80, 80}}, NewPerSecond: 9}}}
	if err := manager.SetAutoDefense(t.Context(), auto); err != nil || len(runner.batches) != 0 {
		t.Fatalf("without a table SetAutoDefense only keeps the part: %v %d", err, len(runner.batches))
	}
	if err := manager.Apply(t.Context(), autoSpec(t)); err != nil {
		t.Fatal(err)
	}
	if last := runner.batches[len(runner.batches)-1]; !strings.Contains(last, "ad_rs_"+GroupToken("web")+"_9_v4") {
		t.Fatal("Apply dropped the auto defense part")
	}
	auto.Groups[0].NewPerSecond = 1 // the manager holds its own copy
	if manager.AutoDefense().Groups[0].NewPerSecond != 9 {
		t.Fatal("caller's value aliased")
	}
	restarted, err := NewManager(t.Context(), runner, root)
	if err != nil {
		t.Fatal(err)
	}
	if got := restarted.AutoDefense(); got == nil || got.Groups[0].NewPerSecond != 9 {
		t.Fatalf("restart did not adopt the running auto defense part: %+v", got)
	}
	if err := restarted.SetAutoDefense(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if last := runner.batches[len(runner.batches)-1]; strings.Contains(last, "add chain inet cdnca_ddos ad_") {
		t.Fatal("removing the part still renders its chains")
	}
	if err := manager.SetAutoDefense(t.Context(), &AutoDefense{Groups: []AutoGroup{{ID: "dns", Protocol: "udp", Ports: []PortRange{{53, 53}}, MaxConnsPerIP: 4}}}); err == nil {
		t.Fatal("a UDP group with a connection limit was accepted")
	}
	overlap := &AutoDefense{Groups: []AutoGroup{{ID: "a", Protocol: "tcp", Ports: []PortRange{{80, 90}}}, {ID: "b", Protocol: "tcp", Ports: []PortRange{{90, 90}}}}}
	if err := manager.SetAutoDefense(t.Context(), overlap); err == nil {
		t.Fatal("overlapping groups of one protocol were accepted")
	}
}

func TestSourceElementsDecodesCountingSets(t *testing.T) {
	sources, err := sourceElements([]byte(`{"nftables":[{"metainfo":{}},{"set":{"name":"ad_s4_x","elem":[
		{"elem":{"val":"192.0.2.7","timeout":60,"expires":51,"counter":{"packets":42,"bytes":2520}}},
		{"elem":{"val":"2001:db8::","counter":{"packets":3,"bytes":180}}},"198.51.100.1"]}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 2 || sources[0].Client.String() != "192.0.2.7" || sources[0].Packets != 42 || sources[1].Packets != 3 {
		t.Fatalf("sources %+v", sources)
	}
}
