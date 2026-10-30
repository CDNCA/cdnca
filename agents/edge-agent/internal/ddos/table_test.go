package ddos

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

func testDDoS(t *testing.T) *edgeconfig.SiteRuntimeDDoS {
	t.Helper()
	value, err := edgeconfig.NewSiteRuntimeDDoS(edgeconfig.DDoSProtection{
		MaxConnectionsPerIP: 100, NewConnectionsPerSecond: 50, NewConnectionsPerMinute: 600, RateBanSeconds: 600,
		MaxConnectionsPerPort: 50000, AllowNetworks: []string{"192.0.2.0/24"}, CCKernelBan: edgeconfig.CCKernelBanOff,
	}, []string{"203.0.113.1", "2001:db8::1"})
	if err != nil {
		t.Fatal(err)
	}
	return &value
}

func TestNewSpecMergesPortsAndExemptsNodesLoopbackAndAllowList(t *testing.T) {
	spec, err := NewSpec(testDDoS(t), []PortRange{{443, 443}, {80, 80}, {8080, 8090}, {8085, 9000}, {444, 444}})
	if err != nil || spec == nil {
		t.Fatal(err)
	}
	if got, _ := json.Marshal(spec.Ports); string(got) != `[{"First":80,"Last":80},{"First":443,"Last":444},{"First":8080,"Last":9000}]` {
		t.Fatalf("ports = %s", got)
	}
	for _, address := range []string{"127.0.0.1", "::1", "203.0.113.1", "2001:db8::1", "192.0.2.77"} {
		if !spec.exempt(netip.MustParseAddr(address)) {
			t.Errorf("%s not exempt", address)
		}
	}
	if spec.exempt(netip.MustParseAddr("198.51.100.1")) {
		t.Fatal("a client is exempt")
	}
	for _, none := range []struct {
		value *edgeconfig.SiteRuntimeDDoS
		ports []PortRange
	}{{nil, []PortRange{{80, 80}}}, {testDDoS(t), nil}} {
		if spec, err := NewSpec(none.value, none.ports); err != nil || spec != nil {
			t.Fatalf("nothing to protect produced %+v, %v", spec, err)
		}
	}
}

func flagSpec(t *testing.T, filter bool, types []string, invalid bool) *Spec {
	t.Helper()
	value, err := edgeconfig.NewSiteRuntimeDDoS(edgeconfig.DDoSProtection{AllowNetworks: []string{},
		CCKernelBan: edgeconfig.CCKernelBanOff, TCPFlagFilter: filter, TCPFlagTypes: types, DropInvalid: invalid},
		[]string{"203.0.113.1"})
	if err != nil {
		t.Fatal(err)
	}
	spec, err := NewSpec(&value, []PortRange{{80, 80}})
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

// Every type renders its own counted rule, alone and in every combination;
// a type that is off (or the switch off) leaves no rule or counter.
func TestBatchRendersEveryTCPFlagCombination(t *testing.T) {
	rules := map[string]string{
		edgeconfig.DDoSTCPFlagNull:   `tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0 counter name "drop_tcp_null" drop`,
		edgeconfig.DDoSTCPFlagXmas:   `tcp flags & (fin|syn|rst|psh|ack|urg) == fin|psh|urg counter name "drop_tcp_xmas" drop`,
		edgeconfig.DDoSTCPFlagSynFin: `tcp flags & (fin|syn) == fin|syn counter name "drop_tcp_syn_fin" drop`,
		edgeconfig.DDoSTCPFlagSynRst: `tcp flags & (syn|rst) == syn|rst counter name "drop_tcp_syn_rst" drop`,
		edgeconfig.DDoSTCPFlagFin:    `tcp flags & (fin|syn|rst|psh|ack|urg) == fin ct state != { established, related } counter name "drop_tcp_fin" drop`,
		edgeconfig.DDoSTCPFlagAll:    `tcp flags & (fin|syn|rst|psh|ack|urg) == fin|syn|rst|psh|ack|urg counter name "drop_tcp_all" drop`,
	}
	all := edgeconfig.DDoSTCPFlagTypes
	for mask := 1; mask < 1<<len(all); mask++ {
		var types []string
		for index, kind := range all {
			if mask&(1<<index) != 0 {
				types = append(types, kind)
			}
		}
		for _, invalid := range []bool{false, true} {
			batch := string(flagSpec(t, true, types, invalid).Batch(nil, nil, nil))
			for _, kind := range all {
				if strings.Contains(batch, rules[kind]) && !strings.Contains(batch, "guard meta iif != lo "+rules[kind]) {
					t.Fatalf("%s filters loopback:\n%s", kind, batch)
				}
				on := slices.Contains(types, kind)
				if strings.Contains(batch, rules[kind]) != on || strings.Contains(batch, "add counter inet cdnca_ddos drop_tcp_"+kind+"\n") != on {
					t.Fatalf("types %v invalid %v: %s rendered=%v:\n%s", types, invalid, kind, !on, batch)
				}
			}
			if strings.Contains(batch, `ct state invalid counter name "drop_ct_invalid" drop`) != invalid {
				t.Fatalf("types %v: drop_invalid %v not rendered:\n%s", types, invalid, batch)
			}
			// Exemptions first, filters before any connection counting and
			// before INVALID.
			first, last := len(batch), 0
			for _, kind := range types {
				first, last = min(first, strings.Index(batch, rules[kind])), max(last, strings.Index(batch, rules[kind]))
			}
			if strings.Index(batch, "@exempt_v6 return") > first || first > strings.Index(batch, "ct state != new return") ||
				invalid && last > strings.Index(batch, "ct state invalid") {
				t.Fatalf("rule order for %v:\n%s", types, batch)
			}
			// ALL (which has SYN and FIN set) is matched before SYN+FIN.
			if on := slices.Contains(types, "all") && slices.Contains(types, "syn_fin"); on &&
				strings.Index(batch, rules["all"]) > strings.Index(batch, rules["syn_fin"]) {
				t.Fatalf("ALL after SYN+FIN:\n%s", batch)
			}
		}
	}
	// Switch off: the types are kept in the setting but nothing renders; a
	// running table's counters are deleted.
	off := flagSpec(t, false, all, true)
	batch := string(off.Batch(nil, []string{"drop_tcp_null", "drop_tcp_fin", "drop_ct_invalid"}, nil))
	if strings.Contains(batch, "tcp flags") || strings.Contains(batch, "add counter inet cdnca_ddos drop_tcp") ||
		!strings.Contains(batch, "delete counter inet cdnca_ddos drop_tcp_null") ||
		!strings.Contains(batch, "delete counter inet cdnca_ddos drop_tcp_fin") ||
		strings.Contains(batch, "delete counter inet cdnca_ddos drop_ct_invalid") {
		t.Fatalf("filter off:\n%s", batch)
	}
	if spec, err := NewSpec(&edgeconfig.SiteRuntimeDDoS{Protection: edgeconfig.DDoSProtection{AllowNetworks: []string{},
		CCKernelBan: edgeconfig.CCKernelBanOff, TCPFlagTypes: all}, NodeNetworks: []string{}}, []PortRange{{80, 80}}); err != nil || spec != nil {
		t.Fatalf("filters and limits all off still install a table: %+v %v", spec, err)
	}
	if flagSpec(t, true, []string{"null"}, false).Digest() == flagSpec(t, true, []string{"null", "fin"}, false).Digest() {
		t.Fatal("digest ignores the flag types")
	}
}

func TestBatchKeepsBansAndRenamesMetersWithTheirLimit(t *testing.T) {
	spec, _ := NewSpec(testDDoS(t), []PortRange{{80, 80}, {443, 443}})
	batch := string(spec.Batch([]string{"ports", BanSetIPv4, "meter_conn_99_v4", "meter_conn_100_v4"}, nil, nil))
	for _, want := range []string{
		"add set inet cdnca_ddos ban_v6 { type ipv6_addr; flags timeout; size 262144; }",
		"add element inet cdnca_ddos ports { 80, 443 }",
		"add element inet cdnca_ddos exempt_v4 { 127.0.0.0/8, 192.0.2.0/24, 203.0.113.1/32 }",
		"add element inet cdnca_ddos exempt_v6 { ::1/128, 2001:db8::1/128 }",
		"delete set inet cdnca_ddos meter_conn_99_v4",
		"update @meter_rate_s_50_v4 { ip saddr limit rate over 50/second burst 50 packets } add @ban_v4 { ip saddr timeout 600s } counter drop",
		"update @meter_rate_m_600_v6 { ip6 saddr & ffff:ffff:ffff:ffff:: limit rate over 600/minute burst 600 packets } add @ban_v6 { ip6 saddr & ffff:ffff:ffff:ffff:: timeout 600s } counter drop",
		"add @meter_conn_100_v4 { ip saddr ct count over 100 } counter drop",
		"add @meter_port_50000 { tcp dport ct count over 50000 } counter drop",
		"jump guard comment \"cdnca ddos digest=" + spec.Digest() + "\"",
	} {
		if !strings.Contains(batch, want) {
			t.Errorf("batch lacks %q:\n%s", want, batch)
		}
	}
	for _, unwanted := range []string{"flush set inet cdnca_ddos ban_v4", "add set inet cdnca_ddos ban_v4", "delete set inet cdnca_ddos meter_conn_100_v4", "delete table"} {
		if strings.Contains(batch, unwanted) {
			t.Errorf("batch has %q", unwanted)
		}
	}
	// Exempt and bans come before any counting.
	if strings.Index(batch, "@exempt_v4 return") > strings.Index(batch, "@ban_v4 counter drop") ||
		strings.Index(batch, "@ban_v4 counter drop") > strings.Index(batch, "ct state != new return") ||
		strings.Index(batch, "ct state != new return") > strings.Index(batch, "update @meter_rate_s_50_v4") {
		t.Fatalf("rule order:\n%s", batch)
	}
	noBan := *testDDoS(t)
	noBan.Protection.RateBanSeconds = 0
	spec, _ = NewSpec(&noBan, []PortRange{{80, 80}})
	if batch := string(spec.Batch(nil, nil, nil)); strings.Contains(batch, "add @ban_v4 {") {
		t.Fatalf("rate without a ban time bans:\n%s", batch)
	}
}

type fakeRunner struct {
	calls   [][]string
	batches []string
	listing string
	fail    string
}

func (runner *fakeRunner) Run(_ context.Context, arguments ...string) ([]byte, error) {
	runner.calls = append(runner.calls, arguments)
	joined := strings.Join(arguments, " ")
	if runner.fail != "" && strings.Contains(joined, runner.fail) {
		return nil, errors.New("nft failed")
	}
	if len(arguments) >= 2 && arguments[0] == "--file" {
		raw, _ := os.ReadFile(arguments[1])
		runner.batches = append(runner.batches, string(raw))
		if comment := strings.Index(string(raw), "cdnca ddos digest="); comment >= 0 {
			digest := string(raw)[comment+len("cdnca ddos digest="):]
			digest = digest[:strings.IndexByte(digest, '"')]
			runner.listing = `{"nftables":[{"set":{"name":"ban_v4"}},{"rule":{"chain":"input","comment":"cdnca ddos digest=` + digest + `"}}]}`
		} else if strings.Contains(string(raw), "delete table") {
			runner.listing = ""
		}
		return nil, nil
	}
	if strings.HasPrefix(joined, "--json list table") {
		if runner.listing == "" {
			return nil, errors.New("no such table")
		}
		return []byte(runner.listing), nil
	}
	return nil, nil
}

func TestManagerAppliesOnceAdoptsAfterRestartAndBansOnlyClients(t *testing.T) {
	runner := &fakeRunner{}
	root := t.TempDir()
	manager, err := NewManager(t.Context(), runner, root)
	if err != nil {
		t.Fatal(err)
	}
	if banned, err := manager.Ban(t.Context(), []netip.Addr{netip.MustParseAddr("198.51.100.1")}, time.Minute); err != nil || banned != 0 {
		t.Fatalf("ban without a table = %d, %v", banned, err)
	}
	spec, _ := NewSpec(testDDoS(t), []PortRange{{80, 80}})
	if err := manager.Apply(t.Context(), spec); err != nil {
		t.Fatal(err)
	}
	if err := manager.Apply(t.Context(), spec); err != nil || len(runner.batches) != 1 {
		t.Fatalf("unchanged spec reapplied: %d batches, %v", len(runner.batches), err)
	}
	restarted, err := NewManager(t.Context(), runner, root)
	if err != nil || restarted.Active() == nil || restarted.Active().Digest() != spec.Digest() {
		t.Fatalf("restart did not adopt the running table: %v", err)
	}
	banned, err := restarted.Ban(t.Context(), []netip.Addr{
		netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("192.0.2.5"), netip.MustParseAddr("203.0.113.1"),
		netip.MustParseAddr("2001:db8:5::1"), netip.MustParseAddr("2001:db8:5::2"), netip.MustParseAddr("::ffff:198.51.100.1"),
	}, 10*time.Minute)
	if err != nil || banned != 2 {
		t.Fatalf("banned = %d, %v", banned, err)
	}
	last := runner.batches[len(runner.batches)-1]
	if !strings.Contains(last, "ban_v4 { 198.51.100.1 timeout 600s }") || !strings.Contains(last, "ban_v6 { 2001:db8:5:: timeout 600s }") {
		t.Fatalf("ban batch:\n%s", last)
	}
	if _, err := restarted.Ban(t.Context(), []netip.Addr{netip.MustParseAddr("198.51.100.9")}, 8*24*time.Hour); !errors.Is(err, ErrInvalid) {
		t.Fatalf("over-long ban: %v", err)
	}
	if err := restarted.Apply(t.Context(), nil); err != nil || restarted.Active() != nil ||
		!strings.Contains(runner.batches[len(runner.batches)-1], "delete table inet cdnca_ddos") {
		t.Fatalf("remove: %v", err)
	}
	if _, err := os.Stat(root + "/" + stateFile); !os.IsNotExist(err) {
		t.Fatal("state survived the removal")
	}
}

func TestManagerKeepsRunningTableWhenCheckFails(t *testing.T) {
	runner := &fakeRunner{}
	manager, _ := NewManager(t.Context(), runner, t.TempDir())
	spec, _ := NewSpec(testDDoS(t), []PortRange{{80, 80}})
	if err := manager.Apply(t.Context(), spec); err != nil {
		t.Fatal(err)
	}
	changed := *testDDoS(t)
	changed.Protection.MaxConnectionsPerIP = 7
	next, _ := NewSpec(&changed, []PortRange{{80, 80}})
	runner.fail = "--check"
	if err := manager.Apply(t.Context(), next); err == nil || manager.Active().Digest() != spec.Digest() {
		t.Fatalf("failed check replaced the active spec: %v", err)
	}
}

func TestDropCountersReadTheRunningTable(t *testing.T) {
	runner := &fakeRunner{}
	manager, _ := NewManager(t.Context(), runner, t.TempDir())
	if counters, err := manager.DropCounters(t.Context()); err != nil || counters != nil {
		t.Fatalf("no table: %v %v", counters, err)
	}
	spec := flagSpec(t, true, edgeconfig.DDoSDefaultTCPFlagTypes, true)
	if err := manager.Apply(t.Context(), spec); err != nil {
		t.Fatal(err)
	}
	runner.listing = strings.Replace(runner.listing, `{"set"`, `{"counter":{"name":"drop_tcp_xmas","packets":7,"bytes":280}},`+
		`{"counter":{"name":"drop_ct_invalid","packets":3,"bytes":120}},{"counter":{"name":"other","packets":1}},{"set"`, 1)
	counters, err := manager.DropCounters(t.Context())
	if err != nil || len(counters) != 2 || counters[0] != (DropCounter{DropInvalid, 3, 120}) || counters[1] != (DropCounter{DropTCPXmas, 7, 280}) {
		t.Fatalf("counters = %+v, %v", counters, err)
	}
	// A changed spec deletes only the counters it no longer has.
	if err := manager.Apply(t.Context(), flagSpec(t, true, []string{"null"}, true)); err != nil {
		t.Fatal(err)
	}
	last := runner.batches[len(runner.batches)-1]
	if !strings.Contains(last, "delete counter inet cdnca_ddos drop_tcp_xmas") || strings.Contains(last, "delete counter inet cdnca_ddos drop_ct_invalid") {
		t.Fatalf("update batch:\n%s", last)
	}
}

func TestManagerBanGroupWritesOnlyTheGroupSets(t *testing.T) {
	runner := &fakeRunner{}
	manager, err := NewManager(t.Context(), runner, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := NewSpec(testDDoS(t), []PortRange{{80, 80}})
	if err := manager.Apply(t.Context(), spec); err != nil {
		t.Fatal(err)
	}
	client := []netip.Addr{netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("2001:db8:5::1")}
	if banned, err := manager.BanGroup(t.Context(), "web", client, time.Minute); err != nil || banned != 0 {
		t.Fatalf("ban on a group the table does not run = %d, %v", banned, err)
	}
	if err := manager.SetAutoDefense(t.Context(), &AutoDefense{Groups: []AutoGroup{{ID: "web", Protocol: "tcp", Ports: []PortRange{{80, 80}}}}}); err != nil {
		t.Fatal(err)
	}
	banned, err := manager.BanGroup(t.Context(), "web", client, 10*time.Minute)
	if err != nil || banned != 2 {
		t.Fatalf("banned = %d, %v", banned, err)
	}
	last := runner.batches[len(runner.batches)-1]
	token := GroupToken("web")
	if !strings.Contains(last, "ad_b4_"+token+" { 198.51.100.1 timeout 600s }") || !strings.Contains(last, "ad_b6_"+token+" { 2001:db8:5:: timeout 600s }") ||
		strings.Contains(last, BanSetIPv4) {
		t.Fatalf("group ban batch:\n%s", last)
	}
	if _, err := manager.BanGroup(t.Context(), "web", client, 8*24*time.Hour); !errors.Is(err, ErrInvalid) {
		t.Fatalf("over-long group ban: %v", err)
	}
}
