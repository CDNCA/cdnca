package nodeinventory

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestDetectNodeNetworkInventory(t *testing.T) {
	query := func(_ context.Context, args ...string) ([]byte, error) {
		key := strings.Join(args, " ")
		switch key {
		case "-j -4 route show default":
			return []byte(`[{"dst":"default","dev":"ens17","prefsrc":"1.0.0.125"}]`), nil
		case "-j -6 route show default":
			return []byte(`[]`), nil
		case "-j -4 rule show", "-j -6 rule show":
			return []byte(`[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"}]`), nil
		case "-j address show":
			return []byte(`[{"ifname":"ens17","flags":["UP"],"addr_info":[{"family":"inet","local":"1.0.0.125","scope":"global"}]},{"ifname":"docker0","flags":[],"addr_info":[{"family":"inet","local":"172.17.0.1","scope":"global"}]}]`), nil
		}
		return nil, fmt.Errorf("unexpected command")
	}
	got := detect(context.Background(), query)
	if got.Ipv4.GetAddress() != "1.0.0.125" || got.Ipv4.GetInterfaceName() != "ens17" || got.Ipv4Reason != "" || got.Ipv6 != nil || got.Ipv6Reason != "no_default_route" {
		t.Fatalf("default route inventory = %v", got)
	}
	for _, test := range []struct {
		name, family, rules, routes, addresses, want, reason string
	}{
		{name: "lower-metric-egress", routes: `[{"dst":"default","dev":"ens18","metric":200},{"dst":"default","dev":"ens17","metric":100}]`, want: "1.0.0.125"},
		{name: "equal-metric-ambiguous", routes: `[{"dst":"default","dev":"ens18"},{"dst":"default","dev":"ens17"}]`, reason: "ambiguous_route"},
		{name: "policy-routing-unproven", rules: `[{"priority":100,"src":"all","table":"vpn"}]`, reason: "ambiguous_route"},
		{name: "multipath", routes: `[{"dst":"default","nexthops":[{"dev":"ens17"},{"dev":"ens18"}]}]`, reason: "ambiguous_route"},
		{name: "docker-egress-is-private", routes: `[{"dst":"default","dev":"docker0"}]`, reason: "no_global_address"},
		{name: "route-prefsrc-must-exist", routes: `[{"dst":"default","dev":"ens17","prefsrc":"1.0.0.126"}]`, reason: "no_global_address"},
		{name: "two-addresses-without-source", addresses: `[{"ifname":"ens17","flags":["UP"],"addr_info":[{"family":"inet","local":"1.0.0.125","scope":"global"},{"family":"inet","local":"1.0.0.126","scope":"global"}]}]`, reason: "ambiguous_route"},
		{name: "two-addresses-explicit-source", routes: `[{"dst":"default","dev":"ens17","prefsrc":"1.0.0.126"}]`, addresses: `[{"ifname":"ens17","flags":["UP"],"addr_info":[{"family":"inet","local":"1.0.0.125","scope":"global"},{"family":"inet","local":"1.0.0.126","scope":"global"}]}]`, want: "1.0.0.126"},
		{name: "CGNAT", addresses: `[{"ifname":"ens17","flags":["UP"],"addr_info":[{"family":"inet","local":"100.64.0.1","scope":"global"}]}]`, reason: "no_global_address"},
		{name: "not-up", addresses: `[{"ifname":"ens17","flags":[],"addr_info":[{"family":"inet","local":"1.0.0.125","scope":"global"}]}]`, reason: "no_global_address"},
		{name: "wrong-family-fact", addresses: `[{"ifname":"ens17","flags":["UP"],"addr_info":[{"family":"inet6","local":"1.0.0.125","scope":"global"}]}]`, reason: "no_global_address"},
		{name: "dead-route", routes: `[{"dst":"default","dev":"ens17","flags":["linkdown"]}]`, reason: "no_default_route"},
		{name: "IPv6", family: "-6", addresses: `[{"ifname":"ens17","flags":["UP"],"addr_info":[{"family":"inet6","local":"2606:4700:4700::1111","scope":"global"}]}]`, want: "2606:4700:4700::1111"},
		{name: "IPv6-ULA", family: "-6", addresses: `[{"ifname":"ens17","flags":["UP"],"addr_info":[{"family":"inet6","local":"fd00::1","scope":"global"}]}]`, reason: "no_global_address"},
		{name: "IPv6-tentative", family: "-6", addresses: `[{"ifname":"ens17","flags":["UP"],"addr_info":[{"family":"inet6","local":"2606:4700:4700::1111","scope":"global","tentative":true}]}]`, reason: "no_global_address"},
		{name: "bad-json", routes: `garbage`, reason: "unavailable"},
		{name: "oversize", routes: strings.Repeat(" ", 65537), reason: "unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.family == "" {
				test.family = "-4"
			}
			if test.routes == "" {
				test.routes = `[{"dst":"default","dev":"ens17"}]`
			}
			read := func(ctx context.Context, args ...string) ([]byte, error) {
				key := strings.Join(args, " ")
				if key == "-j "+test.family+" route show default" {
					return []byte(test.routes), nil
				}
				if key == "-j "+test.family+" rule show" && test.rules != "" {
					return []byte(test.rules), nil
				}
				if key == "-j address show" && test.addresses != "" {
					return []byte(test.addresses), nil
				}
				return query(ctx, args...)
			}
			candidate, reason := detectFamily(context.Background(), read, test.family)
			if candidate.GetAddress() != test.want || reason != test.reason {
				t.Fatalf("candidate=%v reason=%s; want=%s/%s", candidate, reason, test.want, test.reason)
			}
		})
	}
}

// Explicit opt-in only: reads kernel facts, never reports them or changes state.
func TestDetectNodeNetworkInventoryLive(t *testing.T) {
	expected, device := os.Getenv("CDNCA_TEST_NODE_NETWORK_IPV4"), os.Getenv("CDNCA_TEST_NODE_NETWORK_INTERFACE")
	if expected == "" && device == "" {
		t.Skip("explicit live IPv4 and interface expectations are required")
	}
	if runtime.GOOS != "linux" || expected == "" || device == "" {
		t.Fatal("live discovery requires Linux and both explicit expectations")
	}
	result := DetectNodeNetworkInventory(t.Context())
	if result.Ipv4.GetAddress() != expected || result.Ipv4.GetInterfaceName() != device || result.Ipv4Reason != "" {
		t.Fatalf("kernel discovery candidate=%v reason=%q", result.Ipv4, result.Ipv4Reason)
	}
	if result.Ipv6 != nil && result.Ipv6.InterfaceName == "docker0" {
		t.Fatal("Docker interface became primary IPv6 candidate")
	}
	t.Logf("kernel candidate matched expected interface; IPv6 candidate present=%t reason=%q (not a transport verification)", result.Ipv6 != nil, result.Ipv6Reason)
}
