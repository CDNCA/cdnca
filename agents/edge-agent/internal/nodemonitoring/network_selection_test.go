package nodemonitoring

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestNetworkSelectionUsesRoutesNotInterfaceNames(t *testing.T) {
	for _, test := range []struct {
		name, routes4, routes6 string
		want                   []string
	}{
		{"private NIC sorts first", `[{"dst":"default","dev":"ens17","gateway":"10.0.0.1"}]`, `[]`, []string{"ens17"}},
		{"lower metric wins", `[{"dst":"default","dev":"eth0","metric":200},{"dst":"default","dev":"ens17","metric":10}]`, `[]`, []string{"ens17"}},
		{"equal cost keeps both", `[{"dst":"default","dev":"eth0","metric":10},{"dst":"default","dev":"ens17","metric":10}]`, `[]`, []string{"ens17", "eth0"}},
		{"IPv6 only", `[]`, `[{"dst":"default","dev":"ens18","metric":1024}]`, []string{"ens18"}},
		{"dual stack different NICs", `[{"dst":"default","dev":"ens17"}]`, `[{"dst":"default","dev":"ens18"}]`, []string{"ens17", "ens18"}},
		{"same NIC deduplicated", `[{"dst":"default","dev":"ens17"}]`, `[{"dst":"default","dev":"ens17"}]`, []string{"ens17"}},
		{"multipath", `[{"dst":"default","metric":100,"nexthops":[{"dev":"ens17","weight":1},{"dev":"ens18","weight":1}]}]`, `[]`, []string{"ens17", "ens18"}},
		{"link down excluded", `[{"dst":"default","dev":"eth0","flags":["linkdown"]},{"dst":"default","dev":"ens17","metric":100}]`, `[]`, []string{"ens17"}},
		{"bond is valid egress", `[{"dst":"default","dev":"bond0"}]`, `[]`, []string{"bond0"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			query := func(_ context.Context, args ...string) ([]byte, error) {
				if strings.Contains(strings.Join(args, " "), "rule") {
					return []byte(`[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"}]`), nil
				}
				if args[1] == "-4" {
					return []byte(test.routes4), nil
				}
				return []byte(test.routes6), nil
			}
			got := detectNetworkSelection(t.Context(), query, map[string]networkCounter{"docker0": {}, "eth0": {}, "ens17": {}, "ens18": {}, "bond0": {}})
			if got.Source != "default_route" || !reflect.DeepEqual(got.Interfaces, test.want) {
				t.Fatalf("selection = %#v, want %v", got, test.want)
			}
		})
	}
}

func TestNetworkSelectionHandlesDualStackAndFailure(t *testing.T) {
	for _, test := range []struct {
		name, routes, rules string
		fail                bool
	}{
		{"no default", `[]`, `[]`, false},
		{"missing interface", `[{"dst":"default","dev":"eth99"}]`, `[]`, false},
		{"loopback", `[{"dst":"default","dev":"lo"}]`, `[]`, false},
		{"reject route", `[{"dst":"default","type":"unreachable"}]`, `[]`, false},
		{"invalid JSON", `{`, `[]`, false},
		{"query failed", `[]`, `[]`, true},
		{"policy routing needs explicit choice", `[{"dst":"default","dev":"ens17"}]`, `[{"priority":100,"src":"all","table":100,"fwmark":"0x1"}]`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			query := func(_ context.Context, args ...string) ([]byte, error) {
				if test.fail {
					return nil, errors.New("no iproute2")
				}
				if strings.Contains(strings.Join(args, " "), "rule") {
					return []byte(test.rules), nil
				}
				return []byte(test.routes), nil
			}
			got := detectNetworkSelection(t.Context(), query, map[string]networkCounter{"ens17": {}})
			if got.Source != "unavailable" || len(got.Interfaces) != 0 {
				t.Fatalf("must not guess: %#v", got)
			}
		})
	}
}

func TestNetworkSelectionRequiresMainRuleInBothFamilies(t *testing.T) {
	for _, family := range []string{"-4", "-6"} {
		t.Run(family, func(t *testing.T) {
			query := func(_ context.Context, args ...string) ([]byte, error) {
				if args[2] == "rule" {
					if args[1] == family {
						return []byte(`[{"priority":0,"src":"all","table":"local"}]`), nil
					}
					return []byte(`[{"priority":32766,"src":"all","table":"main"}]`), nil
				}
				if args[1] == "-4" {
					return []byte(`[{"dst":"default","dev":"ens17"}]`), nil
				}
				return []byte(`[]`), nil
			}
			got := detectNetworkSelection(t.Context(), query, map[string]networkCounter{"ens17": {}})
			if got.Source != "unavailable" || len(got.Interfaces) != 0 {
				t.Fatalf("main-table route alone does not prove effective routing: %+v", got)
			}
		})
	}
}
