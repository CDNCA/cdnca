package nodeinventory

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os/exec"
	"runtime"
	"slices"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

type routeQuery func(context.Context, ...string) ([]byte, error)

func detect(ctx context.Context, query routeQuery) *agentv1.ReportNodeNetworkInventoryV1Request {
	result := &agentv1.ReportNodeNetworkInventoryV1Request{SchemaVersion: 1}
	result.Ipv4, result.Ipv4Reason = detectFamily(ctx, query, "-4")
	result.Ipv6, result.Ipv6Reason = detectFamily(ctx, query, "-6")
	return result
}

// DetectNodeNetworkInventory reads kernel facts only. It does not change routes,
// query a public echo service, or infer a service address from a private NIC.
func DetectNodeNetworkInventory(ctx context.Context) *agentv1.ReportNodeNetworkInventoryV1Request {
	if runtime.GOOS != "linux" {
		return &agentv1.ReportNodeNetworkInventoryV1Request{SchemaVersion: 1, Ipv4Reason: "unavailable", Ipv6Reason: "unavailable"}
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return detect(ctx, readIPCommand)
}

func readIPCommand(ctx context.Context, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, "ip", args...)
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := command.Start(); err != nil {
		return nil, err
	}
	value, readErr := io.ReadAll(io.LimitReader(stdout, 65537))
	if readErr != nil || len(value) > 65536 {
		_ = command.Process.Kill()
		_ = command.Wait()
		return nil, fmt.Errorf("network fact output unavailable")
	}
	if err := command.Wait(); err != nil {
		return nil, err
	}
	return value, nil
}

func detectFamily(ctx context.Context, query routeQuery, family string) (*agentv1.NodeNetworkCandidateV1, string) {
	read := func(target any, args ...string) bool {
		value, err := query(ctx, args...)
		return err == nil && len(value) > 0 && len(value) <= 65536 && json.Unmarshal(value, target) == nil
	}
	var rules []map[string]json.RawMessage
	if !read(&rules, "-j", family, "rule", "show") || len(rules) == 0 {
		return nil, "unavailable"
	}
	main := false
	for _, rule := range rules {
		var priority int
		var source, table string
		if json.Unmarshal(rule["priority"], &priority) != nil || json.Unmarshal(rule["src"], &source) != nil || source != "all" {
			return nil, "ambiguous_route"
		}
		if json.Unmarshal(rule["table"], &table) != nil {
			table = string(rule["table"])
		}
		if !(priority == 0 && (table == "local" || table == "255") || priority == 32766 && (table == "main" || table == "254") || priority == 32767 && (table == "default" || table == "253")) {
			return nil, "ambiguous_route"
		}
		for key := range rule {
			if key != "priority" && key != "src" && key != "table" && key != "protocol" {
				return nil, "ambiguous_route"
			}
		}
		main = main || priority == 32766
	}
	if !main {
		return nil, "ambiguous_route"
	}
	var routes []struct {
		Dst, Dev, Prefsrc, Type string
		Metric                  uint64
		Flags                   []string
		Nexthops                []json.RawMessage
	}
	if !read(&routes, "-j", family, "route", "show", "default") || routes == nil {
		return nil, "unavailable"
	}
	selected := -1
	for index, route := range routes {
		if slices.Contains(route.Flags, "linkdown") || slices.Contains(route.Flags, "dead") {
			continue
		}
		if route.Dst != "default" && route.Dst != "0.0.0.0/0" && route.Dst != "::/0" || route.Type != "" && route.Type != "unicast" || route.Dev == "" || len(route.Nexthops) != 0 {
			return nil, "ambiguous_route"
		}
		if selected < 0 || route.Metric < routes[selected].Metric {
			selected = index
		}
	}
	if selected < 0 {
		return nil, "no_default_route"
	}
	for index, route := range routes {
		if index != selected && route.Metric == routes[selected].Metric && !slices.Contains(route.Flags, "linkdown") && !slices.Contains(route.Flags, "dead") {
			return nil, "ambiguous_route"
		}
	}
	var interfaces []struct {
		Name      string   `json:"ifname"`
		Flags     []string `json:"flags"`
		Addresses []struct {
			Family, Local, Scope             string
			Flags                            []string
			Tentative, Deprecated, Dadfailed bool
		} `json:"addr_info"`
	}
	if !read(&interfaces, "-j", "address", "show") {
		return nil, "unavailable"
	}
	var candidate *agentv1.NodeNetworkCandidateV1
	for _, network := range interfaces {
		if network.Name != routes[selected].Dev || network.Name == "lo" || !slices.Contains(network.Flags, "UP") || slices.Contains(network.Flags, "LOOPBACK") {
			continue
		}
		for _, item := range network.Addresses {
			address, err := netip.ParseAddr(item.Local)
			if err != nil || !publicAddress(address) || (family == "-4") != address.Is4() || (address.Is4() && item.Family != "inet") || (!address.Is4() && item.Family != "inet6") || item.Scope != "global" || item.Tentative || item.Deprecated || item.Dadfailed || slices.Contains(item.Flags, "tentative") || slices.Contains(item.Flags, "deprecated") || slices.Contains(item.Flags, "dadfailed") {
				continue
			}
			if routes[selected].Prefsrc != "" && item.Local != routes[selected].Prefsrc {
				continue
			}
			if candidate != nil {
				return nil, "ambiguous_route"
			}
			candidate = &agentv1.NodeNetworkCandidateV1{Address: address.String(), InterfaceName: network.Name}
		}
	}
	if candidate == nil {
		return nil, "no_global_address"
	}
	return candidate, ""
}

func publicAddress(address netip.Addr) bool {
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.Is4In6() || address.Zone() != "" {
		return false
	}
	for _, blocked := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001::/23", "2001:db8::/32", "2002::/16", "3ffe::/16", "3fff::/20"} {
		if netip.MustParsePrefix(blocked).Contains(address) {
			return false
		}
	}
	return address.Is4() || netip.MustParsePrefix("2000::/3").Contains(address)
}
