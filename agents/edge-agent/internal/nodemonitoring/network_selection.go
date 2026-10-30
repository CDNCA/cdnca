package nodemonitoring

import (
	"context"
	"encoding/json"
	"math"
	"os/exec"
	"slices"
	"sort"
	"time"
)

// NetworkSelection describes monitoring only; it never changes host routing or
// listener bindings. Missing metadata from an older Agent is not an auto choice.
type NetworkSelection struct {
	Source     string   `json:"source"`
	Interfaces []string `json:"interfaces"`
}

type routeQuery func(context.Context, ...string) ([]byte, error)

func detectNetworkSelection(ctx context.Context, query routeQuery, interfaces map[string]networkCounter) *NetworkSelection {
	unavailable := &NetworkSelection{Source: "unavailable", Interfaces: []string{}}
	if query == nil {
		return unavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	selected := map[string]bool{}
	for _, family := range []string{"-4", "-6"} {
		payload, err := query(ctx, "-j", family, "route", "show", "default")
		var routes []struct {
			Dst      string   `json:"dst"`
			Dev      string   `json:"dev"`
			Type     string   `json:"type"`
			Metric   uint64   `json:"metric"`
			Flags    []string `json:"flags"`
			Nexthops []struct {
				Dev   string   `json:"dev"`
				Flags []string `json:"flags"`
			} `json:"nexthops"`
		}
		if err != nil || len(payload) > 65536 || json.Unmarshal(payload, &routes) != nil || routes == nil {
			return unavailable
		}
		// Main-table defaults cannot prove the effective egress under policy
		// routing. Keep the raw NIC facts, but do not guess an automatic choice.
		payload, err = query(ctx, "-j", family, "rule", "show")
		var rules []map[string]json.RawMessage
		if err != nil || len(payload) > 65536 || json.Unmarshal(payload, &rules) != nil || len(rules) == 0 {
			return unavailable
		}
		mainRule := false
		for _, rule := range rules {
			var priority int
			var source, table string
			if json.Unmarshal(rule["priority"], &priority) != nil || json.Unmarshal(rule["src"], &source) != nil || source != "all" {
				return unavailable
			}
			if json.Unmarshal(rule["table"], &table) != nil {
				table = string(rule["table"])
			}
			if !(priority == 0 && (table == "local" || table == "255") || priority == 32766 && (table == "main" || table == "254") || priority == 32767 && (table == "default" || table == "253")) {
				return unavailable
			}
			mainRule = mainRule || priority == 32766 && (table == "main" || table == "254")
			for key := range rule {
				if key != "priority" && key != "src" && key != "table" && key != "protocol" {
					return unavailable
				}
			}
		}
		if !mainRule {
			return unavailable
		}
		best := uint64(math.MaxUint64)
		familyNames := map[string]bool{}
		for _, route := range routes {
			if route.Dst != "default" && route.Dst != "0.0.0.0/0" && route.Dst != "::/0" {
				return unavailable
			}
			if route.Type != "" && route.Type != "unicast" {
				return unavailable
			}
			if slices.Contains(route.Flags, "linkdown") || slices.Contains(route.Flags, "dead") {
				continue
			}
			names := []string{}
			if route.Dev != "" {
				names = append(names, route.Dev)
			}
			for _, hop := range route.Nexthops {
				if !slices.Contains(hop.Flags, "linkdown") && !slices.Contains(hop.Flags, "dead") {
					names = append(names, hop.Dev)
				}
			}
			if len(names) == 0 {
				return unavailable
			}
			if route.Metric > best {
				continue
			}
			if route.Metric < best {
				best, familyNames = route.Metric, map[string]bool{}
			}
			for _, name := range names {
				if _, exists := interfaces[name]; !exists || name == "lo" {
					return unavailable
				}
				familyNames[name] = true
			}
		}
		for name := range familyNames {
			selected[name] = true
		}
	}
	if len(selected) == 0 {
		return unavailable
	}
	names := make([]string, 0, len(selected))
	for name := range selected {
		names = append(names, name)
	}
	sort.Strings(names)
	return &NetworkSelection{Source: "default_route", Interfaces: names}
}

func runRouteQuery(ctx context.Context, args ...string) ([]byte, error) {
	// Arguments are internal constants; no shell, packet transmission, or route mutation.
	return exec.CommandContext(ctx, "ip", args...).Output()
}
