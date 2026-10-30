package ddos

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// Site drop (攻击自动升级 D 级, esc-node §3): the TCP ports only level D sites
// use drop every packet. It lives in inet cdnca_ddos beside the spec, in its
// own base chain, set and counter, none of which the spec's Batch touches
// (nor its digest): the drop holds with or without DDoS protection, and a
// spec release keeps it. Loopback passes (the node's own probes, as XDP that
// is only attached to uplinks).
const (
	SiteDropChain   = "site_drop"
	SiteDropSet     = "site_drop_ports"
	SiteDropCounter = "site_drop"
	// siteDropPriority runs after inet cdnca_firewall (-10), before the
	// spec's input chain (-5).
	siteDropPriority = -6
)

// SetSiteDropPorts makes the table drop every TCP packet to ports (sorted or
// not; none lifts the drop). Applied atomically; the ports are kept so a
// spec removal (Apply nil) re-creates them.
func (manager *Manager) SetSiteDropPorts(ctx context.Context, ports []uint16) error {
	ports = slices.Clone(ports)
	slices.Sort(ports)
	ports = slices.Compact(ports)
	ports = slices.DeleteFunc(ports, func(port uint16) bool { return port == 0 })
	manager.mu.Lock()
	defer manager.mu.Unlock()
	batch := siteDropRemoveBatch()
	if len(ports) != 0 {
		batch = siteDropBatch(ports)
	}
	if err := manager.runBatch(ctx, []byte(batch)); err != nil {
		return err
	}
	manager.siteDrop = ports
	if len(ports) == 0 && manager.active == nil {
		// A table nothing else uses goes (one a previous Agent left with
		// a spec this one has not applied yet stays: Apply updates it in
		// place, keeping its bans).
		if listing, err := manager.running(ctx); err == nil && len(listing.sets) == 0 && len(listing.chains) == 0 {
			return manager.runBatch(ctx, RemoveBatch())
		}
	}
	return nil
}

// SiteDropPorts are the ports the table drops (SetSiteDropPorts).
func (manager *Manager) SiteDropPorts() []uint16 {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return slices.Clone(manager.siteDrop)
}

// SiteDropCounter is the site drop counter now (packets and bytes since the
// counter was created; it goes with the drop and starts at zero again).
// Without site drop ports there is none (false, no nft call).
func (manager *Manager) SiteDropCounter(ctx context.Context) (AutoCounter, bool, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if len(manager.siteDrop) == 0 {
		return AutoCounter{}, false, nil
	}
	output, err := manager.runner.Run(ctx, "--json", "list", "counter", TableFamily, TableName, SiteDropCounter)
	if err != nil {
		return AutoCounter{}, false, fmt.Errorf("list counter %s: %w", SiteDropCounter, err)
	}
	return parseSiteDropCounter(output)
}

// parseSiteDropCounter reads the site drop counter of an nft --json listing.
func parseSiteDropCounter(output []byte) (AutoCounter, bool, error) {
	var listing struct {
		Objects []struct {
			Counter *struct {
				Name    string `json:"name"`
				Packets uint64 `json:"packets"`
				Bytes   uint64 `json:"bytes"`
			} `json:"counter,omitempty"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(output, &listing); err != nil {
		return AutoCounter{}, false, fmt.Errorf("%w: %v", ErrUnhealthy, err)
	}
	for _, object := range listing.Objects {
		if counter := object.Counter; counter != nil && counter.Name == SiteDropCounter {
			return AutoCounter{Packets: counter.Packets, Bytes: counter.Bytes}, true, nil
		}
	}
	return AutoCounter{}, false, nil
}

// siteDropBatch creates (or refills) the site drop objects.
func siteDropBatch(ports []uint16) string {
	table := TableFamily + " " + TableName
	elements := make([]string, len(ports))
	for index, port := range ports {
		elements[index] = fmt.Sprint(port)
	}
	var out strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&out, format+"\n", args...) }
	line("add table %s", table)
	line("add set %s %s { type inet_service; }", table, SiteDropSet)
	line("add counter %s %s", table, SiteDropCounter)
	line("add chain %s %s { type filter hook input priority %d; policy accept; }", table, SiteDropChain, siteDropPriority)
	line("flush chain %s %s", table, SiteDropChain)
	line("flush set %s %s", table, SiteDropSet)
	line("add element %s %s { %s }", table, SiteDropSet, strings.Join(elements, ", "))
	line("add rule %s %s meta iif != lo meta l4proto tcp tcp dport @%s counter name %q drop", table, SiteDropChain,
		SiteDropSet, SiteDropCounter)
	return out.String()
}

// siteDropRemoveBatch deletes the site drop objects of a table the spec
// keeps (add first: deleting an absent object fails).
func siteDropRemoveBatch() string {
	table := TableFamily + " " + TableName
	return siteDropBatch([]uint16{1}) +
		fmt.Sprintf("delete chain %s %s\ndelete set %s %s\ndelete counter %s %s\n", table, SiteDropChain, table,
			SiteDropSet, table, SiteDropCounter)
}
