package dynroute

import (
	"context"
	"log"
	"slices"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/ddos"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

// DDoSApplier applies the node DDoS protection table (ddos.Manager).
type DDoSApplier interface {
	Apply(context.Context, *ddos.Spec) error
}

// selectSystem is the system configuration the node runs: the highest
// platform revision the scopes carry (edgeconfig.SelectSiteRuntimeSystem, as
// the composed v8 runtime), the node networks of every scope's DDoS block
// merged so a scope not republished since a node was added still exempts it.
// None: Config.System (tests; nil = built-in defaults). The nginx base is
// this node's (SiteRuntimeSystem.ForNode: region and node overrides).
func (runtime *Runtime) selectSystem(systems []*edgeconfig.SiteRuntimeSystem) (*edgeconfig.SiteRuntimeSystem, error) {
	if len(systems) == 0 {
		return runtime.config.System.ForNode(runtime.config.NodeID), nil
	}
	selected, err := edgeconfig.SelectSiteRuntimeSystem(systems)
	if err != nil || selected == nil {
		return selected, err
	}
	selected = selected.ForNode(runtime.config.NodeID)
	if selected.DDoS == nil {
		return selected, nil
	}
	value := *selected
	ddosValue := *selected.DDoS
	networks := slices.Clone(ddosValue.NodeNetworks)
	for _, system := range systems {
		if system != nil && system.DDoS != nil {
			networks = append(networks, system.DDoS.NodeNetworks...)
		}
	}
	if ddosValue, err = edgeconfig.NewSiteRuntimeDDoS(ddosValue.Protection, networks); err != nil {
		return nil, err
	}
	value.DDoS = &ddosValue
	return &value, nil
}

// nodeNetworks are the running system's node networks (selectSystem merged
// them over the scopes): an L2 node trusts an L1's hop from them.
// None without a system block.
func nodeNetworks(system *edgeconfig.SiteRuntimeSystem) []string {
	if system == nil || system.DDoS == nil {
		return nil
	}
	return system.DDoS.NodeNetworks
}

// sitePorts are the TCP ports the sites listen on (QUIC shares the HTTPS
// port number; the table counts TCP connections only).
func sitePorts(sites []edgesite.Site) []ddos.PortRange {
	var ports []ddos.PortRange
	for _, site := range sites {
		for _, listener := range site.Listeners {
			ports = append(ports, ddos.PortRange{First: uint16(listener.Port), Last: uint16(listener.Port)})
		}
	}
	return ddos.MergePorts(ports)
}

// applyDDoS installs the table the running sites need after their
// generation is active. The generation stands either way: a table that
// cannot be applied leaves the previous one and is retried with the next
// Apply (the v8 adapter's rule). The outcome is kept for DDoSStatus: a
// failure is reported (deployment check, node telemetry), not only logged
// (PJ-E03).
func (runtime *Runtime) applyDDoS(ctx context.Context, system *edgeconfig.SiteRuntimeSystem, sites []edgesite.Site, streams []ddos.PortRange) {
	if runtime.config.DDoS == nil {
		return
	}
	var spec *ddos.Spec
	var err error
	if system != nil && system.DDoS != nil {
		spec, err = ddos.NewSpec(system.DDoS, ddosPorts(sites, streams))
	}
	if err == nil {
		err = runtime.config.DDoS.Apply(ctx, spec)
	}
	status := DDoSStatus{State: DDoSApplied, At: runtime.config.Now()}
	switch {
	case err != nil:
		log.Printf("dynamic routing: DDoS protection not applied: %v", err)
		status.State, status.Detail = DDoSFailed, err.Error()
	case spec == nil:
		status.State = DDoSOff
	}
	runtime.ddosStatus.Store(&status)
}

// DDoS protection outcomes of the last applyDDoS.
const (
	DDoSApplied = "applied" // the running system configuration's table is in place
	DDoSOff     = "off"     // the running configuration has no DDoS block: no table
	DDoSFailed  = "failed"  // the table could not be built or applied (Detail)
)

// DDoSStatus is the last DDoS table application.
type DDoSStatus struct {
	State  string
	Detail string
	At     time.Time
}

// DDoSStatus is the last DDoS table application; false before the first
// (or without a DDoS applier).
func (runtime *Runtime) DDoSStatus() (DDoSStatus, bool) {
	status := runtime.ddosStatus.Load()
	if status == nil {
		return DDoSStatus{}, false
	}
	return *status, true
}

// CCKernelBanPorts are the ports a CC ban of the site's clients covers in
// the kernel under the running cc_kernel_ban mode (DDoS protection): every
// port of the site (site_ports), the ports no other site of the node uses
// (exclusive_ports; an L4 forward's TCP port counts as another user), or
// none (off, or the site is not running). tenantScopeID
// is the CC policy's tenant scope, the site's configuration scope.
func (runtime *Runtime) CCKernelBanPorts(tenantScopeID, siteID string) []uint16 {
	return runtime.ccKernelBanPorts(tenantScopeID, siteID, false)
}

// SharedNodeCCKernelBanPorts are CCKernelBanPorts on a node the tenant does
// not own (A08): site_ports narrows to exclusive_ports, so a ban never covers
// a port another site of the node serves.
func (runtime *Runtime) SharedNodeCCKernelBanPorts(tenantScopeID, siteID string) []uint16 {
	return runtime.ccKernelBanPorts(tenantScopeID, siteID, true)
}

func (runtime *Runtime) ccKernelBanPorts(tenantScopeID, siteID string, exclusiveOnly bool) []uint16 {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	mode := edgeconfig.CCKernelBanOff
	if system := runtime.state.System; system != nil && system.DDoS != nil {
		mode = system.DDoS.Protection.CCKernelBan
	}
	if exclusiveOnly && mode == edgeconfig.CCKernelBanSitePorts {
		mode = edgeconfig.CCKernelBanExclusivePorts
	}
	if mode != edgeconfig.CCKernelBanSitePorts && mode != edgeconfig.CCKernelBanExclusivePorts {
		return nil
	}
	owners := map[int]int{}
	var own []int
	for _, site := range runtime.sites {
		seen := map[int]bool{}
		for _, listener := range site.Listeners {
			if seen[listener.Port] {
				continue
			}
			seen[listener.Port] = true
			owners[listener.Port]++
			if site.ConfigurationScopeID == tenantScopeID && site.SiteID == siteID {
				own = append(own, listener.Port)
			}
		}
	}
	for _, streams := range runtime.state.L4TCP {
		for port := int(streams.First); port <= int(streams.Last); port++ {
			if _, used := owners[port]; used {
				owners[port]++
			}
		}
	}
	var ports []uint16
	for _, port := range own {
		if mode == edgeconfig.CCKernelBanSitePorts || owners[port] == 1 {
			ports = append(ports, uint16(port))
		}
	}
	slices.Sort(ports)
	return ports
}

// RunningSites are the running sites and the L4 streams' TCP ports (esc-node
// site drop derives each level D site's exclusive ports and names from
// them). The slices are copies; the sites themselves must not be changed.
func (runtime *Runtime) RunningSites() ([]edgesite.Site, []ddos.PortRange) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return slices.Clone(runtime.sites), slices.Clone(runtime.state.L4TCP)
}

// SiteTenantScope is the configuration scope of a running site ("" when the
// site does not run here): WAF kernel bans name only the
// site, the kernel ban needs its scope.
func (runtime *Runtime) SiteTenantScope(siteID string) string {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	for _, site := range runtime.sites {
		if site.SiteID == siteID {
			return site.ConfigurationScopeID
		}
	}
	return ""
}
