package main

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/ddos"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/edgeconfig/sitedrop"
)

// Site drop modes (SiteDropReceipt.mode).
const (
	siteDropModeXDP      = "xdp"
	siteDropModeNFTables = "nftables"
)

// siteDropPlan is what the node drops for the level D sites it runs, derived
// from the running sites (攻击自动升级 D 级, esc-node §2):
//   - Ports: the ports only level D sites use (no other site, no L4 TCP
//     stream): every packet is dropped (XDP, else nftables);
//   - SNIPorts / ServerNames: shared TLS ports and the D sites' names (primary
//     and aliases, leading wildcards kept) whose ClientHellos XDP drops; empty
//     without XDP (the receipt reports sni_unavailable);
//   - KeepNames: the names of the other sites on SNIPorts, so XDP keeps
//     their handshakes where a D site's wildcard also matches (nginx picks
//     the exact name, or the longer wildcard);
//   - Hosts: every D site name, for OpenResty to close (444) requests and
//     handshakes selecting them (shared plain HTTP ports, QUIC).
//
// All lists are sorted and unique; the zero plan drops nothing.
type siteDropPlan struct {
	Mode        string
	SiteIDs     []string
	Ports       []uint16
	SNIPorts    []uint16
	ServerNames []string
	KeepNames   []string
	Hosts       []string
}

func (plan siteDropPlan) empty() bool { return len(plan.SiteIDs) == 0 }

// errSiteDropUnsupported: the executor cannot enforce drops on this node
// (receipt not_supported).
var errSiteDropUnsupported = errors.New("site drop enforcement is not available on this node")

// SiteDropExecutor enforces a plan (XDP / nftables / OpenResty, esc-node §3
// and §4). Apply replaces the previous plan as a whole; Clear lifts every
// drop. A failed call may leave a partial state: the runtime calls again.
type SiteDropExecutor interface {
	Apply(ctx context.Context, plan siteDropPlan) error
	Clear(ctx context.Context) error
}

// siteDropRuntime applies the control plane's site drop snapshots: verifies
// the signature with the edge publication key (as securityban), keeps the
// node's revision order, replaces the whole list, derives the plan from the
// running sites and hands it to the executor. refresh (runtime status poller,
// once a second) lifts sites at their until and follows site changes.
type siteDropRuntime struct {
	nodeID   string
	trusted  sitedrop.TrustedKeyFunc
	sites    func() ([]edgesite.Site, []ddos.PortRange)
	xdp      func() bool
	executor SiteDropExecutor
	now      func() time.Time

	mu      sync.Mutex
	applied *sitedrop.List
	// deadline caps every until of the applied list (received + 7 days),
	// whatever the control plane's clock said.
	deadline time.Time
	// executed is the plan the executor holds (nil: unknown, re-apply).
	executed *siteDropPlan
	// failed is the last plan the executor failed on; refresh retries the
	// same plan no sooner than retryAt (siteDropRetryInterval), a different
	// plan (a site expired, sites changed) at once.
	failed  *siteDropPlan
	retryAt time.Time
	// dropped are the sites the executor held since the last DroppedSites
	// (node telemetry site_drop).
	dropped map[string]bool
}

// siteDropRetryInterval spaces retries of a plan the executor failed on (as
// securityban's reapply).
const siteDropRetryInterval = 30 * time.Second

func newSiteDropRuntime(nodeID string, trusted sitedrop.TrustedKeyFunc, sites func() ([]edgesite.Site, []ddos.PortRange),
	xdp func() bool, executor SiteDropExecutor, now func() time.Time) *siteDropRuntime {
	if nodeID == "" || trusted == nil || sites == nil || xdp == nil || executor == nil || now == nil {
		return nil
	}
	return &siteDropRuntime{nodeID: nodeID, trusted: trusted, sites: sites, xdp: xdp, executor: executor, now: now}
}

// ApplySiteDrop implements gatewayclient.SiteDropApplier.
func (runtime *siteDropRuntime) ApplySiteDrop(encoded []byte) gatewayclient.SiteDropResult {
	list, err := sitedrop.Open(encoded, runtime.nodeID, runtime.trusted)
	switch {
	case errors.Is(err, sitedrop.ErrUntrusted):
		return gatewayclient.SiteDropResult{ErrorCode: sitedrop.ErrorUntrusted}
	case errors.Is(err, sitedrop.ErrWrongNode):
		return gatewayclient.SiteDropResult{ErrorCode: sitedrop.ErrorWrongNode}
	case err != nil:
		return gatewayclient.SiteDropResult{ErrorCode: sitedrop.ErrorInvalid}
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.applied != nil && list.Revision < runtime.applied.Revision {
		return gatewayclient.SiteDropResult{ErrorCode: sitedrop.ErrorStale}
	}
	now := runtime.now()
	deadline := now.Add(sitedrop.MaxDuration)
	plan, result := runtime.derive(list, deadline, now)
	if err := runtime.execute(context.Background(), plan); err != nil {
		// The executor may hold part of the new plan: the next refresh
		// re-applies the previous snapshot.
		runtime.executed = nil
		slog.Warn("site drop list not applied", "revision", list.Revision, "error", err)
		if errors.Is(err, errSiteDropUnsupported) {
			return gatewayclient.SiteDropResult{ErrorCode: sitedrop.ErrorNotSupported}
		}
		return gatewayclient.SiteDropResult{ErrorCode: sitedrop.ErrorRuntime}
	}
	runtime.applied, runtime.deadline = &list, deadline
	slog.Info("site drop list applied", "revision", list.Revision, "mode", result.Mode, "sites", result.Sites,
		"ports", result.Ports, "server_names", result.ServerNames, "rejected", len(result.Rejected))
	result.Applied = true
	return result
}

// refresh re-derives the applied list's plan (expired sites, running site and
// XDP changes) and re-applies it when it changed or was not held.
func (runtime *siteDropRuntime) refresh(ctx context.Context) {
	if runtime == nil {
		return
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.applied == nil {
		return
	}
	plan, _ := runtime.derive(*runtime.applied, runtime.deadline, runtime.now())
	if runtime.executed != nil && reflect.DeepEqual(*runtime.executed, plan) {
		return
	}
	if runtime.failed != nil && reflect.DeepEqual(*runtime.failed, plan) && runtime.now().Before(runtime.retryAt) {
		return
	}
	if err := runtime.execute(ctx, plan); err != nil {
		slog.Warn("site drop refresh failed", "revision", runtime.applied.Revision, "error", err)
	}
}

// execute hands plan to the executor and records it. Called with mu held.
func (runtime *siteDropRuntime) execute(ctx context.Context, plan siteDropPlan) error {
	var err error
	if plan.empty() {
		err = runtime.executor.Clear(ctx)
	} else {
		err = runtime.executor.Apply(ctx, plan)
	}
	if err != nil {
		runtime.failed, runtime.retryAt = &plan, runtime.now().Add(siteDropRetryInterval)
		return err
	}
	runtime.executed, runtime.failed = &plan, nil
	runtime.markDropped(plan)
	return nil
}

// markDropped adds plan's sites to dropped. Called with mu held.
func (runtime *siteDropRuntime) markDropped(plan siteDropPlan) {
	if len(plan.SiteIDs) != 0 && runtime.dropped == nil {
		runtime.dropped = map[string]bool{}
	}
	for _, site := range plan.SiteIDs {
		runtime.dropped[site] = true
	}
}

// DroppedSites are the sites the node dropped for since the previous call
// (those of every plan executed in between and of the plan held now).
func (runtime *siteDropRuntime) DroppedSites() []string {
	if runtime == nil {
		return nil
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	sites := make([]string, 0, len(runtime.dropped))
	for site := range runtime.dropped {
		sites = append(sites, site)
	}
	runtime.dropped = nil
	if runtime.executed != nil {
		runtime.markDropped(*runtime.executed)
	}
	return sortedUnique(sites)
}

// derive is list's plan at now and its receipt counts. A listed site is
// active until min(until, deadline); one not running here is not_served.
// Called with mu held.
func (runtime *siteDropRuntime) derive(list sitedrop.List, deadline, now time.Time) (siteDropPlan, gatewayclient.SiteDropResult) {
	active := map[string]bool{}
	for _, site := range list.Sites {
		if until := time.Unix(site.Until, 0); now.Before(until) && now.Before(deadline) {
			active[site.SiteID] = true
		}
	}
	mode := siteDropModeNFTables
	if runtime.xdp() {
		mode = siteDropModeXDP
	}
	result := gatewayclient.SiteDropResult{Mode: mode}
	if len(active) == 0 {
		return siteDropPlan{}, result
	}
	sites, streams := runtime.sites()
	// others: ports some running site outside the list, or an L4 TCP
	// stream, uses.
	others := map[int]bool{}
	var dropped, kept []edgesite.Site
	for _, site := range sites {
		if active[site.SiteID] {
			dropped = append(dropped, site)
			continue
		}
		kept = append(kept, site)
		for _, listener := range site.Listeners {
			others[listener.Port] = true
		}
	}
	for _, stream := range streams {
		for port := int(stream.First); port <= int(stream.Last); port++ {
			others[port] = true
		}
	}

	plan := siteDropPlan{Mode: mode}
	served := map[string]bool{}
	for _, site := range dropped {
		served[site.SiteID] = true
		plan.SiteIDs = append(plan.SiteIDs, site.SiteID)
		names := append([]string{site.Hosts.Primary}, site.Hosts.Aliases...)
		plan.Hosts = append(plan.Hosts, names...)
		sni := false
		for _, listener := range site.Listeners {
			port := uint16(listener.Port)
			switch {
			case !others[listener.Port]:
				plan.Ports = append(plan.Ports, port)
			case listener.TLS == nil:
				// Shared plain HTTP: OpenResty closes it by Host.
			case mode == siteDropModeXDP:
				plan.SNIPorts = append(plan.SNIPorts, port)
				sni = true
			default:
				result.Rejected = append(result.Rejected, gatewayclient.SiteDropRejection{SiteID: site.SiteID, Port: port,
					Reason: sitedrop.RejectSNIUnavailable})
			}
		}
		if sni {
			plan.ServerNames = append(plan.ServerNames, names...)
		}
	}
	for _, site := range list.Sites {
		if active[site.SiteID] && !served[site.SiteID] {
			result.Rejected = append(result.Rejected, gatewayclient.SiteDropRejection{SiteID: site.SiteID,
				Reason: sitedrop.RejectNotServed})
		}
	}
	for _, site := range kept {
		for _, listener := range site.Listeners {
			if listener.TLS != nil && slices.Contains(plan.SNIPorts, uint16(listener.Port)) {
				plan.KeepNames = append(plan.KeepNames, site.Hosts.Primary)
				plan.KeepNames = append(plan.KeepNames, site.Hosts.Aliases...)
				break
			}
		}
	}
	plan.SiteIDs = sortedUnique(plan.SiteIDs)
	plan.KeepNames = sortedUnique(plan.KeepNames)
	plan.Ports = sortedUnique(plan.Ports)
	plan.SNIPorts = sortedUnique(plan.SNIPorts)
	plan.ServerNames = sortedUnique(plan.ServerNames)
	plan.Hosts = sortedUnique(plan.Hosts)
	slices.SortFunc(result.Rejected, func(a, b gatewayclient.SiteDropRejection) int {
		if a.SiteID != b.SiteID {
			if a.SiteID < b.SiteID {
				return -1
			}
			return 1
		}
		return int(a.Port) - int(b.Port)
	})
	result.Rejected = slices.Compact(result.Rejected)
	result.Sites = uint32(len(plan.SiteIDs))
	result.Ports = uint32(len(plan.Ports))
	result.ServerNames = uint32(len(plan.ServerNames))
	if plan.empty() {
		return siteDropPlan{}, result
	}
	return plan, result
}

func sortedUnique[T ~string | ~uint16](values []T) []T {
	slices.Sort(values)
	return slices.Compact(values)
}
