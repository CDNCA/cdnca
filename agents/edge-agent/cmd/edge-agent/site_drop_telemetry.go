package main

import (
	"context"
	"sync"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/ddos"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/nodemonitoring"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/xdp"
)

// siteDropCounterSource reads the node's site drop counters: XDP's site
// stats (port + SNI) and the nftables site_drop counter. A source that is not
// there answers ok=false.
type siteDropCounterSource struct {
	xdp func() (xdp.SiteDropCounters, error)
	nft func(context.Context) (ddos.AutoCounter, bool, error)
}

// siteDropCounts are the cumulative counters of one read, by source.
type siteDropCounts struct {
	xdpPort, xdpSNI, nft dropCount
	hasXDP, hasNFT       bool
}

type dropCount struct{ packets, bytes uint64 }

// counterDelta is what a cumulative counter counted since previous. A counter
// below previous was re-created (XDP program reloaded, nft counter deleted
// with the drop and created again): everything it holds is new.
func counterDelta(previous, current dropCount) dropCount {
	if current.packets < previous.packets || current.bytes < previous.bytes {
		return current
	}
	return dropCount{packets: current.packets - previous.packets, bytes: current.bytes - previous.bytes}
}

// siteDropTelemetry turns the cumulative counters into per sample deltas
// with the level D sites the node dropped for in the interval (node
// telemetry site_drop). The counters are not per site: the delta is the
// node total, shared by the sites.
type siteDropTelemetry struct {
	source siteDropCounterSource
	// sites drains the site IDs the node dropped for since the last call.
	sites func() []string

	mu       sync.Mutex
	previous siteDropCounts
	primed   bool
}

// newSiteDropTelemetry reads XDP's site stats while the filter runs and the
// nftables site_drop counter (manager nil: none).
func newSiteDropTelemetry(filter *xdp.Manager, manager *ddos.Manager, sites func() []string) *siteDropTelemetry {
	source := siteDropCounterSource{xdp: filter.SiteDropCounters}
	if manager != nil {
		source.nft = manager.SiteDropCounter
	}
	return &siteDropTelemetry{source: source, sites: sites}
}

func (telemetry *siteDropTelemetry) read(ctx context.Context) siteDropCounts {
	var counts siteDropCounts
	if telemetry.source.xdp != nil {
		if counters, err := telemetry.source.xdp(); err == nil {
			counts.hasXDP = true
			counts.xdpPort = dropCount{counters.Port.Packets, counters.Port.Bytes}
			counts.xdpSNI = dropCount{counters.SNI.Packets, counters.SNI.Bytes}
		}
	}
	if telemetry.source.nft != nil {
		if counter, ok, err := telemetry.source.nft(ctx); err == nil && ok {
			counts.hasNFT = true
			counts.nft = dropCount{counter.Packets, counter.Bytes}
		}
	}
	return counts
}

// delta is current minus previous per source; a source missing now counts
// nothing, one missing before counts all it holds.
func (counts siteDropCounts) delta(previous siteDropCounts) dropCount {
	var total dropCount
	add := func(present, wasPresent bool, before, now dropCount) {
		if !present {
			return
		}
		if !wasPresent {
			before = dropCount{}
		}
		d := counterDelta(before, now)
		total.packets += d.packets
		total.bytes += d.bytes
	}
	add(counts.hasXDP, previous.hasXDP, previous.xdpPort, counts.xdpPort)
	add(counts.hasXDP, previous.hasXDP, previous.xdpSNI, counts.xdpSNI)
	add(counts.hasNFT, previous.hasNFT, previous.nft, counts.nft)
	return total
}

// Sample is the site drops since the previous sample, nil when the node
// dropped for no site in the interval. The first sample only primes the
// counters (what they held before the Agent started is not attributable).
func (telemetry *siteDropTelemetry) Sample(ctx context.Context) *nodemonitoring.SiteDropMetrics {
	telemetry.mu.Lock()
	defer telemetry.mu.Unlock()
	counts := telemetry.read(ctx)
	sites := telemetry.sites()
	if !telemetry.primed {
		telemetry.previous, telemetry.primed = counts, true
		return nil
	}
	total := counts.delta(telemetry.previous)
	telemetry.previous = counts
	if len(sites) == 0 {
		return nil
	}
	sites = sortedUnique(sites)
	if len(sites) > nodemonitoring.MaxSiteDropSites {
		sites = sites[:nodemonitoring.MaxSiteDropSites]
	}
	return &nodemonitoring.SiteDropMetrics{SiteIDs: sites, Packets: total.packets, Bytes: total.bytes}
}
