package main

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/ddos"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/xdp"
)

const (
	telemetrySiteA = "11111111-1111-4111-8111-111111111111"
	telemetrySiteB = "22222222-2222-4222-8222-222222222222"
)

func TestCounterDeltaTreatsResetAsNew(t *testing.T) {
	for _, test := range []struct{ previous, current, want dropCount }{
		{dropCount{10, 1000}, dropCount{15, 1500}, dropCount{5, 500}},
		{dropCount{10, 1000}, dropCount{10, 1000}, dropCount{}},
		// re-created counter (program reload / drop lifted and set again)
		{dropCount{10, 1000}, dropCount{3, 300}, dropCount{3, 300}},
	} {
		if got := counterDelta(test.previous, test.current); got != test.want {
			t.Fatalf("counterDelta(%v, %v) = %v, want %v", test.previous, test.current, got, test.want)
		}
	}
}

func TestSiteDropTelemetrySamplesDeltasOfXDPAndNFT(t *testing.T) {
	xdpCounters := xdp.SiteDropCounters{Port: xdp.Counter{Packets: 100, Bytes: 6000}, SNI: xdp.Counter{Packets: 7, Bytes: 700}}
	var xdpErr error
	nftCounter, nftOK := ddos.AutoCounter{Packets: 40, Bytes: 2400}, true
	var sites []string
	telemetry := &siteDropTelemetry{
		source: siteDropCounterSource{
			xdp: func() (xdp.SiteDropCounters, error) { return xdpCounters, xdpErr },
			nft: func(context.Context) (ddos.AutoCounter, bool, error) { return nftCounter, nftOK, nil },
		},
		sites: func() []string { drained := sites; sites = nil; return drained },
	}
	// First sample primes: counts from before the Agent are not attributed.
	sites = []string{telemetrySiteA}
	if got := telemetry.Sample(t.Context()); got != nil {
		t.Fatalf("priming sample = %#v", got)
	}
	xdpCounters.Port.Packets, xdpCounters.Port.Bytes = 130, 7800
	xdpCounters.SNI.Packets, xdpCounters.SNI.Bytes = 9, 900
	nftCounter = ddos.AutoCounter{Packets: 45, Bytes: 2700}
	sites = []string{telemetrySiteB, telemetrySiteA, telemetrySiteB}
	got := telemetry.Sample(t.Context())
	if got == nil || !slices.Equal(got.SiteIDs, []string{telemetrySiteA, telemetrySiteB}) || got.Packets != 30+2+5 || got.Bytes != 1800+200+300 {
		t.Fatalf("sample = %#v", got)
	}
	// XDP fell back (counters gone), nft counter re-created: only nft, all of it.
	xdpErr, nftCounter = xdp.ErrNotRunning, ddos.AutoCounter{Packets: 4, Bytes: 240}
	sites = []string{telemetrySiteA}
	if got := telemetry.Sample(t.Context()); got == nil || got.Packets != 4 || got.Bytes != 240 {
		t.Fatalf("sample after fallback = %#v", got)
	}
	// XDP back: its counters count from zero (no previous reading).
	xdpErr = nil
	xdpCounters = xdp.SiteDropCounters{Port: xdp.Counter{Packets: 2, Bytes: 120}}
	sites = []string{telemetrySiteA}
	if got := telemetry.Sample(t.Context()); got == nil || got.Packets != 2 || got.Bytes != 120 {
		t.Fatalf("sample after XDP returns = %#v", got)
	}
	// No site dropped for in the interval: nothing reported.
	nftOK, xdpErr = false, errors.New("gone")
	if got := telemetry.Sample(t.Context()); got != nil {
		t.Fatalf("sample without sites = %#v", got)
	}
}

func TestSiteDropRuntimeDroppedSitesDrainsAndKeepsHeldPlan(t *testing.T) {
	runtime := &siteDropRuntime{}
	runtime.markDropped(siteDropPlan{SiteIDs: []string{telemetrySiteB}})
	held := siteDropPlan{SiteIDs: []string{telemetrySiteA}}
	runtime.executed = &held
	runtime.markDropped(held)
	if got := runtime.DroppedSites(); !slices.Equal(got, []string{telemetrySiteA, telemetrySiteB}) {
		t.Fatalf("DroppedSites() = %v", got)
	}
	// B was lifted; A is still held, so it stays in the next interval.
	if got := runtime.DroppedSites(); !slices.Equal(got, []string{telemetrySiteA}) {
		t.Fatalf("DroppedSites() after drain = %v", got)
	}
	runtime.executed = &siteDropPlan{}
	runtime.DroppedSites()
	if got := runtime.DroppedSites(); len(got) != 0 {
		t.Fatalf("DroppedSites() with nothing held = %v", got)
	}
}
