package main

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/xdp"
)

type fakeSiteDropXDP struct {
	running bool
	drops   []xdp.SiteDrop
	err     error
}

func (filter *fakeSiteDropXDP) Running() bool { return filter.running }
func (filter *fakeSiteDropXDP) SetSiteDrop(drop xdp.SiteDrop) error {
	filter.drops = append(filter.drops, drop)
	return filter.err
}

type fakeSiteDropNFT struct {
	ports [][]uint16
	err   error
}

func (table *fakeSiteDropNFT) SetSiteDropPorts(_ context.Context, ports []uint16) error {
	table.ports = append(table.ports, ports)
	return table.err
}

// fakeSiteDropHosts is the test stub of esc-lua's OpenResty host pusher.
type fakeSiteDropHosts struct {
	pushed [][]string
	clears int
	err    error
}

func (hosts *fakeSiteDropHosts) PushHosts(_ context.Context, names []string) error {
	hosts.pushed = append(hosts.pushed, names)
	return hosts.err
}
func (hosts *fakeSiteDropHosts) ClearHosts(context.Context) error {
	hosts.clears++
	return hosts.err
}

var executorTestPlan = siteDropPlan{Mode: siteDropModeXDP, SiteIDs: []string{dropSiteA}, Ports: []uint16{8443},
	SNIPorts: []uint16{443}, ServerNames: []string{"*.a.example", "a.example"}, KeepNames: []string{"b.example"},
	Hosts: []string{"*.a.example", "a.example"}}

func TestKernelSiteDropExecutorXDPMode(t *testing.T) {
	filter, table, hosts := &fakeSiteDropXDP{running: true}, &fakeSiteDropNFT{}, &fakeSiteDropHosts{}
	executor := kernelSiteDropExecutor{xdp: filter, nft: table, hosts: hosts}
	if err := executor.Apply(t.Context(), executorTestPlan); err != nil {
		t.Fatal(err)
	}
	wantDrop := xdp.SiteDrop{Ports: []uint16{8443}, SNIPorts: []uint16{443}, DropNames: []string{"*.a.example", "a.example"},
		KeepNames: []string{"b.example"}}
	// nftables keeps the exclusive ports too: an XDP fallback leaves no gap.
	if !reflect.DeepEqual(filter.drops, []xdp.SiteDrop{wantDrop}) || !reflect.DeepEqual(table.ports, [][]uint16{{8443}}) ||
		!reflect.DeepEqual(hosts.pushed, [][]string{{"*.a.example", "a.example"}}) {
		t.Fatalf("xdp %+v nft %v hosts %v", filter.drops, table.ports, hosts.pushed)
	}
	if err := executor.Clear(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(filter.drops[1], xdp.SiteDrop{}) || table.ports[1] != nil || hosts.clears != 1 {
		t.Fatalf("clear: xdp %+v nft %v hosts %d", filter.drops, table.ports, hosts.clears)
	}
}

func TestKernelSiteDropExecutorNFTablesModeAndFailures(t *testing.T) {
	filter, table, hosts := &fakeSiteDropXDP{}, &fakeSiteDropNFT{}, &fakeSiteDropHosts{}
	executor := kernelSiteDropExecutor{xdp: filter, nft: table, hosts: hosts}
	plan := siteDropPlan{Mode: siteDropModeNFTables, SiteIDs: []string{dropSiteA}, Ports: []uint16{8443}, Hosts: []string{"a.example"}}
	if err := executor.Apply(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
	if len(filter.drops) != 0 || !reflect.DeepEqual(table.ports, [][]uint16{{8443}}) {
		t.Fatalf("nftables mode: xdp %+v nft %v", filter.drops, table.ports)
	}
	// An xdp plan after the filter fell back: refused, the next derivation
	// is nftables.
	if err := executor.Apply(t.Context(), executorTestPlan); !errors.Is(err, xdp.ErrNotRunning) {
		t.Fatalf("xdp plan without XDP = %v", err)
	}
	table.err = errors.New("nft failed")
	if err := executor.Apply(t.Context(), plan); err == nil {
		t.Fatal("nft failure not reported")
	}
	// Without nft (and XDP) exclusive ports cannot be dropped; without the
	// OpenResty pusher names cannot.
	if err := (kernelSiteDropExecutor{hosts: hosts}).Apply(t.Context(), plan); !errors.Is(err, errSiteDropUnsupported) {
		t.Fatalf("no nft = %v", err)
	}
	if err := (kernelSiteDropExecutor{nft: &fakeSiteDropNFT{}}).Apply(t.Context(), plan); !errors.Is(err, errSiteDropUnsupported) {
		t.Fatalf("no host pusher = %v", err)
	}
	if err := (kernelSiteDropExecutor{nft: &fakeSiteDropNFT{}}).Clear(t.Context()); err != nil {
		t.Fatalf("clear without host pusher = %v", err)
	}
}
