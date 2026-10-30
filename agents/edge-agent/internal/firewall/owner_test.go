package firewall

import (
	"context"
	"strings"
	"testing"
)

const (
	ownerTenantA = "11111111-1111-4111-8111-111111111111"
	ownerTenantB = "22222222-2222-4222-8222-222222222222"
	ownerSiteA   = "33333333-3333-4333-8333-333333333333"
	ownerSiteB   = "44444444-4444-4444-8444-444444444444"
	platformID   = "55555555-5555-4555-8555-555555555555"
)

func gatedManager(t *testing.T) (*Manager, *fakeRunner) {
	t.Helper()
	runner := &fakeRunner{}
	manager := newTestManager(t, testStateRoot(t), runner, fixedTime)
	manager.admitAllTenants = false
	return manager, runner
}

func hostVersion(task, key, tenant, site, kind, network string, protocol Protocol, port uint16) FirewallVersion {
	version := scopedVersion(task, key, tenant, site, 1, 0, network)
	version.PolicyKind = kind
	for index := range version.Entries {
		version.Entries[index].Protocol = protocol
		version.Entries[index].PortStart, version.Entries[index].PortEnd = port, port
	}
	return version
}

// A08: tenants A and B share a platform node. A's host rule (an ANY deny, the
// global/waf_action shape) is refused; the node's ruleset never filters B's
// traffic by it.
func TestSharedNodeRefusesTenantHostRule(t *testing.T) {
	manager, runner := gatedManager(t)
	if err := manager.SetOwnerScope(context.Background(), platformID); err != nil {
		t.Fatal(err)
	}
	result, err := manager.Apply(context.Background(), hostVersion("a-global", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		ownerTenantA, ownerSiteA, "global", "192.0.2.0/24", ProtocolAny, 0))
	if err != nil {
		t.Fatal(err)
	}
	if result.State != StateFailed || result.ErrorCode != ErrorCodeSharedNodeHostRule || !result.RunningVersionUnchanged {
		t.Fatalf("result=%+v, want failed %s with the running version unchanged", result, ErrorCodeSharedNodeHostRule)
	}
	if checks, applies, _ := runner.counts(); checks != 0 || applies != 0 {
		t.Fatalf("nft called (check=%d apply=%d) for a refused tenant host rule", checks, applies)
	}
	// A site-ports kernel ban without a port (ANY) is refused as well.
	result, err = manager.Apply(context.Background(), hostVersion("a-ccban", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		ownerTenantA, ownerSiteA, PolicyKindCCBan, "192.0.2.9/32", ProtocolAny, 0))
	if err != nil || result.State != StateFailed {
		t.Fatalf("portless kernel ban: result=%+v err=%v, want failed", result, err)
	}
	// Withdrawing (empty) always passes.
	if !manager.admitsScope(ownerTenantA, "global", nil) {
		t.Fatal("empty withdrawal refused")
	}
}

// The tenant owning the node keeps host rules; a port-scoped kernel ban of an
// exclusive listener is admitted on a shared node.
func TestOwnedNodeAndPortScopedBanStillApply(t *testing.T) {
	manager, runner := gatedManager(t)
	if err := manager.SetOwnerScope(context.Background(), ownerTenantA); err != nil {
		t.Fatal(err)
	}
	result, err := manager.Apply(context.Background(), hostVersion("a-own", "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
		ownerTenantA, ownerSiteA, "global", "192.0.2.0/24", ProtocolAny, 0))
	if err != nil || result.State != StateApplied {
		t.Fatalf("owned node host rule: result=%+v err=%v, want applied", result, err)
	}
	result, err = manager.Apply(context.Background(), hostVersion("b-ban", "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
		ownerTenantB, ownerSiteB, PolicyKindWAFBan, "198.51.100.9/32", ProtocolTCP, 8443))
	if err != nil || result.State != StateApplied {
		t.Fatalf("port-scoped ban of another tenant: result=%+v err=%v, want applied", result, err)
	}
	batch := runner.lastBatch()
	if !strings.Contains(batch, "192.0.2.0/24") || !strings.Contains(batch, "tcp dport 8443") {
		t.Fatalf("compiled batch lost the owned rule or the port-scoped ban:\n%s", batch)
	}
}

// Rules stored before the gate (or before the node changed hands) leave the
// kernel once the owner is learned; other tenants' port-scoped bans stay.
func TestSetOwnerScopePurgesForeignHostRules(t *testing.T) {
	manager, runner := gatedManager(t)
	manager.admitAllTenants = true // the pre-fix agent applied anything
	for _, version := range []FirewallVersion{
		hostVersion("a-old", "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", ownerTenantA, ownerSiteA, "global", "192.0.2.0/24", ProtocolAny, 0),
		hostVersion("b-ban", "ffffffff-ffff-4fff-8fff-ffffffffffff", ownerTenantB, ownerSiteB, PolicyKindCCBan, "198.51.100.9/32", ProtocolTCP, 8443),
	} {
		if result, err := manager.Apply(context.Background(), version); err != nil || result.State != StateApplied {
			t.Fatalf("seed %s: result=%+v err=%v", version.TaskID, result, err)
		}
	}
	manager.admitAllTenants = false
	if err := manager.SetOwnerScope(context.Background(), platformID); err != nil {
		t.Fatal(err)
	}
	batch := runner.lastBatch()
	if strings.Contains(batch, "192.0.2.0/24") {
		t.Fatalf("tenant A's host rule survived on the shared node:\n%s", batch)
	}
	if !strings.Contains(batch, "198.51.100.9") {
		t.Fatalf("port-scoped ban of tenant B was purged:\n%s", batch)
	}
	if version, entries, err := manager.ScopeEntries(context.Background(), ownerTenantA, ownerSiteA, "global", ownerSiteA); err != nil || len(entries) != 0 || version != 0 {
		t.Fatalf("tenant A scope after purge: version=%d entries=%d err=%v", version, len(entries), err)
	}
	// A second learn with nothing foreign left changes nothing.
	_, applies, _ := runner.counts()
	if err := manager.SetOwnerScope(context.Background(), platformID); err != nil {
		t.Fatal(err)
	}
	if _, again, _ := runner.counts(); again != applies {
		t.Fatalf("idle owner refresh re-applied nftables (%d -> %d)", applies, again)
	}
}

// Compiler: the host chain has no tenant, site or destination match, which is
// why the gate sits before it. Two tenants' entries land in one input chain.
func TestCompilerHostChainCarriesNoTenantMatch(t *testing.T) {
	compiled, err := Compile(FirewallVersion{TaskID: "t", VersionID: "v", Aggregate: true, Entries: []Entry{
		{TenantID: ownerTenantA, SiteID: ownerSiteA, Action: ActionDeny, Network: "192.0.2.0/24", Protocol: ProtocolTCP, PortStart: 443, PortEnd: 443, Source: "global:x", Reason: "r"},
		{TenantID: ownerTenantB, SiteID: ownerSiteB, Action: ActionDeny, Network: "198.51.100.0/24", Protocol: ProtocolTCP, PortStart: 443, PortEnd: 443, Source: "global:y", Reason: "r"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	batch := string(compiled.Batch)
	if strings.Count(batch, "add chain ") != 1 || strings.Contains(batch, "daddr") || strings.Contains(batch, ownerTenantA) {
		t.Fatalf("host chain shape changed (gate assumptions no longer hold):\n%s", batch)
	}
	if !strings.Contains(batch, "192.0.2.0/24, 198.51.100.0/24") {
		t.Fatalf("two tenants' same-port entries were not merged into one host set:\n%s", batch)
	}
}
