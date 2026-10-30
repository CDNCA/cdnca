package firewall

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// Each kernel ban source gets its own set, an nft rule
// comment and a drop log tag; other scoped entries keep the shared form.
func TestCompileNamesKernelBanSources(t *testing.T) {
	tenant, site := "33333333-3333-4333-8333-333333333333", "22222222-2222-4222-8222-222222222222"
	expires := time.Unix(1_900_000_000, 0).UTC()
	ban := func(network, source string) Entry {
		return Entry{TenantID: tenant, SiteID: site, Action: ActionDeny, Network: network, Protocol: ProtocolTCP,
			PortStart: 443, PortEnd: 443, Source: source, Reason: "r", ExpiresAt: &expires}
	}
	compiled, err := Compile(FirewallVersion{TaskID: "t", VersionID: "v", Aggregate: true, Entries: []Entry{
		ban("198.51.100.1/32", PolicyKindCCBan), ban("198.51.100.2/32", PolicyKindWAFBan),
		ban("198.51.100.3/32", PolicyKindSecurityBan), ban("198.51.100.4/32", "l4_guard"),
	}})
	if err != nil {
		t.Fatalf("Compile() = %v", err)
	}
	batch := string(compiled.Batch)
	for _, fragment := range []string{
		`tcp dport 443 counter limit name "cdnca_drop_log" log prefix "cdnca-fw g1 cc_ban " drop comment "cc_ban"`,
		`tcp dport 443 drop comment "cc_ban"`,
		`log prefix "cdnca-fw g2 waf_ban " drop comment "waf_ban"`,
		`log prefix "cdnca-fw g3 security_ban " drop comment "security_ban"`,
		`log prefix "cdnca-fw g4" drop`,
	} {
		if !strings.Contains(batch, fragment) {
			t.Fatalf("batch lacks %q:\n%s", fragment, batch)
		}
	}
	if strings.Contains(batch, `comment "l4_guard"`) {
		t.Fatal("non-ban source got a ban comment")
	}
	// The drop log names the group, which still finds the entry.
	if groups := scopedGroups(compiled.Version.Entries); len(groups) != 4 || groups[1].key.source != PolicyKindWAFBan {
		t.Fatalf("groups = %+v", groups)
	}
}

// Card 5: on the real Manager, narrowing drops a site's ban entries on the
// ports it lost, emptying a scope withdraws it, and BanScopeSites follows.
func TestNarrowSourcedBansWithdrawsLostPorts(t *testing.T) {
	manager, _ := gatedManager(t)
	ctx := context.Background()
	if err := manager.SetOwnerScope(ctx, ownerTenantA); err != nil {
		t.Fatal(err)
	}
	now := fixedTime()
	client := netip.MustParseAddr("198.51.100.7")
	sockets := []BanSocket{{Protocol: ProtocolTCP, Port: 80, PortEnd: 80}, {Protocol: ProtocolTCP, Port: 8443, PortEnd: 8443}}
	for index, site := range []string{ownerSiteA, ownerSiteB} {
		if err := MergeSourcedBans(ctx, manager, ownerTenantA, site, SiteBanSources, 0, sockets,
			map[netip.Prefix]SourcedBan{netip.PrefixFrom(client, client.BitLen()): {Until: now.Add(time.Hour), Kind: PolicyKindCCBan}}, now, uint64(index+1)); err != nil {
			t.Fatal(err)
		}
	}
	sites, err := manager.BanScopeSites(ctx, []string{PolicyKindCCBan, PolicyKindWAFBan})
	if err != nil || len(sites) != 2 {
		t.Fatalf("BanScopeSites = %v, %v", sites, err)
	}
	kept, removed, err := NarrowSourcedBans(ctx, manager, ownerTenantA, ownerSiteA, SiteBanSources, 0, map[uint16]bool{80: true}, now, 3)
	if err != nil || len(kept) != 1 || kept[0].PortStart != 80 || len(removed) != 1 || removed[0].PortStart != 8443 {
		t.Fatalf("narrow: kept=%+v removed=%+v err=%v", kept, removed, err)
	}
	if _, entries, _ := manager.ScopeEntries(ctx, ownerTenantA, ownerSiteA, PolicyKindCCBan, ownerSiteA); len(entries) != 1 || entries[0].PortStart != 80 {
		t.Fatalf("A's scope = %+v", entries)
	}
	// Nothing lost: nothing applied (the policy version stays).
	before, _, _ := manager.ScopeEntries(ctx, ownerTenantA, ownerSiteA, PolicyKindCCBan, ownerSiteA)
	if _, removed, err := NarrowSourcedBans(ctx, manager, ownerTenantA, ownerSiteA, SiteBanSources, 0, map[uint16]bool{80: true}, now, 4); err != nil || len(removed) != 0 {
		t.Fatalf("no-op narrow: removed=%+v err=%v", removed, err)
	}
	if after, _, _ := manager.ScopeEntries(ctx, ownerTenantA, ownerSiteA, PolicyKindCCBan, ownerSiteA); after != before {
		t.Fatalf("no-op narrow applied: %d -> %d", before, after)
	}
	// Offline: every entry goes, the site leaves the list; B is untouched.
	if _, _, err := NarrowSourcedBans(ctx, manager, ownerTenantA, ownerSiteA, SiteBanSources, 0, nil, now, 5); err != nil {
		t.Fatal(err)
	}
	if _, entries, _ := manager.ScopeEntries(ctx, ownerTenantA, ownerSiteA, PolicyKindCCBan, ownerSiteA); len(entries) != 0 {
		t.Fatalf("offline site keeps %+v", entries)
	}
	sites, _ = manager.BanScopeSites(ctx, []string{PolicyKindCCBan})
	if len(sites) != 1 || sites[0] != [2]string{ownerTenantA, ownerSiteB} {
		t.Fatalf("BanScopeSites after offline = %v", sites)
	}
	if _, entries, _ := manager.ScopeEntries(ctx, ownerTenantA, ownerSiteB, PolicyKindCCBan, ownerSiteB); len(entries) != 2 {
		t.Fatalf("B's scope = %+v", entries)
	}
}
