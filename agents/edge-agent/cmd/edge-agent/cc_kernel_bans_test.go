package main

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/firewall"
	"github.com/google/uuid"
)

type ccBanFirewall struct {
	versions []firewall.FirewallVersion
	active   map[string][]firewall.Entry
	fail     bool
	listFail bool
}

func (fw *ccBanFirewall) ScopeEntries(_ context.Context, _, siteID, kind, _ string) (uint64, []firewall.Entry, error) {
	entries := fw.active[kind+siteID]
	return uint64(len(fw.versions)), entries, nil
}

func (fw *ccBanFirewall) Apply(_ context.Context, version firewall.FirewallVersion) (firewall.Result, error) {
	if fw.fail {
		return firewall.Result{State: firewall.StateRolledBack, ErrorCode: "APPLY_FAILED"}, nil
	}
	fw.versions = append(fw.versions, version)
	fw.active[version.PolicyKind+version.SiteID] = version.Entries
	return firewall.Result{State: firewall.StateApplied}, nil
}

func TestCCKernelBansWritePortScopedExpiringEntries(t *testing.T) {
	tenant, site, other := uuid.NewString(), uuid.NewString(), uuid.NewString()
	now := time.Unix(1_800_000_000, 0).UTC()
	fw := &ccBanFirewall{active: map[string][]firewall.Entry{}}
	ports := map[string][]uint16{site: {80, 443}}
	bans := newCCKernelBans(fw, func(_, siteID string) []uint16 { return ports[siteID] }, func() time.Time { return now })
	line := func(siteID, client string, until time.Time) string {
		return fmt.Sprintf("%s|%s|%s|%d", tenant, siteID, client, until.Unix())
	}
	bans.step(t.Context(), []byte(strings.Join([]string{
		line(site, "198.51.100.7", now.Add(10*time.Minute)), line(site, "2001:db8::7", now.Add(time.Minute)),
		line(site, "198.51.100.8", now.Add(time.Second)), // ends within the margin
		line(other, "198.51.100.9", now.Add(time.Hour)),  // no port of its own
		"garbage", tenant + "|" + site + "|127.0.0.1|" + fmt.Sprint(now.Add(time.Hour).Unix()),
	}, "\n")))
	if len(fw.versions) != 1 {
		t.Fatalf("applies = %d", len(fw.versions))
	}
	version := fw.versions[0]
	if version.PolicyKind != firewall.PolicyKindCCBan || version.PolicyID != site || version.TenantID != tenant || len(version.Entries) != 4 {
		t.Fatalf("version = %+v", version)
	}
	for _, entry := range version.Entries {
		if entry.Protocol != firewall.ProtocolTCP || entry.PortStart != entry.PortEnd || (entry.PortStart != 80 && entry.PortStart != 443) ||
			entry.ExpiresAt == nil || (entry.Network != "198.51.100.7/32" && entry.Network != "2001:db8::7/128") {
			t.Fatalf("entry = %+v", entry)
		}
	}
	if _, err := firewall.Compile(firewall.FirewallVersion{TaskID: "check", VersionID: "check", Entries: version.Entries, Aggregate: true}); err != nil {
		t.Fatalf("entries do not compile: %v", err)
	}
	// A failed apply is retried with the next drain.
	fw.fail = true
	bans.step(t.Context(), []byte(line(site, "203.0.113.5", now.Add(time.Hour))))
	fw.fail = false
	bans.step(t.Context(), nil)
	if len(fw.versions) != 2 || len(fw.versions[1].Entries) != 6 {
		t.Fatalf("retry: %d versions", len(fw.versions))
	}
}

// CC (no source field), WAF and ban list lines become kernel
// entries of their own kind / source / reason; one client banned by several
// sources keeps the ban that ends last, in the scope of that source.
func TestKernelBansNameTheirSourceAndMergeByLatestEnd(t *testing.T) {
	tenant, site := uuid.NewString(), uuid.NewString()
	now := time.Unix(1_800_000_000, 0).UTC()
	fw := &ccBanFirewall{active: map[string][]firewall.Entry{}}
	bans := newCCKernelBans(fw, func(_, siteID string) []uint16 { return []uint16{443} }, func() time.Time { return now })
	line := func(client string, until time.Duration, source string) string {
		text := fmt.Sprintf("%s|%s|%s|%d", tenant, site, client, now.Add(until).Unix())
		if source != "" {
			text += "|" + source
		}
		return text
	}
	scope := func(kind string) map[string]firewall.Entry {
		entries := map[string]firewall.Entry{}
		for _, entry := range fw.active[kind+site] {
			entries[entry.Network] = entry
		}
		return entries
	}
	bans.step(t.Context(), []byte(strings.Join([]string{
		line("198.51.100.1", 10*time.Minute, ""),
		line("198.51.100.2", 5*time.Minute, "waf"),
		line("198.51.100.3", 20*time.Minute, "securityban"),
		line("198.51.100.4", time.Hour, "nonsense"), // unknown source: refused
	}, "\n")))
	want := map[string]struct{ network, source, reason string }{
		firewall.PolicyKindCCBan:       {"198.51.100.1/32", "cc_ban", "cc temporary ban"},
		firewall.PolicyKindWAFBan:      {"198.51.100.2/32", "waf_ban", "waf temporary ban"},
		firewall.PolicyKindSecurityBan: {"198.51.100.3/32", "security_ban", "security ban list"},
	}
	if len(fw.versions) != 3 {
		t.Fatalf("applies = %d, want one per source", len(fw.versions))
	}
	for kind, expected := range want {
		entries := scope(kind)
		entry, ok := entries[expected.network]
		if len(entries) != 1 || !ok || entry.Source != expected.source || entry.Reason != expected.reason {
			t.Fatalf("%s scope = %+v", kind, fw.active[kind+site])
		}
	}

	// The same client from WAF ending later: it moves to the WAF scope (WAF
	// applied first, then CC loses it), and the source is WAF.
	applied := len(fw.versions)
	bans.step(t.Context(), []byte(line("198.51.100.1", 30*time.Minute, "waf")))
	if got := fw.versions[applied:]; len(got) != 2 || got[0].PolicyKind != firewall.PolicyKindWAFBan || got[1].PolicyKind != firewall.PolicyKindCCBan {
		t.Fatalf("move applies = %+v", got)
	}
	if entry, ok := scope(firewall.PolicyKindWAFBan)["198.51.100.1/32"]; !ok || !entry.ExpiresAt.Equal(now.Add(30*time.Minute)) {
		t.Fatalf("WAF scope = %+v", fw.active[firewall.PolicyKindWAFBan+site])
	}
	if _, ok := scope(firewall.PolicyKindCCBan)["198.51.100.1/32"]; ok {
		t.Fatal("CC scope keeps the client WAF outlasts")
	}

	// A ban ending earlier from another source changes nothing.
	applied = len(fw.versions)
	bans.step(t.Context(), []byte(line("198.51.100.1", time.Minute, "securityban")+"\n"+line("198.51.100.1", time.Minute, "")))
	if len(fw.versions) != applied {
		t.Fatalf("earlier bans applied %d versions", len(fw.versions)-applied)
	}

	// Two sources in one drain: the later end wins with its source.
	bans.step(t.Context(), []byte(line("203.0.113.9", 2*time.Hour, "")+"\n"+line("203.0.113.9", time.Hour, "waf")))
	if _, ok := scope(firewall.PolicyKindCCBan)["203.0.113.9/32"]; !ok {
		t.Fatal("later CC ban not in the CC scope")
	}
	if _, ok := scope(firewall.PolicyKindWAFBan)["203.0.113.9/32"]; ok {
		t.Fatal("earlier WAF ban also written")
	}
}

// BanScopeSites lists the sites with applied ban entries (the narrowing
// pass's input), as firewall.Manager does.
func (fw *ccBanFirewall) BanScopeSites(_ context.Context, kinds []string) ([][2]string, error) {
	if fw.listFail {
		return nil, fmt.Errorf("list failed")
	}
	seen := map[[2]string]bool{}
	var sites [][2]string
	for _, version := range fw.versions {
		for _, kind := range kinds {
			if version.PolicyKind == kind && len(fw.active[kind+version.SiteID]) != 0 && !seen[[2]string{version.TenantID, version.SiteID}] {
				seen[[2]string{version.TenantID, version.SiteID}] = true
				sites = append(sites, [2]string{version.TenantID, version.SiteID})
			}
		}
	}
	return sites, nil
}

// Card 5: applied kernel bans follow the topology. When site A's port turns
// shared (another site goes live on it) or A goes offline, its bans on the
// lost ports are withdrawn from nftables and XDP on the next drain after the
// topology changes; an unchanged topology applies nothing; a failed narrowing
// is retried until it lands.
func TestKernelBansNarrowWhenTopologyChanges(t *testing.T) {
	tenant, siteA, siteB := uuid.NewString(), uuid.NewString(), uuid.NewString()
	now := time.Unix(1_800_000_000, 0).UTC()
	fw := &ccBanFirewall{active: map[string][]firewall.Entry{}}
	ports := map[string][]uint16{siteA: {80, 8443}, siteB: {9443}}
	topology := "g1"
	bans := newCCKernelBans(fw, func(_, siteID string) []uint16 { return ports[siteID] }, func() time.Time { return now })
	bans.topology = func() string { return topology }
	var withdrawn []string
	bans.mirror = func(map[netip.Addr]time.Time, []uint16) {}
	bans.withdraw = func(clients map[netip.Addr][]uint16) {
		for client, lost := range clients {
			for _, port := range lost {
				withdrawn = append(withdrawn, fmt.Sprintf("%s:%d", client, port))
			}
		}
	}
	line := func(siteID, client string, source string) string {
		text := fmt.Sprintf("%s|%s|%s|%d", tenant, siteID, client, now.Add(time.Hour).Unix())
		if source != "" {
			text += "|" + source
		}
		return text
	}
	portsOf := func(kind, siteID string) map[uint16]bool {
		got := map[uint16]bool{}
		for _, entry := range fw.active[kind+siteID] {
			got[entry.PortStart] = true
		}
		return got
	}
	bans.step(t.Context(), []byte(strings.Join([]string{
		line(siteA, "198.51.100.1", ""), line(siteA, "198.51.100.2", "waf"), line(siteB, "198.51.100.3", ""),
	}, "\n")))
	if got := portsOf(firewall.PolicyKindCCBan, siteA); len(got) != 2 || !got[80] || !got[8443] {
		t.Fatalf("A's CC scope ports = %v", got)
	}

	// The topology does not change: nothing is applied.
	applied := len(fw.versions)
	bans.step(t.Context(), nil)
	bans.step(t.Context(), nil)
	if len(fw.versions) != applied || len(withdrawn) != 0 {
		t.Fatalf("unchanged topology applied %d versions, withdrew %v", len(fw.versions)-applied, withdrawn)
	}

	// Exclusive -> shared: another site goes live on 8443; A keeps only 80.
	ports[siteA] = []uint16{80}
	topology = "g2"
	bans.step(t.Context(), nil)
	for _, kind := range []string{firewall.PolicyKindCCBan, firewall.PolicyKindWAFBan} {
		if got := portsOf(kind, siteA); len(got) != 1 || !got[80] {
			t.Fatalf("A's %s scope after narrowing = %v", kind, got)
		}
	}
	if got := portsOf(firewall.PolicyKindCCBan, siteB); len(got) != 1 || !got[9443] {
		t.Fatalf("B's scope changed: %v", got)
	}
	if strings.Join(sortedStrings(withdrawn), ",") != "198.51.100.1:8443,198.51.100.2:8443" {
		t.Fatalf("XDP withdrawn = %v", withdrawn)
	}
	if got := len(fw.versions) - applied; got != 2 {
		t.Fatalf("narrowing applied %d versions, want A's CC and WAF scopes", got)
	}

	// A failed narrowing is retried with the next drain (same topology).
	withdrawn = nil
	ports[siteA] = nil // A goes offline
	topology = "g3"
	fw.fail = true
	bans.step(t.Context(), nil)
	if len(portsOf(firewall.PolicyKindCCBan, siteA)) == 0 {
		t.Fatal("failed apply changed the scope")
	}
	fw.fail = false
	applied = len(fw.versions)
	bans.step(t.Context(), nil)
	if len(fw.active[firewall.PolicyKindCCBan+siteA]) != 0 || len(fw.active[firewall.PolicyKindWAFBan+siteA]) != 0 {
		t.Fatalf("offline site keeps bans: %+v", fw.active)
	}
	if len(fw.versions)-applied != 2 {
		t.Fatalf("retry applied %d versions", len(fw.versions)-applied)
	}
	if strings.Join(sortedStrings(withdrawn), ",") != "198.51.100.1:80,198.51.100.2:80" {
		t.Fatalf("XDP withdrawn = %v", withdrawn)
	}
	// Done: the next drains apply nothing.
	applied = len(fw.versions)
	bans.step(t.Context(), nil)
	if len(fw.versions) != applied {
		t.Fatal("narrowing repeated after it landed")
	}
}

// XDP port bans are keyed by client and port only: a pair another site's
// applied entry still covers is not withdrawn.
func TestKernelBansNarrowKeepsXDPPairsOtherSitesCover(t *testing.T) {
	tenant, siteA, siteB := uuid.NewString(), uuid.NewString(), uuid.NewString()
	now := time.Unix(1_800_000_000, 0).UTC()
	fw := &ccBanFirewall{active: map[string][]firewall.Entry{}}
	ports := map[string][]uint16{siteA: {443}, siteB: {443}} // site_ports on an owned node
	topology := "g1"
	bans := newCCKernelBans(fw, func(_, siteID string) []uint16 { return ports[siteID] }, func() time.Time { return now })
	bans.topology = func() string { return topology }
	var withdrawn []string
	bans.withdraw = func(clients map[netip.Addr][]uint16) {
		for client, lost := range clients {
			for _, port := range lost {
				withdrawn = append(withdrawn, fmt.Sprintf("%s:%d", client, port))
			}
		}
	}
	until := now.Add(time.Hour).Unix()
	bans.step(t.Context(), []byte(fmt.Sprintf("%s|%s|198.51.100.1|%d\n%s|%s|198.51.100.1|%d\n%s|%s|198.51.100.2|%d",
		tenant, siteA, until, tenant, siteB, until, tenant, siteA, until)))
	ports[siteA] = nil
	topology = "g2"
	bans.step(t.Context(), nil)
	if len(fw.active[firewall.PolicyKindCCBan+siteA]) != 0 || len(fw.active[firewall.PolicyKindCCBan+siteB]) != 1 {
		t.Fatalf("scopes = %+v", fw.active)
	}
	if strings.Join(withdrawn, ",") != "198.51.100.2:443" {
		t.Fatalf("XDP withdrawn = %v, want only the pair B does not cover", withdrawn)
	}
}

func sortedStrings(values []string) []string {
	values = append([]string(nil), values...)
	sort.Strings(values)
	return values
}

// A08: the ban ports of a site follow the configured mode only where its
// tenant owns the node; elsewhere they come from the shared (exclusive) rule.
func TestSharedNodeBanPortsChoosesByOwner(t *testing.T) {
	own := func(string, string) []uint16 { return []uint16{80, 8080} }
	shared := func(string, string) []uint16 { return []uint16{8080} }
	ports := sharedNodeBanPorts(func(scope string) bool { return scope == "owner" }, own, shared)
	if got := ports("owner", "s"); len(got) != 2 {
		t.Fatalf("owned node ports %v", got)
	}
	if got := ports("tenant", "s"); len(got) != 1 || got[0] != 8080 {
		t.Fatalf("shared node ports %v", got)
	}
}

// A ban list network becomes one prefix entry (nft interval set
// element) per port; CC / WAF lines stay single addresses; XDP gets only the
// single addresses (it matches exact clients).
func TestKernelBansWriteBanListNetworks(t *testing.T) {
	tenant, site := uuid.NewString(), uuid.NewString()
	now := time.Unix(1_800_000_000, 0).UTC()
	fw := &ccBanFirewall{active: map[string][]firewall.Entry{}}
	bans := newCCKernelBans(fw, func(_, _ string) []uint16 { return []uint16{443} }, func() time.Time { return now })
	var mirrored []string
	bans.mirror = func(clients map[netip.Addr]time.Time, _ []uint16) {
		for client := range clients {
			mirrored = append(mirrored, client.String())
		}
	}
	line := func(client, source string) string {
		return fmt.Sprintf("%s|%s|%s|%d|%s", tenant, site, client, now.Add(time.Hour).Unix(), source)
	}
	bans.step(t.Context(), []byte(strings.Join([]string{
		line("192.0.2.0/24", "securityban"), line("2001:db8:5::/48", "securityban"), line("198.51.100.7", "securityban"),
		line("203.0.113.0/24", "waf"), line("192.0.2.7/24", "securityban"), line("10.0.0.0/7", "securityban"),
	}, "\n")))
	got := map[string]bool{}
	for _, entry := range fw.active[firewall.PolicyKindSecurityBan+site] {
		got[entry.Network] = true
	}
	if len(got) != 3 || !got["192.0.2.0/24"] || !got["2001:db8:5::/48"] || !got["198.51.100.7/32"] {
		t.Fatalf("security ban entries = %v", got)
	}
	if entries := fw.active[firewall.PolicyKindWAFBan+site]; len(entries) != 0 {
		t.Fatalf("WAF network written: %+v", entries)
	}
	if len(mirrored) != 1 || mirrored[0] != "198.51.100.7" {
		t.Fatalf("XDP mirror = %v", mirrored)
	}
	compiled, err := firewall.Compile(firewall.FirewallVersion{TaskID: "check", VersionID: "check",
		Entries: fw.active[firewall.PolicyKindSecurityBan+site], Aggregate: true})
	if err != nil {
		t.Fatalf("entries do not compile: %v", err)
	}
	if batch := string(compiled.Batch); !strings.Contains(batch, "192.0.2.0/24") || !strings.Contains(batch, "flags interval") {
		t.Fatalf("batch lacks the network interval element:\n%s", batch)
	}
}
