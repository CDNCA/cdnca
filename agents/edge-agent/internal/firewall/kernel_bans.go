package firewall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/google/uuid"
)

// Kernel bans the Agent raises itself (L4 guard bans, CC temporary bans):
// one scope per (tenant, site, kind, policy), entries per client and socket
// that expire with the ban. The expiry scheduler removes ended entries.

// PolicyKindCCBan scopes the kernel bans of a site's CC temporary bans:
// policy ID = site ID, applied locally, never by the
// control plane.
const PolicyKindCCBan = "cc_ban"

// PolicyKindWAFBan and PolicyKindSecurityBan scope a site's WAF automatic
// bans and ban list bans the same way.
const (
	PolicyKindWAFBan      = "waf_ban"
	PolicyKindSecurityBan = "security_ban"
)

// banSourceKinds are the sources whose entries get a group (nft set, rule
// comment, drop log tag) of their own.
var banSourceKinds = map[string]bool{PolicyKindCCBan: true, PolicyKindWAFBan: true, PolicyKindSecurityBan: true}

// BanSocket is a protocol and port range a ban covers.
type BanSocket struct {
	Protocol Protocol
	Port     uint16
	PortEnd  uint16
}

// BanScope names the scope of a set of kernel bans.
type BanScope struct {
	TenantID, SiteID, Kind, PolicyID string
	Source, Reason                   string
	// MaxEntries bounds the scope; the bans that end first are dropped.
	MaxEntries int
}

// ScopedFirewall is the part of Manager kernel bans use.
type ScopedFirewall interface {
	ScopeEntries(ctx context.Context, tenantID, siteID, policyKind, policyID string) (uint64, []Entry, error)
	Apply(context.Context, FirewallVersion) (Result, error)
}

// BanMergeMargin: entries closer to their end are not written.
const BanMergeMargin = 2 * time.Second

type banEntryKey struct {
	network  string
	protocol Protocol
	start    uint16
	end      uint16
}

// MergeBans merges bans (client -> until) on sockets into scope (unexpired
// entries kept, the later expiry wins) and applies it as the next policy
// version. attempt numbers the call so a retry is a task of its own. No
// change: nothing applied.
func MergeBans(ctx context.Context, fw ScopedFirewall, scope BanScope, sockets []BanSocket, bans map[netip.Addr]time.Time,
	now time.Time, attempt uint64) error {
	version, existing, err := fw.ScopeEntries(ctx, scope.TenantID, scope.SiteID, scope.Kind, scope.PolicyID)
	if err != nil {
		return err
	}
	merged := map[banEntryKey]Entry{}
	add := func(entry Entry) {
		if entry.ExpiresAt == nil || !entry.ExpiresAt.After(now.Add(BanMergeMargin)) {
			return
		}
		key := banEntryKey{entry.Network, entry.Protocol, entry.PortStart, entry.PortEnd}
		if previous, ok := merged[key]; ok && !entry.ExpiresAt.After(*previous.ExpiresAt) {
			return
		}
		merged[key] = entry
	}
	for _, entry := range existing {
		add(entry)
	}
	changed := false
	for client, until := range bans {
		network := netip.PrefixFrom(client, client.BitLen()).String()
		for _, socket := range sockets {
			expires := until
			key := banEntryKey{network, socket.Protocol, socket.Port, socket.PortEnd}
			if previous, ok := merged[key]; ok && !expires.After(*previous.ExpiresAt) {
				continue
			}
			if !expires.After(now.Add(BanMergeMargin)) {
				continue
			}
			changed = true
			add(Entry{TenantID: scope.TenantID, SiteID: scope.SiteID, Action: ActionDeny, Network: network,
				Protocol: key.protocol, PortStart: key.start, PortEnd: key.end, Source: scope.Source,
				Reason: scope.Reason, ExpiresAt: &expires})
		}
	}
	if !changed {
		return nil
	}
	entries := make([]Entry, 0, len(merged))
	for _, entry := range merged {
		entries = append(entries, entry)
	}
	return applyBanScope(ctx, fw, scope, version, entries, now, attempt)
}

// SiteBanSources are the kinds of a site's kernel bans:
// CC temporary bans, WAF automatic bans and ban list (security_ban) bans,
// one scope each so the nft rules, drop log and entries name the source.
var SiteBanSources = []BanSource{
	{Kind: PolicyKindCCBan, Source: PolicyKindCCBan, Reason: "cc temporary ban"},
	{Kind: PolicyKindWAFBan, Source: PolicyKindWAFBan, Reason: "waf temporary ban"},
	{Kind: PolicyKindSecurityBan, Source: PolicyKindSecurityBan, Reason: "security ban list"},
}

// BanSource is one kind of kernel bans on a site's ports.
type BanSource struct{ Kind, Source, Reason string }

// SourcedBan is when a client's ban ends and the kind that raised it.
type SourcedBan struct {
	Until time.Time
	Kind  string
}

type sourcedEntry struct {
	entry Entry
	kind  string
}

// MergeSourcedBans merges bans (client prefix -> ban) of several kinds on the
// same sockets of one site: per client and socket only the ban that ends last is kept, in the
// scope of the kind that raised it (an entry another kind outlasts leaves its
// scope). Scopes that gain entries are applied before scopes that only lose
// some, so a client stays banned while it moves between them.
func MergeSourcedBans(ctx context.Context, fw ScopedFirewall, tenantID, siteID string, sources []BanSource, maxEntries int,
	sockets []BanSocket, bans map[netip.Prefix]SourcedBan, now time.Time, attempt uint64) error {
	versions := make(map[string]uint64, len(sources))
	merged := map[banEntryKey]sourcedEntry{}
	gained, lost := map[string]bool{}, map[string]bool{}
	put := func(key banEntryKey, entry Entry, kind string, applied bool) bool {
		if entry.ExpiresAt == nil || !entry.ExpiresAt.After(now.Add(BanMergeMargin)) {
			return false
		}
		if previous, ok := merged[key]; ok {
			if !entry.ExpiresAt.After(*previous.entry.ExpiresAt) {
				if applied && previous.kind != kind {
					lost[kind] = true // an applied duplicate another kind outlasts
				}
				return false
			}
			if previous.kind != kind {
				lost[previous.kind] = true
			}
		}
		merged[key] = sourcedEntry{entry, kind}
		return true
	}
	for _, source := range sources {
		version, existing, err := fw.ScopeEntries(ctx, tenantID, siteID, source.Kind, siteID)
		if err != nil {
			return err
		}
		versions[source.Kind] = version
		for _, entry := range existing {
			put(banEntryKey{entry.Network, entry.Protocol, entry.PortStart, entry.PortEnd}, entry, source.Kind, true)
		}
	}
	byKind := make(map[string]BanSource, len(sources))
	for _, source := range sources {
		byKind[source.Kind] = source
	}
	for client, ban := range bans {
		source, ok := byKind[ban.Kind]
		if !ok {
			continue
		}
		// A client is an address (full-length prefix) or a ban list network,
		// an element of the scope's interval set either way.
		network := client.Masked().String()
		for _, socket := range sockets {
			expires := ban.Until
			key := banEntryKey{network, socket.Protocol, socket.Port, socket.PortEnd}
			if put(key, Entry{TenantID: tenantID, SiteID: siteID, Action: ActionDeny, Network: network,
				Protocol: key.protocol, PortStart: key.start, PortEnd: key.end, Source: source.Source,
				Reason: source.Reason, ExpiresAt: &expires}, source.Kind, false) {
				gained[source.Kind] = true
			}
		}
	}
	entries := map[string][]Entry{}
	for _, value := range merged {
		entries[value.kind] = append(entries[value.kind], value.entry)
	}
	for _, pass := range []func(string) bool{
		func(kind string) bool { return gained[kind] },
		func(kind string) bool { return !gained[kind] && lost[kind] },
	} {
		for _, source := range sources {
			if !pass(source.Kind) {
				continue
			}
			scope := BanScope{TenantID: tenantID, SiteID: siteID, Kind: source.Kind, PolicyID: siteID,
				Source: source.Source, Reason: source.Reason, MaxEntries: maxEntries}
			if err := applyBanScope(ctx, fw, scope, versions[source.Kind], entries[source.Kind], now, attempt); err != nil {
				return err
			}
		}
	}
	return nil
}

// NarrowSourcedBans withdraws a site's applied ban entries on ports no longer
// in allowed (the site's ban ports after a topology change; empty: every
// entry goes). Scopes that lose nothing are not applied. The kept and the
// removed entries are returned so the caller can withdraw the XDP mirror of
// the pairs no site covers any more.
func NarrowSourcedBans(ctx context.Context, fw ScopedFirewall, tenantID, siteID string, sources []BanSource, maxEntries int,
	allowed map[uint16]bool, now time.Time, attempt uint64) (kept, removed []Entry, err error) {
	for _, source := range sources {
		version, existing, err := fw.ScopeEntries(ctx, tenantID, siteID, source.Kind, siteID)
		if err != nil {
			return kept, removed, err
		}
		var stay, lost []Entry
		for _, entry := range existing {
			if entry.ExpiresAt == nil || !entry.ExpiresAt.After(now.Add(BanMergeMargin)) {
				continue // ends anyway (the expiry scheduler removes it)
			}
			if entry.PortStart != 0 && entry.PortStart == entry.PortEnd && allowed[entry.PortStart] {
				stay = append(stay, entry)
				continue
			}
			lost = append(lost, entry)
		}
		if len(lost) != 0 {
			scope := BanScope{TenantID: tenantID, SiteID: siteID, Kind: source.Kind, PolicyID: siteID,
				Source: source.Source, Reason: source.Reason, MaxEntries: maxEntries}
			if err := applyBanScope(ctx, fw, scope, version, stay, now, attempt); err != nil {
				return kept, removed, err
			}
			removed = append(removed, lost...)
		}
		kept = append(kept, stay...)
	}
	return kept, removed, nil
}

// BanScopeSites lists the (tenant, site) pairs with applied entries in a
// site ban scope (policy ID = site ID) of one of kinds.
func (m *Manager) BanScopeSites(ctx context.Context, kinds []string) ([][2]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	unlock, err := m.store.lock(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	active, err := m.store.loadActive()
	if err != nil || active == nil {
		return nil, err
	}
	wanted := make(map[string]bool, len(kinds))
	for _, kind := range kinds {
		wanted[kind] = true
	}
	seen := map[[2]string]bool{}
	var sites [][2]string
	for _, scope := range active.Scopes {
		site := [2]string{scope.TenantID, scope.SiteID}
		if !wanted[scope.PolicyKind] || scope.PolicyID != scope.SiteID || len(scope.Entries) == 0 || seen[site] {
			continue
		}
		seen[site] = true
		sites = append(sites, site)
	}
	return sites, nil
}

// applyBanScope applies entries as the next policy version of scope.
func applyBanScope(ctx context.Context, fw ScopedFirewall, scope BanScope, version uint64, entries []Entry,
	now time.Time, attempt uint64) error {
	// Keep the bans that last longest when over the bound.
	sort.Slice(entries, func(i, j int) bool {
		if !entries[i].ExpiresAt.Equal(*entries[j].ExpiresAt) {
			return entries[i].ExpiresAt.After(*entries[j].ExpiresAt)
		}
		if entries[i].Network != entries[j].Network {
			return entries[i].Network < entries[j].Network
		}
		if entries[i].Protocol != entries[j].Protocol {
			return entries[i].Protocol < entries[j].Protocol
		}
		return entries[i].PortStart < entries[j].PortStart
	})
	if scope.MaxEntries > 0 && len(entries) > scope.MaxEntries {
		entries = entries[:scope.MaxEntries]
	}
	next := version + 1
	// The firewall replays a task ID it has seen; every attempt (a retry of a
	// rolled back one included) is a task of its own.
	payload, _ := json.Marshal(struct {
		Kind     string  `json:"kind"`
		TenantID string  `json:"tenant_id"`
		SiteID   string  `json:"site_id"`
		PolicyID string  `json:"policy_id"`
		Version  uint64  `json:"policy_version"`
		At       int64   `json:"at"`
		Attempt  uint64  `json:"attempt"`
		Entries  []Entry `json:"entries"`
	}{scope.Kind, scope.TenantID, scope.SiteID, scope.PolicyID, next, now.UnixNano(), attempt, entries})
	digest := sha256.Sum256(payload)
	key := uuid.NewSHA1(uuid.NameSpaceOID, digest[:]).String()
	result, err := fw.Apply(ctx, FirewallVersion{
		TaskID: scope.Kind + "-" + key, TaskRevision: next, IdempotencyKey: key,
		TenantID: scope.TenantID, SiteID: scope.SiteID, PolicyKind: scope.Kind, PolicyID: scope.PolicyID,
		PolicyVersion: next, ExpectedActivePolicyVersion: version, Operation: OperationApply,
		RecoveryReason: RecoveryReasonNotApplicable, CommandDigest: hex.EncodeToString(digest[:]),
		VersionID: "runtime-" + key, Entries: entries,
	})
	if err != nil {
		return err
	}
	if result.State != StateApplied {
		return fmt.Errorf("%s kernel bans of %s: firewall %s %s", scope.Kind, scope.PolicyID, result.State, result.ErrorCode)
	}
	return nil
}
