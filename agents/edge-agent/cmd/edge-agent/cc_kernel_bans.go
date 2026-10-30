package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/firewall"
	"github.com/cdnca/cdnca/libs/edgeconfig/securityban"
	"github.com/google/uuid"
)

// ccKernelBans raises the CC engine's temporary bans of a client to the
// node's kernel firewall (DDoS protection cc_kernel_ban): the
// runtime status poller drains <health>/cc-kernel-bans each second; each
// site's bans become a firewall scope (kind cc_ban, policy = site) of deny
// entries on the site's ports that expire with the ban. Bans not applied are
// retried until they end. The OpenResty ban stands either way.
type ccKernelBans struct {
	firewall firewall.ScopedFirewall
	ports    func(tenantScopeID, siteID string) []uint16
	now      func() time.Time
	pending  map[[2]string]map[netip.Prefix]firewall.SourcedBan
	attempts uint64
	// mirror also writes each site's bans to the XDP filter.
	mirror func(map[netip.Addr]time.Time, []uint16)
	// topology names what the ban ports derive from (the active index
	// generation and the node owner); when it changes, applied bans are
	// narrowed to the sites' current ports (card 5). nil: never narrowed.
	topology func() string
	// lastTopology moves only once every site narrowed, so a failed
	// narrowing is retried with the next drain.
	lastTopology string
	// withdraw deletes XDP port bans (client -> ports) no applied entry
	// covers any more.
	withdraw func(map[netip.Addr][]uint16)
}

// banScopeLister lists the sites with applied ban scopes (firewall.Manager).
type banScopeLister interface {
	BanScopeSites(ctx context.Context, kinds []string) ([][2]string, error)
}

// ccKernelBanMaxEntriesPerSite bounds one site's kernel entries.
const ccKernelBanMaxEntriesPerSite = 4096

// sharedNodeBanPorts resolves a site's kernel ban ports: the configured mode
// on a node the site's tenant owns, at most its exclusive ports elsewhere
// (A08). The resolved ports feed both XDP and nftables.
func sharedNodeBanPorts(owned func(string) bool, own, shared func(string, string) []uint16) func(string, string) []uint16 {
	return func(tenantScopeID, siteID string) []uint16 {
		if owned(tenantScopeID) {
			return own(tenantScopeID, siteID)
		}
		return shared(tenantScopeID, siteID)
	}
}

func newCCKernelBans(fw firewall.ScopedFirewall, ports func(string, string) []uint16, now func() time.Time) *ccKernelBans {
	if fw == nil || ports == nil || now == nil {
		return nil
	}
	return &ccKernelBans{firewall: fw, ports: ports, now: now, pending: map[[2]string]map[netip.Prefix]firewall.SourcedBan{}}
}

var errCCKernelBanLine = errors.New("invalid CC kernel ban line")

// Kernel ban line sources: the optional fifth field of
// "<tenant scope>|<site>|<client>|<until>[|<source>]"; none is a CC ban (the
// CC engine's own lines).
const (
	kernelBanSourceCC          = "cc"
	kernelBanSourceWAF         = "waf"
	kernelBanSourceSecurityBan = "securityban"
)

var kernelBanKinds = map[string]string{
	kernelBanSourceCC:          firewall.PolicyKindCCBan,
	kernelBanSourceWAF:         firewall.PolicyKindWAFBan,
	kernelBanSourceSecurityBan: firewall.PolicyKindSecurityBan,
}

// parseCCKernelBan parses a kernel ban line; kind is the firewall policy
// kind of its source. client is a full-length prefix, or a network for a ban
// list line (BAN_CIDR: canonical as the list carries it).
func parseCCKernelBan(line string) (site [2]string, client netip.Prefix, until time.Time, kind string, err error) {
	parts := strings.Split(line, "|")
	kind = firewall.PolicyKindCCBan
	if len(parts) == 5 {
		var known bool
		if kind, known = kernelBanKinds[parts[4]]; !known {
			return [2]string{}, netip.Prefix{}, time.Time{}, "", errCCKernelBanLine
		}
		parts = parts[:4]
	}
	if len(parts) != 4 || uuid.Validate(parts[0]) != nil || uuid.Validate(parts[1]) != nil ||
		strings.ToLower(parts[0]) != parts[0] || strings.ToLower(parts[1]) != parts[1] {
		return [2]string{}, netip.Prefix{}, time.Time{}, "", errCCKernelBanLine
	}
	if securityban.IsNetwork(parts[2]) {
		canonical, ok := securityban.CanonicalClient(parts[2])
		if kind != firewall.PolicyKindSecurityBan || !ok || canonical != parts[2] {
			return [2]string{}, netip.Prefix{}, time.Time{}, "", errCCKernelBanLine
		}
		client = netip.MustParsePrefix(canonical)
	} else {
		address, err := netip.ParseAddr(parts[2])
		if err != nil || address.Zone() != "" || address.Is4In6() || address.IsUnspecified() || address.IsLoopback() {
			return [2]string{}, netip.Prefix{}, time.Time{}, "", errCCKernelBanLine
		}
		client = netip.PrefixFrom(address, address.BitLen())
	}
	seconds, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil || seconds < 1 {
		return [2]string{}, netip.Prefix{}, time.Time{}, "", errCCKernelBanLine
	}
	return [2]string{parts[0], parts[1]}, client, time.Unix(seconds, 0).UTC(), kind, nil
}

// step takes the drained lines and applies every site with bans.
func (bans *ccKernelBans) step(ctx context.Context, body []byte) {
	now := bans.now().UTC()
	bans.narrow(ctx, now)
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 512), 512)
	for scanner.Scan() {
		site, client, until, kind, err := parseCCKernelBan(scanner.Text())
		if err != nil || !until.After(now.Add(firewall.BanMergeMargin)) {
			continue
		}
		if bans.pending[site] == nil {
			bans.pending[site] = map[netip.Prefix]firewall.SourcedBan{}
		}
		// Several sources of one client: the ban that ends last, and its source.
		if until.After(bans.pending[site][client].Until) {
			bans.pending[site][client] = firewall.SourcedBan{Until: until, Kind: kind}
		}
	}
	sites := make([][2]string, 0, len(bans.pending))
	for site := range bans.pending {
		sites = append(sites, site)
	}
	sort.Slice(sites, func(i, j int) bool { return sites[i][0]+sites[i][1] < sites[j][0]+sites[j][1] })
	for _, site := range sites {
		ports := bans.ports(site[0], site[1])
		if len(ports) == 0 {
			// Off, or no port of its own: the OpenResty ban is the whole ban.
			delete(bans.pending, site)
			continue
		}
		sockets := make([]firewall.BanSocket, len(ports))
		for index, port := range ports {
			sockets[index] = firewall.BanSocket{Protocol: firewall.ProtocolTCP, Port: port, PortEnd: port}
		}
		if bans.mirror != nil {
			// XDP drops by client and port only; the source does not matter
			// there. It matches exact clients: networks stay with nftables.
			until := make(map[netip.Addr]time.Time, len(bans.pending[site]))
			for client, ban := range bans.pending[site] {
				if client.IsSingleIP() {
					until[client.Addr()] = ban.Until
				}
			}
			bans.mirror(until, ports)
		}
		bans.attempts++
		err := firewall.MergeSourcedBans(ctx, bans.firewall, site[0], site[1], firewall.SiteBanSources,
			ccKernelBanMaxEntriesPerSite, sockets, bans.pending[site], now, bans.attempts)
		if err == nil {
			delete(bans.pending, site)
			continue
		}
		slog.Warn("kernel bans not applied", "site_id", site[1], "sources", pendingKinds(bans.pending[site]), "error", err)
		for client, ban := range bans.pending[site] {
			if !ban.Until.After(now.Add(firewall.BanMergeMargin)) {
				delete(bans.pending[site], client)
			}
		}
		if len(bans.pending[site]) == 0 {
			delete(bans.pending, site)
		}
	}
}

// narrow withdraws, after a topology change, the applied bans on ports a
// site no longer bans on (a port turned shared, the site went offline, the
// mode or the node owner changed). MergeSourcedBans only adds; this is the
// only path that takes ports away.
func (bans *ccKernelBans) narrow(ctx context.Context, now time.Time) {
	lister, ok := bans.firewall.(banScopeLister)
	if bans.topology == nil || !ok {
		return
	}
	topology := bans.topology()
	if topology == bans.lastTopology {
		return
	}
	kinds := make([]string, len(firewall.SiteBanSources))
	for index, source := range firewall.SiteBanSources {
		kinds[index] = source.Kind
	}
	sites, err := lister.BanScopeSites(ctx, kinds)
	if err != nil {
		slog.Warn("kernel bans not narrowed", "error", err)
		return
	}
	sort.Slice(sites, func(i, j int) bool { return sites[i][0]+sites[i][1] < sites[j][0]+sites[j][1] })
	type pair struct {
		client netip.Addr
		port   uint16
	}
	covered, lost := map[pair]bool{}, map[pair]bool{}
	collect := func(entries []firewall.Entry, into map[pair]bool) {
		for _, entry := range entries {
			prefix, err := netip.ParsePrefix(entry.Network)
			if err != nil || prefix.Bits() != prefix.Addr().BitLen() || entry.PortStart == 0 || entry.PortStart != entry.PortEnd {
				continue
			}
			into[pair{prefix.Addr(), entry.PortStart}] = true
		}
	}
	done := true
	for _, site := range sites {
		allowed := map[uint16]bool{}
		for _, port := range bans.ports(site[0], site[1]) {
			allowed[port] = true
		}
		bans.attempts++
		kept, removed, err := firewall.NarrowSourcedBans(ctx, bans.firewall, site[0], site[1], firewall.SiteBanSources,
			ccKernelBanMaxEntriesPerSite, allowed, now, bans.attempts)
		collect(kept, covered)
		collect(removed, lost)
		if err != nil {
			done = false
			slog.Warn("kernel bans not narrowed", "site_id", site[1], "error", err)
		}
	}
	if bans.withdraw != nil {
		// XDP keys by client and port only: keep a pair another site covers.
		clients := map[netip.Addr][]uint16{}
		for item := range lost {
			if !covered[item] {
				clients[item.client] = append(clients[item.client], item.port)
			}
		}
		if len(clients) != 0 {
			bans.withdraw(clients)
		}
	}
	if done {
		bans.lastTopology = topology
	}
}

// pendingKinds names the sources of a site's pending bans (for the log).
func pendingKinds(pending map[netip.Prefix]firewall.SourcedBan) []string {
	seen := map[string]bool{}
	var kinds []string
	for _, ban := range pending {
		if !seen[ban.Kind] {
			seen[ban.Kind] = true
			kinds = append(kinds, ban.Kind)
		}
	}
	sort.Strings(kinds)
	return kinds
}

// withCCKernelBans drains the CC engine's bans into the kernel firewall.
func (poller *runtimeStatusPoller) withCCKernelBans(bans *ccKernelBans) *runtimeStatusPoller {
	if poller != nil && bans != nil {
		poller.ccBans = bans
	}
	return poller
}

// withWAFKernelBans also raises WAF automatic bans and listed bans
// and keeps the applied ban list in the runtime.
func (poller *runtimeStatusPoller) withWAFKernelBans(tenant func(siteID string) string, bans *securityBanRuntime) *runtimeStatusPoller {
	if poller != nil && tenant != nil {
		poller.siteTenant, poller.securityBans = tenant, bans
	}
	return poller
}

func (poller *runtimeStatusPoller) pollCCKernelBans(ctx context.Context) {
	if poller.ccBans == nil {
		return
	}
	body, err := poller.get(ctx, ccKernelBansSuffix)
	if errors.Is(err, errRuntimeStatusAbsent) {
		body = nil
	} else if err != nil {
		slog.Warn("CC kernel bans unavailable", "error", err)
		body = nil
	}
	// WAF automatic bans join the same kernel ban path
	// (cdnca_banlist queue "<site>|<client>|<until>"; the site's tenant scope
	// from the running sites).
	if poller.siteTenant != nil {
		waf, err := poller.get(ctx, securityBansSuffix)
		switch {
		case errors.Is(err, errRuntimeStatusAbsent):
		case err != nil:
			slog.Warn("WAF kernel bans unavailable", "error", err)
		default:
			body = append(append(body, '\n'), wafKernelBanLines(waf, poller.siteTenant, kernelBanSourceWAF)...)
		}
		// Listed bans (another node's automatic ban, manual bans) too.
		body = append(append(body, '\n'), wafKernelBanLines(poller.securityBans.drainKernel(), poller.siteTenant, kernelBanSourceSecurityBan)...)
	}
	poller.ccBans.step(ctx, body)
}

// wafKernelBanLines turns WAF queue lines into kernel ban lines of source
// ("<tenant scope>|<site>|<client>|<until>|<source>"); a site not running
// here is dropped.
func wafKernelBanLines(body []byte, tenant func(siteID string) string, source string) []byte {
	var output bytes.Buffer
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 512), 512)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), "|")
		if len(parts) != 3 {
			continue
		}
		scope := tenant(parts[0])
		if scope == "" {
			continue
		}
		output.WriteString(scope + "|" + scanner.Text() + "|" + source + "\n")
	}
	return output.Bytes()
}
