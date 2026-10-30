package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynroute"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/edgeconfig/securityban"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
)

// Error page slot pages (errpage-3/4, CAPABILITY_NAME_ERROR_PAGE_SLOTS v1)
// on a real OpenResty: the six pages the node gives itself and the
// node > region > global pick of the area / node overrides.
//
//	待出包前全量跑（errpage-5 只写未跑）。运行：
//	  tests/dynroute-agent/run.sh
//	（MODSECURITY_RUNTIME=none 也覆盖本段：这里的 WAF 拦截走 WAF v2 规则，不依赖 CRS）
//
// Scenarios (edge/openresty Lua response points, errpage-content.md errpage-3):
//   - blacklist: a ban list snapshot (POST <health>/healthz/security-bans)
//     lists the client on a site with a WAF v2 action policy (cdnca_waf.gate
//     reads the list) -> 403 blacklist page, X-Cdnca-Ban listed; without the
//     page the built-in default page (fix-errpages); lifted by a newer snapshot;
//   - 403 vs WAF: an ACL block gets the http_403 page over the site's theme
//     edge_route 403 page, a WAF rule block keeps the theme page (waf_block),
//     a site's own (non-theme) edge_route 403 page beats http_403;
//   - traffic cap: 509 traffic_exceeded page for a site without its own
//     notice, the site's notice otherwise, v7's default notice without page;
//   - connection limit: Max 0 refuses with the connection_limit page (503),
//     a site's own edge_route 503 page beats it;
//   - node IP: an IPv4 / IPv6 literal Host gets node_ip_access, an unknown
//     name keeps unknown_site;
//   - package expired: 403 package_expired page, origin not reached, no cache
//     header; the built-in default page without it; ACME HTTP-01 still reaches origin;
//   - pick: node_ip_access pages for this node, its region and global ->
//     the node's; another node's + this region -> the region's; another
//     region -> the global one.
//   - 502 / 504 overrides (errpage-ovr): site page variants of edge_connect
//     on a site whose origin refuses (502) or stalls past the read timeout
//     (504): this node's 504 variant beats this region's, this region's 502
//     beats the theme page, another node's / region's variants leave the
//     theme page; a site without variants keeps the theme page.
//
// It needs its own runtime (HealthPort for the ban list, NodeID for the
// pick) and returns it as the run's current runtime. The node's region comes
// with the input (fz-x12: the control plane's key document node_region, not
// a node setting): slotRegion is the catalog code of a Chinese-named region
// (华东 → region-7), the code the error page overrides of that region name.
const (
	slotHealthPort = 18479
	slotNodeID     = "0d130000-0000-4000-8000-0000000000b1"
	slotRegion     = "region-7"
)

func slotPage(category, body string) dynroute.NodePage {
	return dynroute.NodePage{Category: category, Status: siteobject.SlotNodePageStatus[category], MIMEType: "text/html", Body: []byte(body)}
}

// slotSiteErrorPage is one site error page (edge_route) for status, its
// body stored in the object store; theme: the rule ID a theme's page has.
func slotSiteErrorPage(status int, body string, theme bool, asset string) ([]edgesite.ErrorPage, error) {
	if err := siteObjects.Put(edgesite.Digest([]byte(body)), []byte(body)); err != nil {
		return nil, err
	}
	id := fmt.Sprintf("site.edge_route.%d", status)
	if theme {
		id = fmt.Sprintf("theme.edge_route.%d", status)
	}
	return edgesite.ErrorPagesFor([]edgesite.ErrorPageRule{{ID: id, Category: edgesite.ErrorEdgeRoute, Codes: []int{status},
		MIMEType: "text/plain", Asset: edgesite.Ref{Kind: edgesite.RefErrorPageAsset, ID: asset, Revision: 1,
			SHA256: edgesite.Digest([]byte(body))}}}, nil)
}

// slotRule is a normalized security rule on a path prefix.
// slotConnectSite is a site with the theme's edge_connect 502 / 504 pages
// and variants (errpage-ovr): its default pool refuses (port 1: 502), /slow/
// goes to the origin with a 300 ms read timeout it outlasts (504).
func slotConnectSite(number int, host string, variants []edgesite.ErrorPageVariant) (edgesite.Site, error) {
	site := makeSite(number, host, 1, portPlain)
	slow := site.Origin.Pools[0]
	slow.ID, slow.Retry.ReadTimeoutMS = "slow", 300
	// own Endpoints: the primary pool's port 1 below must not reach /slow/
	slow.Endpoints = slices.Clone(slow.Endpoints)
	site.Origin.Pools[0].Endpoints[0].Port = 1
	site.Origin.Pools = append(site.Origin.Pools, slow)
	site.Origin.Routes = []edgesite.Route{{ID: "slow", Priority: 1, PathPrefix: "/slow/", PoolID: "slow"}}
	var rules []edgesite.ErrorPageRule
	for _, status := range []int{502, 504} {
		body := fmt.Sprintf("theme edge_connect %d\n", status)
		if err := siteObjects.Put(edgesite.Digest([]byte(body)), []byte(body)); err != nil {
			return site, err
		}
		rules = append(rules, edgesite.ErrorPageRule{ID: fmt.Sprintf("theme.edge_connect.%d", status), Category: edgesite.ErrorEdgeConnect,
			Codes: []int{status}, MIMEType: "text/plain", Asset: edgesite.Ref{Kind: edgesite.RefErrorPageAsset,
				ID: fmt.Sprintf("0d130000-0000-4000-8000-0000000005f%d", status-500), Revision: 1, SHA256: edgesite.Digest([]byte(body))}})
	}
	var err error
	if site.Errors, err = edgesite.ErrorPagesFor(rules, nil); err != nil {
		return site, err
	}
	for _, variant := range variants {
		body := variant.RuleID + "\n"
		if err := siteObjects.Put(edgesite.Digest([]byte(body)), []byte(body)); err != nil {
			return site, err
		}
	}
	site.ErrorVariants = variants
	return site, nil
}

// slotVariant is an edge_connect variant whose body is "<rule id>\n".
func slotVariant(status int, region, nodeID, ruleID string) edgesite.ErrorPageVariant {
	body := []byte(ruleID + "\n")
	return edgesite.ErrorPageVariant{Category: edgesite.ErrorEdgeConnect, Status: status, Region: region, NodeID: nodeID,
		RuleID: ruleID, MIMEType: "text/plain", Asset: edgesite.Ref{Kind: edgesite.RefErrorPageAsset,
			ID: "0d130000-0000-4000-8000-0000000005f9", Revision: 1, SHA256: edgesite.Digest(body)}}
}

func slotRule(id, prefix string, action edgeconfig.WAFAction, config *edgeconfig.WAFActionConfig) edgeconfig.WAFRule {
	rule, err := edgeconfig.NormalizeSecurityRule(edgeconfig.WAFRule{RuleID: id, Action: action, Control: edgeconfig.WAFStop,
		Match: edgeconfig.WAFMatch{Path: &edgeconfig.WAFPathMatch{Kind: edgeconfig.WAFPathPrefix, Value: prefix}}, ActionConfig: config})
	if err != nil {
		panic(fmt.Sprintf("slot rule %s: %v", id, err))
	}
	return rule
}

// withSlotSecurity: an ACL policy blocking /acl-block and a WAF v2 policy
// (a ban rule makes it a segment with an action spec, so cdnca_waf.gate
// reads the ban list) blocking /waf-block.
func withSlotSecurity(site edgesite.Site) edgesite.Site {
	site.Security.Rules.Policies = []edgesite.RulePolicy{
		{Kind: edgeconfig.SecurityACL, PolicyID: "0d130000-0000-4000-8000-0000000005a1", PolicyVersion: 1, BindingRevision: 1,
			RuntimeSHA256: strings.Repeat("5a", 32), Enabled: true, DefaultAction: edgeconfig.WAFAllow, Rules: []edgeconfig.WAFRule{
				slotRule("0d130000-0000-4000-8000-0000000005b1", "/acl-block", edgeconfig.WAFBlock, nil)}},
		{Kind: edgeconfig.SecurityWAF, PolicyID: "0d130000-0000-4000-8000-0000000005a2", PolicyVersion: 1, BindingRevision: 1,
			RuntimeSHA256: strings.Repeat("5b", 32), Enabled: true, DefaultAction: edgeconfig.WAFAllow, Rules: []edgeconfig.WAFRule{
				slotRule("0d130000-0000-4000-8000-0000000005b2", "/waf-block", edgeconfig.WAFBlock, nil),
				slotRule("0d130000-0000-4000-8000-0000000005b3", "/ban-me", edgeconfig.WAFBan, &edgeconfig.WAFActionConfig{BanSeconds: 300})}},
	}
	return site
}

func postBans(snapshot securityban.RuntimeSnapshot) (int, error) {
	raw, _ := json.Marshal(snapshot)
	response, err := (&http.Client{Timeout: 5 * time.Second}).Post(fmt.Sprintf("http://127.0.0.1:%d/healthz/security-bans", slotHealthPort),
		"application/json", bytes.NewReader(raw))
	if err != nil {
		return 0, err
	}
	_ = response.Body.Close()
	return response.StatusCode, nil
}

func checkSlotPages(h *harness, config dynroute.Config, previous *dynroute.Runtime, origin *originServer, others ...edgesite.Site) *dynroute.Runtime {
	ctx := h.ctx
	_ = previous.Stop(ctx)
	slotConfig := config
	slotConfig.HealthPort, slotConfig.NodeID = slotHealthPort, slotNodeID
	runtime, err := dynroute.New(slotConfig)
	if err == nil {
		err = runtime.Recover(ctx)
	}
	check("slot-pages-runtime", err == nil, "%v", err)
	if err != nil {
		return previous
	}
	h.runtime = runtime

	const (
		blacklistBody = "<p>slot blacklist</p>\n"
		http403Body   = "<p>slot http_403</p>\n"
		trafficBody   = "<p>slot traffic_exceeded</p>\n"
		expiredBody   = "<p>slot package_expired</p>\n"
		nodeIPBody    = "<p>slot node_ip_access</p>\n"
		limitBody     = "<p>slot connection_limit</p>\n"
		unknownBody   = "<p>node unknown_site</p>\n"
		themeBlock    = "theme edge_route 403\n"
		siteBlock     = "site own edge_route 403\n"
		site503       = "site own edge_route 503\n"
		ownNotice     = "<p>site own traffic notice</p>\n"
	)
	allPages := []dynroute.NodePage{
		{Category: siteobject.NodePageUnknownSite, Status: 404, MIMEType: "text/html", Body: []byte(unknownBody)},
		slotPage(siteobject.NodePageBlacklist, blacklistBody), slotPage(siteobject.NodePageHTTP403, http403Body),
		slotPage(siteobject.NodePageTrafficExceeded, trafficBody), slotPage(siteobject.NodePagePackageExpired, expiredBody),
		slotPage(siteobject.NodePageNodeIPAccess, nodeIPBody), slotPage(siteobject.NodePageConnectionLimit, limitBody),
	}
	// sites 30-37 (makeSite numbers unused by the other parts)
	themed := withSlotSecurity(makeSite(30, "guard.d13.test", 1, portPlain))
	themed.Errors, err = slotSiteErrorPage(403, themeBlock, true, "0d130000-0000-4000-8000-0000000005e1")
	check("slot-theme-page-fixture", err == nil, "%v", err)
	owned := withSlotSecurity(makeSite(31, "guard-own.d13.test", 1, portPlain))
	owned.Errors, err = slotSiteErrorPage(403, siteBlock, false, "0d130000-0000-4000-8000-0000000005e2")
	check("slot-site-page-fixture", err == nil, "%v", err)
	traffic := makeSite(32, "traffic.d13.test", 1, portPlain)
	traffic.TrafficLimit = &edgesite.TrafficLimit{Period: "daily"}
	noticed := makeSite(33, "notice.d13.test", 1, portPlain)
	noticed.TrafficLimit = &edgesite.TrafficLimit{Period: "monthly", NoticeHTML: ownNotice}
	limited := makeSite(34, "conn.d13.test", 1, portPlain)
	limited.Limits.Connections = &edgesite.Connections{SubscriptionID: "0d130000-0000-4000-8000-0000000005c1", Max: 0}
	limitedOwn := makeSite(35, "conn-own.d13.test", 1, portPlain)
	limitedOwn.Limits.Connections = &edgesite.Connections{SubscriptionID: "0d130000-0000-4000-8000-0000000005c2", Max: 0}
	limitedOwn.Errors, err = slotSiteErrorPage(503, site503, false, "0d130000-0000-4000-8000-0000000005e3")
	check("slot-site-503-fixture", err == nil, "%v", err)
	expired := withCache(makeSite(36, "expired.d13.test", 1, portPlain), 64<<20)
	expired.PackageExpired = true
	plain := makeSite(37, "plain.d13.test", 1, portPlain)
	// errpage-ovr: variants sorted by (category, status, node, region): a
	// region variant (no node) before the node ones
	const connectOtherNode = "0d130000-0000-4000-8000-0000000000b2"
	connect, err := slotConnectSite(38, "connect.d13.test", []edgesite.ErrorPageVariant{
		slotVariant(502, slotRegion, "", "slot.http_502.region.own"),
		slotVariant(502, "", connectOtherNode, "slot.http_502.node.other"),
		slotVariant(504, slotRegion, "", "slot.http_504.region.own"),
		slotVariant(504, "", slotNodeID, "slot.http_504.node.own"),
	})
	check("slot-connect-fixture", err == nil, "%v", err)
	elsewhere, err := slotConnectSite(39, "connect-elsewhere.d13.test", []edgesite.ErrorPageVariant{
		slotVariant(502, "", connectOtherNode, "slot.http_502.node.other"),
		slotVariant(504, "us-west", "", "slot.http_504.region.other"),
	})
	check("slot-connect-elsewhere-fixture", err == nil, "%v", err)
	connectPlain, err := slotConnectSite(40, "connect-plain.d13.test", nil)
	check("slot-connect-plain-fixture", err == nil, "%v", err)
	sites := append([]edgesite.Site{themed, owned, traffic, noticed, limited, limitedOwn, expired, plain,
		connect, elsewhere, connectPlain}, others...)

	h.input.NodePages, h.input.NodeRegion = allPages, slotRegion
	applied := h.apply("slot-pages-apply", sites...)
	check("slot-pages-reload", applied.Reloaded, "reloaded %v", applied.Reloaded)

	// ---------------------------------------------------- blacklist
	r := fetch(portPlain, "guard.d13.test", "/x", nil, nil)
	check("slot-blacklist-before-ban", r.status == 200, "%d %s", r.status, r.err)
	status, err := postBans(securityban.RuntimeSnapshot{Revision: 1, Releases: []securityban.RuntimeRelease{},
		Bans: []securityban.RuntimeBan{{SiteID: themed.SiteID, Client: "127.0.0.1", Until: time.Now().Add(10 * time.Minute).Unix()}}})
	check("slot-blacklist-snapshot", status == 200 && err == nil, "%d %v", status, err)
	r = fetch(portPlain, "guard.d13.test", "/x", nil, nil)
	check("slot-blacklist-page", r.status == 403 && r.body == blacklistBody && r.header.Get("X-Cdnca-Ban") == "listed" &&
		r.header.Get("Content-Length") == fmt.Sprint(len(blacklistBody)), "%d %q ban %q", r.status, r.body, r.header.Get("X-Cdnca-Ban"))
	r = fetch(portPlain, "guard-own.d13.test", "/x", nil, nil)
	check("slot-blacklist-other-site", r.status == 200, "%d", r.status)

	// ---------------------------------------------------- 403 vs WAF
	r = fetch(portPlain, "guard-own.d13.test", "/acl-block", nil, nil)
	check("slot-403-site-page-beats-slot", r.status == 403 && r.body == siteBlock, "%d %q", r.status, r.body)
	r = fetch(portPlain, "guard-own.d13.test", "/waf-block", nil, nil)
	check("slot-waf-site-page", r.status == 403 && r.body == siteBlock, "%d %q", r.status, r.body)

	// ---------------------------------------------------- traffic cap
	r = fetch(portPlain, "traffic.d13.test", "/x", nil, nil)
	check("slot-traffic-page", r.status == 509 && r.body == trafficBody && origin.count("traffic.d13.test", "/x") == 0,
		"%d %q origin %d", r.status, r.body, origin.count("traffic.d13.test", "/x"))
	r = fetch(portPlain, "notice.d13.test", "/x", nil, nil)
	check("slot-traffic-site-notice", r.status == 509 && r.body == ownNotice, "%d %q", r.status, r.body)

	// ---------------------------------------------------- connection limit
	r = fetch(portPlain, "conn.d13.test", "/x", nil, nil)
	check("slot-connection-limit-page", r.status == 503 && r.body == limitBody, "%d %q", r.status, r.body)
	r = fetch(portPlain, "conn-own.d13.test", "/x", nil, nil)
	check("slot-connection-limit-site-page", r.status == 503 && r.body == site503, "%d %q", r.status, r.body)

	// ---------------------------------------------------- node IP
	for _, host := range []string{"127.0.0.1", fmt.Sprintf("127.0.0.1:%d", portPlain), "[::1]"} {
		r = fetch(portPlain, host, "/", nil, nil)
		check("slot-node-ip-"+host, r.status == 403 && r.body == nodeIPBody, "%d %q", r.status, r.body)
	}
	r = fetch(portPlain, "unknown.d13.test", "/", nil, nil)
	check("slot-node-ip-name-keeps-unknown", r.status == 404 && r.body == unknownBody, "%d %q", r.status, r.body)

	// ---------------------------------------------------- package expired
	r = fetch(portPlain, "expired.d13.test", "/e.css", nil, nil)
	check("slot-expired-page", r.status == 403 && r.body == expiredBody && r.header.Get("X-CDN-Cache") == "" &&
		origin.count("expired.d13.test", "/e.css") == 0, "%d %q cache %q origin %d", r.status, r.body,
		r.header.Get("X-CDN-Cache"), origin.count("expired.d13.test", "/e.css"))
	r = fetch(portPlain, "expired.d13.test", "/.well-known/acme-challenge/slot", nil, nil)
	check("slot-expired-acme-to-origin", r.status == 200 && strings.HasPrefix(r.body, "origin expired.d13.test"), "%d %.40q", r.status, r.body)
	r = fetch(portPlain, "plain.d13.test", "/x", nil, nil)
	check("slot-expired-other-site", r.status == 200, "%d", r.status)

	// ---------------------------------------------------- 502 / 504 overrides (errpage-ovr)
	for _, c := range []struct {
		name, host, path string
		status           int
		want             string
	}{
		{"slot-connect-502-region", "connect.d13.test", "/x", 502, "slot.http_502.region.own\n"},
		{"slot-connect-504-node-beats-region", "connect.d13.test", "/slow/x", 504, "slot.http_504.node.own\n"},
		{"slot-connect-502-other-node-theme", "connect-elsewhere.d13.test", "/x", 502, "theme edge_connect 502\n"},
		{"slot-connect-504-other-region-theme", "connect-elsewhere.d13.test", "/slow/x", 504, "theme edge_connect 504\n"},
		{"slot-connect-502-no-variant-theme", "connect-plain.d13.test", "/x", 502, "theme edge_connect 502\n"},
		{"slot-connect-504-no-variant-theme", "connect-plain.d13.test", "/slow/x", 504, "theme edge_connect 504\n"},
	} {
		r = fetch(portPlain, c.host, c.path, nil, nil)
		check(c.name, r.status == c.status && r.body == c.want &&
			r.header.Get("Content-Length") == fmt.Sprint(len(c.want)), "%d %q want %d %q", r.status, r.body, c.status, c.want)
	}

	// a newer snapshot without the ban lifts it
	status, err = postBans(securityban.RuntimeSnapshot{Revision: 2, Bans: []securityban.RuntimeBan{}, Releases: []securityban.RuntimeRelease{}})
	r = fetch(portPlain, "guard.d13.test", "/x", nil, nil)
	check("slot-blacklist-lifted", status == 200 && err == nil && r.status == 200, "%d %v then %d", status, err, r.status)

	// 403 vs WAF on the theme page site: the ACL block is the node's own
	// 403 (http_403 slot over the theme page), the WAF rule keeps the theme
	// page ($cdnca_security_type waf: the waf_block slot)
	r = fetch(portPlain, "guard.d13.test", "/acl-block", nil, nil)
	check("slot-403-acl-page", r.status == 403 && r.body == http403Body, "%d %q", r.status, r.body)
	r = fetch(portPlain, "guard.d13.test", "/waf-block", nil, nil)
	check("slot-403-waf-keeps-theme", r.status == 403 && r.body == themeBlock, "%d %q", r.status, r.body)
	r = fetch(portPlain, "guard.d13.test", "/origin-403", nil, nil)
	check("slot-403-origin-untouched", r.status == 403 && r.body == origin403Body, "%d %q", r.status, r.body)

	// ---------------------------------------------------- without the slot pages
	// (unbound slots: delivery fallback, errpage-4 ownFallback wording)
	h.input.NodePages = allPages[:1] // unknown_site only
	h.apply("slot-pages-fallback-apply", sites...)
	status, err = postBans(securityban.RuntimeSnapshot{Revision: 3, Releases: []securityban.RuntimeRelease{},
		Bans: []securityban.RuntimeBan{{SiteID: themed.SiteID, Client: "127.0.0.1", Until: time.Now().Add(10 * time.Minute).Unix()}}})
	r = fetch(portPlain, "guard.d13.test", "/x", nil, nil)
	check("slot-blacklist-fallback", status == 200 && err == nil && r.status == 403 && strings.Contains(r.body, "您的 IP 已被封禁"), "%d %v then %d %.80q",
		status, err, r.status, r.body)
	_, _ = postBans(securityban.RuntimeSnapshot{Revision: 4, Bans: []securityban.RuntimeBan{}, Releases: []securityban.RuntimeRelease{}})
	r = fetch(portPlain, "guard.d13.test", "/acl-block", nil, nil)
	check("slot-403-fallback-theme", r.status == 403 && r.body == themeBlock, "%d %q", r.status, r.body)
	r = fetch(portPlain, "traffic.d13.test", "/x", nil, nil)
	check("slot-traffic-fallback", r.status == 509 && strings.Contains(r.body, "网站流量已超出限制"), "%d %.80q", r.status, r.body)
	r = fetch(portPlain, "conn.d13.test", "/x", nil, nil)
	check("slot-connection-limit-fallback", r.status == 503 && r.body != limitBody, "%d %.80q", r.status, r.body)
	r = fetch(portPlain, "127.0.0.1", "/", nil, nil)
	check("slot-node-ip-fallback-unknown", r.status == 404 && r.body == unknownBody, "%d %q", r.status, r.body)
	r = fetch(portPlain, "expired.d13.test", "/e.css", nil, nil)
	check("slot-expired-fallback", r.status == 403 && strings.Contains(r.body, "网站套餐已到期") &&
		origin.count("expired.d13.test", "/e.css") == 0, "%d %q origin %d", r.status, r.body, origin.count("expired.d13.test", "/e.css"))

	// ---------------------------------------------------- area / node pick
	pick := func(name string, pages []dynroute.NodePage, want string) {
		h.input.NodePages = pages
		h.apply(name+"-apply", sites...)
		r := fetch(portPlain, "127.0.0.1", "/", nil, nil)
		check(name, r.status == 403 && r.body == want, "%d %q want %q", r.status, r.body, want)
	}
	global, region, node := slotPage(siteobject.NodePageNodeIPAccess, "<p>pick global</p>\n"),
		slotPage(siteobject.NodePageNodeIPAccess, "<p>pick region</p>\n"), slotPage(siteobject.NodePageNodeIPAccess, "<p>pick node</p>\n")
	region.Region, node.NodeID = slotRegion, slotNodeID
	pick("slot-pick-node", []dynroute.NodePage{global, region, node}, string(node.Body))
	otherNode := node
	otherNode.NodeID = "0d130000-0000-4000-8000-0000000000b2"
	pick("slot-pick-region", []dynroute.NodePage{global, otherNode, region}, string(region.Body))
	otherRegion := region
	otherRegion.Region = "us-west"
	pick("slot-pick-global", []dynroute.NodePage{otherRegion, otherNode, global}, string(global.Body))
	h.input.NodePages = []dynroute.NodePage{otherRegion, otherNode}
	h.apply("slot-pick-none-apply", sites...)
	r = fetch(portPlain, "127.0.0.1", "/", nil, nil)
	check("slot-pick-none-421", r.status == 421, "%d %q", r.status, r.body)
	// No region from the control plane (an older control plane, or a node
	// without a region): the region page is not picked, the global one is.
	h.input.NodePages, h.input.NodeRegion = []dynroute.NodePage{global, otherNode, region}, ""
	h.apply("slot-pick-no-region-apply", sites...)
	r = fetch(portPlain, "127.0.0.1", "/", nil, nil)
	check("slot-pick-no-region-global", r.status == 403 && r.body == string(global.Body), "%d %q", r.status, r.body)

	// fix-errpages: the built-in default pages (no node pages)
	checkDefaultPages(h, origin, others...)

	h.input.NodePages, h.input.NodeRegion = nil, ""
	h.apply("slot-pages-removed-apply", others...)
	return runtime
}
