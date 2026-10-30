package marketsubscribe

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/regioncatalog"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
)

// The site's local rules compiled into the revision (fix-mktsiteconf):
// its effective cache policy, its ACL and CC policies, and its conditional
// origins. A rule a siteconf block cannot express blocks the rollout with a
// reason (Unsupported) instead of being dropped.

// compileCache is the site's effective cache policy as the cache block.
func compileCache(doc cachecontrol.PolicyDocument) (json.RawMessage, error) {
	cache := siteconf.Cache{Mode: string(doc.Mode), QueryMode: string(doc.QueryMode),
		QueryNames: slices.Clone(doc.QueryNames), VaryHeaders: slices.Clone(doc.VaryHeaders),
		StaleIfError: doc.Extensions.StaleIfError, BackgroundUpdate: doc.Extensions.BackgroundUpdate,
		MinObjectBytes: doc.Extensions.MinObjectBytes, MaxObjectBytes: doc.Extensions.MaxObjectBytes,
		SliceBytes: doc.Extensions.SliceBytes}
	for _, r := range doc.Rules {
		action := string(r.Action)
		if action == "" {
			action = string(cachecontrol.RuleActionCache) // schema v1: every rule caches
		}
		rule := siteconf.CacheRule{Extensions: slices.Clone(r.Extensions), PathPrefix: r.PathPrefix,
			StatusCodes: slices.Clone(r.StatusCodes), Action: action, TTLSeconds: r.TTLSeconds,
			BrowserTTLSeconds: r.BrowserTTLSeconds, PathRegex: r.PathRegex, ContentTypes: slices.Clone(r.ContentTypes),
			PathExact: r.PathExact, IgnoreQuery: r.IgnoreQuery, SliceBytes: r.SliceBytes, ForceCache: r.ForceCache,
			IgnoreVary: r.IgnoreVary}
		for _, c := range r.NoCache {
			rule.NoCache = append(rule.NoCache, siteconf.CacheNoCacheRule{Source: c.Source, Name: c.Name, Pattern: c.Pattern})
		}
		cache.Rules = append(cache.Rules, rule)
	}
	return json.Marshal(cache)
}

// compileACL is an enabled ACL policy as the access list. The local ACL
// lets any matching allow win over every block (validateACLFields), so the
// list carries the allows first; the leaf maps it back onto its own ACL.
// A disabled policy enforces nothing: no block.
func compileACL(p securitypolicy.Policy) (*siteconf.Access, string) {
	if !p.Enabled {
		return nil, ""
	}
	access := &siteconf.Access{Default: p.DefaultAction}
	var blocks []siteconf.AccessRule
	for _, r := range p.Rules {
		if !r.Enabled {
			continue
		}
		if r.ExpiresAt != "" {
			return nil, "acl_rule_expiry"
		}
		if len(r.Conditions) != 1 || r.Conditions[0].Field != "client_ip" || r.Conditions[0].Operator != "ip_in_cidr" ||
			len(r.Conditions[0].Values) != 1 {
			return nil, "acl_condition"
		}
		rule := siteconf.AccessRule{CIDR: r.Conditions[0].Values[0], Action: r.Action}
		if r.Action == securitypolicy.ActionAllow {
			access.Rules = append(access.Rules, rule)
		} else {
			blocks = append(blocks, rule)
		}
	}
	access.Rules = append(access.Rules, blocks...)
	if len(access.Rules) == 0 {
		if access.Default == securitypolicy.ActionAllow {
			return nil, "" // allows everyone: nothing to enforce
		}
		return nil, "acl_block_all"
	}
	return access, ""
}

// compileOriginRoutes is the site's conditional origin document. Node
// regions name the subscriber's own node regions: each is carried as its
// region catalog geography (geos, by code; the leaf matches its own regions'
// geography), and a region without a country refuses (node_region_geo).
// The ingress source address is a subscriber node fact and refuses.
func compileOriginRoutes(doc site.ConditionalOriginDocument, geos map[string]regioncatalog.CodeGeo) (*siteconf.OriginRoutes, string) {
	if doc.IngressSourceEnabled {
		return nil, "ingress_source"
	}
	out := &siteconf.OriginRoutes{DefaultPoolID: doc.DefaultPoolID, DefaultFallbackPoolID: doc.DefaultFallbackPoolID,
		Routes: []siteconf.Route{}, Retry: siteconf.RouteRetry{Methods: slices.Clone(doc.Retry.Methods),
			MaxAttempts: doc.Retry.MaxAttempts, ConnectTimeoutMS: doc.Retry.ConnectTimeoutMS,
			ReadTimeoutMS: doc.Retry.ReadTimeoutMS, TotalBudgetMS: doc.Retry.TotalBudgetMS}}
	for _, p := range doc.Pools {
		pool := siteconf.RoutePool{ID: p.ID, BalanceMethod: p.BalanceMethod}
		for _, e := range p.Endpoints {
			pool.Endpoints = append(pool.Endpoints, siteconf.RouteEndpoint{ID: e.ID, Host: e.Host, Port: e.Port, Weight: e.Weight})
		}
		out.Pools = append(out.Pools, pool)
	}
	for _, r := range doc.Routes {
		var nodeGeos []siteconf.NodeGeo
		for _, code := range r.NodeRegions {
			geo, ok := geos[code]
			if !ok || geo.CountryCode == "" {
				return nil, "node_region_geo"
			}
			nodeGeos = append(nodeGeos, siteconf.NodeGeo{Country: geo.CountryCode, Province: geo.ProvinceCode})
		}
		slices.SortFunc(nodeGeos, func(a, b siteconf.NodeGeo) int {
			if a.Country != b.Country {
				return strings.Compare(a.Country, b.Country)
			}
			return strings.Compare(a.Province, b.Province)
		})
		out.Routes = append(out.Routes, siteconf.Route{ID: r.ID, Priority: r.Priority, PathPrefix: r.PathPrefix,
			ClientCIDRs: slices.Clone(r.ClientCIDRs), Hosts: slices.Clone(r.Hosts), NodeGeos: slices.Compact(nodeGeos),
			PoolID: r.PoolID, FallbackPoolID: r.FallbackPoolID})
	}
	return out, ""
}

func originRoutesNameRegions(doc site.ConditionalOriginDocument) bool {
	for _, r := range doc.Routes {
		if len(r.NodeRegions) > 0 {
			return true
		}
	}
	return false
}
