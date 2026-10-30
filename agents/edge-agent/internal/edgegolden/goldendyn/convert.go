// Package goldendyn is the dynamic routing renderer of the edge golden
// (ADR 0009 §5, renderer "cdnca-dynroute"): a scenario's site facts become
// cdnca.edge.site/v2 site objects, activated in the node index (D3) of one
// shared-server OpenResty, and requests run through the request-time
// modules (cdnca_site selection, cdnca_origin origin selection, ...).
//
// It covers what the dynamic routing modules implement so far; a scenario
// needing something else is refused with the missing piece named, and the
// renderer grows with the modules (D5b adds origin TLS on top of this).
package goldendyn

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"sort"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/edgegolden"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/edgeconfig/sched302"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
)

// ErrUnsupported names a scenario fact the dynamic routing runtime does not
// serve yet.
type ErrUnsupported struct{ What string }

func (err ErrUnsupported) Error() string {
	return "dynamic routing does not serve " + err.What + " yet"
}

// document is the part of the site runtime v2 document the renderer reads.
type document struct {
	Schema               string         `json:"schema"`
	ConfigurationScopeID string         `json:"configuration_scope_id"`
	Sites                []documentSite `json:"sites"`
}

type documentSite struct {
	ID            string             `json:"id"`
	Revision      int64              `json:"revision"`
	Domains       []string           `json:"domains"`
	Listeners     []documentListener `json:"listeners"`
	OriginPools   []documentPool     `json:"origin_pools"`
	DefaultPoolID string             `json:"default_pool_id"`
	WebSocket     bool               `json:"websocket"`
	Range         bool               `json:"range"`
	L2            documentL2         `json:"l2"`
	// Cache: the site runtime v2 cache binding (D8 dynroute cache)
	Cache *edgeconfig.SiteRuntimeCache `json:"cache,omitempty"`
	// Forwarding: trusted proxies, WebSocket Origin allowlist, the TLS
	// listeners' pool (ge-origin)
	Forwarding *struct {
		TrustedProxyCIDRs []string `json:"trusted_proxy_cidrs,omitempty"`
		WebSocketOrigins  []string `json:"websocket_origins,omitempty"`
		HTTPSPoolID       string   `json:"https_pool_id,omitempty"`
	} `json:"forwarding,omitempty"`
	// PackageLimits / TrafficLimit: D10 (cdnca_limits)
	PackageLimits *edgeconfig.PackageConnectionLimit `json:"package_limits,omitempty"`
	TrafficLimit  *edgeconfig.SiteTrafficLimit       `json:"traffic_limit,omitempty"`
	// Schedule302: HTTP 302 scheduling
	Schedule302 *sched302.Site `json:"schedule302,omitempty"`
}

type documentListener struct {
	ID            string          `json:"id"`
	Port          int             `json:"port"`
	AddressFamily string          `json:"address_family"`
	Protocols     []string        `json:"protocols"`
	TLS           json.RawMessage `json:"tls,omitempty"`
	Security      json.RawMessage `json:"security,omitempty"`
}

type documentPool struct {
	ID                     string           `json:"id"`
	Kind                   string           `json:"kind"`
	Algorithm              string           `json:"algorithm"`
	Origins                []documentOrigin `json:"origins"`
	Retry                  documentRetry    `json:"retry"`
	KeepaliveIdleTimeoutMS *int64           `json:"keepalive_idle_timeout_ms,omitempty"`
	HashKey                string           `json:"hash_key,omitempty"`
	Sticky                 *edgesite.Sticky `json:"sticky,omitempty"`
	RequestHost            *struct {
		Mode  string `json:"mode"`
		Value string `json:"value,omitempty"`
	} `json:"request_host,omitempty"`
	FollowPort bool `json:"follow_port,omitempty"`
}

type documentOrigin struct {
	ID       string `json:"id"`
	Scheme   string `json:"scheme"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Weight   int    `json:"weight"`
	NodeID   string `json:"node_id,omitempty"`
	SNI      string `json:"sni,omitempty"`
	TrustRef string `json:"trust_ref,omitempty"`
	Backup   bool   `json:"backup,omitempty"`
	MaxConns int    `json:"max_conns,omitempty"`
}

type documentRetry struct {
	Methods          []string `json:"methods"`
	MaxAttempts      int      `json:"max_attempts"`
	ConnectTimeoutMS int      `json:"connect_timeout_ms"`
	ReadTimeoutMS    int      `json:"read_timeout_ms"`
	TotalBudgetMS    int      `json:"total_budget_ms"`
}

type documentL2 struct {
	Enabled              bool   `json:"enabled"`
	DirectFallbackPoolID string `json:"direct_fallback_pool_id,omitempty"`
	ProbeIntervalMS      int    `json:"probe_interval_ms"`
	FailureThreshold     int    `json:"failure_threshold"`
	RecoveryThreshold    int    `json:"recovery_threshold"`
}

// known site fields; any other present field is refused
var servedSiteFields = map[string]bool{
	"id": true, "revision": true, "domains": true, "listeners": true, "origin_pools": true,
	"default_pool_id": true, "websocket": true, "range": true, "l2": true, "cache": true, "forwarding": true,
	"package_limits": true, "traffic_limit": true, "schedule302": true,
}

// goldenTenant: the facts carry no tenant unless telemetry names one.
const goldenTenant = "0a1b0000-0000-4000-8000-00000000c0de"

// placeholder L2 identity (the golden's L2 is a plain mock origin)
const (
	l2Identity         = "sha256:" + "0000000000000000000000000000000000000000000000000000000000000001"
	l2TopologyRevision = 1
)

// Convert turns the expanded site runtime v2 document of a scenario into one
// site object per site, as the control plane's buildSiteObjectsV2 would for
// the fields both carry (services/control-api/internal/edgepublish/
// site_objects_v2.go convertSiteOriginV2).
func Convert(raw []byte, scenario *edgegolden.Scenario, values map[string]string) ([]edgesite.Site, error) {
	routes, err := originRoutes(scenario, values)
	if err != nil {
		return nil, err
	}
	if len(scenario.Facts.HTTPPolicy) != 0 || scenario.Facts.CRS ||
		len(scenario.Facts.Node.Certificates) != 0 || len(scenario.Facts.Node.Challenges) != 0 {
		return nil, ErrUnsupported{"HTTP policy, CRS, certificates or challenges"}
	}
	var value document
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	var generic struct {
		Sites []map[string]json.RawMessage `json:"sites"`
	}
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil, err
	}
	sites := make([]edgesite.Site, 0, len(value.Sites))
	for index, site := range value.Sites {
		for field := range generic.Sites[index] {
			if !servedSiteFields[field] {
				return nil, ErrUnsupported{"site field " + field}
			}
		}
		converted, err := convertSite(value.ConfigurationScopeID, site, routes[site.ID])
		if err != nil {
			return nil, fmt.Errorf("site %s: %w", site.ID, err)
		}
		if telemetry := scenario.Facts.Telemetry; telemetry != nil {
			// the telemetry identity as the production conversion carries it
			// (scope tenant, package subscription, capture policy; D12)
			converted.TenantID = telemetry.TenantID
			if len(telemetry.Capture) != 0 {
				return nil, ErrUnsupported{"capture policy without the production conversion"}
			}
			converted.Telemetry = &edgesite.Telemetry{PackageSubscriptionID: telemetry.Subscriptions[site.ID],
				Capture: siteobject.TelemetryCapture{Methods: []string{}, URIPrefixes: []string{}, RequestHeaderAllowlist: []string{},
					ResponseHeaderAllowlist: []string{}, RequestBodyFieldAllowlist: []string{}, ResponseBodyFieldAllowlist: []string{}}}
		}
		if err := edgesite.Validate(converted); err != nil {
			return nil, fmt.Errorf("site %s: %w", site.ID, err)
		}
		sites = append(sites, converted)
	}
	return sites, nil
}

func convertSite(scope string, site documentSite, route *routeDocument) (edgesite.Site, error) {
	aliases := slices.Clone(site.Domains[1:])
	sort.Strings(aliases)
	converted := edgesite.Site{
		Schema: edgesite.Schema, ConfigurationScopeID: scope, TenantID: goldenTenant,
		SiteID: site.ID, Revision: max(site.Revision, 1),
		Hosts: edgesite.Hosts{Primary: site.Domains[0], Aliases: append([]string{}, aliases...)},
		Security: edgesite.Security{Rules: edgesite.RulePlan{HeaderOverflow: edgesite.HeaderOverflowNoMatch,
			Policies: []edgesite.RulePolicy{}}, CC: []edgesite.CCBinding{}},
		Errors: []edgesite.ErrorPage{}, Range: site.Range, WebSocket: site.WebSocket,
		// v7 always answers X-CDN-Cache (响应头显示缓存状态 on, the default)
		CacheStatusHeader: true,
	}
	for _, listener := range site.Listeners {
		if len(listener.TLS) != 0 {
			return edgesite.Site{}, ErrUnsupported{"TLS listeners"}
		}
		if len(listener.Security) != 0 {
			return edgesite.Site{}, ErrUnsupported{"listener security (production conversion path)"}
		}
		converted.Listeners = append(converted.Listeners, edgesite.Listener{Port: listener.Port, AddressFamily: listener.AddressFamily})
	}
	if site.PackageLimits != nil {
		converted.Limits.Connections = &edgesite.Connections{SubscriptionID: site.PackageLimits.SubscriptionID,
			Max: site.PackageLimits.Connections, BandwidthBPS: site.PackageLimits.BandwidthBPS}
	}
	if site.TrafficLimit != nil && site.TrafficLimit.Exceeded {
		// as the control plane's buildSiteObjectsV2 (present only while exceeded)
		converted.TrafficLimit = &edgesite.TrafficLimit{Period: site.TrafficLimit.Period, NoticeHTML: site.TrafficLimit.NoticeHTML}
	}
	sort.Slice(converted.Listeners, func(i, j int) bool { return converted.Listeners[i].Port < converted.Listeners[j].Port })
	if site.Schedule302 != nil {
		value := *site.Schedule302
		converted.Schedule302 = &value
	}
	origin := edgesite.Origin{DefaultPoolID: site.DefaultPoolID, Routes: []edgesite.Route{}, Auth: []edgesite.OriginAuth{}}
	for _, pool := range site.OriginPools {
		value := edgesite.Pool{ID: pool.ID, Kind: pool.Kind, Algorithm: pool.Algorithm,
			Retry: edgesite.Retry{Methods: slices.Sorted(slices.Values(pool.Retry.Methods)), MaxAttempts: pool.Retry.MaxAttempts,
				ConnectTimeoutMS: pool.Retry.ConnectTimeoutMS, ReadTimeoutMS: pool.Retry.ReadTimeoutMS, TotalBudgetMS: pool.Retry.TotalBudgetMS},
			KeepaliveIdleTimeoutMS: pool.KeepaliveIdleTimeoutMS, HashKey: pool.HashKey, Sticky: pool.Sticky, FollowPort: pool.FollowPort}
		if pool.RequestHost != nil {
			value.RequestHost = &edgesite.RequestHost{Mode: pool.RequestHost.Mode, Value: pool.RequestHost.Value}
		}
		for _, endpoint := range pool.Origins {
			converted := edgesite.Endpoint{ID: endpoint.ID, Scheme: endpoint.Scheme, Host: endpoint.Host, Port: endpoint.Port, Weight: endpoint.Weight,
				SNI: endpoint.SNI, TrustAnchor: endpoint.TrustRef, Level: backupLevel(endpoint.Backup), MaxConns: endpoint.MaxConns}
			if pool.Kind == edgesite.PoolL2 {
				converted.NodeID, converted.MTLSIdentitySHA256, converted.TopologyRevision = endpoint.NodeID, l2Identity, l2TopologyRevision
			}
			value.Endpoints = append(value.Endpoints, converted)
		}
		origin.Pools = append(origin.Pools, value)
	}
	if route != nil {
		if err := applyRoute(&origin, route); err != nil {
			return edgesite.Site{}, err
		}
	}
	if forwarding := site.Forwarding; forwarding != nil {
		origin.TrustedProxyCIDRs = slices.Sorted(slices.Values(forwarding.TrustedProxyCIDRs))
		converted.WebSocketOrigins = slices.Sorted(slices.Values(forwarding.WebSocketOrigins))
		origin.HTTPSPoolID = forwarding.HTTPSPoolID
	}
	sort.Slice(origin.Pools, func(i, j int) bool { return origin.Pools[i].ID < origin.Pools[j].ID })
	if site.L2.Enabled {
		origin.L2 = &edgesite.L2{DirectFallbackPoolID: site.L2.DirectFallbackPoolID, ProbeIntervalMS: site.L2.ProbeIntervalMS,
			FailureThreshold: site.L2.FailureThreshold, RecoveryThreshold: site.L2.RecoveryThreshold}
	}
	converted.Origin = origin
	if site.Cache != nil {
		// as the control plane's convertSiteCacheV2: the cache tenant is the
		// site's tenant (the golden names one per document)
		converted.TenantID = site.Cache.TenantID
		policy := site.Cache.Policy
		if policy.Rules == nil {
			policy.Rules = []edgeconfig.CacheRuleDocument{}
		}
		if policy.QueryNames == nil {
			policy.QueryNames = []string{}
		}
		if policy.VaryHeaders == nil {
			policy.VaryHeaders = []string{}
		}
		cache := &edgesite.Cache{KeyPrefix: edgesite.CacheKeyPrefix(converted.TenantID, site.ID), Domain: site.Cache.Domain,
			KeyByHost: !site.Cache.SharedAcrossDomains, Policy: policy}
		token, err := edgesite.CacheGeneration(*cache)
		if err != nil {
			return edgesite.Site{}, err
		}
		cache.Generation = token
		converted.Cache = cache
	}
	return converted, nil
}

// The conditional origin route bundle (origin-route.v1.json) as the control
// plane publishes it beside the site runtime document.
type routeBundle struct {
	Sites []struct {
		SiteID   string        `json:"site_id"`
		Document routeDocument `json:"document"`
	} `json:"sites"`
}

type routePool struct {
	ID            string `json:"id"`
	Kind          string `json:"kind,omitempty"`
	BalanceMethod string `json:"balance_method,omitempty"`
	Endpoints     []struct {
		ID     string `json:"id"`
		Host   string `json:"host"`
		Port   int    `json:"port"`
		Weight int    `json:"weight"`
		NodeID string `json:"node_id,omitempty"`
	} `json:"endpoints"`
}

type routeDocument struct {
	IngressSourceEnabled  bool        `json:"ingress_source_enabled"`
	DefaultPoolID         string      `json:"default_pool_id"`
	DefaultFallbackPoolID string      `json:"default_fallback_pool_id,omitempty"`
	Pools                 []routePool `json:"pools"`
	Routes                []struct {
		ID             string   `json:"id"`
		Priority       int      `json:"priority"`
		PathPrefix     string   `json:"path_prefix,omitempty"`
		NodeRegions    []string `json:"node_regions,omitempty"`
		ClientCIDRs    []string `json:"client_cidrs,omitempty"`
		Hosts          []string `json:"hosts,omitempty"`
		PoolID         string   `json:"pool_id"`
		FallbackPoolID string   `json:"fallback_pool_id,omitempty"`
	} `json:"routes"`
	Retry documentRetry `json:"retry"`
}

func originRoutes(scenario *edgegolden.Scenario, values map[string]string) (map[string]*routeDocument, error) {
	result := map[string]*routeDocument{}
	if len(scenario.Facts.OriginRoute) == 0 {
		return result, nil
	}
	raw, err := edgegolden.Expand(scenario.Facts.OriginRoute, values)
	if err != nil {
		return nil, fmt.Errorf("origin_route: %w", err)
	}
	var bundle routeBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return nil, fmt.Errorf("origin_route: %w", err)
	}
	for index := range bundle.Sites {
		result[bundle.Sites[index].SiteID] = &bundle.Sites[index].Document
	}
	return result, nil
}

// applyRoute: the route document's pools replace the runtime's (endpoints,
// algorithm, retry), as edgepublish convertSiteOriginV2 does.
func applyRoute(origin *edgesite.Origin, route *routeDocument) error {
	pools := map[string]int{}
	for index, pool := range origin.Pools {
		pools[pool.ID] = index
	}
	for _, routePool := range route.Pools {
		kind := routePool.Kind
		if kind == "" {
			kind = edgesite.PoolOrigin
		}
		index, ok := pools[routePool.ID]
		if !ok {
			origin.Pools = append(origin.Pools, edgesite.Pool{ID: routePool.ID, Kind: kind,
				Retry: edgesite.Retry{Methods: slices.Sorted(slices.Values(route.Retry.Methods))}})
			index = len(origin.Pools) - 1
			pools[routePool.ID] = index
		}
		pool := &origin.Pools[index]
		if pool.Kind != kind {
			return fmt.Errorf("origin route pool %s kind differs", routePool.ID)
		}
		pool.Retry.MaxAttempts, pool.Retry.ConnectTimeoutMS = route.Retry.MaxAttempts, route.Retry.ConnectTimeoutMS
		pool.Retry.ReadTimeoutMS, pool.Retry.TotalBudgetMS = route.Retry.ReadTimeoutMS, route.Retry.TotalBudgetMS
		if kind == edgesite.PoolOrigin && sameEndpoints(pool.Endpoints, routePool) {
			continue // the signed pool keeps its TLS, backup, balancing (control: routeKeepsPool)
		}
		pool.Algorithm = routePool.BalanceMethod
		if pool.Algorithm == "" {
			pool.Algorithm = "round_robin"
		}
		pool.HashKey, pool.Sticky = "", nil
		pool.Endpoints = nil
		for _, endpoint := range routePool.Endpoints {
			value := edgesite.Endpoint{ID: endpoint.ID, Scheme: "http", Host: endpoint.Host, Port: endpoint.Port, Weight: endpoint.Weight}
			if kind == edgesite.PoolL2 {
				value.NodeID, value.MTLSIdentitySHA256, value.TopologyRevision = endpoint.NodeID, l2Identity, l2TopologyRevision
			}
			pool.Endpoints = append(pool.Endpoints, value)
		}
	}
	origin.DefaultPoolID = route.DefaultPoolID
	origin.DefaultFallbackPoolID = route.DefaultFallbackPoolID
	origin.IngressSource = route.IngressSourceEnabled
	for _, value := range route.Routes {
		origin.Routes = append(origin.Routes, edgesite.Route{ID: value.ID, Priority: value.Priority, PathPrefix: value.PathPrefix,
			ClientCIDRs: value.ClientCIDRs, NodeRegions: value.NodeRegions, Hosts: value.Hosts, PoolID: value.PoolID, FallbackPoolID: value.FallbackPoolID})
	}
	return nil
}

func sameEndpoints(endpoints []edgesite.Endpoint, pool routePool) bool {
	if len(endpoints) == 0 || len(endpoints) != len(pool.Endpoints) {
		return false
	}
	for index, endpoint := range pool.Endpoints {
		current := endpoints[index]
		if current.ID != endpoint.ID || current.Host != endpoint.Host || current.Port != endpoint.Port || current.Weight != endpoint.Weight {
			return false
		}
	}
	return true
}

// backupLevel: a golden scenario's backup origin is level 1.
func backupLevel(backup bool) int {
	if backup {
		return 1
	}
	return 0
}
