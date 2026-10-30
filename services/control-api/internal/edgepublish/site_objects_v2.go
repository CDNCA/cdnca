package edgepublish

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"slices"
	"sort"
	"strconv"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	"github.com/cdnca/cdnca/services/control-api/internal/httppolicycontrol"
	"github.com/google/uuid"
)

// Dynamic routing D1: semantic site objects (cdnca.edge.site/v2,
// libs/edgeconfig/edgesite) generated from the site model a v8 publication
// already compiled (siteobject.Publication: the v2 document split per site).
// Nothing here is on the publication path yet; D2/D3 switch delivery.
//
// Every value comes from the publication, except what does not travel in
// the v2 bundle (error pages and origin authentication are separate
// releases): the caller passes those per site in siteObjectV2Facts.

// siteObjectV2Facts are a site's facts outside the v2 bundle. ErrorAssets
// are the bodies the error pages reference (digest -> body; the scope's
// siteErrorPageFacts output), added to the scope's referenced objects.
type siteObjectV2Facts struct {
	ErrorPages []edgesite.ErrorPage
	// ErrorVariants: the site's region / node edge_connect page variants
	// (errpage-ovr), bodies in ErrorAssets.
	ErrorVariants []edgesite.ErrorPageVariant
	ErrorAssets   map[string][]byte
	OriginAuth    []edgesite.OriginAuth
	// Mounts are the site's published rule pack mounts
	// (site_security_mounts.security: rulepack.Security JSON), nil if none.
	Mounts *siteRuleMounts
	// ModSecurity is the site's modsecurity mount (loadSiteModSecurityFacts),
	// nil without one: it narrows the managed WAF (applySiteModSecurity).
	ModSecurity *siteModSecurityFacts
	// CacheStatusHeader: the site's 响应头显示缓存状态, off while it is at
	// attack escalation level B or above (loadSiteCacheStatusHeaders).
	CacheStatusHeader bool
}

// siteRuleMounts is site_security_mounts.security (rulepack.Security).
type siteRuleMounts struct {
	Mounts         []edgesite.RuleMount `json:"mounts"`
	ResolvedSHA256 string               `json:"resolved_sha256"`
}

// siteObjectsV2 is one scope's v2 site objects, sorted by site ID, and the
// objects they reference (CC policies, HTTP policy entries, firewall
// actions) by digest.
type siteObjectsV2 struct {
	Sites      []siteObjectV2
	Referenced map[string][]byte
	Ports      []edgesite.PortProfile
}

type siteObjectV2 struct {
	SiteID    string
	Revision  int64
	SHA256    string
	Plaintext []byte
	Site      edgesite.Site
}

// buildSiteObjectsV2 converts every site of source. tenantID is the scope's
// tenant (tenants.id: cache, challenge and telemetry identity).
func buildSiteObjectsV2(source siteObjectsV2Source, tenantID uuid.UUID,
	facts map[string]siteObjectV2Facts) (siteObjectsV2, error) {
	if tenantID == uuid.Nil {
		return siteObjectsV2{}, fmt.Errorf("%w: site objects v2: tenant", ErrInvalidInput)
	}
	objects := source.fileObjects()
	result := siteObjectsV2{Referenced: map[string][]byte{}}
	for _, entry := range source.Sites {
		siteID := entry.Runtime.ID
		site, err := convertSiteObjectV2(entry, source.ScopeID, tenantID.String(), source.Files, objects, facts[siteID], result.Referenced)
		if outOfProfile := (*CRSOutOfProfileError)(nil); errors.As(err, &outOfProfile) {
			return siteObjectsV2{}, outOfProfile
		}
		if err != nil {
			return siteObjectsV2{}, fmt.Errorf("%w: site objects v2: site %s: %v", ErrInvalidInput, siteID, err)
		}
		if err := attachSiteClientCAV2(&site, entry.Runtime, source.Files, result.Referenced); err != nil {
			return siteObjectsV2{}, fmt.Errorf("%w: site objects v2: site %s: %v", ErrInvalidInput, siteID, err)
		}
		plaintext, err := edgesite.Encode(site)
		if err != nil {
			return siteObjectsV2{}, fmt.Errorf("%w: site objects v2: site %s: %v", ErrInvalidInput, siteID, err)
		}
		result.Sites = append(result.Sites, siteObjectV2{SiteID: site.SiteID, Revision: site.Revision,
			SHA256: edgesite.Digest(plaintext), Plaintext: plaintext, Site: site})
	}
	sort.Slice(result.Sites, func(i, j int) bool { return result.Sites[i].SiteID < result.Sites[j].SiteID })
	sites := make([]edgesite.Site, len(result.Sites))
	for index, site := range result.Sites {
		sites[index] = site.Site
	}
	ports, err := edgesite.PortProfiles(sites)
	if err != nil {
		return siteObjectsV2{}, fmt.Errorf("%w: site objects v2: %v", ErrInvalidInput, err)
	}
	result.Ports = ports
	return result, nil
}

func decodeStrictJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return fmt.Errorf("trailing data")
	}
	return nil
}

func addReferencedObject(referenced map[string][]byte, plaintext []byte) (string, error) {
	if len(plaintext) == 0 || len(plaintext) > edgesite.MaxReferencedBytes {
		return "", fmt.Errorf("referenced object of %d bytes", len(plaintext))
	}
	digest := siteobject.Digest(plaintext)
	referenced[digest] = bytes.Clone(plaintext)
	return digest, nil
}

func convertSiteObjectV2(entry siteObjectsV2SourceSite, scopeID, tenantID string, files, objects map[string][]byte,
	facts siteObjectV2Facts, referenced map[string][]byte) (edgesite.Site, error) {
	runtime := entry.Runtime
	if len(runtime.Domains) == 0 || runtime.WebSocket == nil || runtime.Range == nil || runtime.L2.Enabled == nil {
		return edgesite.Site{}, fmt.Errorf("runtime identity")
	}
	site := edgesite.Site{
		Schema: edgesite.Schema, ConfigurationScopeID: scopeID, TenantID: tenantID,
		SiteID: runtime.ID, Revision: runtime.Revision,
		Hosts:     edgesite.Hosts{Primary: runtime.Domains[0], Aliases: slices.Sorted(slices.Values(runtime.Domains[1:]))},
		WebSocket: *runtime.WebSocket, Range: *runtime.Range,
		CacheStatusHeader: facts.CacheStatusHeader,
		Errors:            []edgesite.ErrorPage{},
	}
	if site.Hosts.Aliases == nil {
		site.Hosts.Aliases = []string{}
	}
	listeners := slices.Clone(runtime.Listeners)
	sort.SliceStable(listeners, func(i, j int) bool { return listeners[i].Port < listeners[j].Port })
	for _, listener := range listeners {
		converted, err := convertSiteListenerV2(listener)
		if err != nil {
			return edgesite.Site{}, err
		}
		site.Listeners = append(site.Listeners, converted)
	}
	if runtime.ForceHTTPS != nil {
		site.ForceHTTPS = &edgesite.ForceHTTPS{RedirectPort: int(runtime.ForceHTTPS.RedirectPort),
			Status: int(runtime.ForceHTTPS.Status), ExcludeHosts: slices.Clone(runtime.ForceHTTPS.ExcludeHosts)}
	}
	if runtime.Access != nil {
		// HSTS is the site object's own field (D9 dynfilters sends it); the
		// rest of access stays under access.
		access := *runtime.Access
		if hsts := access.HSTS; hsts != nil {
			site.HSTS = &edgesite.HSTS{MaxAgeSeconds: hsts.MaxAgeSeconds,
				IncludeSubdomains: hsts.IncludeSubdomains, Preload: hsts.Preload}
			access.HSTS = nil
		}
		if access.HostRedirects != nil || access.Compression != nil || access.Limits != nil ||
			access.BasicAuth != nil || access.Maintenance != nil {
			site.Access = &access
		}
	}
	site.PackageExpired = runtime.PackageExpired
	if runtime.TrafficLimit != nil && runtime.TrafficLimit.Exceeded {
		site.TrafficLimit = &edgesite.TrafficLimit{Period: runtime.TrafficLimit.Period, NoticeHTML: runtime.TrafficLimit.NoticeHTML}
	}
	if runtime.Schedule302 != nil {
		value := *runtime.Schedule302
		value.Extensions = slices.Clone(value.Extensions)
		value.PathPrefixes = slices.Clone(value.PathPrefixes)
		site.Schedule302 = &value
	}
	var err error
	if site.Origin, err = convertSiteOriginV2(runtime, entry.OriginRoute, facts.OriginAuth); err != nil {
		return edgesite.Site{}, err
	}
	if forwarding := runtime.Forwarding; forwarding != nil {
		site.Origin.TrustedProxyCIDRs = slices.Sorted(slices.Values(forwarding.TrustedProxyCIDRs))
		site.WebSocketOrigins = slices.Sorted(slices.Values(forwarding.WebSocketOrigins))
		if forwarding.HTTPSPoolID != nil {
			site.Origin.HTTPSPoolID = *forwarding.HTTPSPoolID
		}
		if forwarding.FollowRedirect != nil {
			value := *forwarding.FollowRedirect
			site.Origin.FollowRedirect = &value
		}
		if forwarding.SearchEnginePoolID != nil {
			site.Origin.SearchEngine = &edgesite.SearchEngineOrigin{PoolID: *forwarding.SearchEnginePoolID}
		}
		site.Origin.ACMEPassthrough = forwarding.ACMEPassthrough
		site.Origin.Unbuffered = slices.Clone(forwarding.Unbuffered)
		site.Default = forwarding.DefaultSite
	}
	// The CA sets HTTPS endpoints trust are referenced objects: a v8 release
	// carries each as the scope file origin-trust/<hex>.pem, whose file
	// object digest is <hex> (the trust anchor) itself. The production
	// publisher passes no trust files yet (site origins are plain HTTP until
	// ge-origin, site_runtime_v2.go buildSiteRuntimeV2Bundle(canonical, nil,
	// ...)); an anchor without its CA set stays in the site object and the
	// node refuses that origin (cdnca_origintls: object missing -> rejected),
	// it is never served unverified.
	for _, digest := range site.TrustAnchors() {
		content, ok := objects[digest]
		if !ok {
			continue
		}
		if err := edgesite.ValidateCASet(content); err != nil {
			return edgesite.Site{}, fmt.Errorf("origin trust CA set %s: %v", digest, err)
		}
		referenced[digest] = bytes.Clone(content)
	}
	if runtime.Cache != nil {
		if site.Cache, err = convertSiteCacheV2(runtime, tenantID); err != nil {
			return edgesite.Site{}, err
		}
	}
	if site.Security, err = convertSiteSecurityV2(runtime, listeners, tenantID, files, referenced); err != nil {
		return edgesite.Site{}, err
	}
	if facts.Mounts != nil && len(facts.Mounts.Mounts) > 0 {
		site.Security.Mounts = slices.Clone(facts.Mounts.Mounts)
		site.Security.ResolvedSHA256 = facts.Mounts.ResolvedSHA256
	}
	if err := applySiteModSecurity(&site, facts.ModSecurity); err != nil {
		return edgesite.Site{}, err
	}
	if policy := entry.HTTPPolicy; policy != nil {
		var edge httppolicycontrol.EdgeSitePolicy
		if err := decodeStrictJSON(policy.Edge, &edge); err != nil || edge.SiteID != runtime.ID || edge.MaxUploadBytes < 1 {
			return edgesite.Site{}, fmt.Errorf("http policy entry")
		}
		digest, err := addReferencedObject(referenced, policy.Edge)
		if err != nil {
			return edgesite.Site{}, err
		}
		site.HTTP = &edgesite.Ref{Kind: edgesite.RefHTTPPolicy, ID: policy.PolicyID,
			Revision: policy.PolicyRevision, SHA256: digest}
		// v7 writes the policy's upload limit as the location's
		// client_max_body_size; without a policy the system limit applies (0).
		site.Limits.MaxBodyBytes = edge.MaxUploadBytes
	}
	if facts.ErrorPages != nil {
		for _, page := range facts.ErrorPages {
			body, found := facts.ErrorAssets[page.Asset.SHA256]
			if !found {
				return edgesite.Site{}, fmt.Errorf("error page %s %d: asset %s missing", page.Category, page.Status, page.Asset.SHA256)
			}
			if digest, err := addReferencedObject(referenced, body); err != nil || digest != page.Asset.SHA256 {
				return edgesite.Site{}, fmt.Errorf("error page %s %d: asset does not match its digest", page.Category, page.Status)
			}
		}
		for _, variant := range facts.ErrorVariants {
			body, found := facts.ErrorAssets[variant.Asset.SHA256]
			if !found {
				return edgesite.Site{}, fmt.Errorf("error page variant %s: asset %s missing", variant.RuleID, variant.Asset.SHA256)
			}
			if digest, err := addReferencedObject(referenced, body); err != nil || digest != variant.Asset.SHA256 {
				return edgesite.Site{}, fmt.Errorf("error page variant %s: asset does not match its digest", variant.RuleID)
			}
		}
		site.ErrorVariants = slices.Clone(facts.ErrorVariants)
		site.Errors = slices.Clone(facts.ErrorPages)
		sort.Slice(site.Errors, func(i, j int) bool {
			if site.Errors[i].Category != site.Errors[j].Category {
				return site.Errors[i].Category < site.Errors[j].Category
			}
			return site.Errors[i].Status < site.Errors[j].Status
		})
	}
	if runtime.PackageLimits != nil {
		site.Limits.Connections = &edgesite.Connections{SubscriptionID: runtime.PackageLimits.SubscriptionID,
			Max: runtime.PackageLimits.Connections, BandwidthBPS: runtime.PackageLimits.BandwidthBPS,
			MaxConnections: runtime.PackageLimits.MaxConnections, NewPerSecond: runtime.PackageLimits.NewPerSecond,
			QPS: runtime.PackageLimits.QPS, Stopped: runtime.PackageLimits.Stopped}
	}
	if entry.Telemetry != nil {
		capture := entry.Telemetry.Capture
		for _, list := range []*[]string{&capture.Methods, &capture.URIPrefixes, &capture.RequestHeaderAllowlist,
			&capture.ResponseHeaderAllowlist, &capture.RequestBodyFieldAllowlist, &capture.ResponseBodyFieldAllowlist} {
			if *list == nil {
				*list = []string{}
			}
		}
		site.Telemetry = &edgesite.Telemetry{PackageSubscriptionID: entry.Telemetry.PackageSubscriptionID, Capture: capture}
	}
	return site, nil
}

func convertSiteListenerV2(listener siteRuntimeV2Listener) (edgesite.Listener, error) {
	result := edgesite.Listener{Port: int(listener.Port), AddressFamily: listener.AddressFamily,
		HTTP2: slices.Contains(listener.Protocols, "http2"), HTTP3: slices.Contains(listener.Protocols, "http3")}
	if !slices.Contains(listener.Protocols, "http1") {
		return edgesite.Listener{}, fmt.Errorf("listener %d without http1 (shared servers always serve HTTP/1.1)", listener.Port)
	}
	if listener.TLS != nil {
		protocols := edgeconfig.BaselineTLSProtocols() // nginx's default when the document names none
		if listener.TLS.Protocols != nil {
			protocols = slices.Clone(listener.TLS.Protocols) // already the ascending range
		}
		result.TLS = &edgesite.TLS{CertificateVersionID: listener.TLS.CertificateVersionID, Protocols: protocols,
			CipherPreset: listener.TLS.CipherPreset, CipherSuites: slices.Clone(listener.TLS.CipherSuites), OCSPStapling: listener.TLS.OCSPStapling, ClientAuth: listener.TLS.ClientAuth,
			PreferServerCiphers: listener.TLS.PreferServerCiphers}
	}
	return result, nil
}

// attachSiteClientCAV2 references the site's client CA bundle (the release
// file client-ca/<hex>.pem) as an object of the site.
func attachSiteClientCAV2(site *edgesite.Site, runtime siteRuntimeV2Site, files, referenced map[string][]byte) error {
	for index, listener := range runtime.Listeners {
		if listener.TLS == nil || listener.TLS.ClientCARef == "" {
			continue
		}
		content, ok := files[edgeconfig.ClientCAPath(listener.TLS.ClientCARef)]
		digest := siteobject.Digest(content)
		if !ok || "sha256:"+digest != listener.TLS.ClientCARef {
			return fmt.Errorf("client CA file")
		}
		referenced[digest] = bytes.Clone(content)
		for target := range site.Listeners {
			if site.Listeners[target].Port == int(runtime.Listeners[index].Port) && site.Listeners[target].TLS != nil {
				site.Listeners[target].TLS.ClientCA = &edgesite.Ref{Kind: edgesite.RefClientCA, ID: runtime.ID,
					Revision: runtime.Revision, SHA256: digest}
			}
		}
	}
	return nil
}

// convertSiteOriginV2 is the agent's overlay (siteruntimev2
// overlayOriginRoutePolicies) as data: the origin-route document, when the
// site has one, replaces the pools it names (algorithm, endpoints, retry
// budget), the default pool and adds routes; pools only in the runtime keep
// their own values. TLS endpoint settings are kept by endpoint ID.
func convertSiteOriginV2(runtime siteRuntimeV2Site, route json.RawMessage, auth []edgesite.OriginAuth) (edgesite.Origin, error) {
	origin := edgesite.Origin{DefaultPoolID: runtime.DefaultPoolID, Routes: []edgesite.Route{}, Auth: []edgesite.OriginAuth{}}
	pools := map[string]*edgesite.Pool{}
	runtimeEndpoints := map[string]map[string]siteRuntimeV2Origin{}
	for _, pool := range runtime.OriginPools {
		converted := edgesite.Pool{ID: pool.ID, Kind: pool.Kind, Algorithm: pool.Algorithm,
			Retry: edgesite.Retry{Methods: slices.Sorted(slices.Values(pool.Retry.Methods)), MaxAttempts: int(pool.Retry.MaxAttempts),
				ConnectTimeoutMS: int(pool.Retry.ConnectTimeoutMS), ReadTimeoutMS: int(pool.Retry.ReadTimeoutMS),
				TotalBudgetMS: int(pool.Retry.TotalBudgetMS)},
			KeepaliveIdleTimeoutMS: pool.KeepaliveIdleTimeoutMS}
		if pool.HashKey != nil {
			converted.HashKey = *pool.HashKey
		}
		if pool.Sticky != nil {
			converted.Sticky = &edgesite.Sticky{Source: pool.Sticky.Source, Name: pool.Sticky.Name}
		}
		if pool.RequestHost != nil {
			converted.RequestHost = &edgesite.RequestHost{Mode: pool.RequestHost.Mode}
			if pool.RequestHost.Value != nil {
				converted.RequestHost.Value = *pool.RequestHost.Value
			}
		}
		converted.FollowPort = pool.FollowPort != nil && *pool.FollowPort
		if pool.ActiveLevel != nil {
			converted.ActiveLevel = int(*pool.ActiveLevel)
		}
		runtimeEndpoints[pool.ID] = map[string]siteRuntimeV2Origin{}
		for _, endpoint := range pool.Origins {
			converted.Endpoints = append(converted.Endpoints, convertSiteEndpointV2(endpoint))
			runtimeEndpoints[pool.ID][endpoint.ID] = endpoint
		}
		pools[pool.ID] = &converted
	}
	if route != nil {
		var document siteOriginRouteDocument
		if err := decodeStrictJSON(route, &document); err != nil {
			return edgesite.Origin{}, fmt.Errorf("origin route: %v", err)
		}
		retry := document.Retry
		levels, activeLevel := siteOriginLevels(runtime)
		for _, routePool := range document.Pools {
			pool := pools[routePool.ID]
			if pool == nil {
				// A route pool absent from the runtime: plain origins with
				// the runtime's first pool as the retry template.
				template := runtime.OriginPools[0].Retry
				pool = &edgesite.Pool{ID: routePool.ID, Kind: routePool.Kind,
					Retry: edgesite.Retry{Methods: slices.Sorted(slices.Values(template.Methods))}}
				pools[routePool.ID] = pool
			} else if pool.Kind != routePool.Kind {
				return edgesite.Origin{}, fmt.Errorf("origin route pool %s kind differs from the runtime", routePool.ID)
			}
			pool.Retry.MaxAttempts, pool.Retry.ConnectTimeoutMS = retry.MaxAttempts, retry.ConnectTimeoutMS
			pool.Retry.ReadTimeoutMS, pool.Retry.TotalBudgetMS = retry.ReadTimeoutMS, retry.TotalBudgetMS
			if pool.Kind == edgesite.PoolOrigin && routeKeepsPool(runtimeEndpoints[routePool.ID], routePool) {
				// The basic route fact of a signed pool (every site has one):
				// the pool keeps its TLS, backup, connection bounds and
				// balancing (hash/sticky have no origin-route form), as the
				// agent's overlay does (siteruntimev2 originPlansDiffer).
				continue
			}
			pool.Algorithm = routePool.BalanceMethod
			pool.HashKey, pool.Sticky = "", nil
			pool.Endpoints = nil
			for _, endpoint := range routePool.Endpoints {
				converted := edgesite.Endpoint{ID: endpoint.ID, Scheme: "http", Host: endpoint.Host, Port: endpoint.Port,
					Weight: endpoint.Weight, NodeID: endpoint.NodeID, MTLSIdentitySHA256: endpoint.MTLSIdentitySHA256,
					TopologyRevision: endpoint.TopologyRevision}
				if previous, ok := runtimeEndpoints[routePool.ID][endpoint.ID]; ok && previous.Scheme == "https" {
					if previous.Host != endpoint.Host || previous.Port != int64(endpoint.Port) {
						return edgesite.Origin{}, fmt.Errorf("origin route cannot replace TLS endpoint %s", endpoint.ID)
					}
					tls := convertSiteEndpointV2(previous)
					converted.Scheme, converted.SNI, converted.TrustAnchor = tls.Scheme, tls.SNI, tls.TrustAnchor
				}
				pool.Endpoints = append(pool.Endpoints, converted)
			}
			if pool.Kind == edgesite.PoolL2 {
				// the route document sorts endpoints by id; an L2 pool keeps
				// the runtime's order (the L2 configuration's member sort, A19)
				slices.SortStableFunc(pool.Endpoints, func(left, right edgesite.Endpoint) int {
					return int(runtimeEndpoints[routePool.ID][left.ID].Position - runtimeEndpoints[routePool.ID][right.ID].Position)
				})
			}
			if pool.Kind == edgesite.PoolOrigin {
				applySiteOriginLevels(pool, levels, activeLevel)
			}
		}
		origin.DefaultPoolID = document.DefaultPoolID
		origin.DefaultFallbackPoolID = document.DefaultFallbackPoolID
		origin.IngressSource = document.IngressSourceEnabled
		for _, value := range document.Routes {
			origin.Routes = append(origin.Routes, edgesite.Route{ID: value.ID, Priority: value.Priority,
				PathPrefix: value.PathPrefix, ClientCIDRs: value.ClientCIDRs, NodeRegions: value.NodeRegions,
				Hosts: value.Hosts, PoolID: value.PoolID, FallbackPoolID: value.FallbackPoolID})
		}
	}
	for _, id := range slices.Sorted(maps.Keys(pools)) {
		pools[id].ExpandSNIModes() // v7 SNI semantics as an explicit sni_mode
		origin.Pools = append(origin.Pools, *pools[id])
	}
	if *runtime.L2.Enabled {
		if runtime.L2.DirectFallbackPoolID == nil {
			return edgesite.Origin{}, fmt.Errorf("l2 without a direct fallback pool")
		}
		origin.L2 = &edgesite.L2{DirectFallbackPoolID: *runtime.L2.DirectFallbackPoolID,
			ProbeIntervalMS: int(runtime.L2.ProbeIntervalMS), FailureThreshold: int(runtime.L2.FailureThreshold),
			RecoveryThreshold: int(runtime.L2.RecoveryThreshold), CacheOnly: runtime.L2.CacheOnly,
			Passthrough: runtime.L2.Passthrough}
		for _, condition := range runtime.L2.Conditions {
			origin.L2.Conditions = append(origin.L2.Conditions, edgesite.L2Condition{ID: condition.ID,
				Rules: slices.Clone(condition.Rules), NodeIDs: slices.Clone(condition.NodeIDs),
				EndpointIDs: slices.Clone(condition.EndpointIDs)})
		}
	}
	if auth != nil {
		origin.Auth = slices.Clone(auth)
		sort.Slice(origin.Auth, func(i, j int) bool { return origin.Auth[i].PoolID < origin.Auth[j].PoolID })
	}
	return origin, nil
}

func convertSiteEndpointV2(endpoint siteRuntimeV2Origin) edgesite.Endpoint {
	result := edgesite.Endpoint{ID: endpoint.ID, Scheme: endpoint.Scheme, Host: endpoint.Host,
		Port: int(endpoint.Port), Weight: int(endpoint.Weight)}
	if endpoint.SNI != nil {
		result.SNI = *endpoint.SNI
	}
	if endpoint.TrustRef != nil {
		result.TrustAnchor = *endpoint.TrustRef
	}
	if endpoint.NodeID != nil {
		result.NodeID = *endpoint.NodeID
	}
	if endpoint.Level != nil {
		result.Level = int(*endpoint.Level)
	}
	if endpoint.MaxConns != nil {
		result.MaxConns = int(*endpoint.MaxConns)
	}
	return result
}

// siteOriginLevels: the failover level of each site origin by host:port
// (unique per site, site_origins) and the site's active level.
func siteOriginLevels(runtime siteRuntimeV2Site) (map[string]int, int) {
	levels, active := map[string]int{}, 0
	for _, pool := range runtime.OriginPools {
		if pool.Kind != edgesite.PoolOrigin {
			continue
		}
		if pool.ActiveLevel != nil {
			active = int(*pool.ActiveLevel)
		}
		for _, endpoint := range pool.Origins {
			if endpoint.Level != nil {
				levels[siteOriginLevelKey(endpoint.Host, int(endpoint.Port))] = int(*endpoint.Level)
			}
		}
	}
	return levels, active
}

func siteOriginLevelKey(host string, port int) string {
	if normalized, err := normalizeSiteOriginRouteHost(host); err == nil {
		host = normalized
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// applySiteOriginLevels gives a pool replaced by a custom origin route the
// levels of the site origins it lists (others are primaries) and the site's
// active level, so failover walks the levels there too (cdnca_origin.lua
// compile_pool). A pool without a primary among them, or with no level at
// or above the active one, stays a plain pool: there an active level would
// either be invalid (edgesite: a pool needs level 0) or make the node fall
// back to every level at once.
func applySiteOriginLevels(pool *edgesite.Pool, levels map[string]int, active int) {
	primaries, highest := 0, 0
	for index := range pool.Endpoints {
		endpoint := &pool.Endpoints[index]
		endpoint.Level = levels[siteOriginLevelKey(endpoint.Host, endpoint.Port)]
		if endpoint.Level == 0 {
			primaries++
		}
		highest = max(highest, endpoint.Level)
	}
	if primaries == 0 {
		for index := range pool.Endpoints {
			pool.Endpoints[index].Level = 0
		}
		highest = 0
	}
	pool.ActiveLevel = 0
	if active <= highest {
		pool.ActiveLevel = active
	}
}

// routeKeepsPool: the route pool lists exactly the runtime pool's endpoints
// (id, host, port, weight, in order).
func routeKeepsPool(runtime map[string]siteRuntimeV2Origin, pool siteOriginRoutePool) bool {
	if len(runtime) == 0 || len(runtime) != len(pool.Endpoints) {
		return false
	}
	for _, endpoint := range pool.Endpoints {
		value, ok := runtime[endpoint.ID]
		if !ok || value.Host != endpoint.Host || value.Port != int64(endpoint.Port) || value.Weight != int64(endpoint.Weight) {
			return false
		}
	}
	return true
}

func convertSiteCacheV2(runtime siteRuntimeV2Site, tenantID string) (*edgesite.Cache, error) {
	value := runtime.Cache
	if value.TenantID != tenantID {
		return nil, fmt.Errorf("cache tenant differs from the scope tenant")
	}
	policy := value.Policy
	if policy.Rules == nil {
		policy.Rules = []edgeconfig.CacheRuleDocument{}
	}
	if policy.QueryNames == nil {
		policy.QueryNames = []string{}
	}
	if policy.VaryHeaders == nil {
		policy.VaryHeaders = []string{}
	}
	cache := &edgesite.Cache{KeyPrefix: edgesite.CacheKeyPrefix(tenantID, runtime.ID), Domain: value.Domain,
		KeyByHost: !value.SharedAcrossDomains, Policy: policy}
	token, err := edgesite.CacheGeneration(*cache)
	if err != nil {
		return nil, err
	}
	cache.Generation = token
	return cache, nil
}

// convertSiteSecurityV2: v7 compiles a site's security once per listener
// (siteRuntimeV2ListenerSecurity); the bound policies, managed WAF and
// challenge are the site's, so every listener carries the same ones, and
// only the rules (a "port" condition resolves per listener) and the CC
// binding may differ by port.
func convertSiteSecurityV2(runtime siteRuntimeV2Site, listeners []siteRuntimeV2Listener, tenantID string,
	files, referenced map[string][]byte) (edgesite.Security, error) {
	security := edgesite.Security{
		Rules: edgesite.RulePlan{HeaderOverflow: edgesite.HeaderOverflowNoMatch, Policies: []edgesite.RulePolicy{}},
		CC:    []edgesite.CCBinding{},
	}
	present := 0
	var first *edgeconfig.ListenerSecurity
	for _, listener := range listeners {
		if listener.Security != nil {
			present++
			if first == nil {
				first = listener.Security
			}
		}
	}
	if present != 0 && present != len(listeners) {
		return edgesite.Security{}, fmt.Errorf("security is bound on some listeners only")
	}
	if first != nil {
		for _, listener := range listeners {
			if !sameJSON(listener.Security.ManagedWAF, first.ManagedWAF) || !sameJSON(listener.Security.Challenge, first.Challenge) ||
				len(listener.Security.Policies) != len(first.Policies) {
				return edgesite.Security{}, fmt.Errorf("listeners carry different site security")
			}
		}
		for index, policy := range first.Policies {
			plan, err := mergeSiteRulePolicyV2(listeners, index, policy)
			if err != nil {
				return edgesite.Security{}, err
			}
			security.Rules.Policies = append(security.Rules.Policies, plan)
		}
		if first.ManagedWAF != nil {
			normalized, err := edgeconfig.CanonicalListenerManagedWAF(*first.ManagedWAF)
			if err != nil {
				return edgesite.Security{}, fmt.Errorf("managed WAF: %v", err)
			}
			managed := edgesite.ManagedWAFFromEdge(*normalized)
			security.ManagedWAF = &managed
			if normalized.InspectionLimitAction == edgeconfig.ManagedWAFInspectionBlock {
				security.Rules.HeaderOverflow = edgesite.HeaderOverflowBlock // v7 headerOverflowBlocks
			}
		}
		if challenge := first.Challenge; challenge != nil {
			if challenge.TenantID != tenantID || challenge.PolicyVersion > uint64(edgesite.MaxSafeInteger) {
				return edgesite.Security{}, fmt.Errorf("challenge identity")
			}
			security.Challenge = &edgesite.Ref{Kind: edgesite.RefChallenge, ID: challenge.PolicyID, Revision: int64(challenge.PolicyVersion)}
		}
		bindings, err := convertSiteCCBindingsV2(listeners, referenced)
		if err != nil {
			return edgesite.Security{}, err
		}
		security.CC = bindings
	}
	if action := runtime.FirewallAction; action != nil {
		content, ok := files[action.ArtifactPath]
		digest := siteobject.Digest(content)
		if !validFirewallActionArtifactPath(runtime.ID, action.ArtifactPath) || !ok || digest != action.DocumentSHA256 {
			return edgesite.Security{}, fmt.Errorf("firewall action file")
		}
		referenced[digest] = bytes.Clone(content)
		security.FirewallAction = &edgesite.Ref{Kind: edgesite.RefFirewallAction, ID: action.PolicyID,
			Revision: action.PolicyRevision, SHA256: digest}
	}
	return security, nil
}

func sameJSON(left, right any) bool {
	leftBytes, leftErr := json.Marshal(left)
	rightBytes, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

// mergeSiteRulePolicyV2 is policy index of every listener as one plan
// policy: once, port-free, when the listeners' rules differ only by the port
// v7 pins them to; otherwise every listener's rules in port order, each
// pinned to its listener's port (only that port can match it, so each
// port's last-match-wins result is unchanged).
func mergeSiteRulePolicyV2(listeners []siteRuntimeV2Listener, index int, header edgeconfig.SecurityPolicy) (edgesite.RulePolicy, error) {
	plan := edgesite.RulePolicy{Kind: header.Kind, PolicyID: header.PolicyID, PolicyVersion: header.PolicyVersion,
		BindingRevision: header.BindingRevision, RuntimeSHA256: header.RuntimeSHA256, Enabled: header.Enabled,
		DefaultAction: header.DefaultAction, Rules: []edgeconfig.WAFRule{}, Mode: header.Mode, AutoBlock: header.AutoBlock}
	perListener := make([][]edgeconfig.WAFRule, len(listeners))
	portFree := make([][]byte, len(listeners))
	for listenerIndex, listener := range listeners {
		policy := listener.Security.Policies[index]
		if policy.Kind != header.Kind || policy.PolicyID != header.PolicyID || policy.PolicyVersion != header.PolicyVersion ||
			policy.BindingRevision != header.BindingRevision || policy.RuntimeSHA256 != header.RuntimeSHA256 ||
			policy.Enabled != header.Enabled || policy.DefaultAction != header.DefaultAction ||
			policy.Mode != header.Mode || !sameJSON(policy.AutoBlock, header.AutoBlock) {
			return edgesite.RulePolicy{}, fmt.Errorf("listeners bind different %s policies", header.Kind)
		}
		port := uint16(listener.Port)
		stripped := make([]edgeconfig.WAFRule, 0, len(policy.Rules))
		for _, rule := range policy.Rules {
			normalized, err := edgeconfig.NormalizeSecurityRule(rule)
			if err != nil {
				return edgesite.RulePolicy{}, fmt.Errorf("rule %s: %v", rule.RuleID, err)
			}
			switch normalized.Match.Port {
			case 0, port:
			default:
				continue // pinned to another port: can never match on this listener
			}
			normalized.Match.Port = port
			perListener[listenerIndex] = append(perListener[listenerIndex], normalized)
			normalized.Match.Port = 0
			stripped = append(stripped, normalized)
		}
		portFree[listenerIndex], _ = json.Marshal(stripped)
	}
	same := true
	for _, value := range portFree[1:] {
		same = same && bytes.Equal(value, portFree[0])
	}
	if same {
		for _, rule := range perListener[0] {
			rule.Match.Port = 0
			plan.Rules = append(plan.Rules, rule)
		}
		return plan, nil
	}
	for _, rules := range perListener {
		plan.Rules = append(plan.Rules, rules...)
	}
	return plan, nil
}

// convertSiteCCBindingsV2 groups listeners by their CC binding: one
// referenced CC policy object (its canonical encoding, digest =
// CompiledSHA256) per distinct binding.
func convertSiteCCBindingsV2(listeners []siteRuntimeV2Listener, referenced map[string][]byte) ([]edgesite.CCBinding, error) {
	byDigest := map[string]*edgesite.CCBinding{}
	var order []string
	for _, listener := range listeners {
		binding := listener.Security.CC
		if binding == nil {
			continue
		}
		canonical, err := edgeconfig.CanonicalCCV2Policy(binding.Policy)
		if err != nil {
			return nil, fmt.Errorf("cc policy: %v", err)
		}
		sum := sha256.Sum256(canonical)
		if hex.EncodeToString(sum[:]) != binding.CompiledSHA256 {
			return nil, fmt.Errorf("cc policy digest")
		}
		key := binding.CompiledSHA256 + "|" + binding.SourceSHA256
		if byDigest[key] == nil {
			if _, err := addReferencedObject(referenced, canonical); err != nil {
				return nil, err
			}
			byDigest[key] = &edgesite.CCBinding{SourceSHA256: binding.SourceSHA256, Policy: edgesite.Ref{
				Kind: edgesite.RefCCPolicy, ID: binding.Policy.PolicyID, Revision: binding.Policy.PolicyVersion,
				SHA256: binding.CompiledSHA256}}
			order = append(order, key)
		}
		byDigest[key].Ports = append(byDigest[key].Ports, int(listener.Port))
	}
	result := make([]edgesite.CCBinding, 0, len(order))
	for _, key := range order {
		result = append(result, *byDigest[key])
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Ports[0] < result[j].Ports[0] })
	return result, nil
}
