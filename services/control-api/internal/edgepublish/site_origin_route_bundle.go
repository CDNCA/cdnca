package edgepublish

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	siteOriginRouteSchemaV1     = "cdnca.edge.origin-route/v1"
	siteOriginRouteBundleSchema = "cdnca.edge.origin-route-bundle/v1"
	siteOriginRouteBundlePath   = "origin-route.v1.json"
)

var siteOriginRouteTokenPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
var siteOriginRouteMTLSIdentityPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type siteOriginRouteEndpoint struct {
	ID                 string `json:"id"`
	Tier               string `json:"tier,omitempty"`
	NodeID             string `json:"node_id,omitempty"`
	TopologyRevision   int64  `json:"topology_revision,omitempty"`
	MTLSIdentitySHA256 string `json:"mtls_identity_sha256,omitempty"`
	Host               string `json:"host"`
	Port               int    `json:"port"`
	Weight             int    `json:"weight"`
}

type siteOriginRoutePool struct {
	ID            string                    `json:"id"`
	Kind          string                    `json:"kind,omitempty"`
	BalanceMethod string                    `json:"balance_method,omitempty"`
	Endpoints     []siteOriginRouteEndpoint `json:"endpoints"`
}

type siteOriginRoute struct {
	ID             string   `json:"id"`
	Priority       int      `json:"priority"`
	PathPrefix     string   `json:"path_prefix,omitempty"`
	NodeRegions    []string `json:"node_regions,omitempty"`
	ClientCIDRs    []string `json:"client_cidrs,omitempty"`
	Hosts          []string `json:"hosts,omitempty"`
	PoolID         string   `json:"pool_id"`
	FallbackPoolID string   `json:"fallback_pool_id,omitempty"`
}

type siteOriginRouteRetry struct {
	Methods          []string `json:"methods"`
	MaxAttempts      int      `json:"max_attempts"`
	ConnectTimeoutMS int      `json:"connect_timeout_ms"`
	ReadTimeoutMS    int      `json:"read_timeout_ms"`
	TotalBudgetMS    int      `json:"total_budget_ms"`
}

type siteOriginRouteDocument struct {
	Schema                string                `json:"schema"`
	IngressSourceEnabled  bool                  `json:"ingress_source_enabled"`
	Pools                 []siteOriginRoutePool `json:"pools"`
	DefaultPoolID         string                `json:"default_pool_id"`
	DefaultFallbackPoolID string                `json:"default_fallback_pool_id,omitempty"`
	Routes                []siteOriginRoute     `json:"routes"`
	Retry                 siteOriginRouteRetry  `json:"retry"`
}

type siteOriginRouteFact struct {
	siteID       uuid.UUID
	siteRevision int64
	document     siteOriginRouteDocument
}

type siteOriginRouteBundleDocument struct {
	Schema               string                        `json:"schema"`
	ConfigurationScopeID string                        `json:"configuration_scope_id"`
	SourceRevision       int64                         `json:"source_revision"`
	ConfigVersionID      string                        `json:"config_version_id"`
	Targets              []siteOriginRouteBundleTarget `json:"targets,omitempty"`
	Sites                []siteOriginRouteBundleSite   `json:"sites"`
}

type siteOriginRouteBundleTarget struct {
	NodeID             string `json:"node_id"`
	Tier               string `json:"tier"`
	TopologyRevision   int64  `json:"topology_revision"`
	MTLSIdentitySHA256 string `json:"mtls_identity_sha256"`
}

type siteOriginRouteBundleSite struct {
	SiteID       string                  `json:"site_id"`
	SiteRevision int64                   `json:"site_revision"`
	Document     siteOriginRouteDocument `json:"document"`
}

// basicSiteOriginRouteFact maps the ordinary site origin pool into the signed
// origin-route contract. Advanced route rows replace this fact when present.
func basicSiteOriginRouteFact(site siteRuntimeV2Site) (siteOriginRouteFact, error) {
	return basicSiteOriginRouteFactWithTopology(site, nil)
}

func basicSiteOriginRouteFactWithTopology(site siteRuntimeV2Site, topology *L2TopologySnapshot) (siteOriginRouteFact, error) {
	siteID, err := uuid.Parse(site.ID)
	if err != nil || siteID == uuid.Nil || siteID.String() != site.ID || site.Revision < 1 || site.Revision > maxSiteRuntimeV2SafeInteger {
		return siteOriginRouteFact{}, ErrInvalidInput
	}
	if site.DefaultPoolID == "" || len(site.OriginPools) == 0 {
		return siteOriginRouteFact{}, ErrInvalidInput
	}
	document := siteOriginRouteDocument{Schema: siteOriginRouteSchemaV1, DefaultPoolID: site.DefaultPoolID}
	for _, pool := range site.OriginPools {
		if (pool.Kind != "origin" && pool.Kind != "l2") || len(pool.Origins) == 0 || len(pool.Origins) > 32 {
			return siteOriginRouteFact{}, ErrInvalidInput
		}
		balance := pool.Algorithm
		if balance == "" || balance == "hash" || balance == "sticky" {
			// The origin-route form has no key; the node keeps the signed
			// pool's balancing when the endpoints match (overlay).
			balance = "round_robin"
		}
		if !validSiteOriginRouteBalance(balance) {
			return siteOriginRouteFact{}, ErrInvalidInput
		}
		if pool.Retry.BodylessOnly == nil || pool.Retry.ResponseNotStarted == nil ||
			len(pool.Retry.Methods) != 2 || len(pool.Retry.RetryOn) != 6 {
			return siteOriginRouteFact{}, ErrInvalidInput
		}
		routePool := siteOriginRoutePool{ID: pool.ID, Kind: pool.Kind, BalanceMethod: balance, Endpoints: make([]siteOriginRouteEndpoint, len(pool.Origins))}
		for index, origin := range pool.Origins {
			host, err := normalizeSiteOriginRouteHost(origin.Host)
			if err != nil || origin.ID == "" || origin.Port < 1 || origin.Port > 65535 || origin.Weight < 1 || origin.Weight > 100 {
				return siteOriginRouteFact{}, ErrInvalidInput
			}
			endpoint := siteOriginRouteEndpoint{ID: origin.ID, Tier: pool.Kind, Host: host, Port: int(origin.Port), Weight: int(origin.Weight)}
			if pool.Kind == "l2" {
				bound, ok := findL2TopologyEndpoint(topology, origin)
				if !ok {
					return siteOriginRouteFact{}, ErrTargetSnapshotConflict
				}
				endpoint.NodeID = bound.NodeID.String()
				endpoint.TopologyRevision = topology.Revision
				endpoint.MTLSIdentitySHA256 = "sha256:" + fmt.Sprintf("%x", bound.MTLSIdentitySHA256[:])
			}
			routePool.Endpoints[index] = endpoint
		}
		document.Pools = append(document.Pools, routePool)
		if document.Retry.MaxAttempts == 0 {
			document.Retry = siteOriginRouteRetry{
				Methods: append([]string(nil), pool.Retry.Methods...), MaxAttempts: int(pool.Retry.MaxAttempts),
				ConnectTimeoutMS: int(pool.Retry.ConnectTimeoutMS), ReadTimeoutMS: int(pool.Retry.ReadTimeoutMS),
				TotalBudgetMS: int(pool.Retry.TotalBudgetMS),
			}
		}
	}
	if site.L2.Enabled != nil && *site.L2.Enabled {
		if site.L2.DirectFallbackPoolID == nil {
			return siteOriginRouteFact{}, ErrTargetSnapshotConflict
		}
		document.DefaultFallbackPoolID = *site.L2.DirectFallbackPoolID
	}
	normalized, err := normalizeSiteOriginRouteDocument(document)
	if err != nil {
		return siteOriginRouteFact{}, fmt.Errorf("normalize basic origin route: %w", err)
	}
	return siteOriginRouteFact{siteID: siteID, siteRevision: site.Revision, document: normalized}, nil
}

func normalizeSiteOriginRouteHost(value string) (string, error) {
	if value == "" || strings.TrimSpace(value) != value || strings.HasSuffix(value, ".") {
		return "", ErrInvalidInput
	}
	if address, err := netip.ParseAddr(value); err == nil {
		if address.Is4In6() || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() ||
			address.IsLinkLocalUnicast() || address == netip.MustParseAddr("255.255.255.255") {
			return "", ErrInvalidInput
		}
		return address.String(), nil
	}
	value = strings.ToLower(value)
	if !validSiteRuntimeV2Host(value) || strings.Contains(value, "*") || !strings.Contains(value, ".") || value == "localhost" {
		return "", ErrInvalidInput
	}
	last := value[strings.LastIndexByte(value, '.')+1:]
	if strings.IndexFunc(last, func(r rune) bool { return r >= 'a' && r <= 'z' }) < 0 {
		return "", ErrInvalidInput
	}
	return value, nil
}

func loadSiteOriginRouteFacts(
	ctx context.Context,
	tx pgx.Tx,
	scopeID uuid.UUID,
	sites []siteRuntimeV2Site,
	topology *L2TopologySnapshot,
) ([]siteOriginRouteFact, error) {
	if scopeID == uuid.Nil || len(sites) > maxSiteRuntimeV2Sites {
		return nil, ErrInvalidInput
	}
	if len(sites) == 0 {
		return nil, nil
	}
	revisions := make(map[uuid.UUID]int64, len(sites))
	siteIDs := make([]uuid.UUID, len(sites))
	basic := make(map[uuid.UUID]siteOriginRouteFact, len(sites))
	for index, value := range sites {
		siteID, err := uuid.Parse(value.ID)
		if err != nil || siteID == uuid.Nil || siteID.String() != value.ID || value.Revision < 1 ||
			value.Revision > maxSiteRuntimeV2SafeInteger {
			return nil, ErrInvalidInput
		}
		if _, duplicate := revisions[siteID]; duplicate {
			return nil, ErrInvalidInput
		}
		revisions[siteID], siteIDs[index] = value.Revision, siteID
		fact, err := basicSiteOriginRouteFactWithTopology(value, topology)
		if err != nil {
			return nil, fmt.Errorf("%w: build basic site origin-route fact", ErrPersistence)
		}
		basic[siteID] = fact
	}

	rows, err := tx.Query(ctx, `SELECT config.site_id,config.schema,config.default_pool_id,
		COALESCE(config.default_fallback_pool_id,''),config.retry_methods,config.max_attempts,
		config.connect_timeout_ms,config.read_timeout_ms,config.total_budget_ms,config.ingress_source_enabled
		FROM site_origin_route_configs config
		JOIN sites site ON site.id=config.site_id AND site.scope_id=$1
		WHERE config.site_id=ANY($2::uuid[])
		ORDER BY config.site_id FOR SHARE OF config`, scopeID, siteIDs)
	if err != nil {
		return nil, fmt.Errorf("%w: read site origin-route configs", ErrPersistence)
	}
	facts := make(map[uuid.UUID]*siteOriginRouteFact)
	orderedIDs := make([]uuid.UUID, 0)
	for rows.Next() {
		var fact siteOriginRouteFact
		if err := rows.Scan(&fact.siteID, &fact.document.Schema, &fact.document.DefaultPoolID,
			&fact.document.DefaultFallbackPoolID, &fact.document.Retry.Methods, &fact.document.Retry.MaxAttempts,
			&fact.document.Retry.ConnectTimeoutMS, &fact.document.Retry.ReadTimeoutMS,
			&fact.document.Retry.TotalBudgetMS, &fact.document.IngressSourceEnabled); err != nil {
			rows.Close()
			return nil, fmt.Errorf("%w: scan site origin-route configs", ErrPersistence)
		}
		revision, known := revisions[fact.siteID]
		if !known || facts[fact.siteID] != nil {
			rows.Close()
			return nil, fmt.Errorf("%w: validate site origin-route config ownership", ErrPersistence)
		}
		fact.siteRevision = revision
		facts[fact.siteID] = &fact
		orderedIDs = append(orderedIDs, fact.siteID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("%w: iterate site origin-route configs", ErrPersistence)
	}
	rows.Close()
	if len(facts) == 0 {
		result := make([]siteOriginRouteFact, len(siteIDs))
		for index, siteID := range siteIDs {
			result[index] = basic[siteID]
		}
		return result, nil
	}

	// host is canonical text (IP or DNS name, migration 485), read as stored.
	rows, err = tx.Query(ctx, `SELECT pool.site_id,pool.pool_id,pool.balance_method,
		endpoint.endpoint_id,endpoint.host,endpoint.port,endpoint.weight
		FROM site_origin_route_pools pool
		JOIN site_origin_route_configs config ON config.site_id=pool.site_id
		JOIN sites site ON site.id=config.site_id AND site.scope_id=$1
		JOIN site_origin_route_endpoints endpoint
		  ON endpoint.site_id=pool.site_id AND endpoint.pool_id=pool.pool_id
		WHERE pool.site_id=ANY($2::uuid[])
		ORDER BY pool.site_id,pool.position,pool.pool_id,endpoint.position,endpoint.endpoint_id
		FOR SHARE OF config,pool,endpoint`, scopeID, orderedIDs)
	if err != nil {
		return nil, fmt.Errorf("%w: read site origin-route pools", ErrPersistence)
	}
	for rows.Next() {
		var siteID uuid.UUID
		var poolID, balanceMethod string
		var endpoint siteOriginRouteEndpoint
		if err := rows.Scan(&siteID, &poolID, &balanceMethod, &endpoint.ID, &endpoint.Host,
			&endpoint.Port, &endpoint.Weight); err != nil {
			rows.Close()
			return nil, fmt.Errorf("%w: scan site origin-route pools", ErrPersistence)
		}
		fact := facts[siteID]
		if fact == nil {
			rows.Close()
			return nil, fmt.Errorf("%w: validate site origin-route pool ownership", ErrPersistence)
		}
		if len(fact.document.Pools) == 0 || fact.document.Pools[len(fact.document.Pools)-1].ID != poolID {
			fact.document.Pools = append(fact.document.Pools, siteOriginRoutePool{ID: poolID, Kind: "origin", BalanceMethod: balanceMethod})
		}
		pool := &fact.document.Pools[len(fact.document.Pools)-1]
		if pool.BalanceMethod != balanceMethod {
			rows.Close()
			return nil, fmt.Errorf("%w: inconsistent site origin-route pool", ErrPersistence)
		}
		pool.Endpoints = append(pool.Endpoints, endpoint)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("%w: iterate site origin-route pools", ErrPersistence)
	}
	rows.Close()

	rows, err = tx.Query(ctx, `SELECT route.site_id,route.route_id,route.priority,
		COALESCE(route.path_prefix,''),route.node_regions,route.client_cidrs::text[],
		route.pool_id,COALESCE(route.fallback_pool_id,''),route.hosts
		FROM site_origin_routes route
		JOIN site_origin_route_configs config ON config.site_id=route.site_id
		JOIN sites site ON site.id=config.site_id AND site.scope_id=$1
		WHERE route.site_id=ANY($2::uuid[])
		ORDER BY route.site_id,route.position,route.route_id FOR SHARE OF config,route`, scopeID, orderedIDs)
	if err != nil {
		return nil, fmt.Errorf("%w: read site origin routes", ErrPersistence)
	}
	for rows.Next() {
		var siteID uuid.UUID
		var route siteOriginRoute
		if err := rows.Scan(&siteID, &route.ID, &route.Priority, &route.PathPrefix, &route.NodeRegions,
			&route.ClientCIDRs, &route.PoolID, &route.FallbackPoolID, &route.Hosts); err != nil {
			rows.Close()
			return nil, fmt.Errorf("%w: scan site origin routes", ErrPersistence)
		}
		fact := facts[siteID]
		if fact == nil {
			rows.Close()
			return nil, fmt.Errorf("%w: validate site origin-route ownership", ErrPersistence)
		}
		fact.document.Routes = append(fact.document.Routes, route)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("%w: iterate site origin routes", ErrPersistence)
	}
	rows.Close()

	result := make([]siteOriginRouteFact, len(siteIDs))
	for index, siteID := range siteIDs {
		fact := basic[siteID]
		if advanced := facts[siteID]; advanced != nil {
			// a site whose own L2 is off (site-backend6) has no L2 pool
			// even under an L2 topology: its routes stay direct
			if l2Pool, ok := l2RoutePool(basic[siteID]); topology != nil && ok {
				for _, pool := range advanced.document.Pools {
					if pool.ID == l2Pool.ID {
						return nil, ErrTargetSnapshotConflict
					}
				}
				directFallback := advanced.document.DefaultPoolID
				advanced.document.Pools = append([]siteOriginRoutePool{l2Pool}, advanced.document.Pools...)
				advanced.document.DefaultPoolID = l2Pool.ID
				advanced.document.DefaultFallbackPoolID = directFallback
			}
			normalized, err := normalizeSiteOriginRouteDocument(advanced.document)
			if err != nil {
				return nil, fmt.Errorf("%w: validate stored site origin-route document", ErrPersistence)
			}
			advanced.document = normalized
			fact = *advanced
		}
		result[index] = fact
	}
	return result, nil
}

func l2RoutePool(fact siteOriginRouteFact) (siteOriginRoutePool, bool) {
	for _, pool := range fact.document.Pools {
		if pool.Kind == "l2" {
			return pool, true
		}
	}
	return siteOriginRoutePool{}, false
}

func findL2TopologyEndpoint(topology *L2TopologySnapshot, origin siteRuntimeV2Origin) (L2TopologyEndpoint, bool) {
	if topology == nil || origin.NodeID == nil {
		return L2TopologyEndpoint{}, false
	}
	if topology.Sites != nil {
		// a node-list publication: the endpoint is in some site's topology
		// (endpoint ids are per configuration member, siteL2PublicationTopology)
		for _, site := range topology.Sites {
			if endpoint, ok := findL2TopologyEndpoint(site, origin); ok {
				return endpoint, true
			}
		}
		return L2TopologyEndpoint{}, false
	}
	nodeID, err := uuid.Parse(*origin.NodeID)
	if err != nil || nodeID == uuid.Nil {
		return L2TopologyEndpoint{}, false
	}
	// the weight is the site's: an L2 configuration member's weight replaces
	// the line group endpoint's (A19, siteL2Topology)
	for _, endpoint := range topology.Endpoints {
		if endpoint.NodeID == nodeID && endpoint.EndpointID.String() == origin.ID &&
			endpoint.Address == origin.Host && endpoint.Port == int(origin.Port) {
			return endpoint, true
		}
	}
	return L2TopologyEndpoint{}, false
}

func compileSiteOriginRouteBundle(
	scopeID, configID uuid.UUID,
	sourceRevision int64,
	facts []siteOriginRouteFact,

) ([]byte, error) {
	return compileSiteOriginRouteBundleWithTopology(scopeID, configID, sourceRevision, facts, nil)
}

func compileSiteOriginRouteBundleWithTopology(
	scopeID, configID uuid.UUID,
	sourceRevision int64,
	facts []siteOriginRouteFact,
	topology *L2TopologySnapshot,
) ([]byte, error) {
	if scopeID == uuid.Nil || configID == uuid.Nil || sourceRevision < 1 ||
		sourceRevision > maxSiteRuntimeV2SafeInteger || len(facts) == 0 || len(facts) > maxSiteRuntimeV2Sites {
		return nil, ErrInvalidInput
	}
	values := append([]siteOriginRouteFact(nil), facts...)
	sort.Slice(values, func(i, j int) bool { return values[i].siteID.String() < values[j].siteID.String() })
	document := siteOriginRouteBundleDocument{
		Schema: siteOriginRouteBundleSchema, ConfigurationScopeID: scopeID.String(),
		SourceRevision: sourceRevision, ConfigVersionID: configID.String(),
		Sites: make([]siteOriginRouteBundleSite, len(values)),
	}
	if topology != nil {
		if topology.Revision < 1 || len(topology.TargetIdentities) == 0 {
			return nil, ErrTargetSnapshotConflict
		}
		document.Targets = make([]siteOriginRouteBundleTarget, len(topology.TargetIdentities))
		identities := append([]L2TopologyIdentity(nil), topology.TargetIdentities...)
		sort.Slice(identities, func(i, j int) bool { return identities[i].NodeID.String() < identities[j].NodeID.String() })
		for index, identity := range identities {
			if identity.NodeID == uuid.Nil || identity.MTLSIdentitySHA256 == ([sha256.Size]byte{}) ||
				index > 0 && identities[index-1].NodeID == identity.NodeID {
				return nil, ErrTargetSnapshotConflict
			}
			document.Targets[index] = siteOriginRouteBundleTarget{
				NodeID: identity.NodeID.String(), Tier: "l1", TopologyRevision: topology.Revision,
				MTLSIdentitySHA256: "sha256:" + fmt.Sprintf("%x", identity.MTLSIdentitySHA256[:]),
			}
		}
	}
	for index, fact := range values {
		if fact.siteID == uuid.Nil || fact.siteRevision < 1 || fact.siteRevision > maxSiteRuntimeV2SafeInteger ||
			index > 0 && values[index-1].siteID == fact.siteID {
			return nil, ErrInvalidInput
		}
		normalized, err := normalizeSiteOriginRouteDocument(fact.document)
		if err != nil {
			return nil, err
		}
		document.Sites[index] = siteOriginRouteBundleSite{
			SiteID: fact.siteID.String(), SiteRevision: fact.siteRevision, Document: normalized,
		}
	}
	content, err := json.Marshal(document)
	if err != nil {
		return nil, ErrInvalidInput
	}
	return content, nil
}

func normalizeSiteOriginRouteDocument(input siteOriginRouteDocument) (siteOriginRouteDocument, error) {
	if input.Schema != siteOriginRouteSchemaV1 || len(input.Pools) < 1 || len(input.Pools) > 64 || len(input.Routes) > 256 {
		return siteOriginRouteDocument{}, ErrInvalidInput
	}
	pools := make([]siteOriginRoutePool, len(input.Pools))
	poolIDs := make(map[string]struct{}, len(input.Pools))
	for index, pool := range input.Pools {
		kind := pool.Kind
		if kind == "" {
			kind = "origin"
		}
		if kind != "origin" && kind != "l2" || !siteOriginRouteTokenPattern.MatchString(pool.ID) || len(pool.Endpoints) < 1 || len(pool.Endpoints) > 32 ||
			!validSiteOriginRouteBalance(pool.BalanceMethod) {
			return siteOriginRouteDocument{}, ErrInvalidInput
		}
		if _, duplicate := poolIDs[pool.ID]; duplicate {
			return siteOriginRouteDocument{}, ErrInvalidInput
		}
		poolIDs[pool.ID] = struct{}{}
		endpoints := make([]siteOriginRouteEndpoint, len(pool.Endpoints))
		endpointIDs := make(map[string]struct{}, len(pool.Endpoints))
		sockets := make(map[string]struct{}, len(pool.Endpoints))
		for endpointIndex, endpoint := range pool.Endpoints {
			host, err := normalizeSiteOriginRouteHost(endpoint.Host)
			if err != nil || !siteOriginRouteTokenPattern.MatchString(endpoint.ID) || endpoint.Port < 1 || endpoint.Port > 65535 || endpoint.Weight < 1 || endpoint.Weight > 100 {
				return siteOriginRouteDocument{}, ErrInvalidInput
			}
			tier := endpoint.Tier
			if tier == "" && kind == "origin" {
				tier = "origin"
			}
			if kind == "l2" {
				if tier != "l2" || !canonicalSiteRuntimeV2UUID(endpoint.NodeID) || endpoint.TopologyRevision < 1 ||
					endpoint.TopologyRevision > maxSiteRuntimeV2SafeInteger || !siteOriginRouteMTLSIdentityPattern.MatchString(endpoint.MTLSIdentitySHA256) {
					return siteOriginRouteDocument{}, ErrInvalidInput
				}
			} else if tier != "origin" || endpoint.NodeID != "" || endpoint.TopologyRevision != 0 || endpoint.MTLSIdentitySHA256 != "" {
				return siteOriginRouteDocument{}, ErrInvalidInput
			}
			socket := host + ":" + strconv.Itoa(endpoint.Port)
			if address, parseErr := netip.ParseAddr(host); parseErr == nil {
				socket = netip.AddrPortFrom(address, uint16(endpoint.Port)).String()
			}
			if _, duplicate := endpointIDs[endpoint.ID]; duplicate {
				return siteOriginRouteDocument{}, ErrInvalidInput
			}
			if _, duplicate := sockets[socket]; duplicate {
				return siteOriginRouteDocument{}, ErrInvalidInput
			}
			endpointIDs[endpoint.ID], sockets[socket] = struct{}{}, struct{}{}
			endpoint.Host = host
			endpoint.Tier = tier
			endpoints[endpointIndex] = endpoint
		}
		sort.Slice(endpoints, func(i, j int) bool { return endpoints[i].ID < endpoints[j].ID })
		pools[index] = siteOriginRoutePool{ID: pool.ID, Kind: kind, BalanceMethod: pool.BalanceMethod, Endpoints: endpoints}
	}
	sort.Slice(pools, func(i, j int) bool { return pools[i].ID < pools[j].ID })
	if _, exists := poolIDs[input.DefaultPoolID]; !exists {
		return siteOriginRouteDocument{}, ErrInvalidInput
	}
	if input.DefaultFallbackPoolID != "" {
		if _, exists := poolIDs[input.DefaultFallbackPoolID]; !exists || input.DefaultFallbackPoolID == input.DefaultPoolID {
			return siteOriginRouteDocument{}, ErrInvalidInput
		}
	}

	routes := make([]siteOriginRoute, len(input.Routes))
	routeIDs := make(map[string]struct{}, len(input.Routes))
	for index, route := range input.Routes {
		path, err := normalizeSiteOriginRoutePath(route.PathPrefix)
		if err != nil || !siteOriginRouteTokenPattern.MatchString(route.ID) || route.Priority < -1000 || route.Priority > 1000 {
			return siteOriginRouteDocument{}, ErrInvalidInput
		}
		if _, duplicate := routeIDs[route.ID]; duplicate {
			return siteOriginRouteDocument{}, ErrInvalidInput
		}
		routeIDs[route.ID] = struct{}{}
		regions, err := normalizeSiteOriginRouteRegions(route.NodeRegions)
		if err != nil {
			return siteOriginRouteDocument{}, err
		}
		cidrs, err := normalizeSiteOriginRouteCIDRs(route.ClientCIDRs)
		if err != nil {
			return siteOriginRouteDocument{}, ErrInvalidInput
		}
		hosts, err := normalizeSiteOriginRouteHosts(route.Hosts)
		if err != nil || path == "" && len(regions) == 0 && len(cidrs) == 0 && len(hosts) == 0 {
			return siteOriginRouteDocument{}, ErrInvalidInput
		}
		if _, exists := poolIDs[route.PoolID]; !exists {
			return siteOriginRouteDocument{}, ErrInvalidInput
		}
		if route.FallbackPoolID != "" {
			if _, exists := poolIDs[route.FallbackPoolID]; !exists || route.FallbackPoolID == route.PoolID {
				return siteOriginRouteDocument{}, ErrInvalidInput
			}
		}
		routes[index] = siteOriginRoute{
			ID: route.ID, Priority: route.Priority, PathPrefix: path, NodeRegions: regions,
			ClientCIDRs: cidrs, Hosts: hosts, PoolID: route.PoolID, FallbackPoolID: route.FallbackPoolID,
		}
	}
	sort.Slice(routes, func(i, j int) bool { return siteOriginRouteLess(routes[i], routes[j]) })
	retry, err := normalizeSiteOriginRouteRetry(input.Retry)
	if err != nil {
		return siteOriginRouteDocument{}, err
	}
	return siteOriginRouteDocument{
		Schema: siteOriginRouteSchemaV1, IngressSourceEnabled: input.IngressSourceEnabled,
		Pools: pools, DefaultPoolID: input.DefaultPoolID,
		DefaultFallbackPoolID: input.DefaultFallbackPoolID, Routes: routes, Retry: retry,
	}, nil
}

func validSiteOriginRouteBalance(value string) bool {
	switch value {
	case "round_robin", "ip_hash", "url_hash", "least_conn", "random":
		return true
	default:
		return false
	}
}

func normalizeSiteOriginRoutePath(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	if len(value) > 2048 || value[0] != '/' || strings.ContainsAny(value, "\\?#%\x00\r\n\t") || strings.Contains(value, "//") {
		return "", ErrInvalidInput
	}
	for _, character := range value {
		if character < 0x20 || character > 0x7e {
			return "", ErrInvalidInput
		}
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "." || segment == ".." {
			return "", ErrInvalidInput
		}
	}
	// The trailing slash is meaningful (path segment prefix): kept.
	return value, nil
}

func normalizeSiteOriginRouteRegions(values []string) ([]string, error) {
	if len(values) > 32 {
		return nil, ErrInvalidInput
	}
	result := make([]string, len(values))
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		value = strings.ToLower(value)
		if !siteOriginRouteTokenPattern.MatchString(value) {
			return nil, ErrInvalidInput
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, ErrInvalidInput
		}
		seen[value], result[index] = struct{}{}, value
	}
	sort.Strings(result)
	return result, nil
}

func normalizeSiteOriginRouteCIDRs(values []string) ([]string, error) {
	if len(values) > 32 {
		return nil, ErrInvalidInput
	}
	result := make([]string, len(values))
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix != prefix.Masked() || prefix.String() != value || prefix.Addr().Is4In6() ||
			prefix.Addr().Zone() != "" || prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() {
			return nil, ErrInvalidInput
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, ErrInvalidInput
		}
		seen[value], result[index] = struct{}{}, value
	}
	sort.Strings(result)
	return result, nil
}

func normalizeSiteOriginRouteRetry(value siteOriginRouteRetry) (siteOriginRouteRetry, error) {
	if value.MaxAttempts < 1 || value.MaxAttempts > 8 || value.ConnectTimeoutMS < 10 || value.ConnectTimeoutMS > 60000 ||
		value.ReadTimeoutMS < 10 || value.ReadTimeoutMS > 60000 ||
		value.TotalBudgetMS < value.ConnectTimeoutMS+value.ReadTimeoutMS || value.TotalBudgetMS > 120000 ||
		len(value.Methods) < 1 || len(value.Methods) > 2 {
		return siteOriginRouteRetry{}, ErrInvalidInput
	}
	methods := make([]string, len(value.Methods))
	seen := make(map[string]struct{}, len(value.Methods))
	for index, method := range value.Methods {
		method = strings.ToUpper(method)
		if method != "GET" && method != "HEAD" {
			return siteOriginRouteRetry{}, ErrInvalidInput
		}
		if _, duplicate := seen[method]; duplicate {
			return siteOriginRouteRetry{}, ErrInvalidInput
		}
		seen[method], methods[index] = struct{}{}, method
	}
	sort.Strings(methods)
	value.Methods = methods
	return value, nil
}

func siteOriginRouteLess(left, right siteOriginRoute) bool {
	if left.Priority != right.Priority {
		return left.Priority > right.Priority
	}
	leftPathSpecificity, rightPathSpecificity := siteOriginRoutePathSpecificity(left.PathPrefix), siteOriginRoutePathSpecificity(right.PathPrefix)
	if leftPathSpecificity != rightPathSpecificity {
		return leftPathSpecificity > rightPathSpecificity
	}
	if (len(left.Hosts) > 0) != (len(right.Hosts) > 0) {
		return len(left.Hosts) > 0
	}
	if (len(left.NodeRegions) > 0) != (len(right.NodeRegions) > 0) {
		return len(left.NodeRegions) > 0
	}
	leftBits, rightBits := -1, -1
	for _, value := range left.ClientCIDRs {
		prefix, _ := netip.ParsePrefix(value)
		leftBits = max(leftBits, prefix.Bits())
	}
	for _, value := range right.ClientCIDRs {
		prefix, _ := netip.ParsePrefix(value)
		rightBits = max(rightBits, prefix.Bits())
	}
	if leftBits != rightBits {
		return leftBits > rightBits
	}
	return left.ID < right.ID
}

func siteOriginRoutePathSpecificity(value string) int {
	if value == "/" {
		return 0
	}
	return len(value)
}

// normalizeSiteOriginRouteHosts: lower-case FQDNs or "*.<domain>", sorted,
// unique, at most 100 (the site's own domain limit).
func normalizeSiteOriginRouteHosts(values []string) ([]string, error) {
	if len(values) > 100 {
		return nil, ErrInvalidInput
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if len(value) > 253 || !siteRuntimeV2DomainPattern.MatchString(value) {
			return nil, ErrInvalidInput
		}
		result = append(result, value)
	}
	sort.Strings(result)
	for index := 1; index < len(result); index++ {
		if result[index] == result[index-1] {
			return nil, ErrInvalidInput
		}
	}
	if len(result) == 0 {
		return nil, nil
	}
	return result, nil
}
