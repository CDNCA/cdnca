package site

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const ConditionalOriginSchemaV1 = "cdnca.edge.origin-route/v1"

var conditionalOriginTokenPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

type ConditionalOriginEndpoint struct {
	ID     string `json:"id"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Weight int    `json:"weight"`
}

type ConditionalOriginPool struct {
	ID            string                      `json:"id"`
	BalanceMethod string                      `json:"balance_method,omitempty"`
	Endpoints     []ConditionalOriginEndpoint `json:"endpoints"`
}

type ConditionalOriginRoute struct {
	ID          string   `json:"id"`
	Priority    int      `json:"priority"`
	PathPrefix  string   `json:"path_prefix,omitempty"`
	NodeRegions []string `json:"node_regions,omitempty"`
	ClientCIDRs []string `json:"client_cidrs,omitempty"`
	// Hosts match the request host (one of the site's domains; "*.x" also
	// matches a leading wildcard domain's subdomains).
	Hosts          []string `json:"hosts,omitempty"`
	PoolID         string   `json:"pool_id"`
	FallbackPoolID string   `json:"fallback_pool_id,omitempty"`
}

type ConditionalOriginRetry struct {
	Methods          []string `json:"methods"`
	MaxAttempts      int      `json:"max_attempts"`
	ConnectTimeoutMS int      `json:"connect_timeout_ms"`
	ReadTimeoutMS    int      `json:"read_timeout_ms"`
	TotalBudgetMS    int      `json:"total_budget_ms"`
}

type ConditionalOriginEffectiveRetry struct {
	BodylessOnly       bool     `json:"bodyless_only"`
	ResponseNotStarted bool     `json:"response_not_started"`
	RetryOn            []string `json:"retry_on"`
}

type ConditionalOriginEffectiveL2Fallback struct {
	DirectOriginOnly         bool `json:"direct_origin_only"`
	WithinTotalBudget        bool `json:"within_total_budget"`
	NodeIDRequired           bool `json:"node_id_required"`
	TierRequired             bool `json:"tier_required"`
	TopologyRevisionRequired bool `json:"topology_revision_required"`
	MTLSIdentityRequired     bool `json:"mtls_identity_required"`
	ProbeIntervalMS          int  `json:"probe_interval_ms"`
	FailureThreshold         int  `json:"failure_threshold"`
	RecoveryThreshold        int  `json:"recovery_threshold"`
	SingleHalfOpenProbe      bool `json:"single_half_open_probe"`
	MaxHops                  int  `json:"max_hops"`
}

type ConditionalOriginDocument struct {
	Schema                string                   `json:"schema"`
	IngressSourceEnabled  bool                     `json:"ingress_source_enabled"`
	Pools                 []ConditionalOriginPool  `json:"pools"`
	DefaultPoolID         string                   `json:"default_pool_id"`
	DefaultFallbackPoolID string                   `json:"default_fallback_pool_id,omitempty"`
	Routes                []ConditionalOriginRoute `json:"routes"`
	Retry                 ConditionalOriginRetry   `json:"retry"`
}

type ConditionalOriginState struct {
	SiteID              uuid.UUID                            `json:"site_id"`
	Version             int64                                `json:"version"`
	Document            ConditionalOriginDocument            `json:"document"`
	EffectiveRetry      ConditionalOriginEffectiveRetry      `json:"effective_retry"`
	EffectiveL2Fallback ConditionalOriginEffectiveL2Fallback `json:"effective_l2_fallback"`
	UpdatedAt           time.Time                            `json:"updated_at"`
}

type UpdateConditionalOriginRequest struct {
	ID               uuid.UUID
	ExpectedRevision int64
	Document         ConditionalOriginDocument
	IdempotencyKey   string
	RequestID        string
}

func NormalizeConditionalOriginDocument(input ConditionalOriginDocument) (ConditionalOriginDocument, error) {
	if input.Schema != ConditionalOriginSchemaV1 || len(input.Pools) < 1 || len(input.Pools) > 64 ||
		len(input.Routes) > 256 {
		return ConditionalOriginDocument{}, ErrInvalidInput
	}
	pools := make([]ConditionalOriginPool, len(input.Pools))
	poolIDs := make(map[string]struct{}, len(input.Pools))
	for index, pool := range input.Pools {
		if !conditionalOriginTokenPattern.MatchString(pool.ID) || len(pool.Endpoints) < 1 || len(pool.Endpoints) > 32 {
			return ConditionalOriginDocument{}, ErrInvalidInput
		}
		if _, exists := poolIDs[pool.ID]; exists {
			return ConditionalOriginDocument{}, ErrInvalidInput
		}
		poolIDs[pool.ID] = struct{}{}
		balanceMethod := pool.BalanceMethod
		if balanceMethod == "" {
			balanceMethod = BalanceRoundRobin
		}
		if !validConditionalOriginBalance(balanceMethod) {
			return ConditionalOriginDocument{}, ErrInvalidInput
		}
		endpoints := make([]ConditionalOriginEndpoint, len(pool.Endpoints))
		endpointIDs := make(map[string]struct{}, len(pool.Endpoints))
		endpointSockets := make(map[string]struct{}, len(pool.Endpoints))
		for endpointIndex, endpoint := range pool.Endpoints {
			host, err := normalizeConditionalOriginHost(endpoint.Host)
			if err != nil || !conditionalOriginTokenPattern.MatchString(endpoint.ID) || endpoint.Port < 1 ||
				endpoint.Port > 65535 || endpoint.Weight < 1 || endpoint.Weight > 100 {
				return ConditionalOriginDocument{}, ErrInvalidInput
			}
			socket := host + ":" + fmt.Sprint(endpoint.Port)
			if address, parseErr := netip.ParseAddr(host); parseErr == nil {
				socket = netip.AddrPortFrom(address, uint16(endpoint.Port)).String()
			}
			if _, exists := endpointIDs[endpoint.ID]; exists {
				return ConditionalOriginDocument{}, ErrInvalidInput
			}
			if _, exists := endpointSockets[socket]; exists {
				return ConditionalOriginDocument{}, ErrInvalidInput
			}
			endpointIDs[endpoint.ID], endpointSockets[socket] = struct{}{}, struct{}{}
			endpoints[endpointIndex] = ConditionalOriginEndpoint{
				ID: endpoint.ID, Host: host, Port: endpoint.Port, Weight: endpoint.Weight,
			}
		}
		sort.Slice(endpoints, func(i, j int) bool { return endpoints[i].ID < endpoints[j].ID })
		pools[index] = ConditionalOriginPool{ID: pool.ID, BalanceMethod: balanceMethod, Endpoints: endpoints}
	}
	sort.Slice(pools, func(i, j int) bool { return pools[i].ID < pools[j].ID })
	if _, exists := poolIDs[input.DefaultPoolID]; !exists {
		return ConditionalOriginDocument{}, ErrInvalidInput
	}
	if input.DefaultFallbackPoolID != "" {
		if _, exists := poolIDs[input.DefaultFallbackPoolID]; !exists || input.DefaultFallbackPoolID == input.DefaultPoolID {
			return ConditionalOriginDocument{}, ErrInvalidInput
		}
	}

	routes := make([]ConditionalOriginRoute, len(input.Routes))
	routeIDs := make(map[string]struct{}, len(input.Routes))
	for index, route := range input.Routes {
		if !conditionalOriginTokenPattern.MatchString(route.ID) || route.Priority < -1000 || route.Priority > 1000 {
			return ConditionalOriginDocument{}, ErrInvalidInput
		}
		if _, exists := routeIDs[route.ID]; exists {
			return ConditionalOriginDocument{}, ErrInvalidInput
		}
		routeIDs[route.ID] = struct{}{}
		path, err := normalizeConditionalOriginPath(route.PathPrefix)
		if err != nil {
			return ConditionalOriginDocument{}, ErrInvalidInput
		}
		regions, err := normalizeConditionalOriginRegions(route.NodeRegions)
		if err != nil {
			return ConditionalOriginDocument{}, ErrInvalidInput
		}
		cidrs, err := normalizeConditionalOriginCIDRs(route.ClientCIDRs)
		if err != nil {
			return ConditionalOriginDocument{}, ErrInvalidInput
		}
		hosts, err := normalizeConditionalOriginHosts(route.Hosts)
		if err != nil || path == "" && len(regions) == 0 && len(cidrs) == 0 && len(hosts) == 0 {
			return ConditionalOriginDocument{}, ErrInvalidInput
		}
		if _, exists := poolIDs[route.PoolID]; !exists {
			return ConditionalOriginDocument{}, ErrInvalidInput
		}
		if route.FallbackPoolID != "" {
			if _, exists := poolIDs[route.FallbackPoolID]; !exists || route.FallbackPoolID == route.PoolID {
				return ConditionalOriginDocument{}, ErrInvalidInput
			}
		}
		routes[index] = ConditionalOriginRoute{
			ID: route.ID, Priority: route.Priority, PathPrefix: path, NodeRegions: regions,
			ClientCIDRs: cidrs, Hosts: hosts, PoolID: route.PoolID, FallbackPoolID: route.FallbackPoolID,
		}
	}
	sort.Slice(routes, func(i, j int) bool { return conditionalOriginRouteLess(routes[i], routes[j]) })
	retry, err := normalizeConditionalOriginRetry(input.Retry)
	if err != nil {
		return ConditionalOriginDocument{}, ErrInvalidInput
	}
	return ConditionalOriginDocument{
		Schema: ConditionalOriginSchemaV1, IngressSourceEnabled: input.IngressSourceEnabled,
		Pools: pools, DefaultPoolID: input.DefaultPoolID,
		DefaultFallbackPoolID: input.DefaultFallbackPoolID, Routes: routes, Retry: retry,
	}, nil
}

func (s *Service) GetConditionalOrigin(ctx context.Context, actor Actor, id uuid.UUID) (ConditionalOriginState, error) {
	if !validActor(actor) || id == uuid.Nil {
		return ConditionalOriginState{}, ErrInvalidInput
	}
	state, err := s.store.GetConditionalOrigin(ctx, actor, id)
	if err != nil {
		return ConditionalOriginState{}, err
	}
	return withConditionalOriginEffectiveRetry(state), nil
}

func (s *Service) UpdateConditionalOrigin(
	ctx context.Context,
	actor Actor,
	request UpdateConditionalOriginRequest,
) (ConditionalOriginState, error) {
	if !validActor(actor) || request.ID == uuid.Nil || request.ExpectedRevision < 1 ||
		!validWriteMetadata(request.IdempotencyKey, request.RequestID) {
		return ConditionalOriginState{}, ErrInvalidInput
	}
	document, err := NormalizeConditionalOriginDocument(request.Document)
	if err != nil {
		return ConditionalOriginState{}, err
	}
	request.Document = document
	digest, err := digestRequest(struct {
		ID               uuid.UUID                 `json:"id"`
		ExpectedRevision int64                     `json:"expected_version"`
		Document         ConditionalOriginDocument `json:"document"`
	}{request.ID, request.ExpectedRevision, request.Document})
	if err != nil {
		return ConditionalOriginState{}, err
	}
	state, err := s.store.UpdateConditionalOrigin(ctx, actor, request, digest)
	if err != nil {
		return ConditionalOriginState{}, err
	}
	return withConditionalOriginEffectiveRetry(state), nil
}

func withConditionalOriginEffectiveRetry(state ConditionalOriginState) ConditionalOriginState {
	state.EffectiveRetry = ConditionalOriginEffectiveRetry{
		BodylessOnly: true, ResponseNotStarted: true,
		RetryOn: []string{"connect_error", "connect_timeout", "read_timeout", "http_502", "http_503", "http_504"},
	}
	state.EffectiveL2Fallback = ConditionalOriginEffectiveL2Fallback{
		DirectOriginOnly: true, WithinTotalBudget: true, NodeIDRequired: true, TierRequired: true,
		TopologyRevisionRequired: true, MTLSIdentityRequired: true, ProbeIntervalMS: 10000,
		FailureThreshold: 3, RecoveryThreshold: 3, SingleHalfOpenProbe: true, MaxHops: 1,
	}
	return state
}

func (s *Store) GetConditionalOrigin(ctx context.Context, actor Actor, id uuid.UUID) (ConditionalOriginState, error) {
	query := `SELECT revision, updated_at FROM sites WHERE id=$1 AND deleted_at IS NULL`
	args := []any{id}
	if actor.ScopeKind == "tenant" {
		query += ` AND scope_id=$2`
		args = append(args, actor.ScopeID)
	}
	state := ConditionalOriginState{SiteID: id}
	if err := s.pool.QueryRow(ctx, query, args...).Scan(&state.Version, &state.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ConditionalOriginState{}, ErrNotFound
		}
		return ConditionalOriginState{}, fmt.Errorf("get conditional origin site: %w", err)
	}
	document, updatedAt, err := s.readConditionalOriginDocument(ctx, id)
	if err != nil {
		return ConditionalOriginState{}, err
	}
	state.Document = document
	if !updatedAt.IsZero() {
		state.UpdatedAt = updatedAt
	}
	return state, nil
}

func (s *Store) UpdateConditionalOrigin(
	ctx context.Context,
	actor Actor,
	request UpdateConditionalOriginRequest,
	digest [32]byte,
) (ConditionalOriginState, error) {
	var result ConditionalOriginState
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		targetScopeID, err := mutationTargetScope(ctx, tx, actor, request.ID)
		if err != nil {
			return err
		}
		if err := authorizeAutomaticMutation(ctx, tx, actor, targetScopeID); err != nil {
			return err
		}
		scopeID, deleted, _, locked, currentRevision, err := s.lockSite(ctx, tx, actor, request.ID)
		if err != nil {
			return err
		}
		if scopeID != targetScopeID {
			return ErrNotFound
		}
		stored, err := s.claimConditionalOriginWrite(ctx, tx, actor, targetScopeID, request, digest)
		if err != nil {
			return err
		}
		if stored != nil {
			if err := json.Unmarshal(stored, &result); err != nil {
				return fmt.Errorf("decode stored conditional origin response: %w", err)
			}
			return nil
		}
		if locked && actor.ScopeKind == "tenant" {
			return ErrLocked
		}
		if deleted {
			return ErrNotFound
		}
		if currentRevision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		now := s.now().UTC()
		if err := replaceConditionalOriginDocument(ctx, tx, request.ID, actor.UserID, request.Document, now); err != nil {
			return err
		}
		command, err := tx.Exec(ctx, `UPDATE sites
			SET revision=revision+1, updated_by_user_id=$2, updated_at=$3
			WHERE id=$1 AND revision=$4 AND deleted_at IS NULL`, request.ID, actor.UserID, now, request.ExpectedRevision)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrRevisionConflict
		}
		result = ConditionalOriginState{
			SiteID: request.ID, Version: request.ExpectedRevision + 1, Document: request.Document, UpdatedAt: now,
		}
		if err := enqueueAutomaticMutation(ctx, tx, actor, scopeID, request.ID,
			"site.origin.update", request.RequestID); err != nil {
			return err
		}
		if err := s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: scopeID, ActorUserID: &actor.UserID, Action: "site.origin_route.update",
			ResourceType: "site", ResourceID: request.ID.String(), RequestID: request.RequestID,
			Result: "success", Payload: automaticAuditPayload(actor, scopeID, "site.origin_route.update", map[string]any{
				"from_version": request.ExpectedRevision, "to_version": result.Version,
				"pool_count": len(request.Document.Pools), "route_count": len(request.Document.Routes),
				"ingress_source_enabled": request.Document.IngressSourceEnabled,
			}),
		}); err != nil {
			return err
		}
		return s.completeConditionalOriginWrite(ctx, tx, actor, request, result, now)
	})
	if err != nil {
		return ConditionalOriginState{}, fmt.Errorf("update site conditional origin: %w", err)
	}
	return result, nil
}

func (s *Store) claimConditionalOriginWrite(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	targetScopeID uuid.UUID,
	request UpdateConditionalOriginRequest,
	digest [32]byte,
) ([]byte, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	command, err := tx.Exec(ctx, `INSERT INTO site_origin_route_write_requests (
		id, actor_scope_id, actor_user_id, target_scope_id, site_id, idempotency_key,
		request_digest, expected_revision, created_at
	) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
	ON CONFLICT (actor_scope_id, actor_user_id, idempotency_key) DO NOTHING`,
		id, actor.ScopeID, actor.UserID, targetScopeID, request.ID, request.IdempotencyKey,
		digest[:], request.ExpectedRevision, s.now().UTC())
	if err != nil {
		return nil, err
	}
	if command.RowsAffected() == 1 {
		return nil, nil
	}
	var existingDigest, responseBody []byte
	var completedAt *time.Time
	if err := tx.QueryRow(ctx, `SELECT request_digest,response_body,completed_at
		FROM site_origin_route_write_requests
		WHERE actor_scope_id=$1 AND actor_user_id=$2 AND idempotency_key=$3`,
		actor.ScopeID, actor.UserID, request.IdempotencyKey).Scan(&existingDigest, &responseBody, &completedAt); err != nil {
		return nil, err
	}
	if !bytes.Equal(existingDigest, digest[:]) || completedAt == nil || len(responseBody) == 0 {
		return nil, ErrIdempotencyConflict
	}
	return responseBody, nil
}

func (s *Store) completeConditionalOriginWrite(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	request UpdateConditionalOriginRequest,
	result ConditionalOriginState,
	now time.Time,
) error {
	encoded, err := json.Marshal(result)
	if err != nil {
		return err
	}
	command, err := tx.Exec(ctx, `UPDATE site_origin_route_write_requests request
		SET response_body=$4, completed_at=$5, audit_event_id=(
			SELECT event.id FROM audit_events event
			WHERE event.scope_id=request.target_scope_id
			  AND event.actor_user_id=request.actor_user_id
			  AND event.action='site.origin_route.update'
			  AND event.resource_type='site' AND event.resource_id=request.site_id::text
			  AND event.request_id=$6
			ORDER BY event.stream_position DESC LIMIT 1
		)
		WHERE actor_scope_id=$1 AND actor_user_id=$2 AND idempotency_key=$3
		  AND completed_at IS NULL`, actor.ScopeID, actor.UserID, request.IdempotencyKey,
		string(encoded), now, request.RequestID)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrIdempotencyConflict
	}
	return nil
}

func replaceConditionalOriginDocument(
	ctx context.Context,
	tx pgx.Tx,
	siteID, actorUserID uuid.UUID,
	document ConditionalOriginDocument,
	now time.Time,
) error {
	_, err := tx.Exec(ctx, `INSERT INTO site_origin_route_configs (
		site_id,schema,default_pool_id,default_fallback_pool_id,retry_methods,max_attempts,
		connect_timeout_ms,read_timeout_ms,total_budget_ms,ingress_source_enabled,updated_by_user_id,updated_at
	) VALUES ($1,$2,$3,NULLIF($4,''),$5,$6,$7,$8,$9,$10,$11,$12)
	ON CONFLICT (site_id) DO UPDATE SET
		schema=EXCLUDED.schema,default_pool_id=EXCLUDED.default_pool_id,
		default_fallback_pool_id=EXCLUDED.default_fallback_pool_id,retry_methods=EXCLUDED.retry_methods,
		max_attempts=EXCLUDED.max_attempts,connect_timeout_ms=EXCLUDED.connect_timeout_ms,
		read_timeout_ms=EXCLUDED.read_timeout_ms,total_budget_ms=EXCLUDED.total_budget_ms,
		ingress_source_enabled=EXCLUDED.ingress_source_enabled,
		updated_by_user_id=EXCLUDED.updated_by_user_id,updated_at=EXCLUDED.updated_at`,
		siteID, document.Schema, document.DefaultPoolID, document.DefaultFallbackPoolID,
		document.Retry.Methods, document.Retry.MaxAttempts, document.Retry.ConnectTimeoutMS,
		document.Retry.ReadTimeoutMS, document.Retry.TotalBudgetMS, document.IngressSourceEnabled, actorUserID, now)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM site_origin_routes WHERE site_id=$1`, siteID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM site_origin_route_endpoints WHERE site_id=$1`, siteID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM site_origin_route_pools WHERE site_id=$1`, siteID); err != nil {
		return err
	}
	for poolPosition, pool := range document.Pools {
		if _, err := tx.Exec(ctx, `INSERT INTO site_origin_route_pools
			(site_id,pool_id,position,balance_method) VALUES ($1,$2,$3,$4)`,
			siteID, pool.ID, poolPosition, pool.BalanceMethod); err != nil {
			return err
		}
		for endpointPosition, endpoint := range pool.Endpoints {
			if _, err := tx.Exec(ctx, `INSERT INTO site_origin_route_endpoints
				(site_id,pool_id,endpoint_id,position,host,port,weight)
				VALUES ($1,$2,$3,$4,$5,$6,$7)`, siteID, pool.ID, endpoint.ID,
				endpointPosition, endpoint.Host, endpoint.Port, endpoint.Weight); err != nil {
				return err
			}
		}
	}
	for position, route := range document.Routes {
		hosts := route.Hosts
		if hosts == nil {
			hosts = []string{}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO site_origin_routes (
			site_id,route_id,position,priority,path_prefix,node_regions,client_cidrs,pool_id,fallback_pool_id,hosts
		) VALUES ($1,$2,$3,$4,NULLIF($5,''),$6,$7,$8,NULLIF($9,''),$10)`,
			siteID, route.ID, position, route.Priority, route.PathPrefix, route.NodeRegions,
			route.ClientCIDRs, route.PoolID, route.FallbackPoolID, hosts); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) readConditionalOriginDocument(
	ctx context.Context,
	siteID uuid.UUID,
) (ConditionalOriginDocument, time.Time, error) {
	var document ConditionalOriginDocument
	var updatedAt time.Time
	err := s.pool.QueryRow(ctx, `SELECT schema,default_pool_id,COALESCE(default_fallback_pool_id,''),
		retry_methods,max_attempts,connect_timeout_ms,read_timeout_ms,total_budget_ms,ingress_source_enabled,updated_at
		FROM site_origin_route_configs WHERE site_id=$1`, siteID).Scan(
		&document.Schema, &document.DefaultPoolID, &document.DefaultFallbackPoolID,
		&document.Retry.Methods, &document.Retry.MaxAttempts, &document.Retry.ConnectTimeoutMS,
		&document.Retry.ReadTimeoutMS, &document.Retry.TotalBudgetMS, &document.IngressSourceEnabled, &updatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		value, fallbackUpdatedAt, fallbackErr := s.readDefaultConditionalOriginDocument(ctx, siteID)
		return value, fallbackUpdatedAt, fallbackErr
	}
	if err != nil {
		return ConditionalOriginDocument{}, time.Time{}, fmt.Errorf("read conditional origin config: %w", err)
	}
	pools, err := s.readConditionalOriginPools(ctx, siteID)
	if err != nil {
		return ConditionalOriginDocument{}, time.Time{}, err
	}
	document.Pools = pools
	routes, err := s.readConditionalOriginRoutes(ctx, siteID)
	if err != nil {
		return ConditionalOriginDocument{}, time.Time{}, err
	}
	document.Routes = routes
	normalized, err := NormalizeConditionalOriginDocument(document)
	if err != nil {
		return ConditionalOriginDocument{}, time.Time{}, fmt.Errorf("stored conditional origin document: %w", err)
	}
	return normalized, updatedAt, nil
}

func (s *Store) readConditionalOriginPools(ctx context.Context, siteID uuid.UUID) ([]ConditionalOriginPool, error) {
	// host is canonical text (IP or DNS name, migration 485), read as stored.
	rows, err := s.pool.Query(ctx, `SELECT pool.pool_id,pool.balance_method,
		endpoint.endpoint_id,endpoint.host,endpoint.port,endpoint.weight
		FROM site_origin_route_pools pool
		JOIN site_origin_route_endpoints endpoint
		  ON endpoint.site_id=pool.site_id AND endpoint.pool_id=pool.pool_id
		WHERE pool.site_id=$1
		ORDER BY pool.position,pool.pool_id,endpoint.position,endpoint.endpoint_id`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	pools := make([]ConditionalOriginPool, 0)
	for rows.Next() {
		var poolID, balanceMethod string
		var endpoint ConditionalOriginEndpoint
		if err := rows.Scan(&poolID, &balanceMethod, &endpoint.ID, &endpoint.Host,
			&endpoint.Port, &endpoint.Weight); err != nil {
			return nil, err
		}
		if len(pools) == 0 || pools[len(pools)-1].ID != poolID {
			pools = append(pools, ConditionalOriginPool{ID: poolID, BalanceMethod: balanceMethod})
		}
		pools[len(pools)-1].Endpoints = append(pools[len(pools)-1].Endpoints, endpoint)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return pools, nil
}

func (s *Store) readConditionalOriginRoutes(ctx context.Context, siteID uuid.UUID) ([]ConditionalOriginRoute, error) {
	rows, err := s.pool.Query(ctx, `SELECT route_id,priority,COALESCE(path_prefix,''),node_regions,
		client_cidrs::text[],pool_id,COALESCE(fallback_pool_id,''),hosts
		FROM site_origin_routes WHERE site_id=$1 ORDER BY position,route_id`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	routes := make([]ConditionalOriginRoute, 0)
	for rows.Next() {
		var route ConditionalOriginRoute
		if err := rows.Scan(&route.ID, &route.Priority, &route.PathPrefix, &route.NodeRegions,
			&route.ClientCIDRs, &route.PoolID, &route.FallbackPoolID, &route.Hosts); err != nil {
			return nil, err
		}
		routes = append(routes, route)
	}
	return routes, rows.Err()
}

func (s *Store) readDefaultConditionalOriginDocument(
	ctx context.Context,
	siteID uuid.UUID,
) (ConditionalOriginDocument, time.Time, error) {
	return readDefaultConditionalOriginDocument(ctx, s.pool, siteID)
}

// readDefaultConditionalOriginDocument: the document of a site without one,
// its basic origin pool as pool "default" (q: the pool, or a site create's tx).
func readDefaultConditionalOriginDocument(
	ctx context.Context,
	q interface {
		QueryRow(context.Context, string, ...any) pgx.Row
		Query(context.Context, string, ...any) (pgx.Rows, error)
	},
	siteID uuid.UUID,
) (ConditionalOriginDocument, time.Time, error) {
	var pool ConditionalOriginPool
	var failoverTries, connectTimeoutMS, readTimeoutMS int
	var updatedAt time.Time
	pool.ID = "default"
	if err := q.QueryRow(ctx, `SELECT balance_method,failover_tries,connect_timeout_ms,read_timeout_ms,updated_at
		FROM site_origin_pools WHERE site_id=$1`, siteID).Scan(&pool.BalanceMethod, &failoverTries,
		&connectTimeoutMS, &readTimeoutMS, &updatedAt); err != nil {
		return ConditionalOriginDocument{}, time.Time{}, fmt.Errorf("read default conditional origin pool: %w", err)
	}
	rows, err := q.Query(ctx, `SELECT position,host,port,weight FROM site_origins
		WHERE site_id=$1 AND enabled ORDER BY position`, siteID)
	if err != nil {
		return ConditionalOriginDocument{}, time.Time{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var position int
		var endpoint ConditionalOriginEndpoint
		if err := rows.Scan(&position, &endpoint.Host, &endpoint.Port, &endpoint.Weight); err != nil {
			return ConditionalOriginDocument{}, time.Time{}, err
		}
		endpoint.ID = fmt.Sprintf("origin-%02d", position)
		pool.Endpoints = append(pool.Endpoints, endpoint)
	}
	if err := rows.Err(); err != nil {
		return ConditionalOriginDocument{}, time.Time{}, err
	}
	maxAttempts := failoverTries
	if maxAttempts > 8 {
		maxAttempts = 8
	}
	if connectTimeoutMS > 60000 {
		connectTimeoutMS = 60000
	}
	if readTimeoutMS > 60000 {
		readTimeoutMS = 60000
	}
	document := ConditionalOriginDocument{
		Schema: ConditionalOriginSchemaV1, Pools: []ConditionalOriginPool{pool}, DefaultPoolID: pool.ID,
		Routes: []ConditionalOriginRoute{}, Retry: ConditionalOriginRetry{
			Methods: []string{"GET", "HEAD"}, MaxAttempts: maxAttempts,
			ConnectTimeoutMS: connectTimeoutMS, ReadTimeoutMS: readTimeoutMS,
			TotalBudgetMS: min(connectTimeoutMS+readTimeoutMS, 120000),
		},
	}
	normalized, err := NormalizeConditionalOriginDocument(document)
	if err != nil {
		return ConditionalOriginDocument{}, time.Time{}, fmt.Errorf("default conditional origin document: %w", err)
	}
	return normalized, updatedAt, nil
}

func validConditionalOriginBalance(value string) bool {
	return value == BalanceRoundRobin || value == BalanceIPHash || value == BalanceURLHash ||
		value == BalanceLeastConn || value == BalanceRandom
}

func normalizeConditionalOriginHost(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	address, err := netip.ParseAddr(strings.ToLower(trimmed))
	if err != nil || address.IsUnspecified() || address.IsMulticast() || address.IsLinkLocalUnicast() ||
		address.Is4In6() || address.Zone() != "" || address == netip.MustParseAddr("255.255.255.255") {
		if err == nil {
			return "", ErrInvalidInput
		}
		return normalizeConditionalOriginDNSHostname(value)
	}
	return address.String(), nil
}

func normalizeConditionalOriginDNSHostname(value string) (string, error) {
	if value == "" || strings.TrimSpace(value) != value {
		return "", ErrInvalidInput
	}
	value = strings.ToLower(strings.TrimSuffix(value, "."))
	if len(value) < 1 || len(value) > 253 || value == "localhost" ||
		strings.HasSuffix(value, ".in-addr.arpa") || strings.HasSuffix(value, ".ip6.arpa") {
		return "", ErrInvalidInput
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return "", ErrInvalidInput
	}
	for _, label := range labels {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrInvalidInput
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return "", ErrInvalidInput
			}
		}
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return "", ErrInvalidInput
	}
	last := labels[len(labels)-1]
	for _, character := range last {
		if character >= 'a' && character <= 'z' {
			return value, nil
		}
	}
	return "", ErrInvalidInput
}

func normalizeConditionalOriginPath(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	if len(value) > 2048 || value[0] != '/' || strings.ContainsAny(value, "\\?#%\x00\r\n\t") ||
		strings.Contains(value, "//") {
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
	// The trailing slash is meaningful (path segment prefix): "/api/"
	// matches "/api/..." only, "/api" also "/api" itself.
	return value, nil
}

func normalizeConditionalOriginRegions(values []string) ([]string, error) {
	if len(values) > 32 {
		return nil, ErrInvalidInput
	}
	result := make([]string, len(values))
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		value = strings.ToLower(value)
		if !conditionalOriginTokenPattern.MatchString(value) {
			return nil, ErrInvalidInput
		}
		if _, exists := seen[value]; exists {
			return nil, ErrInvalidInput
		}
		seen[value], result[index] = struct{}{}, value
	}
	sort.Strings(result)
	return result, nil
}

func normalizeConditionalOriginCIDRs(values []string) ([]string, error) {
	if len(values) > 32 {
		return nil, ErrInvalidInput
	}
	result := make([]string, len(values))
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" ||
			prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() {
			return nil, ErrInvalidInput
		}
		prefix = prefix.Masked()
		canonical := prefix.String()
		if canonical != value {
			return nil, ErrInvalidInput
		}
		if _, exists := seen[canonical]; exists {
			return nil, ErrInvalidInput
		}
		seen[canonical], result[index] = struct{}{}, canonical
	}
	sort.Strings(result)
	return result, nil
}

func normalizeConditionalOriginRetry(value ConditionalOriginRetry) (ConditionalOriginRetry, error) {
	if value.MaxAttempts < 1 || value.MaxAttempts > 8 || value.ConnectTimeoutMS < 10 ||
		value.ConnectTimeoutMS > 60000 || value.ReadTimeoutMS < 10 || value.ReadTimeoutMS > 60000 ||
		value.TotalBudgetMS < value.ConnectTimeoutMS+value.ReadTimeoutMS || value.TotalBudgetMS > 120000 ||
		len(value.Methods) < 1 || len(value.Methods) > 2 {
		return ConditionalOriginRetry{}, ErrInvalidInput
	}
	methods := make([]string, len(value.Methods))
	seen := make(map[string]struct{}, len(value.Methods))
	for index, method := range value.Methods {
		method = strings.ToUpper(method)
		if method != "GET" && method != "HEAD" {
			return ConditionalOriginRetry{}, ErrInvalidInput
		}
		if _, exists := seen[method]; exists {
			return ConditionalOriginRetry{}, ErrInvalidInput
		}
		seen[method], methods[index] = struct{}{}, method
	}
	sort.Strings(methods)
	value.Methods = methods
	return value, nil
}

func conditionalOriginRouteLess(left, right ConditionalOriginRoute) bool {
	if left.Priority != right.Priority {
		return left.Priority > right.Priority
	}
	leftPathSpecificity, rightPathSpecificity := conditionalOriginPathSpecificity(left.PathPrefix), conditionalOriginPathSpecificity(right.PathPrefix)
	if leftPathSpecificity != rightPathSpecificity {
		return leftPathSpecificity > rightPathSpecificity
	}
	if (len(left.Hosts) > 0) != (len(right.Hosts) > 0) {
		return len(left.Hosts) > 0
	}
	if (len(left.NodeRegions) > 0) != (len(right.NodeRegions) > 0) {
		return len(left.NodeRegions) > 0
	}
	leftBits, rightBits := conditionalOriginMaxPrefixBits(left.ClientCIDRs), conditionalOriginMaxPrefixBits(right.ClientCIDRs)
	if leftBits != rightBits {
		return leftBits > rightBits
	}
	return left.ID < right.ID
}

func conditionalOriginPathSpecificity(value string) int {
	if value == "/" {
		return 0
	}
	return len(value)
}

func conditionalOriginMaxPrefixBits(values []string) int {
	maximum := -1
	for _, value := range values {
		prefix, _ := netip.ParsePrefix(value)
		if prefix.Bits() > maximum {
			maximum = prefix.Bits()
		}
	}
	return maximum
}

// normalizeConditionalOriginHosts lower-cases, deduplicates and sorts route
// hosts: exact names or one leading wildcard label.
func normalizeConditionalOriginHosts(values []string) ([]string, error) {
	if len(values) > 100 {
		return nil, ErrInvalidInput
	}
	result := make([]string, 0, len(values))
	for _, raw := range values {
		host, err := normalizeDomain(strings.ToLower(raw), true)
		if err != nil {
			return nil, ErrInvalidInput
		}
		if !slices.Contains(result, host) {
			result = append(result, host)
		}
	}
	slices.Sort(result)
	if len(result) == 0 {
		return nil, nil
	}
	return result, nil
}
