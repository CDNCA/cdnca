package marketsupply

import (
	"context"
	"errors"
	"slices"
	"strconv"

	"github.com/cdnca/cdnca/libs/marketproto/grant"
	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/regioncatalog"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// BlockerHTTP3Unavailable (advisory, OK reply): the supply's nodes do not
// declare SITE_QUIC, so the leaf serves the site over HTTP/2 instead of
// refusing it (fix-mktsiteconf).
const BlockerHTTP3Unavailable = "http3_unavailable"

// supplyServesHTTP3 reports whether every serving node of the grant's line
// group declares SITE_QUIC (their OpenResty has the HTTP/3 module). A pool
// without serving nodes cannot serve HTTP/3 either.
func (s *Service) supplyServesHTTP3(ctx context.Context, actor serviceActor, g grant.Grant) (bool, error) {
	poolID, err := s.pool_(ctx, actor.scopeID, g.NodePoolRef)
	if err != nil {
		return false, err
	}
	served := false
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var nodes []uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT COALESCE(array_agg(DISTINCT serving.node_id ORDER BY serving.node_id), '{}')
			FROM node_line_groups line_group
			JOIN node_line_endpoint_serving serving ON serving.tenant_scope_id=line_group.tenant_scope_id
			  AND serving.line_group_id=line_group.id AND serving.config_revision=line_group.current_revision
			  AND serving.serving
			JOIN nodes node ON node.id=serving.node_id AND node.admin_state='active'
			WHERE line_group.id=$1 AND line_group.deleted_at IS NULL`, poolID).Scan(&nodes); err != nil {
			return err
		}
		if len(nodes) == 0 {
			return nil
		}
		err := edgepublish.ValidateFeatureCapabilityTargets(ctx, tx, nodes,
			[]*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_QUIC, ApiVersion: 1}})
		var refusal *edgepublish.TargetCapabilityError
		switch {
		case err == nil:
			served = true
		case errors.As(err, &refusal):
		default:
			return err
		}
		return nil
	})
	return served, err
}

// http3Advisory decides HTTP/3 for a revision that asks for it: served when
// the supply's nodes can, otherwise an advisory and HTTP/2 only.
func (s *Service) http3Advisory(ctx context.Context, actor serviceActor, g grant.Grant, c siteconf.Config) (bool, []siteconf.Blocker, error) {
	if !c.HTTP3 || len(c.HTTPSPorts) == 0 {
		return false, nil, nil
	}
	served, err := s.supplyServesHTTP3(ctx, actor, g)
	if err != nil || served {
		return served, nil, err
	}
	return false, []siteconf.Blocker{{Code: BlockerHTTP3Unavailable}}, nil
}

// BlockerOriginRouteGeoUnmatched (advisory, OK reply): a conditional
// origin rule names node geographies none of the leaf's regions has, so it
// never applies on the leaf's nodes and is left out (detail = rule ID).
const BlockerOriginRouteGeoUnmatched = "origin_route_geo_unmatched"

// originRouteDocument maps the neutral conditional origin block onto the
// local document, checked with the local rules. A rule's node geographies
// become the leaf's region codes with that geography (geos, by code: a
// country matches all its regions, a province those in it); a rule no leaf
// region matches is left out and listed in unmatched.
func originRouteDocument(r *siteconf.OriginRoutes, geos map[string]regioncatalog.CodeGeo) (site.ConditionalOriginDocument, []string, error) {
	doc := site.ConditionalOriginDocument{Schema: site.ConditionalOriginSchemaV1, DefaultPoolID: r.DefaultPoolID,
		DefaultFallbackPoolID: r.DefaultFallbackPoolID, Routes: []site.ConditionalOriginRoute{},
		Retry: site.ConditionalOriginRetry{Methods: r.Retry.Methods, MaxAttempts: r.Retry.MaxAttempts,
			ConnectTimeoutMS: r.Retry.ConnectTimeoutMS, ReadTimeoutMS: r.Retry.ReadTimeoutMS, TotalBudgetMS: r.Retry.TotalBudgetMS}}
	for _, p := range r.Pools {
		pool := site.ConditionalOriginPool{ID: p.ID, BalanceMethod: p.BalanceMethod}
		for _, e := range p.Endpoints {
			pool.Endpoints = append(pool.Endpoints, site.ConditionalOriginEndpoint{ID: e.ID, Host: e.Host, Port: e.Port, Weight: e.Weight})
		}
		doc.Pools = append(doc.Pools, pool)
	}
	var unmatched []string
	for _, route := range r.Routes {
		regions := leafRegionsFor(route.NodeGeos, geos)
		if len(route.NodeGeos) > 0 && len(regions) == 0 {
			unmatched = append(unmatched, route.ID)
			continue
		}
		doc.Routes = append(doc.Routes, site.ConditionalOriginRoute{ID: route.ID, Priority: route.Priority,
			PathPrefix: route.PathPrefix, ClientCIDRs: route.ClientCIDRs, Hosts: route.Hosts, NodeRegions: regions,
			PoolID: route.PoolID, FallbackPoolID: route.FallbackPoolID})
	}
	doc, err := site.NormalizeConditionalOriginDocument(doc)
	return doc, unmatched, err
}

// leafRegionsFor is, sorted, every leaf region code whose geography is one
// of want.
func leafRegionsFor(want []siteconf.NodeGeo, geos map[string]regioncatalog.CodeGeo) []string {
	if len(want) == 0 {
		return nil
	}
	var out []string
	for code, geo := range geos {
		for _, g := range want {
			if geo.CountryCode == g.Country && (g.Province == "" || geo.ProvinceCode == g.Province) {
				out = append(out, code)
				break
			}
		}
	}
	slices.Sort(out) // more than a rule may name (32) is refused by the local rules
	return out
}

// originRouteAdvisory lists the rules the leaf leaves out
// (BlockerOriginRouteGeoUnmatched).
func originRouteAdvisory(c siteconf.Config, geos map[string]regioncatalog.CodeGeo) []siteconf.Blocker {
	if c.OriginRoutes == nil {
		return nil
	}
	_, unmatched, err := originRouteDocument(c.OriginRoutes, geos)
	if err != nil {
		return nil
	}
	out := make([]siteconf.Blocker, 0, len(unmatched))
	for _, id := range unmatched {
		out = append(out, siteconf.Blocker{Code: BlockerOriginRouteGeoUnmatched, Detail: id})
	}
	return out
}

// routeGeos is the leaf's region geographies when the config's origin
// routes name node geographies (nil otherwise).
func (s *Service) routeGeos(ctx context.Context, c siteconf.Config) (map[string]regioncatalog.CodeGeo, error) {
	if c.OriginRoutes == nil {
		return nil, nil
	}
	for _, r := range c.OriginRoutes.Routes {
		if len(r.NodeGeos) > 0 {
			return regioncatalog.LoadCodeGeos(ctx, s.pool)
		}
	}
	return nil, nil
}

// ConditionalOrigins is the subset of site.Service that writes a leaf
// site's conditional origin document.
type ConditionalOrigins interface {
	GetConditionalOrigin(ctx context.Context, actor site.Actor, id uuid.UUID) (site.ConditionalOriginState, error)
	UpdateConditionalOrigin(ctx context.Context, actor site.Actor, request site.UpdateConditionalOriginRequest) (site.ConditionalOriginState, error)
}

// applyOriginRoutes writes the site's conditional origin document, unless
// the config carries none or the site already has the same document. An
// absent block is not managed (the leaf keeps what the site has).
func (s *Service) applyOriginRoutes(ctx context.Context, actor serviceActor, leafSiteID uuid.UUID, req siteconf.CommitRequest) error {
	if req.Config.OriginRoutes == nil {
		return nil
	}
	routes, ok := s.sites.(ConditionalOrigins)
	if !ok {
		return errors.New("market supply: conditional origins are not configured")
	}
	geos, err := s.routeGeos(ctx, req.Config)
	if err != nil {
		return err
	}
	doc, _, err := originRouteDocument(req.Config.OriginRoutes, geos)
	if err != nil {
		return err
	}
	current, err := routes.GetConditionalOrigin(ctx, siteActor(actor), leafSiteID)
	if err != nil {
		return err
	}
	if sameJSON(current.Document, doc) {
		return nil
	}
	key := "market-routes-" + req.SiteID.String() + "-" + strconv.FormatInt(req.Revision, 10)
	_, err = routes.UpdateConditionalOrigin(ctx, siteActor(actor), site.UpdateConditionalOriginRequest{ID: leafSiteID,
		ExpectedRevision: current.Version, Document: doc, IdempotencyKey: key, RequestID: key})
	return err
}
