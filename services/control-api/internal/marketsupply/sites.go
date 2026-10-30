package marketsupply

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strconv"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/marketproto/envelope"
	"github.com/cdnca/cdnca/libs/marketproto/grant"
	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	mspec "github.com/cdnca/cdnca/libs/marketproto/spec"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/regioncatalog"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
	"github.com/google/uuid"
)

// SiteWriter is the subset of site.Service the leaf drives.
type SiteWriter interface {
	Create(ctx context.Context, actor site.Actor, request site.CreateRequest) (site.WriteResult, error)
	Update(ctx context.Context, actor site.Actor, request site.UpdateRequest) (site.WriteResult, error)
	UpdateOrigin(ctx context.Context, actor site.Actor, request site.UpdateOriginRequest) (site.WriteResult, error)
	Delete(ctx context.Context, actor site.Actor, request site.DeleteRequest) (site.DeleteResult, error)
	Get(ctx context.Context, actor site.Actor, id uuid.UUID) (site.Site, error)
}

// ICPChecker reports whether a hostname is filed, using the seller's own
// provider and key (docs/marketplace/06-compliance.md §1).
type ICPChecker func(ctx context.Context, hostname string) (bool, error)

var (
	ErrUnknownGrant  = errors.New("market supply: grant not synced")
	ErrGrantInactive = errors.New("market supply: grant not active")
	ErrHeaderDomains = errors.New("market supply: envelope domains differ from the site config")
	ErrDigest        = errors.New("market supply: commit does not match the prepared digest")
	ErrForeignSite   = errors.New("market supply: site does not belong to this grant")
	ErrUnsupportedOp = errors.New("market supply: operation not supported")
)

func (s *Service) WithSites(writer SiteWriter, icp ICPChecker) *Service {
	s.sites, s.icp = writer, icp
	return s
}

func (s *Service) remember(grants []grant.Grant) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.grants == nil {
		s.grants = map[uuid.UUID]grant.Grant{}
	}
	for _, g := range grants {
		s.grants[g.GrantID] = g
	}
}

func (s *Service) lookup(id uuid.UUID) (grant.Grant, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.grants[id]
	return g, ok
}

// Handle executes one decrypted relay request and returns the reply payload.
// Business refusals come back as a Reply with OK=false; only transport-level
// problems are returned as errors.
func (s *Service) Handle(ctx context.Context, header envelope.Header, payload []byte) (siteconf.Reply, error) {
	reply := siteconf.Reply{Operation: header.Operation}
	fail := func(err error) (siteconf.Reply, error) {
		reply.Error = err.Error()
		return reply, nil
	}
	g, ok := s.lookup(header.GrantID)
	if !ok {
		return fail(ErrUnknownGrant)
	}
	switch g.StatusAt(s.now()) {
	case grant.StatusActive, grant.StatusGrace:
	default:
		return fail(ErrGrantInactive)
	}
	// The relay only delivers subscriber requests from the grant's root
	// buyer, so the sender is where this key's attack digests go.
	s.RememberSubscriber(Key(g), header.SenderMemberID)
	actor, err := s.ensureActor(ctx)
	if err != nil {
		return siteconf.Reply{}, err
	}
	tenant, err := s.ensureTenant(ctx, actor, Key(g))
	if err != nil {
		return siteconf.Reply{}, err
	}
	switch header.Operation {
	case siteconf.OpPrepare, siteconf.OpCommit:
		var req siteconf.CommitRequest
		if err := json.Unmarshal(payload, &req); err != nil {
			return fail(siteconf.ErrInvalid)
		}
		reply.SiteID, reply.Revision = req.SiteID, req.Revision
		if err := req.Config.Normalize(); err != nil {
			return fail(err)
		}
		if !slices.Equal(normalizedHeaderDomains(header.Domains), req.Config.Domains) {
			return fail(ErrHeaderDomains)
		}
		reply.Digest = req.Config.Digest()
		if reply.Blockers = s.blockers(ctx, g, tenant, req.LeafSiteID, req.SiteID, req.Config); len(reply.Blockers) > 0 {
			return reply, nil
		}
		// auto_defense (ML-22): only a malformed block refuses; what the
		// supply does not include or caps is applied tightened and reported
		// back (advisory blockers on an OK reply, U7/U14).
		plugins, _, err := tenantPlugins(ctx, s.pool, tenant.scopeID)
		if err != nil {
			return siteconf.Reply{}, err
		}
		autoDefense, hard, advisory := s.autoDefenseBlockers(req.Config, plugins)
		if len(hard) > 0 {
			reply.Blockers = hard
			return reply, nil
		}
		http3, http3Advisory, err := s.http3Advisory(ctx, actor, g, req.Config)
		if err != nil {
			return siteconf.Reply{}, err
		}
		geos, err := s.routeGeos(ctx, req.Config)
		if err != nil {
			return siteconf.Reply{}, err
		}
		reply.Blockers = append(append(advisory, http3Advisory...), originRouteAdvisory(req.Config, geos)...)
		if header.Operation == siteconf.OpPrepare {
			reply.OK = true
			return reply, nil
		}
		if req.Digest != reply.Digest {
			return fail(ErrDigest)
		}
		// A live origin auth rule pins its origin: the rules this revision
		// drops go before the site's origins change.
		if req.LeafSiteID != nil {
			if err := s.applyOriginAuth(ctx, tenant, *req.LeafSiteID, req, true); err != nil {
				return fail(err)
			}
		}
		leafID, err := s.commit(ctx, actor, g, tenant, req, http3)
		if err != nil {
			return fail(err)
		}
		if err := s.applyOriginRoutes(ctx, actor, leafID, req); err != nil {
			reply.LeafSiteID = &leafID
			return fail(err)
		}
		// The site is committed first so the cache policy has a site to bind
		// to; a failure here fails the commit and the subscriber retries it.
		if err := s.applyCache(ctx, tenant, leafID, req); err != nil {
			reply.LeafSiteID = &leafID
			return fail(err)
		}
		if err := s.applySiteAccess(ctx, actor, leafID, req); err != nil {
			reply.LeafSiteID = &leafID
			return fail(err)
		}
		if err := s.applyHTTPPolicy(ctx, tenant, leafID, req); err != nil {
			reply.LeafSiteID = &leafID
			return fail(err)
		}
		if err := s.applyOriginAuth(ctx, tenant, leafID, req, false); err != nil {
			reply.LeafSiteID = &leafID
			return fail(err)
		}
		// Activation follows once the nodes carry the site (ReconcileSecurity).
		if err := s.applySecurity(ctx, tenant, leafID, req); err != nil {
			reply.LeafSiteID = &leafID
			return fail(err)
		}
		if err := s.applyAutoDefense(ctx, tenant, leafID, autoDefense); err != nil {
			reply.LeafSiteID = &leafID
			return fail(err)
		}
		// The credentials go to the nodes now (fix-mktsiteconf6); what does
		// not reach them yet is advisory, the reconciler retries it.
		reply.Blockers = append(reply.Blockers, s.deliverOriginAuth(ctx, tenant, req.Config)...)
		reply.OK, reply.LeafSiteID = true, &leafID
		return reply, nil
	case siteconf.OpAbort:
		// Prepare stages nothing, so there is nothing to discard.
		reply.OK = true
		return reply, nil
	case siteconf.OpDelete, siteconf.OpStatus:
		var ref siteconf.SiteRef
		if err := json.Unmarshal(payload, &ref); err != nil {
			return fail(siteconf.ErrInvalid)
		}
		reply.SiteID, reply.LeafSiteID = ref.SiteID, &ref.LeafSiteID
		current, err := s.ownedSite(ctx, actor, tenant, ref.LeafSiteID)
		if err != nil {
			return fail(err)
		}
		if header.Operation == siteconf.OpStatus {
			security, err := s.securityStatus(ctx, tenant, current.ID)
			if err != nil {
				return fail(err)
			}
			status := map[string]any{
				"enabled": current.Enabled, "status": current.Status, "revision": current.Revision,
				"operational": current.OperationalStatus, "security": security,
			}
			var auth *edgepublish.OriginAuthDeliveryStatus
			if s.originAuthDelivery != nil {
				delivery, err := s.originAuthDelivery.Status(ctx, tenant.scopeID)
				if err != nil {
					return fail(err)
				}
				if delivery.State != edgepublish.OriginAuthDeliveryNone {
					status["origin_auth_delivery"], auth = delivery, &delivery
				}
			}
			// fix-mktsiteconf7 §1: whether it took effect on this leaf's nodes.
			status["nodes"] = nodeDelivery(current.SyncStatus, security, auth)
			reply.Status, _ = json.Marshal(status)
			reply.OK = true
			return reply, nil
		}
		if _, err := s.sites.Delete(ctx, siteActor(actor), site.DeleteRequest{ID: current.ID,
			ExpectedRevision: current.Revision, IdempotencyKey: "market-del-" + ref.SiteID.String(),
			RequestID: "market-" + header.MessageID.String()}); err != nil {
			return fail(err)
		}
		reply.OK = true
		return reply, nil
	case siteconf.OpPurge:
		if s.purge == nil {
			return fail(ErrUnsupportedOp)
		}
		var req siteconf.PurgeRequest
		if err := json.Unmarshal(payload, &req); err != nil {
			return fail(siteconf.ErrInvalid)
		}
		reply.SiteID, reply.LeafSiteID = req.SiteID, &req.LeafSiteID
		current, err := s.ownedSite(ctx, actor, tenant, req.LeafSiteID)
		if err != nil {
			return fail(err)
		}
		operations, err := s.purgeSite(ctx, tenant, siteRef{id: current.ID, domain: current.Domain,
			https: len(current.HTTPPorts) == 0 && current.HTTPSEnabled}, req, header.MessageID)
		if len(operations) > 0 {
			reply.Status, _ = json.Marshal(map[string]any{"cache_operation_ids": operations})
		}
		if err != nil {
			return fail(err)
		}
		reply.OK = true
		return reply, nil
	default:
		return fail(ErrUnsupportedOp)
	}
}

func (s *Service) blockers(ctx context.Context, g grant.Grant, tenant tenantRef, leafID *uuid.UUID,
	siteID uuid.UUID, c siteconf.Config,
) []siteconf.Blocker {
	out := c.CheckAllocation(g.Allocation, g.Limits)
	var others int64
	// Same "latest fact per domain" rule site.Store uses for active domains.
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM (
			SELECT DISTINCT ON (fact.site_id, fact.canonical_domain) fact.action
			FROM site_domain_facts fact JOIN sites ON sites.id=fact.site_id AND sites.deleted_at IS NULL
			WHERE fact.scope_id=$1 AND ($2::uuid IS NULL OR fact.site_id<>$2)
			ORDER BY fact.site_id, fact.canonical_domain, fact.global_sequence DESC
		) latest WHERE latest.action='activate'`, tenant.scopeID, leafID).Scan(&others); err != nil {
		out = append(out, siteconf.Blocker{Code: "leaf_unavailable"})
	} else if domains, capped := g.Limits.Cap(mspec.MetricDomains); capped && others+int64(len(c.Domains)) > domains {
		out = append(out, siteconf.Blocker{Code: "pool_domain_limit", Detail: strconv.FormatInt(domains, 10)})
	}
	out = append(out, s.cacheBlockers(c)...)
	out = append(out, securityBlockers(c, s.policies != nil && s.activations != nil)...)
	out = append(out, s.wafBlockers(ctx, c, s.policies != nil && s.activations != nil)...)
	out = append(out, ccBlockers(c, s.policies != nil && s.activations != nil)...)
	if geos, err := s.routeGeos(ctx, c); err != nil {
		out = append(out, siteconf.Blocker{Code: "leaf_unavailable"})
	} else {
		out = append(out, protocolBlockers(c, geos)...)
	}
	out = append(out, s.siteAccessBlockers(c)...)
	out = append(out, s.httpPolicyBlockers(c)...)
	out = append(out, s.originAuthBlockers(c, siteID)...)
	if s.cfg.CNAMEDomain == "" {
		out = append(out, siteconf.Blocker{Code: "leaf_cname_unconfigured"})
	}
	if g.Compliance.RequireICP {
		if s.icp == nil {
			out = append(out, siteconf.Blocker{Code: "icp_checker_unconfigured"})
		} else {
			for _, d := range c.Domains {
				filed, err := s.icp(ctx, d)
				if err != nil {
					out = append(out, siteconf.Blocker{Code: "icp_check_failed", Detail: d})
				} else if !filed {
					out = append(out, siteconf.Blocker{Code: "icp_unfiled", Detail: d})
				}
			}
		}
	}
	slices.SortStableFunc(out, func(a, b siteconf.Blocker) int {
		if a.Code < b.Code {
			return -1
		} else if a.Code > b.Code {
			return 1
		}
		return 0
	})
	return out
}

func (s *Service) commit(ctx context.Context, actor serviceActor, g grant.Grant, tenant tenantRef,
	req siteconf.CommitRequest, http3 bool,
) (uuid.UUID, error) {
	var subID, poolID uuid.UUID
	var poolName string
	if err := s.pool.QueryRow(ctx, `SELECT s.id, g.id, g.name FROM package_subscriptions s
		JOIN package_products p ON p.id=s.product_id
		JOIN node_line_groups g ON g.id=(p.spec->>'node_group_id')::uuid AND g.deleted_at IS NULL
		WHERE s.tenant_scope_id=$1 AND s.lifecycle_status='active' AND s.deleted_at IS NULL AND p.name=$2
		ORDER BY s.created_at DESC LIMIT 1`, tenant.scopeID, productPrefix+Key(g)).Scan(&subID, &poolID, &poolName); err != nil {
		return uuid.Nil, ErrGrantInactive
	}
	fields, pool := siteFields(req.Config, http3)
	fields.PackageSubscriptionID = &subID
	fields.NodeGroupID, fields.NodeGroupName = &poolID, poolName
	key := "market-" + req.SiteID.String() + "-" + strconv.FormatInt(req.Revision, 10)
	if req.LeafSiteID == nil {
		created, err := s.sites.Create(ctx, siteActor(actor), site.CreateRequest{
			TargetScopeID: tenant.scopeID, OwnerUserID: tenant.userID, Fields: fields, OriginPool: &pool,
			IdempotencyKey: key, RequestID: key,
		})
		if err != nil {
			return uuid.Nil, err
		}
		return created.Site.ID, nil
	}
	current, err := s.ownedSite(ctx, actor, tenant, *req.LeafSiteID)
	if err != nil {
		return uuid.Nil, err
	}
	updated, err := s.sites.Update(ctx, siteActor(actor), site.UpdateRequest{ID: current.ID,
		ExpectedRevision: current.Revision, Fields: fields, IdempotencyKey: key, RequestID: key})
	if err != nil {
		return uuid.Nil, err
	}
	if _, err := s.sites.UpdateOrigin(ctx, siteActor(actor), site.UpdateOriginRequest{ID: current.ID,
		ExpectedRevision: updated.Site.Revision, Pool: pool, IdempotencyKey: key + "-origin", RequestID: key}); err != nil {
		return uuid.Nil, err
	}
	return current.ID, nil
}

func (s *Service) ownedSite(ctx context.Context, actor serviceActor, tenant tenantRef, id uuid.UUID) (site.Site, error) {
	current, err := s.sites.Get(ctx, siteActor(actor), id)
	if err != nil {
		return site.Site{}, err
	}
	if current.ScopeID != tenant.scopeID {
		return site.Site{}, ErrForeignSite
	}
	return current, nil
}

// protocolBlockers: a conditional origin document the local model refuses
// (geos: the leaf's region geographies, routeGeos). WebSocket, HTTP/3,
// HTTPS / follow origins and backup levels are the leaf's own site settings
// and are written as sent (HTTP/3 only where the supply's nodes declare
// SITE_QUIC, http3Advisory).
func protocolBlockers(c siteconf.Config, geos map[string]regioncatalog.CodeGeo) []siteconf.Blocker {
	if c.OriginRoutes == nil {
		return nil
	}
	if _, _, err := originRouteDocument(c.OriginRoutes, geos); err != nil {
		return []siteconf.Blocker{{Code: "origin_routes_invalid"}}
	}
	return nil
}

// siteFields maps the config onto the leaf's site fields and origin pool;
// http3 is false when the supply's nodes cannot serve HTTP/3.
func siteFields(c siteconf.Config, http3 bool) (site.SiteFields, site.OriginPool) {
	ports := func(in []int) []string {
		out := make([]string, len(in))
		for i, p := range in {
			out[i] = strconv.Itoa(p)
		}
		return out
	}
	text := func(v string) *string { return &v }
	boolean := func(v bool) *bool { return &v }
	https := len(c.HTTPSPorts) > 0
	fields := site.SiteFields{
		Domains: slices.Clone(c.Domains), HTTPPorts: ports(c.HTTPPorts), HTTPSPorts: ports(c.HTTPSPorts),
		HTTPSEnabled: https, Enabled: true, ForceHTTPS: boolean(c.ForceHTTPS),
		HTTP3Enabled: boolean(https && c.HTTP3 && http3), TLSClientAuth: text(edgeconfig.ClientAuthOff), TLSClientCAPEM: text(""),
	}
	if c.HTTPSRedirectPort != 0 {
		fields.HTTPSRedirectPort = &c.HTTPSRedirectPort
	}
	// fix-mktsiteconf2: the HTTPS profile (absent: the baseline protocols,
	// modern preset, OCSP off, HTTP/2 on, server cipher preference by preset),
	// IPv6 and the cache switches, always written so a later revision that
	// turns one back to its default is applied too.
	tlsOptions := siteconf.TLSOptions{}
	if c.TLS != nil {
		tlsOptions = *c.TLS
	}
	fields.TLSProtocols = edgeconfig.BaselineTLSProtocols()
	if tlsOptions.Protocols != nil {
		fields.TLSProtocols = slices.Clone(tlsOptions.Protocols)
	}
	preset := tlsOptions.CipherPreset
	if preset == "" {
		preset = edgeconfig.TLSCipherModern
	}
	fields.TLSCipherPreset, fields.TLSCipherSuites = &preset, slices.Clone(tlsOptions.CipherSuites)
	fields.TLSOCSPStapling, fields.HTTP2Enabled = boolean(tlsOptions.OCSPStapling), boolean(!tlsOptions.HTTP2Off)
	fields.TLSPreferServerCiphers = tlsOptions.PreferServerCiphers
	fields.TLSPreferServerCiphersReset = tlsOptions.PreferServerCiphers == nil
	fields.IPv6Enabled = c.IPv6
	fields.CacheSharedAcrossDomains, fields.CacheStatusHeader = boolean(c.CacheSharedAcrossDomains), boolean(!c.CacheStatusHeaderOff)
	if c.ClientAuth != nil {
		fields.TLSClientAuth, fields.TLSClientCAPEM = text(c.ClientAuth.Mode), text(c.ClientAuth.CAPEM)
	}
	f := siteconf.Forwarding{}
	if c.Forwarding != nil {
		f = *c.Forwarding
	}
	keepalive := !f.KeepaliveDisabled
	pool := site.OriginPool{BalanceMethod: c.BalanceMethod, FailoverTries: max(1, f.FailoverTries),
		ConnectTimeoutMS: clamp(c.ConnectTimeoutMS, 3000, 50, 30_000),
		ReadTimeoutMS:    clamp(c.ReadTimeoutMS, 30_000, 100, 300_000),
		Scheme:           c.OriginScheme, HTTPPort: f.HTTPPort, HTTPSPort: f.HTTPSPort, FollowPort: f.FollowPort,
		KeepaliveEnabled: &keepalive, KeepaliveIdleTimeoutMS: f.KeepaliveIdleMS,
		HashKey: f.HashKey, RequestHost: site.OriginRequestHost{Mode: f.RequestHost, Value: f.RequestHostValue},
		TLS:               site.OriginTLS{SNI: f.TLSSNI, Trust: site.OriginTrustSystem},
		WebSocket:         &site.OriginWebSocket{Enabled: c.WebSocket, AllowedOrigins: slices.Clone(f.WebSocketOrigins)},
		TrustedProxyCIDRs: slices.Clone(f.TrustedProxyCIDRs), SearchEngineOrigin: f.SearchEngineOrigin,
		ResponseBuffering: f.ResponseBuffering, RequestBuffering: f.RequestBuffering, ACMEPassthrough: f.ACMEPassthrough,
		FailbackMode: site.FailbackAuto, HealthCheckPath: f.HealthCheckPath,
	}
	if pool.RequestHost.Mode == "" {
		pool.RequestHost.Mode = site.OriginRequestHostVisitor
	}
	if f.TLSCAPEM != "" {
		pool.TLS.Trust, pool.TLS.CAPEM = site.OriginTrustCustom, f.TLSCAPEM
	}
	if f.Sticky != nil {
		pool.Sticky = &site.OriginSticky{Source: f.Sticky.Source, Name: f.Sticky.Name}
	}
	if f.FollowRedirect != nil {
		pool.FollowRedirect = &site.OriginFollowRedirect{Enabled: true, MaxHops: f.FollowRedirect.MaxHops,
			CrossOrigin: f.FollowRedirect.CrossOrigin}
	}
	if f.FailbackManual {
		pool.FailbackMode = site.FailbackManual
	}
	pool.L2Mode = site.SiteL2Package
	if f.L2Off {
		pool.L2Mode = site.SiteL2Off
	}
	for _, o := range c.Origins {
		endpoint := o.Host
		if addr, err := netip.ParseAddr(o.Host); err == nil && addr.Is6() {
			endpoint = "[" + o.Host + "]"
		}
		if o.Port != 80 {
			endpoint += ":" + strconv.Itoa(o.Port)
		}
		fields.Origins = append(fields.Origins, endpoint)
		pool.Origins = append(pool.Origins, site.Origin{Host: o.Host, Port: o.Port, Weight: o.Weight, Enabled: true,
			Level: o.Level, MaxConns: o.MaxConns})
	}
	return fields, pool
}

func clamp(v, fallback, lo, hi int) int {
	if v == 0 {
		return fallback
	}
	return max(lo, min(hi, v))
}

func normalizedHeaderDomains(in []string) []string {
	c := siteconf.Config{Schema: siteconf.SchemaV1, Domains: slices.Clone(in), HTTPPorts: []int{80},
		Origins: []siteconf.Origin{{Host: "192.0.2.1", Port: 80}}}
	if c.Normalize() != nil {
		return nil
	}
	return c.Domains
}

func siteActor(a serviceActor) site.Actor {
	return site.Actor{UserID: a.userID, ScopeID: a.scopeID, ScopeKind: "platform", SessionID: a.sessionID}
}
