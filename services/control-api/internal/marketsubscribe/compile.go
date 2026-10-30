package marketsubscribe

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/regioncatalog"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// MC12 E2 (MK-BUYER-FLOW-01): a market revision compiled from the saved site
// instead of JSON and a revision number typed by the administrator.

// ErrSiteChanged: the site was saved again after the preview the
// administrator approved; apply refuses instead of sending another config.
var ErrSiteChanged = errors.New("market subscribe: site changed since the preview")

// Unsupported is one saved site setting siteconf v1 cannot carry. The
// compiled revision would serve the site without it, so it blocks the
// rollout until the administrator changes the site (never dropped silently).
type Unsupported struct {
	Code   string `json:"code"`
	Detail string `json:"detail,omitempty"`
}

// CompileSite maps a saved site onto siteconf v1: domains, ports, enabled
// origins (level, weight, port, connection limit), scheme, balance and its
// key, timeouts, WebSocket, HTTP/3, forced HTTPS, client certificates, the
// origin forwarding options (fix-mktsiteconf), the HTTPS profile, IPv6, the
// cache switches and the L2 mode (fix-mktsiteconf2). What still cannot be
// carried is listed in the second result; the local rules (cache, security
// policies, conditional origins) are compiled by PlanSite.
func CompileSite(s site.Site) (siteconf.Config, []Unsupported) {
	pool := s.OriginPool
	cfg := siteconf.Config{
		Schema: siteconf.SchemaV1, Domains: slices.Clone(s.Domains), HTTPPorts: intPorts(s.HTTPPorts),
		OriginScheme: pool.Scheme, BalanceMethod: pool.BalanceMethod,
		ConnectTimeoutMS: pool.ConnectTimeoutMS, ReadTimeoutMS: pool.ReadTimeoutMS,
		WebSocket: pool.WebSocket == nil || pool.WebSocket.Enabled, Certificate: "none",
	}
	if len(cfg.Domains) == 0 && s.Domain != "" {
		cfg.Domains = []string{s.Domain}
	}
	if s.HTTPSEnabled {
		cfg.HTTPSPorts, cfg.HTTP3, cfg.Certificate = intPorts(s.HTTPSPorts), s.HTTP3Enabled, "leaf_issued"
		cfg.ForceHTTPS, cfg.HTTPSRedirectPort = s.ForceHTTPS, s.HTTPSRedirectPort
		if s.TLSClientAuth != "" && s.TLSClientAuth != edgeconfig.ClientAuthOff {
			cfg.ClientAuth = &siteconf.ClientAuth{Mode: s.TLSClientAuth, CAPEM: s.TLSClientCAPEM}
		}
	}
	if !cfg.ForceHTTPS {
		cfg.HTTPSRedirectPort = 0
	}
	var out []Unsupported
	add := func(code, detail string) { out = append(out, Unsupported{Code: code, Detail: detail}) }
	enabled := 0
	for _, o := range pool.Origins {
		if !o.Enabled {
			continue
		}
		enabled++
		cfg.Origins = append(cfg.Origins, siteconf.Origin{Host: o.Host, Port: o.Port, Weight: o.Weight, Level: o.Level,
			MaxConns: o.MaxConns})
	}
	if len(cfg.Origins) == 0 {
		add("no_enabled_origin", "")
	}
	if !s.Enabled {
		add("site_disabled", "")
	}
	cfg.Forwarding = compileForwarding(pool, min(pool.FailoverTries, enabled))
	out = append(out, compileSiteSettings(s, &cfg)...)
	return cfg, out
}

// compileForwarding is the pool's forwarding options (nil fields and zero
// values are the defaults; Normalize drops an all-default block).
func compileForwarding(pool site.OriginPool, failoverTries int) *siteconf.Forwarding {
	f := &siteconf.Forwarding{
		RequestHost: pool.RequestHost.Mode, RequestHostValue: pool.RequestHost.Value,
		HTTPPort: pool.HTTPPort, HTTPSPort: pool.HTTPSPort, FollowPort: pool.FollowPort,
		TLSSNI: pool.TLS.SNI, HashKey: pool.HashKey, TrustedProxyCIDRs: slices.Clone(pool.TrustedProxyCIDRs),
		SearchEngineOrigin: pool.SearchEngineOrigin, ResponseBuffering: falseOnly(pool.ResponseBuffering),
		RequestBuffering: falseOnly(pool.RequestBuffering), ACMEPassthrough: pool.ACMEPassthrough,
		KeepaliveDisabled: pool.KeepaliveEnabled != nil && !*pool.KeepaliveEnabled,
		FailbackManual:    pool.FailbackMode == site.FailbackManual, HealthCheckPath: pool.HealthCheckPath,
		FailoverTries: failoverTries,
	}
	if pool.KeepaliveIdleTimeoutMS != site.DefaultKeepaliveIdleTimeoutMS {
		f.KeepaliveIdleMS = pool.KeepaliveIdleTimeoutMS
	}
	if pool.TLS.Trust == site.OriginTrustCustom {
		f.TLSCAPEM = pool.TLS.CAPEM
	}
	if pool.Sticky != nil {
		f.Sticky = &siteconf.Sticky{Source: pool.Sticky.Source, Name: pool.Sticky.Name}
	}
	if pool.FollowRedirect != nil && pool.FollowRedirect.Enabled {
		f.FollowRedirect = &siteconf.FollowRedirect{MaxHops: pool.FollowRedirect.MaxHops, CrossOrigin: pool.FollowRedirect.CrossOrigin}
	}
	if pool.WebSocket != nil && pool.WebSocket.Enabled {
		f.WebSocketOrigins = slices.Clone(pool.WebSocket.AllowedOrigins)
	}
	return f
}

// falseOnly keeps an explicit "off" (true and absent are the default).
func falseOnly(v *bool) *bool {
	if v != nil && !*v {
		off := false
		return &off
	}
	return nil
}

func intPorts(in []string) []int {
	out := make([]int, 0, len(in))
	for _, raw := range in {
		if p, err := strconv.Atoi(raw); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// SiteReader reads a saved site as the platform administrator sees it.
type SiteReader interface {
	Get(ctx context.Context, actor site.Actor, id uuid.UUID) (site.Site, error)
}

// RouteReader reads a site's conditional origin document.
type RouteReader interface {
	GetConditionalOrigin(ctx context.Context, actor site.Actor, id uuid.UUID) (site.ConditionalOriginState, error)
}

// WithSites lets PreviewSite/ApplySite compile revisions from saved sites;
// a reader that also reads conditional origins (site.Service) compiles them.
func (s *Service) WithSites(reader SiteReader) *Service {
	s.sites = reader
	s.routes, _ = reader.(RouteReader)
	return s
}

// SitePlan is the revision compiled from one saved site: the site version
// it was read at, the market revision it becomes, its digest and config, and
// what blocks it. Apply quotes SiteVersion and Digest from the preview.
type SitePlan struct {
	SiteID      uuid.UUID       `json:"site_id"`
	Domain      string          `json:"domain"`
	SiteVersion int64           `json:"site_version"`
	Revision    int64           `json:"revision"`
	Digest      string          `json:"digest"`
	Config      siteconf.Config `json:"config"`
	Unsupported []Unsupported   `json:"unsupported"`
}

// SiteRolloutResult is a plan with the leaves' answers; Result is nil when
// Unsupported stopped it before any leaf was asked.
type SiteRolloutResult struct {
	Plan   SitePlan `json:"plan"`
	Result *Result  `json:"result,omitempty"`
}

// PlanSite compiles the site's current saved version. The market revision
// is the next one after the latest this site applied, or the latest again
// when its digest is unchanged (re-applying is idempotent on the leaves).
func (s *Service) PlanSite(ctx context.Context, actor site.Actor, siteID uuid.UUID) (SitePlan, error) {
	if s.sites == nil {
		return SitePlan{}, ErrInvalid
	}
	current, err := s.sites.Get(ctx, actor, siteID)
	if errors.Is(err, site.ErrNotFound) {
		return SitePlan{}, ErrNotFound
	}
	if err != nil {
		return SitePlan{}, err
	}
	cfg, unsupported := CompileSite(current)
	local, err := s.compileLocal(ctx, actor, siteID, &cfg)
	if err != nil {
		return SitePlan{}, err
	}
	unsupported = append(unsupported, local...)
	extras, err := s.compileSiteExtras(ctx, current, &cfg)
	if err != nil {
		return SitePlan{}, err
	}
	unsupported = append(unsupported, extras...)
	plan := SitePlan{SiteID: siteID, Domain: current.Domain, SiteVersion: current.Revision, Unsupported: unsupported}
	if plan.Unsupported == nil {
		plan.Unsupported = []Unsupported{}
	}
	if err := s.withAutoDefense(ctx, siteID, &cfg); err != nil {
		return SitePlan{}, err
	}
	if err := cfg.Normalize(); err != nil {
		if len(unsupported) == 0 {
			plan.Unsupported = append(plan.Unsupported, Unsupported{Code: "site_config_invalid"})
		}
		plan.Config = cfg
		return plan, nil
	}
	plan.Config, plan.Digest = cfg, cfg.Digest()
	var latest int64
	var latestDigest string
	err = s.pool.QueryRow(ctx, `SELECT revision, digest FROM site_supply_config_revisions WHERE site_id=$1
		ORDER BY revision DESC LIMIT 1`, siteID).Scan(&latest, &latestDigest)
	if err != nil && !isNoRows(err) {
		return SitePlan{}, err
	}
	plan.Revision = latest + 1
	if latest > 0 && latestDigest == plan.Digest {
		plan.Revision = latest
	}
	return plan, nil
}

// compileLocal compiles the site's local rules into cfg: its effective
// cache policy, its bound ACL, CC and WAF policies, its conditional origins.
// A rule a block cannot express is listed instead.
func (s *Service) compileLocal(ctx context.Context, actor site.Actor, siteID uuid.UUID, cfg *siteconf.Config) ([]Unsupported, error) {
	var out []Unsupported
	if doc, found, err := cachecontrol.SiteEffectiveDocument(ctx, s.pool, siteID); err != nil {
		return nil, err
	} else if found {
		if cfg.Cache, err = compileCache(doc); err != nil {
			return nil, err
		}
	}
	policies, err := s.boundPolicies(ctx, siteID)
	if err != nil {
		return nil, err
	}
	for _, p := range policies {
		var reason string
		switch p.Kind {
		case securitypolicy.KindACL:
			var access *siteconf.Access
			if access, reason = compileACL(p); access != nil {
				cfg.Access, _ = json.Marshal(access)
			}
			if reason != "" {
				out = append(out, Unsupported{Code: "site_acl_rule", Detail: reason})
			}
		case securitypolicy.KindCC:
			if cc := compileCC(p); cc != nil {
				if cfg.CC, err = json.Marshal(cc); err != nil {
					return nil, err
				}
			}
		case securitypolicy.KindWAF:
			if reason, err = s.compileWAFPolicy(ctx, siteID, p, cfg); err != nil {
				return nil, err
			}
			if reason != "" {
				out = append(out, Unsupported{Code: "site_waf_policy", Detail: reason})
			}
		}
	}
	var routes bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM site_origin_route_configs WHERE site_id=$1)`,
		siteID).Scan(&routes); err != nil {
		return nil, err
	}
	if routes && s.routes != nil {
		state, err := s.routes.GetConditionalOrigin(ctx, actor, siteID)
		if err != nil {
			return nil, err
		}
		if len(state.Document.Routes) > 0 {
			var geos map[string]regioncatalog.CodeGeo
			if originRoutesNameRegions(state.Document) {
				if geos, err = regioncatalog.LoadCodeGeos(ctx, s.pool); err != nil {
					return nil, err
				}
			}
			compiled, reason := compileOriginRoutes(state.Document, geos)
			if reason != "" {
				out = append(out, Unsupported{Code: "site_origin_routes", Detail: reason})
			}
			cfg.OriginRoutes = compiled
		}
	} else if routes {
		out = append(out, Unsupported{Code: "site_origin_routes", Detail: "unavailable"})
	}
	return out, nil
}

// boundPolicies are the policy versions the site's nodes run: each security
// binding's active version.
func (s *Service) boundPolicies(ctx context.Context, siteID uuid.UUID) ([]securitypolicy.Policy, error) {
	rows, err := s.pool.Query(ctx, `SELECT version.document FROM security_policy_site_bindings binding
		JOIN security_policy_versions version ON version.policy_id=binding.policy_id
		 AND version.revision=binding.active_policy_version
		WHERE binding.site_id=$1 ORDER BY binding.policy_kind`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []securitypolicy.Policy
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var p securitypolicy.Policy
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// PreviewSite compiles the saved site and asks every leaf to check it.
func (s *Service) PreviewSite(ctx context.Context, actor site.Actor, siteID uuid.UUID) (SiteRolloutResult, error) {
	plan, err := s.PlanSite(ctx, actor, siteID)
	if err != nil || len(plan.Unsupported) > 0 {
		return SiteRolloutResult{Plan: plan}, err
	}
	result, err := s.run(ctx, siteID, plan.Revision, plan.Config, false)
	if err != nil {
		return SiteRolloutResult{Plan: plan}, err
	}
	return SiteRolloutResult{Plan: plan, Result: &result}, nil
}

// ApplySite applies exactly what the preview showed: it recompiles and
// refuses with ErrSiteChanged when the site version or the digest differs.
// Every attempt that reaches the leaves is audited (site.market_rollout.apply).
func (s *Service) ApplySite(ctx context.Context, actor site.Actor, siteID uuid.UUID, siteVersion int64, digest string) (SiteRolloutResult, error) {
	plan, err := s.PlanSite(ctx, actor, siteID)
	if err != nil {
		return SiteRolloutResult{Plan: plan}, err
	}
	if plan.SiteVersion != siteVersion || plan.Digest != digest {
		return SiteRolloutResult{Plan: plan}, ErrSiteChanged
	}
	if len(plan.Unsupported) > 0 {
		return SiteRolloutResult{Plan: plan}, nil
	}
	result, err := s.run(ctx, siteID, plan.Revision, plan.Config, true)
	if err != nil {
		return SiteRolloutResult{Plan: plan}, err
	}
	if err := s.auditApply(ctx, actor, plan, result); err != nil {
		return SiteRolloutResult{Plan: plan, Result: &result}, err
	}
	return SiteRolloutResult{Plan: plan, Result: &result}, nil
}

func (s *Service) auditApply(ctx context.Context, actor site.Actor, plan SitePlan, result Result) error {
	var scope uuid.UUID
	if err := s.pool.QueryRow(ctx, `SELECT scope_id FROM sites WHERE id=$1`, plan.SiteID).Scan(&scope); err != nil {
		return err
	}
	outcome, reason := "success", ""
	if !result.Applied {
		outcome, reason = "failure", "not_all_leaves_applied"
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		_, err := audit.AppendTx(ctx, tx, audit.Event{
			ScopeID: scope, ActorUserID: &actor.UserID, Action: "site.market_rollout.apply",
			// audit_events.request_id is NOT NULL non-empty (001); one id per apply.
			ResourceType: "site", ResourceID: plan.SiteID.String(), RequestID: uuid.NewString(), Result: outcome, ReasonCode: reason,
			Payload: map[string]any{"site_domain": plan.Domain, "site_version": plan.SiteVersion,
				"revision": result.Revision, "digest": result.Digest, "leaves": len(result.Leaves)},
		})
		return err
	})
}

// SiteBinding is one market supply bound to a site, read back after a change.
type SiteBinding struct {
	SupplyID uuid.UUID `json:"supply_id"`
	Name     string    `json:"name"`
	Role     string    `json:"role"`
	Priority int       `json:"priority"`
	Status   string    `json:"status"`
	Leaves   int       `json:"leaves"`
}

// SiteBindings lists the market supplies bound to a site.
func (s *Service) SiteBindings(ctx context.Context, siteID uuid.UUID) ([]SiteBinding, error) {
	rows, err := s.pool.Query(ctx, `SELECT supply.id, supply.name, binding.role, binding.priority, supply.status,
			jsonb_array_length(supply.leaves)
		FROM site_supply_bindings binding JOIN site_supplies supply ON supply.id=binding.supply_id
		WHERE binding.site_id=$1 AND supply.kind='market_subscription'
		ORDER BY binding.priority, supply.id`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SiteBinding{}
	for rows.Next() {
		var b SiteBinding
		if err := rows.Scan(&b.SupplyID, &b.Name, &b.Role, &b.Priority, &b.Status, &b.Leaves); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}
