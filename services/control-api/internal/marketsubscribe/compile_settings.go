package marketsubscribe

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/services/control-api/internal/httppolicycontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Site settings beyond protocols and origins (fix-mktsiteconf2 ①): carried
// so the leaf serves the site as the subscriber configured it; what the leaf
// cannot hold is listed (never left to the leaf's defaults).

// compileSiteSettings writes the site's HTTPS profile, IPv6, cache switches
// and L2 mode; a custom L2 configuration is the subscriber's own nodes.
func compileSiteSettings(s site.Site, cfg *siteconf.Config) []Unsupported {
	if s.HTTPSEnabled {
		t := &siteconf.TLSOptions{CipherPreset: s.TLSCipherPreset, OCSPStapling: s.TLSOCSPStapling,
			PreferServerCiphers: s.TLSPreferServerCiphers, HTTP2Off: !s.HTTP2Enabled}
		if !slices.Equal(s.TLSProtocols, edgeconfig.BaselineTLSProtocols()) {
			t.Protocols = slices.Clone(s.TLSProtocols)
		}
		if s.TLSCipherPreset == edgeconfig.TLSCipherCustom {
			t.CipherSuites = slices.Clone(s.TLSCipherSuites)
		}
		cfg.TLS = t
	}
	cfg.IPv6 = s.ListenerState.IPv6DesiredEnabled
	cfg.CacheSharedAcrossDomains, cfg.CacheStatusHeaderOff = s.CacheSharedAcrossDomains, !s.CacheStatusHeader
	switch s.OriginPool.L2Mode {
	case "", site.SiteL2Package:
	case site.SiteL2Off:
		if cfg.Forwarding == nil {
			cfg.Forwarding = &siteconf.Forwarding{}
		}
		cfg.Forwarding.L2Off = true
	default:
		return []Unsupported{{Code: "site_l2_custom"}}
	}
	return nil
}

// compileSiteAccess carries the site access settings (访问控制: host
// redirects, HSTS, compression, per-client limits, maintenance page, WebP,
// response rules, forced HTTPS status / excluded hosts, basic auth as the
// stored per-user salted hashes, which do not depend on the site).
func (s *Service) compileSiteAccess(ctx context.Context, siteID uuid.UUID, cfg *siteconf.Config) ([]Unsupported, error) {
	var raw []byte
	var status int
	var exclude []string
	err := s.pool.QueryRow(ctx, `SELECT access.settings, site.https_redirect_status, site.https_redirect_exclude_hosts
		FROM sites site LEFT JOIN site_access_settings access ON access.site_id=site.id
		WHERE site.id=$1`, siteID).Scan(&raw, &status, &exclude)
	if err != nil {
		return nil, err
	}
	var access edgeconfig.SiteAccess
	if raw != nil {
		if err := json.Unmarshal(raw, &access); err != nil {
			return nil, err
		}
	}
	if cfg.SiteAccess, err = siteAccessBlock(access, status, exclude); err != nil {
		return nil, err
	}
	return nil, nil
}

// siteAccessBlock is siteconf's site_access object for the stored settings.
func siteAccessBlock(access edgeconfig.SiteAccess, status int, exclude []string) ([]byte, error) {
	carried := siteAccessDocument{HostRedirects: access.HostRedirects, HSTS: access.HSTS, Compression: access.Compression,
		Limits: access.Limits, Maintenance: access.Maintenance, WebP: access.WebP, ResponseRules: access.ResponseRules,
		BasicAuth: access.BasicAuth}
	if status != 0 && status != 301 || len(exclude) > 0 {
		carried.ForceHTTPS = &siteAccessForceHTTPS{Status: status, ExcludeHosts: exclude}
	}
	return json.Marshal(carried)
}

// siteAccessDocument is siteconf's site_access object: siteaccess.Settings
// with basic auth users as salted hashes, absent members off.
type siteAccessDocument struct {
	HostRedirects []edgeconfig.HostRedirect       `json:"host_redirects,omitempty"`
	HSTS          *edgeconfig.SiteHSTS            `json:"hsts,omitempty"`
	Compression   *edgeconfig.SiteCompression     `json:"compression,omitempty"`
	Limits        *edgeconfig.SiteRequestLimits   `json:"limits,omitempty"`
	Maintenance   *edgeconfig.SiteMaintenancePage `json:"maintenance,omitempty"`
	WebP          *edgeconfig.SiteWebP            `json:"webp,omitempty"`
	ResponseRules []edgeconfig.SiteResponseRule   `json:"response_rules,omitempty"`
	BasicAuth     *edgeconfig.SiteBasicAuth       `json:"basic_auth,omitempty"`
	ForceHTTPS    *siteAccessForceHTTPS           `json:"force_https,omitempty"`
}

type siteAccessForceHTTPS struct {
	Status       int      `json:"status"`
	ExcludeHosts []string `json:"exclude_hosts,omitempty"`
}

// compileSiteExtras compiles the site access settings, the enabled HTTP
// policy (源站请求头、上传上限、改写/跳转/CORS/防盗链, fix-mktsiteconf3: the
// leaf writes it through httppolicycontrol's system site write) and the live
// origin auth rules with their credentials sealed per leaf
// (compile_origin_auth.go, fix-mktsiteconf5).
func (s *Service) compileSiteExtras(ctx context.Context, current site.Site, cfg *siteconf.Config) ([]Unsupported, error) {
	out, err := s.compileSiteAccess(ctx, current.ID, cfg)
	if err != nil {
		return nil, err
	}
	if err := s.compileHTTPPolicy(ctx, current, cfg); err != nil {
		return nil, err
	}
	var originAuth bool
	if err := s.pool.QueryRow(ctx, `SELECT
			EXISTS (SELECT 1 FROM origin_auth_rules rule JOIN LATERAL (SELECT enabled, deleted FROM origin_auth_rule_revisions
				WHERE rule_id=rule.id ORDER BY revision DESC LIMIT 1) latest ON true
				WHERE rule.site_id=$1 AND latest.enabled AND NOT latest.deleted)`, current.ID).Scan(&originAuth); err != nil {
		return nil, err
	}
	auth, err := s.compileOriginAuth(ctx, current, cfg, originAuth)
	if err != nil {
		return nil, err
	}
	return append(out, auth...), nil
}

// compileHTTPPolicy writes the site's enabled HTTP policy config as the
// http_policy block (none: absent, so the leaf removes its own).
func (s *Service) compileHTTPPolicy(ctx context.Context, current site.Site, cfg *siteconf.Config) error {
	return pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var scopeID uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT scope_id FROM sites WHERE id=$1`, current.ID).Scan(&scopeID); err != nil {
			return err
		}
		config, found, err := httppolicycontrol.SiteConfigTx(ctx, tx, scopeID, current.ID)
		if err != nil || !found {
			return err
		}
		cfg.HTTPPolicy, err = json.Marshal(config)
		return err
	})
}
