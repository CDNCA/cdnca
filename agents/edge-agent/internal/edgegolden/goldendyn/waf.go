package goldendyn

import (
	"fmt"
	"path/filepath"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynwaf"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/edgegolden"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/edgegolden/goldenrelease"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgeskeleton"
	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
)

// managedWAF prepares the sites' managed WAF as the agent does (D11,
// internal/dynwaf): the signed catalog's CRS text and the CRS profile packs
// the corpus embeds (goldenrelease.CRSProfiles, libs/rulepack's goldens), the
// engine extension the run mounts. nil without a managed WAF site.
func managedWAF(env edgegolden.Env, sites []edgesite.Site, root string) (*edgeskeleton.ManagedWAF, error) {
	managed := false
	for _, site := range sites {
		managed = managed || site.Security.ManagedWAF != nil
	}
	if !managed {
		return nil, nil
	}
	files, err := rulecatalog.DecodeWAFEngineBundle(*rulecatalog.CRSRulesBundle())
	if err != nil {
		return nil, err
	}
	profiles, err := goldenrelease.CRSProfiles()
	if err != nil {
		return nil, err
	}
	var engine *dynwaf.Engine
	if env.ModSecurity != "" {
		engine = &dynwaf.Engine{ModulePath: filepath.Join(env.ModSecurity, "modules", "ngx_http_modsecurity_module.so"),
			UnicodeMapPath: filepath.Join(env.ModSecurity, "unicode.mapping")}
	}
	result, err := dynwaf.Prepare(dynwaf.Input{Sites: sites, Engine: engine, Profiles: profiles,
		CRSText: &edgeconfig.CRSRuleText{Version: rulecatalog.CRSRulesBundle().Version, Files: files},
		Root:    filepath.Join(root, "managed-waf"), AuditLog: filepath.Join(root, SharedDirectory, "modsecurity-audit.log")})
	if err != nil {
		return nil, fmt.Errorf("managed WAF: %w", err)
	}
	return result.Skeleton, nil
}
