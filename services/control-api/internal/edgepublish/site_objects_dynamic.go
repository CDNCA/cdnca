package edgepublish

import (
	"context"
	"fmt"
	"strings"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// dynamicRoutingPublication builds a scope's dynamic routing (site_runtime 9)
// publication from its compiled v2 release (siteObjectsV2Source, no v8
// split): the cdnca.edge.site/v2 objects of every site
// (buildSiteObjectsV2), the objects they reference and the scope's CRS rule
// text and profile packs, under a v2 root bound to the same document.
// Error pages and origin authentication come from the scope's latest
// published error page snapshot and origin auth publication (D13-b).
// packs are the rule packs the sites read from the node artifact set
// (siteObjectsRulePacks); the caller gates the targets on them.
func (s *Service) dynamicRoutingPublication(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID,
	source siteObjectsV2Source) (siteobject.Publication, []string, error) {
	var tenantID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT tenant_id FROM access_scopes WHERE id=$1 AND kind=$2`,
		scopeID, ScopeKindTenant).Scan(&tenantID); err != nil || tenantID == uuid.Nil {
		return siteobject.Publication{}, nil, fmt.Errorf("%w: load dynamic routing tenant", ErrPersistence)
	}
	pages, auth, err := loadDynamicRoutingFacts(ctx, tx, scopeID)
	if err != nil {
		return siteobject.Publication{}, nil, err
	}
	if auth, err = withoutOriginAuthDisabledSites(ctx, tx, scopeID, auth); err != nil {
		return siteobject.Publication{}, nil, err
	}
	facts, err := dynamicRoutingFacts(source, pages, auth)
	if err != nil {
		return siteobject.Publication{}, nil, err
	}
	facts, err = loadSiteRuleMounts(ctx, tx, scopeID, facts)
	if err != nil {
		return siteobject.Publication{}, nil, err
	}
	if err := loadSiteModSecurityFacts(ctx, tx, facts); err != nil {
		return siteobject.Publication{}, nil, err
	}
	if err := loadSiteCacheStatusHeaders(ctx, tx, scopeID, facts); err != nil {
		return siteobject.Publication{}, nil, err
	}
	var nodePages []siteobject.NodePageV2
	nodeAssets := map[string][]byte{}
	if pages != nil {
		if nodePages, err = nodePageFacts(*pages, nodeAssets); err != nil {
			return siteobject.Publication{}, nil, err
		}
	}
	return buildDynamicRoutingPublication(source, tenantID, facts, nodePages, nodeAssets)
}

// loadSiteRuleMounts reads the published rule pack mounts of the scope's
// sites (rulepackcontrol PublishSite writes them only without conflicts)
// into each site's facts (keyed by site ID; facts may be nil).
func loadSiteRuleMounts(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID,
	facts map[string]siteObjectV2Facts) (map[string]siteObjectV2Facts, error) {
	rows, err := tx.Query(ctx, `SELECT mount.site_id::text, mount.security FROM site_security_mounts mount
		JOIN sites site ON site.id=mount.site_id WHERE site.scope_id=$1 AND site.deleted_at IS NULL`, scopeID)
	if err != nil {
		return nil, fmt.Errorf("%w: load site rule pack mounts", ErrPersistence)
	}
	defer rows.Close()
	if facts == nil {
		facts = map[string]siteObjectV2Facts{}
	}
	for rows.Next() {
		var siteID string
		var document []byte
		if err := rows.Scan(&siteID, &document); err != nil {
			return nil, fmt.Errorf("%w: scan site rule pack mounts", ErrPersistence)
		}
		var mounts siteRuleMounts
		if err := decodeStrictJSON(document, &mounts); err != nil {
			return nil, fmt.Errorf("%w: site %s rule pack mounts: %v", ErrInvalidInput, siteID, err)
		}
		value := facts[siteID]
		value.Mounts = &mounts
		facts[siteID] = value
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: iterate site rule pack mounts", ErrPersistence)
	}
	rows.Close()
	if err := withholdMarketPluginMounts(ctx, tx, scopeID, facts); err != nil {
		return nil, err
	}
	return facts, nil
}

// nodePages are the scope's node pages (nodePageFacts), their bodies in
// nodeAssets (both may be nil).
func buildDynamicRoutingPublication(source siteObjectsV2Source, tenantID uuid.UUID,
	facts map[string]siteObjectV2Facts, nodePages []siteobject.NodePageV2, nodeAssets map[string][]byte) (siteobject.Publication, []string, error) {
	built, err := buildSiteObjectsV2(source, tenantID, facts)
	if err != nil {
		return siteobject.Publication{}, nil, err
	}
	if len(nodeAssets) > 0 && built.Referenced == nil {
		built.Referenced = map[string][]byte{}
	}
	for digest, body := range nodeAssets {
		built.Referenced[digest] = body
	}
	// CRS profile packs reach nodes as node artifact set items (crs_profile/*),
	// not with the release: the targets are gated on them (rule_pack_targets.go).
	scopeFiles := map[string][]byte{}
	for path, content := range source.Files {
		if _, profile := edgeconfig.ListenerCRSProfileDigest(path); profile {
			continue
		}
		if strings.HasPrefix(path, siteobject.ScopeFilePrefixV2) {
			scopeFiles[path] = content
		}
	}
	capabilities, err := siteobject.RootCapabilitiesV2(source.Capabilities)
	if err != nil {
		return siteobject.Publication{}, nil, fmt.Errorf("%w: dynamic routing capabilities: %v", ErrInvalidInput, err)
	}
	sites := make([]siteobject.SiteV2, len(built.Sites))
	for index, site := range built.Sites {
		sites[index] = siteobject.SiteV2{SiteID: site.SiteID, Revision: site.Revision, Plaintext: site.Plaintext}
	}
	// The document's platform system block (nginx base, DDoS protection)
	// and its L4 forwards ride on the v2 scope: the node renders and applies
	// them (D13-c0).
	publication, _, err := siteobject.BuildV2(siteobject.BuildV2Input{
		ConfigurationScopeID: source.ScopeID, ConfigVersionID: source.ConfigVersionID,
		SourceRevision: source.SourceRevision, KeyEpoch: siteObjectKeyEpoch, RequiredCapabilities: capabilities,
		DocumentSHA256: source.DocumentSHA256, Sites: sites, Referenced: built.Referenced, ScopeFiles: scopeFiles,
		System: source.System, Streams: source.Streams, NodePages: nodePages, InstallationID: source.InstallationID,
	})
	if err != nil {
		return siteobject.Publication{}, nil, fmt.Errorf("%w: dynamic routing publication: %v", ErrInvalidInput, err)
	}
	return publication, siteObjectsRulePacks(built), nil
}
