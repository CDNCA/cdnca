package edgepublish

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/services/control-api/internal/errorpagecontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/originauthcontrol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// D13-b: the facts a dynamic routing publication takes from the scope's own
// releases (error pages, origin authentication): the latest published error
// page snapshot (the one its nodes run) and the latest origin auth
// publication, converted per site (siteErrorPageFacts, originAuthFacts).

// loadDynamicRoutingFacts reads the scope's published error page snapshot
// and origin auth publication (either may be absent: nil).
func loadDynamicRoutingFacts(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) (*errorpagecontrol.ProductionSnapshotDocument,
	*originauthcontrol.PublicationSnapshot, error) {
	var wire []byte
	err := tx.QueryRow(ctx, `SELECT artifact.wire_bytes FROM rollouts rollout
		JOIN configuration_artifacts artifact ON artifact.config_version_id=rollout.config_version_id
		 AND artifact.ordinal=1 AND artifact.kind='configuration' AND artifact.media_type=$2
		WHERE rollout.configuration_scope_id=$1 ORDER BY rollout.created_at DESC, rollout.id DESC LIMIT 1`,
		scopeID, errorpagecontrol.ProductionSnapshotMediaType).Scan(&wire)
	var pages *errorpagecontrol.ProductionSnapshotDocument
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// Never published (73: no theme, no error page rule): the node's own
		// 403/429 still get the built-in branded block pages (sec-followup P13).
		builtin, err := errorpagecontrol.BuiltinBlockSnapshot()
		if err != nil {
			return nil, nil, fmt.Errorf("%w: built-in block pages: %v", ErrInvalidInput, err)
		}
		pages = &builtin
	case err != nil:
		return nil, nil, fmt.Errorf("%w: load error page snapshot", ErrPersistence)
	default:
		pages = &errorpagecontrol.ProductionSnapshotDocument{}
		if err := json.Unmarshal(wire, pages); err != nil {
			return nil, nil, fmt.Errorf("%w: error page snapshot: %v", ErrInvalidInput, err)
		}
	}
	var snapshot []byte
	err = tx.QueryRow(ctx, `SELECT canonical_snapshot FROM origin_auth_publications WHERE tenant_scope_id=$1
		ORDER BY revision DESC LIMIT 1`, scopeID).Scan(&snapshot)
	var auth *originauthcontrol.PublicationSnapshot
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return nil, nil, fmt.Errorf("%w: load origin auth publication", ErrPersistence)
	default:
		auth = &originauthcontrol.PublicationSnapshot{}
		if err := json.Unmarshal(snapshot, auth); err != nil {
			return nil, nil, fmt.Errorf("%w: origin auth publication: %v", ErrInvalidInput, err)
		}
	}
	return pages, auth, nil
}

// withoutOriginAuthDisabledSites drops from auth the rules of the scope's
// sites whose origin auth switch is off (site_origin_pools
// origin_auth_enabled, migration 490): their requests are not signed; the
// rules themselves (and the publication) stay, so switching it back on signs
// again with the next site object publication.
func withoutOriginAuthDisabledSites(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID,
	auth *originauthcontrol.PublicationSnapshot) (*originauthcontrol.PublicationSnapshot, error) {
	if auth == nil || len(auth.Rules) == 0 {
		return auth, nil
	}
	rows, err := tx.Query(ctx, `SELECT pool.site_id FROM site_origin_pools pool JOIN sites site ON site.id=pool.site_id
		WHERE site.scope_id=$1 AND NOT pool.origin_auth_enabled`, scopeID)
	if err != nil {
		return nil, fmt.Errorf("%w: read origin auth switches", ErrPersistence)
	}
	defer rows.Close()
	off := map[uuid.UUID]bool{}
	for rows.Next() {
		var siteID uuid.UUID
		if err := rows.Scan(&siteID); err != nil {
			return nil, fmt.Errorf("%w: scan origin auth switches", ErrPersistence)
		}
		off[siteID] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: iterate origin auth switches", ErrPersistence)
	}
	return originAuthEnabledRules(*auth, off), nil
}

// originAuthEnabledRules is snapshot without the rules of the sites in off.
func originAuthEnabledRules(snapshot originauthcontrol.PublicationSnapshot, off map[uuid.UUID]bool) *originauthcontrol.PublicationSnapshot {
	if len(off) == 0 {
		return &snapshot
	}
	rules := make([]originauthcontrol.PublicationRule, 0, len(snapshot.Rules))
	for _, rule := range snapshot.Rules {
		if !off[rule.SiteID] {
			rules = append(rules, rule)
		}
	}
	snapshot.Rules = rules
	return &snapshot
}

// dynamicRoutingFacts converts the scope's error page snapshot and origin
// auth publication into each site's facts (keyed by site ID).
func dynamicRoutingFacts(source siteObjectsV2Source, pages *errorpagecontrol.ProductionSnapshotDocument,
	auth *originauthcontrol.PublicationSnapshot) (map[string]siteObjectV2Facts, error) {
	if pages == nil && auth == nil {
		return nil, nil
	}
	sites := source.runtimes()
	facts := make(map[string]siteObjectV2Facts, len(sites))
	if pages != nil {
		ids := make([]string, 0, len(sites))
		for id := range sites {
			ids = append(ids, id)
		}
		assets := map[string][]byte{}
		byPage, byVariant, err := siteErrorPageFacts(*pages, ids, assets)
		if err != nil {
			return nil, err
		}
		for id, list := range byPage {
			facts[id] = siteObjectV2Facts{ErrorPages: list, ErrorVariants: byVariant[id], ErrorAssets: assets}
		}
	}
	if auth != nil {
		for id, list := range originAuthFacts(*auth, sites) {
			value := facts[id]
			value.OriginAuth = list
			facts[id] = value
		}
	}
	return facts, nil
}

// originAuthFacts binds each rule to the pool that reaches its origin (v7
// origin_auth_release.go: the L2 direct fallback, else the default pool,
// position 1, a pool of one HTTPS origin); other rules are not signed, as in
// v7. The secret object is the rule's at the publication revision (the
// node installer writes <rule>/<revision>.json).
func originAuthFacts(snapshot originauthcontrol.PublicationSnapshot, sites map[string]siteRuntimeV2Site) map[string][]edgesite.OriginAuth {
	result := map[string][]edgesite.OriginAuth{}
	for _, rule := range snapshot.Rules {
		runtime, ok := sites[rule.SiteID.String()]
		if !ok || rule.SourcePosition != 1 || snapshot.PublicationRevision < 1 {
			continue
		}
		poolID := runtime.DefaultPoolID
		if runtime.L2.Enabled != nil && *runtime.L2.Enabled && runtime.L2.DirectFallbackPoolID != nil {
			poolID = *runtime.L2.DirectFallbackPoolID
		}
		signed := false
		for _, pool := range runtime.OriginPools {
			signed = signed || pool.ID == poolID && pool.Kind == edgesite.PoolOrigin && len(pool.Origins) == 1 && pool.Origins[0].Scheme == "https"
		}
		if !signed {
			continue
		}
		result[rule.SiteID.String()] = append(result[rule.SiteID.String()], edgesite.OriginAuth{PoolID: poolID, Endpoint: rule.Endpoint,
			Secret: edgesite.Ref{Kind: edgesite.RefOriginAuthSecret, ID: rule.RuleID.String(), Revision: snapshot.PublicationRevision}})
	}
	return result
}
