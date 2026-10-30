package errorpagecontrol

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// UsageCounts are the error_pages.* values for the license usage report
// (fix-usagereport). The lease limits are enforced per object or per scope
// (asset.go, rule.go, publication.go), so each value is the largest one
// across scopes, measured with the guard's own query: what the license
// service compares with the limit is "the fullest scope".
type UsageCounts struct {
	AssetBytes       int64 // error_pages.asset_bytes: largest live asset
	AssetsCount      int64 // error_pages.assets_count: most live assets in one scope
	TotalBytes       int64 // error_pages.total_bytes: most live asset bytes in one scope
	RulesPerScope    int64 // error_pages.rules_per_scope: most live rules in one rule scope
	PublicationSites int64 // error_pages.publication_sites: most sites in one scope's publication
	PublicationBytes int64 // error_pages.publication_bytes: largest scope publication document
}

// liveAssetFilter is asset.go's quota filter: rejected, deleted and orphaned
// assets do not use the quota.
const liveAssetFilter = `status NOT IN ('rejected','deleted','orphaned')`

func CountUsage(ctx context.Context, tx pgx.Tx) (UsageCounts, error) {
	var result UsageCounts
	if err := tx.QueryRow(ctx, `SELECT COALESCE(max(size_bytes),0),COALESCE(max(assets),0),COALESCE(max(total),0)
		FROM (
			SELECT max(size_bytes) AS size_bytes,count(*) AS assets,sum(size_bytes) AS total
			FROM error_page_assets WHERE `+liveAssetFilter+` GROUP BY scope_id
		) per_scope`).Scan(&result.AssetBytes, &result.AssetsCount, &result.TotalBytes); err != nil {
		return UsageCounts{}, err
	}
	// rule.go ensureRuleCapacity: rules not deleted in their latest revision,
	// per (scope_kind, scope_id, site_id).
	if err := tx.QueryRow(ctx, `SELECT COALESCE(max(rules),0) FROM (
		SELECT count(*) AS rules FROM error_page_rules identity
		JOIN LATERAL (
			SELECT revision.deleted FROM error_page_rule_revisions revision
			WHERE revision.rule_id=identity.id ORDER BY revision.revision DESC LIMIT 1
		) current ON true
		WHERE NOT current.deleted
		GROUP BY identity.scope_kind,identity.scope_id,identity.site_id
	) per_scope`).Scan(&result.RulesPerScope); err != nil {
		return UsageCounts{}, err
	}
	// publication.go: a rule scope's publish is checked against the snapshot
	// of its scope_id, rebuilt here at the latest publication revision.
	var revision int64
	if err := tx.QueryRow(ctx, `SELECT COALESCE(max(revision),0) FROM error_page_publications`).Scan(&revision); err != nil {
		return UsageCounts{}, err
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT scope_id FROM error_page_rules ORDER BY scope_id`)
	if err != nil {
		return UsageCounts{}, err
	}
	scopes, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return UsageCounts{}, err
	}
	for _, scopeID := range scopes {
		snapshot, err := buildSnapshotForScope(ctx, tx, revision, MaxPublicationSites, MaxEdgeRulesPerScope, scopeID)
		if err != nil {
			return UsageCounts{}, errors.Join(errors.New("build error page scope snapshot for usage"), err)
		}
		canonical, err := json.Marshal(snapshot)
		if err != nil {
			return UsageCounts{}, err
		}
		result.PublicationSites = max(result.PublicationSites, int64(len(snapshot.Sites)))
		result.PublicationBytes = max(result.PublicationBytes, int64(len(canonical)))
	}
	return result, nil
}
