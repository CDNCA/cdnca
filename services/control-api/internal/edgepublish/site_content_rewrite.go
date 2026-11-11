package edgepublish

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/cdnca/cdnca/libs/edgeconfig/contentrewrite"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// enabledContentRewriteSQL: the site has a rule the node gets (Compile keeps
// the enabled ones), the same test in loading and in the capability gate.
const enabledContentRewriteSQL = `content_rewrite IS NOT NULL AND jsonb_path_exists(content_rewrite, '$.rules[*] ? (@.enabled == true)')`

// loadSiteContentRewrite fills facts[site].ContentRewrite
// (migration 655) for every live site of the scope with an enabled rule;
// convertSiteObjectV2 compiles it against the site's domains.
func loadSiteContentRewrite(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, facts map[string]siteObjectV2Facts) error {
	rows, err := tx.Query(ctx, `SELECT id::text,content_rewrite FROM sites
		WHERE scope_id=$1 AND deleted_at IS NULL AND `+enabledContentRewriteSQL, scopeID)
	if err != nil {
		return fmt.Errorf("%w: load site content rewrite", ErrPersistence)
	}
	defer rows.Close()
	for rows.Next() {
		var siteID string
		var raw []byte
		if err := rows.Scan(&siteID, &raw); err != nil {
			return fmt.Errorf("%w: scan site content rewrite", ErrPersistence)
		}
		var stored contentrewrite.Settings
		if err := json.Unmarshal(raw, &stored); err != nil {
			return fmt.Errorf("%w: decode site content rewrite", ErrPersistence)
		}
		settings, err := contentrewrite.Normalize(stored)
		if err != nil {
			return fmt.Errorf("%w: site content rewrite: %v", ErrPersistence, err)
		}
		if value, ok := facts[siteID]; ok {
			value.ContentRewrite = &settings
			facts[siteID] = value
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("%w: iterate site content rewrite", ErrPersistence)
	}
	return nil
}

// requireContentRewriteCapability: a release whose sites
// include one with an enabled rule requires SITE_CONTENT_REWRITE v1 (both
// the compiled document and the system overlay call it).
func requireContentRewriteCapability(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, document *siteRuntimeV2Document) error {
	ids := make([]string, len(document.Sites))
	for index, site := range document.Sites {
		ids[index] = site.ID
	}
	var required bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM sites WHERE scope_id=$1 AND id::text=ANY($2::text[])
		AND deleted_at IS NULL AND `+enabledContentRewriteSQL+`)`, scopeID, ids).Scan(&required); err != nil {
		return fmt.Errorf("%w: load site content rewrite", ErrPersistence)
	}
	if required {
		requireSiteRuntimeV2Capability(document, siteobject.ContentRewriteCapability, siteobject.ContentRewriteAPIVersion)
	}
	return nil
}

// withoutContentRewriteCapability drops the rules unless the release root
// requires SITE_CONTENT_REWRITE (an older node would refuse the field).
func withoutContentRewriteCapability(source siteObjectsV2Source, facts map[string]siteObjectV2Facts) {
	for _, capability := range source.Capabilities {
		if capability.Name == siteobject.ContentRewriteCapability && capability.APIVersion >= siteobject.ContentRewriteAPIVersion {
			return
		}
	}
	for siteID, value := range facts {
		if value.ContentRewrite != nil {
			value.ContentRewrite = nil
			facts[siteID] = value
		}
	}
}
