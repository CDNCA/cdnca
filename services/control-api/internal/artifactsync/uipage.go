package artifactsync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	"github.com/cdnca/cdnca/libs/entitlement/pluginui"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ui_page plugin pages (PA-19, ADR 0007 §8.3): the license service lists
// plugin_ui/<plugin id> (a cdnca.plugin-ui/v1 declaration, no code) for
// every ui_page plugin this installation is authorized for. Once the plugin
// installation is enabled on this control plane the declaration is
// materialized in plugin_ui_pages (active): its origin enters the web CSP
// frame-src and its pages the menu. An entry no longer served or an
// installation no longer enabled here is withdrawn at the next sync.

// verifyPluginUI checks downloaded declaration bytes against the entry.
func verifyPluginUI(entry artifactcatalog.Entry, content []byte) (pluginui.Declaration, error) {
	if err := artifactcatalog.VerifyContent(entry, content); err != nil {
		return pluginui.Declaration{}, err
	}
	declaration, err := pluginui.Parse(content)
	if err != nil || declaration.PluginID != strings.TrimPrefix(entry.ArtifactID, entry.Kind+"/") ||
		declaration.Version != entry.Version {
		return pluginui.Declaration{}, artifactcatalog.ErrContentMismatch
	}
	return declaration, nil
}

type pluginUICandidate struct {
	entry         artifactcatalog.Entry
	status        string
	revision      int64
	sha256        string
	content       []byte
	tenantScope   *uuid.UUID
	authorization *uuid.UUID
	pageStatus    *string
	pageSHA       *string
}

// materializePluginUIPages runs in the Materialize transaction.
func (store *Store) materializePluginUIPages(ctx context.Context, tx pgx.Tx, now time.Time) (int, error) {
	target, err := VerifiedCatalogInstallation(ctx, tx)
	if err != nil {
		return 0, err
	}
	rows, err := tx.Query(ctx, `SELECT `+entryColumns+`,entry.status,local.current_revision,local.current_sha256,object.content,
		head.tenant_scope_id,head.authorization_id,page.status,page.declaration_sha256
		FROM local_artifacts local
		JOIN artifact_catalog_entries entry ON entry.artifact_id=local.artifact_id
		JOIN artifact_objects object ON object.sha256=local.current_sha256
		LEFT JOIN plugin_ui_pages page ON page.plugin_id=substr(entry.artifact_id, strpos(entry.artifact_id,'/')+1)
		-- Only a tenant head of the installation the current verified catalog was signed for ($1): a kept head of an
		-- earlier installation (migration/restore) does not enable it here. No target ($1 NULL) matches none.
		LEFT JOIN LATERAL (SELECT head.tenant_scope_id,head.authorization_id FROM plugin_installation_heads head
		 WHERE head.plugin_id=substr(entry.artifact_id, strpos(entry.artifact_id,'/')+1) AND head.status='enabled' AND
		       head.installation_id=$1::uuid AND head.resource_scope='tenant' AND head.entrypoint_type='ui_page'
		 ORDER BY head.updated_at DESC, head.authorization_id LIMIT 1) head ON true
		WHERE entry.kind='plugin_ui' AND local.current_revision IS NOT NULL
		ORDER BY local.artifact_id FOR UPDATE OF local`, target)
	if err != nil {
		return 0, err
	}
	candidates, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (pluginUICandidate, error) {
		var item pluginUICandidate
		entry, err := scanEntry(row, &item.status, &item.revision, &item.sha256, &item.content, &item.tenantScope,
			&item.authorization, &item.pageStatus, &item.pageSHA)
		item.entry = entry
		return item, err
	})
	if err != nil {
		return 0, err
	}
	changed := 0
	for _, item := range candidates {
		downloaded := item.entry
		downloaded.Revision, downloaded.SHA256, downloaded.Size = uint64(item.revision), item.sha256, int64(len(item.content))
		pluginID := strings.TrimPrefix(downloaded.ArtifactID, downloaded.Kind+"/")
		if item.status != "active" || item.tenantScope == nil {
			if item.pageStatus != nil && *item.pageStatus == "active" {
				if err := store.withdrawPluginUI(ctx, tx, downloaded, pluginID, now); err != nil {
					return changed, err
				}
				changed++
			}
			continue
		}
		declaration, err := verifyPluginUI(downloaded, item.content)
		if err != nil {
			return changed, fmt.Errorf("stored artifact %s: %w", downloaded.ArtifactID, err)
		}
		sum := sha256.Sum256(item.content)
		digest := hex.EncodeToString(sum[:])
		if item.pageStatus != nil && *item.pageStatus == "active" && item.pageSHA != nil && *item.pageSHA == digest {
			continue
		}
		// Another enabled plugin already holds this origin: keep it out.
		var taken bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM plugin_ui_pages WHERE origin=$1 AND status='active' AND plugin_id<>$2)`,
			declaration.Origin, pluginID).Scan(&taken); err != nil {
			return changed, err
		}
		if taken {
			if err := store.systemAudit(ctx, tx, "plugin.ui_page.reject", "plugin_ui_page", pluginID, "failure",
				map[string]any{"plugin_id": pluginID, "version": declaration.Version, "origin": declaration.Origin,
					"reason": "origin_in_use"}); err != nil {
				return changed, err
			}
			continue
		}
		from := "absent"
		if item.pageStatus != nil {
			from = *item.pageStatus
		}
		if _, err := tx.Exec(ctx, `INSERT INTO plugin_ui_pages(plugin_id,version,origin,api_base_url,declaration,declaration_sha256,
			status,tenant_scope_id,authorization_id,materialized_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,'active',$7,$8,$9,$9)
			ON CONFLICT (plugin_id) DO UPDATE SET version=EXCLUDED.version,origin=EXCLUDED.origin,api_base_url=EXCLUDED.api_base_url,
			declaration=EXCLUDED.declaration,declaration_sha256=EXCLUDED.declaration_sha256,status='active',
			tenant_scope_id=EXCLUDED.tenant_scope_id,authorization_id=EXCLUDED.authorization_id,updated_at=EXCLUDED.updated_at`,
			pluginID, declaration.Version, declaration.Origin, declaration.APIBaseURL, item.content, digest, *item.tenantScope,
			*item.authorization, now); err != nil {
			return changed, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO market_data_pack_sources(artifact_id,kind,plugin_id,version,revision,sha256,
			local_name,status,materialized_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$3,'active',$7,$7)
			ON CONFLICT (artifact_id) DO UPDATE SET version=EXCLUDED.version,revision=EXCLUDED.revision,sha256=EXCLUDED.sha256,
			status='active',updated_at=EXCLUDED.updated_at`, downloaded.ArtifactID, downloaded.Kind, pluginID,
			downloaded.Version, item.revision, item.sha256, now); err != nil {
			return changed, err
		}
		pages := make([]string, 0, len(declaration.Pages))
		for _, page := range declaration.Pages {
			pages = append(pages, page.ID)
		}
		if err := store.systemAudit(ctx, tx, "plugin.ui_page.enable", "plugin_ui_page", pluginID, "success",
			map[string]any{"plugin_id": pluginID, "version": declaration.Version, "origin": declaration.Origin,
				"api_base_url": declaration.APIBaseURL, "pages": pages,
				"changes": map[string]any{"status": map[string]any{"from": from, "to": "active"}}}); err != nil {
			return changed, err
		}
		changed++
	}
	return changed, nil
}

func (store *Store) withdrawPluginUI(ctx context.Context, tx pgx.Tx, entry artifactcatalog.Entry, pluginID string,
	now time.Time) error {
	var origin string
	if err := tx.QueryRow(ctx, `UPDATE plugin_ui_pages SET status='withdrawn',updated_at=$2 WHERE plugin_id=$1 RETURNING origin`,
		pluginID, now).Scan(&origin); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE market_data_pack_sources SET status='withdrawn',updated_at=$2 WHERE artifact_id=$1`,
		entry.ArtifactID, now); err != nil {
		return err
	}
	return store.systemAudit(ctx, tx, "plugin.ui_page.withdraw", "plugin_ui_page", pluginID, "success",
		map[string]any{"plugin_id": pluginID, "version": entry.Version, "origin": origin,
			"changes": map[string]any{"status": map[string]any{"from": "active", "to": "withdrawn"}}})
}
