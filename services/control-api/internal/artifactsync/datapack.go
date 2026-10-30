package artifactsync

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/cdnca/cdnca/libs/themepack"
	"github.com/cdnca/cdnca/services/control-api/internal/rulepackcontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/theme"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Market data packages (PA-18, ADR 0007 §8.1): the license service lists
// market_rule_pack/<plugin id> and market_theme/<plugin id> for every plugin this
// installation is authorized for. They are resident (downloaded right away)
// and, once the plugin installation is confirmed on this control plane
// (plugin_installation_heads enabled), materialized as downloaded local
// artifacts: a developer-layer rule pack in rulepackcontrol, a market theme
// in the theme download list. Nothing is enabled or activated by this; the
// administrators enable / mount / activate them like any other pack or theme.
// An entry no longer served (authorization disabled, uninstalled, ended) or a
// local installation no longer enabled is withdrawn: the bytes stay, the pack
// is not listed, enabled or mounted any more and the theme cannot be
// activated (ADR 0007 §9).

// verifyDataPack checks downloaded data package bytes against the entry.
func verifyDataPack(entry artifactcatalog.Entry, content []byte) (string, error) {
	if err := artifactcatalog.VerifyContent(entry, content); err != nil {
		return "", err
	}
	pluginID := strings.TrimPrefix(entry.ArtifactID, entry.Kind+"/")
	switch entry.Kind {
	case artifactcatalog.KindMarketRulePack:
		compiled, err := rulepack.Load(content, entry.SHA256)
		if err != nil {
			return "", errors.Join(artifactcatalog.ErrContentMismatch, err)
		}
		if _, ok := rulepack.DeveloperPackPublisher(compiled.Pack.PackID); !ok || compiled.Pack.Layer != rulepack.LayerDeveloper ||
			compiled.Pack.Version != entry.Version || !strings.HasPrefix(pluginID, publisherOf(compiled.Pack.PackID)+".") {
			return "", artifactcatalog.ErrContentMismatch
		}
		return compiled.Pack.PackID, nil
	case artifactcatalog.KindMarketTheme:
		// Community edition: no website (官网) themes; a market theme is a
		// console theme package (a cdnca.site-theme package fails to render).
		rendered, err := themepack.Render(content)
		if err != nil || rendered.Package.ID != themepack.MarketThemeID(pluginID) || rendered.Package.Version != entry.Version {
			return "", artifactcatalog.ErrContentMismatch
		}
		return rendered.Package.ID, nil
	}
	return "", ErrUnsupported
}

// publisherOf is the market publisher of a developer pack; a plugin id
// always starts with its publisher's namespace.
func publisherOf(packID string) string {
	publisher, _ := rulepack.DeveloperPackPublisher(packID)
	return publisher
}

type dataPackCandidate struct {
	entry      artifactcatalog.Entry
	status     string
	revision   int64
	sha256     string
	content    []byte
	installer  *uuid.UUID
	scope      *uuid.UUID
	sourceSHA  *string
	sourceStat *string
}

// RowQuerier is a pool or a transaction.
type RowQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// VerifiedCatalogInstallation is the installation the last applied (verified)
// catalog delivery was signed for, nil when no delivery was applied. ApplyCatalog
// only stores a delivery whose envelope names this control plane's installation.
// Installation heads of any other installation (kept after a migration or restore)
// do not count as installed or enabled here.
func VerifiedCatalogInstallation(ctx context.Context, q RowQuerier) (*uuid.UUID, error) {
	var document []byte
	err := q.QueryRow(ctx, `SELECT signed_document FROM artifact_catalog_state`).Scan(&document)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return catalogInstallation(document)
}

// catalogInstallation reads the installation target of a stored signed delivery (nil document: none).
func catalogInstallation(document []byte) (*uuid.UUID, error) {
	if document == nil {
		return nil, nil
	}
	signed, err := artifactcatalog.Decode(document)
	if err != nil {
		return nil, fmt.Errorf("stored artifact catalog: %w", err)
	}
	target, err := uuid.Parse(signed.Envelope.InstallationID)
	if err != nil {
		return nil, fmt.Errorf("stored artifact catalog installation: %w", ErrInvalidInput)
	}
	return &target, nil
}

// materializeDataPacks runs in the Materialize transaction.
func (store *Store) materializeDataPacks(ctx context.Context, tx pgx.Tx, now time.Time) (int, error) {
	target, err := VerifiedCatalogInstallation(ctx, tx)
	if err != nil {
		return 0, err
	}
	rows, err := tx.Query(ctx, `SELECT `+entryColumns+`,entry.status,local.current_revision,local.current_sha256,object.content,
		confirmed.actor_user_id,confirmed.tenant_scope_id,source.sha256,source.status
		FROM local_artifacts local
		JOIN artifact_catalog_entries entry ON entry.artifact_id=local.artifact_id
		JOIN artifact_objects object ON object.sha256=local.current_sha256
		LEFT JOIN market_data_pack_sources source ON source.artifact_id=local.artifact_id
		-- The platform administrator who confirmed (or last upgraded) this instance-wide plugin here: only a
		-- platform-scope head (resource scope signed by the license service) of the served version, and the
		-- receipt that installed or upgraded to that head's verification. A tenant's receipt never approves it.
		-- The head must belong to the installation the current verified catalog was signed for ($1): after a
		-- migration or restore, a kept confirmation of an earlier installation does not approve this one's
		-- resources (it stays as it is; the current administrator confirms again). No target ($1 NULL) matches none.
		LEFT JOIN LATERAL (SELECT receipt.actor_user_id,receipt.tenant_scope_id FROM plugin_installation_heads head
		 JOIN plugin_installation_receipts receipt ON receipt.tenant_scope_id=head.tenant_scope_id AND
		      receipt.authorization_id=head.authorization_id AND receipt.result IN ('installed','upgrade_applied') AND
		      receipt.response_snapshot->>'verification_id'=head.verification_id::text
		 WHERE head.plugin_id=substr(entry.artifact_id, strpos(entry.artifact_id,'/')+1) AND head.status='enabled' AND
		       head.installation_id=$1::uuid AND head.resource_scope='platform' AND head.plugin_version=entry.version AND
		       head.entrypoint_type=CASE entry.kind WHEN 'market_theme' THEN 'theme' ELSE 'rule_pack' END
		 ORDER BY receipt.occurred_at DESC, receipt.id DESC LIMIT 1) confirmed ON true
		WHERE entry.kind IN ('market_rule_pack','market_theme') AND local.current_revision IS NOT NULL
		ORDER BY local.artifact_id FOR UPDATE OF local`, target)
	if err != nil {
		return 0, err
	}
	candidates, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (dataPackCandidate, error) {
		var item dataPackCandidate
		entry, err := scanEntry(row, &item.status, &item.revision, &item.sha256, &item.content, &item.installer,
			&item.scope, &item.sourceSHA, &item.sourceStat)
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
		usable := item.status == "active" && item.installer != nil
		if !usable {
			if item.sourceStat != nil && *item.sourceStat == "active" {
				if _, err := tx.Exec(ctx, `UPDATE market_data_pack_sources SET status='withdrawn',updated_at=$2
					WHERE artifact_id=$1`, downloaded.ArtifactID, now); err != nil {
					return changed, err
				}
				if err := store.systemAudit(ctx, tx, "plugin.artifact.withdraw", "artifact", downloaded.ArtifactID, "success",
					map[string]any{"kind": downloaded.Kind, "plugin_id": pluginID, "version": downloaded.Version,
						"changes": map[string]any{"status": map[string]any{"from": "active", "to": "withdrawn"}}}); err != nil {
					return changed, err
				}
				changed++
			}
			continue
		}
		if item.sourceSHA != nil && *item.sourceSHA == item.sha256 && *item.sourceStat == "active" {
			continue
		}
		name, err := verifyDataPack(downloaded, item.content)
		if err != nil {
			return changed, fmt.Errorf("stored artifact %s: %w", downloaded.ArtifactID, err)
		}
		switch downloaded.Kind {
		case artifactcatalog.KindMarketRulePack:
			compiled, _ := rulepack.Load(item.content, item.sha256)
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM rule_pack_artifacts WHERE pack_id=$1 AND version=$2)`,
				compiled.Pack.PackID, compiled.Pack.Version).Scan(&exists); err != nil {
				return changed, err
			}
			if !exists {
				if _, err := rulepackcontrol.AddVersion(ctx, tx, now, rulepackcontrol.NewVersion{Compiled: compiled,
					Source: rulepackcontrol.SourceMarket, CreatedBy: *item.installer, AuditScopeID: *item.scope, Audit: map[string]any{
						"artifact_id": downloaded.ArtifactID, "plugin_id": pluginID, "revision": downloaded.Revision}}); err != nil {
					return changed, fmt.Errorf("add market rule pack %s: %w", compiled.Pack.PackID, err)
				}
			}
		case artifactcatalog.KindMarketTheme:
			rendered, added, err := theme.StoreMarketPackageTx(ctx, tx, item.content, pluginID, *item.installer, now)
			if err != nil {
				return changed, fmt.Errorf("store market theme %s: %w", pluginID, err)
			}
			if added {
				if err := store.systemAudit(ctx, tx, theme.ActionDownload, "theme_package", rendered.PackageSHA256, "success",
					map[string]any{"theme_id": rendered.Package.ID, "version": rendered.Package.Version, "source": "market",
						"plugin_id": pluginID, "artifact_id": downloaded.ArtifactID,
						"changes": map[string]any{"downloaded": map[string]any{"from": false, "to": true}}}); err != nil {
					return changed, err
				}
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO market_data_pack_sources(artifact_id,kind,plugin_id,version,revision,sha256,
			local_name,status,materialized_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,'active',$8,$8)
			ON CONFLICT (artifact_id) DO UPDATE SET version=EXCLUDED.version,revision=EXCLUDED.revision,sha256=EXCLUDED.sha256,
			local_name=EXCLUDED.local_name,status='active',updated_at=EXCLUDED.updated_at`, downloaded.ArtifactID, downloaded.Kind,
			pluginID, downloaded.Version, item.revision, item.sha256, name, now); err != nil {
			return changed, err
		}
		changed++
	}
	return changed, nil
}
