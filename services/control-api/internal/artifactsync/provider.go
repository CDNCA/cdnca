package artifactsync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	"github.com/cdnca/cdnca/libs/entitlement/pluginprovider"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Provider plugins (PA-22, ADR 0007 §8.2): the license service lists
// plugin_provider/<plugin id> (a cdnca.plugin-provider/v1 declaration, no
// code) for every DNS / SMS / ICP provider plugin this installation is
// authorized for. Once the plugin installation is enabled on this control
// plane the declaration is materialized in plugin_providers with a pending
// installation contract; internal/pluginproviders runs the contract and an
// administrator enables the provider only after it passed. New declaration
// bytes (an upgrade) reset the contract and keep the provider unusable
// until the new version passed. An entry no longer served or an
// installation no longer enabled here is withdrawn at the next sync.

// verifyPluginProvider checks downloaded declaration bytes against the entry.
func verifyPluginProvider(entry artifactcatalog.Entry, content []byte) (pluginprovider.Declaration, error) {
	if err := artifactcatalog.VerifyContent(entry, content); err != nil {
		return pluginprovider.Declaration{}, err
	}
	declaration, err := pluginprovider.Parse(content)
	if err != nil || declaration.PluginID != strings.TrimPrefix(entry.ArtifactID, entry.Kind+"/") ||
		declaration.Version != entry.Version {
		return pluginprovider.Declaration{}, artifactcatalog.ErrContentMismatch
	}
	return declaration, nil
}

type pluginProviderCandidate struct {
	entry          artifactcatalog.Entry
	status         string
	revision       int64
	sha256         string
	content        []byte
	tenantScope    *uuid.UUID
	authorization  *uuid.UUID
	providerStatus *string
	providerSHA    *string
}

// materializePluginProviders runs in the Materialize transaction.
func (store *Store) materializePluginProviders(ctx context.Context, tx pgx.Tx, now time.Time) (int, error) {
	target, err := VerifiedCatalogInstallation(ctx, tx)
	if err != nil {
		return 0, err
	}
	rows, err := tx.Query(ctx, `SELECT `+entryColumns+`,entry.status,local.current_revision,local.current_sha256,object.content,
		head.tenant_scope_id,head.authorization_id,provider.status,provider.declaration_sha256
		FROM local_artifacts local
		JOIN artifact_catalog_entries entry ON entry.artifact_id=local.artifact_id
		JOIN artifact_objects object ON object.sha256=local.current_sha256
		LEFT JOIN plugin_providers provider ON provider.plugin_id=substr(entry.artifact_id, strpos(entry.artifact_id,'/')+1)
		-- Only a tenant head of the installation the current verified catalog was signed for ($1): a kept head of an
		-- earlier installation (migration/restore) does not enable it here. No target ($1 NULL) matches none.
		LEFT JOIN LATERAL (SELECT head.tenant_scope_id,head.authorization_id FROM plugin_installation_heads head
		 WHERE head.plugin_id=substr(entry.artifact_id, strpos(entry.artifact_id,'/')+1) AND head.status='enabled' AND
		       head.installation_id=$1::uuid AND head.resource_scope='tenant' AND head.entrypoint_type='external_https'
		 ORDER BY head.updated_at DESC, head.authorization_id LIMIT 1) head ON true
		WHERE entry.kind='plugin_provider' AND local.current_revision IS NOT NULL
		ORDER BY local.artifact_id FOR UPDATE OF local`, target)
	if err != nil {
		return 0, err
	}
	candidates, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (pluginProviderCandidate, error) {
		var item pluginProviderCandidate
		entry, err := scanEntry(row, &item.status, &item.revision, &item.sha256, &item.content, &item.tenantScope,
			&item.authorization, &item.providerStatus, &item.providerSHA)
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
		active := item.providerStatus != nil && *item.providerStatus == "active"
		if item.status != "active" || item.tenantScope == nil {
			if active {
				if err := store.withdrawPluginProvider(ctx, tx, downloaded, pluginID, now); err != nil {
					return changed, err
				}
				changed++
			}
			continue
		}
		declaration, err := verifyPluginProvider(downloaded, item.content)
		if err != nil {
			return changed, fmt.Errorf("stored artifact %s: %w", downloaded.ArtifactID, err)
		}
		sum := sha256.Sum256(item.content)
		digest := hex.EncodeToString(sum[:])
		if active && item.providerSHA != nil && *item.providerSHA == digest {
			continue
		}
		from := "absent"
		if item.providerStatus != nil {
			from = *item.providerStatus
		}
		// New bytes: the contract runs again; the administrator's choice is
		// kept but the provider is unusable until the new version passed.
		if _, err := tx.Exec(ctx, `INSERT INTO plugin_providers(plugin_id,version,base_url,kinds,declaration,declaration_sha256,
			status,tenant_scope_id,authorization_id,contract_status,materialized_at,updated_at)
			VALUES($1,$2,$3,$4,$5,$6,'active',$7,$8,'pending',$9,$9)
			ON CONFLICT (plugin_id) DO UPDATE SET version=EXCLUDED.version,base_url=EXCLUDED.base_url,kinds=EXCLUDED.kinds,
			declaration=EXCLUDED.declaration,declaration_sha256=EXCLUDED.declaration_sha256,status='active',
			tenant_scope_id=EXCLUDED.tenant_scope_id,authorization_id=EXCLUDED.authorization_id,
			contract_status=CASE WHEN plugin_providers.declaration_sha256=EXCLUDED.declaration_sha256
			 THEN plugin_providers.contract_status ELSE 'pending' END,
			updated_at=EXCLUDED.updated_at`,
			pluginID, declaration.Version, declaration.BaseURL, declaration.Kinds, item.content, digest, *item.tenantScope,
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
		if err := store.systemAudit(ctx, tx, "plugin.provider.materialize", "plugin_provider", pluginID, "success",
			map[string]any{"plugin_id": pluginID, "version": declaration.Version, "base_url": declaration.BaseURL,
				"kinds": declaration.Kinds, "changes": map[string]any{
					"status":          map[string]any{"from": from, "to": "active"},
					"contract_status": map[string]any{"to": "pending"}}}); err != nil {
			return changed, err
		}
		changed++
	}
	return changed, nil
}

func (store *Store) withdrawPluginProvider(ctx context.Context, tx pgx.Tx, entry artifactcatalog.Entry, pluginID string,
	now time.Time) error {
	if _, err := tx.Exec(ctx, `UPDATE plugin_providers SET status='withdrawn',updated_at=$2 WHERE plugin_id=$1`,
		pluginID, now); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE market_data_pack_sources SET status='withdrawn',updated_at=$2 WHERE artifact_id=$1`,
		entry.ArtifactID, now); err != nil {
		return err
	}
	return store.systemAudit(ctx, tx, "plugin.provider.withdraw", "plugin_provider", pluginID, "success",
		map[string]any{"plugin_id": pluginID, "version": entry.Version,
			"changes": map[string]any{"status": map[string]any{"from": "active", "to": "withdrawn"}}})
}
