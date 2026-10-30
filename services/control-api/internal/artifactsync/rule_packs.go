package artifactsync

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/cdnca/cdnca/services/control-api/internal/rulepackcontrol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Rule pack artifacts (ADR 0007 §6, PA-14).
//
//   - rule_pack/<pack> entries are rule packs: encryption none carries the
//     canonical cdnca.rule-pack/v1 document; install_wrapped the sealed form
//     (cdnca.rule-pack-sealed/v1) with the content key (CEK) wrapped to this
//     installation's X25519 encryption key (entry wrapped_key).
//   - The control plane never decrypts a sealed pack. A download is accepted
//     only if its public manifest checks and the wrapped key opens with the
//     installation key (otherwise rule.pack.decrypt_reject); the CEK is used
//     in memory only to wrap it again for each node (WrapNodeKeys).
//   - Materialization makes each downloaded pack a catalog version in
//     rule_pack_artifacts (sealed bytes for an encrypted pack): downloading
//     still enables nothing.

// CodeDecryptRejected: a sealed pack's wrapped key does not open with this
// installation's encryption key (or its manifest is invalid).
const CodeDecryptRejected = "rule_pack_decrypt_rejected"

// ErrNoEncryptionKey: an encrypted entry and no installation encryption key.
var ErrNoEncryptionKey = errors.New("installation encryption key is not configured")

// verifyRulePack checks a downloaded rule pack against its entry: a plain
// pack must load (canonical, digest); a sealed one must have a valid
// manifest naming the entry's pack and version, and its wrapped key must
// open with encryptionKey. It returns the compiled pack (manifest only when
// sealed).
func verifyRulePack(entry artifactcatalog.Entry, content, encryptionKey []byte) (*rulepack.CompiledPack, error) {
	if err := artifactcatalog.VerifyContent(entry, content); err != nil {
		return nil, err
	}
	var compiled *rulepack.CompiledPack
	var err error
	switch entry.Encryption {
	case artifactcatalog.EncryptionNone:
		if rulepack.IsSealed(content) {
			return nil, fmt.Errorf("%w: sealed pack listed as unencrypted", rulepack.ErrSealRejected)
		}
		compiled, err = rulepack.Load(content, entry.SHA256)
	case artifactcatalog.EncryptionInstallWrapped:
		compiled, err = rulepack.OpenManifest(content, entry.SHA256)
	default:
		return nil, ErrUnsupported
	}
	if err != nil {
		return nil, err
	}
	pack := compiled.Pack
	if artifactcatalog.RulePackArtifactID(pack.PackID) != entry.ArtifactID || pack.Version != entry.Version ||
		pack.Layer == rulepack.LayerUser {
		return nil, fmt.Errorf("%w: pack %s %s does not match entry %s %s", rulepack.ErrInvalidPack, pack.PackID,
			pack.Version, entry.ArtifactID, entry.Version)
	}
	if entry.Encryption == artifactcatalog.EncryptionInstallWrapped {
		cek, err := unwrapInstallationKey(encryptionKey, entry.WrappedKey, pack.PackID, pack.Version, entry.SHA256)
		if err != nil {
			return nil, err
		}
		clear(cek)
	}
	return compiled, nil
}

func unwrapInstallationKey(encryptionKey []byte, wrapped, packID, version, sealedSHA256 string) ([]byte, error) {
	if len(encryptionKey) == 0 {
		return nil, ErrNoEncryptionKey
	}
	public, err := rulepack.X25519PublicKey(encryptionKey)
	if err != nil {
		return nil, err
	}
	return rulepack.UnwrapKey(encryptionKey, wrapped, rulepack.WrapContext{Purpose: rulepack.WrapPurposeInstallation,
		RecipientKeyID: rulepack.X25519KeyID(public), PackID: packID, Version: version, SealedSHA256: sealedSHA256})
}

// RejectDecrypt records a sealed pack the installation key does not open
// (rule.pack.decrypt_reject); like a content mismatch the revision is not
// fetched again within rejectedRetryAfter and the previous download stays.
func (store *Store) RejectDecrypt(ctx context.Context, entry artifactcatalog.Entry, cause error) error {
	now := store.now().UTC()
	revision := int64(entry.Revision)
	reason := "key_rejected"
	switch {
	case errors.Is(cause, ErrNoEncryptionKey):
		reason = "no_encryption_key"
	case errors.Is(cause, rulepack.ErrSealRejected), errors.Is(cause, rulepack.ErrInvalidPack):
		reason = "manifest_invalid"
	}
	return pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO local_artifacts(artifact_id,last_attempt_at,last_error_code,rejected_revision,updated_at)
			VALUES($1,$2,$3,$4,$2) ON CONFLICT (artifact_id) DO UPDATE SET last_attempt_at=EXCLUDED.last_attempt_at,
			last_error_code=EXCLUDED.last_error_code,rejected_revision=EXCLUDED.rejected_revision,updated_at=EXCLUDED.updated_at`,
			entry.ArtifactID, now, CodeDecryptRejected, revision); err != nil {
			return err
		}
		return store.systemAudit(ctx, tx, "rule.pack.decrypt_reject", "rule_pack", entry.ArtifactID, "failure",
			map[string]any{"reason": reason, "version": entry.Version, "revision": entry.Revision, "sha256": entry.SHA256})
	})
}

// materializeRulePacks makes every usable downloaded rule pack a catalog
// version (rule_pack_artifacts source catalog; system packs become current
// by themselves, others when first). A version already there is left alone;
// nothing is removed (sites keep their references).
//
// defaultOn reports that a default-on official pack was materialized (a new
// version, or migration 544 cleared its mark): recomputeDefaultOnMounts
// then reads every site.
func (store *Store) materializeRulePacks(ctx context.Context, tx pgx.Tx, features map[string]bool) (changed int, defaultOn bool, err error) {
	rows, err := tx.Query(ctx, `SELECT `+entryColumns+`,entry.status,local.current_revision,local.current_sha256,
		local.current_version,local.current_wrapped_key,local.materialized_sha256,object.content
		FROM local_artifacts local
		JOIN artifact_catalog_entries entry ON entry.artifact_id=local.artifact_id
		JOIN artifact_objects object ON object.sha256=local.current_sha256
		WHERE entry.kind='rule_pack' AND local.current_revision IS NOT NULL
		  AND local.materialized_sha256 IS DISTINCT FROM local.current_sha256
		ORDER BY local.artifact_id FOR UPDATE OF local`)
	if err != nil {
		return 0, false, err
	}
	type candidate struct {
		entry        artifactcatalog.Entry
		status       string
		revision     int64
		materialized *string
		content      []byte
	}
	candidates, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (candidate, error) {
		var item candidate
		var sha, version, wrapped string
		entry, err := scanEntry(row, &item.status, &item.revision, &sha, &version, &wrapped, &item.materialized, &item.content)
		// The downloaded revision, not necessarily the listed one.
		entry.Revision, entry.SHA256, entry.Version, entry.WrappedKey = uint64(item.revision), sha, version, wrapped
		entry.Size = int64(len(item.content))
		item.entry = entry
		return item, err
	})
	if err != nil {
		return 0, false, err
	}
	now := store.now().UTC()
	for _, item := range candidates {
		if item.status != "active" || !permitted(features, item.entry.RequiresFeature) {
			continue
		}
		sealed := item.entry.WrappedKey != ""
		var compiled *rulepack.CompiledPack
		if sealed {
			compiled, err = rulepack.OpenManifest(item.content, item.entry.SHA256)
		} else {
			compiled, err = rulepack.Load(item.content, item.entry.SHA256)
		}
		if err != nil {
			return 0, false, fmt.Errorf("stored rule pack %s: %w", item.entry.ArtifactID, err)
		}
		pack := compiled.Pack
		policy := "manual"
		if pack.Layer == rulepack.LayerSystem {
			policy = "auto"
		}
		created, err := tx.Exec(ctx, `INSERT INTO rule_packs(pack_id,layer,owner_scope_id,current_version,update_policy,
			created_by_user_id,updated_by_user_id,created_at,updated_at) VALUES($1,$2,NULL,NULL,$3,NULL,NULL,$4,$4)
			ON CONFLICT (pack_id) DO NOTHING`, pack.PackID, pack.Layer, policy, now)
		if err != nil {
			return 0, false, err
		}
		official := rulepackcontrol.DefaultOn(pack.Layer, item.entry.RequiresFeature)
		if created.RowsAffected() == 1 && official {
			if err := store.openOfficialPack(ctx, tx, pack.PackID, now); err != nil {
				return 0, false, err
			}
		}
		// Every materialization of a default-on pack (a new version, or the
		// re-materialization migration 544 asks for) recomputes all sites.
		if official {
			defaultOn = true
		}
		var current *string
		var updatePolicy string
		if err := tx.QueryRow(ctx, `SELECT current_version,update_policy FROM rule_packs WHERE pack_id=$1 FOR UPDATE`,
			pack.PackID).Scan(&current, &updatePolicy); err != nil {
			return 0, false, err
		}
		inserted, err := tx.Exec(ctx, `INSERT INTO rule_pack_artifacts(pack_id,version,engine,engine_min_version,name,sha256,
			size_bytes,content,source,state,downloaded_at,created_by_user_id,created_at,sealed,wrapped_key)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,'catalog','downloaded',$9,NULL,$9,$10,$11)
			ON CONFLICT (pack_id,version) DO NOTHING`, pack.PackID, pack.Version, pack.Engine, pack.EngineMinVersion, pack.Name,
			item.entry.SHA256, len(item.content), item.content, now, sealed, item.entry.WrappedKey)
		if err != nil {
			return 0, false, err
		}
		makeCurrent := inserted.RowsAffected() == 1 && (current == nil || updatePolicy == "auto")
		if makeCurrent {
			if _, err := tx.Exec(ctx, `UPDATE rule_packs SET current_version=$2,updated_at=$3 WHERE pack_id=$1`,
				pack.PackID, pack.Version, now); err != nil {
				return 0, false, err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE local_artifacts SET materialized_sha256=$2,updated_at=$3 WHERE artifact_id=$1`,
			item.entry.ArtifactID, item.entry.SHA256, now); err != nil {
			return 0, false, err
		}
		if inserted.RowsAffected() == 0 {
			continue
		}
		changed++
		changes := map[string]any{"versions": map[string]any{"added": pack.Version}}
		if makeCurrent {
			previous := ""
			if current != nil {
				previous = *current
			}
			changes["current_version"] = map[string]any{"from": previous, "to": pack.Version}
		}
		if err := store.systemAudit(ctx, tx, "rule.pack.version.create", "rule_pack", pack.PackID+"@"+pack.Version, "success",
			map[string]any{"pack_id": pack.PackID, "version": pack.Version, "source": "catalog", "sha256": item.entry.SHA256,
				"engine": pack.Engine, "encrypted": sealed, "artifact_id": item.entry.ArtifactID, "changes": changes}); err != nil {
			return 0, false, err
		}
	}
	return changed, defaultOn, nil
}

// openOfficialPack enables an official free system pack (official rule
// seeds, license migration 097; rulepackcontrol.DefaultOn) for every site
// and lets tenants and their sites switch it off or change its action
// parameter: a system pack without a platform row is locked to the
// platform. The row (state enabled, allow_lower) is the control plane's (no
// user, migrations 418/454) and is written once, when the pack first
// arrives; an administrator's row is never touched (it can disable the pack
// for everyone). Before migration 544 only the virtual patches were enabled,
// the others arrived inherit (= still disabled).
func (store *Store) openOfficialPack(ctx context.Context, tx pgx.Tx, packID string, now time.Time) error {
	changes := map[string]any{"allow_lower": map[string]any{"from": false, "to": true},
		"state": map[string]any{"from": "inherit", "to": "enabled"}}
	opened, err := tx.Exec(ctx, `INSERT INTO rule_pack_enablements(id,level,level_object_id,pack_id,rule_id,state,allow_lower,
		priority,params,updated_by_user_id,updated_at) VALUES($1,'platform',NULL,$2,NULL,'enabled',true,NULL,NULL,NULL,$3)
		ON CONFLICT (level,level_object_id,pack_id,rule_id) DO NOTHING`, uuid.New(), packID, now)
	if err != nil || opened.RowsAffected() == 0 {
		return err
	}
	return store.systemAudit(ctx, tx, "rule.pack.override.put", "rule_pack_override", "platform/"+packID, "success",
		map[string]any{"pack_id": packID, "level": "platform", "reason": "official_free_pack", "changes": changes})
}

// recomputeDefaultOnMounts keeps every site's mounts in step with the
// default-on official packs: all sites when such a pack
// arrived or changed version in this materialization, else only the sites
// without published mounts (created since the last run), while one is
// enabled at platform level. The changed scopes are republished
// (DefaultOnPackRepublisher) in the same transaction.
func (store *Store) recomputeDefaultOnMounts(ctx context.Context, tx pgx.Tx, all bool) error {
	enabled, err := rulepackcontrol.DefaultOnPackEnabledTx(ctx, tx)
	if err != nil || !enabled {
		return err
	}
	sites, err := rulepackcontrol.DefaultOnSitesTx(ctx, tx, all)
	if err != nil || len(sites) == 0 {
		return err
	}
	runID := uuid.New()
	scopes, err := rulepackcontrol.NewService(store.pool, store.now).RecomputeDefaultOnMountsTx(ctx, tx, sites,
		"default-on-pack."+runID.String())
	if err != nil {
		return fmt.Errorf("recompute default-on rule pack mounts: %w", err)
	}
	if republisher, ok := store.republisher.(DefaultOnPackRepublisher); ok && len(scopes) != 0 {
		return republisher.RepublishDefaultOnPackMountsTx(ctx, tx, runID, scopes)
	}
	return nil
}

// NodeKeyWrap is one node's wrapped content key for one sealed object.
type NodeKeyWrap struct {
	NodeID         uuid.UUID
	RecipientKeyID string
	SealedSHA256   string
	PackID         string
	Version        string
	WrappedKey     string
}

// WrapNodeKeys keeps node_rule_pack_keys equal to: every sealed pack version
// nodes receive (nodeRulePackVersionsSQL: mounted by a published site, or the
// current version of an enabled system pack) × every active node artifact
// encryption key. The
// CEK is unwrapped with the installation key in memory and wrapped to each
// node key (rule.pack.key_wrap); rows of keys no longer active or objects no
// longer mounted are dropped. It returns how many wraps were added.
func (store *Store) WrapNodeKeys(ctx context.Context, encryptionKey []byte) (int, error) {
	if len(encryptionKey) == 0 {
		return 0, ErrNoEncryptionKey
	}
	now := store.now().UTC()
	added := 0
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('node_rule_pack_keys',0))`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM node_rule_pack_keys wrap WHERE NOT EXISTS (
				SELECT 1 FROM node_artifact_encryption_keys key WHERE key.id=wrap.recipient_key_id AND key.status='active')
			OR NOT EXISTS (SELECT 1 FROM (`+nodeRulePackVersionsSQL+`) node_pack JOIN rule_pack_artifacts artifact
				ON artifact.pack_id=node_pack.pack_id AND artifact.version=node_pack.version WHERE artifact.sha256=wrap.sealed_sha256)`); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT DISTINCT artifact.sha256,artifact.pack_id,artifact.version,artifact.wrapped_key,
			key.node_id,key.id,key.public_key
			FROM (`+nodeRulePackVersionsSQL+`) node_pack
			JOIN rule_pack_artifacts artifact ON artifact.pack_id=node_pack.pack_id AND artifact.version=node_pack.version
			CROSS JOIN node_artifact_encryption_keys key
			WHERE artifact.sealed AND key.status='active' AND NOT EXISTS (SELECT 1 FROM node_rule_pack_keys wrap
				WHERE wrap.node_id=key.node_id AND wrap.recipient_key_id=key.id AND wrap.sealed_sha256=artifact.sha256)
			ORDER BY artifact.sha256,key.id`)
		if err != nil {
			return err
		}
		type missing struct {
			sha, packID, version, installationWrapped, keyID string
			nodeID                                           uuid.UUID
			public                                           []byte
		}
		pending, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (missing, error) {
			var item missing
			err := row.Scan(&item.sha, &item.packID, &item.version, &item.installationWrapped, &item.nodeID, &item.keyID, &item.public)
			return item, err
		})
		if err != nil {
			return err
		}
		for _, item := range pending {
			cek, err := unwrapInstallationKey(encryptionKey, item.installationWrapped, item.packID, item.version, item.sha)
			if err != nil {
				return fmt.Errorf("stored sealed pack %s %s: %w", item.packID, item.version, err)
			}
			wrapped, err := rulepack.WrapKey(item.public, cek, rulepack.WrapContext{Purpose: rulepack.WrapPurposeNode,
				RecipientKeyID: item.keyID, PackID: item.packID, Version: item.version, SealedSHA256: item.sha})
			clear(cek)
			if err != nil {
				return fmt.Errorf("wrap %s %s for node %s: %w", item.packID, item.version, item.nodeID, err)
			}
			if _, err := tx.Exec(ctx, `INSERT INTO node_rule_pack_keys(node_id,recipient_key_id,sealed_sha256,pack_id,version,
				wrapped_key,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, item.nodeID, item.keyID, item.sha, item.packID,
				item.version, wrapped, now); err != nil {
				return err
			}
			added++
			if err := store.systemAudit(ctx, tx, "rule.pack.key_wrap", "rule_pack", item.packID+"@"+item.version, "success",
				map[string]any{"purpose": rulepack.WrapPurposeNode, "node_id": item.nodeID.String(),
					"recipient_key_id": item.keyID, "sealed_sha256": item.sha, "version": item.version}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("wrap rule pack keys for nodes: %w", err)
	}
	return added, nil
}

// NodeKeyWraps lists the wrapped content keys of one node (input of its
// pack delivery; the node opens them with its artifact encryption key).
func (store *Store) NodeKeyWraps(ctx context.Context, nodeID uuid.UUID) ([]NodeKeyWrap, error) {
	rows, err := store.pool.Query(ctx, `SELECT node_id,recipient_key_id,sealed_sha256,pack_id,version,wrapped_key
		FROM node_rule_pack_keys WHERE node_id=$1 ORDER BY sealed_sha256,recipient_key_id`, nodeID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (NodeKeyWrap, error) {
		var wrap NodeKeyWrap
		err := row.Scan(&wrap.NodeID, &wrap.RecipientKeyID, &wrap.SealedSHA256, &wrap.PackID, &wrap.Version, &wrap.WrappedKey)
		return wrap, err
	})
}

// MountedRulePack is a pack version some published site mounts (input of
// the node artifact set: nodes need every mounted pack in their object
// store before a site naming it can be applied, ADR 0009 §8.4).
type MountedRulePack struct {
	PackID  string
	Version string
	SHA256  string
	Sealed  bool
	Content []byte
}

// MountedRulePacks lists the distinct pack versions in
// rule_pack_site_mount_artifacts with their stored bytes (sealed bytes for
// an encrypted pack), by digest.
func (store *Store) MountedRulePacks(ctx context.Context) ([]MountedRulePack, error) {
	rows, err := store.pool.Query(ctx, `SELECT DISTINCT artifact.pack_id,artifact.version,artifact.sha256,artifact.sealed,
		artifact.content FROM rule_pack_site_mount_artifacts mount
		JOIN rule_pack_artifacts artifact ON artifact.pack_id=mount.pack_id AND artifact.version=mount.version
		ORDER BY artifact.sha256`)
	if err != nil {
		return nil, fmt.Errorf("list mounted rule packs: %w", err)
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (MountedRulePack, error) {
		var pack MountedRulePack
		err := row.Scan(&pack.PackID, &pack.Version, &pack.SHA256, &pack.Sealed, &pack.Content)
		return pack, err
	})
}

// enabledSystemPacksSQL selects the current version of every system-layer
// (official) pack not disabled at platform level: official packs are enabled
// by default and follow their source (update_policy auto, ADR 0011 §6.1;
// 官方情报包默认自动启用), so nodes hold them without any site
// mount — system/crs-tuning and the mark-only intel packs act node-wide.
const enabledSystemPacksSQL = `SELECT pack.pack_id,pack.current_version AS version FROM rule_packs pack
	WHERE pack.layer='system' AND pack.current_version IS NOT NULL AND NOT EXISTS (
		SELECT 1 FROM rule_pack_enablements disabled WHERE disabled.level='platform' AND disabled.pack_id=pack.pack_id
		AND disabled.rule_id IS NULL AND disabled.state='disabled')`

// nodeRulePackVersionsSQL is every pack version nodes receive: the ones a
// published site mounts and the enabled system packs (distinct pack_id, version).
const nodeRulePackVersionsSQL = `SELECT mount.pack_id,mount.version FROM rule_pack_site_mount_artifacts mount
	UNION ` + enabledSystemPacksSQL

// SystemRulePacks lists the current versions of the enabled system packs
// (enabledSystemPacksSQL) with their stored bytes (sealed bytes for an
// encrypted pack), by digest: node artifact set input next to the mounted
// packs (a version both mounted and current is one item, by digest).
func (store *Store) SystemRulePacks(ctx context.Context) ([]MountedRulePack, error) {
	rows, err := store.pool.Query(ctx, `SELECT artifact.pack_id,artifact.version,artifact.sha256,artifact.sealed,artifact.content
		FROM (`+enabledSystemPacksSQL+`) node_pack
		JOIN rule_pack_artifacts artifact ON artifact.pack_id=node_pack.pack_id AND artifact.version=node_pack.version
		WHERE artifact.content IS NOT NULL ORDER BY artifact.sha256`)
	if err != nil {
		return nil, fmt.Errorf("list system rule packs: %w", err)
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (MountedRulePack, error) {
		var pack MountedRulePack
		err := row.Scan(&pack.PackID, &pack.Version, &pack.SHA256, &pack.Sealed, &pack.Content)
		return pack, err
	})
}
