package artifactsync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	"github.com/jackc/pgx/v5"
)

// IPIntelLocalID is the IP intelligence library this control plane builds
// itself from the platform's dnspup snapshot (module.ipintel.dnspup, ADR
// 0007 section 4.4). It is kept beside the catalog entries (origin 'local',
// migration 367) so the lease recheck, the LKG rule and the node artifact
// set treat it like a downloaded one.
const (
	IPIntelLocalID      = "ipintel/local"
	IPIntelLocalFeature = "module.ipintel.dnspup"
)

// ErrLocalOutOfOrder: a local build would not move ipintel/local forward.
var ErrLocalOutOfOrder = errors.New("local artifact revision does not move forward")

// LatestLocalRevision returns the revision of ipintel/local (0: none).
func (store *Store) LatestLocalRevision(ctx context.Context) (uint64, error) {
	var revision int64
	err := store.pool.QueryRow(ctx, `SELECT revision FROM artifact_catalog_entries WHERE artifact_id=$1 AND origin='local'`,
		IPIntelLocalID).Scan(&revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read local ip intel revision: %w", err)
	}
	return uint64(revision), nil
}

// StoreLocalBuildTx stores a locally built ipintel/local revision in tx: the
// bytes (content addressed), its entry (origin 'local', feature
// module.ipintel.dnspup) and the local artifact pointer. entry must name
// content (checked); its revision must be newer than the stored one.
// Audited as plugin.artifact.build (system actor).
func (store *Store) StoreLocalBuildTx(ctx context.Context, tx pgx.Tx, entry artifactcatalog.Entry, content []byte,
	payload map[string]any) error {
	if entry.ArtifactID != IPIntelLocalID || entry.Kind != artifactcatalog.KindIPIntel || entry.RequiresFeature != IPIntelLocalFeature ||
		entry.Resident || entry.Encryption != artifactcatalog.EncryptionNone {
		return ErrInvalidInput
	}
	if _, err := artifactcatalog.VerifyIPIntel(entry, content); err != nil {
		return err
	}
	capability, err := json.Marshal(entry.RequiresCapability)
	if err != nil {
		return err
	}
	now := store.now().UTC()
	var previous *int64
	if err := tx.QueryRow(ctx, `SELECT revision FROM artifact_catalog_entries WHERE artifact_id=$1 FOR UPDATE`, entry.ArtifactID).
		Scan(&previous); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if previous != nil && uint64(*previous) >= entry.Revision {
		return ErrLocalOutOfOrder
	}
	if _, err := tx.Exec(ctx, `INSERT INTO artifact_objects(sha256,size,content,stored_at) VALUES($1,$2,$3,$4)
		ON CONFLICT (sha256) DO NOTHING`, entry.SHA256, entry.Size, content, now); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO artifact_catalog_entries(artifact_id,kind,version,revision,sha256,size,media_type,
		requires_feature,requires_capability,resident,encryption,license_spdx,supersedes,status,origin,first_seen_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,false,'none','','','active','local',$10,$10)
		ON CONFLICT (artifact_id) DO UPDATE SET version=EXCLUDED.version,revision=EXCLUDED.revision,sha256=EXCLUDED.sha256,
		size=EXCLUDED.size,media_type=EXCLUDED.media_type,requires_capability=EXCLUDED.requires_capability,updated_at=EXCLUDED.updated_at`,
		entry.ArtifactID, entry.Kind, entry.Version, int64(entry.Revision), entry.SHA256, entry.Size, entry.MediaType,
		entry.RequiresFeature, capability, now); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO local_artifacts(artifact_id,current_revision,current_sha256,current_version,
		current_requires_capability,downloaded_at,last_attempt_at,last_error_code,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$6,'',$6)
		ON CONFLICT (artifact_id) DO UPDATE SET current_revision=EXCLUDED.current_revision,current_sha256=EXCLUDED.current_sha256,
		current_version=EXCLUDED.current_version,current_requires_capability=EXCLUDED.current_requires_capability,
		downloaded_at=EXCLUDED.downloaded_at,last_attempt_at=EXCLUDED.last_attempt_at,last_error_code='',updated_at=EXCLUDED.updated_at`,
		entry.ArtifactID, int64(entry.Revision), entry.SHA256, entry.Version, capability, now); err != nil {
		return err
	}
	before := any(nil)
	if previous != nil {
		before = *previous
	}
	if payload == nil {
		payload = map[string]any{}
	}
	payload["changes"] = map[string]any{"revision": map[string]any{"before": before, "after": entry.Revision}}
	payload["version"], payload["sha256"], payload["size"] = entry.Version, entry.SHA256, entry.Size
	return store.systemAudit(ctx, tx, "plugin.artifact.build", "artifact", entry.ArtifactID, "success", payload)
}
