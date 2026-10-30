package artifactsync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// rejectedRetryAfter: a revision whose bytes failed verification is not
// fetched again before this (the license service may have repaired them).
const rejectedRetryAfter = time.Hour

// entryColumns reads an artifact_catalog_entries row (alias entry) into an
// artifactcatalog.Entry with scanEntry.
const entryColumns = `entry.artifact_id,entry.kind,entry.version,entry.revision,entry.sha256,entry.size,entry.media_type,
	entry.requires_feature,entry.requires_capability,entry.resident,entry.encryption,entry.license_spdx,entry.supersedes,
	entry.wrapped_key`

func scanEntry(row pgx.Row, extra ...any) (artifactcatalog.Entry, error) {
	var entry artifactcatalog.Entry
	var revision int64
	var capability []byte
	targets := append([]any{&entry.ArtifactID, &entry.Kind, &entry.Version, &revision, &entry.SHA256, &entry.Size,
		&entry.MediaType, &entry.RequiresFeature, &capability, &entry.Resident, &entry.Encryption, &entry.LicenseSPDX,
		&entry.Supersedes, &entry.WrappedKey}, extra...)
	if err := row.Scan(targets...); err != nil {
		return artifactcatalog.Entry{}, err
	}
	entry.Revision = uint64(revision)
	if len(capability) > 0 {
		entry.RequiresCapability = &artifactcatalog.Capability{}
		if err := json.Unmarshal(capability, entry.RequiresCapability); err != nil {
			return artifactcatalog.Entry{}, err
		}
	}
	return entry, nil
}

// PendingDownloads lists the active entries whose bytes should be fetched
// now: resident, requested by an administrator, or a newer revision of one
// already downloaded; supported by this release, granted by the local lease,
// and not a revision that failed verification within rejectedRetryAfter.
func (store *Store) PendingDownloads(ctx context.Context) ([]artifactcatalog.Entry, error) {
	var result []artifactcatalog.Entry
	err := pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		features, err := store.readFeatures(ctx, tx)
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT `+entryColumns+` FROM artifact_catalog_entries entry
			LEFT JOIN local_artifacts local ON local.artifact_id=entry.artifact_id
			WHERE entry.status='active'
			  AND (entry.resident OR local.requested_at IS NOT NULL OR local.current_revision IS NOT NULL OR
			       -- cdncaCE: a pack/theme bought on the market is fetched once its
			       -- feature is granted (no console download request is needed).
			       entry.requires_feature LIKE 'pack.%' OR entry.requires_feature LIKE 'theme.%')
			  AND (local.current_revision IS NULL OR local.current_revision < entry.revision OR
			       -- Same sealed copy, its content key wrapped again (new installation encryption key).
			       local.current_revision = entry.revision AND local.current_sha256 = entry.sha256 AND
			       local.current_wrapped_key <> entry.wrapped_key)
			  AND NOT (local.rejected_revision IS NOT DISTINCT FROM entry.revision AND local.last_attempt_at > $1)
			ORDER BY entry.artifact_id`, store.now().UTC().Add(-rejectedRetryAfter))
		if err != nil {
			return err
		}
		entries, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (artifactcatalog.Entry, error) { return scanEntry(row) })
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if artifactcatalog.Supported(entry) && permitted(features, entry.RequiresFeature) {
				result = append(result, entry)
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list pending artifact downloads: %w", err)
	}
	return result, nil
}

// StoreDownload stores verified bytes of entry and advances the local
// artifact to its revision. It does nothing (false) when the catalog moved
// on meanwhile (the entry is no longer active at that revision and digest)
// or the local artifact is already at that revision or newer.
func (store *Store) StoreDownload(ctx context.Context, entry artifactcatalog.Entry, content []byte) (bool, error) {
	if err := artifactcatalog.VerifyContent(entry, content); err != nil {
		return false, err
	}
	var capability []byte
	if entry.RequiresCapability != nil {
		capability, _ = json.Marshal(entry.RequiresCapability)
	}
	now := store.now().UTC()
	stored := false
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		var still bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM artifact_catalog_entries WHERE artifact_id=$1 AND
			status='active' AND revision=$2 AND sha256=$3 AND wrapped_key=$4 FOR SHARE)`, entry.ArtifactID, int64(entry.Revision),
			entry.SHA256, entry.WrappedKey).
			Scan(&still); err != nil || !still {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO artifact_objects(sha256,size,content,stored_at) VALUES($1,$2,$3,$4)
			ON CONFLICT (sha256) DO NOTHING`, entry.SHA256, entry.Size, content, now); err != nil {
			return err
		}
		var previous *int64
		var previousSHA *string
		var previousWrapped string
		err := tx.QueryRow(ctx, `SELECT current_revision,current_sha256,current_wrapped_key FROM local_artifacts
			WHERE artifact_id=$1 FOR UPDATE`, entry.ArtifactID).Scan(&previous, &previousSHA, &previousWrapped)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			_, err = tx.Exec(ctx, `INSERT INTO local_artifacts(artifact_id,current_revision,current_sha256,current_version,
				current_requires_capability,downloaded_at,last_attempt_at,last_error_code,updated_at,current_wrapped_key)
				VALUES($1,$2,$3,$4,$5,$6,$6,'',$6,$7)`, entry.ArtifactID, int64(entry.Revision), entry.SHA256, entry.Version,
				capability, now, entry.WrappedKey)
		case err != nil:
		case previous != nil && uint64(*previous) == entry.Revision && previousSHA != nil && *previousSHA == entry.SHA256 &&
			previousWrapped != entry.WrappedKey && entry.WrappedKey != "":
			// The same sealed copy with its content key wrapped to a new
			// installation key (checked by the caller): keep the bytes, swap
			// the wrapped key here and on the materialized pack version.
			if _, err := tx.Exec(ctx, `UPDATE local_artifacts SET current_wrapped_key=$2,last_attempt_at=$3,last_error_code='',
				rejected_revision=NULL,updated_at=$3 WHERE artifact_id=$1`, entry.ArtifactID, entry.WrappedKey, now); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE rule_pack_artifacts SET wrapped_key=$2 WHERE sha256=$1 AND sealed`,
				entry.SHA256, entry.WrappedKey); err != nil {
				return err
			}
			stored = true
			return store.systemAudit(ctx, tx, "rule.pack.key_rewrap", "rule_pack", entry.ArtifactID, "success",
				map[string]any{"version": entry.Version, "revision": entry.Revision, "sha256": entry.SHA256})
		case previous != nil && uint64(*previous) >= entry.Revision:
			return nil
		default:
			_, err = tx.Exec(ctx, `UPDATE local_artifacts SET current_revision=$2,current_sha256=$3,current_version=$4,
				current_requires_capability=$5,downloaded_at=$6,last_attempt_at=$6,last_error_code='',rejected_revision=NULL,
				updated_at=$6,current_wrapped_key=$7 WHERE artifact_id=$1`, entry.ArtifactID, int64(entry.Revision), entry.SHA256,
				entry.Version, capability, now, entry.WrappedKey)
		}
		if err != nil {
			return err
		}
		stored = true
		before := any(nil)
		if previous != nil {
			before = *previous
		}
		return store.systemAudit(ctx, tx, "plugin.artifact.download", "artifact", entry.ArtifactID, "success",
			map[string]any{"changes": map[string]any{"revision": map[string]any{"before": before, "after": entry.Revision}},
				"version": entry.Version, "sha256": entry.SHA256, "size": entry.Size, "kind": entry.Kind})
	})
	if err != nil {
		return false, fmt.Errorf("store artifact %s: %w", entry.ArtifactID, err)
	}
	return stored, nil
}

// RejectDownload records a failed download of entry; the downloaded
// revision (LKG) is kept. verification=true marks bytes that did not match
// the signed entry (audited, not retried within rejectedRetryAfter);
// otherwise it is a transport failure retried next round.
func (store *Store) RejectDownload(ctx context.Context, entry artifactcatalog.Entry, code string, verification bool) error {
	now := store.now().UTC()
	var rejected *int64
	if verification {
		revision := int64(entry.Revision)
		rejected = &revision
	}
	return pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO local_artifacts(artifact_id,last_attempt_at,last_error_code,rejected_revision,updated_at)
			VALUES($1,$2,$3,$4,$2) ON CONFLICT (artifact_id) DO UPDATE SET last_attempt_at=EXCLUDED.last_attempt_at,
			last_error_code=EXCLUDED.last_error_code,rejected_revision=EXCLUDED.rejected_revision,updated_at=EXCLUDED.updated_at`,
			entry.ArtifactID, now, code, rejected); err != nil {
			return err
		}
		if !verification {
			return nil
		}
		return store.systemAudit(ctx, tx, "plugin.artifact.download_reject", "artifact", entry.ArtifactID, "failure",
			map[string]any{"reason": code, "revision": entry.Revision, "sha256": entry.SHA256, "kind": entry.Kind})
	})
}

// RequestDownload records an administrator asking for an entry's bytes; the
// next sync round fetches them. Downloading never enables the artifact.
func (store *Store) RequestDownload(ctx context.Context, request DownloadRequest) error {
	if !artifactcatalog.ValidArtifactID(request.ArtifactID) || request.ActorUserID == uuid.Nil || request.ScopeID == uuid.Nil ||
		request.RequestID == "" || len(request.RequestID) > 128 {
		return ErrInvalidInput
	}
	now := store.now().UTC()
	// A refused request is audited too, so its transaction commits and the
	// refusal is returned afterwards.
	var refused error
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		features, err := store.readFeatures(ctx, tx)
		if err != nil {
			return err
		}
		var status string
		entry, err := scanEntry(tx.QueryRow(ctx, `SELECT `+entryColumns+`,entry.status FROM artifact_catalog_entries entry
			WHERE entry.artifact_id=$1 FOR SHARE`, request.ArtifactID), &status)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		result, reason := "success", ""
		switch {
		case status != "active" || !artifactcatalog.Supported(entry):
			result, reason, refused = "failure", "unsupported", ErrUnsupported
		case !permitted(features, entry.RequiresFeature):
			result, reason, refused = "failure", "entitlement_feature_denied", ErrNotEntitled
		default:
			_, err = tx.Exec(ctx, `INSERT INTO local_artifacts(artifact_id,requested_at,requested_by_user_id,updated_at)
				VALUES($1,$2,$3,$2) ON CONFLICT (artifact_id) DO UPDATE SET requested_at=EXCLUDED.requested_at,
				requested_by_user_id=EXCLUDED.requested_by_user_id,updated_at=EXCLUDED.updated_at`,
				request.ArtifactID, now, request.ActorUserID)
			if err != nil {
				return err
			}
		}
		payload := map[string]any{"ip": request.SourceIP, "revision": entry.Revision, "version": entry.Version,
			"kind": entry.Kind, "requires_feature": entry.RequiresFeature}
		if reason != "" {
			payload["reason"] = reason
		}
		actor := request.ActorUserID
		return store.auditor.Append(ctx, tx, audit.Event{ScopeID: request.ScopeID, ActorUserID: &actor,
			Action: "plugin.artifact.download_request", ResourceType: "artifact", ResourceID: request.ArtifactID,
			RequestID: request.RequestID, Result: result, Payload: payload})
	})
	if err != nil {
		return err
	}
	return refused
}

// LocalArtifacts lists the downloaded artifacts usable now (active entry,
// feature granted), in artifact_id order. Enablement for nodes is decided
// by the caller (ADR 0007 §5.4: downloading is not enabling).
func (store *Store) LocalArtifacts(ctx context.Context) ([]LocalArtifact, error) {
	return store.localArtifacts(ctx, "")
}

// Current returns the usable downloaded artifact artifactID, nil if none.
func (store *Store) Current(ctx context.Context, artifactID string) (*LocalArtifact, error) {
	if !artifactcatalog.ValidArtifactID(artifactID) {
		return nil, ErrInvalidInput
	}
	artifacts, err := store.localArtifacts(ctx, artifactID)
	if err != nil || len(artifacts) == 0 {
		return nil, err
	}
	return &artifacts[0], nil
}

func (store *Store) localArtifacts(ctx context.Context, only string) ([]LocalArtifact, error) {
	var result []LocalArtifact
	err := pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		features, err := store.readFeatures(ctx, tx)
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT local.artifact_id,entry.kind,local.current_version,local.current_revision,
			local.current_sha256,object.size,entry.media_type,local.current_requires_capability,local.downloaded_at,
			entry.requires_feature
			FROM local_artifacts local
			JOIN artifact_catalog_entries entry ON entry.artifact_id=local.artifact_id AND entry.status='active'
			JOIN artifact_objects object ON object.sha256=local.current_sha256
			WHERE local.current_revision IS NOT NULL AND ($1='' OR local.artifact_id=$1)
			ORDER BY local.artifact_id`, only)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var artifact LocalArtifact
			var revision int64
			var capability []byte
			var feature string
			if err := rows.Scan(&artifact.ArtifactID, &artifact.Kind, &artifact.Version, &revision, &artifact.SHA256,
				&artifact.Size, &artifact.MediaType, &capability, &artifact.AppliedAt, &feature); err != nil {
				return err
			}
			if !permitted(features, feature) {
				continue
			}
			artifact.Revision, artifact.AppliedAt = uint64(revision), artifact.AppliedAt.UTC()
			if len(capability) > 0 {
				artifact.RequiresCapability = &artifactcatalog.Capability{}
				if err := json.Unmarshal(capability, artifact.RequiresCapability); err != nil {
					return err
				}
			}
			result = append(result, artifact)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list local artifacts: %w", err)
	}
	return result, nil
}

// Object returns the stored bytes named by sha256 (lowercase hex). Objects
// are content-addressed and immutable; whether the caller may use them is
// decided by LocalArtifacts / Current.
func (store *Store) Object(ctx context.Context, sha256 string) ([]byte, error) {
	if !artifactcatalog.ValidSHA256(sha256) {
		return nil, ErrInvalidInput
	}
	var content []byte
	err := store.pool.QueryRow(ctx, `SELECT content FROM artifact_objects WHERE sha256=$1`, sha256).Scan(&content)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read artifact object: %w", err)
	}
	return content, nil
}
