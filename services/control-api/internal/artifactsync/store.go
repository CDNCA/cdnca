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
	"github.com/jackc/pgx/v5/pgxpool"
)

const catalogLockKey = "artifact_catalog_consumer"

// Store keeps the verified catalog, the downloaded objects and the local
// artifact state (migration 346).
type Store struct {
	pool        *pgxpool.Pool
	now         func() time.Time
	features    FeatureReader
	republisher CRSRepublisher
	auditor     *audit.Log
}

func NewStore(pool *pgxpool.Pool, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{pool: pool, now: now, auditor: audit.NewWithClock(pool, now)}
}

// WithFeatures sets the local lease recheck (nil: free entries only).
func (store *Store) WithFeatures(features FeatureReader) *Store {
	store.features = features
	return store
}

// WithCRSRepublisher makes materialization request the republications a
// CRS rule package change needs.
func (store *Store) WithCRSRepublisher(republisher CRSRepublisher) *Store {
	store.republisher = republisher
	return store
}

func (store *Store) readFeatures(ctx context.Context, tx pgx.Tx) (map[string]bool, error) {
	if store.features == nil {
		return map[string]bool{}, nil
	}
	features, err := store.features.ReadValidFeatures(ctx, tx)
	if err != nil {
		return nil, fmt.Errorf("read lease features: %w", err)
	}
	return features, nil
}

func permitted(features map[string]bool, requiresFeature string) bool {
	return requiresFeature == "" || features[requiresFeature]
}

// Head returns the last applied delivery, nil before the first one.
func (store *Store) Head(ctx context.Context) (*artifactcatalog.Head, error) {
	var deliveryID *uuid.UUID
	var revision *int64
	var digest *string
	if err := store.pool.QueryRow(ctx, `SELECT delivery_id,scope_revision,catalog_sha256 FROM artifact_catalog_state`).
		Scan(&deliveryID, &revision, &digest); err != nil {
		return nil, fmt.Errorf("load artifact catalog head: %w", err)
	}
	if deliveryID == nil || revision == nil || digest == nil {
		return nil, nil
	}
	return &artifactcatalog.Head{DeliveryID: deliveryID.String(), ScopeRevision: uint64(*revision), CatalogSHA256: *digest}, nil
}

// ApplyCatalog atomically installs a verified delivery: delivered entries are
// upserted as active, entries no longer delivered are kept as withdrawn and
// the head advances. An entry whose revision would move backwards (or change
// bytes at the same revision) keeps its stored row; the delivery is still
// applied and the attempt is recorded as entry_revision_out_of_order.
func (store *Store) ApplyCatalog(ctx context.Context, verified artifactcatalog.Verified, expected *artifactcatalog.Head) error {
	signed := verified.Signed
	encoded, err := signed.Encode()
	if err != nil {
		return err
	}
	deliveryID, err := uuid.Parse(signed.Envelope.DeliveryID)
	if err != nil {
		return ErrInvalidInput
	}
	now := store.now().UTC()
	return pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, catalogLockKey); err != nil {
			return err
		}
		var current *int64
		if err := tx.QueryRow(ctx, `SELECT scope_revision FROM artifact_catalog_state FOR UPDATE`).Scan(&current); err != nil {
			return err
		}
		if expected == nil && current != nil || expected != nil && (current == nil || uint64(*current) != expected.ScopeRevision) {
			return ErrStaleApply
		}
		ids := make([]string, 0, len(signed.Catalog.Entries))
		added, updated, skipped := 0, 0, 0
		for _, entry := range signed.Catalog.Entries {
			ids = append(ids, entry.ArtifactID)
			outcome, err := upsertEntry(ctx, tx, entry, deliveryID, now)
			if err != nil {
				return err
			}
			switch outcome {
			case entryAdded:
				added++
			case entryUpdated:
				updated++
			case entryOutOfOrder:
				skipped++
			}
		}
		// Local rows (ipintel/local, migration 367) are not the catalog's.
		withdrawn, err := tx.Exec(ctx, `UPDATE artifact_catalog_entries SET status='withdrawn',withdrawn_at=$2,updated_at=$2
			WHERE status='active' AND origin='catalog' AND NOT (artifact_id = ANY($1::text[]))`, ids, now)
		if err != nil {
			return err
		}
		code := ""
		if skipped > 0 {
			code = CodeEntryOutOfOrder
		}
		if _, err := tx.Exec(ctx, `UPDATE artifact_catalog_state SET delivery_id=$1,scope_revision=$2,catalog_sha256=$3,
			key_id=$4,signed_document=$5,valid_from=$6,expires_at=$7,applied_at=$8,last_attempt_at=$8,last_success_at=$8,
			last_error_code=$9,updated_at=$8`, deliveryID, int64(signed.Envelope.ScopeRevision), signed.Envelope.CatalogSHA256,
			signed.Envelope.KeyID, encoded, time.Unix(signed.Envelope.ValidFrom, 0).UTC(),
			time.Unix(signed.Envelope.ExpiresAt, 0).UTC(), now, code); err != nil {
			return err
		}
		return store.systemAudit(ctx, tx, "plugin.artifact_catalog.apply", "artifact_catalog_delivery", deliveryID.String(),
			"success", map[string]any{"scope_revision": signed.Envelope.ScopeRevision, "entries": len(signed.Catalog.Entries),
				"changes": map[string]any{"added": added, "updated": updated, "withdrawn": withdrawn.RowsAffected(),
					"out_of_order": skipped}, "key_id": signed.Envelope.KeyID})
	})
}

type entryOutcome int

const (
	entryUnchanged entryOutcome = iota
	entryAdded
	entryUpdated
	entryOutOfOrder
)

func upsertEntry(ctx context.Context, tx pgx.Tx, entry artifactcatalog.Entry, deliveryID uuid.UUID, now time.Time) (entryOutcome, error) {
	var capability []byte
	if entry.RequiresCapability != nil {
		encoded, err := json.Marshal(entry.RequiresCapability)
		if err != nil {
			return 0, err
		}
		capability = encoded
	}
	var revision int64
	var sha, status string
	var origin string
	err := tx.QueryRow(ctx, `SELECT revision,sha256,status,origin FROM artifact_catalog_entries WHERE artifact_id=$1 FOR UPDATE`,
		entry.ArtifactID).Scan(&revision, &sha, &status, &origin)
	switch {
	case err == nil && origin != "catalog":
		// The catalog never names a local artifact id; keep the local row.
		return entryOutOfOrder, nil
	case errors.Is(err, pgx.ErrNoRows):
		_, err := tx.Exec(ctx, `INSERT INTO artifact_catalog_entries(artifact_id,kind,version,revision,sha256,size,media_type,
			requires_feature,requires_capability,resident,encryption,license_spdx,supersedes,status,delivery_id,first_seen_at,updated_at,
			wrapped_key) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'active',$14,$15,$15,$16)`,
			entry.ArtifactID, entry.Kind, entry.Version, int64(entry.Revision), entry.SHA256, entry.Size, entry.MediaType,
			entry.RequiresFeature, capability, entry.Resident, entry.Encryption, entry.LicenseSPDX, entry.Supersedes, deliveryID, now,
			entry.WrappedKey)
		return entryAdded, err
	case err != nil:
		return 0, err
	case uint64(revision) > entry.Revision || uint64(revision) == entry.Revision && sha != entry.SHA256:
		return entryOutOfOrder, nil
	}
	// Same revision: metadata (feature, resident, ...) may still change; the
	// delivery that introduced the revision is kept as its source.
	command, err := tx.Exec(ctx, `UPDATE artifact_catalog_entries SET kind=$2,version=$3,revision=$4,sha256=$5,size=$6,
		media_type=$7,requires_feature=$8,requires_capability=$9,resident=$10,encryption=$11,license_spdx=$12,supersedes=$13,
		status='active',withdrawn_at=NULL,updated_at=$15,wrapped_key=$16,
		delivery_id=CASE WHEN revision=$4 AND status='active' THEN delivery_id ELSE $14 END
		WHERE artifact_id=$1 AND (revision<>$4 OR status<>'active' OR kind<>$2 OR version<>$3 OR size<>$6 OR media_type<>$7 OR
		  requires_feature<>$8 OR requires_capability IS DISTINCT FROM $9::jsonb OR resident<>$10 OR encryption<>$11 OR
		  license_spdx<>$12 OR supersedes<>$13 OR wrapped_key<>$16)`,
		entry.ArtifactID, entry.Kind, entry.Version, int64(entry.Revision), entry.SHA256, entry.Size, entry.MediaType,
		entry.RequiresFeature, capability, entry.Resident, entry.Encryption, entry.LicenseSPDX, entry.Supersedes, deliveryID, now,
		entry.WrappedKey)
	if err != nil || command.RowsAffected() == 0 {
		return entryUnchanged, err
	}
	return entryUpdated, nil
}

// RecordAttempt stores the outcome of a round that did not apply a delivery
// ("" = success, e.g. not modified). Nothing applied is touched.
func (store *Store) RecordAttempt(ctx context.Context, code string) error {
	now := store.now().UTC()
	_, err := store.pool.Exec(ctx, `UPDATE artifact_catalog_state SET last_attempt_at=$1,last_error_code=$2,updated_at=$1,
		last_success_at=CASE WHEN $2='' THEN $1 ELSE last_success_at END`, now, code)
	return err
}

// RejectDelivery records a delivery that failed verification and audits it.
func (store *Store) RejectDelivery(ctx context.Context, envelope artifactcatalog.Envelope, code string) error {
	now := store.now().UTC()
	return pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE artifact_catalog_state SET last_attempt_at=$1,last_error_code=$2,updated_at=$1`,
			now, code); err != nil {
			return err
		}
		resourceID := envelope.DeliveryID
		if !artifactcatalog.ValidUUID(resourceID) {
			resourceID = "unknown"
		}
		return store.systemAudit(ctx, tx, "plugin.artifact_catalog.reject", "artifact_catalog_delivery", resourceID, "failure",
			map[string]any{"reason": code, "scope_revision": envelope.ScopeRevision, "key_id": envelope.KeyID})
	})
}

// systemAudit appends an event of the sync itself (actor: system) to the
// platform audit stream. An installation without a platform scope (bare
// test schemas) has no stream to write to and is skipped.
func (store *Store) systemAudit(ctx context.Context, tx pgx.Tx, action, resourceType, resourceID, result string,
	payload map[string]any) error {
	var platformScopeID uuid.UUID
	err := tx.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL ORDER BY id LIMIT 1`).
		Scan(&platformScopeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	payload["actor"] = "system"
	payload["ip"] = ""
	return store.auditor.Append(ctx, tx, audit.Event{ScopeID: platformScopeID, Action: action, ResourceType: resourceType,
		ResourceID: resourceID, RequestID: action + "." + uuid.NewString(), Result: result, Payload: payload})
}
