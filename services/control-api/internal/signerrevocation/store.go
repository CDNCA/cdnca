package signerrevocation

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/entitlementsync"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	writeLock             int64 = 501809704351922
	auditLock             int64 = 501809704351923
	maxCandidateClockSkew       = 5 * time.Minute
)

type Store struct {
	pool  *pgxpool.Pool
	trust DeploymentTrustSource
	now   func() time.Time
}

func NewStore(pool *pgxpool.Pool, trust DeploymentTrustSource, now func() time.Time) *Store {
	return &Store{pool: pool, trust: trust, now: now}
}

func (store *Store) Restore(ctx context.Context) (Snapshot, error) {
	if store == nil || store.pool == nil || store.trust == nil {
		return Snapshot{}, ErrInvalidInput
	}
	var snapshot Snapshot
	err := pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly},
		func(tx pgx.Tx) error {
			if err := verifyAuditTx(ctx, tx); err != nil {
				return err
			}
			var err error
			snapshot, err = store.restoreTx(ctx, tx)
			return err
		})
	if err != nil {
		return Snapshot{}, err
	}
	if snapshot.Revision == 0 {
		return Snapshot{}, ErrNoSnapshot
	}
	return cloneSnapshot(snapshot), nil
}

func (store *Store) Accept(ctx context.Context, candidate Candidate) (Snapshot, error) {
	if store == nil || store.pool == nil || store.trust == nil || store.now == nil || candidate.OperationID == uuid.Nil ||
		candidate.ObservedAt.IsZero() ||
		(len(candidate.KeysetPayload) == 0 && len(candidate.RevocationPayload) == 0) ||
		(len(candidate.KeysetPayload) == 0) != (candidate.KeysetETag == "") ||
		(len(candidate.RevocationPayload) == 0) != (candidate.RevocationETag == "") {
		return Snapshot{}, ErrInvalidInput
	}
	verifyAt := store.now().UTC().Truncate(time.Microsecond)
	if verifyAt.IsZero() {
		return Snapshot{}, ErrInvalidInput
	}
	candidate.ObservedAt = candidate.ObservedAt.UTC().Truncate(time.Microsecond)
	if candidate.ObservedAt.Before(verifyAt.Add(-maxCandidateClockSkew)) ||
		candidate.ObservedAt.After(verifyAt.Add(maxCandidateClockSkew)) {
		rejected := eventRecord{OperationID: candidate.OperationID, Stage: "reject", Result: "failure",
			Reason: ReasonObservedAtOutOfRange, KeysetETag: candidate.KeysetETag,
			RevocationETag: candidate.RevocationETag, OccurredAt: verifyAt}
		if err := store.appendEvent(ctx, rejected); err != nil {
			return Snapshot{}, errors.Join(ErrObservedAtOutOfRange, err)
		}
		return Snapshot{}, ErrObservedAtOutOfRange
	}
	fetched := eventRecord{OperationID: candidate.OperationID, Stage: "fetch", Result: "success",
		Reason: ReasonFetchReceived, KeysetETag: candidate.KeysetETag, RevocationETag: candidate.RevocationETag,
		OccurredAt: candidate.ObservedAt}
	if err := store.appendEvent(ctx, fetched); err != nil {
		return Snapshot{}, err
	}

	var accepted Snapshot
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", writeLock); err != nil {
			return err
		}
		pre, err := store.restoreTx(ctx, tx)
		if err != nil {
			return err
		}
		pins, err := store.trust.KeysetPins(ctx)
		if err != nil || len(pins) == 0 {
			return errors.Join(ErrAuthorityUntrusted, err)
		}

		keyset := pre.Keyset
		keysetPayload, keysetETag := pre.KeysetPayload, pre.KeysetETag
		keysetChanged := false
		if len(candidate.KeysetPayload) > 0 {
			if !validStrongETag(candidate.KeysetETag, candidate.KeysetPayload) {
				return ErrInvalidETag
			}
			keyset, err = entitlementsync.VerifyPublicKeyset(candidate.KeysetPayload, pins, pre.Keyset, verifyAt)
			if err != nil {
				return err
			}
			keysetPayload = append([]byte(nil), candidate.KeysetPayload...)
			keysetETag = candidate.KeysetETag
			keysetChanged = pre.Keyset == nil || pre.KeysetETag != keysetETag || !equalBytes(pre.KeysetPayload, keysetPayload)
		}
		if keyset == nil {
			return ErrAuthorityUntrusted
		}

		var verified verifiedManifest
		revocationChanged := false
		if len(candidate.RevocationPayload) > 0 {
			if !validStrongETag(candidate.RevocationETag, candidate.RevocationPayload) {
				return ErrInvalidETag
			}
			verified, err = exactStoredReplay(candidate, pre)
			if errors.Is(err, ErrSequenceConflict) {
				verified, err = verifyManifest(ctx, candidate.RevocationPayload, pre, store.trust, verifyAt)
			}
			if err != nil {
				return err
			}
			revocationChanged = !verified.replayed
		}

		reason := ReasonVerified
		if verified.replayed {
			reason = ReasonSameReplay
		}
		verificationEvent := fetched
		verificationEvent.Stage, verificationEvent.Reason, verificationEvent.OccurredAt = "verify", reason, verifyAt
		if len(candidate.RevocationPayload) > 0 {
			verificationEvent.RevocationSequence = verified.signed.Manifest.Sequence
			verificationEvent.RevocationDigest = verified.digest[:]
		}
		if err := appendEventTx(ctx, tx, verificationEvent); err != nil {
			return err
		}

		if !keysetChanged && !revocationChanged {
			accepted = pre
			applied := verificationEvent
			applied.Stage, applied.Reason, applied.SnapshotRevision = "apply", ReasonSameReplay, pre.Revision
			return appendEventTx(ctx, tx, applied)
		}
		accepted = Snapshot{Revision: pre.Revision + 1, Keyset: keyset, KeysetETag: keysetETag,
			KeysetPayload: keysetPayload, RevocationHead: pre.RevocationHead,
			RevocationETag: pre.RevocationETag, Revocations: append([]Revocation(nil), pre.Revocations...),
			AcceptedAt: verifyAt}
		if revocationChanged {
			revoked := manifestRevocation(verified, candidate.RevocationETag, candidate.RevocationPayload)
			accepted.RevocationHead = ChainState{Sequence: revoked.Sequence, ManifestSHA256: revoked.ManifestSHA256}
			accepted.RevocationETag = revoked.ETag
			accepted.Revocations = append(accepted.Revocations, revoked)
		}
		if err := insertSnapshot(ctx, tx, pre, accepted); err != nil {
			return err
		}
		if revocationChanged {
			if err := insertManifest(ctx, tx, accepted.Revision, accepted.Revocations[len(accepted.Revocations)-1],
				verified.signed.Manifest); err != nil {
				return err
			}
		}
		applied := verificationEvent
		applied.Stage, applied.Reason, applied.SnapshotRevision = "apply", ReasonApplied, accepted.Revision
		return appendEventTx(ctx, tx, applied)
	})
	if err == nil {
		return cloneSnapshot(accepted), nil
	}
	rejected := fetched
	rejected.Stage, rejected.Result, rejected.Reason, rejected.OccurredAt =
		"reject", "failure", rejectionReason(err), verifyAt
	if auditErr := store.appendEvent(ctx, rejected); auditErr != nil {
		err = errors.Join(err, fmt.Errorf("append signer revocation rejection: %w", auditErr))
	}
	return Snapshot{}, err
}

func exactStoredReplay(candidate Candidate, pre Snapshot) (verifiedManifest, error) {
	if len(pre.Revocations) == 0 {
		return verifiedManifest{}, ErrSequenceConflict
	}
	stored := pre.Revocations[len(pre.Revocations)-1]
	if candidate.RevocationETag != stored.ETag || !equalBytes(candidate.RevocationPayload, stored.Encoded) {
		return verifiedManifest{}, ErrSequenceConflict
	}
	signed, err := Decode(candidate.RevocationPayload)
	if err != nil {
		return verifiedManifest{}, err
	}
	canonical, err := CanonicalManifest(signed.Manifest)
	if err != nil {
		return verifiedManifest{}, err
	}
	digest := sha256.Sum256(canonical)
	if signed.Manifest.Sequence != pre.RevocationHead.Sequence || encodeDigest(digest) != pre.RevocationHead.ManifestSHA256 {
		return verifiedManifest{}, ErrSequenceConflict
	}
	return verifiedManifest{signed: signed, digest: digest, authority: stored.Authority, replayed: true,
		acceptedAt: stored.AcceptedAt}, nil
}

func (store *Store) RecordOutage(ctx context.Context, operationID uuid.UUID, observedAt time.Time) error {
	if store == nil || store.pool == nil || operationID == uuid.Nil || observedAt.IsZero() {
		return ErrInvalidInput
	}
	return store.appendEvent(ctx, eventRecord{OperationID: operationID, Stage: "fetch", Result: "failure",
		Reason: ReasonTransportUnavailable, OccurredAt: observedAt.UTC().Truncate(time.Microsecond)})
}

type snapshotRow struct {
	revision, revocationSequence uint64
	previousRevision             *uint64
	keysetSchema, keysetETag     string
	keysetActiveKeyID            string
	keysetPayload, keysetDigest  []byte
	revocationDigest             []byte
	revocationETag               *string
	acceptedAt                   time.Time
}

type manifestRow struct {
	sequence, snapshotRevision uint64
	manifestDigest             []byte
	etag                       string
	encoded                    []byte
	acceptedAt                 time.Time
}

func (store *Store) restoreTx(ctx context.Context, tx pgx.Tx) (Snapshot, error) {
	pins, err := store.trust.KeysetPins(ctx)
	if err != nil || len(pins) == 0 {
		return Snapshot{}, errors.Join(ErrAuthorityUntrusted, err)
	}
	manifests, err := readManifestRows(ctx, tx)
	if err != nil {
		return Snapshot{}, err
	}
	rows, err := tx.Query(ctx, `SELECT revision,previous_revision,keyset_schema,keyset_etag,keyset_active_key_id,
		keyset_payload,keyset_payload_sha256,revocation_sequence,revocation_manifest_sha256,
		revocation_etag,accepted_at FROM control_signer_trust_snapshots ORDER BY revision`)
	if err != nil {
		return Snapshot{}, err
	}
	defer rows.Close()
	var current Snapshot
	for rows.Next() {
		var row snapshotRow
		if err := rows.Scan(&row.revision, &row.previousRevision, &row.keysetSchema, &row.keysetETag,
			&row.keysetActiveKeyID, &row.keysetPayload, &row.keysetDigest, &row.revocationSequence,
			&row.revocationDigest, &row.revocationETag, &row.acceptedAt); err != nil {
			return Snapshot{}, err
		}
		if row.revision != current.Revision+1 || (current.Revision == 0 && row.previousRevision != nil) ||
			(current.Revision > 0 && (row.previousRevision == nil || *row.previousRevision != current.Revision)) ||
			!equalPayloadDigest(row.keysetPayload, row.keysetDigest) || !validStrongETag(row.keysetETag, row.keysetPayload) {
			return Snapshot{}, ErrInvalidStoredState
		}
		verifiedKeyset, verifyErr := entitlementsync.VerifyPublicKeyset(row.keysetPayload, pins, current.Keyset, row.acceptedAt)
		if verifyErr != nil || verifiedKeyset.Schema != row.keysetSchema || verifiedKeyset.ActiveKeyID != row.keysetActiveKeyID {
			return Snapshot{}, errors.Join(ErrInvalidStoredState, verifyErr)
		}
		next := Snapshot{Revision: row.revision, Keyset: verifiedKeyset, KeysetETag: row.keysetETag,
			KeysetPayload: append([]byte(nil), row.keysetPayload...), RevocationHead: current.RevocationHead,
			RevocationETag: current.RevocationETag, Revocations: append([]Revocation(nil), current.Revocations...),
			AcceptedAt: row.acceptedAt.UTC()}
		switch {
		case row.revocationSequence == current.RevocationHead.Sequence:
			if row.revocationSequence == 0 {
				if len(row.revocationDigest) != 0 || row.revocationETag != nil {
					return Snapshot{}, ErrInvalidStoredState
				}
			} else if subtle.ConstantTimeCompare(row.revocationDigest, decodedDigest(current.RevocationHead.ManifestSHA256)) != 1 ||
				row.revocationETag == nil || *row.revocationETag != current.RevocationETag {
				return Snapshot{}, ErrInvalidStoredState
			}
		case row.revocationSequence == current.RevocationHead.Sequence+1:
			manifest, found := manifests[row.revocationSequence]
			if !found || manifest.snapshotRevision != row.revision || !equalPayloadDigest(manifest.encoded,
				decodedDigest(strongETagDigest(manifest.etag))) {
				return Snapshot{}, ErrInvalidStoredState
			}
			verified, verifyErr := verifyManifest(ctx, manifest.encoded, current, store.trust, manifest.acceptedAt)
			if verifyErr != nil || verified.replayed || subtle.ConstantTimeCompare(manifest.manifestDigest, verified.digest[:]) != 1 ||
				subtle.ConstantTimeCompare(row.revocationDigest, verified.digest[:]) != 1 ||
				row.revocationETag == nil || *row.revocationETag != manifest.etag {
				return Snapshot{}, errors.Join(ErrInvalidStoredState, verifyErr)
			}
			revoked := manifestRevocation(verified, manifest.etag, manifest.encoded)
			next.RevocationHead = ChainState{Sequence: revoked.Sequence, ManifestSHA256: revoked.ManifestSHA256}
			next.RevocationETag = revoked.ETag
			next.Revocations = append(next.Revocations, revoked)
		default:
			return Snapshot{}, ErrInvalidStoredState
		}
		current = next
	}
	if err := rows.Err(); err != nil {
		return Snapshot{}, err
	}
	if len(manifests) != int(current.RevocationHead.Sequence) {
		return Snapshot{}, ErrInvalidStoredState
	}
	return current, nil
}

func readManifestRows(ctx context.Context, tx pgx.Tx) (map[uint64]manifestRow, error) {
	rows, err := tx.Query(ctx, `SELECT sequence,snapshot_revision,manifest_sha256,etag,signed_manifest,accepted_at
		FROM control_signer_revocation_manifests ORDER BY sequence`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[uint64]manifestRow)
	for rows.Next() {
		var row manifestRow
		if err := rows.Scan(&row.sequence, &row.snapshotRevision, &row.manifestDigest, &row.etag,
			&row.encoded, &row.acceptedAt); err != nil {
			return nil, err
		}
		if _, exists := result[row.sequence]; exists || !validStrongETag(row.etag, row.encoded) {
			return nil, ErrInvalidStoredState
		}
		result[row.sequence] = row
	}
	return result, rows.Err()
}

func insertSnapshot(ctx context.Context, tx pgx.Tx, previous, snapshot Snapshot) error {
	keysetDigest := sha256.Sum256(snapshot.KeysetPayload)
	var previousRevision any
	if previous.Revision > 0 {
		previousRevision = previous.Revision
	}
	var revocationDigest, revocationETag any
	if snapshot.RevocationHead.Sequence > 0 {
		revocationDigest = decodedDigest(snapshot.RevocationHead.ManifestSHA256)
		revocationETag = snapshot.RevocationETag
	}
	_, err := tx.Exec(ctx, `INSERT INTO control_signer_trust_snapshots(
		revision,previous_revision,keyset_schema,keyset_etag,keyset_active_key_id,keyset_payload,
		keyset_payload_sha256,revocation_sequence,revocation_manifest_sha256,revocation_etag,accepted_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, snapshot.Revision, previousRevision,
		snapshot.Keyset.Schema, snapshot.KeysetETag, snapshot.Keyset.ActiveKeyID, snapshot.KeysetPayload,
		keysetDigest[:], snapshot.RevocationHead.Sequence, revocationDigest, revocationETag, snapshot.AcceptedAt)
	return err
}

func insertManifest(ctx context.Context, tx pgx.Tx, revision uint64, revoked Revocation, manifest Manifest) error {
	var previousSequence, previousDigest any
	if manifest.PreviousSequence != nil {
		previousSequence = *manifest.PreviousSequence
		previousDigest = decodedDigest(*manifest.PreviousManifestSHA256)
	}
	_, err := tx.Exec(ctx, `INSERT INTO control_signer_revocation_manifests(
		sequence,snapshot_revision,previous_sequence,previous_manifest_sha256,manifest_sha256,etag,
		revoked_key_id,revoked_key_generation,artifact_classes,effective_not_before,authority_kind,
		authority_key_id,authority_key_generation,signed_manifest,accepted_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, revoked.Sequence, revision,
		previousSequence, previousDigest, decodedDigest(revoked.ManifestSHA256), revoked.ETag, revoked.RevokedKeyID,
		revoked.RevokedKeyGeneration, artifactStrings(revoked.ArtifactClasses), revoked.EffectiveNotBefore,
		revoked.Authority.Kind, revoked.Authority.KeyID, revoked.Authority.Generation, revoked.Encoded, revoked.AcceptedAt)
	return err
}

type eventRecord struct {
	OperationID        uuid.UUID
	Stage, Result      string
	Reason             string
	SnapshotRevision   uint64
	RevocationSequence uint64
	RevocationDigest   []byte
	KeysetETag         string
	RevocationETag     string
	OccurredAt         time.Time
}

func (store *Store) appendEvent(ctx context.Context, event eventRecord) error {
	return pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error { return appendEventTx(ctx, tx, event) })
}

func appendEventTx(ctx context.Context, tx pgx.Tx, event eventRecord) error {
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", auditLock); err != nil {
		return err
	}
	var position uint64
	var previous []byte
	err := tx.QueryRow(ctx, `SELECT stream_position,event_hash FROM control_signer_revocation_audit
		ORDER BY stream_position DESC LIMIT 1`).Scan(&position, &previous)
	if errors.Is(err, pgx.ErrNoRows) {
		position = 0
		previous = nil
	} else if err != nil {
		return err
	}
	position++
	eventID := uuid.Must(uuid.NewV7())
	eventHash := hashAudit(previous, position, eventID, event)
	var revision, sequence, digest, keysetETag, revocationETag any
	if event.SnapshotRevision > 0 {
		revision = event.SnapshotRevision
	}
	if event.RevocationSequence > 0 {
		sequence = event.RevocationSequence
	}
	if len(event.RevocationDigest) > 0 {
		digest = event.RevocationDigest
	}
	if event.KeysetETag != "" {
		keysetETag = event.KeysetETag
	}
	if event.RevocationETag != "" {
		revocationETag = event.RevocationETag
	}
	if _, err := tx.Exec(ctx, `INSERT INTO control_signer_revocation_events(
		id,stream_position,operation_id,stage,result,reason_code,snapshot_revision,revocation_sequence,
		revocation_manifest_sha256,keyset_etag,revocation_etag,occurred_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, eventID, position, event.OperationID,
		event.Stage, event.Result, event.Reason, revision, sequence, digest, keysetETag, revocationETag,
		event.OccurredAt); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO control_signer_revocation_audit(
		stream_position,event_id,previous_hash,event_hash,occurred_at) VALUES($1,$2,$3,$4,$5)`,
		position, eventID, nullBytes(previous), eventHash[:], event.OccurredAt)
	return err
}

func (store *Store) VerifyAudit(ctx context.Context) error {
	if store == nil || store.pool == nil {
		return ErrInvalidInput
	}
	return pgx.BeginTxFunc(ctx, store.pool,
		pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly},
		func(tx pgx.Tx) error { return verifyAuditTx(ctx, tx) })
}

func verifyAuditTx(ctx context.Context, tx pgx.Tx) error {
	rows, err := tx.Query(ctx, `SELECT audit.stream_position,event.stream_position,audit.event_id,event.id,
		audit.previous_hash,audit.event_hash,event.operation_id,event.stage,event.result,event.reason_code,
		event.snapshot_revision,event.revocation_sequence,event.revocation_manifest_sha256,event.keyset_etag,
		event.revocation_etag,event.occurred_at
		FROM control_signer_revocation_audit audit FULL OUTER JOIN control_signer_revocation_events event
		ON event.id=audit.event_id ORDER BY COALESCE(audit.stream_position,event.stream_position)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var previous []byte
	var expected uint64 = 1
	for rows.Next() {
		var auditPosition, eventPosition *uint64
		var auditEventID, eventID, operationID *uuid.UUID
		var storedPrevious, storedHash, digest []byte
		var stage, result, reason *string
		var revision, sequence *uint64
		var keysetETag, revocationETag *string
		var occurredAt *time.Time
		if err := rows.Scan(&auditPosition, &eventPosition, &auditEventID, &eventID, &storedPrevious, &storedHash,
			&operationID, &stage, &result, &reason, &revision, &sequence, &digest, &keysetETag,
			&revocationETag, &occurredAt); err != nil {
			return err
		}
		if auditPosition == nil || eventPosition == nil || auditEventID == nil || eventID == nil ||
			operationID == nil || stage == nil || result == nil || reason == nil || occurredAt == nil ||
			*auditPosition != *eventPosition || *auditEventID != *eventID {
			return ErrInvalidStoredState
		}
		position := *auditPosition
		event := eventRecord{OperationID: *operationID, Stage: *stage, Result: *result, Reason: *reason,
			RevocationDigest: digest, OccurredAt: *occurredAt}
		if revision != nil {
			event.SnapshotRevision = *revision
		}
		if sequence != nil {
			event.RevocationSequence = *sequence
		}
		if keysetETag != nil {
			event.KeysetETag = *keysetETag
		}
		if revocationETag != nil {
			event.RevocationETag = *revocationETag
		}
		expectedHash := hashAudit(previous, position, *eventID, event)
		if position != expected || subtle.ConstantTimeCompare(storedPrevious, previous) != 1 ||
			subtle.ConstantTimeCompare(storedHash, expectedHash[:]) != 1 {
			return ErrInvalidStoredState
		}
		previous = append([]byte(nil), storedHash...)
		expected++
	}
	return rows.Err()
}

func hashAudit(previous []byte, position uint64, eventID uuid.UUID, event eventRecord) [sha256.Size]byte {
	payload, _ := json.Marshal(struct {
		Position           uint64 `json:"position"`
		EventID            string `json:"event_id"`
		OperationID        string `json:"operation_id"`
		Stage              string `json:"stage"`
		Result             string `json:"result"`
		Reason             string `json:"reason"`
		SnapshotRevision   uint64 `json:"snapshot_revision"`
		RevocationSequence uint64 `json:"revocation_sequence"`
		RevocationDigest   []byte `json:"revocation_digest"`
		KeysetETag         string `json:"keyset_etag"`
		RevocationETag     string `json:"revocation_etag"`
		OccurredAt         string `json:"occurred_at"`
	}{position, eventID.String(), event.OperationID.String(), event.Stage, event.Result, event.Reason,
		event.SnapshotRevision, event.RevocationSequence, event.RevocationDigest, event.KeysetETag,
		event.RevocationETag, canonicalTime(event.OccurredAt)})
	hash := sha256.New()
	writeHashField(hash, previous)
	writeHashField(hash, payload)
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func writeHashField(writer io.Writer, value []byte) {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(value)))
	_, _ = writer.Write(size[:])
	_, _ = writer.Write(value)
}

func rejectionReason(err error) string {
	switch {
	case errors.Is(err, ErrInvalidETag):
		return ReasonInvalidETag
	case errors.Is(err, ErrInvalidManifest):
		return ReasonInvalidManifest
	case errors.Is(err, ErrInvalidSignature):
		return ReasonInvalidSignature
	case errors.Is(err, ErrSequenceReplay):
		return ReasonSequenceReplay
	case errors.Is(err, ErrSequenceConflict):
		return ReasonSequenceConflict
	case errors.Is(err, ErrChainBranch):
		return ReasonChainBranch
	case errors.Is(err, ErrManifestNotCurrent):
		return ReasonManifestNotCurrent
	case errors.Is(err, ErrAuthorityRevoked):
		return ReasonAuthorityRevoked
	case errors.Is(err, ErrAuthorityGeneration):
		return ReasonAuthorityGeneration
	case errors.Is(err, ErrAuthorityUntrusted):
		return ReasonAuthorityUntrusted
	case errors.Is(err, entitlementsync.ErrKeysetRollback):
		return ReasonKeysetRollback
	case errors.Is(err, ErrObservedAtOutOfRange):
		return ReasonObservedAtOutOfRange
	case errors.Is(err, entitlementsync.ErrInvalidKeyset):
		return ReasonInvalidKeyset
	default:
		return ReasonStorageFailure
	}
}

func strongETagDigest(etag string) string {
	if len(etag) < 2 {
		return ""
	}
	return etag[1 : len(etag)-1]
}

func artifactStrings(classes []ArtifactClass) []string {
	result := make([]string, len(classes))
	for index, class := range classes {
		result[index] = string(class)
	}
	return result
}

func nullBytes(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}

var _ SnapshotSource = (*Store)(nil)
