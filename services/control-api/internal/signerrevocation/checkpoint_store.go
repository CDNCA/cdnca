package signerrevocation

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/signercheckpoint"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	checkpointWriteLock int64 = 501809704351924
	checkpointAuditLock int64 = 501809704351925

	ReasonCheckpointAccepted        = "checkpoint_accepted"
	ReasonCheckpointReplay          = "checkpoint_replay"
	ReasonCheckpointNetworkOutage   = "network_unavailable_lkg_retained"
	ReasonCheckpointServerOutage    = "server_unavailable_lkg_retained"
	ReasonCheckpointRateLimited     = "rate_limited_lkg_retained"
	ReasonCheckpointNotModified     = "not_modified_lkg_retained"
	ReasonCheckpointInvalidResponse = "invalid_response_lkg_retained"
)

type CheckpointLKG struct {
	Checkpoint signercheckpoint.Snapshot
	Runtime    Snapshot
	ETag       string
	AcceptedAt time.Time
}

type CheckpointStore struct {
	pool  *pgxpool.Pool
	trust signercheckpoint.TrustSource
	now   func() time.Time
}

func NewCheckpointStore(pool *pgxpool.Pool, trust signercheckpoint.TrustSource, now func() time.Time) *CheckpointStore {
	return &CheckpointStore{pool: pool, trust: trust, now: now}
}

func (store *CheckpointStore) RestoreV2(ctx context.Context) (CheckpointLKG, error) {
	if store == nil || store.pool == nil || store.trust == nil {
		return CheckpointLKG{}, ErrInvalidInput
	}
	var lkg CheckpointLKG
	err := pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly},
		func(tx pgx.Tx) error {
			var err error
			lkg, err = store.restoreCheckpointTx(ctx, tx)
			return err
		})
	return lkg, err
}

func (store *CheckpointStore) AcceptV2(ctx context.Context, operationID uuid.UUID, encoded []byte, etag string,
	observedAt time.Time) (CheckpointLKG, error) {
	if store == nil || store.pool == nil || store.trust == nil || store.now == nil || operationID == uuid.Nil ||
		observedAt.IsZero() || !validStrongETag(etag, encoded) {
		return CheckpointLKG{}, ErrInvalidInput
	}
	verifyAt := store.now().UTC().Truncate(time.Microsecond)
	observedAt = observedAt.UTC().Truncate(time.Microsecond)
	if verifyAt.IsZero() || observedAt.Before(verifyAt.Add(-maxCandidateClockSkew)) ||
		observedAt.After(verifyAt.Add(maxCandidateClockSkew)) {
		return CheckpointLKG{}, ErrObservedAtOutOfRange
	}
	var accepted CheckpointLKG
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", checkpointWriteLock); err != nil {
			return err
		}
		previous, err := store.restoreCheckpointTx(ctx, tx)
		if errors.Is(err, ErrNoSnapshot) {
			previous = CheckpointLKG{}
		} else if err != nil {
			return err
		}
		projection, err := signercheckpoint.VerifyCandidate(ctx, encoded, previous.Checkpoint, store.trust, verifyAt)
		if err != nil {
			return err
		}
		eventType, reason := "accept", ReasonCheckpointAccepted
		if projection.Replayed {
			eventType, reason = "replay", ReasonCheckpointReplay
			accepted = previous
		} else {
			accepted, err = store.checkpointLKG(ctx, projection.Snapshot, etag, verifyAt)
			if err != nil {
				return err
			}
			if err := insertCheckpointProjection(ctx, tx, projection, previous.Checkpoint.Revision, etag, verifyAt); err != nil {
				return err
			}
		}
		return appendCheckpointAuditTx(ctx, tx, checkpointAuditRecord{
			OperationID: operationID, EventType: eventType, Reason: reason,
			Revision: projection.Snapshot.Revision, CheckpointSHA256: projection.Snapshot.CheckpointSHA256,
			ETag: etag, OccurredAt: verifyAt,
		})
	})
	if err != nil {
		return CheckpointLKG{}, err
	}
	return accepted, nil
}

func (store *CheckpointStore) RecordCheckpointOutage(ctx context.Context, operationID uuid.UUID, reason string,
	observedAt time.Time) error {
	if store == nil || store.pool == nil || operationID == uuid.Nil || observedAt.IsZero() || !checkpointOutageReason(reason) {
		return ErrInvalidInput
	}
	return pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := verifyCheckpointAuditTx(ctx, tx); err != nil {
			return err
		}
		return appendCheckpointAuditTx(ctx, tx, checkpointAuditRecord{
			OperationID: operationID, EventType: "outage", Reason: reason,
			OccurredAt: observedAt.UTC().Truncate(time.Microsecond),
		})
	})
}

func checkpointOutageReason(reason string) bool {
	switch reason {
	case ReasonCheckpointNetworkOutage, ReasonCheckpointServerOutage, ReasonCheckpointRateLimited,
		ReasonCheckpointNotModified, ReasonCheckpointInvalidResponse:
		return true
	default:
		return false
	}
}

type checkpointSnapshotRow struct {
	revision, headSequence                     uint64
	acceptedPreviousRevision, previousRevision *uint64
	previousCheckpointSHA256, checkpointSHA256 []byte
	etag                                       string
	encoded, keysetPayload, keysetSHA256       []byte
	headManifestSHA256                         []byte
	acceptedAt                                 time.Time
}

type checkpointManifestRow struct {
	sequence                       uint64
	previousSequence               *uint64
	previousManifestSHA256         []byte
	manifestSHA256, signedManifest []byte
}

func (store *CheckpointStore) restoreCheckpointTx(ctx context.Context, tx pgx.Tx) (CheckpointLKG, error) {
	if err := verifyCheckpointAuditTx(ctx, tx); err != nil {
		return CheckpointLKG{}, err
	}
	manifests, err := readCheckpointManifestRows(ctx, tx)
	if err != nil {
		return CheckpointLKG{}, err
	}
	rows, err := tx.Query(ctx, `SELECT revision,accepted_previous_revision,previous_revision,
		previous_checkpoint_sha256,checkpoint_sha256,
		etag,signed_checkpoint,keyset_payload,keyset_sha256,head_sequence,head_manifest_sha256,accepted_at
		FROM control_signer_checkpoint_snapshots ORDER BY revision`)
	if err != nil {
		return CheckpointLKG{}, err
	}
	defer rows.Close()
	var current signercheckpoint.Snapshot
	var currentETag string
	var acceptedAt time.Time
	for rows.Next() {
		var row checkpointSnapshotRow
		if err := rows.Scan(&row.revision, &row.acceptedPreviousRevision, &row.previousRevision,
			&row.previousCheckpointSHA256,
			&row.checkpointSHA256, &row.etag, &row.encoded, &row.keysetPayload, &row.keysetSHA256,
			&row.headSequence, &row.headManifestSHA256, &row.acceptedAt); err != nil {
			return CheckpointLKG{}, err
		}
		if row.revision <= current.Revision || !validStrongETag(row.etag, row.encoded) ||
			!equalPayloadDigest(row.keysetPayload, row.keysetSHA256) {
			return CheckpointLKG{}, ErrInvalidStoredState
		}
		if current.Revision == 0 {
			if row.acceptedPreviousRevision != nil {
				return CheckpointLKG{}, ErrInvalidStoredState
			}
		} else if row.acceptedPreviousRevision == nil || *row.acceptedPreviousRevision != current.Revision {
			return CheckpointLKG{}, ErrInvalidStoredState
		}
		projection, verifyErr := signercheckpoint.VerifyCandidate(ctx, row.encoded, current, store.trust, row.acceptedAt)
		if verifyErr != nil || projection.Snapshot.Revision != row.revision ||
			projection.Snapshot.CheckpointSHA256 != encodeCheckpointDigest(row.checkpointSHA256) ||
			!equalBytes(projection.Snapshot.KeysetPayload, row.keysetPayload) ||
			projection.Snapshot.HeadSequence != row.headSequence ||
			projection.Snapshot.HeadManifestSHA256 != encodeCheckpointDigest(row.headManifestSHA256) ||
			!checkpointManifestProjectionMatches(projection.Snapshot.Manifests, manifests[row.revision]) {
			return CheckpointLKG{}, errors.Join(ErrInvalidStoredState, verifyErr)
		}
		wire := projection.Signed.Checkpoint
		if (wire.PreviousRevision == nil) != (row.previousRevision == nil) ||
			(wire.PreviousRevision != nil && *wire.PreviousRevision != *row.previousRevision) ||
			(wire.PreviousCheckpointSHA256 == nil) != (len(row.previousCheckpointSHA256) == 0) ||
			(wire.PreviousCheckpointSHA256 != nil && subtle.ConstantTimeCompare(row.previousCheckpointSHA256,
				decodedCheckpointDigest(*wire.PreviousCheckpointSHA256)) != 1) {
			return CheckpointLKG{}, ErrInvalidStoredState
		}
		delete(manifests, row.revision)
		current, currentETag, acceptedAt = projection.Snapshot, row.etag, row.acceptedAt.UTC()
	}
	if err := rows.Err(); err != nil {
		return CheckpointLKG{}, err
	}
	if err := verifyCheckpointAuditProjectionTx(ctx, tx); err != nil {
		return CheckpointLKG{}, err
	}
	if current.Revision == 0 {
		return CheckpointLKG{}, ErrNoSnapshot
	}
	if len(manifests) != 0 {
		return CheckpointLKG{}, ErrInvalidStoredState
	}
	return store.checkpointLKG(ctx, current, currentETag, acceptedAt)
}

func verifyCheckpointAuditProjectionTx(ctx context.Context, tx pgx.Tx) error {
	var invalid bool
	err := tx.QueryRow(ctx, `SELECT
		EXISTS (
			SELECT snapshot.revision
			FROM control_signer_checkpoint_snapshots snapshot
			LEFT JOIN control_signer_checkpoint_audit audit
			  ON audit.event_type='accept'
			 AND audit.reason_code=$1
			 AND audit.checkpoint_revision=snapshot.revision
			 AND audit.checkpoint_sha256=snapshot.checkpoint_sha256
			 AND audit.etag=snapshot.etag
			 AND audit.occurred_at=snapshot.accepted_at
			GROUP BY snapshot.revision
			HAVING count(audit.stream_position) <> 1
		) OR EXISTS (
			SELECT 1
			FROM control_signer_checkpoint_audit audit
			WHERE audit.event_type='accept' AND NOT EXISTS (
				SELECT 1
				FROM control_signer_checkpoint_snapshots snapshot
				WHERE audit.reason_code=$1
				  AND snapshot.revision=audit.checkpoint_revision
				  AND snapshot.checkpoint_sha256=audit.checkpoint_sha256
				  AND snapshot.etag=audit.etag
				  AND snapshot.accepted_at=audit.occurred_at
			)
		)`, ReasonCheckpointAccepted).Scan(&invalid)
	if err != nil {
		return err
	}
	if invalid {
		return ErrInvalidStoredState
	}
	return nil
}

func (store *CheckpointStore) checkpointLKG(ctx context.Context, checkpoint signercheckpoint.Snapshot, etag string,
	acceptedAt time.Time) (CheckpointLKG, error) {
	pins, err := store.trust.KeysetPins(ctx)
	if err != nil || len(pins) == 0 {
		return CheckpointLKG{}, errors.Join(ErrAuthorityUntrusted, err)
	}
	keyset, err := signercheckpoint.CanonicalKeyset(checkpoint.KeysetPayload, pins, acceptedAt)
	if err != nil {
		return CheckpointLKG{}, errors.Join(ErrInvalidStoredState, err)
	}
	runtimeSnapshot := Snapshot{
		Revision: checkpoint.Revision, Keyset: keyset, KeysetETag: strongETag(checkpoint.KeysetPayload),
		KeysetPayload:  append([]byte(nil), checkpoint.KeysetPayload...),
		RevocationHead: ChainState{Sequence: checkpoint.HeadSequence, ManifestSHA256: checkpoint.HeadManifestSHA256},
		AcceptedAt:     acceptedAt.UTC(),
	}
	runtimeSnapshot.Revocations = make([]Revocation, len(checkpoint.Manifests))
	for index, signed := range checkpoint.Manifests {
		manifestBytes, encodeErr := signercheckpoint.EncodeManifest(signed)
		effective, timeErr := time.Parse(time.RFC3339Nano, signed.Manifest.EffectiveNotBefore)
		if encodeErr != nil || timeErr != nil {
			return CheckpointLKG{}, errors.Join(ErrInvalidStoredState, encodeErr, timeErr)
		}
		classes := make([]ArtifactClass, len(signed.Manifest.ArtifactClasses))
		for classIndex, class := range signed.Manifest.ArtifactClasses {
			classes[classIndex] = ArtifactClass(class)
		}
		runtimeSnapshot.Revocations[index] = Revocation{
			Sequence: signed.Manifest.Sequence, ManifestSHA256: signed.Envelope.ManifestSHA256,
			ETag: strongETag(manifestBytes), RevokedKeyID: signed.Manifest.RevokedKeyID,
			RevokedKeyGeneration: signed.Manifest.RevokedKeyGeneration, ArtifactClasses: classes,
			EffectiveNotBefore: effective.UTC(), Authority: AuthorityRef{Kind: AuthorityKind(signed.Envelope.AuthorityKind),
				KeyID: signed.Envelope.AuthorityKeyID, Generation: signed.Envelope.AuthorityKeyGeneration},
			Encoded: manifestBytes, AcceptedAt: acceptedAt.UTC(),
		}
	}
	if len(runtimeSnapshot.Revocations) > 0 {
		runtimeSnapshot.RevocationETag = runtimeSnapshot.Revocations[len(runtimeSnapshot.Revocations)-1].ETag
	}
	return CheckpointLKG{Checkpoint: checkpoint, Runtime: runtimeSnapshot, ETag: etag, AcceptedAt: acceptedAt.UTC()}, nil
}

func insertCheckpointProjection(ctx context.Context, tx pgx.Tx, projection signercheckpoint.Projection,
	acceptedPreviousRevision uint64, etag string, acceptedAt time.Time) error {
	snapshot, checkpoint := projection.Snapshot, projection.Signed.Checkpoint
	var previousRevision, previousCheckpointDigest any
	if checkpoint.PreviousRevision != nil {
		previousRevision = *checkpoint.PreviousRevision
		previousCheckpointDigest = decodedCheckpointDigest(*checkpoint.PreviousCheckpointSHA256)
	}
	var headDigest any
	if snapshot.HeadSequence > 0 {
		headDigest = decodedCheckpointDigest(snapshot.HeadManifestSHA256)
	}
	keysetDigest := sha256.Sum256(snapshot.KeysetPayload)
	var acceptedPrevious any
	if acceptedPreviousRevision > 0 {
		acceptedPrevious = acceptedPreviousRevision
	}
	if _, err := tx.Exec(ctx, `INSERT INTO control_signer_checkpoint_snapshots(
		revision,accepted_previous_revision,previous_revision,previous_checkpoint_sha256,checkpoint_sha256,etag,signed_checkpoint,
		keyset_payload,keyset_sha256,head_sequence,head_manifest_sha256,accepted_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, snapshot.Revision, acceptedPrevious, previousRevision,
		previousCheckpointDigest, decodedCheckpointDigest(snapshot.CheckpointSHA256), etag, projection.Encoded,
		snapshot.KeysetPayload, keysetDigest[:], snapshot.HeadSequence, headDigest, acceptedAt); err != nil {
		return err
	}
	for _, signed := range snapshot.Manifests {
		manifestBytes, err := signercheckpoint.EncodeManifest(signed)
		if err != nil {
			return err
		}
		var previousSequence, previousManifestDigest any
		if signed.Manifest.PreviousSequence != nil {
			previousSequence = *signed.Manifest.PreviousSequence
			previousManifestDigest = decodedCheckpointDigest(*signed.Manifest.PreviousManifestSHA256)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO control_signer_checkpoint_manifests(
			checkpoint_revision,sequence,previous_sequence,previous_manifest_sha256,manifest_sha256,signed_manifest)
			VALUES($1,$2,$3,$4,$5,$6)`, snapshot.Revision, signed.Manifest.Sequence, previousSequence,
			previousManifestDigest, decodedCheckpointDigest(signed.Envelope.ManifestSHA256), manifestBytes); err != nil {
			return err
		}
	}
	return nil
}

func readCheckpointManifestRows(ctx context.Context, tx pgx.Tx) (map[uint64][]checkpointManifestRow, error) {
	rows, err := tx.Query(ctx, `SELECT checkpoint_revision,sequence,previous_sequence,previous_manifest_sha256,
		manifest_sha256,signed_manifest FROM control_signer_checkpoint_manifests ORDER BY checkpoint_revision,sequence`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[uint64][]checkpointManifestRow)
	for rows.Next() {
		var revision uint64
		var row checkpointManifestRow
		if err := rows.Scan(&revision, &row.sequence, &row.previousSequence, &row.previousManifestSHA256,
			&row.manifestSHA256, &row.signedManifest); err != nil {
			return nil, err
		}
		result[revision] = append(result[revision], row)
	}
	return result, rows.Err()
}

func checkpointManifestProjectionMatches(manifests []signercheckpoint.SignedSignerRevocationManifest,
	rows []checkpointManifestRow) bool {
	if len(manifests) != len(rows) {
		return false
	}
	for index, signed := range manifests {
		encoded, err := signercheckpoint.EncodeManifest(signed)
		row := rows[index]
		if err != nil || row.sequence != signed.Manifest.Sequence || !equalBytes(row.signedManifest, encoded) ||
			subtle.ConstantTimeCompare(row.manifestSHA256, decodedCheckpointDigest(signed.Envelope.ManifestSHA256)) != 1 {
			return false
		}
		if signed.Manifest.PreviousSequence == nil {
			if row.previousSequence != nil || len(row.previousManifestSHA256) != 0 {
				return false
			}
		} else if row.previousSequence == nil || *row.previousSequence != *signed.Manifest.PreviousSequence ||
			subtle.ConstantTimeCompare(row.previousManifestSHA256,
				decodedCheckpointDigest(*signed.Manifest.PreviousManifestSHA256)) != 1 {
			return false
		}
	}
	return true
}

type checkpointAuditRecord struct {
	OperationID      uuid.UUID
	EventType        string
	Reason           string
	Revision         uint64
	CheckpointSHA256 string
	ETag             string
	OccurredAt       time.Time
}

type checkpointAuditDocument struct {
	Position         uint64 `json:"position"`
	OperationID      string `json:"operation_id"`
	EventType        string `json:"event_type"`
	Reason           string `json:"reason_code"`
	Revision         uint64 `json:"checkpoint_revision"`
	CheckpointSHA256 string `json:"checkpoint_sha256"`
	ETag             string `json:"etag"`
	OccurredAt       string `json:"occurred_at"`
	PreviousHash     string `json:"previous_hash"`
}

func appendCheckpointAuditTx(ctx context.Context, tx pgx.Tx, record checkpointAuditRecord) error {
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", checkpointAuditLock); err != nil {
		return err
	}
	var position uint64
	var previousHash []byte
	err := tx.QueryRow(ctx, `SELECT stream_position,event_hash FROM control_signer_checkpoint_audit
		ORDER BY stream_position DESC LIMIT 1 FOR UPDATE`).Scan(&position, &previousHash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	position++
	eventHash, err := checkpointAuditHash(position, record, previousHash)
	if err != nil {
		return err
	}
	var revision, digest, etag any
	if record.Revision > 0 {
		revision, digest, etag = record.Revision, decodedCheckpointDigest(record.CheckpointSHA256), record.ETag
	}
	_, err = tx.Exec(ctx, `INSERT INTO control_signer_checkpoint_audit(
		stream_position,operation_id,event_type,reason_code,checkpoint_revision,checkpoint_sha256,etag,
		occurred_at,previous_hash,event_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		position, record.OperationID, record.EventType, record.Reason, revision, digest, etag,
		record.OccurredAt, nullBytes(previousHash), eventHash)
	return err
}

func verifyCheckpointAuditTx(ctx context.Context, tx pgx.Tx) error {
	rows, err := tx.Query(ctx, `SELECT stream_position,operation_id,event_type,reason_code,checkpoint_revision,
		checkpoint_sha256,etag,occurred_at,previous_hash,event_hash
		FROM control_signer_checkpoint_audit ORDER BY stream_position`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var expectedPosition uint64 = 1
	var previousHash []byte
	for rows.Next() {
		var position uint64
		var revision *uint64
		var operationID uuid.UUID
		var eventType, reason string
		var etag *string
		var checkpointDigest, storedPrevious, eventHash []byte
		var occurredAt time.Time
		if err := rows.Scan(&position, &operationID, &eventType, &reason, &revision, &checkpointDigest, &etag,
			&occurredAt, &storedPrevious, &eventHash); err != nil {
			return err
		}
		if position != expectedPosition || subtle.ConstantTimeCompare(storedPrevious, previousHash) != 1 {
			return ErrInvalidStoredState
		}
		record := checkpointAuditRecord{OperationID: operationID, EventType: eventType, Reason: reason,
			CheckpointSHA256: encodeCheckpointDigest(checkpointDigest), OccurredAt: occurredAt}
		if revision != nil {
			record.Revision = *revision
		}
		if etag != nil {
			record.ETag = *etag
		}
		expectedHash, err := checkpointAuditHash(position, record, previousHash)
		if err != nil || subtle.ConstantTimeCompare(eventHash, expectedHash) != 1 {
			return errors.Join(ErrInvalidStoredState, err)
		}
		previousHash = append(previousHash[:0], eventHash...)
		expectedPosition++
	}
	return rows.Err()
}

func checkpointAuditHash(position uint64, record checkpointAuditRecord, previousHash []byte) ([]byte, error) {
	document := checkpointAuditDocument{
		Position: position, OperationID: record.OperationID.String(), EventType: record.EventType,
		Reason: record.Reason, Revision: record.Revision, CheckpointSHA256: record.CheckpointSHA256,
		ETag: record.ETag, OccurredAt: record.OccurredAt.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano),
		PreviousHash: base64.RawURLEncoding.EncodeToString(previousHash),
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("encode signer checkpoint audit: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return digest[:], nil
}

func decodedCheckpointDigest(value string) []byte {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil
	}
	return decoded
}

func encodeCheckpointDigest(value []byte) string {
	if len(value) == 0 {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(value)
}
