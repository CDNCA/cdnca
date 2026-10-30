package nodecertlifecycle

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresCheckpointStore is the migration-153 adapter. The migration creates
// an immutable history table and a compare-and-swap LKG projection; this code
// can be composed after that migration version is allocated by the root task.
type PostgresCheckpointStore struct{ pool *pgxpool.Pool }

func NewPostgresCheckpointStore(pool *pgxpool.Pool) (*PostgresCheckpointStore, error) {
	if pool == nil {
		return nil, ErrCheckpointInvalid
	}
	return &PostgresCheckpointStore{pool: pool}, nil
}

func (store *PostgresCheckpointStore) Load(ctx context.Context, installationID string) (VerifiedRevocationCheckpoint, bool, error) {
	if store == nil || ctx == nil || !validCheckpointIdentity(installationID) {
		return VerifiedRevocationCheckpoint{}, false, ErrCheckpointInvalid
	}
	var result VerifiedRevocationCheckpoint
	var digest []byte
	err := store.pool.QueryRow(ctx, `SELECT installation_id,revision,issued_at,expires_at,key_id,artifact_sha256,wire_bytes
		FROM node_revocation_checkpoint_lkg WHERE installation_id=$1`, installationID).Scan(
		&result.InstallationID, &result.Revision, &result.IssuedAt, &result.ExpiresAt, &result.KeyID, &digest, &result.WireBytes)
	if errors.Is(err, pgx.ErrNoRows) {
		return VerifiedRevocationCheckpoint{}, false, nil
	}
	if err != nil || len(digest) != 32 || result.Revision == 0 {
		return VerifiedRevocationCheckpoint{}, false, ErrPersistence
	}
	copy(result.Digest[:], digest)
	return result, true, nil
}

func (store *PostgresCheckpointStore) StoreNext(ctx context.Context, checkpoint VerifiedRevocationCheckpoint, previousRevision uint64) error {
	if store == nil || ctx == nil || !validCheckpointIdentity(checkpoint.InstallationID) || checkpoint.Revision <= previousRevision || checkpoint.Digest == [32]byte{} || len(checkpoint.WireBytes) == 0 {
		return ErrCheckpointInvalid
	}
	return pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		var current uint64
		err := tx.QueryRow(ctx, `SELECT revision FROM node_revocation_checkpoint_lkg WHERE installation_id=$1 FOR UPDATE`, checkpoint.InstallationID).Scan(&current)
		if errors.Is(err, pgx.ErrNoRows) {
			if previousRevision != 0 {
				return ErrCheckpointConflict
			}
		} else if err != nil {
			return ErrPersistence
		} else if current != previousRevision {
			return ErrCheckpointConflict
		}
		if _, err := tx.Exec(ctx, `INSERT INTO node_revocation_checkpoint_history(
			installation_id,revision,issued_at,expires_at,key_id,artifact_sha256,wire_bytes)
			VALUES($1,$2,$3,$4,$5,$6,$7)`, checkpoint.InstallationID, checkpoint.Revision, checkpoint.IssuedAt,
			checkpoint.ExpiresAt, checkpoint.KeyID, checkpoint.Digest[:], checkpoint.WireBytes); err != nil {
			return mapDatabaseError(err)
		}
		command, err := tx.Exec(ctx, `INSERT INTO node_revocation_checkpoint_lkg(
			installation_id,revision,issued_at,expires_at,key_id,artifact_sha256,wire_bytes)
			VALUES($1,$2,$3,$4,$5,$6,$7)
			ON CONFLICT (installation_id) DO UPDATE SET revision=EXCLUDED.revision,issued_at=EXCLUDED.issued_at,
			expires_at=EXCLUDED.expires_at,key_id=EXCLUDED.key_id,artifact_sha256=EXCLUDED.artifact_sha256,
			wire_bytes=EXCLUDED.wire_bytes WHERE node_revocation_checkpoint_lkg.revision=$8`, checkpoint.InstallationID,
			checkpoint.Revision, checkpoint.IssuedAt, checkpoint.ExpiresAt, checkpoint.KeyID, checkpoint.Digest[:], checkpoint.WireBytes, previousRevision)
		if err != nil {
			return ErrPersistence
		}
		if command.RowsAffected() != 1 {
			return ErrCheckpointConflict
		}
		return nil
	})
}

var _ CheckpointLKGStore = (*PostgresCheckpointStore)(nil)
