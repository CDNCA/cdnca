package nodemonitoringoutbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
)

type Store struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

func NewStore(pool *pgxpool.Pool, now func() time.Time) (*Store, error) {
	if pool == nil || now == nil {
		return nil, ErrInvalidInput
	}
	return &Store{pool: pool, now: now}, nil
}

func (store *Store) EnqueueNodeMonitoringArtifact(ctx context.Context, tx pgx.Tx, artifact *agentv1.NodeMonitoringArtifact) error {
	if store == nil || store.pool == nil || ctx == nil || tx == nil || artifact == nil || artifact.Event == nil ||
		artifact.NodeId == "" || artifact.ConfigRevision == 0 || artifact.PublicationSequence != artifact.ConfigRevision ||
		artifact.Schema != agentv1.NodeMonitoringSchema_NODE_MONITORING_SCHEMA_V1 || artifact.Event.OccurredTime == nil ||
		artifact.Event.OccurredTime.CheckValid() != nil ||
		len(artifact.CanonicalConfigJson) == 0 || len(artifact.ConfigSha256) != sha256.Size {
		return ErrInvalidInput
	}
	nodeID, err := uuid.Parse(artifact.NodeId)
	if err != nil || nodeID == uuid.Nil || nodeID.String() != artifact.NodeId {
		return ErrInvalidInput
	}
	payload, err := (proto.MarshalOptions{Deterministic: true}).Marshal(artifact)
	if err != nil || len(payload) == 0 {
		return ErrInvalidInput
	}
	configDigest := sha256.Sum256(artifact.CanonicalConfigJson)
	if !bytes.Equal(configDigest[:], artifact.ConfigSha256) {
		return ErrInvalidInput
	}
	digest := sha256.Sum256(payload)
	eventID, err := uuid.Parse(artifact.Event.EventId)
	if err != nil || eventID == uuid.Nil || eventID.String() != artifact.Event.EventId {
		return ErrInvalidInput
	}
	messageID := CommandMessagePrefix + eventID.String()
	subject := CommandSubjectBase + "." + nodeID.String()
	createdAt := store.now().UTC()
	var existingDigest []byte
	err = tx.QueryRow(ctx, `SELECT payload_sha256 FROM node_monitoring_command_outbox
		WHERE node_id=$1 AND config_revision=$2 FOR UPDATE`, nodeID, artifact.ConfigRevision).Scan(&existingDigest)
	if err == nil {
		if bytes.Equal(existingDigest, digest[:]) {
			return nil
		}
		return ErrConflict
	}
	if err != pgx.ErrNoRows {
		return fmt.Errorf("check node monitoring outbox idempotency: %w", err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO node_monitoring_command_outbox(
		id,event_id,node_id,config_revision,subject,message_id,payload,payload_sha256,
		state,next_attempt_at,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,'pending',$9,$9,$9)`, eventID, eventID, nodeID,
		artifact.ConfigRevision, subject, messageID, payload, digest[:], createdAt)
	if err != nil {
		return fmt.Errorf("enqueue node monitoring artifact: %w", err)
	}
	return nil
}

func (store *Store) ClaimCommands(ctx context.Context, workerID uuid.UUID, limit int, lease time.Duration) ([]Command, error) {
	if store == nil || store.pool == nil || ctx == nil || workerID == uuid.Nil || limit < 1 || limit > 128 || lease <= 0 {
		return nil, ErrInvalidInput
	}
	if err := store.reconcileActiveNodeMonitoring(ctx, limit); err != nil {
		return nil, fmt.Errorf("reconcile active node monitoring: %w", err)
	}
	now := store.now().UTC()
	rows, err := store.pool.Query(ctx, `WITH candidates AS (
		SELECT id FROM node_monitoring_command_outbox
		WHERE (state='pending' AND next_attempt_at<=$1) OR (state='publishing' AND claimed_until<=$1)
		ORDER BY created_at,id FOR UPDATE SKIP LOCKED LIMIT $2
	) UPDATE node_monitoring_command_outbox outbox
	SET state='publishing',claim_token=$3,claimed_until=$4,attempt_count=attempt_count+1,last_error_code=NULL,updated_at=$1
	FROM candidates WHERE outbox.id=candidates.id
	RETURNING outbox.id,outbox.node_id,outbox.config_revision,outbox.subject,outbox.message_id,
		outbox.payload,outbox.payload_sha256,outbox.claim_token,outbox.attempt_count`, now, limit, workerID, now.Add(lease))
	if err != nil {
		return nil, fmt.Errorf("claim node monitoring outbox: %w", err)
	}
	defer rows.Close()
	commands := make([]Command, 0, limit)
	for rows.Next() {
		var command Command
		if err := rows.Scan(&command.ID, &command.NodeID, &command.ConfigRevision, &command.Subject,
			&command.MessageID, &command.Payload, &command.PayloadSHA256, &command.ClaimToken, &command.AttemptCount); err != nil {
			return nil, fmt.Errorf("scan node monitoring outbox: %w", err)
		}
		commands = append(commands, command)
	}
	return commands, rows.Err()
}

func (store *Store) FailCommand(ctx context.Context, command Command, errorCode string) error {
	if store == nil || store.pool == nil || ctx == nil || command.ID == uuid.Nil || command.ClaimToken == uuid.Nil ||
		errorCode == "" || len(errorCode) > 64 || strings.TrimSpace(errorCode) != errorCode {
		return ErrInvalidInput
	}
	result, err := store.pool.Exec(ctx, `UPDATE node_monitoring_command_outbox
		SET state='failed',claim_token=NULL,claimed_until=NULL,last_error_code=$3,updated_at=$4
		WHERE id=$1 AND claim_token=$2 AND state='publishing' AND payload_sha256=$5`, command.ID, command.ClaimToken,
		errorCode, store.now().UTC(), command.PayloadSHA256)
	if err != nil {
		return fmt.Errorf("mark node monitoring command failed: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}

func (store *Store) MarkPublished(ctx context.Context, command Command, stream string, sequence uint64) error {
	if store == nil || store.pool == nil || ctx == nil || command.ID == uuid.Nil || command.ClaimToken == uuid.Nil ||
		stream != CommandStream || sequence == 0 {
		return ErrInvalidInput
	}
	result, err := store.pool.Exec(ctx, `UPDATE node_monitoring_command_outbox
		SET state='published',claim_token=NULL,claimed_until=NULL,puback_stream=$3,puback_sequence=$4,
			published_at=$5,updated_at=$5,last_error_code=NULL
		WHERE id=$1 AND claim_token=$2 AND state='publishing' AND payload_sha256=$6`, command.ID, command.ClaimToken,
		stream, sequence, store.now().UTC(), command.PayloadSHA256)
	if err != nil {
		return fmt.Errorf("mark node monitoring command published: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}

func (store *Store) ReleaseCommand(ctx context.Context, command Command, retryAt time.Time, errorCode string) error {
	if store == nil || store.pool == nil || ctx == nil || command.ID == uuid.Nil || command.ClaimToken == uuid.Nil ||
		retryAt.IsZero() || errorCode == "" || len(errorCode) > 64 || strings.TrimSpace(errorCode) != errorCode {
		return ErrInvalidInput
	}
	result, err := store.pool.Exec(ctx, `UPDATE node_monitoring_command_outbox
		SET state='pending',claim_token=NULL,claimed_until=NULL,next_attempt_at=$3,last_error_code=$4,updated_at=$5
		WHERE id=$1 AND claim_token=$2 AND state='publishing'`, command.ID, command.ClaimToken, retryAt.UTC(), errorCode, store.now().UTC())
	if err != nil {
		return fmt.Errorf("release node monitoring command: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}
