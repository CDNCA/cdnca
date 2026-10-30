package edgeoutbox

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type outboxStore interface {
	claim(context.Context, int, time.Duration) ([]claimedCommand, error)
	markPublished(context.Context, uuid.UUID, time.Time) error
	markFailed(context.Context, uuid.UUID, time.Time, failure, time.Duration, int) error
	markSuperseded(context.Context, uuid.UUID, time.Time) error
}

type postgresStore struct {
	pool *pgxpool.Pool
}

func (s *postgresStore) claim(ctx context.Context, limit int, leaseTimeout time.Duration) ([]claimedCommand, error) {
	rows, err := s.pool.Query(ctx, `
		WITH candidates AS MATERIALIZED (
			SELECT outbox.id
			FROM edge_command_outbox outbox
			WHERE (
				(outbox.status IN ('pending', 'failed') AND outbox.available_at <= CURRENT_TIMESTAMP) OR
				(outbox.status = 'publishing' AND
				 outbox.updated_at <= CURRENT_TIMESTAMP - ($2::bigint * interval '1 microsecond'))
			)
			ORDER BY outbox.available_at, outbox.id
			FOR UPDATE OF outbox SKIP LOCKED
			LIMIT $1
		), claimed AS (
			UPDATE edge_command_outbox outbox
			SET status = 'publishing',
				publish_attempts = outbox.publish_attempts + 1,
				updated_at = CURRENT_TIMESTAMP
			FROM candidates
			WHERE outbox.id = candidates.id
			RETURNING outbox.id, outbox.deployment_id, outbox.deployment_attempt,
				outbox.node_id, outbox.subject, outbox.payload, outbox.payload_sha256,
				outbox.publish_attempts, outbox.updated_at
		)
		SELECT claimed.id, claimed.deployment_id, claimed.deployment_attempt,
			claimed.node_id, claimed.subject, claimed.payload, claimed.payload_sha256,
			claimed.publish_attempts, claimed.updated_at,
			deployment.command_event_id, deployment.node_id,
			deployment.rollout_id, deployment.config_version_id,
			deployment.command_bytes, deployment.command_sha256,
			-- fix-cfgflow2 §3: the deployment already ended (timed out, refused,
			-- cancelled, or a later attempt replaced it). One deployment runs per
			-- node and scope (288/291), so a newer one exists only past this point.
			deployment.state IN ('healthy','failed','reverted','rollback_failed','cancelled') AS superseded
		FROM claimed
		JOIN node_deployments deployment
		  ON deployment.id = claimed.deployment_id
		 AND deployment.attempt = claimed.deployment_attempt
		ORDER BY claimed.id`, limit, leaseTimeout.Microseconds())
	if err != nil {
		return nil, fmt.Errorf("claim edge command outbox: %w", err)
	}
	defer rows.Close()
	commands := make([]claimedCommand, 0, limit)
	for rows.Next() {
		var command claimedCommand
		if err := rows.Scan(
			&command.outboxID, &command.deploymentID, &command.deploymentAttempt,
			&command.nodeID, &command.subject, &command.payload, &command.payloadSHA256,
			&command.publishAttempts, &command.claimToken,
			&command.commandEventID, &command.deploymentNodeID,
			&command.rolloutID, &command.configVersionID,
			&command.commandBytes, &command.commandSHA256, &command.superseded,
		); err != nil {
			return nil, fmt.Errorf("scan claimed edge command: %w", err)
		}
		commands = append(commands, command)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate claimed edge commands: %w", err)
	}
	return commands, nil
}

func (s *postgresStore) markPublished(ctx context.Context, id uuid.UUID, claimToken time.Time) error {
	result, err := s.pool.Exec(ctx, `
		UPDATE edge_command_outbox
		SET status = 'published', published_at = CURRENT_TIMESTAMP,
			last_error = NULL, updated_at = CURRENT_TIMESTAMP
		WHERE id = $1 AND status = 'publishing' AND updated_at = $2`, id, claimToken)
	if err != nil {
		return fmt.Errorf("mark edge command published: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrClaimLost
	}
	return nil
}

func (s *postgresStore) markFailed(
	ctx context.Context,
	id uuid.UUID,
	claimToken time.Time,
	failure failure,
	backoff time.Duration,
	maxErrorBytes int,
) error {
	result, err := s.pool.Exec(ctx, `
		UPDATE edge_command_outbox
		SET status = 'failed',
			available_at = CASE
				WHEN $3::boolean THEN CURRENT_TIMESTAMP + ($4::bigint * interval '1 microsecond')
				ELSE 'infinity'::timestamptz
			END,
			published_at = NULL,
			last_error = $5,
			updated_at = CURRENT_TIMESTAMP
		WHERE id = $1 AND status = 'publishing' AND updated_at = $2`,
		id, claimToken, failure.retryable, backoff.Microseconds(), failure.safeText(maxErrorBytes))
	if err != nil {
		return fmt.Errorf("mark edge command failed: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrClaimLost
	}
	return nil
}

// markSuperseded closes a claimed command that must not be sent (claim's
// superseded): publishing -> failed -> cancelled in one statement each, as
// the outbox state machine (migration 263) allows, with last_error saying why.
func (s *postgresStore) markSuperseded(ctx context.Context, id uuid.UUID, claimToken time.Time) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("close superseded edge command: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	result, err := tx.Exec(ctx, `
		UPDATE edge_command_outbox
		SET status = 'failed', available_at = 'infinity'::timestamptz, published_at = NULL,
			last_error = 'superseded:newer_deployment', updated_at = CURRENT_TIMESTAMP
		WHERE id = $1 AND status = 'publishing' AND updated_at = $2`, id, claimToken)
	if err != nil {
		return fmt.Errorf("close superseded edge command: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrClaimLost
	}
	if _, err := tx.Exec(ctx, `UPDATE edge_command_outbox SET status = 'cancelled', updated_at = CURRENT_TIMESTAMP
		WHERE id = $1 AND status = 'failed'`, id); err != nil {
		return fmt.Errorf("cancel superseded edge command: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("close superseded edge command: %w", err)
	}
	return nil
}
