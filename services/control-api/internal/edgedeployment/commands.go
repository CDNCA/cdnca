package edgedeployment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	rolloutOperationStart  = "edge_rollout.start"
	rolloutOperationPause  = "edge_rollout.pause"
	rolloutOperationResume = "edge_rollout.resume"
	rolloutOperationCancel = "edge_rollout.cancel"
	rolloutOperationRetry  = "edge_rollout.retry"
)

type normalizedRolloutCommand struct {
	RolloutCommandRequest
	RequestUUID     uuid.UUID
	CorrelationUUID uuid.UUID
	Digest          [32]byte
}

type commandDeployment struct {
	id           uuid.UUID
	nodeID       uuid.UUID
	attempt      uint32
	configID     uuid.UUID
	previousID   *uuid.UUID
	action       string
	state        string
	commandBytes []byte
	outboxStatus string
	cohort       int
	// superseded: an ignored old release, never retried (fix-cfgflow2 §1).
	superseded bool
}

// retryableFailure: a failed deployment worth another attempt. An ignored
// old release is not: the node already runs a newer revision.
func (d commandDeployment) retryableFailure() bool {
	return deploymentFailed(d.state) && !d.superseded
}

func (s *Store) CancelRollout(ctx context.Context, request RolloutCommandRequest) (RolloutCommandResult, error) {
	return s.runRolloutCommand(ctx, rolloutOperationCancel, request)
}

func (s *Store) StartRollout(ctx context.Context, request RolloutCommandRequest) (RolloutCommandResult, error) {
	return s.runRolloutCommand(ctx, rolloutOperationStart, request)
}

func (s *Store) PauseRollout(ctx context.Context, request RolloutCommandRequest) (RolloutCommandResult, error) {
	return s.runRolloutCommand(ctx, rolloutOperationPause, request)
}

func (s *Store) ResumeRollout(ctx context.Context, request RolloutCommandRequest) (RolloutCommandResult, error) {
	return s.runRolloutCommand(ctx, rolloutOperationResume, request)
}

func (s *Store) RetryRollout(ctx context.Context, request RolloutCommandRequest) (RolloutCommandResult, error) {
	return s.runRolloutCommand(ctx, rolloutOperationRetry, request)
}

func (s *Store) runRolloutCommand(
	ctx context.Context,
	operation string,
	request RolloutCommandRequest,
) (RolloutCommandResult, error) {
	if err := s.protectedOperationError(); err != nil {
		return RolloutCommandResult{}, err
	}
	normalized, err := normalizeRolloutCommand(operation, request)
	if ctx == nil || err != nil {
		return RolloutCommandResult{}, ErrInvalidInput
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	var result RolloutCommandResult
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		authorization, err := s.authorizeSession(
			ctx, tx, normalized.Actor, normalized.ConfigurationScopeID, PermissionManage,
		)
		if err != nil {
			return err
		}
		actorUserID := authorization.UserID()
		replayed, found, err := claimRolloutCommand(ctx, tx, operation, normalized, now)
		if err != nil {
			return err
		}
		if found {
			result = replayed
			result.Replayed = true
			return nil
		}
		var persistedStatus string
		var revision int64
		var maxAttempts int
		var contractVersion int16
		var deadline time.Time
		err = tx.QueryRow(ctx, `
			SELECT status,revision,max_attempts,contract_version,deadline_at
			FROM rollouts WHERE configuration_scope_id=$1 AND id=$2 FOR UPDATE`,
			normalized.ConfigurationScopeID, normalized.RolloutID).Scan(
			&persistedStatus, &revision, &maxAttempts, &contractVersion, &deadline,
		)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("lock rollout command: %w", err)
		}
		if revision != normalized.ExpectedRevision {
			return ErrRevisionConflict
		}
		if operation == rolloutOperationRetry && !deadline.After(now) {
			return ErrDeadlineExpired
		}
		if contractVersion == 2 {
			if operation == rolloutOperationRetry {
				deployments, lockErr := lockCommandDeployments(
					ctx, tx, normalized.ConfigurationScopeID, normalized.RolloutID,
				)
				if lockErr != nil {
					return lockErr
				}
				err = retryFailedCohortDeployments(
					ctx, tx, normalized, persistedStatus, uint32(maxAttempts), deployments, now,
				)
			} else {
				err = runCohortRolloutCommand(ctx, tx, operation, normalized.RolloutID, persistedStatus, now)
			}
		} else {
			deployments, lockErr := lockCommandDeployments(ctx, tx, normalized.ConfigurationScopeID, normalized.RolloutID)
			if lockErr != nil {
				return lockErr
			}
			switch operation {
			case rolloutOperationCancel:
				err = cancelQueuedDeployments(ctx, tx, normalized.RolloutID, persistedStatus, deployments, now)
			case rolloutOperationRetry:
				err = retryFailedDeployments(ctx, tx, normalized, persistedStatus, uint32(maxAttempts), deployments, now)
			default:
				err = ErrInvalidTransition
			}
			if err == nil {
				var command pgconn.CommandTag
				command, err = tx.Exec(ctx, `UPDATE rollouts
						SET status=CASE WHEN $3=$4 THEN 'cancelled' ELSE status END,revision=revision+1,updated_at=$5
						WHERE configuration_scope_id=$1 AND id=$2 AND revision=$6`,
					normalized.ConfigurationScopeID, normalized.RolloutID, operation, rolloutOperationCancel,
					now, normalized.ExpectedRevision)
				if err == nil && command.RowsAffected() != 1 {
					err = ErrRevisionConflict
				}
				if err == nil && operation == rolloutOperationCancel {
					err = projectSiteIPv6RolloutTerminalTx(ctx, tx, normalized.RolloutID, true, now)
				}
			}
		}
		if err != nil {
			return err
		}
		result.Rollout, err = loadRolloutSnapshot(ctx, tx, normalized.ConfigurationScopeID, normalized.RolloutID, now)
		if err != nil {
			return err
		}
		if err := s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: authorization.AuthenticationScopeID(), ActorUserID: &actorUserID,
			Action: operation, ResourceType: "edge_rollout", ResourceID: normalized.RolloutID.String(),
			RequestID: normalized.RequestID, Result: "success",
			Payload: map[string]any{
				"configuration_scope_id": normalized.ConfigurationScopeID.String(),
				"previous_revision":      normalized.ExpectedRevision, "revision": result.Rollout.Revision,
				"state": result.Rollout.State,
			},
		}); err != nil {
			return err
		}
		return completeRolloutCommand(ctx, tx, operation, normalized, result, now)
	})
	return result, stableOperationError(err)
}

func runCohortRolloutCommand(
	ctx context.Context,
	tx pgx.Tx,
	operation string,
	rolloutID uuid.UUID,
	status string,
	now time.Time,
) error {
	rollout, err := lockCohortRollout(ctx, tx, rolloutID)
	if err != nil {
		return err
	}
	switch operation {
	case rolloutOperationStart:
		if status != "queued" || rollout.released != -1 {
			return ErrInvalidTransition
		}
		if released, err := releaseCohortOutboxes(ctx, tx, rolloutID, 0, now); err != nil {
			return err
		} else if released == 0 {
			return ErrInvalidTransition
		}
		command, updateErr := tx.Exec(ctx, `UPDATE rollouts SET status='running',released_cohort=0,started_at=$2,
			pause_reason=NULL,paused_at=NULL,revision=revision+1,updated_at=$2 WHERE id=$1 AND status='queued'`, rolloutID, now)
		err = checkedRolloutUpdate(command, updateErr)
	case rolloutOperationPause:
		if status != "running" {
			return ErrInvalidTransition
		}
		if err := holdCohortOutboxes(ctx, tx, rolloutID, rollout.released, now); err != nil {
			return err
		}
		command, updateErr := tx.Exec(ctx, `UPDATE rollouts SET status='paused',pause_reason='operator',paused_at=$2,
			revision=revision+1,updated_at=$2 WHERE id=$1 AND status='running'`, rolloutID, now)
		err = checkedRolloutUpdate(command, updateErr)
	case rolloutOperationResume:
		if status != "paused" {
			return ErrInvalidTransition
		}
		progress, progressErr := loadCohortProgress(ctx, tx, rolloutID, rollout.released, rollout.action)
		if progressErr != nil {
			return progressErr
		}
		nextStatus, nextReleased := "running", rollout.released
		if progress.terminal == progress.total {
			if rollout.released < rollout.maxCohort {
				nextReleased++
				if released, err := releaseCohortOutboxes(ctx, tx, rolloutID, nextReleased, now); err != nil {
					return err
				} else if released == 0 {
					return ErrInvalidTransition
				}
			} else if progress.succeeded == 0 {
				nextStatus = "failed"
			} else {
				nextStatus = "completed"
			}
		} else if _, err := releaseCohortOutboxes(ctx, tx, rolloutID, rollout.released, now); err != nil {
			return err
		}
		command, updateErr := tx.Exec(ctx, `UPDATE rollouts SET status=$2,released_cohort=$3,pause_reason=NULL,paused_at=NULL,
			revision=revision+1,updated_at=$4 WHERE id=$1 AND status='paused'`, rolloutID, nextStatus, nextReleased, now)
		err = checkedRolloutUpdate(command, updateErr)
	case rolloutOperationCancel:
		if status != "queued" && status != "running" && status != "paused" {
			return ErrInvalidTransition
		}
		if _, err := tx.Exec(ctx, `UPDATE edge_command_outbox outbox SET status='cancelled',updated_at=$2
			FROM node_deployments deployment WHERE deployment.rollout_id=$1
			  AND outbox.deployment_id=deployment.id AND outbox.deployment_attempt=deployment.attempt
			  AND outbox.status IN ('held','pending')`, rolloutID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE node_deployments SET state='cancelled',updated_at=$2
			WHERE rollout_id=$1 AND state='queued'`, rolloutID, now); err != nil {
			return err
		}
		command, updateErr := tx.Exec(ctx, `UPDATE rollouts SET status='cancelled',revision=revision+1,updated_at=$2
			WHERE id=$1 AND status IN ('queued','running','paused')`, rolloutID, now)
		err = checkedRolloutUpdate(command, updateErr)
	default:
		return ErrInvalidTransition
	}
	if err != nil {
		return fmt.Errorf("advance rollout cohort command: %w", err)
	}
	if operation == rolloutOperationCancel {
		return projectSiteIPv6RolloutTerminalTx(ctx, tx, rolloutID, true, now)
	}
	if operation == rolloutOperationResume {
		return projectSiteIPv6RolloutTerminalTx(ctx, tx, rolloutID, false, now)
	}
	return nil
}

func checkedRolloutUpdate(command pgconn.CommandTag, err error) error {
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrInvalidTransition
	}
	return nil
}

func cancelQueuedDeployments(
	ctx context.Context,
	tx pgx.Tx,
	rolloutID uuid.UUID,
	persistedStatus string,
	deployments []commandDeployment,
	now time.Time,
) error {
	if persistedStatus != "queued" || len(deployments) == 0 {
		return ErrInvalidTransition
	}
	for _, deployment := range deployments {
		if deployment.state != "queued" || deployment.outboxStatus != "pending" {
			return ErrInvalidTransition
		}
	}
	if _, err := tx.Exec(ctx, `
		UPDATE edge_command_outbox outbox
		SET status='cancelled',updated_at=$2
		FROM node_deployments deployment
		WHERE deployment.rollout_id=$1
		  AND outbox.deployment_id=deployment.id AND outbox.deployment_attempt=deployment.attempt
		  AND outbox.status='pending'`, rolloutID, now); err != nil {
		return fmt.Errorf("cancel rollout outbox: %w", err)
	}
	command, err := tx.Exec(ctx, `
		UPDATE node_deployments SET state='cancelled',updated_at=$2
		WHERE rollout_id=$1 AND state='queued'`, rolloutID, now)
	if err != nil {
		return fmt.Errorf("cancel rollout deployments: %w", err)
	}
	if command.RowsAffected() != int64(len(deployments)) {
		return ErrInvalidTransition
	}
	return nil
}

func retryFailedCohortDeployments(
	ctx context.Context,
	tx pgx.Tx,
	request normalizedRolloutCommand,
	persistedStatus string,
	maxAttempts uint32,
	deployments []commandDeployment,
	now time.Time,
) error {
	if persistedStatus != "paused" || len(deployments) == 0 {
		return ErrInvalidTransition
	}
	var releasedCohort int
	if err := tx.QueryRow(ctx, `SELECT released_cohort FROM rollouts WHERE id=$1`,
		request.RolloutID).Scan(&releasedCohort); err != nil {
		return fmt.Errorf("read retry rollout cohort: %w", err)
	}
	retryable := make([]commandDeployment, 0, len(deployments))
	for _, deployment := range deployments {
		if deployment.cohort == releasedCohort && deployment.retryableFailure() &&
			deployment.attempt < maxAttempts {
			if err := requireConfigurationOnlyRetry(ctx, tx, deployment.id, deployment.attempt); err != nil {
				return err
			}
			retryable = append(retryable, deployment)
		}
	}
	if len(retryable) == 0 {
		for _, deployment := range deployments {
			if deployment.cohort == releasedCohort && deployment.retryableFailure() &&
				deployment.attempt >= maxAttempts {
				return ErrRetriesExhausted
			}
		}
		return ErrInvalidTransition
	}
	for _, deployment := range retryable {
		if err := appendDeploymentRetry(ctx, tx, request, deployment, "held", now); err != nil {
			return err
		}
	}
	command, err := tx.Exec(ctx, `UPDATE rollouts SET revision=revision+1,updated_at=$2
		WHERE id=$1 AND status='paused'`, request.RolloutID, now)
	return checkedRolloutUpdate(command, err)
}

func retryFailedDeployments(
	ctx context.Context,
	tx pgx.Tx,
	request normalizedRolloutCommand,
	persistedStatus string,
	maxAttempts uint32,
	deployments []commandDeployment,
	now time.Time,
) error {
	if persistedStatus != "queued" || len(deployments) == 0 {
		return ErrInvalidTransition
	}
	for _, deployment := range deployments {
		if err := requireConfigurationOnlyRetry(ctx, tx, deployment.id, deployment.attempt); err != nil {
			return err
		}
	}
	retryable := make([]commandDeployment, 0, len(deployments))
	for _, deployment := range deployments {
		if deployment.retryableFailure() && deployment.attempt < maxAttempts {
			retryable = append(retryable, deployment)
		}
	}
	if len(retryable) == 0 {
		for _, deployment := range deployments {
			if deployment.retryableFailure() && deployment.attempt >= maxAttempts {
				return ErrRetriesExhausted
			}
		}
		return ErrInvalidTransition
	}
	for _, deployment := range retryable {
		if err := appendDeploymentRetry(ctx, tx, request, deployment, "pending", now); err != nil {
			return err
		}
	}
	return nil
}

func appendDeploymentRetry(
	ctx context.Context,
	tx pgx.Tx,
	request normalizedRolloutCommand,
	deployment commandDeployment,
	outboxStatus string,
	now time.Time,
) error {
	command, err := unmarshalDeploymentCommand(deployment.commandBytes)
	if err != nil {
		return err
	}
	eventID := uuid.New()
	command.Attempt = deployment.attempt + 1
	command.Event = &commonv1.EventMetadata{
		EventId: eventID.String(), RequestId: request.RequestUUID.String(), OccurredTime: timestamppb.New(now),
		Traceparent: request.Traceparent, CorrelationId: request.CorrelationUUID.String(), TaskId: cloneString(request.TaskID),
	}
	encoded, err := marshalDeploymentCommand(command)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(encoded)
	nextAttempt := deployment.attempt + 1
	if _, err := tx.Exec(ctx, `
		INSERT INTO node_deployments (
			id,rollout_id,node_id,attempt,config_version_id,previous_config_version_id,
			action,state,cohort,command_event_id,command_bytes,command_sha256,deadline_at,created_at,updated_at,
			queued_per_scope
		)
		SELECT id,rollout_id,node_id,$3,config_version_id,previous_config_version_id,
		       action,'queued',cohort,$4,$5,$6,deadline_at,$7,$7,queued_per_scope
		FROM node_deployments WHERE id=$1 AND attempt=$2`,
		deployment.id, deployment.attempt, nextAttempt, eventID, encoded, digest[:], now); err != nil {
		return fmt.Errorf("append node deployment retry: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO node_deployment_artifacts (
			deployment_id,deployment_attempt,config_version_id,artifact_id,ordinal
		)
		SELECT deployment_id,$3,config_version_id,artifact_id,ordinal
		FROM node_deployment_artifacts
		WHERE deployment_id=$1 AND deployment_attempt=$2`, deployment.id, deployment.attempt, nextAttempt); err != nil {
		return fmt.Errorf("copy deployment retry artifacts: %w", err)
	}
	subject := "cdnca.agent.commands." + deployment.nodeID.String()
	if _, err := tx.Exec(ctx, `
		INSERT INTO edge_command_outbox (
			id,deployment_id,deployment_attempt,node_id,subject,payload,payload_sha256,
			status,available_at,created_at,updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,$9)`,
		uuid.New(), deployment.id, nextAttempt, deployment.nodeID, subject, encoded, digest[:], outboxStatus, now); err != nil {
		return fmt.Errorf("append deployment retry outbox: %w", err)
	}
	return nil
}

func unmarshalDeploymentCommand(encoded []byte) (*agentv1.DeploymentCommand, error) {
	command := new(agentv1.DeploymentCommand)
	if err := proto.Unmarshal(encoded, command); err != nil || command.Event == nil {
		return nil, fmt.Errorf("%w: decode deployment retry command", ErrInvalidInput)
	}
	return command, nil
}

func lockCommandDeployments(ctx context.Context, tx pgx.Tx, scopeID, rolloutID uuid.UUID) ([]commandDeployment, error) {
	rows, err := tx.Query(ctx, `
		SELECT deployment.id,deployment.node_id,deployment.attempt,deployment.config_version_id,
		       deployment.previous_config_version_id,deployment.action,deployment.state,
		       deployment.command_bytes,outbox.status,deployment.cohort,`+SupersededDeploymentSQL+`
		FROM node_deployments deployment
		JOIN rollouts rollout ON rollout.id=deployment.rollout_id
		JOIN edge_command_outbox outbox
		  ON outbox.deployment_id=deployment.id AND outbox.deployment_attempt=deployment.attempt
		WHERE rollout.configuration_scope_id=$1 AND rollout.id=$2
		  AND NOT EXISTS (
		      SELECT 1 FROM node_deployments newer
		      WHERE newer.id=deployment.id AND newer.attempt>deployment.attempt
		  )
		ORDER BY deployment.node_id
		FOR UPDATE OF deployment,outbox`, scopeID, rolloutID)
	if err != nil {
		return nil, fmt.Errorf("lock rollout deployments: %w", err)
	}
	defer rows.Close()
	var result []commandDeployment
	for rows.Next() {
		var item commandDeployment
		var attempt int
		if err := rows.Scan(&item.id, &item.nodeID, &attempt, &item.configID, &item.previousID,
			&item.action, &item.state, &item.commandBytes, &item.outboxStatus, &item.cohort, &item.superseded); err != nil {
			return nil, fmt.Errorf("scan locked rollout deployment: %w", err)
		}
		item.attempt = uint32(attempt)
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate locked rollout deployments: %w", err)
	}
	return result, nil
}

func normalizeRolloutCommand(operation string, request RolloutCommandRequest) (normalizedRolloutCommand, error) {
	requestID, requestErr := uuid.Parse(request.RequestID)
	if request.CorrelationID == "" {
		request.CorrelationID = request.RequestID
	}
	correlationID, correlationErr := uuid.Parse(request.CorrelationID)
	if (operation != rolloutOperationStart && operation != rolloutOperationPause && operation != rolloutOperationResume &&
		operation != rolloutOperationCancel && operation != rolloutOperationRetry) || !validActor(request.Actor) ||
		request.ConfigurationScopeID == uuid.Nil || request.RolloutID == uuid.Nil || request.ExpectedRevision <= 0 ||
		!validIdempotencyKey(request.IdempotencyKey) || requestErr != nil || requestID.String() != request.RequestID ||
		correlationErr != nil || correlationID.String() != request.CorrelationID ||
		len(request.Traceparent) > 512 || strings.TrimSpace(request.Traceparent) != request.Traceparent ||
		(request.TaskID != nil && !identifierPattern.MatchString(*request.TaskID)) {
		return normalizedRolloutCommand{}, ErrInvalidInput
	}
	encoded, err := json.Marshal(struct {
		ScopeID          string `json:"scope_id"`
		RolloutID        string `json:"rollout_id"`
		ExpectedRevision int64  `json:"expected_revision"`
	}{request.ConfigurationScopeID.String(), request.RolloutID.String(), request.ExpectedRevision})
	if err != nil {
		return normalizedRolloutCommand{}, ErrInvalidInput
	}
	return normalizedRolloutCommand{
		RolloutCommandRequest: request, RequestUUID: requestID, CorrelationUUID: correlationID,
		Digest: sha256.Sum256(encoded),
	}, nil
}

func claimRolloutCommand(
	ctx context.Context,
	tx pgx.Tx,
	operation string,
	request normalizedRolloutCommand,
	now time.Time,
) (RolloutCommandResult, bool, error) {
	// The write request references the rollout; a missing rollout must surface
	// as NotFound instead of a foreign-key violation that aborts as Unavailable.
	var rolloutExists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM rollouts WHERE configuration_scope_id=$1 AND id=$2)`,
		request.ConfigurationScopeID, request.RolloutID).Scan(&rolloutExists); err != nil {
		return RolloutCommandResult{}, false, fmt.Errorf("check rollout command target: %w", err)
	}
	if !rolloutExists {
		return RolloutCommandResult{}, false, ErrNotFound
	}
	command, err := tx.Exec(ctx, `
		INSERT INTO edge_rollout_write_requests (
			id,actor_user_id,actor_scope_id,configuration_scope_id,rollout_id,operation,
			idempotency_key,request_digest,expected_revision,request_id,created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT (actor_user_id,operation,idempotency_key) DO NOTHING`,
		uuid.New(), request.Actor.UserID, request.Actor.ScopeID, request.ConfigurationScopeID,
		request.RolloutID, operation, request.IdempotencyKey, request.Digest[:],
		request.ExpectedRevision, request.RequestUUID, now)
	if err != nil {
		return RolloutCommandResult{}, false, fmt.Errorf("claim rollout command: %w", err)
	}
	if command.RowsAffected() == 1 {
		return RolloutCommandResult{}, false, nil
	}
	var persistedDigest, response []byte
	if err := tx.QueryRow(ctx, `
		SELECT request_digest,response_body
		FROM edge_rollout_write_requests
		WHERE actor_user_id=$1 AND operation=$2 AND idempotency_key=$3`,
		request.Actor.UserID, operation, request.IdempotencyKey).Scan(&persistedDigest, &response); err != nil {
		return RolloutCommandResult{}, false, fmt.Errorf("read rollout command replay: %w", err)
	}
	if !bytes.Equal(persistedDigest, request.Digest[:]) {
		return RolloutCommandResult{}, false, ErrIdempotencyConflict
	}
	var result RolloutCommandResult
	if len(response) == 0 || json.Unmarshal(response, &result) != nil {
		return RolloutCommandResult{}, false, fmt.Errorf("read rollout command response: %w", ErrIdempotencyConflict)
	}
	return result, true, nil
}

func completeRolloutCommand(
	ctx context.Context,
	tx pgx.Tx,
	operation string,
	request normalizedRolloutCommand,
	result RolloutCommandResult,
	now time.Time,
) error {
	response, err := json.Marshal(result)
	if err != nil {
		return err
	}
	command, err := tx.Exec(ctx, `
		UPDATE edge_rollout_write_requests
		SET response_body=$4,completed_at=$5
		WHERE actor_user_id=$1 AND operation=$2 AND idempotency_key=$3
		  AND completed_at IS NULL`, request.Actor.UserID, operation, request.IdempotencyKey, response, now)
	if err != nil {
		return fmt.Errorf("complete rollout command: %w", err)
	}
	if command.RowsAffected() != 1 {
		return ErrIdempotencyConflict
	}
	return nil
}
