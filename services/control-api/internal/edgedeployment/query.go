package edgedeployment

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type deploymentCursor struct {
	NodeID       uuid.UUID `json:"node_id"`
	DeploymentID uuid.UUID `json:"deployment_id"`
}

type rolloutCursor struct {
	CreatedAt time.Time `json:"created_at"`
	RolloutID uuid.UUID `json:"rollout_id"`
}

func (s *Store) GetRollout(ctx context.Context, actor Actor, scopeID, rolloutID uuid.UUID) (RolloutSnapshot, error) {
	if err := s.protectedOperationError(); err != nil {
		return RolloutSnapshot{}, err
	}
	if ctx == nil || !validActor(actor) || scopeID == uuid.Nil || rolloutID == uuid.Nil {
		return RolloutSnapshot{}, ErrInvalidInput
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	var result RolloutSnapshot
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead}, func(tx pgx.Tx) error {
		if _, err := s.authorizeSession(ctx, tx, actor, scopeID, PermissionRead); err != nil {
			return err
		}
		var err error
		result, err = loadRolloutSnapshot(ctx, tx, scopeID, rolloutID, now)
		return err
	})
	return result, stableOperationError(err)
}

func loadRolloutSnapshot(
	ctx context.Context,
	tx pgx.Tx,
	scopeID, rolloutID uuid.UUID,
	now time.Time,
) (RolloutSnapshot, error) {
	var result RolloutSnapshot
	var persistedState string
	var maxAttempts int
	var contractVersion int16
	var strategy string
	var canarySize, batchSize, failureThreshold int
	var pauseReason *string
	var deadline time.Time
	if err := tx.QueryRow(ctx, `
		SELECT id,configuration_scope_id,config_version_id,action,status,revision,max_attempts,
		       created_at,updated_at,contract_version,strategy,canary_size,batch_size,failure_threshold,
		       released_cohort,pause_reason,deadline_at
		FROM rollouts WHERE configuration_scope_id=$1 AND id=$2`, scopeID, rolloutID).Scan(
		&result.ID, &result.ConfigurationScopeID, &result.ConfigVersionID, &result.Action,
		&persistedState, &result.Revision, &maxAttempts, &result.CreatedAt, &result.UpdatedAt,
		&contractVersion, &strategy, &canarySize, &batchSize, &failureThreshold,
		&result.ReleasedCohort, &pauseReason, &deadline); errors.Is(err, pgx.ErrNoRows) {
		return RolloutSnapshot{}, ErrNotFound
	} else if err != nil {
		return RolloutSnapshot{}, fmt.Errorf("read rollout: %w", err)
	}
	result.MaxAttempts = uint32(maxAttempts)
	if pauseReason != nil {
		result.PauseReason = *pauseReason
	}
	deployments, err := loadLatestDeployments(
		ctx, tx, scopeID, rolloutID, result.MaxAttempts, deadline.After(now), nil, 10001,
	)
	if err != nil {
		return RolloutSnapshot{}, err
	}
	if len(deployments) == 0 || len(deployments) > 10000 {
		return RolloutSnapshot{}, fmt.Errorf("%w: rollout deployment count", ErrInvalidInput)
	}
	if contractVersion == 2 {
		result.Policy = RolloutPolicy{Strategy: strategy, CanarySize: uint32(canarySize), BatchSize: uint32(batchSize),
			FailureThreshold: uint32(failureThreshold), CohortCount: deployments[len(deployments)-1].Cohort + 1}
	}
	applyRolloutAggregate(&result, persistedState, deployments)
	return result, nil
}

func (s *Store) ListRollouts(
	ctx context.Context,
	actor Actor,
	scopeID uuid.UUID,
	request RolloutPageRequest,
) (RolloutPage, error) {
	if err := s.protectedOperationError(); err != nil {
		return RolloutPage{}, err
	}
	if ctx == nil || !validActor(actor) || scopeID == uuid.Nil || request.Limit < 0 || request.Limit > 100 {
		return RolloutPage{}, ErrInvalidInput
	}
	if request.Limit == 0 {
		request.Limit = 20
	}
	cursor, err := decodeRolloutCursor(request.Cursor)
	if err != nil {
		return RolloutPage{}, ErrInvalidInput
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	var result RolloutPage
	err = pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead}, func(tx pgx.Tx) error {
		if _, err := s.authorizeSession(ctx, tx, actor, scopeID, PermissionRead); err != nil {
			return err
		}
		var cursorTime *time.Time
		var cursorID *uuid.UUID
		if cursor != nil {
			cursorTime, cursorID = &cursor.CreatedAt, &cursor.RolloutID
		}
		rows, err := tx.Query(ctx, `
			SELECT id,created_at FROM rollouts
			WHERE configuration_scope_id=$1
			  AND ($2::timestamptz IS NULL OR (created_at,id) < ($2,$3))
			ORDER BY created_at DESC,id DESC LIMIT $4`, scopeID, cursorTime, cursorID, request.Limit+1)
		if err != nil {
			return fmt.Errorf("list rollouts: %w", err)
		}
		var keys []rolloutCursor
		for rows.Next() {
			var key rolloutCursor
			if err := rows.Scan(&key.RolloutID, &key.CreatedAt); err != nil {
				rows.Close()
				return fmt.Errorf("scan rollout page key: %w", err)
			}
			keys = append(keys, key)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("iterate rollout page keys: %w", err)
		}
		rows.Close()
		if len(keys) > request.Limit {
			result.NextCursor, err = encodeRolloutCursor(keys[request.Limit-1])
			if err != nil {
				return fmt.Errorf("encode rollout cursor: %w", err)
			}
			keys = keys[:request.Limit]
		}
		result.Items = make([]RolloutSnapshot, 0, len(keys))
		for _, key := range keys {
			item, err := loadRolloutSnapshot(ctx, tx, scopeID, key.RolloutID, now)
			if err != nil {
				return err
			}
			result.Items = append(result.Items, item)
		}
		return nil
	})
	return result, stableOperationError(err)
}

func (s *Store) ListDeployments(
	ctx context.Context,
	actor Actor,
	scopeID, rolloutID uuid.UUID,
	request DeploymentPageRequest,
) (DeploymentPage, error) {
	if err := s.protectedOperationError(); err != nil {
		return DeploymentPage{}, err
	}
	if ctx == nil || !validActor(actor) || scopeID == uuid.Nil || rolloutID == uuid.Nil || request.Limit < 0 || request.Limit > 100 {
		return DeploymentPage{}, ErrInvalidInput
	}
	if request.Limit == 0 {
		request.Limit = 20
	}
	cursor, err := decodeDeploymentCursor(request.Cursor)
	if err != nil {
		return DeploymentPage{}, ErrInvalidInput
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	var result DeploymentPage
	err = pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead}, func(tx pgx.Tx) error {
		if _, err := s.authorizeSession(ctx, tx, actor, scopeID, PermissionRead); err != nil {
			return err
		}
		var maxAttempts int
		var deadline time.Time
		if err := tx.QueryRow(ctx, `
			SELECT max_attempts,deadline_at FROM rollouts
			WHERE configuration_scope_id=$1 AND id=$2`, scopeID, rolloutID).Scan(
			&maxAttempts, &deadline,
		); errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return fmt.Errorf("read rollout deployment limit: %w", err)
		}
		items, err := loadLatestDeployments(
			ctx, tx, scopeID, rolloutID, uint32(maxAttempts), deadline.After(now), cursor, request.Limit+1,
		)
		if err != nil {
			return err
		}
		if len(items) > request.Limit {
			last := items[request.Limit-1]
			result.NextCursor, err = encodeDeploymentCursor(deploymentCursor{NodeID: last.NodeID, DeploymentID: last.ID})
			if err != nil {
				return err
			}
			items = items[:request.Limit]
		}
		result.Items = items
		return nil
	})
	return result, stableOperationError(err)
}

func loadLatestDeployments(
	ctx context.Context,
	tx pgx.Tx,
	scopeID, rolloutID uuid.UUID,
	maxAttempts uint32,
	retryAllowed bool,
	cursor *deploymentCursor,
	limit int,
) ([]DeploymentSnapshot, error) {
	var cursorNodeID, cursorDeploymentID *uuid.UUID
	if cursor != nil {
		cursorNodeID, cursorDeploymentID = &cursor.NodeID, &cursor.DeploymentID
	}
	rows, err := tx.Query(ctx, `
		WITH latest AS (
			SELECT DISTINCT ON (deployment.id)
			       deployment.id,deployment.node_id,deployment.attempt,deployment.state,deployment.cohort,
			       deployment.created_at,deployment.updated_at
			FROM node_deployments deployment
			JOIN rollouts rollout ON rollout.id=deployment.rollout_id
			WHERE rollout.configuration_scope_id=$1 AND rollout.id=$2
			ORDER BY deployment.id,deployment.attempt DESC
		)
		SELECT latest.id,latest.node_id,latest.attempt,latest.state,latest.cohort,
		       latest.created_at,latest.updated_at,event.payload,outbox.status,`+FrozenMarkSQL+`
		FROM latest
		JOIN edge_command_outbox outbox ON outbox.deployment_id=latest.id AND outbox.deployment_attempt=latest.attempt
		LEFT JOIN LATERAL (
			SELECT payload FROM deployment_status_events
			WHERE deployment_id=latest.id AND attempt=latest.attempt
			ORDER BY transition_sequence DESC LIMIT 1
		) event ON true
		WHERE ($3::uuid IS NULL OR (latest.node_id,latest.id) > ($3,$4))
		ORDER BY latest.node_id,latest.id LIMIT $5`,
		scopeID, rolloutID, cursorNodeID, cursorDeploymentID, limit)
	if err != nil {
		return nil, fmt.Errorf("list rollout deployments: %w", err)
	}
	defer rows.Close()
	result := make([]DeploymentSnapshot, 0, limit)
	for rows.Next() {
		var item DeploymentSnapshot
		var attempt int
		var payload []byte
		var outboxStatus, frozenMark string
		if err := rows.Scan(&item.ID, &item.NodeID, &attempt, &item.State, &item.Cohort,
			&item.CreatedAt, &item.UpdatedAt, &payload, &outboxStatus, &frozenMark); err != nil {
			return nil, fmt.Errorf("scan rollout deployment: %w", err)
		}
		item.Attempt, item.MaxAttempts = uint32(attempt), maxAttempts
		item.Released = outboxStatus != "held"
		code, unchanged := DeploymentStatusError(payload)
		item.ErrorCode = code
		item.Superseded = DeploymentSuperseded(item.State, code, unchanged)
		item.CanRetry = retryAllowed && deploymentFailed(item.State) && !item.Superseded && item.Attempt < maxAttempts
		item.Warnings = DeploymentWarnings(payload)
		ApplyFrozenMark(&item, frozenMark)
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rollout deployments: %w", err)
	}
	return result, nil
}

func applyRolloutAggregate(result *RolloutSnapshot, persistedState string, deployments []DeploymentSnapshot) {
	for _, deployment := range deployments {
		switch {
		case deployment.State == "queued":
			result.Progress.Pending++
		case deploymentSucceeded(result.Action, deployment.State):
			result.Progress.Succeeded++
		case deployment.Frozen:
			result.Progress.Frozen++
		case deployment.Superseded:
			result.Progress.Superseded++
		case deploymentFailed(deployment.State):
			result.Progress.Failed++
		case deployment.State == "cancelled":
			result.Progress.Cancelled++
		default:
			result.Progress.Running++
		}
	}
	result.Progress.Total = len(deployments)
	if result.Policy.Strategy == RolloutStrategyCanary {
		switch persistedState {
		case "queued":
			result.State = RolloutStateQueued
		case "running":
			result.State = RolloutStateRunning
		case "paused":
			result.State = RolloutStatePaused
		case "cancelled":
			result.State = RolloutStateCancelled
		case "failed":
			result.State = RolloutStateFailed
		case "completed":
			if result.Progress.Succeeded+result.Progress.Superseded+result.Progress.Frozen == result.Progress.Total {
				result.State = RolloutStateSucceeded
			} else {
				result.State = RolloutStatePartialFailed
			}
		}
		result.CanStart = persistedState == "queued" && result.ReleasedCohort == -1
		result.CanPause = persistedState == "running"
		result.CanResume = persistedState == "paused"
		result.CanCancel = persistedState == "queued" || persistedState == "running" || persistedState == "paused"
		result.CanRetry = persistedState == "paused" &&
			hasRetryableCohortDeployment(deployments, result.ReleasedCohort)
		return
	}
	// A frozen refusal is no failure: the redelivery is a new publication.
	terminal := result.Progress.Succeeded + result.Progress.Superseded + result.Progress.Frozen + result.Progress.Failed + result.Progress.Cancelled
	switch {
	case result.Progress.Cancelled == result.Progress.Total && persistedState == "cancelled":
		result.State = RolloutStateCancelled
	case result.Progress.Succeeded+result.Progress.Superseded+result.Progress.Frozen == result.Progress.Total:
		result.State = RolloutStateSucceeded
	case terminal == result.Progress.Total && result.Progress.Failed > 0 && result.Progress.Succeeded == 0:
		result.State = RolloutStateFailed
	case terminal == result.Progress.Total && (result.Progress.Failed > 0 || result.Progress.Cancelled > 0):
		result.State = RolloutStatePartialFailed
	case result.Progress.Pending == result.Progress.Total:
		result.State = RolloutStateQueued
	default:
		result.State = RolloutStateRunning
	}
	result.CanCancel = persistedState == "queued" && result.Progress.Pending == result.Progress.Total
	result.CanRetry = (result.State == RolloutStateFailed || result.State == RolloutStatePartialFailed) &&
		hasRetryableDeployment(deployments)
}

func deploymentSucceeded(action, state string) bool {
	return action == "apply" && state == "healthy" || action == "rollback" && state == "reverted"
}

func deploymentFailed(state string) bool {
	return state == "failed" || state == "rollback_failed"
}

func hasRetryableCohortDeployment(deployments []DeploymentSnapshot, cohort int) bool {
	for _, deployment := range deployments {
		if deployment.Cohort == cohort && deployment.CanRetry {
			return true
		}
	}
	return false
}

func hasRetryableDeployment(deployments []DeploymentSnapshot) bool {
	for _, deployment := range deployments {
		if deployment.CanRetry {
			return true
		}
	}
	return false
}

func validActor(actor Actor) bool {
	return actor.UserID != uuid.Nil && actor.ScopeID != uuid.Nil && actor.SessionID != uuid.Nil &&
		(actor.ScopeKind == ScopeKindPlatform || actor.ScopeKind == ScopeKindTenant)
}

func decodeDeploymentCursor(encoded string) (*deploymentCursor, error) {
	if encoded == "" {
		return nil, nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	var cursor deploymentCursor
	if err := json.Unmarshal(payload, &cursor); err != nil || cursor.NodeID == uuid.Nil || cursor.DeploymentID == uuid.Nil {
		return nil, ErrInvalidInput
	}
	return &cursor, nil
}

func encodeDeploymentCursor(cursor deploymentCursor) (string, error) {
	payload, err := json.Marshal(cursor)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

func decodeRolloutCursor(encoded string) (*rolloutCursor, error) {
	if encoded == "" {
		return nil, nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	var cursor rolloutCursor
	if err := json.Unmarshal(payload, &cursor); err != nil || cursor.CreatedAt.IsZero() || cursor.RolloutID == uuid.Nil {
		return nil, ErrInvalidInput
	}
	return &cursor, nil
}

func encodeRolloutCursor(cursor rolloutCursor) (string, error) {
	payload, err := json.Marshal(cursor)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(payload), nil
}
