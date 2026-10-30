package edgedeployment

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func normalizeRolloutPolicy(policy RolloutPolicy, nodeCount int) (RolloutPolicy, error) {
	if nodeCount < 1 || nodeCount > 10000 || policy.Strategy != RolloutStrategyCanary ||
		policy.CanarySize < 1 || policy.CanarySize > 1000 || int(policy.CanarySize) > nodeCount ||
		policy.BatchSize < 1 || policy.BatchSize > 1000 || int(policy.BatchSize) > nodeCount ||
		policy.FailureThreshold < 1 || policy.FailureThreshold > 10000 || int(policy.FailureThreshold) > nodeCount ||
		policy.CohortCount != 0 {
		return RolloutPolicy{}, ErrInvalidInput
	}
	remaining := nodeCount - int(policy.CanarySize)
	policy.CohortCount = 1
	if remaining > 0 {
		policy.CohortCount += (remaining + int(policy.BatchSize) - 1) / int(policy.BatchSize)
	}
	return policy, nil
}

func cohortForIndex(index int, policy RolloutPolicy) int {
	if index < int(policy.CanarySize) {
		return 0
	}
	return 1 + (index-int(policy.CanarySize))/int(policy.BatchSize)
}

type persistedCohortRollout struct {
	contractVersion int16
	status          string
	action          string
	released        int
	threshold       int
	maxCohort       int
}

type cohortProgress struct {
	total     int
	succeeded int
	failed    int
	terminal  int
}

func lockCohortRollout(ctx context.Context, tx pgx.Tx, rolloutID uuid.UUID) (persistedCohortRollout, error) {
	var result persistedCohortRollout
	err := tx.QueryRow(ctx, `SELECT contract_version,status,action,released_cohort,failure_threshold
		FROM rollouts WHERE id=$1 FOR UPDATE`, rolloutID).Scan(
		&result.contractVersion, &result.status, &result.action, &result.released,
		&result.threshold,
	)
	if err != nil {
		return persistedCohortRollout{}, fmt.Errorf("lock rollout cohort: %w", err)
	}
	if err := tx.QueryRow(ctx, `SELECT COALESCE(MAX(cohort),0) FROM node_deployments WHERE rollout_id=$1`, rolloutID).
		Scan(&result.maxCohort); err != nil {
		return persistedCohortRollout{}, fmt.Errorf("read rollout max cohort: %w", err)
	}
	return result, nil
}

func loadCohortProgress(ctx context.Context, tx pgx.Tx, rolloutID uuid.UUID, cohort int, action string) (cohortProgress, error) {
	var result cohortProgress
	// An ignored old release (SupersededDeploymentSQL) ends its node and counts
	// as succeeded: the node runs a newer revision, nothing failed there.
	err := tx.QueryRow(ctx, `WITH latest AS (
		SELECT DISTINCT ON (deployment.id) deployment.id,deployment.state,deployment.cohort,
		       `+SupersededDeploymentSQL+` AS superseded
		FROM node_deployments deployment WHERE deployment.rollout_id=$1
		ORDER BY deployment.id,deployment.attempt DESC
	)
	SELECT count(*),
	       count(*) FILTER (WHERE ($3='apply' AND state='healthy') OR ($3='rollback' AND state='reverted') OR superseded),
	       count(*) FILTER (WHERE state IN ('failed','rollback_failed') AND NOT superseded),
	       count(*) FILTER (WHERE state IN ('healthy','failed','reverted','rollback_failed','cancelled'))
	FROM latest WHERE cohort=$2`, rolloutID, cohort, action).Scan(
		&result.total, &result.succeeded, &result.failed, &result.terminal,
	)
	if err != nil {
		return cohortProgress{}, fmt.Errorf("read rollout cohort progress: %w", err)
	}
	if result.total == 0 {
		return cohortProgress{}, ErrInvalidTransition
	}
	return result, nil
}

func releaseCohortOutboxes(ctx context.Context, tx pgx.Tx, rolloutID uuid.UUID, cohort int, now time.Time) (int64, error) {
	command, err := tx.Exec(ctx, `WITH latest AS (
		SELECT DISTINCT ON (id) id,attempt FROM node_deployments
		WHERE rollout_id=$1 AND cohort=$2 ORDER BY id,attempt DESC
	)
	UPDATE edge_command_outbox outbox SET status='pending',available_at=$3,updated_at=$3
	FROM latest WHERE outbox.deployment_id=latest.id AND outbox.deployment_attempt=latest.attempt
	  AND outbox.status='held'`, rolloutID, cohort, now)
	if err != nil {
		return 0, fmt.Errorf("release rollout cohort: %w", err)
	}
	return command.RowsAffected(), nil
}

func holdCohortOutboxes(ctx context.Context, tx pgx.Tx, rolloutID uuid.UUID, cohort int, now time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE edge_command_outbox outbox SET status='held',updated_at=$3
	FROM node_deployments deployment
	WHERE deployment.rollout_id=$1 AND deployment.cohort=$2
	  AND outbox.deployment_id=deployment.id AND outbox.deployment_attempt=deployment.attempt
	  AND outbox.status='pending'`, rolloutID, cohort, now)
	if err != nil {
		return fmt.Errorf("hold rollout cohort: %w", err)
	}
	return nil
}

// AdvanceRolloutAfterStatusTx advances only contract-v2 cohort facts in the
// same transaction as a non-stale deployment status projection.
func AdvanceRolloutAfterStatusTx(ctx context.Context, tx pgx.Tx, rolloutID uuid.UUID, now time.Time) error {
	rollout, err := lockCohortRollout(ctx, tx, rolloutID)
	if err != nil {
		return err
	}
	if rollout.contractVersion != 2 {
		return projectSiteIPv6RolloutTerminalTx(ctx, tx, rolloutID, false, now)
	}
	if rollout.status != "running" {
		return nil
	}
	progress, err := loadCohortProgress(ctx, tx, rolloutID, rollout.released, rollout.action)
	if err != nil {
		return err
	}
	if progress.failed >= rollout.threshold {
		if err := holdCohortOutboxes(ctx, tx, rolloutID, rollout.released, now); err != nil {
			return err
		}
		command, err := tx.Exec(ctx, `UPDATE rollouts SET status='paused',pause_reason='failure_threshold',paused_at=$2,
			revision=revision+1,updated_at=$2 WHERE id=$1 AND status='running'`, rolloutID, now)
		if err != nil {
			return fmt.Errorf("pause rollout at failure threshold: %w", err)
		}
		if command.RowsAffected() != 1 {
			return ErrInvalidTransition
		}
		return nil
	}
	if progress.terminal != progress.total {
		return nil
	}
	if rollout.released < rollout.maxCohort {
		next := rollout.released + 1
		if released, err := releaseCohortOutboxes(ctx, tx, rolloutID, next, now); err != nil {
			return err
		} else if released == 0 {
			return ErrInvalidTransition
		}
		command, err := tx.Exec(ctx, `UPDATE rollouts SET released_cohort=$2,revision=revision+1,updated_at=$3
			WHERE id=$1 AND status='running'`, rolloutID, next, now)
		if err != nil {
			return fmt.Errorf("advance rollout cohort: %w", err)
		}
		if command.RowsAffected() != 1 {
			return ErrInvalidTransition
		}
		return nil
	}
	terminalStatus := "completed"
	if progress.succeeded == 0 {
		terminalStatus = "failed"
	}
	command, err := tx.Exec(ctx, `UPDATE rollouts SET status=$2,revision=revision+1,updated_at=$3
		WHERE id=$1 AND status='running'`, rolloutID, terminalStatus, now)
	if err != nil {
		return fmt.Errorf("complete rollout cohorts: %w", err)
	}
	if command.RowsAffected() != 1 {
		return ErrInvalidTransition
	}
	return projectSiteIPv6RolloutTerminalTx(ctx, tx, rolloutID, false, now)
}
