package acmeedge

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type reconcileCandidate struct {
	deploymentID      uuid.UUID
	deploymentAttempt int
	outboxID          uuid.UUID
}

func (s *Service) ReconcileDeployments(ctx context.Context, request ReconcileRequest) (ReconcileResult, error) {
	if ctx == nil || request.Now.IsZero() || request.AttemptTimeout <= 0 || request.AttemptTimeout > time.Hour ||
		request.Limit < 1 || request.Limit > 1000 {
		return ReconcileResult{}, ErrInvalidInput
	}
	now := request.Now.UTC().Truncate(time.Microsecond)
	candidates, err := s.reconcileCandidates(ctx, now, request.AttemptTimeout, request.Limit)
	if err != nil {
		return ReconcileResult{}, err
	}
	var result ReconcileResult
	for _, candidate := range candidates {
		candidateResult, err := s.reconcileCandidate(ctx, candidate, now, request.AttemptTimeout)
		if err != nil {
			return result, err
		}
		result.TimedOut += candidateResult.TimedOut
		result.Retried += candidateResult.Retried
	}
	return result, nil
}

func (s *Service) reconcileCandidates(
	ctx context.Context,
	now time.Time,
	attemptTimeout time.Duration,
	limit int,
) ([]reconcileCandidate, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT deployment.id,deployment.attempt,outbox.id
		FROM acme_http01_overlay_deployments deployment
		JOIN acme_http01_overlay_outbox outbox
		  ON outbox.deployment_id=deployment.id AND outbox.deployment_attempt=deployment.attempt
		JOIN acme_http01_overlay_outbox_states outbox_state ON outbox_state.outbox_id=outbox.id
		JOIN acme_http01_overlay_versions version ON version.id=deployment.version_id
		JOIN acme_http01_overlay_publications publication ON publication.id=version.publication_id
		JOIN LATERAL (
			SELECT state,occurred_at
			FROM acme_http01_overlay_deployment_events
			WHERE deployment_id=deployment.id AND deployment_attempt=deployment.attempt
			ORDER BY sequence DESC LIMIT 1
		) event ON true
		WHERE NOT EXISTS (
			SELECT 1 FROM acme_http01_overlay_deployments newer
			WHERE newer.id=deployment.id AND newer.attempt>deployment.attempt
		) AND NOT (
			outbox_state.status='claimed' AND outbox_state.lease_expires_at>$1
		) AND (
			(publication.deadline_at<=$1 AND event.state IN ('queued','retry_queued','dispatched','applied')) OR
			(outbox_state.status='published' AND event.state IN ('dispatched','applied')
			 AND event.occurred_at<=$1-$2::interval) OR
			(event.state='timed_out' AND event.occurred_at<=$1-$3::interval
			 AND deployment.attempt<publication.max_attempts AND publication.deadline_at>$1)
		)
		ORDER BY event.occurred_at,deployment.id
		LIMIT $4`, now, attemptTimeout, s.retryDelay, limit)
	if err != nil {
		return nil, fmt.Errorf("%w: list overlay reconciliation candidates", ErrPersistence)
	}
	defer rows.Close()
	candidates := make([]reconcileCandidate, 0, limit)
	for rows.Next() {
		var candidate reconcileCandidate
		if err := rows.Scan(&candidate.deploymentID, &candidate.deploymentAttempt, &candidate.outboxID); err != nil {
			return nil, fmt.Errorf("%w: scan overlay reconciliation candidate", ErrPersistence)
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: iterate overlay reconciliation candidates", ErrPersistence)
	}
	return candidates, nil
}

func (s *Service) reconcileCandidate(
	ctx context.Context,
	candidate reconcileCandidate,
	now time.Time,
	attemptTimeout time.Duration,
) (ReconcileResult, error) {
	var result ReconcileResult
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		outbox, locked, err := lockReconcileOutboxState(ctx, tx, candidate.outboxID)
		if err != nil || !locked {
			return err
		}
		if outbox.deploymentID != candidate.deploymentID || outbox.deploymentAttempt != candidate.deploymentAttempt ||
			outbox.status == "claimed" && outbox.leaseExpiresAt != nil && outbox.leaseExpiresAt.After(now) {
			return nil
		}
		record, err := lockLatestDeployment(ctx, tx, candidate.deploymentID)
		if err != nil {
			return err
		}
		if record.DeploymentAttempt != candidate.deploymentAttempt {
			return nil
		}
		current, err := currentDeploymentState(ctx, tx, record.DeploymentID, record.DeploymentAttempt)
		if err != nil {
			return err
		}
		deadline, maxAttempts, err := loadPublicationRetryPolicy(ctx, tx, record.VersionID)
		if err != nil {
			return err
		}
		if record.maxAttempts != maxAttempts || !record.Deadline.Equal(deadline) {
			return fmt.Errorf("%w: overlay retry policy drift", ErrPersistence)
		}

		newlyTimedOut := false
		globalExpired := !deadline.After(now)
		if (globalExpired && (current.State == DeploymentQueued || current.State == DeploymentRetryQueued ||
			current.State == DeploymentDispatched || current.State == DeploymentApplied)) ||
			(!globalExpired && outbox.status == "published" &&
				(current.State == DeploymentDispatched || current.State == DeploymentApplied) &&
				!current.OccurredAt.Add(attemptTimeout).After(now)) {
			if _, err := appendDeploymentEvent(ctx, tx, record.DeploymentID, record.DeploymentAttempt,
				DeploymentTimedOut, uuid.Nil, [32]byte{}, "deployment_timed_out", now); err != nil {
				return err
			}
			if err := exhaustTimedOutOutbox(ctx, tx, record.DeploymentID, record.DeploymentAttempt, now); err != nil {
				return err
			}
			if err := s.auditor.Append(ctx, tx, audit.Event{
				ScopeID: record.tenantScopeID, ActorUserID: nil,
				Action: "acme_http01_overlay.timeout", ResourceType: "acme_http01_overlay_deployment",
				ResourceID: record.DeploymentID.String(), RequestID: record.DeploymentID.String(), Result: "success",
				Payload: map[string]any{
					"attempt": record.DeploymentAttempt, "site_id": record.siteID.String(),
					"revision": record.revision, "node_id": record.NodeID.String(),
				},
			}); err != nil {
				return err
			}
			result.TimedOut = 1
			newlyTimedOut = true
			current.State = DeploymentTimedOut
			current.OccurredAt = now
		}
		if current.State != DeploymentTimedOut || record.DeploymentAttempt >= maxAttempts || !deadline.After(now) ||
			!newlyTimedOut && current.OccurredAt.Add(s.retryDelay).After(now) {
			return nil
		}
		nextAttempt := record.DeploymentAttempt + 1
		requestID := uuid.NewSHA1(record.DeploymentID, []byte(fmt.Sprintf("acme-http01/reconcile/%d", nextAttempt)))
		if _, err := s.insertRetryDeploymentTx(ctx, tx, record, requestID, deadline, now); err != nil {
			if errors.Is(err, ErrInvalidTransition) {
				return nil
			}
			return err
		}
		result.Retried = 1
		return nil
	})
	return result, err
}

func lockReconcileOutboxState(
	ctx context.Context,
	tx pgx.Tx,
	outboxID uuid.UUID,
) (outboxStateRecord, bool, error) {
	var state outboxStateRecord
	err := tx.QueryRow(ctx, `
		SELECT state.outbox_id,outbox.deployment_id,outbox.deployment_attempt,
		       state.status,state.publish_attempts,state.lease_token,state.lease_expires_at
		FROM acme_http01_overlay_outbox_states state
		JOIN acme_http01_overlay_outbox outbox ON outbox.id=state.outbox_id
		WHERE state.outbox_id=$1 FOR UPDATE OF state SKIP LOCKED`, outboxID).Scan(
		&state.outboxID, &state.deploymentID, &state.deploymentAttempt, &state.status,
		&state.publishAttempts, &state.leaseToken, &state.leaseExpiresAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return outboxStateRecord{}, false, nil
	}
	if err != nil {
		return outboxStateRecord{}, false, fmt.Errorf("%w: lock overlay reconciliation outbox", ErrPersistence)
	}
	return state, true, nil
}
