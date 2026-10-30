package nodescheduler

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Service) RecordProbe(ctx context.Context, request ProbeRequest) (ProbeResult, error) {
	now := s.now().UTC().Truncate(time.Microsecond)
	request.ObservedAt = request.ObservedAt.UTC().Truncate(time.Microsecond)
	if request.TenantScopeID == uuid.Nil || request.GroupID == uuid.Nil || request.EndpointID == uuid.Nil ||
		request.Revision < 1 || request.Sequence < 1 || request.ObservedAt.IsZero() ||
		request.ObservedAt.Before(now.Add(-maxProbeAge)) || request.ObservedAt.After(now.Add(maxProbeFutureSkew)) {
		return ProbeResult{}, ErrInvalidInput
	}
	digest, err := probeDigest(request)
	if err != nil {
		return ProbeResult{}, err
	}
	var result ProbeResult
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var currentRevision int64
		if err := tx.QueryRow(ctx, `
			SELECT current_revision FROM node_line_groups
			WHERE tenant_scope_id=$1 AND id=$2 AND deleted_at IS NULL FOR SHARE`,
			request.TenantScopeID, request.GroupID).Scan(&currentRevision); errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if currentRevision != request.Revision {
			return ErrRevisionConflict
		}
		var policy HealthPolicy
		var intervalMS, timeoutMS, failureDebounceMS, recoveryDebounceMS int64
		var current HealthState
		err := tx.QueryRow(ctx, `
			SELECT revision.probe_interval_ms,revision.probe_timeout_ms,
			       revision.failure_threshold,revision.recovery_threshold,
			       revision.failure_debounce_ms,revision.recovery_debounce_ms,
			       health.status,health.consecutive_successes,health.consecutive_failures,
			       health.streak_started_at,health.last_sequence,health.last_observed_at,
			       health.last_received_at,health.last_probe_digest,health.last_probe_healthy,
			       health.last_changed_at,
			       health.row_revision,health.created_at,health.updated_at
			FROM node_line_endpoint_health health
			JOIN node_line_group_revisions revision
			  ON revision.tenant_scope_id=health.tenant_scope_id
			 AND revision.line_group_id=health.line_group_id
			 AND revision.revision=health.config_revision
			WHERE health.tenant_scope_id=$1 AND health.line_group_id=$2
			  AND health.config_revision=$3 AND health.endpoint_id=$4
			FOR UPDATE OF health`, request.TenantScopeID, request.GroupID,
			request.Revision, request.EndpointID).Scan(
			&intervalMS, &timeoutMS, &policy.FailureThreshold, &policy.RecoveryThreshold,
			&failureDebounceMS, &recoveryDebounceMS,
			&current.Status, &current.ConsecutiveSuccesses, &current.ConsecutiveFailures,
			&current.StreakStartedAt, &current.LastSequence, &current.LastObservedAt,
			&current.LastReceivedAt, &current.LastProbeDigest, &current.LastProbeHealthy,
			&current.LastChangedAt,
			&current.RowRevision, &current.CreatedAt, &current.UpdatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if request.Sequence == current.LastSequence {
			if bytes.Equal(current.LastProbeDigest, digest[:]) {
				result = ProbeResult{TenantScopeID: request.TenantScopeID, GroupID: request.GroupID,
					Revision: request.Revision, EndpointID: request.EndpointID, Health: current, Replayed: true}
				return nil
			}
			return ErrProbeConflict
		}
		if request.Sequence < current.LastSequence ||
			(current.LastObservedAt != nil && !request.ObservedAt.After(*current.LastObservedAt)) ||
			request.ObservedAt.Before(current.CreatedAt) {
			return ErrStaleProbe
		}
		policy.ProbeInterval = time.Duration(intervalMS) * time.Millisecond
		policy.ProbeTimeout = time.Duration(timeoutMS) * time.Millisecond
		policy.FailureDebounce = time.Duration(failureDebounceMS) * time.Millisecond
		policy.RecoveryDebounce = time.Duration(recoveryDebounceMS) * time.Millisecond
		next, transitioned := nextHealthState(current, policy, request, now)
		next.LastProbeDigest = bytes.Clone(digest[:])
		command, err := tx.Exec(ctx, `
			UPDATE node_line_endpoint_health SET
				status=$6,consecutive_successes=$7,consecutive_failures=$8,
				streak_started_at=$9,last_sequence=$10,last_observed_at=$11,
				last_received_at=$12,last_probe_digest=$13,last_probe_healthy=$14,
				last_changed_at=$15,row_revision=$16,updated_at=$17
			WHERE tenant_scope_id=$1 AND line_group_id=$2 AND config_revision=$3
			  AND endpoint_id=$4 AND row_revision=$5`,
			request.TenantScopeID, request.GroupID, request.Revision, request.EndpointID,
			current.RowRevision, next.Status, next.ConsecutiveSuccesses, next.ConsecutiveFailures,
			next.StreakStartedAt, next.LastSequence, next.LastObservedAt, next.LastReceivedAt,
			next.LastProbeDigest, next.LastProbeHealthy, next.LastChangedAt, next.RowRevision, next.UpdatedAt)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrStaleProbe
		}
		result = ProbeResult{TenantScopeID: request.TenantScopeID, GroupID: request.GroupID,
			Revision: request.Revision, EndpointID: request.EndpointID, Health: next, Transitioned: transitioned}
		return nil
	})
	if err != nil {
		return ProbeResult{}, fmt.Errorf("record node health probe: %w", err)
	}
	return result, nil
}
