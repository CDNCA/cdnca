package nodescheduler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Service) List(ctx context.Context, actor Actor) ([]LineGroupRevision, error) {
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || actor.ResourceScopeID() == uuid.Nil {
		return nil, ErrInvalidInput
	}
	result := make([]LineGroupRevision, 0)
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeTx(ctx, tx, actor, permissionRead, false); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT id FROM node_line_groups
			WHERE tenant_scope_id=$1 AND deleted_at IS NULL AND purpose='general'
			ORDER BY sort_order,created_at DESC,id DESC`, actor.ResourceScopeID())
		if err != nil {
			return fmt.Errorf("list node line groups: %w", err)
		}
		var groupIDs []uuid.UUID
		for rows.Next() {
			var groupID uuid.UUID
			if err := rows.Scan(&groupID); err != nil {
				rows.Close()
				return fmt.Errorf("scan node line group: %w", err)
			}
			groupIDs = append(groupIDs, groupID)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return fmt.Errorf("iterate node line groups: %w", err)
		}
		for _, groupID := range groupIDs {
			group, err := loadRevision(ctx, tx, actor.ResourceScopeID(), groupID, 0)
			if err != nil {
				return err
			}
			if err := attachReadState(ctx, tx, &group); err != nil {
				return err
			}
			result = append(result, group)
		}
		return nil
	})
	return result, err
}

func (s *Service) ListStatistics(
	ctx context.Context,
	actor Actor,
	groups []LineGroupRevision,
) (map[uuid.UUID]LineGroupStatistics, error) {
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || actor.ResourceScopeID() == uuid.Nil {
		return nil, ErrInvalidInput
	}
	result := make(map[uuid.UUID]LineGroupStatistics, len(groups))
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeTx(ctx, tx, actor, permissionRead, false); err != nil {
			return err
		}
		for _, group := range groups {
			if group.GroupID == uuid.Nil || group.TenantScopeID != actor.ResourceScopeID() || group.Revision < 1 {
				return ErrInvalidInput
			}
			var currentRevision int64
			var statistics LineGroupStatistics
			err := tx.QueryRow(ctx, `
				WITH current_group AS (
					SELECT current_revision
					FROM node_line_groups
					WHERE tenant_scope_id=$1 AND id=$2 AND deleted_at IS NULL AND purpose='general'
				)
				SELECT current_group.current_revision,
				       (SELECT count(DISTINCT endpoint.node_id)
				        FROM node_line_endpoints endpoint
				        WHERE endpoint.tenant_scope_id=$1 AND endpoint.line_group_id=$2
				          AND endpoint.config_revision=current_group.current_revision
				          AND endpoint.node_id IS NOT NULL),
				       (SELECT count(*)
				        FROM sites site
				        LEFT JOIN package_subscriptions subscription
				          ON subscription.tenant_scope_id=site.scope_id
				         AND subscription.id=site.package_subscription_id AND subscription.deleted_at IS NULL
				        WHERE site.scope_id=$1 AND site.deleted_at IS NULL
				          AND (site.node_group_id=$2 OR site.node_group_id IS NULL
				            AND (subscription.product_snapshot#>>'{spec,node_group_id}'=$2::text
				              OR subscription.product_snapshot#>>'{spec,backup_node_group_id}'=$2::text))),
				       (SELECT count(*)
				        FROM l4_forwards forward_rule
				        JOIN package_subscriptions subscription
				          ON subscription.tenant_scope_id=forward_rule.scope_id
				         AND subscription.id=forward_rule.package_subscription_id
				        WHERE forward_rule.scope_id=$1 AND forward_rule.deleted_at IS NULL
				          AND ($2 IN (forward_rule.node_group_id, forward_rule.backup_node_group_id)
				            OR forward_rule.node_group_id IS NULL
				            AND (subscription.product_snapshot#>>'{spec,node_group_id}'=$2::text
				              OR subscription.product_snapshot#>>'{spec,backup_node_group_id}'=$2::text)))
				FROM current_group`, actor.ResourceScopeID(), group.GroupID).Scan(
				&currentRevision, &statistics.NodeCount, &statistics.SiteCount, &statistics.ForwardCount,
			)
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			if err != nil {
				return fmt.Errorf("load node line group statistics: %w", err)
			}
			if currentRevision != group.Revision {
				return ErrRevisionConflict
			}
			result[group.GroupID] = statistics
		}
		return nil
	})
	return result, err
}

func (s *Service) DecideCurrent(ctx context.Context, actor Actor, groupID uuid.UUID, request DecisionRequest) (Decision, error) {
	if ctx == nil || actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || actor.ResourceScopeID() == uuid.Nil ||
		groupID == uuid.Nil || !writeMetadataPattern.MatchString(request.RequestID) {
		return Decision{}, ErrInvalidInput
	}
	stableKey, valid := normalizeStableKey(request.StableKey)
	if !valid {
		return Decision{}, ErrInvalidInput
	}
	request.StableKey = stableKey
	now := s.now().UTC().Truncate(time.Microsecond)
	var result Decision
	var decisionErr error
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeTx(ctx, tx, actor, permissionRead, false); err != nil {
			return err
		}
		group, err := loadRevision(ctx, tx, actor.ResourceScopeID(), groupID, 0)
		if err != nil {
			return err
		}
		plan, err := BuildPlan(group, request.Selector, now)
		if err != nil {
			strategy := strings.TrimSpace(request.Strategy)
			if strategy == "" {
				strategy = StrategyWeightedBaseline
			}
			result = Decision{Plan: plan, Strategy: strategy}
			if err == ErrNoHealthyEndpoint {
				result.Reason = ReasonNoHealthyEndpoint
			}
			decisionErr = err
			return s.appendDecisionAudit(ctx, tx, actor, groupID, group.Revision, request, result, decisionErr)
		}
		var loads map[uuid.UUID]LoadSample
		telemetryUnavailable := false
		if request.Strategy == StrategyP2CLeastLoaded && s.loads != nil && len(plan.Candidates) > 1 {
			loads, err = s.loads.Loads(ctx, actor.ResourceScopeID(), plan.Candidates)
			if err != nil {
				loads = nil
				telemetryUnavailable = true
			}
		}
		result, decisionErr = Decide(plan, request, loads, now)
		if telemetryUnavailable && decisionErr == nil && result.Fallback &&
			result.Reason == ReasonTelemetryInsufficient {
			result.Reason = ReasonTelemetryUnavailableFallback
		}
		return s.appendDecisionAudit(ctx, tx, actor, groupID, group.Revision, request, result, decisionErr)
	})
	if err != nil {
		return Decision{}, err
	}
	return result, decisionErr
}

func (s *Service) appendDecisionAudit(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	groupID uuid.UUID,
	revision int64,
	request DecisionRequest,
	decision Decision,
	decisionErr error,
) error {
	payload := decisionAuditPayload(groupID, revision, request, decision)
	result := "success"
	if decisionErr != nil {
		result = "failure"
	}
	return s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: actor.ResourceScopeID(), ActorUserID: &actor.UserID,
		Action: "node_scheduling.decision.evaluate", ResourceType: "node_line_group",
		ResourceID: groupID.String(), RequestID: request.RequestID, Result: result, Payload: payload,
	})
}

func decisionAuditPayload(
	groupID uuid.UUID,
	revision int64,
	request DecisionRequest,
	decision Decision,
) map[string]any {
	stableKeyDigest := sha256.Sum256([]byte(request.StableKey))
	effective := decision.Strategy
	if decision.Fallback {
		effective = StrategyWeightedBaseline
	}
	endpointID := ""
	if decision.Endpoint.ID != uuid.Nil {
		endpointID = decision.Endpoint.ID.String()
	}
	evaluations := make([]map[string]any, len(decision.Plan.Evaluations))
	for index, evaluation := range decision.Plan.Evaluations {
		endpoint := evaluation.Endpoint
		evaluations[index] = map[string]any{
			"endpoint_id":         endpoint.ID.String(),
			"node_id":             uuidString(endpoint.NodeID),
			"address":             endpoint.Address,
			"port":                endpoint.Port,
			"priority":            endpoint.Priority,
			"weight":              endpoint.Weight,
			"enabled":             endpoint.Enabled,
			"health_status":       endpoint.Health.Status,
			"health_row_revision": endpoint.Health.RowRevision,
			"last_observed_at":    endpoint.Health.LastObservedAt,
			"last_received_at":    endpoint.Health.LastReceivedAt,
			"disposition":         evaluation.Disposition,
		}
	}
	var selectedPriority any
	if len(decision.Plan.Candidates) > 0 {
		selectedPriority = decision.Plan.Priority
	}
	return map[string]any{
		"requested_strategy": request.Strategy,
		"effective_strategy": effective,
		"reason":             decision.Reason,
		"fallback":           decision.Fallback,
		"group_id":           groupID.String(),
		"revision":           revision,
		"endpoint_id":        endpointID,
		"plan_digest":        hex.EncodeToString(decision.Plan.Digest[:]),
		"selector": map[string]string{
			"region": request.Selector.Region, "carrier": request.Selector.Carrier,
		},
		"priority":          decision.Plan.Priority,
		"candidate_count":   len(decision.Plan.Candidates),
		"standby_count":     len(decision.Plan.Standby),
		"stable_key_sha256": hex.EncodeToString(stableKeyDigest[:]),
		"snapshot": map[string]any{
			"tenant_scope_id":      uuidString(decision.Plan.TenantScopeID),
			"group_id":             uuidString(decision.Plan.GroupID),
			"revision":             decision.Plan.Revision,
			"configuration_digest": hex.EncodeToString(decision.Plan.ConfigurationDigest),
			"plan_digest":          hex.EncodeToString(decision.Plan.Digest[:]),
			"selector":             decision.Plan.Selector,
			"evaluated_at":         decision.Plan.EvaluatedAt,
			"selected_priority":    selectedPriority,
			"tier_reason":          decision.Plan.TierReason,
			"endpoint_evaluations": evaluations,
		},
	}
}
