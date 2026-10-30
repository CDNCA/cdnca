package controlupgrade

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	rolloutReadPermission   = "control.upgrades.read"
	rolloutManagePermission = "control.upgrades.manage"
)

func (s *Service) ListRolloutStatusReceipts(ctx context.Context, actor Actor,
	planID string) ([]RolloutStatusReceipt, error) {
	if s == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	return s.store.ListRolloutStatusReceipts(ctx, actor, planID)
}

func (s *Store) ListRolloutStatusReceipts(ctx context.Context, actor Actor,
	planID string) ([]RolloutStatusReceipt, error) {
	if !validRolloutActor(actor) || !validCanonicalPlanUUID(planID) {
		return nil, ErrInvalidInput
	}
	receipts := []RolloutStatusReceipt{}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorizeRolloutTx(ctx, tx, actor, rolloutReadPermission); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT status_id,status_revision,command_id,plan_id,plan_revision,
			batch_id,installation_id,node_id,action,command_sha256,status_bytes,status_sha256,state,
			observed_at,COALESCE(delivery_stream,''),COALESCE(delivery_consumer,''),
			COALESCE(delivery_sequence,0)
			FROM control_upgrade_status_receipts
			WHERE plan_id=$1 AND actor_scope_id=$2
			ORDER BY delivery_sequence NULLS FIRST,created_at,status_id`, planID, actor.ScopeID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var receipt RolloutStatusReceipt
			var commandDigest, statusDigest []byte
			if err := rows.Scan(&receipt.StatusID, &receipt.StatusRevision, &receipt.CommandID,
				&receipt.PlanID, &receipt.PlanRevision, &receipt.BatchID, &receipt.InstallationID,
				&receipt.NodeID, &receipt.Action, &commandDigest, &receipt.StatusBytes, &statusDigest,
				&receipt.State, &receipt.ObservedAt, &receipt.DeliveryStream, &receipt.DeliveryConsumer,
				&receipt.DeliverySequence); err != nil {
				return err
			}
			receipt.CommandSHA256 = fmt.Sprintf("%x", commandDigest)
			receipt.StatusSHA256 = fmt.Sprintf("%x", statusDigest)
			if !hydrateRolloutStatusReceipt(&receipt) {
				return ErrInvalidPlanEvent
			}
			receipts = append(receipts, receipt)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list control upgrade status receipts: %w", err)
	}
	return receipts, nil
}

func (s *Store) ListRollouts(ctx context.Context, actor Actor,
	request ListRolloutsRequest) (ListRolloutsResponse, error) {
	if !validRolloutActor(actor) || request.Page < 1 || request.PageSize < 1 || request.PageSize > 100 ||
		request.State != "" && !validPlanState(request.State) ||
		request.NodeID != "" && !validCanonicalPlanUUID(request.NodeID) {
		return ListRolloutsResponse{}, ErrInvalidInput
	}
	var response ListRolloutsResponse
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorizeRolloutTx(ctx, tx, actor, rolloutReadPermission); err != nil {
			return err
		}
		conditions := "actor_scope_id=$1"
		arguments := []any{actor.ScopeID}
		if request.State != "" {
			arguments = append(arguments, request.State)
			conditions += fmt.Sprintf(" AND state=$%d", len(arguments))
		}
		if request.NodeID != "" {
			arguments = append(arguments, request.NodeID)
			conditions += fmt.Sprintf(" AND (convert_from(canonical_snapshot_bytes,'UTF8')::jsonb->'Targets') ? $%d", len(arguments))
		}
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM control_upgrade_rollout_plans WHERE "+conditions,
			arguments...).Scan(&response.Total); err != nil {
			return err
		}
		arguments = append(arguments, request.PageSize, (request.Page-1)*request.PageSize)
		rows, err := tx.Query(ctx, `SELECT installation_id,canonical_snapshot_bytes,
			canonical_snapshot_sha256,created_at,updated_at FROM control_upgrade_rollout_plans WHERE `+
			conditions+fmt.Sprintf(" ORDER BY created_at DESC,id DESC LIMIT $%d OFFSET $%d",
			len(arguments)-1, len(arguments)), arguments...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var installationID string
			var snapshot, digest []byte
			var createdAt, updatedAt time.Time
			if err := rows.Scan(&installationID, &snapshot, &digest, &createdAt, &updatedAt); err != nil {
				return err
			}
			plan, _, err := decodeRolloutPlan(snapshot, digest)
			if err != nil {
				return err
			}
			response.Data = append(response.Data, rolloutSummary(plan, installationID, createdAt, updatedAt))
		}
		return rows.Err()
	})
	if err != nil {
		return ListRolloutsResponse{}, fmt.Errorf("list control upgrade rollouts: %w", err)
	}
	if response.Data == nil {
		response.Data = []RolloutSummary{}
	}
	response.Page, response.PageSize = request.Page, request.PageSize
	return response, nil
}

func (s *Store) GetRollout(ctx context.Context, actor Actor, planID string) (RolloutDetail, error) {
	if !validRolloutActor(actor) || !validCanonicalPlanUUID(planID) {
		return RolloutDetail{}, ErrInvalidInput
	}
	var detail RolloutDetail
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorizeRolloutTx(ctx, tx, actor, rolloutReadPermission); err != nil {
			return err
		}
		var err error
		detail, _, err = readRolloutDetailTx(ctx, tx, actor.ScopeID, planID, false)
		return err
	})
	if err != nil {
		return RolloutDetail{}, fmt.Errorf("get control upgrade rollout: %w", err)
	}
	return detail, nil
}

func readRolloutDetailTx(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, planID string,
	lock bool) (RolloutDetail, RolloutIdentity, error) {
	query := `SELECT actor_scope_id,actor_user_id,installation_id,canonical_snapshot_bytes,
		canonical_snapshot_sha256,created_at,updated_at FROM control_upgrade_rollout_plans
		WHERE id=$1 AND actor_scope_id=$2`
	if lock {
		query += " FOR UPDATE"
	}
	var identity RolloutIdentity
	var snapshot, digest []byte
	var createdAt, updatedAt time.Time
	err := tx.QueryRow(ctx, query, planID, scopeID).Scan(&identity.ActorScopeID, &identity.ActorUserID,
		&identity.InstallationID, &snapshot, &digest, &createdAt, &updatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return RolloutDetail{}, RolloutIdentity{}, ErrRolloutNotFound
	}
	if err != nil {
		return RolloutDetail{}, RolloutIdentity{}, err
	}
	plan, _, err := decodeRolloutPlan(snapshot, digest)
	if err != nil || plan.ID != planID {
		return RolloutDetail{}, RolloutIdentity{}, ErrInvalidPlan
	}
	detail := rolloutDetail(plan, identity.InstallationID, createdAt, updatedAt)
	if detail.EventTimes, err = readRolloutEventTimesTx(ctx, tx, planID); err != nil {
		return RolloutDetail{}, RolloutIdentity{}, err
	}
	return detail, identity, nil
}

func readRolloutEventTimesTx(ctx context.Context, tx pgx.Tx, planID string) (map[uint64]time.Time, error) {
	rows, err := tx.Query(ctx, `SELECT revision,created_at FROM control_upgrade_rollout_events
		WHERE plan_id=$1 ORDER BY revision`, planID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	times := map[uint64]time.Time{}
	for rows.Next() {
		var revision int64
		var at time.Time
		if err := rows.Scan(&revision, &at); err != nil {
			return nil, err
		}
		if revision > 0 {
			times[uint64(revision)] = at.UTC()
		}
	}
	return times, rows.Err()
}

func authorizeRolloutTx(ctx context.Context, tx pgx.Tx, actor Actor, permission string) error {
	return authorizeUpgradeAccessTx(ctx, tx, actor, permission, true)
}

func authorizeUpgradeAccessTx(ctx context.Context, tx pgx.Tx, actor Actor, permission string, lock bool) error {
	if !validRolloutActor(actor) || permission != rolloutReadPermission && permission != rolloutManagePermission && permission != "nodes.read" {
		return ErrPermissionDenied
	}
	locking := ""
	if lock {
		locking = " FOR SHARE OF actor,scope,membership,assignment,role,grant_row"
	}
	var granted string
	err := tx.QueryRow(ctx, `SELECT grant_row.permission_name FROM users actor
		JOIN access_scopes scope ON scope.id=$2
		JOIN memberships membership ON membership.scope_id=scope.id AND membership.user_id=actor.id
		JOIN role_assignments assignment ON assignment.scope_id=membership.scope_id
			AND assignment.user_id=membership.user_id
		JOIN roles role ON role.scope_id=assignment.scope_id AND role.id=assignment.role_id
		JOIN role_permissions grant_row ON grant_row.role_id=role.id
		WHERE actor.id=$1 AND actor.status='active' AND scope.kind='platform'
		  AND membership.status='active' AND grant_row.permission_name=ANY($3::text[])
		ORDER BY grant_row.permission_name LIMIT 1`+locking,
		actor.UserID, actor.ScopeID, []string{permission, "platform.admin"}).Scan(&granted)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrPermissionDenied
	}
	if err != nil {
		return err
	}
	if granted != permission && granted != "platform.admin" {
		return ErrPermissionDenied
	}
	return nil
}

func validRolloutActor(actor Actor) bool {
	return actor.UserID != uuid.Nil && actor.ScopeID != uuid.Nil && actor.ScopeKind == "platform"
}

func validPlanState(state PlanState) bool {
	return state == PlanQueued || state == PlanCanary || state == PlanRunning || state == PlanPaused ||
		state == PlanRollingBack || state == PlanCompleted || state == PlanFailed
}

func rolloutSummary(plan RolloutPlan, installationID string, createdAt, updatedAt time.Time) RolloutSummary {
	summary := RolloutSummary{ID: plan.ID, SchemaVersion: plan.SchemaVersion, InstallationID: installationID,
		Component: plan.Component, CurrentVersion: plan.CurrentVersion, TargetVersion: plan.TargetVersion,
		State: plan.State, Completion: plan.Completion, Revision: plan.Revision,
		AutomaticRollback: plan.AutomaticRollback, ParentGrantID: plan.ParentGrantID,
		ArtifactID: plan.ArtifactID, ArtifactSHA256: plan.SHA256Digest,
		ArtifactSizeBytes: plan.ArtifactSizeBytes, RollbackArtifactID: plan.RollbackArtifactID,
		RollbackArtifactSHA256:    plan.RollbackSHA256Digest,
		RollbackArtifactSizeBytes: plan.RollbackArtifactSizeBytes, ActiveBatch: plan.ActiveBatch,
		TotalNodes: len(plan.NodeStates), CreatedAt: createdAt.UTC(), UpdatedAt: updatedAt.UTC()}
	for _, state := range plan.NodeStates {
		switch state {
		case NodePending:
			summary.PendingNodes++
		case NodeDispatched:
			summary.DispatchedNodes++
		case NodeHealthy:
			summary.HealthyNodes++
		case NodeFailed:
			summary.FailedNodes++
		case NodeRolledBack:
			summary.RolledBackNodes++
		}
	}
	for _, blocker := range plan.Blockers {
		summary.Blockers = append(summary.Blockers, RolloutBlocker{Code: blocker.Code, NodeID: blocker.NodeID})
	}
	if summary.Blockers == nil {
		summary.Blockers = []RolloutBlocker{}
	}
	return summary
}

func rolloutDetail(plan RolloutPlan, installationID string, createdAt, updatedAt time.Time) RolloutDetail {
	detail := RolloutDetail{RolloutSummary: rolloutSummary(plan, installationID, createdAt, updatedAt)}
	for _, batch := range plan.Batches {
		detail.Batches = append(detail.Batches, RolloutBatch{ID: batch.ID, GroupID: batch.GroupID,
			Canary: batch.Canary, NodeIDs: append([]string(nil), batch.NodeIDs...)})
	}
	nodeIDs := make([]string, 0, len(plan.Targets))
	for nodeID := range plan.Targets {
		nodeIDs = append(nodeIDs, nodeID)
	}
	sort.Strings(nodeIDs)
	for _, nodeID := range nodeIDs {
		target := plan.Targets[nodeID]
		detail.Nodes = append(detail.Nodes, RolloutNode{NodeID: nodeID, AgentVersion: target.AgentVersion,
			ProtocolVersion: target.ProtocolVersion, State: plan.NodeStates[nodeID],
			DispatchRevision: plan.NodeDispatchRevisions[nodeID]})
	}
	for _, receipt := range plan.CommandReceipts {
		detail.Events = append(detail.Events, rolloutEvent(receipt.Event))
	}
	for _, receipt := range plan.HealthReceipts {
		detail.Events = append(detail.Events, rolloutEvent(receipt.Event))
	}
	sort.Slice(detail.Events, func(left, right int) bool { return detail.Events[left].Revision < detail.Events[right].Revision })
	if detail.Batches == nil {
		detail.Batches = []RolloutBatch{}
	}
	if detail.Nodes == nil {
		detail.Nodes = []RolloutNode{}
	}
	if detail.Events == nil {
		detail.Events = []RolloutEvent{}
	}
	return detail
}

func rolloutEvent(event PlanEvent) RolloutEvent {
	return RolloutEvent{ID: event.ID, Revision: event.Revision, From: event.From, To: event.To,
		Action: event.Action, Reason: event.Reason, BatchID: event.BatchID, NodeID: event.NodeID}
}
