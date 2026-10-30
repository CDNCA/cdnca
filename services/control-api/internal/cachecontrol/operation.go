package cachecontrol

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (store *Store) CreateOperation(
	ctx context.Context,
	actor Actor,
	request CreateOperationRequest,
) (OperationWriteResult, error) {
	result, err := store.createOperation(ctx, actor, request, uuid.Nil)
	if err != nil {
		return OperationWriteResult{}, store.withWriteRejection(ctx, actor, rejectedWrite{
			action: WriteCreate, siteID: request.SiteID, key: request.IdempotencyKey, requestID: request.RequestID,
		}, err)
	}
	return result, nil
}

// createOperationDigest is the idempotency identity of a create request. An
// automatic-node request (no node_ids) is identified by site, action, target
// type, targets and the auto flag only: the carrying node set is resolved at
// write time and may change between retries of the same intent (ADD-08), so
// it is not part of the identity. Explicit node lists stay in the identity.
func createOperationDigest(
	request CreateOperationRequest, targets []Target, sortedNodeIDs []uuid.UUID, autoNodes bool,
) ([32]byte, error) {
	if autoNodes {
		sortedNodeIDs = nil
	}
	return digestJSON(struct {
		SiteID      uuid.UUID   `json:"site_id"`
		Action      Action      `json:"action"`
		TargetType  TargetType  `json:"target_type"`
		Targets     []Target    `json:"targets"`
		NodeIDs     []uuid.UUID `json:"node_ids,omitempty"`
		MaxAttempts uint32      `json:"max_attempts"`
		Priority    string      `json:"priority"`
		AutoNodes   bool        `json:"auto_nodes,omitempty"`
	}{request.SiteID, request.Action, request.TargetType, targets, sortedNodeIDs, request.MaxRetries + 1, "normal", autoNodes})
}

// createOperation writes a new operation; resubmitOf (non-nil) names the
// operation it re-submits, whose cache.operation.resubmit audit is written in
// the same transaction as the new operation's creation.
func (store *Store) createOperation(
	ctx context.Context,
	actor Actor,
	request CreateOperationRequest,
	resubmitOf uuid.UUID,
) (OperationWriteResult, error) {
	if ctx == nil || validateCreateOperation(actor, request) != nil {
		return OperationWriteResult{}, ErrInvalidInput
	}
	nodeIDs := append([]uuid.UUID(nil), request.NodeIDs...)
	now := store.timestamp()
	var result OperationWriteResult
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		tenantID, err := store.authorizeActor(ctx, tx, actor, "sites.manage")
		if err != nil {
			return err
		}
		site, err := loadSiteDescriptor(ctx, tx, actor.ScopeID, request.SiteID, true)
		if err != nil {
			return err
		}
		if site.TenantID != tenantID {
			return ErrPermissionDenied
		}
		if err := store.checkSiteEntitlement(
			ctx, tx, actor, request.SiteID, request.RequestID, "cache.operation.create",
		); err != nil {
			return err
		}
		targets, err := normalizeTargets(request.Targets, request.Action, request.TargetType, site)
		if errors.Is(err, ErrWildcardTargetHost) {
			return ErrWildcardTargetHost
		}
		var targetErr *TargetError
		if errors.As(err, &targetErr) {
			return targetErr
		}
		if err != nil {
			return ErrInvalidInput
		}
		autoNodes := len(nodeIDs) == 0
		if len(nodeIDs) > maxNodes {
			return ErrInvalidInput
		}
		sort.Slice(nodeIDs, func(i, j int) bool { return nodeIDs[i].String() < nodeIDs[j].String() })
		digest, err := createOperationDigest(request, targets, nodeIDs, autoNodes)
		if err != nil {
			return err
		}

		var existingID uuid.UUID
		var existingActorID uuid.UUID
		var existingDigest []byte
		err = tx.QueryRow(ctx, `
			SELECT id,actor_user_id,request_digest FROM cache_operations
			WHERE scope_id=$1 AND actor_scope_id=$2 AND actor_user_id=$3 AND idempotency_key=$4 FOR UPDATE`,
			actor.ScopeID, actor.ActorScopeID, actor.UserID, request.IdempotencyKey).Scan(
			&existingID, &existingActorID, &existingDigest)
		if err == nil {
			if existingActorID != actor.UserID || !bytes.Equal(existingDigest, digest[:]) {
				return ErrIdempotencyConflict
			}
			result.Operation, err = loadOperation(ctx, tx, actor.ScopeID, existingID)
			result.Replayed = err == nil
			return err
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("read idempotent cache operation: %w", err)
		}
		if autoNodes {
			if nodeIDs, err = carryingNodes(ctx, tx, actor.ScopeID); err != nil {
				return err
			}
			if len(nodeIDs) == 0 {
				return ErrNoCarryingNode
			}
			sort.Slice(nodeIDs, func(i, j int) bool { return nodeIDs[i].String() < nodeIDs[j].String() })
		}
		if len(nodeIDs) > maxNodes || len(targets)*len(nodeIDs) > maxOperationItems {
			return ErrInvalidInput
		}
		// 自动选节点时 nodeIDs 到这里才确定；之前校验时列表为空，通配刷新会绕过能力检查。
		if targetsHaveWildcardHost(targets) {
			if err := checkWildcardPurgeNodes(ctx, tx, nodeIDs); err != nil {
				return err
			}
		}
		if countsTowardsDailyLimit(actor) {
			if err := checkDailyLimit(ctx, tx, actor.ScopeID, request.Action, request.TargetType,
				len(targets), now); err != nil {
				return err
			}
		}

		operationID, existing, err := store.insertOperation(ctx, tx, operationInsert{
			actor: actor, tenantID: tenantID, siteID: request.SiteID, action: request.Action,
			targetType: request.TargetType, targets: targets, nodeIDs: nodeIDs, maxRetries: request.MaxRetries,
			idempotencyKey: request.IdempotencyKey, requestID: request.RequestID, digest: digest,
			autoNodes: autoNodes,
		}, now)
		if err != nil {
			return err
		}
		if resubmitOf != uuid.Nil && !existing {
			if _, err := store.appendAudit(ctx, tx, actor.ScopeID, &actor.UserID,
				"cache.operation.resubmit", resubmitOf, request.RequestID, map[string]any{
					"actor_scope_id": actor.ActorScopeID, "operation_id": operationID.String(),
					"auto_nodes": autoNodes, "nodes": len(nodeIDs), "targets": len(targets),
				}); err != nil {
				return err
			}
		}
		result.Operation, err = loadOperation(ctx, tx, actor.ScopeID, operationID)
		result.Replayed = existing && err == nil
		return err
	})
	if err != nil {
		if errors.Is(err, ErrEntitlementDenied) {
			if auditErr := store.persistSiteEntitlementDenial(
				ctx, actor, request.SiteID, request.RequestID, "cache.operation.create",
			); auditErr != nil {
				err = errors.Join(err, auditErr)
			}
		}
		return OperationWriteResult{}, fmt.Errorf("persist cache operation: %w", err)
	}
	return result, nil
}

func (store *Store) GetOperation(ctx context.Context, actor Actor, operationID uuid.UUID) (Operation, error) {
	if ctx == nil || !validActor(actor) || operationID == uuid.Nil {
		return Operation{}, ErrInvalidInput
	}
	var result Operation
	err := pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{
		IsoLevel: pgx.RepeatableRead,
	}, func(tx pgx.Tx) error {
		if _, err := store.authorizeActor(ctx, tx, actor, "sites.read"); err != nil {
			return err
		}
		var err error
		result, err = loadOperation(ctx, tx, actor.ScopeID, operationID)
		return err
	})
	return result, err
}

type operationQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func loadOperation(ctx context.Context, query operationQuerier, scopeID, operationID uuid.UUID) (Operation, error) {
	var result Operation
	var state string
	var maxAttempts int
	var cancelledAt, startedAt, completedAt *time.Time
	err := query.QueryRow(ctx, `
		SELECT operation.id,operation.display_id::text,operation.scope_id,operation.tenant_id,
		       operation.site_id,site.display_id::text,operation.action,operation.target_type,
		       operation.idempotency_key,operation.state,operation.max_attempts,
		       operation.total_count,operation.completed_count,operation.succeeded_count,
		       operation.failed_count,operation.cancelled_count,operation.cancel_requested_at,
		       operation.created_at,operation.started_at,operation.updated_at,operation.completed_at,
		       operation.auto_nodes,operation.parent_operation_id
		FROM cache_operations operation
		JOIN sites site ON site.scope_id=operation.scope_id AND site.id=operation.site_id
		WHERE operation.scope_id=$1 AND operation.id=$2`, scopeID, operationID).Scan(
		&result.ID, &result.DisplayID, &result.ScopeID, &result.TenantID, &result.SiteID,
		&result.SiteDisplayID, &result.Action,
		&result.TargetType, &result.IdempotencyKey, &state, &maxAttempts,
		&result.Progress.Total, &result.Progress.Completed, &result.Progress.Succeeded,
		&result.Progress.Failed, &result.Progress.Cancelled, &cancelledAt,
		&result.CreatedAt, &startedAt, &result.UpdatedAt, &completedAt, &result.AutoNodes,
		&result.ParentOperationID)
	if err == pgx.ErrNoRows {
		return Operation{}, ErrNotFound
	}
	if err != nil {
		return Operation{}, fmt.Errorf("load cache operation: %w", err)
	}
	result.State = State(state)
	result.MaxAttempts = uint32(maxAttempts)
	if cancelledAt != nil {
		result.CancelRequestedAt = *cancelledAt
	}
	if startedAt != nil {
		result.StartedAt = *startedAt
	}
	if completedAt != nil {
		result.CompletedAt = *completedAt
	}

	rows, err := query.Query(ctx, `
		SELECT ordinal,canonical_url,canonical_path FROM cache_operation_targets
		WHERE scope_id=$1 AND operation_id=$2 ORDER BY ordinal`, scopeID, operationID)
	if err != nil {
		return Operation{}, fmt.Errorf("load cache operation targets: %w", err)
	}
	for rows.Next() {
		var target Target
		if err := rows.Scan(&target.Ordinal, &target.CanonicalURL, &target.CanonicalPath); err != nil {
			rows.Close()
			return Operation{}, fmt.Errorf("scan cache operation target: %w", err)
		}
		result.Targets = append(result.Targets, target)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return Operation{}, err
	}
	rows.Close()

	rows, err = query.Query(ctx, `
		SELECT projection.node_id,node.display_id::text,projection.state,projection.attempt,
		       projection.total_count,projection.completed_count,projection.succeeded_count,projection.failed_count,
		       projection.cancelled_count,projection.last_error_code,projection.updated_at,projection.completed_at,
		       (SELECT delivery.state FROM cache_operation_cancel_deliveries delivery
		        WHERE delivery.scope_id=projection.scope_id AND delivery.operation_id=projection.operation_id
		          AND delivery.node_id=projection.node_id ORDER BY delivery.attempt DESC LIMIT 1)
		FROM cache_operation_nodes projection
		JOIN nodes node ON node.id=projection.node_id
		WHERE projection.scope_id=$1 AND projection.operation_id=$2 ORDER BY projection.node_id`,
		scopeID, operationID)
	if err != nil {
		return Operation{}, fmt.Errorf("load cache operation nodes: %w", err)
	}
	nodeIndex := make(map[uuid.UUID]int)
	for rows.Next() {
		var node NodeProjection
		var nodeState string
		var attempt int
		var errorCode *string
		var nodeCompletedAt *time.Time
		var cancelConfirmation *string
		if err := rows.Scan(
			&node.NodeID, &node.NodeDisplayID, &nodeState, &attempt, &node.Progress.Total, &node.Progress.Completed,
			&node.Progress.Succeeded, &node.Progress.Failed, &node.Progress.Cancelled,
			&errorCode, &node.UpdatedAt, &nodeCompletedAt, &cancelConfirmation,
		); err != nil {
			rows.Close()
			return Operation{}, fmt.Errorf("scan cache operation node: %w", err)
		}
		node.State = State(nodeState)
		node.Attempt = uint32(attempt)
		if errorCode != nil {
			node.LastErrorCode = *errorCode
		}
		if nodeCompletedAt != nil {
			node.CompletedAt = *nodeCompletedAt
		}
		if cancelConfirmation != nil {
			node.CancelConfirmation = CancelConfirmation(*cancelConfirmation)
		}
		nodeIndex[node.NodeID] = len(result.Nodes)
		result.Nodes = append(result.Nodes, node)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return Operation{}, err
	}
	rows.Close()

	rows, err = query.Query(ctx, `
		SELECT node_id,target_ordinal,state,attempt,sequence,error_code,completed_at
		FROM cache_operation_node_targets
		WHERE scope_id=$1 AND operation_id=$2 ORDER BY node_id,target_ordinal`, scopeID, operationID)
	if err != nil {
		return Operation{}, fmt.Errorf("load cache operation target projections: %w", err)
	}
	for rows.Next() {
		var nodeID uuid.UUID
		var projection TargetProjection
		var itemState string
		var attempt int
		var sequence int64
		var errorCode *string
		var itemCompletedAt *time.Time
		if err := rows.Scan(&nodeID, &projection.TargetOrdinal, &itemState, &attempt,
			&sequence, &errorCode, &itemCompletedAt); err != nil {
			rows.Close()
			return Operation{}, fmt.Errorf("scan cache operation target projection: %w", err)
		}
		index, exists := nodeIndex[nodeID]
		if !exists {
			rows.Close()
			return Operation{}, fmt.Errorf("cache operation target projection has no node")
		}
		projection.State = ItemState(itemState)
		projection.Attempt = uint32(attempt)
		projection.Sequence = uint64(sequence)
		if errorCode != nil {
			projection.ErrorCode = *errorCode
		}
		if itemCompletedAt != nil {
			projection.CompletedAt = *itemCompletedAt
		}
		result.Nodes[index].Targets = append(result.Nodes[index].Targets, projection)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return Operation{}, err
	}
	rows.Close()
	return result, nil
}

// operationInsert is one operation to write (CreateOperation, or a follow-up
// for a node that started carrying an automatic operation's site).
type operationInsert struct {
	actor          Actor
	tenantID       uuid.UUID
	siteID         uuid.UUID
	action         Action
	targetType     TargetType
	targets        []Target
	nodeIDs        []uuid.UUID
	maxRetries     uint32
	idempotencyKey string
	requestID      string
	digest         [32]byte
	autoNodes      bool
	parent         *uuid.UUID
}

func (in operationInsert) parentText() string {
	if in.parent == nil {
		return ""
	}
	return in.parent.String()
}

// insertOperation writes the operation, its targets, node and target
// projections, unified job and creation audit. existing reports an
// operation the idempotency key already names (its ID is returned).
func (store *Store) insertOperation(ctx context.Context, tx pgx.Tx, in operationInsert, now time.Time) (uuid.UUID, bool, error) {
	var nodeCount int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM nodes
		WHERE id=ANY($2) AND tenant_carries_node_287($1,id)`,
		in.actor.ScopeID, in.nodeIDs).Scan(&nodeCount); err != nil {
		return uuid.Nil, false, fmt.Errorf("validate cache operation nodes: %w", err)
	}
	if nodeCount != len(in.nodeIDs) {
		return uuid.Nil, false, ErrTargetNodeUnavailable
	}
	operationID := uuid.New()
	command, err := tx.Exec(ctx, `
		INSERT INTO cache_operations (
			id,scope_id,tenant_id,site_id,action,target_type,idempotency_key,request_digest,
			request_id,actor_scope_id,actor_user_id,state,max_attempts,target_count,node_count,total_count,
			created_at,updated_at,auto_nodes,parent_operation_id
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'queued',$12,$13,$14,$15,$16,$16,$17,$18)
		ON CONFLICT (scope_id,actor_scope_id,actor_user_id,idempotency_key) DO NOTHING`,
		operationID, in.actor.ScopeID, in.tenantID, in.siteID, in.action, in.targetType,
		in.idempotencyKey, in.digest[:], in.requestID, in.actor.ActorScopeID, in.actor.UserID, in.maxRetries+1,
		len(in.targets), len(in.nodeIDs), len(in.targets)*len(in.nodeIDs), now, in.autoNodes, in.parent)
	if err != nil {
		return uuid.Nil, false, fmt.Errorf("create cache operation: %w", err)
	}
	if command.RowsAffected() == 0 {
		var existingID, existingActorID uuid.UUID
		var existingDigest []byte
		if err := tx.QueryRow(ctx, `
			SELECT id,actor_user_id,request_digest FROM cache_operations
			WHERE scope_id=$1 AND actor_scope_id=$2 AND actor_user_id=$3 AND idempotency_key=$4 FOR UPDATE`,
			in.actor.ScopeID, in.actor.ActorScopeID, in.actor.UserID, in.idempotencyKey).Scan(
			&existingID, &existingActorID, &existingDigest,
		); err != nil {
			return uuid.Nil, false, fmt.Errorf("read concurrent cache operation: %w", err)
		}
		if existingActorID != in.actor.UserID || !bytes.Equal(existingDigest, in.digest[:]) {
			return uuid.Nil, false, ErrIdempotencyConflict
		}
		return existingID, true, nil
	}

	targetRows := make([][]any, len(in.targets))
	for index, target := range in.targets {
		targetRows[index] = []any{
			operationID, in.actor.ScopeID, target.Ordinal, target.CanonicalURL, target.CanonicalPath,
		}
	}
	if inserted, err := tx.CopyFrom(ctx, pgx.Identifier{"cache_operation_targets"},
		[]string{"operation_id", "scope_id", "ordinal", "canonical_url", "canonical_path"},
		pgx.CopyFromRows(targetRows)); err != nil || inserted != int64(len(targetRows)) {
		if err != nil {
			return uuid.Nil, false, fmt.Errorf("create cache operation targets: %w", err)
		}
		return uuid.Nil, false, fmt.Errorf("create cache operation targets: inserted %d of %d", inserted, len(targetRows))
	}

	nodeRows := make([][]any, len(in.nodeIDs))
	for index, nodeID := range in.nodeIDs {
		nodeRows[index] = []any{
			operationID, in.actor.ScopeID, nodeID, string(StateQueued), len(in.targets), now, now, now,
		}
	}
	if inserted, err := tx.CopyFrom(ctx, pgx.Identifier{"cache_operation_nodes"},
		[]string{"operation_id", "scope_id", "node_id", "state", "total_count", "next_attempt_at", "created_at", "updated_at"},
		pgx.CopyFromRows(nodeRows)); err != nil || inserted != int64(len(nodeRows)) {
		if err != nil {
			return uuid.Nil, false, fmt.Errorf("create cache operation node projections: %w", err)
		}
		return uuid.Nil, false, fmt.Errorf("create cache operation node projections: inserted %d of %d", inserted, len(nodeRows))
	}

	projectionRows := make([][]any, 0, len(in.targets)*len(in.nodeIDs))
	for _, nodeID := range in.nodeIDs {
		for _, target := range in.targets {
			projectionRows = append(projectionRows, []any{
				operationID, in.actor.ScopeID, nodeID, target.Ordinal, string(ItemQueued),
			})
		}
	}
	if inserted, err := tx.CopyFrom(ctx, pgx.Identifier{"cache_operation_node_targets"},
		[]string{"operation_id", "scope_id", "node_id", "target_ordinal", "state"},
		pgx.CopyFromRows(projectionRows)); err != nil || inserted != int64(len(projectionRows)) {
		if err != nil {
			return uuid.Nil, false, fmt.Errorf("create cache operation target projections: %w", err)
		}
		return uuid.Nil, false, fmt.Errorf("create cache operation target projections: inserted %d of %d", inserted, len(projectionRows))
	}
	jobItems := make([]jobstate.CreateItem, 0, len(projectionRows))
	for _, nodeID := range in.nodeIDs {
		for _, target := range in.targets {
			node := nodeID
			jobItems = append(jobItems, jobstate.CreateItem{
				ItemID: fmt.Sprintf("%s:%d", nodeID, target.Ordinal),
				NodeID: &node,
			})
		}
	}
	if _, err := jobstate.CreateTx(ctx, tx, jobstate.CreateInput{
		JobID: operationID, TenantID: in.tenantID, Kind: "cache.operation",
		Subject: operationID.String(), IdempotencyKey: "cache.operation." + operationID.String(),
		Payload: in.digest[:], Items: jobItems, MaxAttempts: in.maxRetries + 1,
		RequestID: in.requestID,
	}, now); err != nil {
		return uuid.Nil, false, fmt.Errorf("create unified cache operation job: %w", err)
	}
	if _, err := store.appendAudit(ctx, tx, in.actor.ScopeID, &in.actor.UserID,
		"cache.operation.create", operationID, in.requestID, map[string]any{
			"actor_scope_id": in.actor.ActorScopeID,
			"action":         in.action, "target_type": in.targetType,
			"targets": len(in.targets), "nodes": len(in.nodeIDs), "max_attempts": in.maxRetries + 1,
			"priority": "normal", "request_digest": fmt.Sprintf("%x", in.digest[:]),
			"auto_nodes": in.autoNodes, "parent_operation_id": in.parentText(),
		}); err != nil {
		return uuid.Nil, false, err
	}
	return operationID, false, nil
}
