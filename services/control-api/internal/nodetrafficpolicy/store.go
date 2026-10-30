package nodetrafficpolicy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool    *pgxpool.Pool
	auditor *audit.Log
	now     func() time.Time
}

func NewStore(pool *pgxpool.Pool, now func() time.Time) (*Store, error) {
	if pool == nil || now == nil {
		return nil, ErrInvalidConfig
	}
	return &Store{pool: pool, auditor: audit.NewWithClock(pool, now), now: now}, nil
}

func (store *Store) Get(ctx context.Context, scopeID, nodeID uuid.UUID) (PolicyState, error) {
	if scopeID == uuid.Nil || nodeID == uuid.Nil {
		return PolicyState{}, ErrInvalidInput
	}
	var state PolicyState
	var windows []byte
	var overrideExpiresAt *time.Time
	var configVersionID *uuid.UUID
	err := store.pool.QueryRow(ctx, `
		SELECT policy.id,policy.scope_id,policy.node_id,policy.monthly_limit_bytes,policy.timezone,
		       policy.windows,policy.override_mode,policy.override_revision,policy.override_expires_at,
		       policy.revision,policy.created_at,policy.updated_at,node.admin_state,config.current_config_version_id
		FROM node_traffic_policies policy
		JOIN nodes node ON node.id=policy.node_id AND node.scope_id=policy.scope_id
		LEFT JOIN node_config_state config ON config.node_id=node.id AND config.configuration_scope_id=policy.scope_id
		WHERE policy.scope_id=$1 AND policy.node_id=$2`, scopeID, nodeID).Scan(
		&state.Policy.ID, &state.Policy.ScopeID, &state.Policy.NodeID, &state.Policy.MonthlyLimitBytes,
		&state.Policy.Timezone, &windows, &state.Policy.Override.Mode, &state.Policy.Override.Revision,
		&overrideExpiresAt, &state.Policy.Revision, &state.Policy.CreatedAt, &state.Policy.UpdatedAt,
		&state.AdminState, &configVersionID,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		var createdAt, updatedAt time.Time
		err = store.pool.QueryRow(ctx, `SELECT node.admin_state,node.created_at,node.updated_at,config.current_config_version_id
			FROM nodes node LEFT JOIN node_config_state config ON config.node_id=node.id
			  AND config.configuration_scope_id=node.scope_id
			WHERE node.scope_id=$1 AND node.id=$2`, scopeID, nodeID).
			Scan(&state.AdminState, &createdAt, &updatedAt, &configVersionID)
		if errors.Is(err, pgx.ErrNoRows) {
			return PolicyState{}, ErrNotFound
		}
		if err != nil {
			return PolicyState{}, errors.Join(ErrUnavailable, err)
		}
		state.Policy = Policy{
			ID: PolicyID(scopeID, nodeID), ScopeID: scopeID, NodeID: nodeID,
			Timezone: "Asia/Shanghai", Windows: []ScheduleWindow{}, Override: ManualOverride{Mode: OverrideNone},
			Revision: 0, CreatedAt: createdAt, UpdatedAt: updatedAt,
		}
		state.CurrentConfigVersionID = configVersionID
		return state, nil
	}
	if err != nil {
		return PolicyState{}, errors.Join(ErrUnavailable, err)
	}
	if err := json.Unmarshal(windows, &state.Policy.Windows); err != nil {
		return PolicyState{}, errors.Join(ErrUnavailable, err)
	}
	state.Policy.Override.ExpiresAt = overrideExpiresAt
	if configVersionID != nil {
		state.CurrentConfigVersionID = configVersionID
	}
	var latest EvaluationSnapshot
	err = store.pool.QueryRow(ctx, `
		SELECT period_key,suppressed,reason_code,override_revision
		FROM node_traffic_policy_evaluations
		WHERE scope_id=$1 AND node_id=$2 ORDER BY evaluated_at DESC,id DESC LIMIT 1`, scopeID, nodeID).Scan(
		&latest.PeriodKey, &latest.Suppressed, &latest.ReasonCode, &latest.OverrideRevision)
	if err == nil {
		state.LastEvaluation = &latest
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return PolicyState{}, errors.Join(ErrUnavailable, err)
	}
	return state, nil
}

func (store *Store) Put(ctx context.Context, actor Actor, request PutRequest) (WriteResult, error) {
	digest, err := putRequestDigest(request)
	if err != nil {
		return WriteResult{}, ErrInvalidInput
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return WriteResult{}, errors.Join(ErrUnavailable, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if replay, found, replayErr := replayOperation[WriteResult](ctx, tx, request.Policy.ScopeID, request.IdempotencyKey, digest, "put"); replayErr != nil || found {
		return replay, replayErr
	}

	var lockedNodeID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM nodes WHERE id=$1 AND scope_id=$2 FOR UPDATE`, request.Policy.NodeID, request.Policy.ScopeID).Scan(&lockedNodeID); errors.Is(err, pgx.ErrNoRows) {
		return WriteResult{}, ErrNotFound
	} else if err != nil {
		return WriteResult{}, errors.Join(ErrUnavailable, err)
	}
	var currentRevision int64
	var currentOverrideMode string
	var currentOverrideRevision int64
	var currentOverrideExpiresAt *time.Time
	err = tx.QueryRow(ctx, `SELECT revision,override_mode,override_revision,override_expires_at
		FROM node_traffic_policies WHERE scope_id=$1 AND node_id=$2 FOR UPDATE`, request.Policy.ScopeID, request.Policy.NodeID).
		Scan(&currentRevision, &currentOverrideMode, &currentOverrideRevision, &currentOverrideExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		currentRevision = 0
		currentOverrideMode = OverrideNone
		currentOverrideRevision = 0
		currentOverrideExpiresAt = nil
	} else if err != nil {
		return WriteResult{}, errors.Join(ErrUnavailable, err)
	}
	if currentRevision != request.ExpectedRevision {
		return WriteResult{}, ErrRevisionConflict
	}
	if !validOverrideTransition(currentOverrideMode, currentOverrideRevision, currentOverrideExpiresAt, request.Policy.Override) {
		return WriteResult{}, ErrRevisionConflict
	}

	windows, err := json.Marshal(request.Policy.Windows)
	if err != nil {
		return WriteResult{}, ErrInvalidInput
	}
	now := store.now().UTC()
	if _, err := tx.Exec(ctx, `
		INSERT INTO node_traffic_policies(id,scope_id,node_id,monthly_limit_bytes,timezone,windows,
			override_mode,override_revision,override_expires_at,revision,created_by_user_id,created_at,updated_at,next_evaluation_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,1,$10,$11,$11,$11)
		ON CONFLICT (scope_id,node_id) DO UPDATE SET
			monthly_limit_bytes=EXCLUDED.monthly_limit_bytes,timezone=EXCLUDED.timezone,windows=EXCLUDED.windows,
			override_mode=EXCLUDED.override_mode,override_revision=EXCLUDED.override_revision,
			override_expires_at=EXCLUDED.override_expires_at,revision=node_traffic_policies.revision+1,
			updated_at=EXCLUDED.updated_at,next_evaluation_at=EXCLUDED.next_evaluation_at,last_evaluation_error=NULL`,
		request.Policy.ID, request.Policy.ScopeID, request.Policy.NodeID, request.Policy.MonthlyLimitBytes,
		request.Policy.Timezone, windows, request.Policy.Override.Mode, request.Policy.Override.Revision,
		request.Policy.Override.ExpiresAt, actor.UserID, now); err != nil {
		return WriteResult{}, errors.Join(ErrUnavailable, err)
	}
	state, err := getStateTx(ctx, tx, request.Policy.ScopeID, request.Policy.NodeID)
	if err != nil {
		return WriteResult{}, err
	}
	result := WriteResult{State: state}
	if err := recordOperation(ctx, tx, request.Policy.ScopeID, request.IdempotencyKey, digest, "put", actor.UserID, request.RequestID, result, now); err != nil {
		return WriteResult{}, err
	}
	if err := store.auditor.Append(ctx, tx, audit.Event{
		ScopeID: request.Policy.ScopeID, ActorUserID: &actor.UserID,
		Action: "node_traffic_policy.put", ResourceType: "node", ResourceID: request.Policy.NodeID.String(),
		RequestID: request.RequestID, Result: "success",
		Payload: map[string]any{
			"policy_revision": result.State.Policy.Revision, "monthly_limit_bytes": request.Policy.MonthlyLimitBytes,
			"timezone": request.Policy.Timezone, "override_mode": request.Policy.Override.Mode,
			"override_revision": request.Policy.Override.Revision,
		},
	}); err != nil {
		return WriteResult{}, errors.Join(ErrUnavailable, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return WriteResult{}, errors.Join(ErrUnavailable, err)
	}
	return result, nil
}

func (store *Store) ApplyEvaluation(ctx context.Context, request ApplyEvaluationRequest) (EvaluationRecord, error) {
	digest, err := evaluationRequestDigest(EvaluateRequest{
		ScopeID: request.ScopeID, NodeID: request.NodeID,
		IdempotencyKey: request.IdempotencyKey, RequestID: request.RequestID,
	})
	if err != nil {
		return EvaluationRecord{}, ErrInvalidInput
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return EvaluationRecord{}, errors.Join(ErrUnavailable, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if replay, found, replayErr := replayOperation[EvaluationRecord](ctx, tx, request.ScopeID, request.IdempotencyKey, digest, "evaluate"); replayErr != nil || found {
		return replay, replayErr
	}
	var revision int64
	var adminState string
	var currentConfigVersionID *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT policy.revision,node.admin_state,config.current_config_version_id FROM node_traffic_policies policy
		JOIN nodes node ON node.id=policy.node_id AND node.scope_id=policy.scope_id
		LEFT JOIN node_config_state config ON config.node_id=node.id AND config.configuration_scope_id=policy.scope_id
		WHERE policy.scope_id=$1 AND policy.node_id=$2 FOR UPDATE OF policy,node`, request.ScopeID, request.NodeID).
		Scan(&revision, &adminState, &currentConfigVersionID); errors.Is(err, pgx.ErrNoRows) {
		return EvaluationRecord{}, ErrNotFound
	} else if err != nil {
		return EvaluationRecord{}, errors.Join(ErrUnavailable, err)
	}
	if revision != request.PolicyRevision {
		return EvaluationRecord{}, ErrRevisionConflict
	}
	if adminState != request.AdminState ||
		(adminState == NodeStateDisabled || adminState == NodeStateRetired) && request.Decision.ReasonCode != ReasonAdminStateProtected {
		return EvaluationRecord{}, ErrRevisionConflict
	}
	if request.SyncTask != nil && (currentConfigVersionID == nil || *currentConfigVersionID != request.SyncTask.ConfigVersionID) {
		return EvaluationRecord{}, ErrRevisionConflict
	}
	now := store.now().UTC()
	record := EvaluationRecord{ID: uuid.New(), ScopeID: request.ScopeID, NodeID: request.NodeID, Decision: request.Decision, SyncTask: request.SyncTask}
	if _, err := tx.Exec(ctx, `INSERT INTO node_traffic_policy_evaluations(
		id,scope_id,node_id,policy_revision,period_key,period_start,period_end,usage_bytes,monthly_limit_bytes,
		suppressed,sync_required,reason_code,override_revision,evaluated_at,source_snapshot_at,
		source_finalized_through,source_digest,request_id)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,decode($17,'hex'),$18)`,
		record.ID, request.ScopeID, request.NodeID, request.PolicyRevision, request.Decision.PeriodKey,
		request.Decision.PeriodStart, request.Decision.PeriodEnd, request.Decision.UsageBytes,
		request.Decision.MonthlyLimitBytes, request.Decision.Suppressed, request.Decision.SyncRequired,
		request.Decision.ReasonCode, request.Decision.OverrideRevision, request.Decision.EvaluatedAt,
		request.Decision.SourceSnapshotAt, request.Decision.SourceFinalizedThrough, request.Decision.SourceDigest,
		request.RequestID); err != nil {
		return EvaluationRecord{}, errors.Join(ErrUnavailable, err)
	}
	if request.SyncTask != nil {
		if _, err := tx.Exec(ctx, `INSERT INTO node_traffic_sync_tasks(
			id,evaluation_id,scope_id,node_id,config_version_id,status,attempts,available_at,created_at,updated_at)
			VALUES($1,$2,$3,$4,$5,'queued',0,$6,$6,$6)`, request.SyncTask.ID, record.ID, request.ScopeID,
			request.NodeID, request.SyncTask.ConfigVersionID, now); err != nil {
			return EvaluationRecord{}, errors.Join(ErrUnavailable, err)
		}
	}
	if err := recordOperation(ctx, tx, request.ScopeID, request.IdempotencyKey, digest, "evaluate", request.ActorUserID, request.RequestID, record, now); err != nil {
		return EvaluationRecord{}, err
	}
	var actorID *uuid.UUID
	if request.ActorUserID != uuid.Nil {
		actorID = &request.ActorUserID
	}
	var syncTaskID any
	if request.SyncTask != nil {
		syncTaskID = request.SyncTask.ID.String()
	}
	if err := store.auditor.Append(ctx, tx, audit.Event{
		ScopeID: request.ScopeID, ActorUserID: actorID,
		Action: "node_traffic_policy.evaluate", ResourceType: "node", ResourceID: request.NodeID.String(),
		RequestID: request.RequestID, Result: "success",
		Payload: map[string]any{
			"period_key": request.Decision.PeriodKey, "reason_code": request.Decision.ReasonCode,
			"suppressed": request.Decision.Suppressed, "usage_bytes": request.Decision.UsageBytes,
			"policy_revision": request.PolicyRevision, "sync_task_id": syncTaskID,
		},
	}); err != nil {
		return EvaluationRecord{}, errors.Join(ErrUnavailable, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return EvaluationRecord{}, errors.Join(ErrUnavailable, err)
	}
	return record, nil
}

func (store *Store) ReplayEvaluation(ctx context.Context, request EvaluateRequest) (EvaluationRecord, bool, error) {
	digest, err := evaluationRequestDigest(request)
	if err != nil {
		return EvaluationRecord{}, false, ErrInvalidInput
	}
	var storedDigest []byte
	var response []byte
	var operation string
	err = store.pool.QueryRow(ctx, `SELECT operation,request_digest,response FROM node_traffic_policy_operations
		WHERE scope_id=$1 AND idempotency_key=$2`, request.ScopeID, request.IdempotencyKey).
		Scan(&operation, &storedDigest, &response)
	if errors.Is(err, pgx.ErrNoRows) {
		return EvaluationRecord{}, false, nil
	}
	if err != nil {
		return EvaluationRecord{}, false, errors.Join(ErrUnavailable, err)
	}
	if operation != "evaluate" || !bytes.Equal(storedDigest, digest[:]) {
		return EvaluationRecord{}, false, ErrIdempotencyConflict
	}
	var result EvaluationRecord
	if err := json.Unmarshal(response, &result); err != nil {
		return EvaluationRecord{}, false, errors.Join(ErrUnavailable, err)
	}
	result.Replayed = true
	return result, true, nil
}

func (store *Store) GetSyncTask(ctx context.Context, scopeID, taskID uuid.UUID) (SyncTask, error) {
	var task SyncTask
	err := store.pool.QueryRow(ctx, `SELECT id,scope_id,node_id,config_version_id,status,error_code,rollout_id,created_at,updated_at
		FROM node_traffic_sync_tasks WHERE scope_id=$1 AND id=$2`, scopeID, taskID).Scan(
		&task.ID, &task.ScopeID, &task.NodeID, &task.ConfigVersionID, &task.Status, &task.ErrorCode,
		&task.RolloutID, &task.CreatedAt, &task.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return SyncTask{}, ErrNotFound
	}
	if err != nil {
		return SyncTask{}, errors.Join(ErrUnavailable, err)
	}
	return task, nil
}

func getStateTx(ctx context.Context, tx pgx.Tx, scopeID, nodeID uuid.UUID) (PolicyState, error) {
	var state PolicyState
	var windows []byte
	var overrideExpiresAt *time.Time
	var configID *uuid.UUID
	err := tx.QueryRow(ctx, `SELECT policy.id,policy.scope_id,policy.node_id,policy.monthly_limit_bytes,policy.timezone,
		policy.windows,policy.override_mode,policy.override_revision,policy.override_expires_at,policy.revision,
		policy.created_at,policy.updated_at,node.admin_state,config.current_config_version_id
		FROM node_traffic_policies policy JOIN nodes node ON node.id=policy.node_id AND node.scope_id=policy.scope_id
		LEFT JOIN node_config_state config ON config.node_id=node.id AND config.configuration_scope_id=policy.scope_id
		WHERE policy.scope_id=$1 AND policy.node_id=$2`, scopeID, nodeID).Scan(
		&state.Policy.ID, &state.Policy.ScopeID, &state.Policy.NodeID, &state.Policy.MonthlyLimitBytes,
		&state.Policy.Timezone, &windows, &state.Policy.Override.Mode, &state.Policy.Override.Revision,
		&overrideExpiresAt, &state.Policy.Revision, &state.Policy.CreatedAt, &state.Policy.UpdatedAt,
		&state.AdminState, &configID)
	if err != nil {
		return PolicyState{}, errors.Join(ErrUnavailable, err)
	}
	if err := json.Unmarshal(windows, &state.Policy.Windows); err != nil {
		return PolicyState{}, errors.Join(ErrUnavailable, err)
	}
	state.Policy.Override.ExpiresAt = overrideExpiresAt
	if configID != nil {
		state.CurrentConfigVersionID = configID
	}
	return state, nil
}

func validOverrideTransition(mode string, revision int64, expiresAt *time.Time, next ManualOverride) bool {
	unchanged := mode == next.Mode && revision == next.Revision && equalTimePointers(expiresAt, next.ExpiresAt)
	if unchanged {
		return true
	}
	return next.Revision == revision+1
}

func equalTimePointers(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.Equal(*right)
}

func putRequestDigest(request PutRequest) ([32]byte, error) {
	encoded, err := json.Marshal(struct {
		ScopeID           uuid.UUID        `json:"scope_id"`
		NodeID            uuid.UUID        `json:"node_id"`
		MonthlyLimitBytes uint64           `json:"monthly_limit_bytes"`
		Timezone          string           `json:"timezone"`
		Windows           []ScheduleWindow `json:"windows"`
		Override          ManualOverride   `json:"manual_override"`
		ExpectedRevision  int64            `json:"expected_revision"`
		RequestID         string           `json:"request_id"`
	}{
		ScopeID: request.Policy.ScopeID, NodeID: request.Policy.NodeID,
		MonthlyLimitBytes: request.Policy.MonthlyLimitBytes, Timezone: request.Policy.Timezone,
		Windows: request.Policy.Windows, Override: request.Policy.Override,
		ExpectedRevision: request.ExpectedRevision, RequestID: request.RequestID,
	})
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func evaluationRequestDigest(request EvaluateRequest) ([32]byte, error) {
	encoded, err := json.Marshal(struct {
		ScopeID   uuid.UUID `json:"scope_id"`
		NodeID    uuid.UUID `json:"node_id"`
		RequestID string    `json:"request_id"`
	}{ScopeID: request.ScopeID, NodeID: request.NodeID, RequestID: request.RequestID})
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func replayOperation[T any](ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, key string, digest [32]byte, operation string) (T, bool, error) {
	var zero T
	var storedOperation string
	var storedDigest []byte
	var response []byte
	err := tx.QueryRow(ctx, `SELECT operation,request_digest,response FROM node_traffic_policy_operations
		WHERE scope_id=$1 AND idempotency_key=$2`, scopeID, key).Scan(&storedOperation, &storedDigest, &response)
	if errors.Is(err, pgx.ErrNoRows) {
		return zero, false, nil
	}
	if err != nil {
		return zero, false, errors.Join(ErrUnavailable, err)
	}
	if storedOperation != operation || !bytes.Equal(storedDigest, digest[:]) {
		return zero, false, ErrIdempotencyConflict
	}
	if err := json.Unmarshal(response, &zero); err != nil {
		return zero, false, errors.Join(ErrUnavailable, err)
	}
	switch value := any(&zero).(type) {
	case *WriteResult:
		value.Replayed = true
	case *EvaluationRecord:
		value.Replayed = true
	}
	return zero, true, nil
}

func recordOperation(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, key string, digest [32]byte, operation string, actorID uuid.UUID, requestID string, result any, now time.Time) error {
	response, err := json.Marshal(result)
	if err != nil {
		return ErrInvalidInput
	}
	var actor any
	if actorID != uuid.Nil {
		actor = actorID
	}
	_, err = tx.Exec(ctx, `INSERT INTO node_traffic_policy_operations(
		scope_id,idempotency_key,operation,request_digest,actor_user_id,request_id,response,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, scopeID, key, operation, digest[:], actor, requestID, response, now)
	if err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	return nil
}
