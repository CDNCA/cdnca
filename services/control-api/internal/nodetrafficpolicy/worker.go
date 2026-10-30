package nodetrafficpolicy

import (
	"context"
	"errors"
	"strconv"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type SyncDispatcher interface {
	Dispatch(context.Context, SyncTask) (uuid.UUID, error)
}

type EvaluationWorker struct {
	store    *Store
	service  *Service
	now      func() time.Time
	interval time.Duration
}

func NewEvaluationWorker(store *Store, service *Service, now func() time.Time, interval time.Duration) (*EvaluationWorker, error) {
	if store == nil || service == nil || now == nil || interval < time.Minute || interval > time.Hour {
		return nil, ErrInvalidConfig
	}
	return &EvaluationWorker{store: store, service: service, now: now, interval: interval}, nil
}

func (worker *EvaluationWorker) RunOnce(ctx context.Context) (bool, error) {
	now := worker.now().UTC()
	var scopeID, nodeID uuid.UUID
	err := worker.store.pool.QueryRow(ctx, `WITH candidate AS (
		SELECT scope_id,node_id FROM node_traffic_policies
		WHERE next_evaluation_at<=$1 ORDER BY next_evaluation_at,scope_id,node_id
		FOR UPDATE SKIP LOCKED LIMIT 1
	) UPDATE node_traffic_policies policy
	SET next_evaluation_at=$2,last_evaluation_error=NULL
	FROM candidate WHERE policy.scope_id=candidate.scope_id AND policy.node_id=candidate.node_id
	RETURNING policy.scope_id,policy.node_id`, now, now.Add(worker.interval)).Scan(&scopeID, &nodeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, errors.Join(ErrUnavailable, err)
	}
	slot := now.Truncate(worker.interval)
	requestID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("cdnca.node-traffic-evaluation/v1:"+scopeID.String()+":"+nodeID.String()+":"+slot.Format(time.RFC3339))).String()
	_, evaluateErr := worker.service.EvaluateSystem(ctx, EvaluateRequest{
		ScopeID: scopeID, NodeID: nodeID,
		IdempotencyKey: "node-traffic-auto:" + nodeID.String() + ":" + strconv.FormatInt(slot.Unix(), 10),
		RequestID:      requestID,
	})
	if evaluateErr == nil {
		return true, nil
	}
	_, rescheduleErr := worker.store.pool.Exec(ctx, `UPDATE node_traffic_policies
		SET next_evaluation_at=$3,last_evaluation_error='evaluation_failed'
		WHERE scope_id=$1 AND node_id=$2`, scopeID, nodeID, now.Add(15*time.Second))
	return true, errors.Join(evaluateErr, rescheduleErr)
}

type Worker struct {
	store      *Store
	dispatcher SyncDispatcher
	now        func() time.Time
}

func NewWorker(store *Store, dispatcher SyncDispatcher, now func() time.Time) (*Worker, error) {
	if store == nil || dispatcher == nil || now == nil {
		return nil, ErrInvalidConfig
	}
	return &Worker{store: store, dispatcher: dispatcher, now: now}, nil
}

func (worker *Worker) RunOnce(ctx context.Context) (bool, error) {
	task, found, err := worker.claim(ctx)
	if err != nil || !found {
		return found, err
	}
	rolloutID, dispatchErr := worker.dispatcher.Dispatch(ctx, task)
	if dispatchErr != nil {
		return true, errors.Join(dispatchErr, worker.finish(ctx, task.ID, SyncTaskFailed, uuid.Nil, "edge_deployment_unavailable"))
	}
	return true, worker.finish(ctx, task.ID, SyncTaskRunning, rolloutID, "")
}

func (worker *Worker) ReconcileOnce(ctx context.Context) (bool, error) {
	var taskID uuid.UUID
	var rolloutState string
	err := worker.store.pool.QueryRow(ctx, `SELECT task.id,rollout.status
		FROM node_traffic_sync_tasks task JOIN rollouts rollout
			ON rollout.id=task.rollout_id AND rollout.configuration_scope_id=task.scope_id
		WHERE task.status='running' AND task.rollout_id IS NOT NULL
			AND rollout.status IN ('completed','failed','cancelled')
		ORDER BY task.updated_at,task.id LIMIT 1`).Scan(&taskID, &rolloutState)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, errors.Join(ErrUnavailable, err)
	}
	switch rolloutState {
	case "completed":
		return true, worker.finish(ctx, taskID, SyncTaskSucceeded, uuid.Nil, "")
	case "failed", "cancelled":
		return true, worker.finish(ctx, taskID, SyncTaskFailed, uuid.Nil, "edge_rollout_"+rolloutState)
	default:
		return true, nil
	}
}

func (worker *Worker) claim(ctx context.Context) (SyncTask, bool, error) {
	var task SyncTask
	now := worker.now().UTC()
	err := worker.store.pool.QueryRow(ctx, `WITH candidate AS (
		SELECT id FROM node_traffic_sync_tasks WHERE status='queued' AND available_at<=$1
		ORDER BY available_at,id FOR UPDATE SKIP LOCKED LIMIT 1
	) UPDATE node_traffic_sync_tasks task SET status='running',attempts=attempts+1,updated_at=$1
	FROM candidate WHERE task.id=candidate.id
	RETURNING task.id,task.scope_id,task.node_id,task.config_version_id,task.status,task.created_at,task.updated_at`, now).Scan(
		&task.ID, &task.ScopeID, &task.NodeID, &task.ConfigVersionID, &task.Status, &task.CreatedAt, &task.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return SyncTask{}, false, nil
	}
	if err != nil {
		return SyncTask{}, false, errors.Join(ErrUnavailable, err)
	}
	return task, true, nil
}

func (worker *Worker) finish(ctx context.Context, taskID uuid.UUID, status string, rolloutID uuid.UUID, errorCode string) error {
	var rollout any
	if rolloutID != uuid.Nil {
		rollout = rolloutID
	}
	var failure any
	if errorCode != "" {
		failure = errorCode
	}
	command, err := worker.store.pool.Exec(ctx, `UPDATE node_traffic_sync_tasks
		SET status=$2,rollout_id=COALESCE($3,rollout_id),error_code=$4,updated_at=$5 WHERE id=$1 AND status='running'`,
		taskID, status, rollout, failure, worker.now().UTC())
	if err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	if command.RowsAffected() != 1 {
		return ErrRevisionConflict
	}
	return nil
}

type RolloutCreator interface {
	CreateRollout(context.Context, edgedeployment.CreateRolloutRequest) (edgedeployment.CreateRolloutResult, error)
}

type EdgeDeploymentDispatcher struct {
	creator RolloutCreator
	now     func() time.Time
}

func NewEdgeDeploymentDispatcher(creator RolloutCreator, now func() time.Time) (*EdgeDeploymentDispatcher, error) {
	if creator == nil || now == nil {
		return nil, ErrInvalidConfig
	}
	return &EdgeDeploymentDispatcher{creator: creator, now: now}, nil
}

func (dispatcher *EdgeDeploymentDispatcher) Dispatch(ctx context.Context, task SyncTask) (uuid.UUID, error) {
	if task.ID == uuid.Nil || task.ScopeID == uuid.Nil || task.NodeID == uuid.Nil || task.ConfigVersionID == uuid.Nil {
		return uuid.Nil, ErrInvalidInput
	}
	now := dispatcher.now().UTC()
	taskID := task.ID.String()
	result, err := dispatcher.creator.CreateRollout(ctx, edgedeployment.CreateRolloutRequest{
		ConfigurationScopeID: task.ScopeID, ConfigVersionID: task.ConfigVersionID,
		Action: agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY, NodeIDs: []uuid.UUID{task.NodeID},
		HealthCheck: edgedeployment.HealthCheckPolicy{
			ActivationTimeout: 30 * time.Second, ObservationWindow: 30 * time.Second,
			RequiredConsecutiveSuccesses: 3,
		},
		Deadline: now.Add(10 * time.Minute), IdempotencyKey: "node-traffic-sync:" + taskID,
		RequestID: taskID, CorrelationID: taskID, TaskID: &taskID, MaxAttempts: 3, ContractVersion: 2,
		Rollout: edgedeployment.RolloutPolicy{
			Strategy: edgedeployment.RolloutStrategyCanary, CanarySize: 1, BatchSize: 1,
			FailureThreshold: 1, AutoStart: true, CohortCount: 1,
		},
	})
	if err != nil {
		return uuid.Nil, err
	}
	return result.Rollout.ID, nil
}
