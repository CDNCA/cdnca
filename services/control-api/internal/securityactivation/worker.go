package securityactivation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

const reconcileWorkerBatchSize = 100

type Worker struct {
	store   *Store
	running atomic.Bool
	mu      sync.RWMutex
	lastOK  time.Time
	cursor  uuid.UUID
	rebind  *rebinder
}

type workerItem struct {
	actor              securitypolicy.Actor
	input              ReconcileInput
	status             CandidateStatus
	updatedAt          time.Time
	receiptAt          *time.Time
	receiptSeq         int64
	nodeStateAt        *time.Time
	recoveryAt         *time.Time
	recoveryReceiptAt  *time.Time
	recoveryReceiptSeq int64
}

func NewWorker(store *Store) (*Worker, error) {
	if store == nil || store.pool == nil || store.clock == nil || store.config.validate() != nil {
		return nil, ErrInvalidInput
	}
	return &Worker{store: store, rebind: newRebinder(store, store.clock, store.config.CandidateTTL)}, nil
}

func (worker *Worker) Run(ctx context.Context) error {
	if worker == nil || worker.store == nil || ctx == nil || !worker.running.CompareAndSwap(false, true) {
		return ErrUnavailable
	}
	defer worker.running.Store(false)
	if err := worker.reconcile(ctx); err != nil {
		return err
	}
	worker.markReady()
	ticker := time.NewTicker(worker.store.config.ReconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := worker.reconcile(ctx); err != nil {
				return err
			}
			worker.markReady()
		}
	}
}

func (worker *Worker) Ready() error {
	if worker == nil || worker.store == nil || !worker.running.Load() {
		return ErrUnavailable
	}
	worker.mu.RLock()
	lastOK := worker.lastOK
	worker.mu.RUnlock()
	if lastOK.IsZero() || worker.store.clock().Sub(lastOK) > 3*worker.store.config.ReconcileInterval {
		return ErrUnavailable
	}
	return nil
}

func (worker *Worker) reconcile(ctx context.Context) error {
	if worker.store.publisher != nil {
		if err := worker.store.resumeCapabilityWaits(ctx); err != nil {
			return err
		}
	}
	// A library saved without a site context republishes its stale bound
	// sites (rebind.go); their candidates are reconciled below.
	if worker.store.publisher != nil {
		if err := worker.rebind.run(ctx); err != nil {
			return err
		}
	}
	items, err := worker.store.loadWorkerItems(ctx, reconcileWorkerBatchSize, worker.cursor)
	if err != nil {
		return err
	}
	if len(items) == 0 {
		worker.cursor = uuid.Nil
		return nil
	}
	for _, item := range items {
		item.input.IdempotencyKey = workerItemKey(item)
		requestID := uuid.NewSHA1(item.input.CandidateID, []byte(item.input.IdempotencyKey)).String()
		item.input.RequestID = requestID
		item.input.CorrelationID = item.input.CandidateID.String()
		item.input.Traceparent = activationTraceparent(item.input.CandidateID, "worker")
		taskID := "security-activation-reconcile"
		item.input.TaskID = &taskID
		_, err := worker.store.Reconcile(ctx, item.actor, item.input)
		if errors.Is(err, ErrPermissionDenied) {
			recoveryContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), worker.store.config.HealthCheck)
			_, err = worker.store.reconcileRevokedCandidate(recoveryContext, item.actor, item.input)
			cancel()
		}
		if err != nil && !ignorableWorkerError(err) {
			return fmt.Errorf("reconcile security activation %s: %w", item.input.CandidateID, err)
		}
	}
	worker.cursor = items[len(items)-1].input.CandidateID
	if len(items) < reconcileWorkerBatchSize {
		worker.cursor = uuid.Nil
	}
	return nil
}

// ignorableWorkerError skips the item for this pass; the next pass retries.
// Row contention (55P03 NOWAIT lock not available, 40001 serialization
// failure, 40P01 deadlock) is a concurrent writer, not a reason to stop.
func ignorableWorkerError(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && (pgErr.Code == "55P03" || pgErr.Code == "40001" || pgErr.Code == "40P01") {
		return true
	}
	return errors.Is(err, ErrInvalidInput) || errors.Is(err, ErrPermissionDenied) ||
		errors.Is(err, ErrNotFound) || errors.Is(err, ErrConflict) ||
		errors.Is(err, ErrIdempotencyConflict) || errors.Is(err, ErrNotHealthy) ||
		errors.Is(err, ErrSourceRevisionConflict)
}

func (worker *Worker) markReady() {
	worker.mu.Lock()
	worker.lastOK = worker.store.clock().UTC()
	worker.mu.Unlock()
}

func (store *Store) loadWorkerItems(ctx context.Context, limit int, after uuid.UUID) ([]workerItem, error) {
	if limit < 1 || limit > 1000 {
		return nil, ErrInvalidInput
	}
	rows, err := store.pool.Query(ctx, `SELECT
		candidate.id,candidate.tenant_scope_id,candidate.binding_id,candidate.binding_revision,
		candidate.last_bundle_id,candidate.last_claimed_policy_version,candidate.expected_active_policy_version,
		candidate.candidate_source_revision,candidate.candidate_config_version_id,
		candidate.candidate_artifact_sha256,candidate.target_snapshot_sha256,candidate.candidate_status,
		candidate.actor_scope_id,candidate.actor_user_id,actor_scope.kind,candidate.updated_at,
		(SELECT max(event.received_at) FROM security_policy_activation_rollouts activation_rollout
		 JOIN node_deployments deployment ON deployment.rollout_id=activation_rollout.rollout_id
		 JOIN deployment_status_events event ON event.deployment_id=deployment.id
		 WHERE activation_rollout.candidate_id=candidate.id),
		COALESCE((SELECT max(event.transition_sequence) FROM security_policy_activation_rollouts activation_rollout
		 JOIN node_deployments deployment ON deployment.rollout_id=activation_rollout.rollout_id
		 JOIN deployment_status_events event ON event.deployment_id=deployment.id
		 WHERE activation_rollout.candidate_id=candidate.id),0),
		(SELECT max(state.updated_at) FROM node_config_state state
		 WHERE state.configuration_scope_id=candidate.tenant_scope_id
		   AND state.node_id=ANY(candidate.canary_node_ids || candidate.expand_node_ids)),
		(SELECT max(recovery.created_at) FROM security_policy_activation_recovery_rollouts recovery
		 WHERE recovery.candidate_id=candidate.id),
		(SELECT max(event.received_at) FROM security_policy_activation_recovery_rollouts recovery
		 JOIN node_deployments deployment ON deployment.rollout_id=recovery.rollout_id
		 JOIN deployment_status_events event ON event.deployment_id=deployment.id
		 WHERE recovery.candidate_id=candidate.id),
		COALESCE((SELECT max(event.transition_sequence) FROM security_policy_activation_recovery_rollouts recovery
		 JOIN node_deployments deployment ON deployment.rollout_id=recovery.rollout_id
		 JOIN deployment_status_events event ON event.deployment_id=deployment.id
		 WHERE recovery.candidate_id=candidate.id),0)
	FROM security_policy_activation_candidates candidate
	JOIN access_scopes actor_scope ON actor_scope.id=candidate.actor_scope_id
	WHERE (candidate.candidate_status IN ('claimed','canary','expanding','healthy') OR
	      (candidate.candidate_status IN ('failed','cancelled','expired') AND candidate.recovered_at IS NULL))
	  AND ($2::uuid='00000000-0000-0000-0000-000000000000'::uuid OR candidate.id>$2)
	ORDER BY candidate.id LIMIT $1`, limit, after)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]workerItem, 0, limit)
	for rows.Next() {
		var item workerItem
		var artifact, target []byte
		if err := rows.Scan(
			&item.input.CandidateID, &item.input.PromotionCAS.TenantScopeID,
			&item.input.PromotionCAS.BindingID, &item.input.PromotionCAS.BindingRevision,
			&item.input.PromotionCAS.LastBundleID, &item.input.PromotionCAS.LastClaimedPolicyVersion,
			&item.input.PromotionCAS.ExpectedActivePolicyVersion,
			&item.input.PromotionCAS.CandidateSourceRevision,
			&item.input.PromotionCAS.CandidateConfigVersionID, &artifact, &target, &item.status,
			&item.actor.ScopeID, &item.actor.UserID, &item.actor.ScopeKind, &item.updatedAt,
			&item.receiptAt, &item.receiptSeq, &item.nodeStateAt, &item.recoveryAt,
			&item.recoveryReceiptAt, &item.recoveryReceiptSeq,
		); err != nil {
			return nil, err
		}
		if len(artifact) != sha256.Size || len(target) != sha256.Size {
			return nil, ErrConflict
		}
		copy(item.input.PromotionCAS.CandidateArtifactSHA256[:], artifact)
		copy(item.input.PromotionCAS.TargetSnapshotSHA256[:], target)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

func workerItemKey(item workerItem) string {
	value := item.input.CandidateID.String() + "\n" + string(item.status) + "\n" +
		item.updatedAt.UTC().Format(time.RFC3339Nano) + "\n" + workerTime(item.receiptAt) + "\n" +
		fmt.Sprint(item.receiptSeq) + "\n" + workerTime(item.nodeStateAt) + "\n" + workerTime(item.recoveryAt) + "\n" +
		workerTime(item.recoveryReceiptAt) + "\n" + fmt.Sprint(item.recoveryReceiptSeq)
	digest := sha256.Sum256([]byte(value))
	return "worker." + hex.EncodeToString(digest[:])
}

func workerTime(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

var _ interface {
	Run(context.Context) error
	Ready() error
} = (*Worker)(nil)
