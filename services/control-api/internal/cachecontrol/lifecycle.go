package cachecontrol

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	codeCancelled        = "cancelled"
	codeLeaseExpired     = "lease_expired"
	codeRetriesExhausted = "retries_exhausted"
	codeTargetFailed     = "target_failed"
	leaseRetryBase       = time.Second
	leaseRetryMaximum    = time.Minute
)

type claimCandidate struct {
	operationID    uuid.UUID
	tenantID       uuid.UUID
	siteID         uuid.UUID
	action         Action
	targetType     TargetType
	nodeID         uuid.UUID
	attempt        uint32
	maxAttempts    uint32
	requestDigest  []byte
	configVersion  *uuid.UUID
	configRevision *int64
}

func (store *Store) Claim(ctx context.Context, request ClaimRequest) ([]Claim, error) {
	if ctx == nil || validateClaim(request) != nil {
		return nil, ErrInvalidInput
	}
	now := store.timestamp()
	leaseExpiresAt := now.Add(request.LeaseDuration)
	claims := make([]Claim, 0, request.Limit)
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := authorizeWorkerScope(ctx, tx, request.ScopeID); err != nil {
			return err
		}
		if err := store.expireLeases(ctx, tx, request.ScopeID, request.RequestID, now); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `
			WITH ranked AS MATERIALIZED (
					SELECT node.operation_id,node.node_id,
				       COALESCE(attempts.claim_count, 0) + row_number() OVER (
				           PARTITION BY node.operation_id
				           ORDER BY node.next_attempt_at,node.node_id
				       ) AS fairness_round
				FROM cache_operation_nodes node
				JOIN cache_operations operation ON operation.id=node.operation_id
				LEFT JOIN LATERAL (
					SELECT count(*) AS claim_count
					FROM cache_operation_node_attempts attempt
					WHERE attempt.operation_id=node.operation_id
				) attempts ON true
				WHERE node.scope_id=$1 AND node.state='queued' AND node.next_attempt_at <= $2
				  AND node.node_id=ANY($3) AND node.attempt < operation.max_attempts
				  AND operation.state IN ('queued','running')
			)
					SELECT node.operation_id,operation.tenant_id,operation.site_id,operation.action,operation.target_type,
				       node.node_id,node.attempt,operation.max_attempts,operation.request_digest,
				       config.current_config_version_id,config.revision
			FROM ranked
			JOIN cache_operation_nodes node
			  ON node.operation_id=ranked.operation_id AND node.node_id=ranked.node_id
			JOIN cache_operations operation ON operation.id=node.operation_id
			LEFT JOIN node_config_state config
			  ON config.node_id=node.node_id AND config.configuration_scope_id=operation.scope_id
			WHERE NOT $5 OR (config.current_config_version_id IS NOT NULL
			  AND NOT config.reconciliation_required)
			ORDER BY ranked.fairness_round,operation.created_at,operation.id,node.node_id
			FOR UPDATE OF node SKIP LOCKED
			LIMIT $4`, request.ScopeID, now, request.OnlineNodeIDs, request.Limit,
			request.RequireActiveConfig)
		if err != nil {
			return fmt.Errorf("select fair cache operation claims: %w", err)
		}
		candidates := make([]claimCandidate, 0, request.Limit)
		for rows.Next() {
			var candidate claimCandidate
			var attempt, maximum int
			if err := rows.Scan(
				&candidate.operationID, &candidate.tenantID, &candidate.siteID, &candidate.action,
				&candidate.targetType, &candidate.nodeID, &attempt, &maximum, &candidate.requestDigest,
				&candidate.configVersion, &candidate.configRevision,
			); err != nil {
				rows.Close()
				return fmt.Errorf("scan cache operation claim: %w", err)
			}
			candidate.attempt = uint32(attempt)
			candidate.maxAttempts = uint32(maximum)
			candidates = append(candidates, candidate)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()

		for _, candidate := range candidates {
			nextAttempt := candidate.attempt + 1
			leaseID := uuid.New()
			targets, err := loadClaimTargets(ctx, tx, request.ScopeID, candidate.operationID, candidate.nodeID)
			if err != nil {
				return err
			}
			if len(targets) == 0 || nextAttempt > candidate.maxAttempts {
				return ErrInvalidTransition
			}
			if _, err := tx.Exec(ctx, `
				UPDATE cache_operation_node_targets
				SET state='running',attempt=$4
				WHERE scope_id=$1 AND operation_id=$2 AND node_id=$3 AND state='queued'`,
				request.ScopeID, candidate.operationID, candidate.nodeID, nextAttempt); err != nil {
				return fmt.Errorf("claim cache operation target projections: %w", err)
			}
			command, err := tx.Exec(ctx, `
				UPDATE cache_operation_nodes SET
					state='running',attempt=$4,lease_id=$5,lease_owner=$6,
					lease_expires_at=$7,next_attempt_at=NULL,last_error_code=NULL,
					updated_at=$8,completed_at=NULL
				WHERE scope_id=$1 AND operation_id=$2 AND node_id=$3 AND state='queued'`,
				request.ScopeID, candidate.operationID, candidate.nodeID, nextAttempt,
				leaseID, request.WorkerID, leaseExpiresAt, now)
			if err != nil {
				return fmt.Errorf("claim cache operation node: %w", err)
			}
			if command.RowsAffected() != 1 {
				return ErrClaimLost
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO cache_operation_node_attempts (
					operation_id,scope_id,node_id,attempt,lease_id,worker_id,state,
					target_count,started_at,lease_expires_at
				) VALUES ($1,$2,$3,$4,$5,$6,'running',$7,$8,$9)`,
				candidate.operationID, request.ScopeID, candidate.nodeID, nextAttempt,
				leaseID, request.WorkerID, len(targets), now, leaseExpiresAt); err != nil {
				return fmt.Errorf("record cache operation node attempt: %w", err)
			}
			if _, err := tx.Exec(ctx, `
				UPDATE cache_operations SET state='running',started_at=COALESCE(started_at,$3),updated_at=$3
				WHERE scope_id=$1 AND id=$2 AND state IN ('queued','running')`,
				request.ScopeID, candidate.operationID, now); err != nil {
				return fmt.Errorf("start cache operation: %w", err)
			}
			if _, err := jobstate.StartTx(ctx, tx, jobstate.StartInput{
				TenantID: candidate.tenantID, JobID: candidate.operationID, Kind: "cache.operation",
				WorkerID: "cache.operation." + candidate.operationID.String(), LeaseDuration: time.Hour,
			}, now); err != nil {
				return fmt.Errorf("start unified cache operation job: %w", err)
			}
			claimAudit := map[string]any{
				"node_id": candidate.nodeID, "attempt": nextAttempt,
				"lease_id": leaseID, "target_count": len(targets),
			}
			if candidate.configVersion != nil && candidate.configRevision != nil && *candidate.configRevision > 0 {
				claimAudit["config_version_id"] = *candidate.configVersion
				claimAudit["config_revision"] = *candidate.configRevision
			} else if request.RequireActiveConfig {
				return ErrInvalidTransition
			}
			if _, err := store.appendAudit(ctx, tx, request.ScopeID, nil,
				"cache.operation.claim", candidate.operationID, request.RequestID, claimAudit); err != nil {
				return err
			}
			var requestDigest [32]byte
			if copy(requestDigest[:], candidate.requestDigest) != len(requestDigest) {
				return ErrInvalidTransition
			}
			claims = append(claims, Claim{
				OperationID: candidate.operationID, ScopeID: request.ScopeID,
				TenantID: candidate.tenantID, SiteID: candidate.siteID,
				Action: candidate.action, TargetType: candidate.targetType,
				NodeID: candidate.nodeID, Attempt: nextAttempt, LeaseID: leaseID, WorkerID: request.WorkerID,
				ClaimedAt: now, LeaseExpiresAt: leaseExpiresAt,
				RequestDigest: requestDigest, Priority: "normal", Targets: targets,
			})
			if candidate.configVersion != nil && candidate.configRevision != nil {
				claims[len(claims)-1].ConfigVersionID = *candidate.configVersion
				claims[len(claims)-1].ConfigRevision = uint64(*candidate.configRevision)
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("claim cache operations: %w", err)
	}
	return claims, nil
}

// OpenClaims rebuilds unpublished or publish-unknown commands from immutable
// running attempt facts. A restarted worker must reuse its stable worker ID.
func (store *Store) OpenClaims(ctx context.Context, request OpenClaimsRequest) ([]Claim, error) {
	if ctx == nil || !validSafeText(request.WorkerID, 128) || request.Limit < 1 || request.Limit > maxClaimBatch {
		return nil, ErrInvalidInput
	}
	now := store.timestamp()
	rows, err := store.pool.Query(ctx, `
		SELECT attempt.operation_id,attempt.scope_id,operation.tenant_id,operation.site_id,operation.action,
		       operation.target_type,attempt.node_id,attempt.attempt,attempt.lease_id,
		       attempt.worker_id,attempt.started_at,attempt.lease_expires_at,operation.request_digest,
		       NULLIF(claim.payload->>'config_version_id','')::uuid,
		       NULLIF(claim.payload->>'config_revision','')::bigint
		FROM cache_operation_node_attempts attempt
		JOIN cache_operations operation
		  ON operation.scope_id=attempt.scope_id AND operation.id=attempt.operation_id
		JOIN cache_operation_nodes node
		  ON node.scope_id=attempt.scope_id AND node.operation_id=attempt.operation_id
		 AND node.node_id=attempt.node_id
		JOIN audit_events claim
		  ON claim.scope_id=attempt.scope_id AND claim.action='cache.operation.claim'
		 AND claim.resource_type='cache_operation' AND claim.resource_id=attempt.operation_id::text
		 AND claim.result='success' AND claim.payload->>'node_id'=attempt.node_id::text
		 AND claim.payload->>'attempt'=attempt.attempt::text
		 AND claim.payload->>'lease_id'=attempt.lease_id::text
		WHERE attempt.worker_id=$1 AND attempt.state='running' AND attempt.lease_expires_at>$2
		  AND node.state='running' AND node.attempt=attempt.attempt AND node.lease_id=attempt.lease_id
		ORDER BY attempt.started_at,attempt.operation_id,attempt.node_id LIMIT $3`,
		request.WorkerID, now, request.Limit)
	if err != nil {
		return nil, fmt.Errorf("list open cache operation claims: %w", err)
	}
	defer rows.Close()
	claims := make([]Claim, 0, request.Limit)
	for rows.Next() {
		var claim Claim
		var digest []byte
		var configVersion *uuid.UUID
		var configRevision *int64
		if err := rows.Scan(
			&claim.OperationID, &claim.ScopeID, &claim.TenantID, &claim.SiteID, &claim.Action,
			&claim.TargetType, &claim.NodeID, &claim.Attempt, &claim.LeaseID,
			&claim.WorkerID, &claim.ClaimedAt, &claim.LeaseExpiresAt, &digest, &configVersion, &configRevision,
		); err != nil {
			return nil, fmt.Errorf("scan open cache operation claim: %w", err)
		}
		if copy(claim.RequestDigest[:], digest) != len(claim.RequestDigest) {
			return nil, ErrInvalidTransition
		}
		claim.Priority = "normal"
		if configVersion != nil && configRevision != nil && *configRevision > 0 {
			claim.ConfigVersionID = *configVersion
			claim.ConfigRevision = uint64(*configRevision)
		} else if configVersion != nil || configRevision != nil {
			return nil, ErrInvalidTransition
		}
		claim.Targets, err = loadAttemptTargets(
			ctx, store.pool, claim.ScopeID, claim.OperationID, claim.NodeID, claim.Attempt,
		)
		if err != nil {
			return nil, err
		}
		if len(claim.Targets) == 0 {
			return nil, ErrInvalidTransition
		}
		claims = append(claims, claim)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return claims, nil
}

func (store *Store) ResolveClaim(ctx context.Context, identity ClaimIdentity) (Claim, error) {
	if ctx == nil || identity.ScopeID == uuid.Nil || identity.OperationID == uuid.Nil ||
		identity.NodeID == uuid.Nil || identity.LeaseID == uuid.Nil || identity.Attempt == 0 {
		return Claim{}, ErrInvalidInput
	}
	now := store.timestamp()
	var claim Claim
	var digest []byte
	var configVersion *uuid.UUID
	var configRevision *int64
	err := store.pool.QueryRow(ctx, `
		SELECT attempt.operation_id,attempt.scope_id,operation.tenant_id,operation.site_id,operation.action,
		       operation.target_type,attempt.node_id,attempt.attempt,attempt.lease_id,
		       attempt.worker_id,attempt.started_at,attempt.lease_expires_at,operation.request_digest,
		       NULLIF(claim.payload->>'config_version_id','')::uuid,
		       NULLIF(claim.payload->>'config_revision','')::bigint
		FROM cache_operation_node_attempts attempt
		JOIN cache_operations operation
		  ON operation.scope_id=attempt.scope_id AND operation.id=attempt.operation_id
		JOIN cache_operation_nodes node
		  ON node.scope_id=attempt.scope_id AND node.operation_id=attempt.operation_id
		 AND node.node_id=attempt.node_id
		JOIN audit_events claim
		  ON claim.scope_id=attempt.scope_id AND claim.action='cache.operation.claim'
		 AND claim.resource_type='cache_operation' AND claim.resource_id=attempt.operation_id::text
		 AND claim.result='success' AND claim.payload->>'node_id'=attempt.node_id::text
		 AND claim.payload->>'attempt'=attempt.attempt::text
		 AND claim.payload->>'lease_id'=attempt.lease_id::text
		WHERE attempt.scope_id=$1 AND attempt.operation_id=$2 AND attempt.node_id=$3
		  AND attempt.attempt=$4 AND attempt.lease_id=$5 AND attempt.state='running'
		  AND attempt.lease_expires_at>$6 AND node.state='running'
		  AND node.attempt=attempt.attempt AND node.lease_id=attempt.lease_id`,
		identity.ScopeID, identity.OperationID, identity.NodeID, identity.Attempt, identity.LeaseID, now).Scan(
		&claim.OperationID, &claim.ScopeID, &claim.TenantID, &claim.SiteID, &claim.Action,
		&claim.TargetType, &claim.NodeID, &claim.Attempt, &claim.LeaseID, &claim.WorkerID,
		&claim.ClaimedAt, &claim.LeaseExpiresAt, &digest, &configVersion, &configRevision,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Claim{}, ErrNotFound
	}
	if err != nil {
		return Claim{}, fmt.Errorf("resolve cache operation claim: %w", err)
	}
	if copy(claim.RequestDigest[:], digest) != len(claim.RequestDigest) {
		return Claim{}, ErrInvalidTransition
	}
	claim.Priority = "normal"
	if configVersion == nil || configRevision == nil || *configRevision < 1 {
		return Claim{}, ErrInvalidTransition
	}
	claim.ConfigVersionID = *configVersion
	claim.ConfigRevision = uint64(*configRevision)
	claim.Targets, err = loadAttemptTargets(
		ctx, store.pool, claim.ScopeID, claim.OperationID, claim.NodeID, claim.Attempt,
	)
	if err != nil {
		return Claim{}, err
	}
	if len(claim.Targets) == 0 {
		return Claim{}, ErrInvalidTransition
	}
	return claim, nil
}

func loadAttemptTargets(
	ctx context.Context,
	query operationQuerier,
	scopeID, operationID, nodeID uuid.UUID,
	attempt uint32,
) ([]Target, error) {
	rows, err := query.Query(ctx, `
		SELECT target.ordinal,target.canonical_url,target.canonical_path
		FROM cache_operation_node_targets projection
		JOIN cache_operation_targets target
		  ON target.operation_id=projection.operation_id AND target.ordinal=projection.target_ordinal
		WHERE projection.scope_id=$1 AND projection.operation_id=$2 AND projection.node_id=$3
		  AND projection.state='running' AND projection.attempt=$4
		ORDER BY target.ordinal`, scopeID, operationID, nodeID, attempt)
	if err != nil {
		return nil, fmt.Errorf("load open cache claim targets: %w", err)
	}
	defer rows.Close()
	var targets []Target
	for rows.Next() {
		var target Target
		if err := rows.Scan(&target.Ordinal, &target.CanonicalURL, &target.CanonicalPath); err != nil {
			return nil, err
		}
		targets = append(targets, target)
	}
	return targets, rows.Err()
}

func loadClaimTargets(
	ctx context.Context,
	tx pgx.Tx,
	scopeID, operationID, nodeID uuid.UUID,
) ([]Target, error) {
	rows, err := tx.Query(ctx, `
		SELECT target.ordinal,target.canonical_url,target.canonical_path
		FROM cache_operation_node_targets projection
		JOIN cache_operation_targets target
		  ON target.operation_id=projection.operation_id AND target.ordinal=projection.target_ordinal
		WHERE projection.scope_id=$1 AND projection.operation_id=$2 AND projection.node_id=$3
		  AND projection.state='queued'
		ORDER BY target.ordinal`, scopeID, operationID, nodeID)
	if err != nil {
		return nil, fmt.Errorf("load cache claim targets: %w", err)
	}
	defer rows.Close()
	var targets []Target
	for rows.Next() {
		var target Target
		if err := rows.Scan(&target.Ordinal, &target.CanonicalURL, &target.CanonicalPath); err != nil {
			return nil, err
		}
		targets = append(targets, target)
	}
	return targets, rows.Err()
}

func (store *Store) expireLeases(
	ctx context.Context,
	tx pgx.Tx,
	scopeID uuid.UUID,
	requestID string,
	now time.Time,
) error {
	rows, err := tx.Query(ctx, `
		SELECT node.operation_id,node.node_id,node.attempt,operation.max_attempts
		FROM cache_operation_nodes node
		JOIN cache_operations operation ON operation.id=node.operation_id
		WHERE node.scope_id=$1 AND node.state='running' AND node.lease_expires_at <= $2
		  AND operation.state='running'
		ORDER BY node.lease_expires_at,node.operation_id,node.node_id
		FOR UPDATE OF node SKIP LOCKED LIMIT 1000`, scopeID, now)
	if err != nil {
		return fmt.Errorf("select expired cache operation leases: %w", err)
	}
	type expired struct {
		operationID uuid.UUID
		nodeID      uuid.UUID
		attempt     int
		maximum     int
	}
	var values []expired
	for rows.Next() {
		var value expired
		if err := rows.Scan(&value.operationID, &value.nodeID, &value.attempt, &value.maximum); err != nil {
			rows.Close()
			return err
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	affectedOperations := make(map[uuid.UUID]struct{})
	for _, value := range values {
		auditEventID, err := store.appendAudit(ctx, tx, scopeID, nil,
			"cache.operation.lease_expire", value.operationID, requestID, map[string]any{
				"node_id": value.nodeID, "attempt": value.attempt,
				"requeued": value.attempt < value.maximum,
			})
		if err != nil {
			return err
		}
		if value.attempt >= value.maximum {
			rows, err := tx.Query(ctx, `SELECT target_ordinal
				FROM cache_operation_node_targets
				WHERE scope_id=$1 AND operation_id=$2 AND node_id=$3
				  AND state='running' AND attempt=$4 ORDER BY target_ordinal`,
				scopeID, value.operationID, value.nodeID, value.attempt)
			if err != nil {
				return fmt.Errorf("load exhausted cache operation targets: %w", err)
			}
			var ordinals []int
			for rows.Next() {
				var ordinal int
				if err := rows.Scan(&ordinal); err != nil {
					rows.Close()
					return err
				}
				ordinals = append(ordinals, ordinal)
			}
			if err := rows.Err(); err != nil {
				rows.Close()
				return err
			}
			rows.Close()
			for _, ordinal := range ordinals {
				if _, err := tx.Exec(ctx, `INSERT INTO cache_operation_target_results (
					id,operation_id,scope_id,node_id,target_ordinal,attempt,source,state,
					sequence,error_code,audit_event_id,created_at
				) VALUES ($1,$2,$3,$4,$5,$6,'lease_expire','failed',0,$7,$8,$9)`,
					uuid.New(), value.operationID, scopeID, value.nodeID, ordinal, value.attempt,
					codeRetriesExhausted, auditEventID, now); err != nil {
					return fmt.Errorf("record exhausted cache operation result: %w", err)
				}
			}
		}
		command, err := tx.Exec(ctx, `
			UPDATE cache_operation_node_attempts
			SET state='lease_expired',error_code=$5,completed_at=$6
			WHERE scope_id=$1 AND operation_id=$2 AND node_id=$3 AND attempt=$4 AND state='running'`,
			scopeID, value.operationID, value.nodeID, value.attempt, codeLeaseExpired, now)
		if err != nil {
			return fmt.Errorf("expire cache operation attempt: %w", err)
		}
		if command.RowsAffected() != 1 {
			return ErrClaimLost
		}
		if value.attempt < value.maximum {
			nextAttemptAt := now.Add(leaseRetryBackoff(value.attempt))
			if _, err := tx.Exec(ctx, `
				UPDATE cache_operation_node_targets
				SET state='queued',attempt=0,sequence=0,error_code=NULL,completed_at=NULL
				WHERE scope_id=$1 AND operation_id=$2 AND node_id=$3 AND state='running'`,
				scopeID, value.operationID, value.nodeID); err != nil {
				return fmt.Errorf("requeue expired cache operation targets: %w", err)
			}
			progress, err := projectionProgress(ctx, tx, scopeID, value.operationID, value.nodeID)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `
				UPDATE cache_operation_nodes SET state='queued',lease_id=NULL,lease_owner=NULL,
					lease_expires_at=NULL,next_attempt_at=$4,completed_count=$5,succeeded_count=$6,
					failed_count=$7,cancelled_count=$8,last_error_code=$9,updated_at=$4,completed_at=NULL
				WHERE scope_id=$1 AND operation_id=$2 AND node_id=$3`,
				scopeID, value.operationID, value.nodeID, nextAttemptAt, progress.Completed,
				progress.Succeeded, progress.Failed, progress.Cancelled, codeLeaseExpired); err != nil {
				return fmt.Errorf("requeue expired cache operation node: %w", err)
			}
		} else {
			if _, err := tx.Exec(ctx, `
				UPDATE cache_operation_node_targets
				SET state='failed',sequence=0,error_code=$4,completed_at=$5
				WHERE scope_id=$1 AND operation_id=$2 AND node_id=$3 AND state='running'`,
				scopeID, value.operationID, value.nodeID, codeRetriesExhausted, now); err != nil {
				return fmt.Errorf("exhaust expired cache operation targets: %w", err)
			}
			if err := setCompletedNode(ctx, tx, scopeID, value.operationID, value.nodeID, codeRetriesExhausted, now); err != nil {
				return err
			}
		}
		affectedOperations[value.operationID] = struct{}{}
	}
	for operationID := range affectedOperations {
		if err := rollupOperation(ctx, tx, scopeID, operationID, now); err != nil {
			return err
		}
	}
	return nil
}

func leaseRetryBackoff(attempt int) time.Duration {
	if attempt < 1 {
		return leaseRetryBase
	}
	delay := leaseRetryBase
	for index := 1; index < attempt && delay < leaseRetryMaximum; index++ {
		delay *= 2
		if delay > leaseRetryMaximum {
			return leaseRetryMaximum
		}
	}
	return delay
}

func (store *Store) ReconcileExpired(ctx context.Context, scopeID uuid.UUID, requestID string) error {
	if ctx == nil || scopeID == uuid.Nil || !validSafeText(requestID, 128) {
		return ErrInvalidInput
	}
	now := store.timestamp()
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := authorizeWorkerScope(ctx, tx, scopeID); err != nil {
			return err
		}
		return store.expireLeases(ctx, tx, scopeID, requestID, now)
	})
	if err != nil {
		return fmt.Errorf("reconcile expired cache operation leases: %w", err)
	}
	return nil
}

func (store *Store) Report(ctx context.Context, request ReportRequest) (ReportResult, error) {
	results, digest, err := normalizeReport(request)
	if ctx == nil || err != nil {
		return ReportResult{}, ErrInvalidInput
	}
	now := store.timestamp()
	var output ReportResult
	err = pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := authorizeWorkerScope(ctx, tx, request.ScopeID); err != nil {
			return err
		}
		var nodeState string
		var currentAttempt int
		var currentLeaseID *uuid.UUID
		var currentOwner *string
		var currentExpiry *time.Time
		err := tx.QueryRow(ctx, `
			SELECT state,attempt,lease_id,lease_owner,lease_expires_at
			FROM cache_operation_nodes
			WHERE scope_id=$1 AND operation_id=$2 AND node_id=$3 FOR UPDATE`,
			request.ScopeID, request.OperationID, request.NodeID).Scan(
			&nodeState, &currentAttempt, &currentLeaseID, &currentOwner, &currentExpiry)
		if err == pgx.ErrNoRows {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("lock cache operation report node: %w", err)
		}

		var attemptState, workerID string
		var leaseID uuid.UUID
		var reportSequence int64
		var reportDigest []byte
		err = tx.QueryRow(ctx, `
			SELECT state,worker_id,lease_id,report_sequence,report_digest
			FROM cache_operation_node_attempts
			WHERE scope_id=$1 AND operation_id=$2 AND node_id=$3 AND attempt=$4`,
			request.ScopeID, request.OperationID, request.NodeID, request.Attempt).Scan(
			&attemptState, &workerID, &leaseID, &reportSequence, &reportDigest)
		if err == pgx.ErrNoRows {
			if currentAttempt > int(request.Attempt) {
				output.Operation, err = loadOperation(ctx, tx, request.ScopeID, request.OperationID)
				return err
			}
			return ErrClaimLost
		}
		if err != nil {
			return fmt.Errorf("load cache operation report attempt: %w", err)
		}
		if attemptState != string(StateRunning) {
			if bytes.Equal(reportDigest, digest[:]) {
				output.Replayed = true
				output.Operation, err = loadOperation(ctx, tx, request.ScopeID, request.OperationID)
				return err
			}
			if reportSequence == int64(request.Sequence) && reportSequence > 0 {
				return ErrReportConflict
			}
			output.Operation, err = loadOperation(ctx, tx, request.ScopeID, request.OperationID)
			return err
		}
		if nodeState != string(StateRunning) || currentAttempt != int(request.Attempt) ||
			currentLeaseID == nil || *currentLeaseID != request.LeaseID || leaseID != request.LeaseID ||
			currentOwner == nil || *currentOwner != request.WorkerID || workerID != request.WorkerID ||
			currentExpiry == nil || !now.Before(*currentExpiry) {
			return ErrClaimLost
		}
		var tenantID uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT tenant_id FROM cache_operations
			WHERE scope_id=$1 AND id=$2`, request.ScopeID, request.OperationID).Scan(&tenantID); err != nil {
			return fmt.Errorf("load cache operation tenant: %w", err)
		}
		unifiedClaim, err := jobstate.StartTx(ctx, tx, jobstate.StartInput{
			TenantID: tenantID, JobID: request.OperationID, Kind: "cache.operation",
			WorkerID: "cache.operation." + request.OperationID.String(), LeaseDuration: time.Hour,
		}, now)
		if err != nil {
			return fmt.Errorf("resume unified cache operation job: %w", err)
		}

		rows, err := tx.Query(ctx, `
			SELECT target_ordinal FROM cache_operation_node_targets
			WHERE scope_id=$1 AND operation_id=$2 AND node_id=$3 AND state='running' AND attempt=$4
			ORDER BY target_ordinal FOR UPDATE`, request.ScopeID, request.OperationID,
			request.NodeID, request.Attempt)
		if err != nil {
			return fmt.Errorf("lock cache operation report targets: %w", err)
		}
		var ordinals []int
		for rows.Next() {
			var ordinal int
			if err := rows.Scan(&ordinal); err != nil {
				rows.Close()
				return err
			}
			ordinals = append(ordinals, ordinal)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		if len(ordinals) != len(results) {
			return ErrInvalidInput
		}
		for index, ordinal := range ordinals {
			if results[index].TargetOrdinal != ordinal {
				return ErrInvalidInput
			}
		}

		state, reason := summarizeReportResults(results)
		attemptState = string(state)
		var attemptError any
		if reason != "" {
			attemptError = reason
		}
		auditEventID, err := store.appendAudit(ctx, tx, request.ScopeID, nil,
			"cache.operation.report", request.OperationID, request.RequestID, map[string]any{
				"node_id": request.NodeID, "attempt": request.Attempt,
				"sequence": request.Sequence, "state": attemptState,
			})
		if err != nil {
			return err
		}
		for _, result := range results {
			var errorCode any
			if result.State != ItemSucceeded {
				errorCode = result.ErrorCode
			}
			if _, err := tx.Exec(ctx, `INSERT INTO cache_operation_target_results (
				id,operation_id,scope_id,node_id,target_ordinal,attempt,source,state,
				sequence,error_code,report_digest,audit_event_id,created_at
			) VALUES ($1,$2,$3,$4,$5,$6,'report',$7,$8,$9,$10,$11,$12)`,
				uuid.New(), request.OperationID, request.ScopeID, request.NodeID,
				result.TargetOrdinal, request.Attempt, result.State, request.Sequence,
				errorCode, digest[:], auditEventID, now); err != nil {
				return fmt.Errorf("record cache operation target result: %w", err)
			}
			command, err := tx.Exec(ctx, `
				UPDATE cache_operation_node_targets
				SET state=$5,sequence=$6,error_code=$7,completed_at=$8
				WHERE scope_id=$1 AND operation_id=$2 AND node_id=$3 AND target_ordinal=$4
				  AND state='running' AND attempt=$9`,
				request.ScopeID, request.OperationID, request.NodeID, result.TargetOrdinal,
				result.State, request.Sequence, errorCode, now, request.Attempt)
			if err != nil {
				return fmt.Errorf("apply cache operation target result: %w", err)
			}
			if command.RowsAffected() != 1 {
				return ErrClaimLost
			}
		}
		command, err := tx.Exec(ctx, `
			UPDATE cache_operation_node_attempts
			SET state=$5,report_sequence=$6,report_digest=$7,error_code=$8,completed_at=$9
			WHERE scope_id=$1 AND operation_id=$2 AND node_id=$3 AND attempt=$4 AND state='running'`,
			request.ScopeID, request.OperationID, request.NodeID, request.Attempt,
			attemptState, request.Sequence, digest[:], attemptError, now)
		if err != nil {
			return fmt.Errorf("complete cache operation node attempt: %w", err)
		}
		if command.RowsAffected() != 1 {
			return ErrClaimLost
		}
		if err := setCompletedNode(ctx, tx, request.ScopeID, request.OperationID,
			request.NodeID, stringValue(attemptError), now); err != nil {
			return err
		}
		if err := rollupOperation(ctx, tx, request.ScopeID, request.OperationID, now); err != nil {
			return err
		}
		for _, result := range results {
			// fix-cacheflow2: a target the node stopped on cancel is cancelled in
			// the unified job too (it used to be counted as failed).
			state, code := jobstate.ItemSucceeded, ""
			switch result.State {
			case ItemCancelled:
				state, code = jobstate.ItemCancelled, jobstate.CodeCancelled
			case ItemFailed:
				state, code = jobstate.ItemFailed, result.ErrorCode
			}
			if _, err := jobstate.ReportTx(ctx, tx, jobstate.ReportInput{
				TenantID: tenantID, JobID: request.OperationID, WorkerID: unifiedClaim.WorkerID,
				LeaseID: unifiedClaim.LeaseID, Report: jobstate.Report{
					ItemID: fmt.Sprintf("%s:%d", request.NodeID, result.TargetOrdinal),
					State:  state, Code: code, Attempt: unifiedClaim.Job.Attempt, Sequence: request.Sequence,
				},
			}, now); err != nil {
				return fmt.Errorf("report unified cache operation item: %w", err)
			}
		}
		output.Applied = true
		output.Operation, err = loadOperation(ctx, tx, request.ScopeID, request.OperationID)
		return err
	})
	if err != nil {
		return ReportResult{}, fmt.Errorf("report cache operation result: %w", err)
	}
	return output, nil
}

func summarizeReportResults(results []TargetResult) (State, string) {
	failed, cancelled := 0, 0
	for _, result := range results {
		switch result.State {
		case ItemFailed:
			failed++
		case ItemCancelled:
			cancelled++
		}
	}
	switch {
	case failed == len(results):
		return StateFailed, codeTargetFailed
	case cancelled == len(results):
		return StateCancelled, codeCancelled
	case failed > 0:
		return StatePartialFailed, codeTargetFailed
	case cancelled > 0:
		return StatePartialFailed, codeCancelled
	default:
		return StateSucceeded, ""
	}
}

func (store *Store) Retry(ctx context.Context, actor Actor, request RetryRequest) (OperationWriteResult, error) {
	if ctx == nil || !validActor(actor) || request.OperationID == uuid.Nil ||
		!validWriteMetadata(request.IdempotencyKey, request.RequestID) {
		return OperationWriteResult{}, ErrInvalidInput
	}
	digest, _ := digestJSON(struct {
		OperationID uuid.UUID `json:"operation_id"`
		Command     string    `json:"command"`
	}{request.OperationID, "retry"})
	now := store.timestamp()
	var output OperationWriteResult
	var siteID uuid.UUID
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if _, err := store.authorizeActor(ctx, tx, actor, "sites.manage"); err != nil {
			return err
		}
		state, err := lockOperationState(ctx, tx, actor.ScopeID, request.OperationID)
		if err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT site_id FROM cache_operations
				WHERE scope_id=$1 AND id=$2`, actor.ScopeID, request.OperationID).Scan(&siteID); err != nil {
			return err
		}
		if err := store.checkSiteEntitlement(
			ctx, tx, actor, siteID, request.RequestID, "cache.operation.retry",
		); err != nil {
			return err
		}
		commandID, replayed, err := claimCommand(ctx, tx, actor, request.OperationID, "retry",
			request.IdempotencyKey, digest, now, state == StateFailed || state == StatePartialFailed)
		if err != nil {
			return err
		}
		if replayed {
			output.Replayed = true
			output.Operation, err = loadOperation(ctx, tx, actor.ScopeID, request.OperationID)
			return err
		}
		rows, err := tx.Query(ctx, `
			UPDATE cache_operation_node_targets projection
			SET state='queued',attempt=0,sequence=0,error_code=NULL,completed_at=NULL
			FROM cache_operation_nodes node,cache_operations operation
			WHERE projection.scope_id=$1 AND projection.operation_id=$2 AND projection.state='failed'
			  AND node.operation_id=projection.operation_id AND node.node_id=projection.node_id
			  AND operation.id=projection.operation_id AND node.attempt < operation.max_attempts
			RETURNING projection.node_id`, actor.ScopeID, request.OperationID)
		if err != nil {
			return fmt.Errorf("retry cache operation target projections: %w", err)
		}
		nodeSet := make(map[uuid.UUID]struct{})
		for rows.Next() {
			var nodeID uuid.UUID
			if err := rows.Scan(&nodeID); err != nil {
				rows.Close()
				return err
			}
			nodeSet[nodeID] = struct{}{}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		if len(nodeSet) == 0 {
			return ErrRetriesExhausted
		}
		for nodeID := range nodeSet {
			progress, err := projectionProgress(ctx, tx, actor.ScopeID, request.OperationID, nodeID)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `
				UPDATE cache_operation_nodes SET state='queued',lease_id=NULL,lease_owner=NULL,
					lease_expires_at=NULL,next_attempt_at=$4,completed_count=$5,succeeded_count=$6,
					failed_count=$7,cancelled_count=$8,last_error_code=NULL,updated_at=$4,completed_at=NULL
				WHERE scope_id=$1 AND operation_id=$2 AND node_id=$3`,
				actor.ScopeID, request.OperationID, nodeID, now, progress.Completed,
				progress.Succeeded, progress.Failed, progress.Cancelled); err != nil {
				return fmt.Errorf("retry cache operation node: %w", err)
			}
		}
		progress, err := operationProgress(ctx, tx, actor.ScopeID, request.OperationID)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE cache_operations SET state='queued',completed_count=$3,succeeded_count=$4,
				failed_count=$5,cancelled_count=$6,updated_at=$7,completed_at=NULL
			WHERE scope_id=$1 AND id=$2`, actor.ScopeID, request.OperationID,
			progress.Completed, progress.Succeeded, progress.Failed, progress.Cancelled, now); err != nil {
			return fmt.Errorf("queue cache operation retry: %w", err)
		}
		var tenantID uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT tenant_id FROM cache_operations
			WHERE scope_id=$1 AND id=$2`, actor.ScopeID, request.OperationID).Scan(&tenantID); err != nil {
			return fmt.Errorf("load retried cache operation tenant: %w", err)
		}
		job, err := jobstate.RetryTx(ctx, tx, tenantID, request.OperationID, now)
		if err != nil {
			if errors.Is(err, jobstate.ErrRetriesExhausted) {
				return ErrRetriesExhausted
			}
			if errors.Is(err, jobstate.ErrInvalidTransition) {
				return ErrInvalidTransition
			}
			return fmt.Errorf("retry unified cache operation job: %w", err)
		}
		if _, err := store.appendAudit(ctx, tx, actor.ScopeID, &actor.UserID,
			"cache.operation.retry", request.OperationID, request.RequestID,
			map[string]any{
				"command_id": commandID, "node_count": len(nodeSet), "actor_scope_id": actor.ActorScopeID,
			}); err != nil {
			return err
		}
		if err := store.recordJobCommandReceipt(ctx, tx, actor, request.OperationID, "retry",
			request.IdempotencyKey, request.RequestID, digest, job, now); err != nil {
			return err
		}
		if err := completeCommand(ctx, tx, actor, request.OperationID,
			"retry", request.IdempotencyKey, now); err != nil {
			return err
		}
		output.Operation, err = loadOperation(ctx, tx, actor.ScopeID, request.OperationID)
		return err
	})
	if err != nil {
		if errors.Is(err, ErrEntitlementDenied) {
			if auditErr := store.persistSiteEntitlementDenial(
				ctx, actor, siteID, request.RequestID, "cache.operation.retry",
			); auditErr != nil {
				err = errors.Join(err, auditErr)
			}
		}
		return OperationWriteResult{}, store.withWriteRejection(ctx, actor, rejectedWrite{
			action: WriteRetry, operationID: request.OperationID, key: request.IdempotencyKey, requestID: request.RequestID,
		}, fmt.Errorf("retry cache operation: %w", err))
	}
	return output, nil
}

func (store *Store) Cancel(ctx context.Context, actor Actor, request CancelRequest) (OperationWriteResult, error) {
	if ctx == nil || !validActor(actor) || request.OperationID == uuid.Nil ||
		!validWriteMetadata(request.IdempotencyKey, request.RequestID) {
		return OperationWriteResult{}, ErrInvalidInput
	}
	digest, _ := digestJSON(struct {
		OperationID uuid.UUID `json:"operation_id"`
		Command     string    `json:"command"`
	}{request.OperationID, "cancel"})
	now := store.timestamp()
	var output OperationWriteResult
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if _, err := store.authorizeActor(ctx, tx, actor, "sites.manage"); err != nil {
			return err
		}
		state, err := lockOperationState(ctx, tx, actor.ScopeID, request.OperationID)
		if err != nil {
			return err
		}
		commandID, replayed, err := claimCommand(ctx, tx, actor, request.OperationID, "cancel",
			request.IdempotencyKey, digest, now, state == StateQueued || state == StateRunning)
		if err != nil {
			return err
		}
		if replayed {
			output.Replayed = true
			output.Operation, err = loadOperation(ctx, tx, actor.ScopeID, request.OperationID)
			return err
		}
		rows, err := tx.Query(ctx, `
			SELECT node_id FROM cache_operation_nodes
			WHERE scope_id=$1 AND operation_id=$2 AND state IN ('queued','running') FOR UPDATE`,
			actor.ScopeID, request.OperationID)
		if err != nil {
			return err
		}
		var nodeIDs []uuid.UUID
		for rows.Next() {
			var nodeID uuid.UUID
			if err := rows.Scan(&nodeID); err != nil {
				rows.Close()
				return err
			}
			nodeIDs = append(nodeIDs, nodeID)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		// CACHE-ADD-07: before the running attempts are marked cancelled,
		// queue a node cancel for each (or record that the node cannot take one).
		if err := recordCancelDeliveries(ctx, tx, actor.ScopeID, request.OperationID, commandID, now); err != nil {
			return err
		}
		auditEventID, err := store.appendAudit(ctx, tx, actor.ScopeID, &actor.UserID,
			"cache.operation.cancel", request.OperationID, request.RequestID,
			map[string]any{
				"command_id": commandID, "cancelled_nodes": len(nodeIDs), "actor_scope_id": actor.ActorScopeID,
			})
		if err != nil {
			return err
		}
		type cancelledTarget struct {
			nodeID  uuid.UUID
			ordinal int
			attempt int
		}
		rows, err = tx.Query(ctx, `SELECT node_id,target_ordinal,attempt
			FROM cache_operation_node_targets
			WHERE scope_id=$1 AND operation_id=$2 AND state IN ('queued','running')
			ORDER BY node_id,target_ordinal FOR UPDATE`, actor.ScopeID, request.OperationID)
		if err != nil {
			return err
		}
		var cancelledTargets []cancelledTarget
		for rows.Next() {
			var target cancelledTarget
			if err := rows.Scan(&target.nodeID, &target.ordinal, &target.attempt); err != nil {
				rows.Close()
				return err
			}
			cancelledTargets = append(cancelledTargets, target)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		for _, target := range cancelledTargets {
			var attempt any
			if target.attempt > 0 {
				attempt = target.attempt
			}
			if _, err := tx.Exec(ctx, `INSERT INTO cache_operation_target_results (
				id,operation_id,scope_id,node_id,target_ordinal,attempt,source,state,
				sequence,error_code,command_id,audit_event_id,created_at
			) VALUES ($1,$2,$3,$4,$5,$6,'cancel','cancelled',0,$7,$8,$9,$10)`,
				uuid.New(), request.OperationID, actor.ScopeID, target.nodeID, target.ordinal,
				attempt, codeCancelled, commandID, auditEventID, now); err != nil {
				return fmt.Errorf("record cache operation cancellation result: %w", err)
			}
		}
		if _, err := tx.Exec(ctx, `
			UPDATE cache_operation_node_attempts
			SET state='cancelled',error_code=$3,completed_at=$4
			WHERE scope_id=$1 AND operation_id=$2 AND state='running'`,
			actor.ScopeID, request.OperationID, codeCancelled, now); err != nil {
			return fmt.Errorf("cancel cache operation attempts: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE cache_operation_node_targets
			SET state='cancelled',sequence=0,error_code=$3,completed_at=$4
			WHERE scope_id=$1 AND operation_id=$2 AND state IN ('queued','running')`,
			actor.ScopeID, request.OperationID, codeCancelled, now); err != nil {
			return fmt.Errorf("cancel cache operation target projections: %w", err)
		}
		for _, nodeID := range nodeIDs {
			progress, err := projectionProgress(ctx, tx, actor.ScopeID, request.OperationID, nodeID)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `
				UPDATE cache_operation_nodes SET state='cancelled',lease_id=NULL,lease_owner=NULL,
					lease_expires_at=NULL,next_attempt_at=NULL,completed_count=$4,succeeded_count=$5,
					failed_count=$6,cancelled_count=$7,last_error_code=$8,updated_at=$9,completed_at=$9
				WHERE scope_id=$1 AND operation_id=$2 AND node_id=$3`,
				actor.ScopeID, request.OperationID, nodeID, progress.Completed,
				progress.Succeeded, progress.Failed, progress.Cancelled, codeCancelled, now); err != nil {
				return err
			}
		}
		progress, err := operationProgress(ctx, tx, actor.ScopeID, request.OperationID)
		if err != nil {
			return err
		}
		if err := completeCommand(ctx, tx, actor, request.OperationID,
			"cancel", request.IdempotencyKey, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE cache_operations SET state='cancelled',cancel_requested_at=$3,
				completed_count=$4,succeeded_count=$5,failed_count=$6,cancelled_count=$7,
				updated_at=$3,completed_at=$3
			WHERE scope_id=$1 AND id=$2`, actor.ScopeID, request.OperationID, now,
			progress.Completed, progress.Succeeded, progress.Failed, progress.Cancelled); err != nil {
			return fmt.Errorf("cancel cache operation: %w", err)
		}
		var tenantID uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT tenant_id FROM cache_operations
			WHERE scope_id=$1 AND id=$2`, actor.ScopeID, request.OperationID).Scan(&tenantID); err != nil {
			return fmt.Errorf("load cancelled cache operation tenant: %w", err)
		}
		job, err := jobstate.CancelTx(ctx, tx, tenantID, request.OperationID, now)
		if err != nil {
			if errors.Is(err, jobstate.ErrInvalidTransition) {
				return ErrInvalidTransition
			}
			return fmt.Errorf("cancel unified cache operation job: %w", err)
		}
		if err := store.recordJobCommandReceipt(ctx, tx, actor, request.OperationID, "cancel",
			request.IdempotencyKey, request.RequestID, digest, job, now); err != nil {
			return err
		}
		output.Operation, err = loadOperation(ctx, tx, actor.ScopeID, request.OperationID)
		return err
	})
	if err != nil {
		return OperationWriteResult{}, store.withWriteRejection(ctx, actor, rejectedWrite{
			action: WriteCancel, operationID: request.OperationID, key: request.IdempotencyKey, requestID: request.RequestID,
		}, fmt.Errorf("cancel cache operation: %w", err))
	}
	return output, nil
}

func lockOperationState(ctx context.Context, tx pgx.Tx, scopeID, operationID uuid.UUID) (State, error) {
	var state string
	if err := tx.QueryRow(ctx, `
		SELECT state FROM cache_operations WHERE scope_id=$1 AND id=$2 FOR UPDATE`,
		scopeID, operationID).Scan(&state); err == pgx.ErrNoRows {
		return "", ErrNotFound
	} else if err != nil {
		return "", err
	}
	return State(state), nil
}

func claimCommand(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	operationID uuid.UUID,
	commandName, key string,
	digest [32]byte,
	now time.Time,
	insertAllowed bool,
) (uuid.UUID, bool, error) {
	var commandID uuid.UUID
	var storedActorID uuid.UUID
	var storedDigest []byte
	var completedAt *time.Time
	err := tx.QueryRow(ctx, `
		SELECT id,actor_user_id,request_digest,completed_at FROM cache_operation_commands
		WHERE scope_id=$1 AND actor_scope_id=$2 AND actor_user_id=$3
		  AND operation_id=$4 AND command=$5 AND idempotency_key=$6 FOR UPDATE`,
		actor.ScopeID, actor.ActorScopeID, actor.UserID, operationID, commandName, key).Scan(
		&commandID, &storedActorID, &storedDigest, &completedAt,
	)
	if err == nil {
		if storedActorID != actor.UserID || !bytes.Equal(storedDigest, digest[:]) {
			return uuid.Nil, false, ErrIdempotencyConflict
		}
		if completedAt == nil {
			return uuid.Nil, false, fmt.Errorf("incomplete cache operation command")
		}
		return commandID, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, false, err
	}
	if !insertAllowed {
		return uuid.Nil, false, ErrInvalidTransition
	}
	commandID = uuid.New()
	result, err := tx.Exec(ctx, `
		INSERT INTO cache_operation_commands (
			id,operation_id,scope_id,actor_scope_id,command,idempotency_key,request_digest,actor_user_id,created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (scope_id,actor_scope_id,actor_user_id,operation_id,command,idempotency_key) DO NOTHING`,
		commandID, operationID, actor.ScopeID, actor.ActorScopeID, commandName, key, digest[:], actor.UserID, now)
	if err != nil {
		return uuid.Nil, false, err
	}
	if result.RowsAffected() == 1 {
		return commandID, false, nil
	}
	return claimCommand(ctx, tx, actor, operationID, commandName, key, digest, now, insertAllowed)
}

func completeCommand(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	operationID uuid.UUID,
	commandName, key string,
	now time.Time,
) error {
	command, err := tx.Exec(ctx, `
		UPDATE cache_operation_commands SET completed_at=$7
		WHERE scope_id=$1 AND actor_scope_id=$2 AND actor_user_id=$3
		  AND operation_id=$4 AND command=$5 AND idempotency_key=$6
		  AND completed_at IS NULL`, actor.ScopeID, actor.ActorScopeID, actor.UserID,
		operationID, commandName, key, now)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrIdempotencyConflict
	}
	return nil
}

func projectionProgress(
	ctx context.Context,
	tx pgx.Tx,
	scopeID, operationID, nodeID uuid.UUID,
) (Progress, error) {
	var result Progress
	err := tx.QueryRow(ctx, `
		SELECT count(*)::integer,
		       count(*) FILTER (WHERE state IN ('succeeded','failed','cancelled'))::integer,
		       count(*) FILTER (WHERE state='succeeded')::integer,
		       count(*) FILTER (WHERE state='failed')::integer,
		       count(*) FILTER (WHERE state='cancelled')::integer
		FROM cache_operation_node_targets
		WHERE scope_id=$1 AND operation_id=$2 AND node_id=$3`,
		scopeID, operationID, nodeID).Scan(
		&result.Total, &result.Completed, &result.Succeeded, &result.Failed, &result.Cancelled)
	return result, err
}

func operationProgress(ctx context.Context, tx pgx.Tx, scopeID, operationID uuid.UUID) (Progress, error) {
	var result Progress
	err := tx.QueryRow(ctx, `
		SELECT count(*)::integer,
		       count(*) FILTER (WHERE state IN ('succeeded','failed','cancelled'))::integer,
		       count(*) FILTER (WHERE state='succeeded')::integer,
		       count(*) FILTER (WHERE state='failed')::integer,
		       count(*) FILTER (WHERE state='cancelled')::integer
		FROM cache_operation_node_targets
		WHERE scope_id=$1 AND operation_id=$2`, scopeID, operationID).Scan(
		&result.Total, &result.Completed, &result.Succeeded, &result.Failed, &result.Cancelled)
	return result, err
}

func setCompletedNode(
	ctx context.Context,
	tx pgx.Tx,
	scopeID, operationID, nodeID uuid.UUID,
	errorCode string,
	now time.Time,
) error {
	progress, err := projectionProgress(ctx, tx, scopeID, operationID, nodeID)
	if err != nil {
		return err
	}
	state := StateSucceeded
	if progress.Cancelled == progress.Total {
		state = StateCancelled
	} else if progress.Failed == progress.Total {
		state = StateFailed
	} else if progress.Failed+progress.Cancelled > 0 {
		state = StatePartialFailed
	}
	var storedError any
	if errorCode != "" {
		storedError = errorCode
	}
	_, err = tx.Exec(ctx, `
		UPDATE cache_operation_nodes SET state=$4,lease_id=NULL,lease_owner=NULL,
			lease_expires_at=NULL,next_attempt_at=NULL,completed_count=$5,succeeded_count=$6,
			failed_count=$7,cancelled_count=$8,last_error_code=$9,updated_at=$10,completed_at=$10
		WHERE scope_id=$1 AND operation_id=$2 AND node_id=$3`, scopeID, operationID, nodeID,
		state, progress.Completed, progress.Succeeded, progress.Failed, progress.Cancelled, storedError, now)
	return err
}

func rollupOperation(ctx context.Context, tx pgx.Tx, scopeID, operationID uuid.UUID, now time.Time) error {
	progress, err := operationProgress(ctx, tx, scopeID, operationID)
	if err != nil {
		return err
	}
	var current string
	if err := tx.QueryRow(ctx, `SELECT state FROM cache_operations WHERE scope_id=$1 AND id=$2`,
		scopeID, operationID).Scan(&current); err != nil {
		return err
	}
	state := State(current)
	var completedAt any
	if progress.Completed == progress.Total {
		state = StateSucceeded
		if progress.Cancelled == progress.Total {
			state = StateCancelled
		} else if progress.Failed == progress.Total {
			state = StateFailed
		} else if progress.Failed+progress.Cancelled > 0 {
			state = StatePartialFailed
		}
		completedAt = now
	}
	_, err = tx.Exec(ctx, `
		UPDATE cache_operations SET state=$3,completed_count=$4,succeeded_count=$5,
			failed_count=$6,cancelled_count=$7,updated_at=$8,completed_at=$9
		WHERE scope_id=$1 AND id=$2`, scopeID, operationID, state, progress.Completed,
		progress.Succeeded, progress.Failed, progress.Cancelled, now, completedAt)
	return err
}

func stringValue(value any) string {
	if value == nil {
		return ""
	}
	return value.(string)
}
