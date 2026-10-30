package ja4block

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/securitybinding"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresStore struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

func NewPostgresStore(pool *pgxpool.Pool, now func() time.Time) (*PostgresStore, error) {
	if pool == nil || now == nil {
		return nil, ErrInvalidConfiguration
	}
	return &PostgresStore{pool: pool, now: now}, nil
}

func (store *PostgresStore) Create(ctx context.Context, workflow Workflow) (Workflow, error) {
	requestBytes, stateBytes, err := encodeWorkflow(workflow)
	if err != nil {
		return Workflow{}, ErrInvalidInput
	}
	var created Workflow
	err = pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		command, execErr := tx.Exec(ctx, `INSERT INTO ja4_block_workflows_157(
			id,tenant_scope_id,site_id,actor_user_id,actor_scope_id,actor_scope_kind,session_id,
			step_up_evidence_id,step_up_verified_at,ja4_sha256,
			ranking_snapshot_at,ranking_expires_at,duration_seconds,reason,phase,revision,
			idempotency_key,request_id,request_bytes,request_sha256,workflow_json,created_at,updated_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,decode($10,'hex'),$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$22)
			ON CONFLICT(tenant_scope_id,idempotency_key) DO NOTHING`, workflow.ID, workflow.TenantScopeID,
			workflow.SiteID, workflow.ActorUserID, workflow.ActorScopeID, workflow.ActorScopeKind,
			workflow.SessionID, workflow.StepUpEvidenceID, workflow.StepUpVerifiedAt, workflow.JA4SHA256,
			workflow.SnapshotAt, workflow.SnapshotExpiresAt, int64(workflow.Duration/time.Second),
			workflow.Reason, workflow.Phase, workflow.Revision, workflow.IdempotencyKey, workflow.RequestID,
			requestBytes, workflow.RequestSHA256[:], stateBytes, workflow.CreatedAt)
		if execErr != nil {
			return execErr
		}
		if command.RowsAffected() == 0 {
			existing, loadErr := loadWorkflow(ctx, tx, workflow.TenantScopeID, uuid.Nil, workflow.IdempotencyKey, false)
			if loadErr != nil {
				return loadErr
			}
			if existing.RequestSHA256 != workflow.RequestSHA256 {
				return ErrIdempotencyConflict
			}
			existing.Replayed = true
			created = existing
			return nil
		}
		_, execErr = tx.Exec(ctx, `INSERT INTO ja4_block_outbox_157(
			workflow_id,action,state,attempt_count,available_at,created_at,updated_at)
			VALUES($1,$2,'pending',0,$3,$3,$3)`, workflow.ID, ActionApplyPolicy, workflow.AvailableAt)
		if execErr != nil {
			return execErr
		}
		created = workflow
		return nil
	})
	if err != nil {
		return Workflow{}, storeError(err)
	}
	return created, nil
}

func (store *PostgresStore) Claim(ctx context.Context, workerID string, now time.Time, lease time.Duration) (Claim, bool, error) {
	token := uuid.New()
	var encoded []byte
	var action string
	err := store.pool.QueryRow(ctx, `WITH candidate AS (
		SELECT outbox.workflow_id,outbox.action FROM ja4_block_outbox_157 outbox
		JOIN ja4_block_workflows_157 workflow ON workflow.id=outbox.workflow_id
		WHERE outbox.available_at<=$1 AND (outbox.state='pending' OR
			(outbox.state='claimed' AND outbox.claim_expires_at<=$1))
		  AND ((outbox.action='apply_policy' AND workflow.phase='queued') OR
		       (outbox.action='publish_binding' AND workflow.phase='policy_ready'))
		ORDER BY outbox.available_at,outbox.workflow_id,outbox.action FOR UPDATE OF outbox SKIP LOCKED LIMIT 1
	), claimed AS (
		UPDATE ja4_block_outbox_157 outbox SET state='claimed',claimed_by=$2,claim_token=$3,
			claim_expires_at=$1+$4::interval,updated_at=$1
		FROM candidate WHERE outbox.workflow_id=candidate.workflow_id AND outbox.action=candidate.action
		RETURNING outbox.workflow_id,outbox.action
	)
	SELECT workflow.workflow_json,claimed.action FROM claimed
	JOIN ja4_block_workflows_157 workflow ON workflow.id=claimed.workflow_id`, now, workerID, token,
		fmt.Sprintf("%f seconds", lease.Seconds())).Scan(&encoded, &action)
	if errors.Is(err, pgx.ErrNoRows) {
		return Claim{}, false, nil
	}
	if err != nil {
		return Claim{}, false, storeError(err)
	}
	workflow, err := decodeWorkflow(encoded)
	if err != nil {
		return Claim{}, false, err
	}
	return Claim{Workflow: workflow, Token: token, Action: action}, true, nil
}

func (store *PostgresStore) SetPolicy(ctx context.Context, claim Claim, result securitypolicy.WriteResult) (Workflow, error) {
	item := claim.Workflow
	item.PolicyID, item.PolicyRevision = result.Policy.ID, result.Policy.Revision
	item.Phase, item.Revision, item.LastErrorCode = PhasePolicyReady, item.Revision+1, ""
	item.UpdatedAt = store.now().UTC()
	return store.settle(ctx, claim, item, "policy", result.Policy.ID, result, ActionPublishBinding)
}

func (store *PostgresStore) SetPublication(ctx context.Context, claim Claim, result securitybinding.Publication) (Workflow, error) {
	item := claim.Workflow
	item.BindingID, item.BindingRevision = result.BindingID, result.BindingRevision
	item.PublicationID, item.EdgeState = result.BundleID, "pending"
	item.Phase, item.Revision, item.LastErrorCode = PhaseEdgePending, item.Revision+1, ""
	item.UpdatedAt = store.now().UTC()
	return store.settle(ctx, claim, item, "binding", result.BundleID, result, "")
}

func (store *PostgresStore) settle(ctx context.Context, claim Claim, item Workflow, receiptKind string,
	externalID uuid.UUID, receipt any, nextAction string,
) (Workflow, error) {
	receiptBytes, err := json.Marshal(receipt)
	if err != nil {
		return Workflow{}, ErrInvalidInput
	}
	receiptDigest := sha256.Sum256(receiptBytes)
	_, stateBytes, err := encodeWorkflow(item)
	if err != nil {
		return Workflow{}, err
	}
	err = pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		command, execErr := tx.Exec(ctx, `UPDATE ja4_block_outbox_157 SET state='completed',claim_token=NULL,
			claim_expires_at=NULL,claimed_by=NULL,updated_at=$1
			WHERE workflow_id=$2 AND action=$3 AND state='claimed' AND claim_token=$4 AND claim_expires_at>$1`,
			item.UpdatedAt, item.ID, claim.Action, claim.Token)
		if execErr != nil {
			return execErr
		}
		if command.RowsAffected() != 1 {
			return ErrClaimLost
		}
		command, execErr = tx.Exec(ctx, `UPDATE ja4_block_workflows_157 SET phase=$1,revision=$2,
			workflow_json=$3,updated_at=$4 WHERE id=$5 AND tenant_scope_id=$6 AND phase=$7 AND revision=$8`,
			item.Phase, item.Revision, stateBytes, item.UpdatedAt, item.ID, item.TenantScopeID,
			claim.Workflow.Phase, claim.Workflow.Revision)
		if execErr != nil {
			return execErr
		}
		if command.RowsAffected() != 1 {
			return ErrRevisionConflict
		}
		_, execErr = tx.Exec(ctx, `INSERT INTO ja4_block_receipts_157(
			id,workflow_id,receipt_kind,phase_revision,external_id,receipt_bytes,receipt_sha256,created_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, uuid.New(), item.ID, receiptKind, item.Revision,
			externalID, receiptBytes, receiptDigest[:], item.UpdatedAt)
		if execErr != nil {
			return execErr
		}
		if nextAction != "" {
			_, execErr = tx.Exec(ctx, `INSERT INTO ja4_block_outbox_157(
				workflow_id,action,state,attempt_count,available_at,created_at,updated_at)
				VALUES($1,$2,'pending',0,$3,$3,$3)`, item.ID, nextAction, item.UpdatedAt)
		}
		return execErr
	})
	if err != nil {
		return Workflow{}, storeError(err)
	}
	return item, nil
}

func (store *PostgresStore) Retry(ctx context.Context, claim Claim, code string, availableAt time.Time) error {
	item := claim.Workflow
	item.AttemptCount++
	item.LastErrorCode = code
	item.AvailableAt = availableAt
	item.UpdatedAt = store.now().UTC()
	_, stateBytes, err := encodeWorkflow(item)
	if err != nil {
		return err
	}
	return storeError(pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		command, execErr := tx.Exec(ctx, `UPDATE ja4_block_outbox_157 SET state='pending',attempt_count=attempt_count+1,
			available_at=$1,last_error_code=$2,claimed_by=NULL,claim_token=NULL,claim_expires_at=NULL,updated_at=$3
			WHERE workflow_id=$4 AND action=$5 AND state='claimed' AND claim_token=$6 AND claim_expires_at>$3`,
			availableAt, code, item.UpdatedAt, item.ID, claim.Action, claim.Token)
		if execErr != nil {
			return execErr
		}
		if command.RowsAffected() != 1 {
			return ErrClaimLost
		}
		_, execErr = tx.Exec(ctx, `UPDATE ja4_block_workflows_157 SET workflow_json=$1,updated_at=$2
			WHERE id=$3 AND revision=$4`, stateBytes, item.UpdatedAt, item.ID, item.Revision)
		return execErr
	}))
}

func (store *PostgresStore) Get(ctx context.Context, tenantScopeID, workflowID uuid.UUID) (Workflow, error) {
	return loadWorkflow(ctx, store.pool, tenantScopeID, workflowID, "", true)
}

func (store *PostgresStore) SetEdgeReceipt(ctx context.Context, input EdgeReceiptInput) (Workflow, error) {
	var result Workflow
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		var encoded []byte
		loadErr := tx.QueryRow(ctx, `SELECT workflow_json FROM ja4_block_workflows_157
			WHERE tenant_scope_id=$1 AND id=$2 FOR UPDATE`, input.TenantScopeID, input.WorkflowID).Scan(&encoded)
		if errors.Is(loadErr, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if loadErr != nil {
			return loadErr
		}
		item, decodeErr := decodeWorkflow(encoded)
		if decodeErr != nil {
			return decodeErr
		}
		if item.SiteID != input.SiteID || item.PolicyID != input.PolicyID || item.PolicyRevision != input.PolicyRevision ||
			item.BindingID != input.BindingID || item.BindingRevision != input.BindingRevision ||
			item.PublicationID != input.PublicationID || item.RolloutID != input.RolloutID ||
			!containsNode(item.TargetNodeIDs, input.NodeID) {
			return ErrRevisionConflict
		}
		if (item.Phase == PhaseActive || item.Phase == PhaseFailed) && item.Revision == input.ExpectedRevision+1 {
			recorded, queryErr := lockExactEdgeReceipt(ctx, tx, input)
			if queryErr != nil || !recorded {
				return ErrRevisionConflict
			}
			item.Replayed = true
			result = item
			return nil
		}
		if item.Phase != PhaseEdgePending || item.RolloutID != input.RolloutID || item.Revision != input.ExpectedRevision {
			return ErrRevisionConflict
		}
		recorded, queryErr := lockExactEdgeReceipt(ctx, tx, input)
		if queryErr != nil {
			return queryErr
		}
		if !recorded {
			recordedAt := store.now().UTC()
			if recordedAt.Before(input.ObservedAt.UTC()) {
				recordedAt = input.ObservedAt.UTC()
			}
			command, execErr := tx.Exec(ctx, `UPDATE ja4_block_edge_receipt_queue_158
				SET recorded_at=$2,updated_at=GREATEST(updated_at,$2)
				WHERE receipt_id=$1 AND state='claimed' AND recorded_at IS NULL`, input.ReceiptID, recordedAt)
			if execErr != nil {
				return execErr
			}
			if command.RowsAffected() != 1 {
				return ErrRevisionConflict
			}
		} else {
			item.Replayed = true
		}
		facts, queryErr := loadRecordedEdgeReceipts(ctx, tx, item.ID)
		if queryErr != nil {
			return queryErr
		}
		if len(facts) > len(item.TargetNodeIDs) || !exactReceiptTargets(item.TargetNodeIDs, facts) {
			return ErrRevisionConflict
		}
		if len(facts) < len(item.TargetNodeIDs) {
			result = item
			return nil
		}
		allActive, anyRollback := true, false
		terminalAt := item.UpdatedAt.UTC()
		reason := "edge_applied"
		for _, fact := range facts {
			allActive = allActive && fact.State == "active"
			anyRollback = anyRollback || fact.State == "rolled_back"
			if fact.State != "active" && reason == "edge_applied" {
				reason = fact.ReasonCode
			}
			if fact.ObservedAt.After(terminalAt) {
				terminalAt = fact.ObservedAt
			}
		}
		item.Revision++
		item.LastErrorCode, item.UpdatedAt = reason, terminalAt
		if allActive {
			item.Phase, item.EdgeState = PhaseActive, "active"
			command, execErr := tx.Exec(ctx, `UPDATE security_policy_site_bindings SET
				active_policy_version=$2,revision=revision+1,updated_at=$3
				WHERE tenant_scope_id=$1 AND id=$4 AND site_id=$5 AND policy_id=$6 AND policy_kind='waf'
				  AND revision=$7 AND last_bundle_id=$8 AND last_claimed_policy_version=$2
				  AND COALESCE(active_policy_version,0)=$9`, item.TenantScopeID, item.PolicyRevision,
				item.UpdatedAt, item.BindingID, item.SiteID, item.PolicyID, item.BindingRevision,
				item.PublicationID, item.ExpectedActiveVersion)
			if execErr != nil {
				return execErr
			}
			if command.RowsAffected() != 1 {
				return ErrRevisionConflict
			}
		} else {
			item.Phase, item.EdgeState = PhaseFailed, "failed"
			if anyRollback {
				item.EdgeState = "rolled_back"
			}
		}
		releaseReason := "cancelled"
		if allActive {
			releaseReason = "completed"
		}
		command, execErr := tx.Exec(ctx, `UPDATE security_policy_publication_targets
			SET released_at=$2,release_reason=$3
			WHERE publication_id=$1 AND released_at IS NULL`, item.PublicationID, item.UpdatedAt, releaseReason)
		if execErr != nil {
			return execErr
		}
		if command.RowsAffected() != int64(len(item.TargetNodeIDs)) {
			return ErrRevisionConflict
		}
		_, stateBytes, encodeErr := encodeWorkflow(item)
		if encodeErr != nil {
			return encodeErr
		}
		command, execErr = tx.Exec(ctx, `UPDATE ja4_block_workflows_157 SET phase=$1,revision=$2,
			workflow_json=$3,updated_at=$4 WHERE tenant_scope_id=$5 AND id=$6 AND phase='edge_pending' AND revision=$7`,
			item.Phase, item.Revision, stateBytes, item.UpdatedAt, item.TenantScopeID, item.ID, input.ExpectedRevision)
		if execErr != nil {
			return execErr
		}
		if command.RowsAffected() != 1 {
			return ErrRevisionConflict
		}
		receiptBytes, encodeErr := json.Marshal(struct {
			WorkflowID    uuid.UUID         `json:"workflow_id"`
			PublicationID uuid.UUID         `json:"publication_id"`
			RolloutID     uuid.UUID         `json:"rollout_id"`
			State         string            `json:"state"`
			Receipts      []edgeReceiptFact `json:"receipts"`
		}{item.ID, item.PublicationID, item.RolloutID, item.EdgeState, facts})
		if encodeErr != nil {
			return encodeErr
		}
		digest := sha256.Sum256(receiptBytes)
		_, execErr = tx.Exec(ctx, `INSERT INTO ja4_block_receipts_157(
			id,workflow_id,receipt_kind,phase_revision,external_id,receipt_bytes,receipt_sha256,created_at)
			VALUES($1,$2,'edge',$3,$4,$5,$6,$7)`, uuid.NewSHA1(item.ID, []byte("edge-aggregate")), item.ID, item.Revision,
			input.PublicationID, receiptBytes, digest[:], item.UpdatedAt)
		result = item
		return execErr
	})
	if err != nil {
		return Workflow{}, storeError(err)
	}
	return result, nil
}

type edgeReceiptFact struct {
	ReceiptID     uuid.UUID `json:"receipt_id"`
	NodeID        uuid.UUID `json:"node_id"`
	ConfigSHA256  [32]byte  `json:"config_sha256"`
	ReceiptSHA256 [32]byte  `json:"receipt_sha256"`
	State         string    `json:"state"`
	ReasonCode    string    `json:"reason_code"`
	ObservedAt    time.Time `json:"observed_at"`
}

func lockExactEdgeReceipt(ctx context.Context, tx pgx.Tx, input EdgeReceiptInput) (bool, error) {
	var recordedAt *time.Time
	err := tx.QueryRow(ctx, `SELECT recorded_at FROM ja4_block_edge_receipt_queue_158
		WHERE receipt_id=$1 AND tenant_scope_id=$2 AND site_id=$3 AND workflow_id=$4
		  AND policy_id=$5 AND policy_revision=$6 AND binding_id=$7 AND binding_revision=$8
		  AND publication_id=$9 AND rollout_id=$10 AND node_id=$11
		  AND config_sha256=$12 AND receipt_sha256=$13 AND expected_revision=$14
		  AND active_policy_revision=$15 AND terminal_state=$16 AND reason_code=$17
		  AND observed_at=$18 AND state IN ('claimed','completed')
		FOR UPDATE`, input.ReceiptID, input.TenantScopeID, input.SiteID, input.WorkflowID,
		input.PolicyID, input.PolicyRevision, input.BindingID, input.BindingRevision,
		input.PublicationID, input.RolloutID, input.NodeID, input.ConfigSHA256[:], input.ReceiptSHA256[:],
		input.ExpectedRevision, input.ActivePolicyRevision, input.State, input.ReasonCode,
		input.ObservedAt.UTC()).Scan(&recordedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrRevisionConflict
	}
	return recordedAt != nil, err
}

func loadRecordedEdgeReceipts(ctx context.Context, tx pgx.Tx, workflowID uuid.UUID) ([]edgeReceiptFact, error) {
	rows, err := tx.Query(ctx, `SELECT receipt_id,node_id,config_sha256,receipt_sha256,
		terminal_state,reason_code,observed_at FROM ja4_block_edge_receipt_queue_158
		WHERE workflow_id=$1 AND recorded_at IS NOT NULL ORDER BY node_id FOR SHARE`, workflowID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]edgeReceiptFact, 0)
	for rows.Next() {
		var fact edgeReceiptFact
		var configDigest, receiptDigest []byte
		if err := rows.Scan(&fact.ReceiptID, &fact.NodeID, &configDigest, &receiptDigest,
			&fact.State, &fact.ReasonCode, &fact.ObservedAt); err != nil {
			return nil, err
		}
		if copyExactDigest(&fact.ConfigSHA256, configDigest) != nil ||
			copyExactDigest(&fact.ReceiptSHA256, receiptDigest) != nil {
			return nil, ErrRevisionConflict
		}
		result = append(result, fact)
	}
	return result, rows.Err()
}

func exactReceiptTargets(targets []uuid.UUID, facts []edgeReceiptFact) bool {
	if len(facts) > len(targets) {
		return false
	}
	want := make(map[uuid.UUID]struct{}, len(targets))
	for _, target := range targets {
		want[target] = struct{}{}
	}
	for _, fact := range facts {
		if _, ok := want[fact.NodeID]; !ok {
			return false
		}
		delete(want, fact.NodeID)
	}
	return len(want) == len(targets)-len(facts)
}

func containsNode(nodes []uuid.UUID, want uuid.UUID) bool {
	for _, nodeID := range nodes {
		if nodeID == want {
			return true
		}
	}
	return false
}

type queryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func loadWorkflow(ctx context.Context, db queryer, tenantScopeID, workflowID uuid.UUID,
	idempotencyKey string, byID bool,
) (Workflow, error) {
	query := `SELECT workflow_json FROM ja4_block_workflows_157 WHERE tenant_scope_id=$1 AND idempotency_key=$2`
	arg := any(idempotencyKey)
	if byID {
		query = `SELECT workflow_json FROM ja4_block_workflows_157 WHERE tenant_scope_id=$1 AND id=$2`
		arg = workflowID
	}
	var encoded []byte
	if err := db.QueryRow(ctx, query, tenantScopeID, arg).Scan(&encoded); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Workflow{}, ErrNotFound
		}
		return Workflow{}, storeError(err)
	}
	return decodeWorkflow(encoded)
}

func encodeWorkflow(workflow Workflow) ([]byte, []byte, error) {
	state, err := json.Marshal(workflow)
	if err != nil {
		return nil, nil, err
	}
	requestBytes, err := canonicalRequestBytes(workflow)
	return requestBytes, state, err
}

func decodeWorkflow(encoded []byte) (Workflow, error) {
	var workflow Workflow
	decoderErr := json.Unmarshal(encoded, &workflow)
	if decoderErr != nil || workflow.ID == uuid.Nil || workflow.TenantScopeID == uuid.Nil || workflow.Revision < 1 {
		return Workflow{}, ErrStoreUnavailable
	}
	return workflow, nil
}

func storeError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrIdempotencyConflict) || errors.Is(err, ErrRevisionConflict) || errors.Is(err, ErrNotFound) || errors.Is(err, ErrClaimLost) {
		return err
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrIdempotencyConflict
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return fmt.Errorf("%w: %v", ErrStoreUnavailable, err)
}

var _ WorkflowStore = (*PostgresStore)(nil)
