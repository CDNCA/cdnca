package nodeisolation

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool    *pgxpool.Pool
	auditor *audit.Log
}

func NewIsolationStore(pool *pgxpool.Pool, clock func() time.Time) (*Store, error) {
	if pool == nil || clock == nil {
		return nil, ErrInvalidInput
	}
	return &Store{pool: pool, auditor: audit.NewWithClock(pool, clock)}, nil
}

func (store *Store) Apply(ctx context.Context, command ApplyCommand) (ApplyResult, error) {
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return ApplyResult{}, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	if replay, found, err := replayIsolationReport(ctx, tx, command); err != nil || found {
		return replay, err
	}
	if err := lockNodeAndDesiredIdentity(ctx, tx, command.Result); err != nil {
		return ApplyResult{}, err
	}
	previous, err := readIsolationState(ctx, tx, command.Result.ScopeID, command.Result.NodeID, true)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return ApplyResult{}, err
	}
	result := evolveIsolationState(previous, command)
	if err := writeIsolationState(ctx, tx, result.State); err != nil {
		return ApplyResult{}, err
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return ApplyResult{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO node_isolation_reports(
		report_id,scope_id,node_id,request_digest,response,created_at)
		VALUES($1,$2,$3,$4,$5,$6)`, command.Result.ReportID, command.Result.ScopeID,
		command.Result.NodeID, command.Digest[:], encoded, command.Now); err != nil {
		return ApplyResult{}, err
	}
	if err := store.persistEffects(ctx, tx, command.Result, result); err != nil {
		return ApplyResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ApplyResult{}, err
	}
	return result, nil
}

func (store *Store) List(ctx context.Context, scopeID uuid.UUID, nodeIDs []uuid.UUID) (map[uuid.UUID]State, error) {
	query := `SELECT scope_id,node_id,status,desired_config_version_id,desired_artifact_sha256,
		desired_identity_schema,consecutive_failures,consecutive_healthy,last_session_epoch,
		last_health_sequence,last_report_id,last_outcome,last_error_code,reason_code,revision,
		isolated_at,recovered_at,updated_at FROM node_isolation_states WHERE scope_id=$1`
	arguments := []any{scopeID}
	if len(nodeIDs) > 0 {
		query += ` AND node_id=ANY($2::uuid[])`
		arguments = append(arguments, nodeIDs)
	}
	query += ` ORDER BY node_id`
	rows, err := store.pool.Query(ctx, query, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	states := make(map[uuid.UUID]State)
	for rows.Next() {
		state, err := scanIsolationState(rows)
		if err != nil {
			return nil, err
		}
		states[state.NodeID] = state
	}
	return states, rows.Err()
}

func replayIsolationReport(ctx context.Context, tx pgx.Tx, command ApplyCommand) (ApplyResult, bool, error) {
	var scopeID uuid.UUID
	var digest, response []byte
	err := tx.QueryRow(ctx, `SELECT scope_id,request_digest,response FROM node_isolation_reports
		WHERE report_id=$1`, command.Result.ReportID).Scan(&scopeID, &digest, &response)
	if errors.Is(err, pgx.ErrNoRows) {
		return ApplyResult{}, false, nil
	}
	if err != nil {
		return ApplyResult{}, false, err
	}
	if scopeID != command.Result.ScopeID || !bytes.Equal(digest, command.Digest[:]) {
		return ApplyResult{}, false, ErrConflict
	}
	var result ApplyResult
	if err := json.Unmarshal(response, &result); err != nil {
		return ApplyResult{}, false, err
	}
	result.Replay = true
	result.Effects = nil
	return result, true, nil
}

// lockNodeAndDesiredIdentity locks the node in its owner scope. Isolation is
// node-level (migration 288): a platform node a tenant claimed has no single
// current configuration identity, so the desired identity is not matched
// against node_config_state; it only has to name an existing config version.
func lockNodeAndDesiredIdentity(ctx context.Context, tx pgx.Tx, value SyncResult) error {
	var known bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM config_versions WHERE id=$3)
		FROM nodes node WHERE node.id=$1 AND node.scope_id=$2 FOR UPDATE OF node`,
		value.NodeID, value.ScopeID, value.Desired.ConfigVersionID).Scan(&known)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if !known {
		return ErrConflict
	}
	return nil
}

func readIsolationState(ctx context.Context, tx pgx.Tx, scopeID, nodeID uuid.UUID, lock bool) (State, error) {
	query := `SELECT scope_id,node_id,status,desired_config_version_id,desired_artifact_sha256,
		desired_identity_schema,consecutive_failures,consecutive_healthy,last_session_epoch,
		last_health_sequence,last_report_id,last_outcome,last_error_code,reason_code,revision,
		isolated_at,recovered_at,updated_at FROM node_isolation_states WHERE scope_id=$1 AND node_id=$2`
	if lock {
		query += ` FOR UPDATE`
	}
	return scanIsolationState(tx.QueryRow(ctx, query, scopeID, nodeID))
}

type rowScanner interface {
	Scan(...any) error
}

func scanIsolationState(row rowScanner) (State, error) {
	var state State
	var artifact []byte
	var identitySchema int32
	var sessionEpoch, healthSequence int64
	var lastErrorCode *string
	err := row.Scan(&state.ScopeID, &state.NodeID, &state.Status, &state.Desired.ConfigVersionID, &artifact,
		&identitySchema, &state.ConsecutiveFailures, &state.ConsecutiveHealthy, &sessionEpoch,
		&healthSequence, &state.LastReportID, &state.LastOutcome, &lastErrorCode, &state.ReasonCode,
		&state.Revision, &state.IsolatedAt, &state.RecoveredAt, &state.UpdatedAt)
	if err != nil {
		return State{}, err
	}
	if len(artifact) != len(state.Desired.ArtifactSHA256) || identitySchema != 1 || sessionEpoch < 0 || healthSequence < 0 {
		return State{}, ErrOutcomeUncertain
	}
	copy(state.Desired.ArtifactSHA256[:], artifact)
	state.Desired.Schema = uint32(identitySchema)
	if lastErrorCode != nil {
		state.LastErrorCode = *lastErrorCode
	}
	state.LastSessionEpoch = uint64(sessionEpoch)
	state.LastHealthSequence = uint64(healthSequence)
	return state, nil
}

func writeIsolationState(ctx context.Context, tx pgx.Tx, state State) error {
	_, err := tx.Exec(ctx, `INSERT INTO node_isolation_states(
		scope_id,node_id,status,desired_config_version_id,desired_artifact_sha256,desired_identity_schema,
		consecutive_failures,consecutive_healthy,last_session_epoch,last_health_sequence,last_report_id,
		last_outcome,last_error_code,reason_code,revision,isolated_at,recovered_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NULLIF($13,''),$14,$15,$16,$17,$18)
		ON CONFLICT(scope_id,node_id) DO UPDATE SET status=EXCLUDED.status,
		desired_config_version_id=EXCLUDED.desired_config_version_id,
		desired_artifact_sha256=EXCLUDED.desired_artifact_sha256,
		desired_identity_schema=EXCLUDED.desired_identity_schema,
		consecutive_failures=EXCLUDED.consecutive_failures,consecutive_healthy=EXCLUDED.consecutive_healthy,
		last_session_epoch=EXCLUDED.last_session_epoch,last_health_sequence=EXCLUDED.last_health_sequence,
		last_report_id=EXCLUDED.last_report_id,last_outcome=EXCLUDED.last_outcome,
		last_error_code=EXCLUDED.last_error_code,reason_code=EXCLUDED.reason_code,
		revision=EXCLUDED.revision,isolated_at=EXCLUDED.isolated_at,recovered_at=EXCLUDED.recovered_at,
		updated_at=EXCLUDED.updated_at`, state.ScopeID, state.NodeID, state.Status,
		state.Desired.ConfigVersionID, state.Desired.ArtifactSHA256[:], int32(state.Desired.Schema),
		state.ConsecutiveFailures, state.ConsecutiveHealthy, int64(state.LastSessionEpoch),
		int64(state.LastHealthSequence), state.LastReportID, state.LastOutcome, state.LastErrorCode,
		state.ReasonCode, state.Revision, state.IsolatedAt, state.RecoveredAt, state.UpdatedAt)
	return err
}

func (store *Store) persistEffects(ctx context.Context, tx pgx.Tx, input SyncResult, result ApplyResult) error {
	for _, effect := range result.Effects {
		if effect.Kind == EffectAlertOpened || effect.Kind == EffectAlertResolved {
			eventID, err := uuid.NewV7()
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO node_isolation_alert_events(
				id,scope_id,node_id,state_revision,kind,code,dedupe_key,created_at)
				VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, eventID, input.ScopeID, input.NodeID,
				result.State.Revision, effect.Kind, effect.Code, effect.DedupeKey, result.State.UpdatedAt); err != nil {
				return err
			}
		}
		if effect.Kind != EffectAudit {
			continue
		}
		if err := store.auditor.Append(ctx, tx, audit.Event{
			ScopeID: input.ScopeID, Action: isolationAuditAction(effect.Code), ResourceType: "node", ResourceID: input.NodeID.String(),
			RequestID: input.ReportID.String(), Result: isolationAuditResult(input.Outcome), Payload: map[string]any{
				"config_version_id": input.Desired.ConfigVersionID.String(),
				"artifact_sha256":   hex.EncodeToString(input.Desired.ArtifactSHA256[:]),
				"identity_schema":   input.Desired.Schema,
				"error_code":        input.ErrorCode, "reason_code": result.State.ReasonCode,
				"state_revision": result.State.Revision,
			},
		}); err != nil {
			return fmt.Errorf("append node isolation audit: %w", err)
		}
	}
	return nil
}

// isolationAuditResult maps a sync outcome to an audit_events.result value.
func isolationAuditResult(outcome Outcome) string {
	if outcome == OutcomeSucceeded {
		return "success"
	}
	return "failure"
}

// isolationAuditAction names the audit event of an effect code in the event
// catalog's <category>.<object>.<verb> form; the alert table keeps the code.
func isolationAuditAction(code string) string {
	switch code {
	case AuditNodeIsolated:
		return "node.config_sync.isolated"
	case AuditNodeRecovered:
		return "node.config_sync.recovered"
	}
	return "node.config_sync.result_recorded"
}
