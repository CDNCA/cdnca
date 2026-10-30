package controlupgrade

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type RolloutDispatchIntent struct {
	CommandID      string
	PlanID         string
	PlanRevision   uint64
	BatchID        string
	NodeID         string
	InstallationID string
	Action         string
}

type PreparedRolloutAction struct {
	Actor              Actor
	Request            RolloutActionRequest
	RequestDigest      [32]byte
	PlanIdentity       RolloutIdentity
	Plan               RolloutPlan
	PlanSnapshotSHA256 string
	Binding            PlanGrantBinding
	Command            PlanCommand
	Dispatches         []RolloutDispatchIntent
}

type PreparedRolloutStatus struct {
	Identity           RolloutIdentity
	Receipt            RolloutStatusReceipt
	Plan               RolloutPlan
	PlanSnapshotSHA256 string
	Binding            PlanGrantBinding
	Health             PlanHealthEvent
	Dispatches         []RolloutDispatchIntent
}

type RolloutWriteResult struct {
	Detail   RolloutDetail
	Replayed bool
}

func (s *Store) PrepareRolloutStatus(ctx context.Context, identity RolloutIdentity,
	receipt RolloutStatusReceipt) (PreparedRolloutStatus, bool, error) {
	receipt.ObservedAt = receipt.ObservedAt.UTC().Truncate(time.Microsecond)
	if !validRolloutIdentity(identity) || !validRolloutStatus(identity, receipt) ||
		!terminalRolloutStatus(receipt.State) {
		return PreparedRolloutStatus{}, false, ErrInvalidPlanEvent
	}
	var prepared PreparedRolloutStatus
	var replayed bool
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		status, found, err := s.readRolloutStatusContext(ctx, tx, identity, &receipt, false)
		if err != nil {
			return err
		}
		if found {
			replayed = true
			return nil
		}
		health, err := rolloutHealthFromStatus(status.Command, receipt, status.Payload)
		if err != nil {
			return err
		}
		result, err := ApplyPlanHealth(status.Plan.Plan, health)
		if err != nil {
			return err
		}
		prepared = PreparedRolloutStatus{Identity: identity, Receipt: receipt,
			Plan: status.Plan.Plan, PlanSnapshotSHA256: status.Plan.SnapshotSHA256,
			Binding: status.Plan.Binding, Health: health,
			Dispatches: rolloutDispatchIntents(identity, status.Plan.Plan, result.Plan)}
		return nil
	})
	if err != nil {
		return PreparedRolloutStatus{}, false, fmt.Errorf("prepare control upgrade status: %w", err)
	}
	return prepared, replayed, nil
}

func (s *Store) FinalizeRolloutStatus(ctx context.Context, prepared PreparedRolloutStatus,
	commands []RolloutNodeCommand, outbox []RolloutOutboxMessage) (bool, error) {
	if !validRolloutIdentity(prepared.Identity) || !validRolloutStatus(prepared.Identity, prepared.Receipt) ||
		!terminalRolloutStatus(prepared.Receipt.State) || !validRolloutPlan(prepared.Plan) ||
		!validPlanDigest(prepared.PlanSnapshotSHA256) ||
		!validPlanGrantBinding(prepared.Identity, prepared.Plan, prepared.Binding) {
		return false, ErrInvalidPlanEvent
	}
	var replayed bool
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		receipt := prepared.Receipt
		status, found, err := s.readRolloutStatusContext(ctx, tx, prepared.Identity, &receipt, true)
		if err != nil {
			return err
		}
		if found {
			replayed = true
			return nil
		}
		if status.Plan.Plan.Revision != prepared.Plan.Revision ||
			status.Plan.SnapshotSHA256 != prepared.PlanSnapshotSHA256 ||
			status.Plan.Identity != prepared.Identity {
			return ErrStalePlanRevision
		}
		health, err := rolloutHealthFromStatus(status.Command, receipt, status.Payload)
		if err != nil || !samePlanHealth(health, prepared.Health) {
			return ErrStalePlanRevision
		}
		causeBytes, err := encodeRolloutValue(health)
		if err != nil {
			return err
		}
		cause := RolloutCausation{ID: health.ID, SHA256: encodedRolloutDigest(causeBytes)}
		if _, err := s.transactLockedTx(ctx, tx, prepared.Identity, prepared.Plan.ID, cause,
			func(locked LockedRolloutPlan) (RolloutAtomicMutation, error) {
				return buildRolloutStatusMutation(locked, health, commands, outbox)
			}); err != nil {
			return err
		}
		return insertRolloutStatusTx(ctx, tx, prepared.Identity, receipt, status)
	})
	if err != nil {
		return false, fmt.Errorf("finalize control upgrade status: %w", err)
	}
	return replayed, nil
}

func (s *Store) PrepareRolloutAction(ctx context.Context, actor Actor,
	request RolloutActionRequest) (PreparedRolloutAction, RolloutWriteResult, error) {
	if err := validateRolloutActionRequest(actor, request); err != nil {
		return PreparedRolloutAction{}, RolloutWriteResult{}, err
	}
	var digest [32]byte
	var prepared PreparedRolloutAction
	var replay RolloutWriteResult
	var denied bool
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorizeRolloutTx(ctx, tx, actor, rolloutManagePermission); err != nil {
			if !errors.Is(err, ErrPermissionDenied) {
				return err
			}
			denied = true
			return appendRolloutDeniedAuditOnce(ctx, tx, s.auditor, actor, request)
		}
		receipt, found, err := readRolloutWriteReceipt(ctx, tx, actor, request.IdempotencyKey)
		if err != nil {
			return err
		}
		if found {
			digest, _, err = rolloutRequestDigest(actor, uuid.MustParse(receipt.InstallationID),
				request.Operation, request.PlanID, request.RolloutActionBody)
			if err != nil {
				return err
			}
			if !bytes.Equal(receipt.RequestDigest, digest[:]) || receipt.PlanID != request.PlanID ||
				receipt.Operation != request.Operation {
				return ErrIdempotencyConflict
			}
			replay.Detail, err = receipt.detail(ctx, tx, actor.ScopeID)
			replay.Replayed = true
			return err
		}
		record, err := readActionPlanTx(ctx, tx, actor.ScopeID, request.PlanID, false)
		if err != nil {
			return err
		}
		digest, _, err = rolloutRequestDigest(actor, uuid.MustParse(record.Identity.InstallationID),
			request.Operation, request.PlanID, request.RolloutActionBody)
		if err != nil {
			return err
		}
		command := rolloutActionCommand(actor, request)
		result, err := ApplyPlanCommand(record.Plan, command)
		if err != nil {
			return err
		}
		prepared = PreparedRolloutAction{Actor: actor, Request: request, RequestDigest: digest,
			PlanIdentity: record.Identity, Plan: record.Plan, PlanSnapshotSHA256: record.SnapshotSHA256,
			Binding: record.Binding, Command: command,
			Dispatches: rolloutDispatchIntents(record.Identity, record.Plan, result.Plan)}
		return nil
	})
	if err != nil {
		return PreparedRolloutAction{}, RolloutWriteResult{}, fmt.Errorf("prepare control upgrade action: %w", err)
	}
	if denied {
		return PreparedRolloutAction{}, RolloutWriteResult{}, ErrPermissionDenied
	}
	return prepared, replay, nil
}

func (s *Store) FinalizeRolloutAction(ctx context.Context, prepared PreparedRolloutAction,
	commands []RolloutNodeCommand, outbox []RolloutOutboxMessage) (RolloutWriteResult, error) {
	if err := validatePreparedRolloutAction(prepared); err != nil {
		return RolloutWriteResult{}, err
	}
	var result RolloutWriteResult
	var denied bool
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorizeRolloutTx(ctx, tx, prepared.Actor, rolloutManagePermission); err != nil {
			if !errors.Is(err, ErrPermissionDenied) {
				return err
			}
			denied = true
			return appendRolloutDeniedAuditOnce(ctx, tx, s.auditor, prepared.Actor, prepared.Request)
		}
		receipt, found, err := readRolloutWriteReceipt(ctx, tx, prepared.Actor,
			prepared.Request.IdempotencyKey)
		if err != nil {
			return err
		}
		if found {
			if !bytes.Equal(receipt.RequestDigest, prepared.RequestDigest[:]) ||
				receipt.PlanID != prepared.Request.PlanID || receipt.Operation != prepared.Request.Operation {
				return ErrIdempotencyConflict
			}
			result.Detail, err = receipt.detail(ctx, tx, prepared.Actor.ScopeID)
			result.Replayed = true
			return err
		}
		record, err := readActionPlanTx(ctx, tx, prepared.Actor.ScopeID, prepared.Request.PlanID, true)
		if err != nil {
			return err
		}
		if record.Identity != prepared.PlanIdentity || record.Plan.Revision != prepared.Plan.Revision ||
			record.SnapshotSHA256 != prepared.PlanSnapshotSHA256 {
			return ErrStalePlanRevision
		}
		causeBytes, err := encodeRolloutValue(prepared.Command)
		if err != nil {
			return err
		}
		cause := RolloutCausation{ID: prepared.Command.ID, SHA256: encodedRolloutDigest(causeBytes)}
		commit, err := s.transactLockedTx(ctx, tx, record.Identity, record.Plan.ID, cause,
			func(locked LockedRolloutPlan) (RolloutAtomicMutation, error) {
				return buildRolloutActionMutation(locked, prepared.Command, cause, causeBytes, commands, outbox)
			})
		if err != nil {
			return err
		}
		if err := s.auditor.Append(ctx, tx, audit.Event{ScopeID: prepared.Actor.ScopeID,
			ActorUserID: &prepared.Actor.UserID, Action: "control_upgrade_rollout." + prepared.Request.Operation,
			ResourceType: "control_upgrade_rollout", ResourceID: prepared.Request.PlanID,
			RequestID: prepared.Request.RequestID, Result: "success",
			Payload: map[string]any{"revision": commit.Plan.Revision, "state": commit.Plan.State}}); err != nil {
			return err
		}
		var auditID uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT id FROM audit_events WHERE scope_id=$1 AND actor_user_id=$2
			AND action=$3 AND request_id=$4 AND result='success' ORDER BY stream_position DESC LIMIT 1`,
			prepared.Actor.ScopeID, prepared.Actor.UserID, "control_upgrade_rollout."+prepared.Request.Operation,
			prepared.Request.RequestID).Scan(&auditID); err != nil {
			return err
		}
		var completedAt, createdAt, updatedAt time.Time
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp(),created_at,updated_at
			FROM control_upgrade_rollout_plans WHERE id=$1`, prepared.Request.PlanID).
			Scan(&completedAt, &createdAt, &updatedAt); err != nil {
			return err
		}
		snapshot, err := encodeRolloutValue(commit.Plan)
		if err != nil {
			return err
		}
		snapshotDigest := rolloutSHA256(snapshot)
		receiptID, err := uuid.NewV7()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO control_upgrade_write_receipts_096(
			id,actor_scope_id,actor_user_id,installation_id,plan_id,operation,idempotency_key,
			request_digest,request_id,result_snapshot_bytes,result_snapshot_sha256,result_revision,
			audit_event_id,created_at,completed_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$14)`, receiptID,
			prepared.Actor.ScopeID, prepared.Actor.UserID, record.Identity.InstallationID,
			prepared.Request.PlanID, prepared.Request.Operation, prepared.Request.IdempotencyKey,
			prepared.RequestDigest[:], prepared.Request.RequestID, snapshot, snapshotDigest,
			commit.Plan.Revision, auditID, completedAt.UTC().Truncate(time.Microsecond)); err != nil {
			return err
		}
		result.Detail = rolloutDetail(commit.Plan, record.Identity.InstallationID, createdAt, updatedAt)
		return nil
	})
	if err != nil {
		return RolloutWriteResult{}, fmt.Errorf("finalize control upgrade action: %w", err)
	}
	if denied {
		return RolloutWriteResult{}, ErrPermissionDenied
	}
	return result, nil
}

type actionPlanRecord struct {
	Identity       RolloutIdentity
	Plan           RolloutPlan
	SnapshotSHA256 string
	Binding        PlanGrantBinding
}

func readActionPlanTx(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, planID string,
	lock bool) (actionPlanRecord, error) {
	query := `SELECT actor_scope_id,actor_user_id,installation_id,canonical_snapshot_bytes,
		canonical_snapshot_sha256,parent_grant_bytes,parent_grant_sha256,artifact_bundle_bytes,
		artifact_bundle_sha256,forward_profile_bytes,
		forward_profile_sha256,rollback_profile_bytes,rollback_profile_sha256
		FROM control_upgrade_rollout_plans WHERE id=$1 AND actor_scope_id=$2`
	if lock {
		query += " FOR UPDATE"
	} else {
		query += " FOR SHARE"
	}
	var record actionPlanRecord
	var snapshot, snapshotDigest, parentDigest, bundleDigest, forwardDigest, rollbackDigest []byte
	err := tx.QueryRow(ctx, query, planID, scopeID).Scan(&record.Identity.ActorScopeID,
		&record.Identity.ActorUserID, &record.Identity.InstallationID, &snapshot, &snapshotDigest,
		&record.Binding.ParentGrantBytes, &parentDigest, &record.Binding.ArtifactBundleBytes,
		&bundleDigest, &record.Binding.ForwardProfileBytes, &forwardDigest,
		&record.Binding.RollbackProfileBytes, &rollbackDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		return actionPlanRecord{}, ErrRolloutNotFound
	}
	if err != nil {
		return actionPlanRecord{}, err
	}
	record.Plan, record.SnapshotSHA256, err = decodeRolloutPlan(snapshot, snapshotDigest)
	if err != nil || record.Plan.ID != planID {
		return actionPlanRecord{}, ErrInvalidPlan
	}
	record.Binding.ParentGrantSHA256 = base64.RawURLEncoding.EncodeToString(parentDigest)
	record.Binding.ArtifactBundleSHA256 = base64.RawURLEncoding.EncodeToString(bundleDigest)
	record.Binding.ForwardProfileSHA256 = base64.RawURLEncoding.EncodeToString(forwardDigest)
	record.Binding.RollbackProfileSHA256 = base64.RawURLEncoding.EncodeToString(rollbackDigest)
	if !validPlanGrantBinding(record.Identity, record.Plan, record.Binding) {
		return actionPlanRecord{}, ErrInvalidPlan
	}
	return record, nil
}

type storedRolloutWriteReceipt struct {
	RequestDigest  []byte
	InstallationID string
	PlanID         string
	Operation      string
	Snapshot       []byte
	SnapshotDigest []byte
	Revision       uint64
	CompletedAt    time.Time
}

func readRolloutWriteReceipt(ctx context.Context, tx pgx.Tx, actor Actor,
	key string) (storedRolloutWriteReceipt, bool, error) {
	var receipt storedRolloutWriteReceipt
	err := tx.QueryRow(ctx, `SELECT request_digest,installation_id,plan_id,operation,
		result_snapshot_bytes,result_snapshot_sha256,result_revision,completed_at
		FROM control_upgrade_write_receipts_096
		WHERE actor_scope_id=$1 AND actor_user_id=$2 AND idempotency_key=$3 FOR UPDATE`,
		actor.ScopeID, actor.UserID, key).Scan(&receipt.RequestDigest, &receipt.InstallationID,
		&receipt.PlanID, &receipt.Operation, &receipt.Snapshot, &receipt.SnapshotDigest,
		&receipt.Revision, &receipt.CompletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return storedRolloutWriteReceipt{}, false, nil
	}
	return receipt, err == nil, err
}

func (receipt storedRolloutWriteReceipt) detail(ctx context.Context, tx pgx.Tx,
	scopeID uuid.UUID) (RolloutDetail, error) {
	plan, _, err := decodeRolloutPlan(receipt.Snapshot, receipt.SnapshotDigest)
	if err != nil || plan.ID != receipt.PlanID || plan.Revision != receipt.Revision {
		return RolloutDetail{}, ErrInvalidPlan
	}
	var createdAt time.Time
	if err := tx.QueryRow(ctx, `SELECT created_at FROM control_upgrade_rollout_plans
		WHERE id=$1 AND actor_scope_id=$2`, receipt.PlanID, scopeID).Scan(&createdAt); err != nil {
		return RolloutDetail{}, err
	}
	return rolloutDetail(plan, receipt.InstallationID, createdAt, receipt.CompletedAt), nil
}

func buildRolloutActionMutation(locked LockedRolloutPlan, command PlanCommand, cause RolloutCausation,
	causeBytes []byte, commands []RolloutNodeCommand, outbox []RolloutOutboxMessage) (RolloutAtomicMutation, error) {
	result, err := ApplyPlanCommand(locked.Plan, command)
	if err != nil {
		return RolloutAtomicMutation{}, err
	}
	eventBytes, err := encodeRolloutValue(result.Event)
	if err != nil {
		return RolloutAtomicMutation{}, err
	}
	snapshot, err := encodeRolloutValue(result.Plan)
	if err != nil {
		return RolloutAtomicMutation{}, err
	}
	return RolloutAtomicMutation{ExpectedRevision: locked.Plan.Revision, Plan: result.Plan,
		CanonicalSnapshotBytes: snapshot, CanonicalSnapshotSHA256: encodedRolloutDigest(snapshot),
		Events: []RolloutEventMutation{{Causation: cause, CausationBytes: append([]byte(nil), causeBytes...),
			Event: result.Event, EventBytes: eventBytes, EventSHA256: encodedRolloutDigest(eventBytes)}},
		NodeCommands: cloneRolloutCommands(commands), Outbox: cloneRolloutOutbox(outbox)}, nil
}

func buildRolloutStatusMutation(locked LockedRolloutPlan, health PlanHealthEvent,
	commands []RolloutNodeCommand, outbox []RolloutOutboxMessage) (RolloutAtomicMutation, error) {
	result, err := ApplyPlanHealth(locked.Plan, health)
	if err != nil {
		return RolloutAtomicMutation{}, err
	}
	events := make([]RolloutEventMutation, 0, result.Plan.Revision-locked.Plan.Revision)
	for revision := locked.Plan.Revision + 1; revision <= result.Plan.Revision; revision++ {
		event, found := rolloutPlanEventAt(result.Plan, revision)
		causationValue, causeFound := rolloutPlanCausationAt(result.Plan, revision)
		if !found || !causeFound {
			return RolloutAtomicMutation{}, ErrInvalidPlanEvent
		}
		causeBytes, err := encodeRolloutValue(causationValue)
		if err != nil {
			return RolloutAtomicMutation{}, err
		}
		eventBytes, err := encodeRolloutValue(event)
		if err != nil {
			return RolloutAtomicMutation{}, err
		}
		events = append(events, RolloutEventMutation{
			Causation: RolloutCausation{ID: rolloutCausationID(causationValue),
				SHA256: encodedRolloutDigest(causeBytes)},
			CausationBytes: causeBytes, Event: event, EventBytes: eventBytes,
			EventSHA256: encodedRolloutDigest(eventBytes),
		})
	}
	snapshot, err := encodeRolloutValue(result.Plan)
	if err != nil {
		return RolloutAtomicMutation{}, err
	}
	return RolloutAtomicMutation{ExpectedRevision: locked.Plan.Revision, Plan: result.Plan,
		CanonicalSnapshotBytes: snapshot, CanonicalSnapshotSHA256: encodedRolloutDigest(snapshot),
		Events: events, NodeCommands: cloneRolloutCommands(commands), Outbox: cloneRolloutOutbox(outbox)}, nil
}

func rolloutHealthFromStatus(command RolloutNodeCommand, receipt RolloutStatusReceipt,
	payload rolloutStatusPayload) (PlanHealthEvent, error) {
	health := PlanHealthEvent{ID: receipt.StatusID,
		NodeID: receipt.NodeID, DispatchRevision: command.PlanRevision,
		InstallerTransactionID: payload.InstallerTransactionID}
	switch receipt.State {
	case "healthy", "rolled_back":
		if payload.Schema == EdgeUpgradeStatusSchemaV1 {
			return PlanHealthEvent{}, ErrStaleStatusEvidence
		}
		if payload.Schema != EdgeUpgradeStatusSchemaV2 ||
			!validActiveProbeEvidence(payload.InstallerTransactionID, payload.ActiveEvidence) ||
			payload.ActiveEvidence.ProbeObservedAt.After(receipt.ObservedAt) {
			return PlanHealthEvent{}, ErrInvalidPlanEvent
		}
		// An upgrade command that ends rolled_back restored the previous
		// artifact on the node (agent evidence: active=rollback artifact,
		// last known good=forward artifact, as migration 105 enforces): the
		// upgrade failed on this node.
		// Counting it as healthy would mark a node still running the old
		// version as upgraded.
		if receipt.State == "rolled_back" && command.Action == "upgrade" {
			if health.Code = rolloutFailureReason(payload.ErrorCode); health.Code == "" {
				return PlanHealthEvent{}, ErrInvalidPlanEvent
			}
			break
		}
		health.Success = true
		health.ActiveEvidence = cloneControlActiveProbeEvidence(payload.ActiveEvidence)
	case "uncertain":
		health.Code = "unknown_outcome"
	case "failed":
		if health.Code = rolloutFailureReason(payload.ErrorCode); health.Code == "" {
			return PlanHealthEvent{}, ErrInvalidPlanEvent
		}
	default:
		return PlanHealthEvent{}, ErrInvalidPlanEvent
	}
	return health, nil
}

// rolloutFailureReason normalizes an agent error code into a plan reason; ""
// means it cannot be one.
func rolloutFailureReason(errorCode string) string {
	code := strings.NewReplacer("-", "_", ".", "_", ":", "_").Replace(strings.ToLower(errorCode))
	if !planReasonPattern.MatchString(code) {
		return ""
	}
	return code
}

func rolloutDispatchIntents(identity RolloutIdentity, before, after RolloutPlan) []RolloutDispatchIntent {
	dispatches := expectedRolloutDispatches(before, after)
	intents := make([]RolloutDispatchIntent, 0, len(dispatches))
	for key, dispatch := range dispatches {
		intents = append(intents, RolloutDispatchIntent{CommandID: derivedPlanID(after.ID, "node-command",
			fmt.Sprintf("%d:%s:%s", key.revision, key.action, key.nodeID)), PlanID: after.ID,
			PlanRevision: key.revision, BatchID: dispatch.batchID, NodeID: key.nodeID,
			InstallationID: identity.InstallationID, Action: key.action})
	}
	sort.Slice(intents, func(left, right int) bool { return intents[left].NodeID < intents[right].NodeID })
	return intents
}

func rolloutActionCommand(actor Actor, request RolloutActionRequest) PlanCommand {
	return PlanCommand{ID: derivedPlanID(request.PlanID, "api-action",
		actor.ScopeID.String()+":"+actor.UserID.String()+":"+request.IdempotencyKey),
		Action: PlanAction(request.Operation), ExpectedRevision: request.ExpectedRevision, Reason: request.Reason}
}

func validateRolloutActionRequest(actor Actor, request RolloutActionRequest) error {
	if !validRolloutActor(actor) || !validCanonicalPlanUUID(request.PlanID) ||
		(request.Operation != string(PlanStart) && request.Operation != string(PlanPauseAction) &&
			request.Operation != string(PlanResume) && request.Operation != string(PlanRollback)) ||
		request.ExpectedRevision == 0 || request.ExpectedRevision > maxRolloutRevision ||
		!planReasonPattern.MatchString(request.Reason) ||
		!writeMetadataPattern.MatchString(request.IdempotencyKey) ||
		!writeMetadataPattern.MatchString(request.RequestID) {
		return ErrInvalidInput
	}
	return nil
}

func validatePreparedRolloutAction(prepared PreparedRolloutAction) error {
	if validateRolloutActionRequest(prepared.Actor, prepared.Request) != nil ||
		!validRolloutIdentity(prepared.PlanIdentity) || !validRolloutPlan(prepared.Plan) ||
		prepared.Plan.ID != prepared.Request.PlanID || prepared.Plan.Revision != prepared.Request.ExpectedRevision ||
		!validPlanDigest(prepared.PlanSnapshotSHA256) ||
		prepared.Command != rolloutActionCommand(prepared.Actor, prepared.Request) {
		return ErrInvalidInput
	}
	wantDigest, _, err := rolloutRequestDigest(prepared.Actor,
		uuid.MustParse(prepared.PlanIdentity.InstallationID), prepared.Request.Operation,
		prepared.Request.PlanID, prepared.Request.RolloutActionBody)
	if err != nil || wantDigest != prepared.RequestDigest {
		return ErrInvalidInput
	}
	return nil
}

func appendRolloutDeniedAuditOnce(ctx context.Context, tx pgx.Tx, logger *audit.Log, actor Actor,
	request RolloutActionRequest) error {
	action := "control_upgrade_rollout." + request.Operation
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM audit_events WHERE scope_id=$1
		AND actor_user_id=$2 AND action=$3 AND request_id=$4 AND result='denied')`,
		actor.ScopeID, actor.UserID, action, request.RequestID).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return nil
	}
	return logger.Append(ctx, tx, audit.Event{ScopeID: actor.ScopeID, ActorUserID: &actor.UserID,
		Action: action, ResourceType: "control_upgrade_rollout", ResourceID: request.PlanID,
		RequestID: request.RequestID, Result: "denied", Payload: map[string]any{"reason": "permission_denied"}})
}

func encodeRolloutValue(value any) ([]byte, error) { return json.Marshal(value) }

func encodedRolloutDigest(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(rolloutSHA256(value))
}
