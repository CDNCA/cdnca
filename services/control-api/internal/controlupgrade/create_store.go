package controlupgrade

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
)

const (
	createIntentReserved = "reserved"
	createIntentAcquired = "acquired"
	createIntentConsumed = "consumed"
)

type CreateRolloutIntent struct {
	ID            string
	PlanID        string
	State         string
	RequestDigest [sha256.Size]byte
	RequestID     string
	Binding       PlanGrantBinding
}

func (s *Store) PrepareCreateRollout(ctx context.Context, actor Actor, identity RolloutIdentity,
	request CreateRolloutRequest, digest [sha256.Size]byte) (CreateRolloutIntent, RolloutWriteResult, error) {
	if s == nil || s.pool == nil || !validRolloutActor(actor) || !validRolloutIdentity(identity) ||
		identity.ActorScopeID != actor.ScopeID.String() || identity.ActorUserID != actor.UserID.String() ||
		validateCreateRolloutRequest(request) != nil {
		return CreateRolloutIntent{}, RolloutWriteResult{}, ErrInvalidInput
	}
	var intent CreateRolloutIntent
	var replay RolloutWriteResult
	var denied bool
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorizeRolloutTx(ctx, tx, actor, rolloutManagePermission); err != nil {
			if !errors.Is(err, ErrPermissionDenied) {
				return err
			}
			denied = true
			return appendCreateRolloutDeniedAuditOnce(ctx, tx, s.auditor, actor, request)
		}
		if receipt, found, err := readRolloutWriteReceipt(ctx, tx, actor, request.IdempotencyKey); err != nil {
			return err
		} else if found {
			if receipt.Operation != "create" || !bytes.Equal(receipt.RequestDigest, digest[:]) ||
				receipt.InstallationID != identity.InstallationID {
				return ErrIdempotencyConflict
			}
			replay.Detail, err = receipt.detail(ctx, tx, actor.ScopeID)
			replay.Replayed = true
			return err
		}
		var requestDigest, parentDigest, bundleDigest, forwardDigest, rollbackDigest []byte
		err := tx.QueryRow(ctx, `SELECT id,candidate_plan_id,state,request_digest,request_id,
			parent_grant_bytes,parent_grant_sha256,artifact_bundle_bytes,artifact_bundle_sha256,
			forward_profile_bytes,forward_profile_sha256,rollback_profile_bytes,rollback_profile_sha256
			FROM control_upgrade_grant_intents_096
			WHERE actor_scope_id=$1 AND actor_user_id=$2 AND idempotency_key=$3 FOR UPDATE`,
			actor.ScopeID, actor.UserID, request.IdempotencyKey).Scan(&intent.ID, &intent.PlanID,
			&intent.State, &requestDigest, &intent.RequestID, &intent.Binding.ParentGrantBytes,
			&parentDigest, &intent.Binding.ArtifactBundleBytes, &bundleDigest,
			&intent.Binding.ForwardProfileBytes, &forwardDigest, &intent.Binding.RollbackProfileBytes, &rollbackDigest)
		if err == nil {
			if !bytes.Equal(requestDigest, digest[:]) || intent.RequestID != request.RequestID {
				return ErrIdempotencyConflict
			}
			copy(intent.RequestDigest[:], requestDigest)
			if intent.State == createIntentAcquired {
				intent.Binding.ParentGrantSHA256 = base64.RawURLEncoding.EncodeToString(parentDigest)
				intent.Binding.ArtifactBundleSHA256 = base64.RawURLEncoding.EncodeToString(bundleDigest)
				intent.Binding.ForwardProfileSHA256 = base64.RawURLEncoding.EncodeToString(forwardDigest)
				intent.Binding.RollbackProfileSHA256 = base64.RawURLEncoding.EncodeToString(rollbackDigest)
			}
			if intent.State != createIntentReserved && intent.State != createIntentAcquired {
				return ErrIdempotencyConflict
			}
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		intentID, err := uuid.NewV7()
		if err != nil {
			return err
		}
		planID, err := uuid.NewV7()
		if err != nil {
			return err
		}
		var now time.Time
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO control_upgrade_grant_intents_096(
			id,actor_scope_id,actor_user_id,installation_id,candidate_plan_id,plan_id,
			idempotency_key,request_digest,request_id,state,created_at,updated_at)
			VALUES($1,$2,$3,$4,$5,NULL,$6,$7,$8,'reserved',$9,$9)`, intentID, actor.ScopeID,
			actor.UserID, identity.InstallationID, planID, request.IdempotencyKey, digest[:], request.RequestID,
			now.UTC().Truncate(time.Microsecond))
		if err != nil {
			return err
		}
		intent = CreateRolloutIntent{ID: intentID.String(), PlanID: planID.String(),
			State: createIntentReserved, RequestDigest: digest, RequestID: request.RequestID}
		return nil
	})
	if err != nil {
		return CreateRolloutIntent{}, RolloutWriteResult{}, fmt.Errorf("prepare control upgrade rollout create: %w", err)
	}
	if denied {
		return CreateRolloutIntent{}, RolloutWriteResult{}, ErrPermissionDenied
	}
	return intent, replay, nil
}

func (s *Store) AcquireCreateRollout(ctx context.Context, actor Actor, intent CreateRolloutIntent,
	binding PlanGrantBinding) error {
	if s == nil || s.pool == nil || !validRolloutActor(actor) || !validCanonicalPlanUUID(intent.ID) ||
		!validCanonicalPlanUUID(intent.PlanID) || intent.RequestID == "" || len(binding.ParentGrantBytes) == 0 ||
		len(binding.ArtifactBundleBytes) == 0 || !validPlanDigest(binding.ParentGrantSHA256) ||
		!validPlanDigest(binding.ArtifactBundleSHA256) || !validPlanDigest(binding.ForwardProfileSHA256) ||
		!validPlanDigest(binding.RollbackProfileSHA256) {
		return ErrInvalidInput
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorizeRolloutTx(ctx, tx, actor, rolloutManagePermission); err != nil {
			return err
		}
		var state, planID string
		var requestDigest, parent, parentDigest, bundle, bundleDigest, forward, forwardDigest, rollback, rollbackDigest []byte
		if err := tx.QueryRow(ctx, `SELECT state,candidate_plan_id,request_digest,parent_grant_bytes,
			parent_grant_sha256,artifact_bundle_bytes,artifact_bundle_sha256,forward_profile_bytes,
			forward_profile_sha256,rollback_profile_bytes,rollback_profile_sha256
			FROM control_upgrade_grant_intents_096 WHERE id=$1 AND actor_scope_id=$2 AND actor_user_id=$3 FOR UPDATE`,
			intent.ID, actor.ScopeID, actor.UserID).Scan(&state, &planID, &requestDigest, &parent,
			&parentDigest, &bundle, &bundleDigest, &forward, &forwardDigest, &rollback, &rollbackDigest); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrIdempotencyConflict
			}
			return err
		}
		if planID != intent.PlanID || !bytes.Equal(requestDigest, intent.RequestDigest[:]) {
			return ErrIdempotencyConflict
		}
		if state == createIntentAcquired {
			if !sameStoredPlanGrantBinding(binding, parent, parentDigest, bundle, bundleDigest,
				forward, forwardDigest, rollback, rollbackDigest) {
				return ErrIdempotencyConflict
			}
			return nil
		}
		if state != createIntentReserved {
			return ErrIdempotencyConflict
		}
		var parentExpiresAt, commandIssuanceNotAfter int64
		parentGrant, parentErr := decodeParentGrant(binding.ParentGrantBytes)
		bundleValue, bundleErr := decodePlanBundle(binding.ArtifactBundleBytes)
		if parentErr != nil || bundleErr != nil || parentGrant.GrantID != bundleValue.ParentGrantID ||
			bundleValue.PlanID != intent.PlanID {
			return ErrGrantInvalid
		}
		parentExpiresAt, commandIssuanceNotAfter = parentGrant.ExpiresAt, bundleValue.CommandIssuanceNotAfter
		_, err := tx.Exec(ctx, `UPDATE control_upgrade_grant_intents_096 SET state='acquired',
			parent_grant_bytes=$2,parent_grant_sha256=$3,parent_grant_expires_at=to_timestamp($4),
			artifact_bundle_id=$5,artifact_bundle_bytes=$6,artifact_bundle_sha256=$7,
			command_issuance_not_after=to_timestamp($8),forward_profile_bytes=$9,forward_profile_sha256=$10,
			rollback_profile_bytes=$11,rollback_profile_sha256=$12,updated_at=clock_timestamp()
			WHERE id=$1`, intent.ID, binding.ParentGrantBytes, mustDecodePlanDigest(binding.ParentGrantSHA256),
			parentExpiresAt, bundleValue.BundleID, binding.ArtifactBundleBytes,
			mustDecodePlanDigest(binding.ArtifactBundleSHA256), commandIssuanceNotAfter,
			binding.ForwardProfileBytes, mustDecodePlanDigest(binding.ForwardProfileSHA256),
			binding.RollbackProfileBytes, mustDecodePlanDigest(binding.RollbackProfileSHA256))
		return err
	})
}

func decodeParentGrant(encoded []byte) (entitlement.UpgradeGrant, error) {
	signed, err := entitlement.DecodeUpgradeGrant(encoded)
	if err != nil {
		return entitlement.UpgradeGrant{}, ErrGrantInvalid
	}
	return signed.Grant, nil
}

func (s *Store) FinalizeCreateRollout(ctx context.Context, actor Actor, identity RolloutIdentity,
	request CreateRolloutRequest, digest [sha256.Size]byte, intent CreateRolloutIntent,
	cohort RolloutTargetCohort, plan RolloutPlan, binding PlanGrantBinding, snapshot []byte,
	snapshotDigest string) (RolloutWriteResult, error) {
	if !validRolloutIdentity(identity) || !validRolloutPlan(plan) || plan.ID != intent.PlanID ||
		!validPlanGrantBinding(identity, plan, binding) || !validRolloutSnapshot(plan, snapshot, snapshotDigest) {
		return RolloutWriteResult{}, ErrInvalidPlan
	}
	var result RolloutWriteResult
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorizeRolloutTx(ctx, tx, actor, rolloutManagePermission); err != nil {
			return err
		}
		if receipt, found, err := readRolloutWriteReceipt(ctx, tx, actor, request.IdempotencyKey); err != nil {
			return err
		} else if found {
			if receipt.Operation != "create" || !bytes.Equal(receipt.RequestDigest, digest[:]) {
				return ErrIdempotencyConflict
			}
			result.Detail, err = receipt.detail(ctx, tx, actor.ScopeID)
			result.Replayed = true
			return err
		}
		var state, candidatePlanID string
		var requestDigest []byte
		if err := tx.QueryRow(ctx, `SELECT state,candidate_plan_id,request_digest
			FROM control_upgrade_grant_intents_096 WHERE id=$1 AND actor_scope_id=$2 AND actor_user_id=$3 FOR UPDATE`,
			intent.ID, actor.ScopeID, actor.UserID).Scan(&state, &candidatePlanID, &requestDigest); err != nil {
			return err
		}
		if state != createIntentAcquired || candidatePlanID != plan.ID || !bytes.Equal(requestDigest, digest[:]) {
			return ErrIdempotencyConflict
		}
		confirmed, err := loadRolloutTargetCohortTx(ctx, tx, actor.ScopeID, request.NodeIDs)
		if err != nil || !reflect.DeepEqual(confirmed, cohort) {
			if err == nil {
				err = ErrCohortIncompatible
			}
			return err
		}
		createdAt := s.now().UTC().Truncate(time.Microsecond)
		if err := insertRolloutPlanTx(ctx, tx, identity, plan, binding, snapshot, snapshotDigest, createdAt); err != nil {
			return err
		}
		if err := s.auditor.Append(ctx, tx, audit.Event{ScopeID: actor.ScopeID, ActorUserID: &actor.UserID,
			Action: "control_upgrade_rollout.create", ResourceType: "control_upgrade_rollout", ResourceID: plan.ID,
			RequestID: request.RequestID, Result: "success",
			Payload: map[string]any{"revision": plan.Revision, "state": plan.State}}); err != nil {
			return err
		}
		var auditID uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT id FROM audit_events WHERE scope_id=$1 AND actor_user_id=$2
			AND action='control_upgrade_rollout.create' AND request_id=$3 AND result='success'
			ORDER BY stream_position DESC LIMIT 1`, actor.ScopeID, actor.UserID, request.RequestID).Scan(&auditID); err != nil {
			return err
		}
		receiptID, err := uuid.NewV7()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO control_upgrade_write_receipts_096(
			id,actor_scope_id,actor_user_id,installation_id,plan_id,operation,idempotency_key,
			request_digest,request_id,result_snapshot_bytes,result_snapshot_sha256,result_revision,
			audit_event_id,created_at,completed_at)
			VALUES($1,$2,$3,$4,$5,'create',$6,$7,$8,$9,$10,$11,$12,$13,$13)`, receiptID,
			actor.ScopeID, actor.UserID, identity.InstallationID, plan.ID, request.IdempotencyKey,
			digest[:], request.RequestID, snapshot, mustDecodePlanDigest(snapshotDigest), plan.Revision,
			auditID, createdAt); err != nil {
			return err
		}
		var receiptObservedAt time.Time
		if err := tx.QueryRow(ctx, `UPDATE control_upgrade_grant_intents_096
				SET state='consumed',plan_id=$2,updated_at=date_trunc('second',clock_timestamp())
				WHERE id=$1 RETURNING updated_at`, intent.ID, plan.ID).Scan(&receiptObservedAt); err != nil {
			return err
		}
		if err := insertInitialParentGrantReceiptsTx(ctx, tx, identity, plan, receiptObservedAt); err != nil {
			return err
		}
		result.Detail = rolloutDetail(plan, identity.InstallationID, createdAt, createdAt)
		return nil
	})
	if err != nil {
		return RolloutWriteResult{}, fmt.Errorf("finalize control upgrade rollout create: %w", err)
	}
	return result, nil
}

func insertRolloutPlanTx(ctx context.Context, tx pgx.Tx, identity RolloutIdentity, plan RolloutPlan,
	binding PlanGrantBinding, snapshot []byte, snapshotDigest string, now time.Time) error {
	result, err := tx.Exec(ctx, `INSERT INTO control_upgrade_rollout_plans(
		id,actor_scope_id,actor_user_id,installation_id,schema_version,revision,state,
		resume_state,completion,active_batch,canonical_snapshot_bytes,canonical_snapshot_sha256,
		created_at,updated_at,parent_grant_id,parent_grant_bytes,parent_grant_sha256,parent_grant_expires_at,
		artifact_bundle_id,artifact_bundle_bytes,artifact_bundle_sha256,command_issuance_not_after,
		forward_profile_bytes,forward_profile_sha256,rollback_profile_bytes,rollback_profile_sha256,
		artifact_size_bytes,rollback_artifact_size_bytes)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13,$14,$15,$16,to_timestamp($17),
		$18,$19,$20,to_timestamp($21),$22,$23,$24,$25,$26,$27) ON CONFLICT (id) DO NOTHING`,
		plan.ID, identity.ActorScopeID, identity.ActorUserID, identity.InstallationID, plan.SchemaVersion,
		plan.Revision, plan.State, plan.ResumeState, plan.Completion, plan.ActiveBatch, snapshot,
		mustDecodePlanDigest(snapshotDigest), now, plan.ParentGrantID, binding.ParentGrantBytes,
		mustDecodePlanDigest(binding.ParentGrantSHA256), plan.ParentGrantExpiresAt, plan.ArtifactBundleID,
		binding.ArtifactBundleBytes, mustDecodePlanDigest(binding.ArtifactBundleSHA256),
		plan.CommandIssuanceNotAfter, binding.ForwardProfileBytes,
		mustDecodePlanDigest(binding.ForwardProfileSHA256), binding.RollbackProfileBytes,
		mustDecodePlanDigest(binding.RollbackProfileSHA256), plan.ArtifactSizeBytes, plan.RollbackArtifactSizeBytes)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrPlanIdempotencyConflict
	}
	return nil
}

func loadRolloutTargetCohortTx(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID,
	nodeIDs []string) (RolloutTargetCohort, error) {
	parsed := make([]uuid.UUID, len(nodeIDs))
	for index, nodeID := range nodeIDs {
		parsed[index] = uuid.MustParse(nodeID)
	}
	rows, err := tx.Query(ctx, `SELECT id FROM nodes
		WHERE scope_id=$1 AND id=ANY($2::uuid[]) ORDER BY id FOR SHARE`, scopeID, parsed)
	if err != nil {
		return RolloutTargetCohort{}, err
	}
	found := 0
	for rows.Next() {
		found++
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return RolloutTargetCohort{}, err
	}
	if found != len(parsed) {
		return RolloutTargetCohort{}, ErrNodeNotFound
	}
	if err := lockUpgradeSessionAuthority(ctx, tx, parsed); err != nil {
		return RolloutTargetCohort{}, err
	}
	var transactionNow time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&transactionNow); err != nil {
		return RolloutTargetCohort{}, err
	}
	rows, err = tx.Query(ctx, `SELECT node.id,presence.confirmed_agent_version,
		node_authority.selected_protocol_major,node_authority.capabilities_snapshot,node_authority.capabilities_sha256
		FROM unnest($2::uuid[]) WITH ORDINALITY AS target(node_id,ordinality)
		JOIN nodes node ON node.id=target.node_id AND node.scope_id=$1 AND node.admin_state='active'
		JOIN node_presence presence ON presence.node_id=node.id AND presence.status='online'
		  AND presence.confirmed_agent_version IS NOT NULL
		JOIN LATERAL (`+upgradeSessionAuthoritySQL+` FOR SHARE OF facts,state,artifact,auth,initial,installation NOWAIT
		) node_authority ON true ORDER BY target.ordinality FOR SHARE OF node,presence`, scopeID, parsed, transactionNow)
	if err != nil {
		return RolloutTargetCohort{}, err
	}
	facts := make([]rolloutNodeCapabilityFact, 0, len(parsed))
	for rows.Next() {
		var fact rolloutNodeCapabilityFact
		if err := rows.Scan(&fact.NodeID, &fact.PresenceVersion, &fact.ProtocolVersion,
			&fact.CapabilityBytes, &fact.CapabilitySHA256); err != nil {
			rows.Close()
			return RolloutTargetCohort{}, err
		}
		var capabilities agentv1.AgentCapabilities
		if proto.Unmarshal(fact.CapabilityBytes, &capabilities) != nil {
			rows.Close()
			return RolloutTargetCohort{}, ErrCohortIncompatible
		}
		facts = append(facts, fact)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return RolloutTargetCohort{}, err
	}
	if len(facts) != len(parsed) {
		return RolloutTargetCohort{}, ErrCohortIncompatible
	}
	return rolloutCohortFromFacts(facts)
}

func decodePlanBundle(encoded []byte) (entitlement.UpgradePlanArtifactBundle, error) {
	signed, err := entitlement.DecodeUpgradePlanArtifactBundle(encoded)
	if err != nil {
		return entitlement.UpgradePlanArtifactBundle{}, ErrGrantInvalid
	}
	return signed.Bundle, nil
}

func appendCreateRolloutDeniedAuditOnce(ctx context.Context, tx pgx.Tx, logger *audit.Log,
	actor Actor, request CreateRolloutRequest) error {
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM audit_events WHERE scope_id=$1
		AND actor_user_id=$2 AND action='control_upgrade_rollout.create' AND request_id=$3 AND result='denied')`,
		actor.ScopeID, actor.UserID, request.RequestID).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return nil
	}
	return logger.Append(ctx, tx, audit.Event{ScopeID: actor.ScopeID, ActorUserID: &actor.UserID,
		Action: "control_upgrade_rollout.create", ResourceType: "control_upgrade_rollout", ResourceID: "create",
		RequestID: request.RequestID, Result: "denied", Payload: map[string]any{"reason": "permission_denied"}})
}
