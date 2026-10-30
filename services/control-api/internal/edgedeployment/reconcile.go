package edgedeployment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type normalizedReconciliation struct {
	ReconcileNodeConfigRequest
	digest [sha256.Size]byte
}

func (s *Store) ReconcileNodeConfig(ctx context.Context, request ReconcileNodeConfigRequest) (ReconcileNodeConfigResult, error) {
	return s.reconcileNodeConfig(ctx, request, nil)
}

func (s *Store) reconcileNodeConfig(
	ctx context.Context,
	request ReconcileNodeConfigRequest,
	commandContext *normalizedReconcileNodeConfigCommand,
) (ReconcileNodeConfigResult, error) {
	if ctx == nil {
		return ReconcileNodeConfigResult{}, fmt.Errorf("%w: reconciliation context", ErrInvalidInput)
	}
	normalized, err := normalizeReconciliation(request)
	if err != nil {
		return ReconcileNodeConfigResult{}, err
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	var result ReconcileNodeConfigResult
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var auditScopeID uuid.UUID
		var auditActorUserID *uuid.UUID
		if commandContext != nil {
			authorization, authorizeErr := s.authorizeSession(
				ctx, tx, commandContext.Actor, normalized.ConfigurationScopeID, PermissionManage,
			)
			if authorizeErr != nil {
				return authorizeErr
			}
			actorUserID := authorization.UserID()
			auditScopeID = authorization.AuthenticationScopeID()
			auditActorUserID = &actorUserID
		}
		existing, found, err := loadReconciliationByRequest(ctx, tx, normalized.RequestID, normalized.digest)
		if err != nil {
			return err
		}
		if found {
			result = ReconcileNodeConfigResult{Reconciliation: existing, Replayed: true}
			return nil
		}

		var scopeID *uuid.UUID
		var currentID, previousID *uuid.UUID
		var currentSchema, previousSchema *int32
		var currentDigest, previousDigest []byte
		var required bool
		var reason *string
		var sourceID *uuid.UUID
		var sourceAttempt *int32
		err = tx.QueryRow(ctx, `
			SELECT configuration_scope_id, current_config_version_id, previous_config_version_id,
			       current_config_identity_schema, current_config_artifact_sha256,
			       previous_config_identity_schema, previous_config_artifact_sha256,
			       reconciliation_required, reconciliation_reason,
			       reconciliation_deployment_id, reconciliation_deployment_attempt
			FROM node_config_state WHERE node_id = $1 AND configuration_scope_id = $2 FOR UPDATE`,
			normalized.NodeID, normalized.ConfigurationScopeID).Scan(
			&scopeID, &currentID, &previousID,
			&currentSchema, &currentDigest, &previousSchema, &previousDigest,
			&required, &reason, &sourceID, &sourceAttempt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrReconciliationNotRequired
		}
		if err != nil {
			return fmt.Errorf("lock node reconciliation state: %w", err)
		}

		// A concurrent identical request can commit while this transaction waits
		// for the node row. Recheck after acquiring the serialization lock.
		existing, found, err = loadReconciliationByRequest(ctx, tx, normalized.RequestID, normalized.digest)
		if err != nil {
			return err
		}
		if found {
			result = ReconcileNodeConfigResult{Reconciliation: existing, Replayed: true}
			return nil
		}
		if !required && (normalized.Resolution != ReconciliationOperatorConfirmed || normalized.ObservedConfigVersionID == nil) {
			return ErrReconciliationNotRequired
		}
		if scopeID == nil || *scopeID != normalized.ConfigurationScopeID {
			return ErrReconciliationSource
		}
		var deploymentNodeID, deploymentConfigID uuid.UUID
		var deploymentPreviousID *uuid.UUID
		var deploymentAction, deploymentState string
		var deploymentUpdatedAt time.Time
		err = tx.QueryRow(ctx, `
			SELECT node_id, config_version_id, previous_config_version_id, action, state, updated_at
			FROM node_deployments WHERE id = $1 AND attempt = $2`, normalized.SourceDeploymentID, normalized.SourceDeploymentAttempt).Scan(
			&deploymentNodeID, &deploymentConfigID, &deploymentPreviousID,
			&deploymentAction, &deploymentState, &deploymentUpdatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrReconciliationSource
		}
		if err != nil {
			return fmt.Errorf("read reconciliation deployment: %w", err)
		}
		recoveryMode := "rollback_failed"
		var observedArtifactDigest []byte
		switch {
		case required:
			if reason == nil || *reason != "rollback_failed" || sourceID == nil || *sourceID != normalized.SourceDeploymentID ||
				sourceAttempt == nil || *sourceAttempt != normalized.SourceDeploymentAttempt ||
				deploymentNodeID != normalized.NodeID || deploymentState != "rollback_failed" {
				return ErrReconciliationSource
			}
		case deploymentNodeID == normalized.NodeID && deploymentAction == "apply" && deploymentState == "failed" &&
			normalized.ObservedConfigVersionID != nil && deploymentConfigID == *normalized.ObservedConfigVersionID &&
			sameReconciliationUUID(currentID, deploymentPreviousID) && currentSchema != nil && *currentSchema == 1 && len(currentDigest) == sha256.Size:
			var presenceStatus, openRestyState string
			var presenceCurrentID, presencePreviousID, presenceLoadedID *uuid.UUID
			var identityAPIVersion, presenceCurrentSchema, presencePreviousSchema, presenceLoadedSchema *int32
			var presenceCurrentDigest, presencePreviousDigest, presenceLoadedDigest []byte
			var presenceOccurredAt time.Time
			err = tx.QueryRow(ctx, `
				SELECT status, current_config_version_id, previous_config_version_id, loaded_config_version_id,
				       openresty_state, active_config_identity_api_version,
				       current_config_identity_schema, current_config_artifact_sha256,
				       previous_config_identity_schema, previous_config_artifact_sha256,
				       loaded_config_identity_schema, loaded_config_artifact_sha256, projected_at
				FROM node_presence WHERE node_id = $1`, normalized.NodeID).Scan(
				&presenceStatus, &presenceCurrentID, &presencePreviousID, &presenceLoadedID,
				&openRestyState, &identityAPIVersion,
				&presenceCurrentSchema, &presenceCurrentDigest,
				&presencePreviousSchema, &presencePreviousDigest,
				&presenceLoadedSchema, &presenceLoadedDigest, &presenceOccurredAt)
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrReconciliationSource
			}
			if err != nil {
				return fmt.Errorf("read failed apply reconciliation observation: %w", err)
			}
			var activeDeployment bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(
				SELECT 1 FROM node_deployments
				WHERE node_id = $1 AND state NOT IN ('healthy', 'failed', 'reverted', 'rollback_failed')
			)`, normalized.NodeID).Scan(&activeDeployment); err != nil {
				return fmt.Errorf("read failed apply reconciliation activity: %w", err)
			}
			if presenceStatus != "online" || openRestyState != "stopped" || activeDeployment ||
				identityAPIVersion == nil || *identityAPIVersion != 1 ||
				!sameReconciliationUUID(presenceCurrentID, normalized.ObservedConfigVersionID) ||
				!sameReconciliationUUID(presencePreviousID, currentID) || presenceLoadedID != nil ||
				presenceCurrentSchema != nil || len(presenceCurrentDigest) != 0 ||
				presencePreviousSchema == nil || *presencePreviousSchema != 1 ||
				!bytes.Equal(presencePreviousDigest, currentDigest) ||
				presenceLoadedSchema != nil || len(presenceLoadedDigest) != 0 ||
				// Both controller clock: the heartbeat's own time is the
				// node's and may trail the failure it reports on.
				presenceOccurredAt.Before(deploymentUpdatedAt) {
				return ErrReconciliationSource
			}
			err = tx.QueryRow(ctx, `
				SELECT artifact.sha256
				FROM node_deployment_artifacts binding
				JOIN configuration_artifacts artifact
				  ON artifact.config_version_id = binding.config_version_id
				 AND artifact.id = binding.artifact_id
				WHERE binding.deployment_id = $1 AND binding.deployment_attempt = $2
				  AND binding.config_version_id = $3 AND artifact.kind = 'configuration'
				  AND artifact.sha256 = sha256(artifact.wire_bytes)`,
				normalized.SourceDeploymentID, normalized.SourceDeploymentAttempt, deploymentConfigID).Scan(
				&observedArtifactDigest)
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrReconciliationSource
			}
			if err != nil {
				return fmt.Errorf("read failed apply reconciliation artifact: %w", err)
			}
			recoveryMode = "failed_apply_identity_loss"
		default:
			return ErrReconciliationSource
		}
		if normalized.ObservedConfigVersionID != nil {
			var status string
			err := tx.QueryRow(ctx, `
				SELECT status FROM config_versions
				WHERE configuration_scope_id = $1 AND id = $2`,
				normalized.ConfigurationScopeID, *normalized.ObservedConfigVersionID).Scan(&status)
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrConfigNotFound
			}
			if err != nil {
				return fmt.Errorf("read observed config version: %w", err)
			}
			if status != "releasable" && status != "superseded" && status != "revoked" {
				return ErrConfigNotReleasable
			}
		}

		reconciliationID := uuid.New()
		_, err = tx.Exec(ctx, `
			INSERT INTO node_config_reconciliations (
				id, request_id, request_digest, node_id, configuration_scope_id,
				source_deployment_id, source_deployment_attempt,
				previous_config_version_id, observed_config_version_id,
				resolution, evidence, reconciled_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
			reconciliationID, normalized.RequestID, normalized.digest[:], normalized.NodeID,
			normalized.ConfigurationScopeID, normalized.SourceDeploymentID,
			normalized.SourceDeploymentAttempt, currentID, normalized.ObservedConfigVersionID,
			string(normalized.Resolution), normalized.Evidence, now)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return ErrIdempotencyConflict
			}
			return fmt.Errorf("append node config reconciliation: %w", err)
		}
		nextPreviousID := previousID
		nextPreviousSchema, nextPreviousDigest := previousSchema, previousDigest
		var nextCurrentSchema *int32
		var nextCurrentDigest []byte
		if !sameReconciliationUUID(currentID, normalized.ObservedConfigVersionID) {
			nextPreviousID = currentID
			nextPreviousSchema, nextPreviousDigest = currentSchema, currentDigest
		}
		switch {
		case recoveryMode == "failed_apply_identity_loss":
			// The heartbeat proves the runtime pointer chain, while the legacy failed
			// deployment cannot prove an immutable active identity. A later healthy
			// publication establishes the observed config identity normally.
		case sameReconciliationUUID(currentID, normalized.ObservedConfigVersionID) && currentSchema != nil:
			nextCurrentSchema, nextCurrentDigest = currentSchema, currentDigest
		case sameReconciliationUUID(previousID, normalized.ObservedConfigVersionID) && previousSchema != nil:
			nextCurrentSchema, nextCurrentDigest = previousSchema, previousDigest
		}
		command, err := tx.Exec(ctx, `
				UPDATE node_config_state
				SET previous_config_version_id = $3,
				    current_config_version_id = $2,
				    current_config_identity_schema = $4,
				    current_config_artifact_sha256 = $5,
				    previous_config_identity_schema = $6,
				    previous_config_artifact_sha256 = $7,
				    reconciliation_required = false,
			    reconciliation_reason = NULL,
			    reconciliation_deployment_id = NULL,
			    reconciliation_deployment_attempt = NULL,
			    reconciliation_requested_at = NULL,
			    revision = revision + 1,
				    updated_at = GREATEST(updated_at, $8)
				WHERE node_id = $1 AND configuration_scope_id = $10 AND reconciliation_required = $9`, normalized.NodeID,
			normalized.ObservedConfigVersionID, nextPreviousID,
			nextCurrentSchema, nextCurrentDigest, nextPreviousSchema, nextPreviousDigest, now, required,
			normalized.ConfigurationScopeID)
		if err != nil {
			return fmt.Errorf("complete node config reconciliation: %w", err)
		}
		if command.RowsAffected() != 1 {
			return ErrReconciliationNotRequired
		}
		result.Reconciliation = NodeConfigReconciliation{
			ID: reconciliationID, RequestID: normalized.RequestID, NodeID: normalized.NodeID,
			ConfigurationScopeID:    normalized.ConfigurationScopeID,
			SourceDeploymentID:      normalized.SourceDeploymentID,
			SourceDeploymentAttempt: normalized.SourceDeploymentAttempt,
			PreviousConfigVersionID: cloneUUID(currentID),
			ObservedConfigVersionID: cloneUUID(normalized.ObservedConfigVersionID),
			Resolution:              normalized.Resolution, ReconciledAt: now,
		}
		if commandContext != nil {
			if err := s.auditor.Append(ctx, tx, audit.Event{
				ScopeID: auditScopeID, ActorUserID: auditActorUserID,
				Action: "edge_config.reconcile", ResourceType: "edge_node_config",
				ResourceID: normalized.NodeID.String(), RequestID: commandContext.RequestID, Result: "success",
				Payload: map[string]any{
					"idempotency_key":            commandContext.IdempotencyKey,
					"correlation_id":             commandContext.CorrelationID,
					"traceparent":                commandContext.Traceparent,
					"task_id":                    cloneString(commandContext.TaskID),
					"actor_session_id":           commandContext.Actor.SessionID.String(),
					"configuration_scope_id":     normalized.ConfigurationScopeID.String(),
					"source_deployment_id":       normalized.SourceDeploymentID.String(),
					"source_deployment_attempt":  normalized.SourceDeploymentAttempt,
					"observed_config_version_id": normalized.ObservedConfigVersionID,
					"resolution":                 normalized.Resolution,
					"recovery_mode":              recoveryMode,
					"reconciliation_id":          reconciliationID.String(),
				},
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return ReconcileNodeConfigResult{}, fmt.Errorf("reconcile node running config: %w", err)
	}
	return result, nil
}

func sameReconciliationUUID(left, right *uuid.UUID) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func normalizeReconciliation(request ReconcileNodeConfigRequest) (normalizedReconciliation, error) {
	request.Evidence = strings.TrimSpace(request.Evidence)
	if request.RequestID == uuid.Nil || request.NodeID == uuid.Nil || request.ConfigurationScopeID == uuid.Nil ||
		request.SourceDeploymentID == uuid.Nil || request.SourceDeploymentAttempt <= 0 ||
		(request.ObservedConfigVersionID != nil && *request.ObservedConfigVersionID == uuid.Nil) ||
		(request.Resolution != ReconciliationAgentObserved && request.Resolution != ReconciliationOperatorConfirmed) ||
		request.Evidence == "" || len(request.Evidence) > 512 || !utf8.ValidString(request.Evidence) {
		return normalizedReconciliation{}, fmt.Errorf("%w: reconciliation request", ErrInvalidInput)
	}
	observed := ""
	if request.ObservedConfigVersionID != nil {
		observed = request.ObservedConfigVersionID.String()
	}
	encoded, err := json.Marshal(struct {
		NodeID                  string `json:"node_id"`
		ConfigurationScopeID    string `json:"configuration_scope_id"`
		SourceDeploymentID      string `json:"source_deployment_id"`
		SourceDeploymentAttempt int32  `json:"source_deployment_attempt"`
		ObservedConfigVersionID string `json:"observed_config_version_id"`
		Resolution              string `json:"resolution"`
		Evidence                string `json:"evidence"`
	}{request.NodeID.String(), request.ConfigurationScopeID.String(), request.SourceDeploymentID.String(),
		request.SourceDeploymentAttempt, observed, string(request.Resolution), request.Evidence})
	if err != nil {
		return normalizedReconciliation{}, fmt.Errorf("%w: reconciliation digest", ErrInvalidInput)
	}
	return normalizedReconciliation{ReconcileNodeConfigRequest: request, digest: sha256.Sum256(encoded)}, nil
}

func loadReconciliationByRequest(ctx context.Context, tx pgx.Tx, requestID uuid.UUID, digest [sha256.Size]byte) (NodeConfigReconciliation, bool, error) {
	var item NodeConfigReconciliation
	var persistedDigest []byte
	var resolution string
	err := tx.QueryRow(ctx, `
		SELECT id, request_id, request_digest, node_id, configuration_scope_id,
		       source_deployment_id, source_deployment_attempt,
		       previous_config_version_id, observed_config_version_id,
		       resolution, reconciled_at
		FROM node_config_reconciliations WHERE request_id = $1`, requestID).Scan(
		&item.ID, &item.RequestID, &persistedDigest, &item.NodeID, &item.ConfigurationScopeID,
		&item.SourceDeploymentID, &item.SourceDeploymentAttempt,
		&item.PreviousConfigVersionID, &item.ObservedConfigVersionID,
		&resolution, &item.ReconciledAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return NodeConfigReconciliation{}, false, nil
	}
	if err != nil {
		return NodeConfigReconciliation{}, false, fmt.Errorf("read idempotent node config reconciliation: %w", err)
	}
	if !bytes.Equal(persistedDigest, digest[:]) {
		return NodeConfigReconciliation{}, false, ErrIdempotencyConflict
	}
	item.Resolution = ReconciliationResolution(resolution)
	return item, true, nil
}

func cloneUUID(value *uuid.UUID) *uuid.UUID {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
