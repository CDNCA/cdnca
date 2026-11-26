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
		var requestedAt *time.Time
		err = tx.QueryRow(ctx, `
			SELECT configuration_scope_id, current_config_version_id, previous_config_version_id,
			       current_config_identity_schema, current_config_artifact_sha256,
			       previous_config_identity_schema, previous_config_artifact_sha256,
			       reconciliation_required, reconciliation_reason,
			       reconciliation_deployment_id, reconciliation_deployment_attempt, reconciliation_requested_at
			FROM node_config_state WHERE node_id = $1 AND configuration_scope_id = $2 FOR UPDATE`,
			normalized.NodeID, normalized.ConfigurationScopeID).Scan(
			&scopeID, &currentID, &previousID,
			&currentSchema, &currentDigest, &previousSchema, &previousDigest,
			&required, &reason, &sourceID, &sourceAttempt, &requestedAt)
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
		var supplementsReconciliationID *uuid.UUID
		var observedArtifactDigest []byte
		switch {
		case required:
			if reason == nil || *reason != "rollback_failed" || sourceID == nil || *sourceID != normalized.SourceDeploymentID ||
				sourceAttempt == nil || *sourceAttempt != normalized.SourceDeploymentAttempt ||
				deploymentNodeID != normalized.NodeID || deploymentState != "rollback_failed" {
				return ErrReconciliationSource
			}
			if normalized.Resolution == ReconciliationAgentObserved {
				if err := requireScopeObservation(ctx, tx, normalized, requestedAt); err != nil {
					return err
				}
			}
			if normalized.Resolution == ReconciliationOperatorConfirmed && normalized.ObservedConfigVersionID != nil {
				// the operator checked on the node
				// that it still serves the release of this very apply attempt
				// (its compensation failed, its generation kept serving). Any
				// other version is refused, and so is a source whose
				// configuration artifact can no longer be verified: that node
				// is reconciled without a version and published again.
				if deploymentAction != "apply" || deploymentConfigID != *normalized.ObservedConfigVersionID {
					return ErrReconciliationObservedNotSource
				}
				if err := requireSourceConfigurationArtifact(ctx, tx, normalized); err != nil {
					return err
				}
				recoveryMode = "rollback_failed_source_serving"
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
		case deploymentState == "rollback_failed":
			// the scope was reconciled
			// without a version (operator_confirmed, observed null) and the
			// operator has since verified on the node that the source release
			// ran there after its rollback failed. Only null -> the source's own version, once, also after
			// a later deployment of the scope (the null reconciliation lifted
			// the hold, so an automatic publication may follow at once).
			supplemented, err := requireSupplementalSourceConfirmation(ctx, tx, normalized,
				deploymentNodeID, deploymentAction, deploymentConfigID)
			if err != nil {
				return err
			}
			supplementsReconciliationID = &supplemented
			recoveryMode = "rollback_failed_source_serving_supplement"
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
		// A supplement is only the reconciliation record: the node state is
		// left as it is (by then it may already name a later deployment's
		// version). The record carries the source version into the Gateway's
		// telemetry authorization and the scope's next apply commands
		// (releasedConfigVersions).
		if supplementsReconciliationID == nil {
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
			event := audit.Event{
				ScopeID: auditScopeID, ActorUserID: auditActorUserID,
				Action: reconcileAuditAction(recoveryMode), ResourceType: "edge_node_config",
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
			}
			if attestation := operatorAttestation(recoveryMode); attestation != "" {
				event.Payload["operator_attestation"] = attestation
			}
			if supplementsReconciliationID != nil {
				event.Payload["supplements_reconciliation_id"] = supplementsReconciliationID.String()
			}
			if err := s.auditor.Append(ctx, tx, event); err != nil {
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

// operatorAttestation names what the operator confirmed, for the audit
// event ("" when the reconciliation rests on the node's report or names no
// version).
func operatorAttestation(recoveryMode string) string {
	switch recoveryMode {
	case "rollback_failed_source_serving":
		return "operator verified on the node that it still serves the source deployment's release"
	case "rollback_failed_source_serving_supplement":
		return supplementAttestation
	}
	return ""
}

// supplementAttestation is what a
// supplemental confirmation attests: the source release ran on the node
// after its rollback failed. The node may serve a later version by then; the
// supplement leaves its current version alone.
const supplementAttestation = "supplemental confirmation: after a reconciliation without a version, the operator verified on the node " +
	"that the source deployment's release ran there after its rollback failed; the node's current version is unchanged"

// reconcileAuditAction: a supplemental confirmation of the source version is
// its own audit action.
func reconcileAuditAction(recoveryMode string) string {
	if recoveryMode == "rollback_failed_source_serving_supplement" {
		return "edge_config.reconcile_supplement"
	}
	return "edge_config.reconcile"
}

// requireSupplementalSourceConfirmation
// checks that an operator_confirmed request naming a version, on a scope no
// longer waiting for reconciliation, upgrades a reconciliation of this very
// source attempt from no version to the source deployment's own version:
//   - the node and scope hold an operator_confirmed reconciliation with no
//     version of this source attempt, a rollback_failed apply on the node,
//     and no reconciliation of the same source attempt named a version since
//     (ErrReconciliationSupplementNotEligible; a second supplement of the
//     same source is refused with it, a retry of the same request replays).
//     Reconciliations of other sources (a later rollback failure of the
//     scope reconciled with its own version) do not end it;
//   - the version is the source apply's own (ErrReconciliationObservedNotSource);
//   - its configuration artifact still verifies (ErrReconciliationSourceUnverifiable).
//
// A later deployment of the scope on the node does not stand in the way: the
// null reconciliation lifted the node's hold, so a waiting automatic
// publication may have reached it at once. The supplement leaves the node
// state alone; the later deployment's version stays current.
//
// It returns the supplemented reconciliation. nodepresence
// sourceConfirmationSQL shows the same rule.
func requireSupplementalSourceConfirmation(ctx context.Context, tx pgx.Tx, request normalizedReconciliation,
	deploymentNodeID uuid.UUID, deploymentAction string, deploymentConfigID uuid.UUID,
) (uuid.UUID, error) {
	// The node state row is locked (FOR UPDATE), so two supplements of the
	// same source cannot both pass the NOT EXISTS.
	var latestID uuid.UUID
	err := tx.QueryRow(ctx, `SELECT reconciliation.id FROM node_config_reconciliations reconciliation
		WHERE reconciliation.node_id=$1 AND reconciliation.configuration_scope_id=$2
		  AND reconciliation.source_deployment_id=$3 AND reconciliation.source_deployment_attempt=$4
		  AND reconciliation.resolution='operator_confirmed' AND reconciliation.observed_config_version_id IS NULL
		  AND NOT EXISTS (SELECT 1 FROM node_config_reconciliations named
		    WHERE named.node_id=reconciliation.node_id AND named.configuration_scope_id=reconciliation.configuration_scope_id
		      AND named.source_deployment_id=reconciliation.source_deployment_id
		      AND named.source_deployment_attempt=reconciliation.source_deployment_attempt
		      AND named.observed_config_version_id IS NOT NULL)
		ORDER BY reconciliation.reconciled_at DESC, reconciliation.id LIMIT 1`,
		request.NodeID, request.ConfigurationScopeID, request.SourceDeploymentID, request.SourceDeploymentAttempt).Scan(&latestID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrReconciliationSupplementNotEligible
	}
	if err != nil {
		return uuid.Nil, fmt.Errorf("read the reconciliation to supplement: %w", err)
	}
	if deploymentNodeID != request.NodeID || deploymentAction != "apply" {
		return uuid.Nil, ErrReconciliationSupplementNotEligible
	}
	if deploymentConfigID != *request.ObservedConfigVersionID {
		return uuid.Nil, ErrReconciliationObservedNotSource
	}
	if err := requireSourceConfigurationArtifact(ctx, tx, request); err != nil {
		return uuid.Nil, err
	}
	return latestID, nil
}

// releasedTelemetryWindow is how far back nodeidentity loadTelemetrySiteScopes
// reads reconciliations into the Gateway's telemetry authorization.
const releasedTelemetryWindow = 90 * 24 * time.Hour

// maxReleasedConfigVersions bounds DeploymentCommand.released_config_version_ids
// (the Gateway and the agent refuse more).
const maxReleasedConfigVersions = 64

// releasedConfigVersions lists, sorted, the
// versions of the scope an operator_confirmed reconciliation on the node named
// as the source version of a rollback_failed apply (directly or as a
// supplemental confirmation) within the telemetry authorization window. The
// node may hold telemetry records of them; the scope's apply commands carry
// them as released_config_version_ids so the agent sends those records, which
// the Gateway's authorization accepts at their own version.
func releasedConfigVersions(ctx context.Context, tx pgx.Tx, nodeID, scopeID uuid.UUID, now time.Time) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT reconciliation.observed_config_version_id
		FROM node_config_reconciliations reconciliation
		JOIN node_deployments source ON source.id=reconciliation.source_deployment_id
		 AND source.attempt=reconciliation.source_deployment_attempt
		WHERE reconciliation.node_id=$1 AND reconciliation.configuration_scope_id=$2
		  AND reconciliation.resolution='operator_confirmed'
		  AND reconciliation.observed_config_version_id IS NOT NULL
		  AND reconciliation.reconciled_at BETWEEN $3 AND $4
		  AND source.node_id=$1 AND source.action='apply' AND source.state='rollback_failed'
		  AND source.config_version_id=reconciliation.observed_config_version_id
		ORDER BY 1 LIMIT $5`, nodeID, scopeID, now.Add(-releasedTelemetryWindow), now, maxReleasedConfigVersions)
	if err != nil {
		return nil, fmt.Errorf("read released config versions: %w", err)
	}
	defer rows.Close()
	var released []string
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("read released config versions: %w", err)
		}
		released = append(released, id.String())
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read released config versions: %w", err)
	}
	return released, nil
}

// requireSourceConfigurationArtifact: the source apply attempt has its
// configuration artifact bound, of its own version, with a stored digest
// matching the stored bytes.
func requireSourceConfigurationArtifact(ctx context.Context, tx pgx.Tx, request normalizedReconciliation) error {
	var verified bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM node_deployments source
		JOIN node_deployment_artifacts binding ON binding.deployment_id=source.id
		 AND binding.deployment_attempt=source.attempt AND binding.config_version_id=source.config_version_id
		JOIN configuration_artifacts artifact ON artifact.config_version_id=binding.config_version_id
		 AND artifact.id=binding.artifact_id AND artifact.kind='configuration'
		JOIN config_versions version ON version.id=source.config_version_id AND version.configuration_scope_id=$4
		WHERE source.id=$1 AND source.attempt=$2 AND source.node_id=$3 AND source.action='apply'
		  AND artifact.sha256=sha256(artifact.wire_bytes))`,
		request.SourceDeploymentID, request.SourceDeploymentAttempt, request.NodeID, request.ConfigurationScopeID).Scan(&verified); err != nil {
		return fmt.Errorf("verify reconciliation source artifact: %w", err)
	}
	if !verified {
		return ErrReconciliationSourceUnverifiable
	}
	return nil
}

// requireScopeObservation: an agent_observed
// reconciliation of a rollback failure names what the node reported for the
// scope: its own scoped identity, reported after the failure on the node's
// current online session, matching the observed version, and not
// contradicting itself (the agent still naming the source rollback_failed,
// or no configuration while OpenResty runs). Without such a report only an
// operator_confirmed reconciliation applies. nodepresence
// ScopeReconciliation shows the same rule.
//
// the agent naming the source rollback_failed
// is consistent when the current it reports is the source deployment's own
// version and configuration artifact (a compensation that failed while the
// generation kept serving).
func requireScopeObservation(ctx context.Context, tx pgx.Tx, request normalizedReconciliation, requestedAt *time.Time) error {
	if requestedAt == nil {
		return ErrReconciliationSource
	}
	var observed bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM node_presence_scope_identities identity
		JOIN node_presence presence ON presence.node_id = identity.node_id
		WHERE identity.node_id = $1 AND identity.configuration_scope_id = $2
		  AND identity.updated_at > $3 AND presence.status = 'online'
		  AND identity.session_epoch = presence.session_epoch
		  AND identity.current_config_version_id IS NOT DISTINCT FROM $4
		  AND NOT (identity.last_apply_deployment_id IS NOT DISTINCT FROM $5
		       AND identity.last_apply_attempt IS NOT DISTINCT FROM $6
		       AND identity.last_apply_state = 'rollback_failed'
		       AND NOT EXISTS (SELECT 1 FROM node_deployments source
		         JOIN node_deployment_artifacts binding ON binding.deployment_id=source.id
		          AND binding.deployment_attempt=source.attempt AND binding.config_version_id=source.config_version_id
		         JOIN configuration_artifacts artifact ON artifact.config_version_id=binding.config_version_id
		          AND artifact.id=binding.artifact_id AND artifact.kind='configuration'
		         WHERE source.id=$5 AND source.attempt=$6 AND source.node_id=$1 AND source.action='apply'
		           AND source.config_version_id=identity.current_config_version_id
		           AND artifact.sha256=identity.current_config_artifact_sha256 AND artifact.sha256=sha256(artifact.wire_bytes)))
		  AND NOT (identity.current_config_version_id IS NULL AND presence.openresty_state = 'running'))`,
		request.NodeID, request.ConfigurationScopeID, *requestedAt, request.ObservedConfigVersionID,
		request.SourceDeploymentID, request.SourceDeploymentAttempt).Scan(&observed); err != nil {
		return fmt.Errorf("read reconciliation scope observation: %w", err)
	}
	if !observed {
		return ErrReconciliationSource
	}
	return nil
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
