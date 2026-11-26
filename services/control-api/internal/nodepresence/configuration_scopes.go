package nodepresence

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/node"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// maxScopeRejections bounds the refused publications shown per node.
const maxScopeRejections = 20

// NodeConfigurationScopes is what an administrator sees of the tenants a
// node serves (docs/architecture/multi-tenant-node-sharing.md 6.2.1): each
// configuration scope's state, its latest deployment and the agent's last
// apply result, plus publications refused for conflicting with them.
type NodeConfigurationScopes struct {
	NodeID     uuid.UUID            `json:"node_id"`
	Scopes     []ConfigurationScope `json:"scopes"`
	Rejections []ScopeRejection     `json:"rejections"`
	// CapabilityRegressions are features the node's latest healthy
	// deployments use that its agent no longer declares (an agent rollback).
	CapabilityRegressions []CapabilityRegression `json:"capability_regressions"`
}

type ConfigurationScope struct {
	ScopeID                 uuid.UUID         `json:"scope_id"`
	ScopeKind               string            `json:"scope_kind"`
	TenantID                *uuid.UUID        `json:"tenant_id"`
	TenantName              string            `json:"tenant_name"`
	CurrentConfigVersionID  *uuid.UUID        `json:"current_config_version_id"`
	PreviousConfigVersionID *uuid.UUID        `json:"previous_config_version_id"`
	ReconciliationRequired  bool              `json:"reconciliation_required"`
	UpdatedAt               time.Time         `json:"updated_at"`
	LatestDeployment        *ScopeDeployment  `json:"latest_deployment"`
	LastApply               *ScopeApplyResult `json:"last_apply"`
	// Reconciliation is set while ReconciliationRequired: what the
	// reconciliation (POST /v1/admin/site-rollouts/reconciliations) names.
	Reconciliation *ScopeReconciliation `json:"reconciliation"`
	// SourceConfirmation is set when the scope may still be confirmed as
	// serving its source release: what
	// a supplemental operator_confirmed reconciliation names.
	SourceConfirmation *ScopeSourceConfirmation `json:"source_confirmation"`
	// TelemetryExcluded is why the node's authorization leaves this scope's
	// telemetry out (nodeidentity.TelemetryExclusion*), empty when it is in
	// or when the Inventory has no TelemetryExclusionReader. Only a node
	// serving several scopes isolates a scope this way.
	TelemetryExcluded string `json:"telemetry_excluded"`
}

type ScopeDeployment struct {
	DeploymentID    uuid.UUID `json:"deployment_id"`
	Attempt         int32     `json:"attempt"`
	RolloutID       uuid.UUID `json:"rollout_id"`
	ConfigVersionID uuid.UUID `json:"config_version_id"`
	Action          string    `json:"action"`
	// State is the control plane's view: queued, delivered, agent_queued,
	// started, staged, ..., healthy, failed, ...
	State     string    `json:"state"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ScopeReconciliation is why a scope waits for reconciliation
// (a first generation whose rollback failed left
// every later publication in retry_wait): the deployment that left the
// node's running state unknown, and what the node reported for the scope.
//
// the report is confirmed only when it is the
// scope's own (scoped identity, not the node-wide heartbeat), arrived after
// the failure on the node's current online session, and does not contradict
// itself: the agent still naming the source deployment rollback_failed, or
// no configuration while OpenResty reports running (served
// generation 1 with an empty journal). Otherwise Observation is unconfirmed
// with the reason and no version is offered (edgedeployment checks the same
// rule before an agent_observed reconciliation).
//
// an agent whose compensation failed while the
// generation kept serving reports that release as the scope's current one
// next to the rollback_failed result. That report is consistent when its
// version and artifact digest are the source deployment's own (sourceServing):
// the node says it runs exactly what the failed deployment delivered.
type ScopeReconciliation struct {
	Reason                  string     `json:"reason"`
	SourceDeploymentID      uuid.UUID  `json:"source_deployment_id"`
	SourceDeploymentAttempt int32      `json:"source_deployment_attempt"`
	Observation             string     `json:"observation"`        // confirmed | unconfirmed
	UnconfirmedReason       *string    `json:"unconfirmed_reason"` // no_scope_report | stale_report | contradicting_report
	ReportedConfigVersionID *uuid.UUID `json:"reported_config_version_id"`
	ReportedAt              *time.Time `json:"reported_at"`
}

// scopeObservation applies the ScopeReconciliation rule.
func scopeObservation(reconciliation *ScopeReconciliation, requestedAt *time.Time, scoped bool, current *uuid.UUID,
	reportedAt *time.Time, identityEpoch, presenceEpoch *int64, presenceStatus, openResty *string,
	applyID *uuid.UUID, applyAttempt *int32, applyState *string, sourceServing bool) {
	unconfirmed := func(reason string) {
		reconciliation.Observation, reconciliation.UnconfirmedReason = "unconfirmed", &reason
	}
	switch {
	case !scoped:
		unconfirmed("no_scope_report")
	case requestedAt == nil || reportedAt == nil || !reportedAt.After(*requestedAt) ||
		presenceStatus == nil || *presenceStatus != "online" ||
		identityEpoch == nil || presenceEpoch == nil || *identityEpoch != *presenceEpoch:
		unconfirmed("stale_report")
	case applyID != nil && *applyID == reconciliation.SourceDeploymentID && applyAttempt != nil &&
		*applyAttempt == reconciliation.SourceDeploymentAttempt && applyState != nil && *applyState == "rollback_failed" &&
		(current == nil || !sourceServing),
		current == nil && openResty != nil && *openResty == "running":
		unconfirmed("contradicting_report")
	default:
		reconciliation.Observation, reconciliation.ReportedConfigVersionID, reconciliation.ReportedAt = "confirmed", current, reportedAt
	}
}

// sourceServingSQL (columns of node_config_state state and
// node_presence_scope_identities identity): the scope's reported current
// version and artifact digest are those of its reconciliation's source
// deployment on this node (an apply, with a configuration artifact bound to
// it whose stored digest matches its bytes). edgedeployment's
// requireScopeObservation applies the same condition.
const sourceServingSQL = `EXISTS (SELECT 1 FROM node_deployments source
		JOIN node_deployment_artifacts binding ON binding.deployment_id=source.id
		 AND binding.deployment_attempt=source.attempt AND binding.config_version_id=source.config_version_id
		JOIN configuration_artifacts artifact ON artifact.config_version_id=binding.config_version_id
		 AND artifact.id=binding.artifact_id AND artifact.kind='configuration'
		WHERE source.id=state.reconciliation_deployment_id AND source.attempt=state.reconciliation_deployment_attempt
		  AND source.node_id=state.node_id AND source.action='apply'
		  AND source.config_version_id=identity.current_config_version_id
		  AND artifact.sha256=identity.current_config_artifact_sha256 AND artifact.sha256=sha256(artifact.wire_bytes))`

// ScopeSourceConfirmation: a
// reconciliation of the scope on this node was operator_confirmed without a
// version while its source was a rollback_failed apply on the node, no
// reconciliation of that source attempt has named a version since, and the
// source's configuration artifact verifies. A later deployment of the scope
// or a reconciliation of another source does not end it. With several such
// sources the oldest is shown; once it is supplemented the next one follows.
// A held version of that release on the node waits for the supplemental
// confirmation of ConfigVersionID (POST
// /v1/admin/site-rollouts/reconciliations, operator_confirmed) and the
// scope's next apply command, which lists it as released. edgedeployment
// requireSupplementalSourceConfirmation applies the same rule.
type ScopeSourceConfirmation struct {
	SourceDeploymentID      uuid.UUID `json:"source_deployment_id"`
	SourceDeploymentAttempt int32     `json:"source_deployment_attempt"`
	ConfigVersionID         uuid.UUID `json:"config_version_id"`
	ReconciledAt            time.Time `json:"reconciled_at"`
}

// sourceConfirmationSQL is the lateral join of ScopeSourceConfirmation for
// node_config_state state.
const sourceConfirmationSQL = `LEFT JOIN LATERAL (
					SELECT pending.source_deployment_id, pending.source_deployment_attempt, source.config_version_id, pending.reconciled_at
					FROM node_config_reconciliations pending
					JOIN node_deployments source ON source.id=pending.source_deployment_id AND source.attempt=pending.source_deployment_attempt
					JOIN node_deployment_artifacts binding ON binding.deployment_id=source.id
					 AND binding.deployment_attempt=source.attempt AND binding.config_version_id=source.config_version_id
					JOIN configuration_artifacts artifact ON artifact.config_version_id=binding.config_version_id
					 AND artifact.id=binding.artifact_id AND artifact.kind='configuration'
					JOIN config_versions version ON version.id=source.config_version_id
					 AND version.configuration_scope_id=state.configuration_scope_id
					WHERE pending.node_id=state.node_id AND pending.configuration_scope_id=state.configuration_scope_id
					  AND NOT state.reconciliation_required
					  AND pending.resolution='operator_confirmed' AND pending.observed_config_version_id IS NULL
					  AND NOT EXISTS (SELECT 1 FROM node_config_reconciliations named
					    WHERE named.node_id=pending.node_id AND named.configuration_scope_id=pending.configuration_scope_id
					      AND named.source_deployment_id=pending.source_deployment_id
					      AND named.source_deployment_attempt=pending.source_deployment_attempt
					      AND named.observed_config_version_id IS NOT NULL)
					  AND source.node_id=state.node_id AND source.action='apply' AND source.state='rollback_failed'
					  AND artifact.sha256=sha256(artifact.wire_bytes)
					  AND version.status IN ('releasable','superseded','revoked')
					ORDER BY pending.reconciled_at, pending.id
					LIMIT 1
				) confirmation ON true`

// ScopeApplyResult is the agent's last apply of the scope as reported in its
// heartbeat; superseded only ever appears here.
type ScopeApplyResult struct {
	DeploymentID    uuid.UUID  `json:"deployment_id"`
	Attempt         int32      `json:"attempt"`
	ConfigVersionID uuid.UUID  `json:"config_version_id"`
	State           string     `json:"state"`
	ErrorCode       *string    `json:"error_code"`
	FinishedAt      *time.Time `json:"finished_at"`
	ReportedAt      time.Time  `json:"reported_at"`
}

type ScopeRejection struct {
	ScopeID    uuid.UUID `json:"scope_id"`
	TenantName string    `json:"tenant_name"`
	Reason     string    `json:"reason"`
	RequestID  string    `json:"request_id"`
	OccurredAt time.Time `json:"occurred_at"`
}

// ConfigurationScopes reads a node of the caller's scope. It is read-only.
func (i *Inventory) ConfigurationScopes(ctx context.Context, scopeID, nodeID uuid.UUID) (NodeConfigurationScopes, error) {
	result := NodeConfigurationScopes{NodeID: nodeID, Scopes: []ConfigurationScope{}, Rejections: []ScopeRejection{},
		CapabilityRegressions: []CapabilityRegression{}}
	err := pgx.BeginTxFunc(ctx, i.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly},
		func(tx pgx.Tx) error {
			var found bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM nodes WHERE scope_id=$1 AND id=$2)`,
				scopeID, nodeID).Scan(&found); err != nil {
				return err
			}
			if !found {
				return node.ErrNotFound
			}
			rows, err := tx.Query(ctx, `SELECT state.configuration_scope_id, scope.kind, scope.tenant_id,
					COALESCE(tenant.display_name,''), state.current_config_version_id, state.previous_config_version_id,
					state.reconciliation_required, state.updated_at,
					deployment.id, deployment.attempt, deployment.rollout_id, deployment.config_version_id,
					deployment.action, deployment.state, deployment.updated_at,
					identity.last_apply_deployment_id, identity.last_apply_attempt, identity.last_apply_config_version_id,
					identity.last_apply_state, identity.last_apply_error_code, identity.last_apply_finished_at,
					identity.updated_at,
					state.reconciliation_reason, state.reconciliation_deployment_id, state.reconciliation_deployment_attempt,
					state.reconciliation_requested_at, identity.node_id IS NOT NULL, identity.current_config_version_id,
					identity.session_epoch, presence.status, presence.session_epoch, presence.openresty_state,
					`+sourceServingSQL+`,
					confirmation.source_deployment_id, confirmation.source_deployment_attempt,
					confirmation.config_version_id, confirmation.reconciled_at
				FROM node_config_state state
				JOIN access_scopes scope ON scope.id=state.configuration_scope_id
				LEFT JOIN tenants tenant ON tenant.id=scope.tenant_id
				LEFT JOIN LATERAL (
					SELECT id, attempt, rollout_id, config_version_id, action, state, updated_at
					FROM node_deployments
					WHERE node_id=state.node_id AND configuration_scope_id=state.configuration_scope_id
					ORDER BY created_at DESC, attempt DESC LIMIT 1
				) deployment ON true
				LEFT JOIN node_presence_scope_identities identity
				  ON identity.node_id=state.node_id AND identity.configuration_scope_id=state.configuration_scope_id
				LEFT JOIN node_presence presence ON presence.node_id=state.node_id
				`+sourceConfirmationSQL+`
				WHERE state.node_id=$1
				ORDER BY COALESCE(tenant.display_name,''), state.configuration_scope_id`, nodeID)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var item ConfigurationScope
				var deploymentID, rolloutID, deploymentConfig *uuid.UUID
				var deploymentAttempt *int32
				var deploymentAction, deploymentState *string
				var deploymentUpdated *time.Time
				var applyID, applyConfig *uuid.UUID
				var applyAttempt *int32
				var applyState *string
				var applyError *string
				var applyFinished, reportedAt *time.Time
				var reconcileReason, presenceStatus, openResty *string
				var reconcileID, reportedConfig *uuid.UUID
				var reconcileAttempt *int32
				var requestedAt *time.Time
				var scoped bool
				var identityEpoch, presenceEpoch *int64
				var sourceServing bool
				var confirmationSource, confirmationVersion *uuid.UUID
				var confirmationAttempt *int32
				var confirmationAt *time.Time
				if err := rows.Scan(&item.ScopeID, &item.ScopeKind, &item.TenantID, &item.TenantName,
					&item.CurrentConfigVersionID, &item.PreviousConfigVersionID, &item.ReconciliationRequired, &item.UpdatedAt,
					&deploymentID, &deploymentAttempt, &rolloutID, &deploymentConfig, &deploymentAction, &deploymentState,
					&deploymentUpdated, &applyID, &applyAttempt, &applyConfig, &applyState, &applyError, &applyFinished,
					&reportedAt, &reconcileReason, &reconcileID, &reconcileAttempt, &requestedAt, &scoped, &reportedConfig,
					&identityEpoch, &presenceStatus, &presenceEpoch, &openResty, &sourceServing,
					&confirmationSource, &confirmationAttempt, &confirmationVersion, &confirmationAt); err != nil {
					return err
				}
				if deploymentID != nil {
					item.LatestDeployment = &ScopeDeployment{DeploymentID: *deploymentID, Attempt: *deploymentAttempt,
						RolloutID: *rolloutID, ConfigVersionID: *deploymentConfig, Action: *deploymentAction,
						State: *deploymentState, UpdatedAt: *deploymentUpdated}
				}
				if applyID != nil {
					item.LastApply = &ScopeApplyResult{DeploymentID: *applyID, Attempt: *applyAttempt,
						ConfigVersionID: *applyConfig, State: *applyState, ErrorCode: applyError,
						FinishedAt: applyFinished, ReportedAt: *reportedAt}
				}
				if item.ReconciliationRequired && reconcileReason != nil && reconcileID != nil && reconcileAttempt != nil {
					item.Reconciliation = &ScopeReconciliation{Reason: *reconcileReason, SourceDeploymentID: *reconcileID,
						SourceDeploymentAttempt: *reconcileAttempt}
					scopeObservation(item.Reconciliation, requestedAt, scoped, reportedConfig, reportedAt, identityEpoch,
						presenceEpoch, presenceStatus, openResty, applyID, applyAttempt, applyState, sourceServing)
				}
				if confirmationSource != nil && confirmationAttempt != nil && confirmationVersion != nil && confirmationAt != nil {
					item.SourceConfirmation = &ScopeSourceConfirmation{SourceDeploymentID: *confirmationSource,
						SourceDeploymentAttempt: *confirmationAttempt, ConfigVersionID: *confirmationVersion, ReconciledAt: *confirmationAt}
				}
				result.Scopes = append(result.Scopes, item)
			}
			if err := rows.Err(); err != nil {
				return err
			}
			rows.Close()
			if i.exclusions != nil {
				excluded, err := i.exclusions(ctx, tx, nodeID, i.now())
				if err != nil {
					return err
				}
				for index := range result.Scopes {
					result.Scopes[index].TelemetryExcluded = excluded[result.Scopes[index].ScopeID]
				}
			}
			// Indexed by audit_events_node_scope_conflict_292_idx.
			rejections, err := tx.Query(ctx, `SELECT event.scope_id, COALESCE(tenant.display_name,''),
					event.payload, event.request_id, event.occurred_at
				FROM audit_events event
				JOIN access_scopes scope ON scope.id=event.scope_id
				LEFT JOIN tenants tenant ON tenant.id=scope.tenant_id
				WHERE event.action='edge_publication.node_scope_conflict' AND event.resource_type='node'
				  AND event.resource_id=$1
				ORDER BY event.occurred_at DESC, event.id DESC LIMIT $2`, nodeID.String(), maxScopeRejections)
			if err != nil {
				return err
			}
			defer rejections.Close()
			for rejections.Next() {
				var item ScopeRejection
				var payload []byte
				if err := rejections.Scan(&item.ScopeID, &item.TenantName, &payload, &item.RequestID, &item.OccurredAt); err != nil {
					return err
				}
				var body struct {
					Reason string `json:"reason"`
				}
				if err := json.Unmarshal(payload, &body); err != nil {
					return err
				}
				item.Reason = body.Reason
				result.Rejections = append(result.Rejections, item)
			}
			if err := rejections.Err(); err != nil {
				return err
			}
			rejections.Close()
			regressions, err := readCapabilityRegressions(ctx, tx, nodeID)
			if err != nil {
				return err
			}
			result.CapabilityRegressions = regressions
			return nil
		})
	if errors.Is(err, node.ErrNotFound) {
		return NodeConfigurationScopes{}, err
	}
	if err != nil {
		return NodeConfigurationScopes{}, fmt.Errorf("read node configuration scopes: %w", err)
	}
	return result, nil
}
