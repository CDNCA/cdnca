package edgepublishhttp

import (
	"context"
	"net/http"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
)

type nodeConfigReconciliationDomain interface {
	ReconcileNodeConfigCommand(
		context.Context,
		edgedeployment.ReconcileNodeConfigCommandRequest,
	) (edgedeployment.ReconcileNodeConfigResult, error)
}

type nodeConfigReconciliationRequest struct {
	ConfigurationScopeID    string  `json:"configuration_scope_id"`
	NodeID                  string  `json:"node_id"`
	SourceDeploymentID      string  `json:"source_deployment_id"`
	SourceDeploymentAttempt int32   `json:"source_deployment_attempt"`
	ObservedConfigVersionID *string `json:"observed_config_version_id"`
	Resolution              string  `json:"resolution"`
	Evidence                string  `json:"evidence"`
}

type NodeConfigReconciliationInput struct {
	ConfigurationScopeID    uuid.UUID
	NodeID                  uuid.UUID
	SourceDeploymentID      uuid.UUID
	SourceDeploymentAttempt int32
	ObservedConfigVersionID *uuid.UUID
	Resolution              edgedeployment.ReconciliationResolution
	Evidence                string
}

type NodeConfigReconciliationView struct {
	ID                      uuid.UUID                               `json:"id"`
	NodeID                  uuid.UUID                               `json:"node_id"`
	ConfigurationScopeID    uuid.UUID                               `json:"configuration_scope_id"`
	SourceDeploymentID      uuid.UUID                               `json:"source_deployment_id"`
	SourceDeploymentAttempt int32                                   `json:"source_deployment_attempt"`
	PreviousConfigVersionID *uuid.UUID                              `json:"previous_config_version_id"`
	CurrentConfigVersionID  *uuid.UUID                              `json:"current_config_version_id"`
	Resolution              edgedeployment.ReconciliationResolution `json:"resolution"`
	ReconciliationRequired  bool                                    `json:"reconciliation_required"`
	ReconciledAt            string                                  `json:"reconciled_at"`
	Replayed                bool                                    `json:"-"`
}

func (h *Handler) handleNodeConfigReconciliation(w http.ResponseWriter, r *http.Request) {
	session, ok := h.session(w, r)
	if !ok {
		return
	}
	metadata, err := parseWriteMetadata(r)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	var body nodeConfigReconciliationRequest
	if err := decodeJSON(w, r, &body); err != nil {
		h.writeError(w, r, ErrInvalidRequest)
		return
	}
	input, err := normalizeNodeConfigReconciliation(body)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	result, err := h.service.ReconcileNodeConfig(r.Context(), session, input, metadata)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	if result.Replayed {
		w.Header().Set("Idempotency-Replayed", "true")
	}
	if err := writeJSON(w, http.StatusCreated, result); err != nil {
		h.writeError(w, r, err)
	}
}

func normalizeNodeConfigReconciliation(body nodeConfigReconciliationRequest) (NodeConfigReconciliationInput, error) {
	scopeID, err := canonicalUUID(body.ConfigurationScopeID)
	if err != nil {
		return NodeConfigReconciliationInput{}, ErrInvalidRequest
	}
	nodeID, err := canonicalUUID(body.NodeID)
	if err != nil {
		return NodeConfigReconciliationInput{}, ErrInvalidRequest
	}
	deploymentID, err := canonicalUUID(body.SourceDeploymentID)
	if err != nil || body.SourceDeploymentAttempt <= 0 {
		return NodeConfigReconciliationInput{}, ErrInvalidRequest
	}
	var observed *uuid.UUID
	if body.ObservedConfigVersionID != nil {
		value, parseErr := canonicalUUID(*body.ObservedConfigVersionID)
		if parseErr != nil {
			return NodeConfigReconciliationInput{}, ErrInvalidRequest
		}
		observed = &value
	}
	resolution := edgedeployment.ReconciliationResolution(body.Resolution)
	if resolution != edgedeployment.ReconciliationAgentObserved &&
		resolution != edgedeployment.ReconciliationOperatorConfirmed {
		return NodeConfigReconciliationInput{}, ErrInvalidRequest
	}
	return NodeConfigReconciliationInput{
		ConfigurationScopeID: scopeID, NodeID: nodeID,
		SourceDeploymentID: deploymentID, SourceDeploymentAttempt: body.SourceDeploymentAttempt,
		ObservedConfigVersionID: observed, Resolution: resolution, Evidence: body.Evidence,
	}, nil
}

func (s *Service) ReconcileNodeConfig(
	ctx context.Context,
	session AuthenticatedSession,
	input NodeConfigReconciliationInput,
	metadata WriteMetadata,
) (NodeConfigReconciliationView, error) {
	domain, ok := s.commands.(nodeConfigReconciliationDomain)
	if !ok || nilPort(domain) {
		return NodeConfigReconciliationView{}, ErrUnsafeRolloutCommands
	}
	if err := requirePrincipal(session.Principal, AudiencePlatform, edgepublish.PermissionManage); err != nil {
		return NodeConfigReconciliationView{}, err
	}
	actor, err := edgedeployment.NewSessionActor(
		session.Principal.UserID,
		session.Principal.ScopeID,
		session.Principal.ScopeKind,
		session.SessionID,
		session.rawToken(),
	)
	if err != nil {
		return NodeConfigReconciliationView{}, ErrUnauthenticated
	}
	if input.ConfigurationScopeID == uuid.Nil || input.NodeID == uuid.Nil || input.SourceDeploymentID == uuid.Nil ||
		input.SourceDeploymentAttempt <= 0 {
		return NodeConfigReconciliationView{}, ErrInvalidRequest
	}
	if err := validateWriteMetadata(metadata); err != nil {
		return NodeConfigReconciliationView{}, err
	}
	result, err := domain.ReconcileNodeConfigCommand(ctx, edgedeployment.ReconcileNodeConfigCommandRequest{
		Actor: actor, NodeID: input.NodeID, ConfigurationScopeID: input.ConfigurationScopeID,
		SourceDeploymentID: input.SourceDeploymentID, SourceDeploymentAttempt: input.SourceDeploymentAttempt,
		ObservedConfigVersionID: input.ObservedConfigVersionID,
		Resolution:              input.Resolution, Evidence: input.Evidence,
		IdempotencyKey: metadata.IdempotencyKey, RequestID: metadata.RequestID,
		CorrelationID: metadata.CorrelationID, Traceparent: metadata.Traceparent, TaskID: cloneString(metadata.TaskID),
	})
	if err != nil {
		return NodeConfigReconciliationView{}, err
	}
	item := result.Reconciliation
	if item.ID == uuid.Nil || item.NodeID != input.NodeID || item.ConfigurationScopeID != input.ConfigurationScopeID ||
		item.SourceDeploymentID != input.SourceDeploymentID || item.SourceDeploymentAttempt != input.SourceDeploymentAttempt ||
		item.Resolution != input.Resolution || item.ReconciledAt.IsZero() ||
		!sameOptionalUUID(item.ObservedConfigVersionID, input.ObservedConfigVersionID) {
		return NodeConfigReconciliationView{}, ErrInvalidResponse
	}
	return NodeConfigReconciliationView{
		ID: item.ID, NodeID: item.NodeID, ConfigurationScopeID: item.ConfigurationScopeID,
		SourceDeploymentID: item.SourceDeploymentID, SourceDeploymentAttempt: item.SourceDeploymentAttempt,
		PreviousConfigVersionID: cloneOptionalUUID(item.PreviousConfigVersionID),
		CurrentConfigVersionID:  cloneOptionalUUID(item.ObservedConfigVersionID),
		Resolution:              item.Resolution, ReconciliationRequired: false,
		ReconciledAt: item.ReconciledAt.UTC().Format(time.RFC3339Nano), Replayed: result.Replayed,
	}, nil
}

func sameOptionalUUID(left, right *uuid.UUID) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func cloneOptionalUUID(value *uuid.UUID) *uuid.UUID {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
