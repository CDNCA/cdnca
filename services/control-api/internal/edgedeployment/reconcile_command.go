package edgedeployment

import (
	"context"
	"strings"

	"github.com/google/uuid"
)

type ReconcileNodeConfigCommandRequest struct {
	Actor                   Actor
	NodeID                  uuid.UUID
	ConfigurationScopeID    uuid.UUID
	SourceDeploymentID      uuid.UUID
	SourceDeploymentAttempt int32
	ObservedConfigVersionID *uuid.UUID
	Resolution              ReconciliationResolution
	Evidence                string
	IdempotencyKey          string
	RequestID               string
	CorrelationID           string
	Traceparent             string
	TaskID                  *string
}

type normalizedReconcileNodeConfigCommand struct {
	ReconcileNodeConfigCommandRequest
	ReconcileNodeConfigRequest ReconcileNodeConfigRequest
}

func (s *Store) ReconcileNodeConfigCommand(
	ctx context.Context,
	request ReconcileNodeConfigCommandRequest,
) (ReconcileNodeConfigResult, error) {
	if err := s.protectedOperationError(); err != nil {
		return ReconcileNodeConfigResult{}, err
	}
	if ctx == nil {
		return ReconcileNodeConfigResult{}, ErrInvalidInput
	}
	normalized, err := normalizeReconcileNodeConfigCommand(request)
	if err != nil {
		return ReconcileNodeConfigResult{}, err
	}
	return s.reconcileNodeConfig(ctx, normalized.ReconcileNodeConfigRequest, &normalized)
}

func normalizeReconcileNodeConfigCommand(
	request ReconcileNodeConfigCommandRequest,
) (normalizedReconcileNodeConfigCommand, error) {
	requestID, requestErr := uuid.Parse(request.RequestID)
	if request.CorrelationID == "" {
		request.CorrelationID = request.RequestID
	}
	correlationID, correlationErr := uuid.Parse(request.CorrelationID)
	if !validActor(request.Actor) || request.NodeID == uuid.Nil || request.ConfigurationScopeID == uuid.Nil ||
		request.SourceDeploymentID == uuid.Nil || request.SourceDeploymentAttempt <= 0 ||
		!validIdempotencyKey(request.IdempotencyKey) || requestErr != nil || requestID.String() != request.RequestID ||
		correlationErr != nil || correlationID.String() != request.CorrelationID ||
		len(request.Traceparent) > 512 || strings.TrimSpace(request.Traceparent) != request.Traceparent ||
		(request.TaskID != nil && !identifierPattern.MatchString(*request.TaskID)) {
		return normalizedReconcileNodeConfigCommand{}, ErrInvalidInput
	}
	idempotencyRequestID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(
		"cdnca.edge-config-reconciliation/v1\x00"+request.ConfigurationScopeID.String()+"\x00"+request.IdempotencyKey,
	))
	core, err := normalizeReconciliation(ReconcileNodeConfigRequest{
		RequestID: idempotencyRequestID, NodeID: request.NodeID,
		ConfigurationScopeID: request.ConfigurationScopeID,
		SourceDeploymentID:   request.SourceDeploymentID, SourceDeploymentAttempt: request.SourceDeploymentAttempt,
		ObservedConfigVersionID: request.ObservedConfigVersionID,
		Resolution:              request.Resolution, Evidence: request.Evidence,
	})
	if err != nil {
		return normalizedReconcileNodeConfigCommand{}, err
	}
	request.Evidence = core.Evidence
	return normalizedReconcileNodeConfigCommand{
		ReconcileNodeConfigCommandRequest: request,
		ReconcileNodeConfigRequest:        core.ReconcileNodeConfigRequest,
	}, nil
}
