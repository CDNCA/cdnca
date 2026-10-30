package edgepublishhttp

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
)

type fakeNodeConfigReconciliationDomain struct {
	*fakeDomain
	requests []edgedeployment.ReconcileNodeConfigCommandRequest
	result   edgedeployment.ReconcileNodeConfigResult
	err      error
}

func (domain *fakeNodeConfigReconciliationDomain) ReconcileNodeConfigCommand(
	_ context.Context,
	request edgedeployment.ReconcileNodeConfigCommandRequest,
) (edgedeployment.ReconcileNodeConfigResult, error) {
	domain.requests = append(domain.requests, request)
	if domain.err != nil {
		return edgedeployment.ReconcileNodeConfigResult{}, domain.err
	}
	if domain.result.Reconciliation.ID != uuid.Nil {
		return domain.result, nil
	}
	previous := uuid.New()
	return edgedeployment.ReconcileNodeConfigResult{Reconciliation: edgedeployment.NodeConfigReconciliation{
		ID: uuid.New(), NodeID: request.NodeID, ConfigurationScopeID: request.ConfigurationScopeID,
		SourceDeploymentID:      request.SourceDeploymentID,
		SourceDeploymentAttempt: request.SourceDeploymentAttempt,
		PreviousConfigVersionID: &previous, ObservedConfigVersionID: request.ObservedConfigVersionID,
		Resolution: request.Resolution, ReconciledAt: testClock,
	}}, nil
}

func newReconciliationTestHandler(t *testing.T, domain *fakeNodeConfigReconciliationDomain) *Handler {
	t.Helper()
	service, err := newRuntimeService(domain.fakeDomain, domain.fakeDomain, domain, newTestCursorCodec(t))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := newSessionHandler(service, testAuthenticateSession, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func TestNodeConfigReconciliationRouteAuthorizesValidatesAndReturnsAuditFact(t *testing.T) {
	scopeID, nodeID, deploymentID, observedID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	body := map[string]any{
		"configuration_scope_id": scopeID.String(), "node_id": nodeID.String(),
		"source_deployment_id": deploymentID.String(), "source_deployment_attempt": int32(1),
		"observed_config_version_id": observedID.String(), "resolution": "operator_confirmed",
		"evidence": "OpenResty PID, active symlink, health response, and heartbeat agree",
	}

	t.Run("platform manager creates reconciliation", func(t *testing.T) {
		domain := &fakeNodeConfigReconciliationDomain{fakeDomain: &fakeDomain{}}
		response := performRequest(newReconciliationTestHandler(t, domain), http.MethodPost,
			"/v1/admin/site-rollouts/reconciliations", "platform-manage", body, true)
		if response.Code != http.StatusCreated {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
		if len(domain.requests) != 1 {
			t.Fatalf("domain requests=%d", len(domain.requests))
		}
		request := domain.requests[0]
		if request.NodeID != nodeID || request.ConfigurationScopeID != scopeID ||
			request.SourceDeploymentID != deploymentID || request.SourceDeploymentAttempt != 1 ||
			request.ObservedConfigVersionID == nil || *request.ObservedConfigVersionID != observedID ||
			request.Resolution != edgedeployment.ReconciliationOperatorConfirmed ||
			request.IdempotencyKey != "publish-test" || request.RequestID == "" || request.CorrelationID == "" {
			t.Fatalf("reconciliation request mismatch: %+v", request)
		}
		var payload NodeConfigReconciliationView
		if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
			t.Fatal(err)
		}
		if payload.NodeID != nodeID || payload.ConfigurationScopeID != scopeID ||
			payload.CurrentConfigVersionID == nil || *payload.CurrentConfigVersionID != observedID ||
			payload.ReconciliationRequired || payload.ReconciledAt == "" {
			t.Fatalf("response mismatch: %+v", payload)
		}
	})

	for _, auth := range []string{"platform-read", "tenant-manage"} {
		t.Run("permission denied "+auth, func(t *testing.T) {
			domain := &fakeNodeConfigReconciliationDomain{fakeDomain: &fakeDomain{}}
			response := performRequest(newReconciliationTestHandler(t, domain), http.MethodPost,
				"/v1/admin/site-rollouts/reconciliations", auth, body, true)
			if response.Code != http.StatusForbidden || len(domain.requests) != 0 {
				t.Fatalf("status=%d requests=%d body=%s", response.Code, len(domain.requests), response.Body.String())
			}
		})
	}

	t.Run("strict request validation", func(t *testing.T) {
		domain := &fakeNodeConfigReconciliationDomain{fakeDomain: &fakeDomain{}}
		invalid := make(map[string]any, len(body)+1)
		for key, value := range body {
			invalid[key] = value
		}
		invalid["unexpected"] = true
		response := performRequest(newReconciliationTestHandler(t, domain), http.MethodPost,
			"/v1/admin/site-rollouts/reconciliations", "platform-manage", invalid, true)
		if response.Code != http.StatusBadRequest || len(domain.requests) != 0 {
			t.Fatalf("status=%d requests=%d", response.Code, len(domain.requests))
		}
	})

	t.Run("state conflict remains explicit", func(t *testing.T) {
		domain := &fakeNodeConfigReconciliationDomain{
			fakeDomain: &fakeDomain{}, err: edgedeployment.ErrReconciliationNotRequired,
		}
		response := performRequest(newReconciliationTestHandler(t, domain), http.MethodPost,
			"/v1/admin/site-rollouts/reconciliations", "platform-manage", body, true)
		if response.Code != http.StatusConflict {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
	})
}

func TestNodeConfigReconciliationReplayHeader(t *testing.T) {
	scopeID, nodeID, deploymentID, observedID, reconciliationID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	domain := &fakeNodeConfigReconciliationDomain{fakeDomain: &fakeDomain{}}
	domain.result = edgedeployment.ReconcileNodeConfigResult{
		Replayed: true,
		Reconciliation: edgedeployment.NodeConfigReconciliation{
			ID: reconciliationID, NodeID: nodeID, ConfigurationScopeID: scopeID,
			SourceDeploymentID: deploymentID, SourceDeploymentAttempt: 1,
			ObservedConfigVersionID: &observedID,
			Resolution:              edgedeployment.ReconciliationAgentObserved, ReconciledAt: testClock,
		},
	}
	response := performRequest(newReconciliationTestHandler(t, domain), http.MethodPost,
		"/v1/admin/site-rollouts/reconciliations", "platform-manage", map[string]any{
			"configuration_scope_id": scopeID.String(), "node_id": nodeID.String(),
			"source_deployment_id": deploymentID.String(), "source_deployment_attempt": 1,
			"observed_config_version_id": observedID.String(), "resolution": "agent_observed",
			"evidence": "signed active configuration observation",
		}, true)
	if response.Code != http.StatusCreated || response.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatalf("status=%d replay=%q body=%s", response.Code,
			response.Header().Get("Idempotency-Replayed"), response.Body.String())
	}
}
