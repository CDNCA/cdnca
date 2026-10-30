package edgedeployment

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestNormalizeReconcileNodeConfigCommand(t *testing.T) {
	actor, err := NewSessionActor(uuid.New(), uuid.New(), ScopeKindPlatform, uuid.New(), "session-token")
	if err != nil {
		t.Fatal(err)
	}
	observed := uuid.New()
	requestID := uuid.NewString()
	request := ReconcileNodeConfigCommandRequest{
		Actor: actor, NodeID: uuid.New(), ConfigurationScopeID: uuid.New(),
		SourceDeploymentID: uuid.New(), SourceDeploymentAttempt: 1,
		ObservedConfigVersionID: &observed, Resolution: ReconciliationAgentObserved,
		Evidence: "  signed agent inventory  ", IdempotencyKey: "reconcile-node-b",
		RequestID: requestID,
	}
	normalized, err := normalizeReconcileNodeConfigCommand(request)
	if err != nil {
		t.Fatal(err)
	}
	wantDomainRequestID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(
		"cdnca.edge-config-reconciliation/v1\x00"+request.ConfigurationScopeID.String()+"\x00"+request.IdempotencyKey,
	))
	if normalized.RequestID != requestID || normalized.CorrelationID != requestID ||
		normalized.ReconcileNodeConfigRequest.RequestID != wantDomainRequestID ||
		normalized.Evidence != "signed agent inventory" || normalized.ReconcileNodeConfigRequest.Evidence != normalized.Evidence {
		t.Fatalf("normalized command = %+v", normalized)
	}
	repeated, err := normalizeReconcileNodeConfigCommand(request)
	if err != nil || repeated.ReconcileNodeConfigRequest.RequestID != normalized.ReconcileNodeConfigRequest.RequestID {
		t.Fatalf("repeated normalization = (%+v, %v)", repeated, err)
	}
}

func TestNormalizeReconcileNodeConfigCommandRejectsInvalidAuthorityAndMetadata(t *testing.T) {
	actor, err := NewSessionActor(uuid.New(), uuid.New(), ScopeKindPlatform, uuid.New(), "session-token")
	if err != nil {
		t.Fatal(err)
	}
	observed := uuid.New()
	valid := ReconcileNodeConfigCommandRequest{
		Actor: actor, NodeID: uuid.New(), ConfigurationScopeID: uuid.New(),
		SourceDeploymentID: uuid.New(), SourceDeploymentAttempt: 1,
		ObservedConfigVersionID: &observed, Resolution: ReconciliationOperatorConfirmed,
		Evidence: "operator evidence", IdempotencyKey: "reconcile-node",
		RequestID: uuid.NewString(), CorrelationID: uuid.NewString(),
	}
	tests := []struct {
		name   string
		mutate func(*ReconcileNodeConfigCommandRequest)
	}{
		{name: "actor user ID", mutate: func(value *ReconcileNodeConfigCommandRequest) { value.Actor.UserID = uuid.Nil }},
		{name: "idempotency key", mutate: func(value *ReconcileNodeConfigCommandRequest) { value.IdempotencyKey = "" }},
		{name: "request ID", mutate: func(value *ReconcileNodeConfigCommandRequest) { value.RequestID = "not-a-uuid" }},
		{name: "correlation ID", mutate: func(value *ReconcileNodeConfigCommandRequest) { value.CorrelationID = "NOT-CANONICAL" }},
		{name: "traceparent whitespace", mutate: func(value *ReconcileNodeConfigCommandRequest) { value.Traceparent = " trace " }},
		{name: "task ID", mutate: func(value *ReconcileNodeConfigCommandRequest) { task := "invalid task"; value.TaskID = &task }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := valid
			test.mutate(&request)
			if _, err := normalizeReconcileNodeConfigCommand(request); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v, want %v", err, ErrInvalidInput)
			}
		})
	}
}
