package edgedeployment

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestNormalizeReconciliation(t *testing.T) {
	observed := uuid.New()
	request := ReconcileNodeConfigRequest{
		RequestID: uuid.New(), NodeID: uuid.New(), ConfigurationScopeID: uuid.New(),
		SourceDeploymentID: uuid.New(), SourceDeploymentAttempt: 2,
		ObservedConfigVersionID: &observed, Resolution: ReconciliationAgentObserved,
		Evidence: "  signed inventory observation  ",
	}
	normalized, err := normalizeReconciliation(request)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.Evidence != "signed inventory observation" || normalized.digest == [32]byte{} {
		t.Fatalf("normalized reconciliation = %+v", normalized)
	}
	repeated, err := normalizeReconciliation(normalized.ReconcileNodeConfigRequest)
	if err != nil || repeated.digest != normalized.digest {
		t.Fatalf("repeated normalization = (%+v, %v)", repeated, err)
	}
}

func TestNormalizeReconciliationRejectsInvalidInput(t *testing.T) {
	observed := uuid.New()
	valid := ReconcileNodeConfigRequest{
		RequestID: uuid.New(), NodeID: uuid.New(), ConfigurationScopeID: uuid.New(),
		SourceDeploymentID: uuid.New(), SourceDeploymentAttempt: 1,
		ObservedConfigVersionID: &observed, Resolution: ReconciliationOperatorConfirmed,
		Evidence: "operator incident evidence",
	}
	tests := []struct {
		name   string
		mutate func(*ReconcileNodeConfigRequest)
	}{
		{name: "request ID", mutate: func(value *ReconcileNodeConfigRequest) { value.RequestID = uuid.Nil }},
		{name: "node ID", mutate: func(value *ReconcileNodeConfigRequest) { value.NodeID = uuid.Nil }},
		{name: "scope ID", mutate: func(value *ReconcileNodeConfigRequest) { value.ConfigurationScopeID = uuid.Nil }},
		{name: "deployment ID", mutate: func(value *ReconcileNodeConfigRequest) { value.SourceDeploymentID = uuid.Nil }},
		{name: "attempt", mutate: func(value *ReconcileNodeConfigRequest) { value.SourceDeploymentAttempt = 0 }},
		{name: "observed config", mutate: func(value *ReconcileNodeConfigRequest) { zero := uuid.Nil; value.ObservedConfigVersionID = &zero }},
		{name: "resolution", mutate: func(value *ReconcileNodeConfigRequest) { value.Resolution = "automatic" }},
		{name: "evidence empty", mutate: func(value *ReconcileNodeConfigRequest) { value.Evidence = "  " }},
		{name: "evidence long", mutate: func(value *ReconcileNodeConfigRequest) { value.Evidence = strings.Repeat("x", 513) }},
		{name: "evidence encoding", mutate: func(value *ReconcileNodeConfigRequest) { value.Evidence = string([]byte{0xff}) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := valid
			test.mutate(&request)
			if _, err := normalizeReconciliation(request); err == nil {
				t.Fatal("invalid reconciliation request was accepted")
			}
		})
	}
}
