package securityactivation

import (
	"crypto/sha256"
	"testing"

	"github.com/google/uuid"
)

// fix-cfgflow3: a node that ignored the candidate as an old release (it
// already runs a newer revision) is counted apart, not failed. The candidate
// cannot be promoted any more (every target must run it), so it is cancelled
// rather than failed.
func TestIgnoredOldReleaseIsNotAPhaseFailure(t *testing.T) {
	candidate := Candidate{ID: uuid.New(), CandidateConfigVersionID: uuid.New(),
		CandidateArtifactSHA256: sha256.Sum256([]byte("artifact"))}
	healthyNode, ignoredNode := uuid.New(), uuid.New()
	rolloutID := uuid.New()
	fact := func(nodeID uuid.UUID, state string, superseded bool) ReceiptFact {
		return ReceiptFact{RolloutID: rolloutID, DeploymentID: uuid.NewSHA1(rolloutID, nodeID[:]), Phase: "canary",
			Action: "apply", NodeID: nodeID, Attempt: 1, TransitionSequence: 3, State: state, Superseded: superseded,
			ConfigVersionID: candidate.CandidateConfigVersionID, ArtifactSHA256: candidate.CandidateArtifactSHA256}
	}
	facts, err := aggregateReceiptFacts(candidate, []uuid.UUID{healthyNode, ignoredNode}, []ReceiptFact{
		fact(healthyNode, "healthy", false), fact(ignoredNode, "failed", true),
	}, nil)
	if err != nil || facts != (phaseFacts{total: 2, healthy: 1, superseded: 1}) {
		t.Fatalf("aggregateReceiptFacts = %+v, %v", facts, err)
	}
	for _, test := range []struct {
		name           string
		status         CandidateStatus
		canary, expand phaseFacts
		want           reconcileAction
	}{
		{name: "canary", status: StatusCanary, canary: facts, expand: phaseFacts{total: 1}, want: actionCancel},
		{name: "expansion", status: StatusExpanding, canary: phaseFacts{total: 1, healthy: 1},
			expand: phaseFacts{total: 2, healthy: 1, superseded: 1}, want: actionCancel},
		{name: "a failure still fails", status: StatusCanary,
			canary: phaseFacts{total: 3, healthy: 1, failed: 1, superseded: 1}, want: actionFail},
		{name: "ignored cannot inflate total", status: StatusCanary,
			canary: phaseFacts{total: 1, healthy: 1, superseded: 1}, want: actionFail},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := decideReconcile(test.status, false, test.canary, test.expand); got != test.want {
				t.Fatalf("decideReconcile() = %q, want %q", got, test.want)
			}
		})
	}
}
