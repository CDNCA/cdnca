package challengepolicy

import (
	"testing"

	"github.com/google/uuid"
)

func TestChallengeBindingPolicyAdvanceIsPolicyLocal(t *testing.T) {
	activePolicyID := uuid.New()
	replacementPolicyID := uuid.New()

	tests := []struct {
		name           string
		policyID       uuid.UUID
		policyRevision int64
		want           bool
	}{
		{name: "same policy advances", policyID: activePolicyID, policyRevision: 8, want: true},
		{name: "replacement policy restarts revision", policyID: replacementPolicyID, policyRevision: 1, want: true},
		{name: "same policy replay", policyID: activePolicyID, policyRevision: 7, want: false},
		{name: "same policy rollback", policyID: activePolicyID, policyRevision: 6, want: false},
		{name: "missing replacement policy", policyID: uuid.Nil, policyRevision: 1, want: false},
		{name: "invalid replacement revision", policyID: replacementPolicyID, policyRevision: 0, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := challengeBindingPolicyAdvanceAllowed(
				activePolicyID, 7, test.policyID, test.policyRevision,
			); got != test.want {
				t.Fatalf("challengeBindingPolicyAdvanceAllowed() = %v, want %v", got, test.want)
			}
		})
	}
}
