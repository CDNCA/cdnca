package edgedeployment

import (
	"errors"
	"testing"
)

func TestNormalizeRolloutPolicyAndDeterministicCohorts(t *testing.T) {
	policy, err := normalizeRolloutPolicy(RolloutPolicy{
		Strategy: RolloutStrategyCanary, CanarySize: 2, BatchSize: 3,
		FailureThreshold: 2, AutoStart: false,
	}, 8)
	if err != nil {
		t.Fatal(err)
	}
	want := []int{0, 0, 1, 1, 1, 2, 2, 2}
	for index, cohort := range want {
		if got := cohortForIndex(index, policy); got != cohort {
			t.Fatalf("index %d cohort=%d want=%d", index, got, cohort)
		}
	}
	if policy.CohortCount != 3 {
		t.Fatalf("cohort count=%d want=3", policy.CohortCount)
	}
}

func TestNormalizeRolloutPolicyRejectsUnsafeBounds(t *testing.T) {
	tests := []RolloutPolicy{
		{Strategy: RolloutStrategyCanary, CanarySize: 0, BatchSize: 1, FailureThreshold: 1},
		{Strategy: RolloutStrategyCanary, CanarySize: 1, BatchSize: 0, FailureThreshold: 1},
		{Strategy: RolloutStrategyCanary, CanarySize: 1, BatchSize: 1, FailureThreshold: 0},
		{Strategy: RolloutStrategyCanary, CanarySize: 6, BatchSize: 1, FailureThreshold: 1},
		{Strategy: RolloutStrategyCanary, CanarySize: 1, BatchSize: 6, FailureThreshold: 1},
		{Strategy: RolloutStrategyCanary, CanarySize: 1, BatchSize: 1, FailureThreshold: 6},
		{Strategy: "future", CanarySize: 1, BatchSize: 1, FailureThreshold: 1},
	}
	for _, policy := range tests {
		if _, err := normalizeRolloutPolicy(policy, 5); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("policy=%+v error=%v want=%v", policy, err, ErrInvalidInput)
		}
	}
}
