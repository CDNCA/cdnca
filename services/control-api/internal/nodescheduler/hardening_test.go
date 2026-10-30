package nodescheduler

import (
	"errors"
	"testing"
)

func TestPlanWeightedSelectionRejectsCandidateOverflow(t *testing.T) {
	endpoint := testEndpoint("192.0.2.1", 443, 0, maxWeight)
	plan := Plan{Candidates: make([]Endpoint, maxEndpoints+1)}
	for index := range plan.Candidates {
		plan.Candidates[index] = endpoint
	}
	if _, err := plan.ChooseWeighted(0); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("candidate overflow error = %v", err)
	}
}
