//go:build integration

package cachecontrol

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCacheAlgorithmComparisonClaimFairness(t *testing.T) {
	pool := openCacheTestDatabase(t, true)
	clock := &testClock{value: cacheTestNow}
	store := mustCacheStore(t, pool, clock.Now)
	fixture := seedCacheFixture(t, pool, "algorithm-fairness", 4)
	first := createSimpleOperation(t, store, fixture, "algorithm-first", 0, fixture.nodeIDs)
	clock.Add(time.Microsecond)
	second := createSimpleOperation(t, store, fixture, "algorithm-second", 0, fixture.nodeIDs)

	claims, err := store.Claim(context.Background(), ClaimRequest{
		ScopeID: fixture.actor.ScopeID, WorkerID: "algorithm-comparison-worker",
		OnlineNodeIDs: fixture.nodeIDs, Limit: 4, LeaseDuration: time.Minute,
		RequestID: "algorithm-comparison-claim",
	})
	if err != nil || len(claims) != 4 {
		t.Fatalf("current fair claim count=%d error=%v", len(claims), err)
	}
	currentCounts := map[uuid.UUID]int{}
	currentOrder := make([]uuid.UUID, len(claims))
	for index, claim := range claims {
		currentCounts[claim.OperationID]++
		currentOrder[index] = claim.OperationID
	}
	currentStarved := 0
	for _, operationID := range []uuid.UUID{first.ID, second.ID} {
		if currentCounts[operationID] == 0 {
			currentStarved++
		}
	}
	currentMaximumRun := cacheAlgorithmMaximumRun(currentOrder)

	// The simple baseline drains the oldest operation before considering the next one.
	baselineOrder := []uuid.UUID{first.ID, first.ID, first.ID, first.ID}
	baselineStarved := 1
	baselineMaximumRun := cacheAlgorithmMaximumRun(baselineOrder)
	if currentStarved != 0 || currentMaximumRun != 1 || baselineMaximumRun != 4 {
		t.Fatalf("fairness current_starved=%d current_max_run=%d baseline_starved=%d baseline_max_run=%d order=%v",
			currentStarved, currentMaximumRun, baselineStarved, baselineMaximumRun, currentOrder)
	}
	t.Logf("CACHE_COMPARE claim_fairness current_claims=4 current_starved=%d current_max_run=%d baseline_claims=4 baseline_starved=%d baseline_max_run=%d",
		currentStarved, currentMaximumRun, baselineStarved, baselineMaximumRun)
}

func cacheAlgorithmMaximumRun(values []uuid.UUID) int {
	maximum, current := 0, 0
	var previous uuid.UUID
	for index, value := range values {
		if index == 0 || value != previous {
			current = 1
		} else {
			current++
		}
		if current > maximum {
			maximum = current
		}
		previous = value
	}
	return maximum
}
