package controlupgrade

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Only a same-version re-release summary carries the release sequences.
func TestRolloutSummaryCarriesReleaseSequencesOnlyForRerelease(t *testing.T) {
	plan := mustRolloutPlan(t)
	now := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	summary := rolloutSummary(plan, planID(900), now, now)
	encoded, _ := json.Marshal(summary)
	if summary.ReleaseSequence != 0 || summary.CurrentReleaseSequence != 0 || strings.Contains(string(encoded), "release_sequence") {
		t.Fatalf("cross-version summary = %s", encoded)
	}
	plan.CurrentReleaseSequence = plan.ReleaseSequence - 1
	summary = rolloutSummary(plan, planID(900), now, now)
	if summary.ReleaseSequence != plan.ReleaseSequence || summary.CurrentReleaseSequence != plan.CurrentReleaseSequence {
		t.Fatalf("re-release summary = %+v", summary)
	}
}
