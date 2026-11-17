//go:build integration

package controlupgrade

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
)

// Migration 096 requires the action's audit event to occur no later than its write receipt
// completes. The audit event took the application clock and the receipt the database clock_timestamp(),
// so start and cancel failed with P9602 whenever the control-api host clock ran ahead of PostgreSQL's
// (tests/control-upgrade-e2e, Docker Desktop VM clock; any deployment with PostgreSQL on another host).
func TestRolloutActionsSucceedWithApplicationClockAheadOfDatabasePostgres(t *testing.T) {
	for _, operation := range []PlanAction{PlanStart, PlanCancel} {
		t.Run(string(operation), func(t *testing.T) {
			fixture := newCreateFlowFixture(t, "1.0.24", "1.0.27", 0, 127, 90)
			created := fixture.create(t, t.Context(), fixture.request("clock-ahead-"+string(operation)))
			fixture.service.store.auditor = audit.NewWithClock(fixture.pool, func() time.Time {
				return time.Now().Add(2 * time.Second)
			})
			result, err := fixture.service.ApplyRolloutAction(t.Context(), fixture.actor, RolloutActionRequest{
				RolloutActionBody: RolloutActionBody{ExpectedRevision: created.Revision, Reason: "operator_requested"},
				PlanID:            created.ID, Operation: string(operation),
				IdempotencyKey: "control-upgrade-clock-ahead-" + string(operation),
				RequestID:      "control-upgrade-clock-ahead-request-" + string(operation)})
			if err != nil || result.Detail.Revision != created.Revision+1 {
				t.Fatalf("%s with the application clock 2s ahead = (%+v, %v)", operation, result.Detail.RolloutSummary, err)
			}
		})
	}
}
