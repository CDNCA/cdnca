//go:build integration

package cachecontrol

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// fix-cacheflow2 §1 (CACHE-ADD-07 third layer): a node report that stopped
// targets on cancel lands in the unified job as cancelled, so the task center
// and the cache page show the same settlement and nothing goes to the DLQ.
func TestNodeReportedCancellationProjectsIntoUnifiedJob(t *testing.T) {
	pool := openCacheTestDatabase(t, true)
	clock := &testClock{value: cacheTestNow}
	store := mustCacheStore(t, pool, clock.Now)
	fixture := seedCacheFixture(t, pool, "producer-cancel", 1)

	for _, test := range []struct {
		name                         string
		states                       []ItemState
		cacheState, jobState         State
		jobCode                      string
		succeeded, failed, cancelled int
	}{
		{name: "success and cancelled", states: []ItemState{ItemSucceeded, ItemCancelled},
			cacheState: StatePartialFailed, jobState: StatePartialFailed, jobCode: "cancelled", succeeded: 1, cancelled: 1},
		{name: "all cancelled", states: []ItemState{ItemCancelled, ItemCancelled},
			cacheState: StateCancelled, jobState: StateCancelled, jobCode: "cancelled", cancelled: 2},
		{name: "failed and cancelled", states: []ItemState{ItemFailed, ItemCancelled},
			cacheState: StatePartialFailed, jobState: StatePartialFailed, jobCode: "item_failed", failed: 1, cancelled: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			key := "producer-cancel-" + uuid.NewString()[:8]
			created, err := store.CreateOperation(context.Background(), fixture.actor, CreateOperationRequest{
				SiteID: fixture.siteID, Action: ActionPurge, TargetType: TargetExactURL,
				Targets: []string{"http://" + fixture.domain + "/" + key + "/a", "http://" + fixture.domain + "/" + key + "/b"},
				NodeIDs: fixture.nodeIDs, MaxRetries: 0, IdempotencyKey: key, RequestID: key + "-request",
			})
			if err != nil {
				t.Fatal(err)
			}
			claims := claimForNodes(t, store, fixture.actor.ScopeID, "producer-cancel-worker", fixture.nodeIDs, 1, key+"-claim")
			if len(claims) != 1 || claims[0].OperationID != created.Operation.ID {
				t.Fatalf("claims=%+v", claims)
			}
			report := reportRequest(claims[0], "producer-cancel-worker", 3, key+"-report", test.states)
			for index := range report.Results {
				if report.Results[index].State == ItemCancelled {
					report.Results[index].ErrorCode = codeCancelled
				}
			}
			result, err := store.Report(context.Background(), report)
			if err != nil || !result.Applied || result.Operation.State != test.cacheState {
				t.Fatalf("report: result=%+v err=%v", result, err)
			}
			assertUnifiedJob(t, pool, created.Operation.ID, test.jobState, test.jobCode,
				test.succeeded, test.failed, test.cancelled)
		})
	}
}

func assertUnifiedJob(t *testing.T, pool *pgxpool.Pool, jobID uuid.UUID, state State, code string,
	succeeded, failed, cancelled int) {
	t.Helper()
	var gotState, gotCode string
	var gotSucceeded, gotFailed, gotCancelled, deadLetters int
	var cancelRequested bool
	if err := pool.QueryRow(context.Background(), `
		SELECT state, COALESCE(last_error_code,''), succeeded_count, failed_count, cancelled_count,
		       cancel_requested_at IS NOT NULL,
		       (SELECT count(*) FROM background_job_dead_letters dead WHERE dead.job_id=job.id)::integer
		FROM background_jobs job WHERE id=$1`, jobID).Scan(&gotState, &gotCode, &gotSucceeded,
		&gotFailed, &gotCancelled, &cancelRequested, &deadLetters); err != nil {
		t.Fatal(err)
	}
	// A failed item whose attempts are used up still goes to the DLQ (the
	// fixture allows no retry); only the cancelled items never do.
	wantDeadLetters := 0
	if failed > 0 {
		wantDeadLetters = 1
	}
	if State(gotState) != state || gotCode != code || gotSucceeded != succeeded || gotFailed != failed ||
		gotCancelled != cancelled || cancelRequested || deadLetters != wantDeadLetters {
		t.Fatalf("unified job state=%s code=%s succeeded=%d failed=%d cancelled=%d cancel_requested=%v dlq=%d",
			gotState, gotCode, gotSucceeded, gotFailed, gotCancelled, cancelRequested, deadLetters)
	}
}
