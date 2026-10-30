//go:build integration

package edgedeployment

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRolloutQueryAggregationPaginationCancelAndRetry(t *testing.T) {
	fixture := newCommandIAMFixture(t, nil)
	pool, store := fixture.pool, fixture.store
	platformScopeID := seedCommandScope(t, pool, ScopeKindPlatform)
	actor := fixture.seedActor(t, platformScopeID, ScopeKindPlatform, PermissionRead, PermissionManage)
	scopeID, userID := seedEdgeScope(t, pool)
	config := persistQueryTestConfig(t, store, scopeID)

	firstNode, secondNode := uuid.New(), uuid.New()
	seedEdgeNode(t, pool, scopeID, userID, firstNode)
	seedEdgeNode(t, pool, scopeID, userID, secondNode)
	request := testRolloutRequest(scopeID, config.ID, []uuid.UUID{secondNode, firstNode}, "query-cancel")
	request.MaxAttempts = 3
	created, err := store.CreateRollout(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	rollout, err := store.GetRollout(context.Background(), actor, scopeID, created.Rollout.ID)
	if err != nil || rollout.State != RolloutStateQueued || rollout.Progress.Total != 2 || !rollout.CanCancel || rollout.CanRetry {
		t.Fatalf("queued rollout = %+v, %v", rollout, err)
	}
	page, err := store.ListDeployments(context.Background(), actor, scopeID, created.Rollout.ID, DeploymentPageRequest{Limit: 1})
	if err != nil || len(page.Items) != 1 || page.NextCursor == "" {
		t.Fatalf("first deployment page = %+v, %v", page, err)
	}
	next, err := store.ListDeployments(context.Background(), actor, scopeID, created.Rollout.ID, DeploymentPageRequest{Limit: 1, Cursor: page.NextCursor})
	if err != nil || len(next.Items) != 1 || next.NextCursor != "" || next.Items[0].NodeID == page.Items[0].NodeID {
		t.Fatalf("second deployment page = %+v, %v", next, err)
	}

	cancelRequest := RolloutCommandRequest{
		Actor: actor, ConfigurationScopeID: scopeID, RolloutID: created.Rollout.ID,
		ExpectedRevision: rollout.Revision, IdempotencyKey: "cancel-query-rollout", RequestID: uuid.NewString(),
	}
	cancelled, err := store.CancelRollout(context.Background(), cancelRequest)
	if err != nil || cancelled.Rollout.State != RolloutStateCancelled || cancelled.Rollout.Revision != rollout.Revision+1 {
		t.Fatalf("cancelled rollout = %+v, %v", cancelled, err)
	}
	replayRequest := cancelRequest
	replayRequest.RequestID = uuid.NewString()
	replayRequest.CorrelationID = uuid.NewString()
	replayRequest.Traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	replayTaskID := "cancel-replay"
	replayRequest.TaskID = &replayTaskID
	replay, err := store.CancelRollout(context.Background(), replayRequest)
	if err != nil || !replay.Replayed || replay.Rollout.Revision != cancelled.Rollout.Revision {
		t.Fatalf("cancel replay = %+v, %v", replay, err)
	}
	conflict := cancelRequest
	conflict.ExpectedRevision++
	if _, err := store.CancelRollout(context.Background(), conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("cancel idempotency conflict = %v", err)
	}
	stale := cancelRequest
	stale.IdempotencyKey = "cancel-stale-revision"
	if _, err := store.CancelRollout(context.Background(), stale); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("cancel stale revision = %v", err)
	}

	thirdNode, fourthNode := uuid.New(), uuid.New()
	seedEdgeNode(t, pool, scopeID, userID, thirdNode)
	seedEdgeNode(t, pool, scopeID, userID, fourthNode)
	retryRequest := testRolloutRequest(scopeID, config.ID, []uuid.UUID{thirdNode, fourthNode}, "query-retry")
	retryRequest.MaxAttempts = 2
	retryCreated, err := store.CreateRollout(context.Background(), retryRequest)
	if err != nil {
		t.Fatal(err)
	}
	advanceDeploymentState(t, pool, retryCreated.Rollout.Deployments[0].ID, "delivered")
	advanceDeploymentState(t, pool, retryCreated.Rollout.Deployments[0].ID, "failed")
	advanceDeploymentState(t, pool, retryCreated.Rollout.Deployments[1].ID, "delivered")
	advanceDeploymentState(t, pool, retryCreated.Rollout.Deployments[1].ID, "staged")
	advanceDeploymentState(t, pool, retryCreated.Rollout.Deployments[1].ID, "prechecked")
	advanceDeploymentState(t, pool, retryCreated.Rollout.Deployments[1].ID, "activated")
	advanceDeploymentState(t, pool, retryCreated.Rollout.Deployments[1].ID, "healthy")
	partial, err := store.GetRollout(context.Background(), actor, scopeID, retryCreated.Rollout.ID)
	if err != nil || partial.State != RolloutStatePartialFailed || partial.Progress.Succeeded != 1 || partial.Progress.Failed != 1 || !partial.CanRetry {
		t.Fatalf("partial rollout = %+v, %v", partial, err)
	}
	retried, err := store.RetryRollout(context.Background(), RolloutCommandRequest{
		Actor: actor, ConfigurationScopeID: scopeID, RolloutID: retryCreated.Rollout.ID,
		ExpectedRevision: partial.Revision, IdempotencyKey: "retry-failed-node", RequestID: uuid.NewString(),
	})
	if err != nil || retried.Rollout.State != RolloutStateRunning || retried.Rollout.Progress.Succeeded != 1 || retried.Rollout.Progress.Pending != 1 {
		t.Fatalf("retried rollout = %+v, %v", retried, err)
	}
	var attempts, newOutbox int
	if err := pool.QueryRow(context.Background(), `
		SELECT count(*),count(*) FILTER (WHERE outbox.deployment_attempt=2)
		FROM node_deployments deployment
		LEFT JOIN edge_command_outbox outbox
		  ON outbox.deployment_id=deployment.id AND outbox.deployment_attempt=deployment.attempt
		WHERE deployment.rollout_id=$1`, retryCreated.Rollout.ID).Scan(&attempts, &newOutbox); err != nil {
		t.Fatal(err)
	}
	if attempts != 3 || newOutbox != 1 {
		t.Fatalf("retry attempts=%d second-attempt-outbox=%d", attempts, newOutbox)
	}
	firstRolloutPage, err := store.ListRollouts(context.Background(), actor, scopeID, RolloutPageRequest{Limit: 1})
	if err != nil || len(firstRolloutPage.Items) != 1 || firstRolloutPage.NextCursor == "" {
		t.Fatalf("first rollout page = %+v, %v", firstRolloutPage, err)
	}
	secondRolloutPage, err := store.ListRollouts(context.Background(), actor, scopeID, RolloutPageRequest{
		Limit: 1, Cursor: firstRolloutPage.NextCursor,
	})
	if err != nil || len(secondRolloutPage.Items) != 1 || secondRolloutPage.NextCursor != "" ||
		secondRolloutPage.Items[0].ID == firstRolloutPage.Items[0].ID {
		t.Fatalf("second rollout page = %+v, %v", secondRolloutPage, err)
	}
	otherScopeID, _ := seedEdgeScope(t, pool)
	emptyRolloutPage, err := store.ListRollouts(context.Background(), actor, otherScopeID, RolloutPageRequest{})
	if err != nil || len(emptyRolloutPage.Items) != 0 {
		t.Fatalf("cross-tenant rollout page = %+v, %v", emptyRolloutPage, err)
	}
}

func TestRolloutCommandsRejectUnsafeBoundaries(t *testing.T) {
	fixture := newCommandIAMFixture(t, nil)
	pool, store := fixture.pool, fixture.store
	platformScopeID := seedCommandScope(t, pool, ScopeKindPlatform)
	actor := fixture.seedActor(t, platformScopeID, ScopeKindPlatform, PermissionRead, PermissionManage)
	scopeID, userID := seedEdgeScope(t, pool)
	config := persistQueryTestConfig(t, store, scopeID)
	nodeID := uuid.New()
	seedEdgeNode(t, pool, scopeID, userID, nodeID)
	request := testRolloutRequest(scopeID, config.ID, []uuid.UUID{nodeID}, "unsafe-command")
	request.MaxAttempts = 1
	created, err := store.CreateRollout(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	advanceDeploymentState(t, pool, created.Rollout.Deployments[0].ID, "delivered")
	rollout, err := store.GetRollout(context.Background(), actor, scopeID, created.Rollout.ID)
	if err != nil {
		t.Fatal(err)
	}
	command := RolloutCommandRequest{Actor: actor, ConfigurationScopeID: scopeID, RolloutID: created.Rollout.ID,
		ExpectedRevision: rollout.Revision, IdempotencyKey: "unsafe-cancel", RequestID: uuid.NewString()}
	if _, err := store.CancelRollout(context.Background(), command); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("delivered cancel error = %v", err)
	}
	advanceDeploymentState(t, pool, created.Rollout.Deployments[0].ID, "failed")
	failed, err := store.GetRollout(context.Background(), actor, scopeID, created.Rollout.ID)
	if err != nil {
		t.Fatal(err)
	}
	command.ExpectedRevision = failed.Revision
	command.IdempotencyKey = "retry-exhausted"
	if _, err := store.RetryRollout(context.Background(), command); !errors.Is(err, ErrRetriesExhausted) {
		t.Fatalf("exhausted retry error = %v", err)
	}
}

func TestConcurrentRolloutCancellationHasOneCASWinner(t *testing.T) {
	fixture := newCommandIAMFixture(t, nil)
	pool, store := fixture.pool, fixture.store
	platformScopeID := seedCommandScope(t, pool, ScopeKindPlatform)
	actor := fixture.seedActor(t, platformScopeID, ScopeKindPlatform, PermissionRead, PermissionManage)
	scopeID, userID := seedEdgeScope(t, pool)
	config := persistQueryTestConfig(t, store, scopeID)
	nodeID := uuid.New()
	seedEdgeNode(t, pool, scopeID, userID, nodeID)
	created, err := store.CreateRollout(context.Background(), testRolloutRequest(
		scopeID, config.ID, []uuid.UUID{nodeID}, "concurrent-cancel",
	))
	if err != nil {
		t.Fatal(err)
	}
	rollout, err := store.GetRollout(context.Background(), actor, scopeID, created.Rollout.ID)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	errs := make([]error, 2)
	var wait sync.WaitGroup
	for index := range errs {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			_, errs[index] = store.CancelRollout(context.Background(), RolloutCommandRequest{
				Actor: actor, ConfigurationScopeID: scopeID, RolloutID: created.Rollout.ID,
				ExpectedRevision: rollout.Revision,
				IdempotencyKey:   "concurrent-cancel-" + string(rune('a'+index)),
				RequestID:        uuid.NewString(),
			})
		}(index)
	}
	close(start)
	wait.Wait()
	successes, conflicts := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrRevisionConflict):
			conflicts++
		default:
			t.Fatalf("concurrent cancellation error = %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent cancellation successes=%d conflicts=%d", successes, conflicts)
	}
	var requests int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM edge_rollout_write_requests`).Scan(&requests); err != nil {
		t.Fatal(err)
	}
	if requests != 1 {
		t.Fatalf("persisted concurrent cancellation requests = %d", requests)
	}
}

func advanceDeploymentState(t *testing.T, pool *pgxpool.Pool, deploymentID uuid.UUID, state string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		UPDATE node_deployments SET state=$2,updated_at=updated_at+interval '1 second'
		WHERE id=$1 AND attempt=(SELECT max(attempt) FROM node_deployments WHERE id=$1)`, deploymentID, state); err != nil {
		t.Fatal(err)
	}
}

func persistQueryTestConfig(t *testing.T, store *Store, scopeID uuid.UUID) ConfigVersion {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return persistTestConfig(t, store, testConfigRequest(t, scopeID, "query-config", "query-key", publicKey, privateKey, []byte("query config")))
}
