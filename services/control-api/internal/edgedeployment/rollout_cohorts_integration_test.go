//go:build integration

package edgedeployment

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCreateRolloutIdempotencyReplayAfterCompletion(t *testing.T) {
	fixture := newCommandIAMFixture(t, nil)
	commandClock := integrationClock
	fixture.store.now = func() time.Time { return commandClock }
	tenantScopeID, tenantUserID := seedEdgeScope(t, fixture.pool)
	configID := fixture.persistConfig(t, tenantScopeID, "completed-rollout-replay-config")
	nodeID := uuid.New()
	seedCohortNode(t, fixture.pool, tenantScopeID, tenantUserID, nodeID)

	request := progressiveRolloutRequest(
		tenantScopeID, configID, []uuid.UUID{nodeID}, "completed-rollout-replay", true,
	)
	request.Rollout.BatchSize = 1
	created, err := fixture.store.CreateRollout(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	setCohortOutboxStatus(t, fixture.pool, created.Rollout.ID, nodeID, "publishing")
	setCohortOutboxStatus(t, fixture.pool, created.Rollout.ID, nodeID, "published")
	advanceCohortDeployment(t, fixture.pool, created.Rollout.ID, nodeID,
		"delivered", "staged", "prechecked", "activated", "healthy")
	advanceCohortProjection(t, fixture.pool, created.Rollout.ID, integrationClock.Add(6*time.Second))
	assertRolloutFacts(t, fixture.pool, created.Rollout.ID, "completed", 2, 0, "", 0, 0)

	commandClock = request.Deadline
	replay, err := fixture.store.CreateRollout(t.Context(), request)
	if err != nil || !replay.Replayed || replay.Rollout.ID != created.Rollout.ID {
		t.Fatalf("completed rollout replay=%+v error=%v", replay, err)
	}
	conflict := request
	conflict.MaxAttempts++
	if _, err := fixture.store.CreateRollout(t.Context(), conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("completed rollout conflict error=%v", err)
	}
	expired := request
	expired.IdempotencyKey = "completed-rollout-expired-new"
	expired.RequestID = uuid.NewString()
	if _, err := fixture.store.CreateRollout(t.Context(), expired); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("new expired rollout error=%v", err)
	}
	var rollouts, deployments int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM rollouts WHERE configuration_scope_id=$1),
		(SELECT count(*) FROM node_deployments WHERE rollout_id=$2)`,
		tenantScopeID, created.Rollout.ID).Scan(&rollouts, &deployments); err != nil {
		t.Fatal(err)
	}
	if rollouts != 1 || deployments != 1 {
		t.Fatalf("expired replay side effects rollouts=%d deployments=%d", rollouts, deployments)
	}
}

func TestCreateRolloutConcurrentReplayWaitsForUncommittedWinnerAfterDeadline(t *testing.T) {
	fixture := newCommandIAMFixture(t, nil)
	tenantScopeID, tenantUserID := seedEdgeScope(t, fixture.pool)
	configID := fixture.persistConfig(t, tenantScopeID, "concurrent-expired-replay-config")
	nodeID := uuid.New()
	seedCohortNode(t, fixture.pool, tenantScopeID, tenantUserID, nodeID)
	deadline := integrationClock.Add(time.Hour)
	request := progressiveRolloutRequest(
		tenantScopeID, configID, []uuid.UUID{nodeID}, "concurrent-expired-replay", true,
	)
	request.Rollout.BatchSize = 1
	request.Deadline = deadline

	freshStore, err := NewStoreWithClock(fixture.pool, func() time.Time { return deadline.Add(-time.Microsecond) })
	if err != nil {
		t.Fatal(err)
	}
	expiredStore, err := NewStoreWithClock(fixture.pool, func() time.Time { return deadline })
	if err != nil {
		t.Fatal(err)
	}
	winnerTx, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = winnerTx.Rollback(t.Context()) }()
	winner, err := freshStore.CreateRolloutTx(t.Context(), winnerTx, request)
	if err != nil {
		t.Fatal(err)
	}

	type replayResult struct {
		value CreateRolloutResult
		err   error
	}
	replayed := make(chan replayResult, 1)
	go func() {
		value, replayErr := expiredStore.CreateRollout(t.Context(), request)
		replayed <- replayResult{value: value, err: replayErr}
	}()
	select {
	case result := <-replayed:
		t.Fatalf("concurrent replay returned before winner commit: %+v error=%v", result.value, result.err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := winnerTx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	result := <-replayed
	if result.err != nil || !result.value.Replayed || result.value.Rollout.ID != winner.Rollout.ID {
		t.Fatalf("concurrent expired replay=%+v error=%v winner=%s", result.value, result.err, winner.Rollout.ID)
	}
	var rollouts, deployments int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM rollouts WHERE configuration_scope_id=$1),
		(SELECT count(*) FROM node_deployments WHERE rollout_id=$2)`,
		tenantScopeID, winner.Rollout.ID).Scan(&rollouts, &deployments); err != nil {
		t.Fatal(err)
	}
	if rollouts != 1 || deployments != 1 {
		t.Fatalf("concurrent replay facts rollouts=%d deployments=%d", rollouts, deployments)
	}
}

func TestCreateRolloutSamplesDeadlineAfterIdempotencyLock(t *testing.T) {
	fixture := newCommandIAMFixture(t, nil)
	tenantScopeID, tenantUserID := seedEdgeScope(t, fixture.pool)
	configID := fixture.persistConfig(t, tenantScopeID, "deadline-after-lock-config")
	nodeID := uuid.New()
	seedCohortNode(t, fixture.pool, tenantScopeID, tenantUserID, nodeID)
	request := progressiveRolloutRequest(
		tenantScopeID, configID, []uuid.UUID{nodeID}, "deadline-after-lock", true,
	)
	request.Rollout.BatchSize = 1
	request.Deadline = integrationClock.Add(time.Hour)

	blocker, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Rollback(t.Context()) }()
	if _, err := blocker.Exec(t.Context(), `SELECT pg_catalog.pg_advisory_xact_lock(
		pg_catalog.hashtextextended('edge-rollout-idempotency:v1:' || $1::text || ':' || $2,0))`,
		request.ConfigurationScopeID, request.IdempotencyKey); err != nil {
		t.Fatal(err)
	}
	clockSampled := make(chan struct{}, 1)
	store, err := NewStoreWithClock(fixture.pool, func() time.Time {
		clockSampled <- struct{}{}
		return request.Deadline
	})
	if err != nil {
		t.Fatal(err)
	}
	type createResult struct {
		value CreateRolloutResult
		err   error
	}
	created := make(chan createResult, 1)
	go func() {
		value, createErr := store.CreateRollout(t.Context(), request)
		created <- createResult{value: value, err: createErr}
	}()
	select {
	case <-clockSampled:
		t.Fatal("deadline clock sampled before idempotency lock was acquired")
	case <-time.After(100 * time.Millisecond):
	}
	if err := blocker.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-clockSampled:
	case <-time.After(time.Second):
		t.Fatal("deadline clock was not sampled after idempotency lock release")
	}
	result := <-created
	if !errors.Is(result.err, ErrInvalidInput) {
		t.Fatalf("expired create after lock result=%+v error=%v", result.value, result.err)
	}
	var rollouts int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM rollouts
		WHERE configuration_scope_id=$1`, tenantScopeID).Scan(&rollouts); err != nil {
		t.Fatal(err)
	}
	if rollouts != 0 {
		t.Fatalf("expired create after lock persisted %d rollouts", rollouts)
	}
}

func TestProgressiveRolloutCohortLifecycle(t *testing.T) {
	fixture := newCommandIAMFixture(t, nil)
	commandClock := integrationClock
	fixture.store.now = func() time.Time { return commandClock }
	actor := seedCohortPlatformOwner(t, fixture)
	tenantScopeID, tenantUserID := seedEdgeScope(t, fixture.pool)
	configID := fixture.persistConfig(t, tenantScopeID, "cohort-lifecycle-config")
	nodeIDs := []uuid.UUID{
		uuid.MustParse("018cc251-f400-7def-8000-000000000005"),
		uuid.MustParse("018cc251-f400-7def-8000-000000000001"),
		uuid.MustParse("018cc251-f400-7def-8000-000000000004"),
		uuid.MustParse("018cc251-f400-7def-8000-000000000002"),
		uuid.MustParse("018cc251-f400-7def-8000-000000000003"),
	}
	for _, nodeID := range nodeIDs {
		seedCohortNode(t, fixture.pool, tenantScopeID, tenantUserID, nodeID)
	}

	request := progressiveRolloutRequest(tenantScopeID, configID, nodeIDs, "cohort-lifecycle", false)
	created, err := fixture.store.CreateRollout(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	rolloutID := created.Rollout.ID
	assertCohortAssignments(t, fixture.pool, rolloutID, map[uuid.UUID]int{
		nodeIDs[1]: 0,
		nodeIDs[3]: 1,
		nodeIDs[4]: 1,
		nodeIDs[2]: 2,
		nodeIDs[0]: 2,
	})
	assertRolloutFacts(t, fixture.pool, rolloutID, "queued", 1, -1, "", 0, 5)

	start := commandRequest(actor, tenantScopeID, commandRollout{ID: rolloutID, Revision: 1}, "cohort-start")
	started, err := fixture.store.StartRollout(t.Context(), start)
	if err != nil {
		t.Fatal(err)
	}
	if started.Rollout.State != RolloutStateRunning || started.Rollout.Revision != 2 || !started.Rollout.CanPause {
		t.Fatalf("started rollout=%+v", started.Rollout)
	}
	assertRolloutFacts(t, fixture.pool, rolloutID, "running", 2, 0, "", 0, 4)
	replayed, err := fixture.store.StartRollout(t.Context(), start)
	if err != nil || !replayed.Replayed || replayed.Rollout.Revision != 2 {
		t.Fatalf("start replay=%+v error=%v", replayed, err)
	}
	conflict := commandRequest(actor, tenantScopeID, commandRollout{ID: rolloutID, Revision: 1}, "cohort-start-stale")
	if _, err := fixture.store.PauseRollout(t.Context(), conflict); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale pause error=%v, want %v", err, ErrRevisionConflict)
	}
	assertRolloutCommandAudit(t, fixture.pool, rolloutID, rolloutOperationStart, 1)

	canaryID := nodeIDs[1]
	setCohortOutboxStatus(t, fixture.pool, rolloutID, canaryID, "publishing")
	paused, err := fixture.store.PauseRollout(t.Context(), commandRequest(
		actor, tenantScopeID, commandRollout{ID: rolloutID, Revision: 2}, "cohort-pause",
	))
	if err != nil {
		t.Fatal(err)
	}
	if paused.Rollout.State != RolloutStatePaused || paused.Rollout.PauseReason != "operator" {
		t.Fatalf("paused rollout=%+v", paused.Rollout)
	}
	advanceCohortDeployment(t, fixture.pool, rolloutID, canaryID, "delivered", "staged", "prechecked", "activated", "healthy")
	advanceCohortProjection(t, fixture.pool, rolloutID, integrationClock.Add(time.Second))
	advanceCohortProjection(t, fixture.pool, rolloutID, integrationClock.Add(2*time.Second))
	assertRolloutFacts(t, fixture.pool, rolloutID, "paused", 3, 0, "operator", 0, 4)

	resumed, err := fixture.store.ResumeRollout(t.Context(), commandRequest(
		actor, tenantScopeID, commandRollout{ID: rolloutID, Revision: 3}, "cohort-resume-next",
	))
	if err != nil {
		t.Fatal(err)
	}
	if resumed.Rollout.State != RolloutStateRunning || resumed.Rollout.ReleasedCohort != 1 {
		t.Fatalf("resumed rollout=%+v", resumed.Rollout)
	}
	assertRolloutFacts(t, fixture.pool, rolloutID, "running", 4, 1, "", 0, 2)

	cohortOne := []uuid.UUID{nodeIDs[3], nodeIDs[4]}
	setCohortOutboxStatus(t, fixture.pool, rolloutID, cohortOne[0], "publishing")
	setCohortOutboxStatus(t, fixture.pool, rolloutID, cohortOne[0], "published")
	advanceCohortDeployment(t, fixture.pool, rolloutID, cohortOne[0], "delivered", "failed")
	advanceCohortProjection(t, fixture.pool, rolloutID, integrationClock.Add(3*time.Second))
	assertRolloutFacts(t, fixture.pool, rolloutID, "paused", 5, 1, "failure_threshold", 1, 3)
	advanceCohortProjection(t, fixture.pool, rolloutID, integrationClock.Add(4*time.Second))
	assertRolloutFacts(t, fixture.pool, rolloutID, "paused", 5, 1, "failure_threshold", 1, 3)

	commandClock = integrationClock.Add(5 * time.Second)
	retried, err := fixture.store.RetryRollout(t.Context(), commandRequest(
		actor, tenantScopeID, commandRollout{ID: rolloutID, Revision: 5}, "cohort-retry-current",
	))
	if err != nil {
		t.Fatal(err)
	}
	if retried.Rollout.State != RolloutStatePaused || retried.Rollout.Revision != 6 ||
		retried.Rollout.ReleasedCohort != 1 || retried.Rollout.PauseReason != "failure_threshold" {
		t.Fatalf("retried rollout=%+v", retried.Rollout)
	}
	assertRolloutFacts(t, fixture.pool, rolloutID, "paused", 6, 1, "failure_threshold", 1, 4)

	commandClock = integrationClock.Add(6 * time.Second)
	resumed, err = fixture.store.ResumeRollout(t.Context(), commandRequest(
		actor, tenantScopeID, commandRollout{ID: rolloutID, Revision: 6}, "cohort-resume-current",
	))
	if err != nil {
		t.Fatal(err)
	}
	if resumed.Rollout.State != RolloutStateRunning || resumed.Rollout.Revision != 7 ||
		resumed.Rollout.ReleasedCohort != 1 {
		t.Fatalf("resumed retry rollout=%+v", resumed.Rollout)
	}
	assertRolloutFacts(t, fixture.pool, rolloutID, "running", 7, 1, "", 1, 2)

	setLatestCohortOutboxStatus(t, fixture.pool, rolloutID, cohortOne[0], "publishing")
	setLatestCohortOutboxStatus(t, fixture.pool, rolloutID, cohortOne[0], "published")
	var retriedDeploymentID uuid.UUID
	if err := fixture.pool.QueryRow(t.Context(), `SELECT id FROM node_deployments
		WHERE rollout_id=$1 AND node_id=$2 AND attempt=2`, rolloutID, cohortOne[0]).Scan(&retriedDeploymentID); err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"delivered", "staged", "prechecked", "activated", "healthy"} {
		advanceDeploymentState(t, fixture.pool, retriedDeploymentID, state)
	}
	setCohortOutboxStatus(t, fixture.pool, rolloutID, cohortOne[1], "publishing")
	setCohortOutboxStatus(t, fixture.pool, rolloutID, cohortOne[1], "published")
	advanceCohortDeployment(t, fixture.pool, rolloutID, cohortOne[1], "delivered", "staged", "prechecked", "activated", "healthy")
	advanceCohortProjection(t, fixture.pool, rolloutID, integrationClock.Add(11*time.Second))
	assertRolloutFacts(t, fixture.pool, rolloutID, "running", 8, 2, "", 1, 0)

	cohortTwo := []uuid.UUID{nodeIDs[2], nodeIDs[0]}
	for index, nodeID := range cohortTwo {
		setCohortOutboxStatus(t, fixture.pool, rolloutID, nodeID, "publishing")
		setCohortOutboxStatus(t, fixture.pool, rolloutID, nodeID, "published")
		advanceCohortDeployment(t, fixture.pool, rolloutID, nodeID, "delivered", "staged", "prechecked", "activated", "healthy")
		advanceCohortProjection(t, fixture.pool, rolloutID, integrationClock.Add(time.Duration(12+index)*time.Second))
	}
	assertRolloutFacts(t, fixture.pool, rolloutID, "completed", 9, 2, "", 1, 0)
	advanceCohortProjection(t, fixture.pool, rolloutID, integrationClock.Add(15*time.Second))
	assertRolloutFacts(t, fixture.pool, rolloutID, "completed", 9, 2, "", 1, 0)

	commandClock = integrationClock
	assertProgressiveCancelAndLateFact(t, fixture, actor, tenantScopeID, tenantUserID, configID)
	assertLegacyOutboxesRemainPending(t, fixture, tenantScopeID, tenantUserID, configID)
}

func TestOperatorPausedCanaryRetryKeepsFollowingCohortHeldAndResumesProgress(t *testing.T) {
	fixture := newCommandIAMFixture(t, nil)
	actor := seedCohortPlatformOwner(t, fixture)
	tenantScopeID, tenantUserID := seedEdgeScope(t, fixture.pool)
	configID := fixture.persistConfig(t, tenantScopeID, "cohort-retry-config")
	canaryNodeID := uuid.MustParse("018cc251-f400-7def-8000-000000000011")
	followingNodeID := uuid.MustParse("018cc251-f400-7def-8000-000000000012")
	for _, nodeID := range []uuid.UUID{canaryNodeID, followingNodeID} {
		seedCohortNode(t, fixture.pool, tenantScopeID, tenantUserID, nodeID)
	}

	request := progressiveRolloutRequest(tenantScopeID, configID,
		[]uuid.UUID{followingNodeID, canaryNodeID}, "cohort-retry", false)
	request.MaxAttempts = 2
	created, err := fixture.store.CreateRollout(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	rolloutID := created.Rollout.ID
	started, err := fixture.store.StartRollout(t.Context(), commandRequest(
		actor, tenantScopeID, commandRollout{ID: rolloutID, Revision: created.Rollout.Revision}, "cohort-retry-start",
	))
	if err != nil {
		t.Fatal(err)
	}
	setLatestCohortOutboxStatus(t, fixture.pool, rolloutID, canaryNodeID, "publishing")
	setLatestCohortOutboxStatus(t, fixture.pool, rolloutID, canaryNodeID, "published")
	if _, err := fixture.store.PauseRollout(t.Context(), commandRequest(
		actor, tenantScopeID, commandRollout{ID: rolloutID, Revision: started.Rollout.Revision}, "cohort-retry-pause",
	)); err != nil {
		t.Fatal(err)
	}
	advanceCohortDeployment(t, fixture.pool, rolloutID, canaryNodeID, "delivered", "failed")
	advanceCohortProjection(t, fixture.pool, rolloutID, integrationClock)

	paused, err := fixture.store.GetRollout(t.Context(), actor, tenantScopeID, rolloutID)
	if err != nil {
		t.Fatal(err)
	}
	if paused.State != RolloutStatePaused || paused.Revision != 3 || paused.ReleasedCohort != 0 ||
		paused.PauseReason != "operator" {
		t.Fatalf("paused rollout=%+v", paused)
	}
	command := commandRequest(actor, tenantScopeID,
		commandRollout{ID: rolloutID, Revision: paused.Revision}, "cohort-retry-failed-canary")
	retried, err := fixture.store.RetryRollout(t.Context(), command)
	if err != nil {
		t.Fatalf("retry paused canary: %v", err)
	}
	if !paused.CanRetry || !paused.CanResume || retried.Rollout.State != RolloutStatePaused ||
		retried.Rollout.Revision != 4 || retried.Rollout.ReleasedCohort != 0 ||
		retried.Rollout.PauseReason != "operator" || retried.Rollout.CanRetry || !retried.Rollout.CanResume {
		t.Fatalf("retry snapshots paused=%+v retried=%+v", paused, retried.Rollout)
	}
	assertRolloutFacts(t, fixture.pool, rolloutID, "paused", 4, 0, "operator", 1, 2)
	assertCohortRetryRows(t, fixture.pool, rolloutID, canaryNodeID, followingNodeID, "held")

	replayRequest := command
	replayRequest.RequestID = uuid.NewString()
	replay, err := fixture.store.RetryRollout(t.Context(), replayRequest)
	if err != nil || !replay.Replayed || replay.Rollout.Revision != 4 {
		t.Fatalf("retry replay=%+v error=%v", replay, err)
	}
	stale := command
	stale.IdempotencyKey = "cohort-retry-stale-revision"
	stale.RequestID = uuid.NewString()
	if _, err := fixture.store.RetryRollout(t.Context(), stale); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("retry stale revision error=%v", err)
	}
	assertCohortRetryRows(t, fixture.pool, rolloutID, canaryNodeID, followingNodeID, "held")
	assertRolloutCommandAudit(t, fixture.pool, rolloutID, rolloutOperationRetry, 1)

	resumed, err := fixture.store.ResumeRollout(t.Context(), commandRequest(
		actor, tenantScopeID, commandRollout{ID: rolloutID, Revision: retried.Rollout.Revision}, "cohort-retry-resume",
	))
	if err != nil {
		t.Fatal(err)
	}
	if resumed.Rollout.State != RolloutStateRunning || resumed.Rollout.Revision != 5 ||
		resumed.Rollout.ReleasedCohort != 0 || resumed.Rollout.CanRetry {
		t.Fatalf("resumed retry rollout=%+v", resumed.Rollout)
	}
	assertRolloutFacts(t, fixture.pool, rolloutID, "running", 5, 0, "", 1, 1)
	assertCohortRetryRows(t, fixture.pool, rolloutID, canaryNodeID, followingNodeID, "pending")

	setLatestCohortOutboxStatus(t, fixture.pool, rolloutID, canaryNodeID, "publishing")
	setLatestCohortOutboxStatus(t, fixture.pool, rolloutID, canaryNodeID, "published")
	var canaryDeploymentID uuid.UUID
	if err := fixture.pool.QueryRow(t.Context(), `SELECT id FROM node_deployments
		WHERE rollout_id=$1 AND node_id=$2 LIMIT 1`, rolloutID, canaryNodeID).Scan(&canaryDeploymentID); err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"delivered", "staged", "prechecked", "activated", "healthy"} {
		advanceDeploymentState(t, fixture.pool, canaryDeploymentID, state)
	}
	advanceCohortProjection(t, fixture.pool, rolloutID, integrationClock.Add(2*time.Second))

	recovered, err := fixture.store.GetRollout(t.Context(), actor, tenantScopeID, rolloutID)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.State != RolloutStateRunning || recovered.Revision != 6 || recovered.ReleasedCohort != 1 ||
		recovered.CanRetry {
		t.Fatalf("recovered rollout=%+v", recovered)
	}
	var followingPending int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*)
		FROM edge_command_outbox outbox JOIN node_deployments deployment
		  ON deployment.id=outbox.deployment_id AND deployment.attempt=outbox.deployment_attempt
		WHERE deployment.rollout_id=$1 AND deployment.node_id=$2 AND outbox.status='pending'`,
		rolloutID, followingNodeID).Scan(&followingPending); err != nil {
		t.Fatal(err)
	}
	if followingPending != 1 {
		t.Fatalf("following cohort pending=%d want=1", followingPending)
	}
}

func TestOperatorPausedCanaryRetryRejectsExhaustedAttempt(t *testing.T) {
	fixture := newCommandIAMFixture(t, nil)
	actor := seedCohortPlatformOwner(t, fixture)
	tenantScopeID, tenantUserID := seedEdgeScope(t, fixture.pool)
	configID := fixture.persistConfig(t, tenantScopeID, "cohort-retry-exhausted-config")
	canaryNodeID := uuid.MustParse("018cc251-f400-7def-8000-000000000021")
	followingNodeID := uuid.MustParse("018cc251-f400-7def-8000-000000000022")
	for _, nodeID := range []uuid.UUID{canaryNodeID, followingNodeID} {
		seedCohortNode(t, fixture.pool, tenantScopeID, tenantUserID, nodeID)
	}
	request := progressiveRolloutRequest(tenantScopeID, configID,
		[]uuid.UUID{followingNodeID, canaryNodeID}, "cohort-retry-exhausted", false)
	request.MaxAttempts = 1
	created, err := fixture.store.CreateRollout(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	started, err := fixture.store.StartRollout(t.Context(), commandRequest(
		actor, tenantScopeID, commandRollout{ID: created.Rollout.ID, Revision: created.Rollout.Revision},
		"cohort-retry-exhausted-start",
	))
	if err != nil {
		t.Fatal(err)
	}
	setLatestCohortOutboxStatus(t, fixture.pool, created.Rollout.ID, canaryNodeID, "publishing")
	setLatestCohortOutboxStatus(t, fixture.pool, created.Rollout.ID, canaryNodeID, "published")
	if _, err := fixture.store.PauseRollout(t.Context(), commandRequest(
		actor, tenantScopeID, commandRollout{ID: created.Rollout.ID, Revision: started.Rollout.Revision},
		"cohort-retry-exhausted-pause",
	)); err != nil {
		t.Fatal(err)
	}
	advanceCohortDeployment(t, fixture.pool, created.Rollout.ID, canaryNodeID, "delivered", "failed")
	paused, err := fixture.store.GetRollout(t.Context(), actor, tenantScopeID, created.Rollout.ID)
	if err != nil {
		t.Fatal(err)
	}
	if paused.State != RolloutStatePaused || paused.Revision != 3 || paused.CanRetry {
		t.Fatalf("exhausted paused rollout=%+v", paused)
	}
	if _, err := fixture.store.RetryRollout(t.Context(), commandRequest(
		actor, tenantScopeID, commandRollout{ID: created.Rollout.ID, Revision: paused.Revision},
		"cohort-retry-exhausted-command",
	)); !errors.Is(err, ErrRetriesExhausted) {
		t.Fatalf("exhausted retry error=%v", err)
	}
	assertRolloutFacts(t, fixture.pool, created.Rollout.ID, "paused", 3, 0, "operator", 1, 1)
	var attempts int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM node_deployments
		WHERE rollout_id=$1 AND node_id=$2`, created.Rollout.ID, canaryNodeID).Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if attempts != 1 {
		t.Fatalf("exhausted retry attempts=%d want=1", attempts)
	}
	assertRolloutCommandAudit(t, fixture.pool, created.Rollout.ID, rolloutOperationRetry, 0)
}

func TestPausedCanaryRetryDeadlineBoundariesAndReplay(t *testing.T) {
	fixture := newCommandIAMFixture(t, nil)
	commandClock := integrationClock
	fixture.store.now = func() time.Time { return commandClock }
	actor := seedCohortPlatformOwner(t, fixture)
	tenantScopeID, tenantUserID := seedEdgeScope(t, fixture.pool)
	configID := fixture.persistConfig(t, tenantScopeID, "cohort-retry-deadline-config")
	deadline := integrationClock.Add(time.Hour)

	createPausedFailure := func(key string) (RolloutSnapshot, RolloutCommandRequest) {
		nodeIDs := []uuid.UUID{uuid.New(), uuid.New()}
		for _, nodeID := range nodeIDs {
			seedCohortNode(t, fixture.pool, tenantScopeID, tenantUserID, nodeID)
		}
		request := progressiveRolloutRequest(tenantScopeID, configID, nodeIDs, key, false)
		request.MaxAttempts = 2
		request.Deadline = deadline
		created, err := fixture.store.CreateRollout(t.Context(), request)
		if err != nil {
			t.Fatal(err)
		}
		var canaryNodeID uuid.UUID
		if err := fixture.pool.QueryRow(t.Context(), `SELECT node_id FROM node_deployments
			WHERE rollout_id=$1 AND cohort=0`, created.Rollout.ID).Scan(&canaryNodeID); err != nil {
			t.Fatal(err)
		}
		started, err := fixture.store.StartRollout(t.Context(), commandRequest(
			actor, tenantScopeID, commandRollout{ID: created.Rollout.ID, Revision: created.Rollout.Revision}, key+"-start",
		))
		if err != nil {
			t.Fatal(err)
		}
		setLatestCohortOutboxStatus(t, fixture.pool, created.Rollout.ID, canaryNodeID, "publishing")
		setLatestCohortOutboxStatus(t, fixture.pool, created.Rollout.ID, canaryNodeID, "published")
		if _, err := fixture.store.PauseRollout(t.Context(), commandRequest(
			actor, tenantScopeID, commandRollout{ID: created.Rollout.ID, Revision: started.Rollout.Revision}, key+"-pause",
		)); err != nil {
			t.Fatal(err)
		}
		advanceCohortDeployment(t, fixture.pool, created.Rollout.ID, canaryNodeID, "delivered", "failed")
		advanceCohortProjection(t, fixture.pool, created.Rollout.ID, integrationClock)
		paused, err := fixture.store.GetRollout(t.Context(), actor, tenantScopeID, created.Rollout.ID)
		if err != nil || !paused.CanRetry || paused.Revision != 3 {
			t.Fatalf("paused rollout=%+v error=%v", paused, err)
		}
		return paused, commandRequest(
			actor, tenantScopeID, commandRollout{ID: paused.ID, Revision: paused.Revision}, key+"-retry",
		)
	}

	before, beforeCommand := createPausedFailure("cohort-retry-before-deadline")
	commandClock = deadline.Add(-time.Microsecond)
	retried, err := fixture.store.RetryRollout(t.Context(), beforeCommand)
	if err != nil || retried.Rollout.Revision != before.Revision+1 {
		t.Fatalf("retry before deadline=%+v error=%v", retried, err)
	}
	commandClock = deadline
	replayCommand := beforeCommand
	replayCommand.RequestID = uuid.NewString()
	replay, err := fixture.store.RetryRollout(t.Context(), replayCommand)
	if err != nil || !replay.Replayed || replay.Rollout.Revision != retried.Rollout.Revision {
		t.Fatalf("retry replay at deadline=%+v error=%v", replay, err)
	}

	commandClock = integrationClock
	expired, expiredCommand := createPausedFailure("cohort-retry-expired")
	commandClock = deadline
	atDeadline, err := fixture.store.GetRollout(t.Context(), actor, tenantScopeID, expired.ID)
	if err != nil || atDeadline.CanRetry {
		t.Fatalf("rollout at deadline=%+v error=%v", atDeadline, err)
	}
	deployments, err := fixture.store.ListDeployments(
		t.Context(), actor, tenantScopeID, expired.ID, DeploymentPageRequest{},
	)
	if err != nil || len(deployments.Items) != 2 {
		t.Fatalf("deployments at deadline=%+v error=%v", deployments, err)
	}
	for _, deployment := range deployments.Items {
		if deployment.CanRetry {
			t.Fatalf("deployment remained retryable at deadline: %+v", deployment)
		}
	}
	if _, err := fixture.store.RetryRollout(t.Context(), expiredCommand); !errors.Is(err, ErrDeadlineExpired) {
		t.Fatalf("retry at deadline error=%v", err)
	}

	commandClock = deadline.Add(time.Microsecond)
	afterDeadline, err := fixture.store.GetRollout(t.Context(), actor, tenantScopeID, expired.ID)
	if err != nil || afterDeadline.CanRetry {
		t.Fatalf("rollout after deadline=%+v error=%v", afterDeadline, err)
	}
	afterCommand := expiredCommand
	afterCommand.IdempotencyKey += "-after"
	afterCommand.RequestID = uuid.NewString()
	if _, err := fixture.store.RetryRollout(t.Context(), afterCommand); !errors.Is(err, ErrDeadlineExpired) {
		t.Fatalf("retry after deadline error=%v", err)
	}

	var revision int64
	var attempts, retryRequests, retryAudits int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT
		(SELECT revision FROM rollouts WHERE id=$1),
		(SELECT count(*) FROM node_deployments WHERE rollout_id=$1),
		(SELECT count(*) FROM edge_rollout_write_requests WHERE rollout_id=$1 AND operation=$2),
		(SELECT count(*) FROM audit_events WHERE resource_type='edge_rollout' AND resource_id=$1::text AND action=$2)`,
		expired.ID, rolloutOperationRetry).Scan(&revision, &attempts, &retryRequests, &retryAudits); err != nil {
		t.Fatal(err)
	}
	if revision != expired.Revision || attempts != 2 || retryRequests != 0 || retryAudits != 0 {
		t.Fatalf("expired retry side effects revision=%d attempts=%d requests=%d audits=%d",
			revision, attempts, retryRequests, retryAudits)
	}
}

func assertCohortRetryRows(
	t *testing.T,
	pool *pgxpool.Pool,
	rolloutID, canaryNodeID, followingNodeID uuid.UUID,
	retryOutboxStatus string,
) {
	t.Helper()
	var failedOriginal, queuedRetry, retryPending, followingOriginal, followingHeld int
	if err := pool.QueryRow(t.Context(), `SELECT
		count(*) FILTER (WHERE deployment.node_id=$2 AND deployment.attempt=1 AND deployment.state='failed'),
		count(*) FILTER (WHERE deployment.node_id=$2 AND deployment.attempt=2 AND deployment.state='queued' AND deployment.cohort=0),
		count(*) FILTER (WHERE deployment.node_id=$2 AND deployment.attempt=2 AND outbox.status=$4),
		count(*) FILTER (WHERE deployment.node_id=$3 AND deployment.attempt=1 AND deployment.cohort=1),
		count(*) FILTER (WHERE deployment.node_id=$3 AND outbox.status='held')
		FROM node_deployments deployment JOIN edge_command_outbox outbox
		  ON outbox.deployment_id=deployment.id AND outbox.deployment_attempt=deployment.attempt
		WHERE deployment.rollout_id=$1`, rolloutID, canaryNodeID, followingNodeID, retryOutboxStatus).Scan(
		&failedOriginal, &queuedRetry, &retryPending, &followingOriginal, &followingHeld,
	); err != nil {
		t.Fatal(err)
	}
	if failedOriginal != 1 || queuedRetry != 1 || retryPending != 1 || followingOriginal != 1 || followingHeld != 1 {
		t.Fatalf("retry rows=(%d,%d,%d,%d,%d) want=(1,1,1,1,1)",
			failedOriginal, queuedRetry, retryPending, followingOriginal, followingHeld)
	}
}

func setLatestCohortOutboxStatus(
	t *testing.T,
	pool *pgxpool.Pool,
	rolloutID, nodeID uuid.UUID,
	status string,
) {
	t.Helper()
	command, err := pool.Exec(t.Context(), `UPDATE edge_command_outbox outbox
		SET status=$3,published_at=CASE WHEN $3='published' THEN $4 ELSE published_at END,updated_at=$4
		FROM node_deployments deployment
		WHERE deployment.rollout_id=$1 AND deployment.node_id=$2
		  AND deployment.attempt=(SELECT max(latest.attempt) FROM node_deployments latest WHERE latest.id=deployment.id)
		  AND outbox.deployment_id=deployment.id AND outbox.deployment_attempt=deployment.attempt`,
		rolloutID, nodeID, status, integrationClock.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if command.RowsAffected() != 1 {
		t.Fatalf("updated latest outbox rows=%d want=1", command.RowsAffected())
	}
}

func seedCohortNode(t *testing.T, pool *pgxpool.Pool, scopeID, userID, nodeID uuid.UUID) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `
		WITH allocated AS (
			INSERT INTO node_display_id_sequences(scope_id,next_value,updated_at)
			VALUES($2,2,$5)
			ON CONFLICT(scope_id) DO UPDATE SET
				next_value=node_display_id_sequences.next_value+1,
				updated_at=EXCLUDED.updated_at
			RETURNING next_value-1 AS display_id
		)
		INSERT INTO nodes (id,display_id,scope_id,name,admin_state,created_by_user_id)
		SELECT $1,allocated.display_id,$2,$3,'active',$4 FROM allocated`, nodeID, scopeID,
		"cohort-node-"+nodeID.String()[28:], userID, integrationClock); err != nil {
		t.Fatal(err)
	}
}

func seedCohortPlatformOwner(t *testing.T, fixture *commandIAMFixture) Actor {
	t.Helper()
	username := "cohort-owner-" + uuid.NewString()[:8]
	bootstrap, err := identity.NewStore(fixture.pool).BootstrapPlatformUser(
		t.Context(), username, "Cohort rollout owner", "not-used", username,
	)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := uuid.New()
	now := time.Now().UTC().Truncate(time.Microsecond)
	refreshDigest := sha256.Sum256(sessionID[:])
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO auth_sessions(
		id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
	) VALUES($1,$2,$3,$4,$5,$6,$7)`, sessionID, uuid.New(), bootstrap.UserID, bootstrap.ScopeID,
		refreshDigest[:], now.Add(-time.Minute), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	return fixture.mintActor(t, bootstrap.UserID, bootstrap.ScopeID, ScopeKindPlatform, sessionID)
}

func progressiveRolloutRequest(scopeID, configID uuid.UUID, nodeIDs []uuid.UUID, key string, autoStart bool) CreateRolloutRequest {
	request := testRolloutRequest(scopeID, configID, nodeIDs, key)
	request.ContractVersion = 2
	request.MaxAttempts = 3
	request.Rollout = RolloutPolicy{
		Strategy: RolloutStrategyCanary, CanarySize: 1, BatchSize: 2,
		FailureThreshold: 1, AutoStart: autoStart,
	}
	return request
}

func assertProgressiveCancelAndLateFact(
	t *testing.T,
	fixture *commandIAMFixture,
	actor Actor,
	scopeID, ownerID, configID uuid.UUID,
) {
	t.Helper()
	nodes := []uuid.UUID{uuid.New(), uuid.New()}
	for _, nodeID := range nodes {
		seedCohortNode(t, fixture.pool, scopeID, ownerID, nodeID)
	}
	request := progressiveRolloutRequest(scopeID, configID, nodes, "cohort-cancel", true)
	request.Rollout.BatchSize = 1
	created, err := fixture.store.CreateRollout(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	rolloutID := created.Rollout.ID
	var inFlight uuid.UUID
	if err := fixture.pool.QueryRow(t.Context(), `SELECT node_id FROM node_deployments
		WHERE rollout_id=$1 AND cohort=0`, rolloutID).Scan(&inFlight); err != nil {
		t.Fatal(err)
	}
	setCohortOutboxStatus(t, fixture.pool, rolloutID, inFlight, "publishing")
	advanceCohortDeployment(t, fixture.pool, rolloutID, inFlight, "delivered")
	result, err := fixture.store.CancelRollout(t.Context(), commandRequest(
		actor, scopeID, commandRollout{ID: rolloutID, Revision: 1}, "cohort-cancel-command",
	))
	if err != nil || result.Rollout.State != RolloutStateCancelled {
		t.Fatalf("cancel result=%+v error=%v", result, err)
	}
	assertRolloutFacts(t, fixture.pool, rolloutID, "cancelled", 2, 0, "", 0, 0)
	advanceCohortDeployment(t, fixture.pool, rolloutID, inFlight, "failed")
	advanceCohortProjection(t, fixture.pool, rolloutID, integrationClock.Add(10*time.Second))
	assertRolloutFacts(t, fixture.pool, rolloutID, "cancelled", 2, 0, "", 1, 0)
}

func assertLegacyOutboxesRemainPending(
	t *testing.T,
	fixture *commandIAMFixture,
	scopeID, ownerID, configID uuid.UUID,
) {
	t.Helper()
	nodes := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
	for _, nodeID := range nodes {
		seedCohortNode(t, fixture.pool, scopeID, ownerID, nodeID)
	}
	request := testRolloutRequest(scopeID, configID, nodes, "cohort-legacy")
	request.ContractVersion = 0
	request.MaxAttempts = 3
	created, err := fixture.store.CreateRollout(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	var pending, held int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT
		count(*) FILTER (WHERE outbox.status='pending'),count(*) FILTER (WHERE outbox.status='held')
		FROM edge_command_outbox outbox JOIN node_deployments deployment
		  ON deployment.id=outbox.deployment_id AND deployment.attempt=outbox.deployment_attempt
		WHERE deployment.rollout_id=$1`, created.Rollout.ID).Scan(&pending, &held); err != nil {
		t.Fatal(err)
	}
	if pending != len(nodes) || held != 0 {
		t.Fatalf("legacy outbox pending=%d held=%d", pending, held)
	}
}

func assertCohortAssignments(t *testing.T, pool *pgxpool.Pool, rolloutID uuid.UUID, want map[uuid.UUID]int) {
	t.Helper()
	rows, err := pool.Query(t.Context(), `SELECT node_id,cohort FROM node_deployments WHERE rollout_id=$1`, rolloutID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seen := make(map[uuid.UUID]int, len(want))
	for rows.Next() {
		var nodeID uuid.UUID
		var cohort int
		if err := rows.Scan(&nodeID, &cohort); err != nil {
			t.Fatal(err)
		}
		seen[nodeID] = cohort
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(seen) != len(want) {
		t.Fatalf("cohort assignment count=%d want=%d", len(seen), len(want))
	}
	for nodeID, cohort := range want {
		if seen[nodeID] != cohort {
			t.Fatalf("node %s cohort=%d want=%d", nodeID, seen[nodeID], cohort)
		}
	}
}

func setCohortOutboxStatus(t *testing.T, pool *pgxpool.Pool, rolloutID, nodeID uuid.UUID, status string) {
	t.Helper()
	command, err := pool.Exec(t.Context(), `UPDATE edge_command_outbox outbox
		SET status=$3,published_at=CASE WHEN $3='published' THEN $4 ELSE published_at END,updated_at=$4
		FROM node_deployments deployment
		WHERE deployment.rollout_id=$1 AND deployment.node_id=$2
		  AND outbox.deployment_id=deployment.id AND outbox.deployment_attempt=deployment.attempt`,
		rolloutID, nodeID, status, integrationClock.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if command.RowsAffected() != 1 {
		t.Fatalf("updated outbox rows=%d want=1", command.RowsAffected())
	}
}

func advanceCohortDeployment(t *testing.T, pool *pgxpool.Pool, rolloutID, nodeID uuid.UUID, states ...string) {
	t.Helper()
	for index, state := range states {
		command, err := pool.Exec(t.Context(), `UPDATE node_deployments SET state=$3,updated_at=$4
			WHERE rollout_id=$1 AND node_id=$2`, rolloutID, nodeID, state,
			integrationClock.Add(time.Duration(index+1)*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if command.RowsAffected() != 1 {
			t.Fatalf("advance node %s to %s rows=%d", nodeID, state, command.RowsAffected())
		}
	}
}

func advanceCohortProjection(t *testing.T, pool *pgxpool.Pool, rolloutID uuid.UUID, now time.Time) {
	t.Helper()
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		return AdvanceRolloutAfterStatusTx(t.Context(), tx, rolloutID, now)
	}); err != nil {
		t.Fatal(err)
	}
}

func assertRolloutFacts(
	t *testing.T,
	pool *pgxpool.Pool,
	rolloutID uuid.UUID,
	wantStatus string,
	wantRevision int64,
	wantReleased int,
	wantPauseReason string,
	wantFailed, wantHeld int,
) {
	t.Helper()
	var status string
	var revision int64
	var released, failed, held int
	var pauseReason *string
	if err := pool.QueryRow(t.Context(), `SELECT rollout.status,rollout.revision,rollout.released_cohort,
		rollout.pause_reason,count(*) FILTER (WHERE deployment.state IN ('failed','rollback_failed')),
		count(*) FILTER (WHERE outbox.status='held')
		FROM rollouts rollout JOIN node_deployments deployment ON deployment.rollout_id=rollout.id
		JOIN edge_command_outbox outbox ON outbox.deployment_id=deployment.id AND outbox.deployment_attempt=deployment.attempt
		WHERE rollout.id=$1 GROUP BY rollout.status,rollout.revision,rollout.released_cohort,rollout.pause_reason`,
		rolloutID).Scan(&status, &revision, &released, &pauseReason, &failed, &held); err != nil {
		t.Fatal(err)
	}
	actualPauseReason := ""
	if pauseReason != nil {
		actualPauseReason = *pauseReason
	}
	if status != wantStatus || revision != wantRevision || released != wantReleased ||
		actualPauseReason != wantPauseReason || failed != wantFailed || held != wantHeld {
		t.Fatalf("rollout facts=(%s,%d,%d,%q,%d,%d) want=(%s,%d,%d,%q,%d,%d)",
			status, revision, released, actualPauseReason, failed, held,
			wantStatus, wantRevision, wantReleased, wantPauseReason, wantFailed, wantHeld)
	}
}

func assertRolloutCommandAudit(t *testing.T, pool *pgxpool.Pool, rolloutID uuid.UUID, action string, want int) {
	t.Helper()
	var count int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events
		WHERE action=$1 AND resource_type='edge_rollout' AND resource_id=$2`, action, rolloutID.String()).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != want {
		t.Fatalf("audit count=%d want=%d", count, want)
	}
}
