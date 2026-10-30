//go:build integration

package edgeautopublish_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSiteRuntimeV2AutomaticMutationsLockScopeBeforeReadingSite(t *testing.T) {
	mutations := []struct {
		name      string
		operation string
		mutate    func(context.Context, *site.Service, site.Actor, site.Site, string) error
	}{
		{
			name:      "update",
			operation: "site.update",
			mutate: func(ctx context.Context, service *site.Service, actor site.Actor, current site.Site, key string) error {
				fields := siteFields(current.Domain)
				fields.CNAME = "runtime-v2-update.example.test"
				_, err := service.Update(ctx, actor, site.UpdateRequest{
					ID: current.ID, ExpectedRevision: current.Revision, Fields: fields,
					IdempotencyKey: key, RequestID: key,
				})
				return err
			},
		},
		{
			name:      "origin",
			operation: "site.origin.update",
			mutate: func(ctx context.Context, service *site.Service, actor site.Actor, current site.Site, key string) error {
				pool := current.OriginPool
				pool.Origins[0].Weight++
				_, err := service.UpdateOrigin(ctx, actor, site.UpdateOriginRequest{
					ID: current.ID, ExpectedRevision: current.Revision, Pool: pool,
					IdempotencyKey: key, RequestID: key,
				})
				return err
			},
		},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			pool := openAutomaticDatabase(t)
			identity := seedAutomaticIntegrationIdentity(t, pool)
			trust := installAutomaticSiteEntitlement(t, pool)
			service := site.NewService(site.NewStoreWithClock(pool, func() time.Time { return automaticIntegrationNow }, trust))
			actor := site.Actor{UserID: identity.tenantUser, ScopeID: identity.tenantScope, ScopeKind: "tenant"}
			insertPolicy(t, pool, identity, 1, edgeautopublish.ModeManual)
			created, err := service.Create(t.Context(), actor,
				newSiteRequest("runtime-v2-"+mutation.name+".example.test", "runtime-v2-create-"+mutation.name))
			if err != nil {
				t.Fatal(err)
			}
			insertPolicy(t, pool, identity, 2, edgeautopublish.ModeAutomatic)

			blocker, err := pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = blocker.Rollback(context.Background()) }()
			var blockerPID int32
			if err := blocker.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&blockerPID); err != nil {
				t.Fatal(err)
			}
			var lockedRevision int64
			if err := blocker.QueryRow(t.Context(), `SELECT source_revision FROM edge_configuration_scopes
				WHERE scope_id=$1 FOR UPDATE`, identity.tenantScope).Scan(&lockedRevision); err != nil {
				t.Fatal(err)
			}

			key := "runtime-v2-" + mutation.name
			done := make(chan error, 1)
			go func() {
				done <- mutation.mutate(context.Background(), service, actor, created.Site, key)
			}()
			waitErr := waitForAutomaticSiteRuntimeV2Blocker(t.Context(), pool, blockerPID)
			lockErr := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
				var exists bool
				return tx.QueryRow(t.Context(), `SELECT true FROM sites WHERE id=$1 FOR UPDATE NOWAIT`, created.Site.ID).
					Scan(&exists)
			})
			if err := blocker.Commit(t.Context()); err != nil {
				t.Fatal(err)
			}
			mutationErr := <-done
			if waitErr != nil {
				t.Fatal(waitErr)
			}
			if lockErr != nil {
				t.Fatalf("%s locked the site before the configuration scope: %v", mutation.name, lockErr)
			}
			if mutationErr != nil {
				t.Fatal(mutationErr)
			}
			var requestRevision, currentRevision int64
			if err := pool.QueryRow(t.Context(), `SELECT source_revision FROM edge_automatic_publication_requests
				WHERE source_request_id=$1 AND operation=$2`, key, mutation.operation).Scan(&requestRevision); err != nil {
				t.Fatal(err)
			}
			if err := pool.QueryRow(t.Context(), `SELECT source_revision FROM edge_configuration_scopes
				WHERE scope_id=$1`, identity.tenantScope).Scan(&currentRevision); err != nil {
				t.Fatal(err)
			}
			if requestRevision != currentRevision || requestRevision <= lockedRevision {
				t.Fatalf("%s enqueue revision=%d current=%d prior-locked=%d", mutation.name, requestRevision, currentRevision, lockedRevision)
			}
		})
	}
}

func TestSiteRuntimeV2EnqueueTxCASHasOneRealPGWinner(t *testing.T) {
	pool := openAutomaticDatabase(t)
	identity := seedAutomaticIntegrationIdentity(t, pool)
	insertPolicy(t, pool, identity, 1, edgeautopublish.ModeAutomatic)
	const sourceRevision int64 = 41
	if _, err := pool.Exec(t.Context(), `INSERT INTO edge_configuration_scopes(scope_id,source_revision,updated_at)
		VALUES($1,$2,clock_timestamp())`, identity.tenantScope, sourceRevision); err != nil {
		t.Fatal(err)
	}
	resourceID := uuid.New()
	inputs := []edgeautopublish.EnqueueInput{
		siteRuntimeV2EnqueueInput(identity, resourceID, "runtime-v2-enqueue-a"),
		siteRuntimeV2EnqueueInput(identity, resourceID, "runtime-v2-enqueue-b"),
	}
	type result struct {
		value edgeautopublish.EnqueueResult
		err   error
	}
	start := make(chan struct{})
	results := make(chan result, len(inputs))
	for _, input := range inputs {
		input := input
		go func() {
			<-start
			var value edgeautopublish.EnqueueResult
			err := pgx.BeginFunc(context.Background(), pool, func(tx pgx.Tx) error {
				var err error
				value, err = edgeautopublish.EnqueueTx(context.Background(), tx, input)
				return err
			})
			results <- result{value: value, err: err}
		}()
	}
	close(start)

	winners, losers := 0, 0
	for range inputs {
		result := <-results
		if result.err == nil && result.value.Enqueued && !result.value.Replayed {
			winners++
			continue
		}
		if errors.Is(result.err, edgeautopublish.ErrIdempotencyConflict) {
			losers++
			continue
		}
		t.Fatalf("unexpected EnqueueTx result=%+v err=%v", result.value, result.err)
	}
	if winners != 1 || losers != 1 {
		t.Fatalf("concurrent EnqueueTx winners/losers=%d/%d", winners, losers)
	}
	var requests int
	var storedRevision, currentRevision int64
	if err := pool.QueryRow(t.Context(), `SELECT count(*),min(source_revision)
		FROM edge_automatic_publication_requests WHERE target_scope_id=$1`, identity.tenantScope).
		Scan(&requests, &storedRevision); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1`,
		identity.tenantScope).Scan(&currentRevision); err != nil {
		t.Fatal(err)
	}
	if requests != 1 || storedRevision != sourceRevision || currentRevision != sourceRevision {
		t.Fatalf("CAS state requests=%d stored=%d current=%d", requests, storedRevision, currentRevision)
	}
}

func TestSiteRuntimeV2EnqueueTxPersistsCanonicalDigestAndReplaysWithoutDuplication(t *testing.T) {
	pool := openAutomaticDatabase(t)
	identity := seedAutomaticIntegrationIdentity(t, pool)
	insertPolicy(t, pool, identity, 1, edgeautopublish.ModeAutomatic)
	const sourceRevision int64 = 41
	if _, err := pool.Exec(t.Context(), `INSERT INTO edge_configuration_scopes(scope_id,source_revision,updated_at)
		VALUES($1,$2,clock_timestamp())`, identity.tenantScope, sourceRevision); err != nil {
		t.Fatal(err)
	}

	input := siteRuntimeV2EnqueueInput(identity, uuid.New(), "runtime-v2-enqueue-replay")
	first := siteRuntimeV2Enqueue(t, pool, input)
	if !first.Enqueued || first.Replayed || first.RequestID == uuid.Nil {
		t.Fatalf("first EnqueueTx result=%+v", first)
	}
	wantDigest := siteRuntimeV2ExpectedEnqueueDigest(t, pool, input, sourceRevision)
	before := siteRuntimeV2ReadAutomaticRequest(t, pool, first.RequestID)
	if before.digest != wantDigest || before.sourceRevision != sourceRevision || before.stateFacts != 1 {
		t.Fatalf("persisted request revision/digest/states=%d/%x/%d want=%d/%x/1",
			before.sourceRevision, before.digest, before.stateFacts, sourceRevision, wantDigest)
	}

	replay := siteRuntimeV2Enqueue(t, pool, input)
	if !replay.Enqueued || !replay.Replayed || replay.RequestID != first.RequestID {
		t.Fatalf("same-digest EnqueueTx replay=%+v first=%+v", replay, first)
	}
	afterReplay := siteRuntimeV2ReadAutomaticRequest(t, pool, first.RequestID)
	if afterReplay != before {
		t.Fatalf("same-digest replay changed persisted facts: before=%+v after=%+v", before, afterReplay)
	}

	changed := input
	changed.SourceRequestID = "runtime-v2-enqueue-changed-digest"
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		_, err := edgeautopublish.EnqueueTx(t.Context(), tx, changed)
		return err
	})
	if !errors.Is(err, edgeautopublish.ErrIdempotencyConflict) {
		t.Fatalf("changed-digest EnqueueTx error=%v", err)
	}
	afterConflict := siteRuntimeV2ReadAutomaticRequest(t, pool, first.RequestID)
	if afterConflict != before {
		t.Fatalf("changed-digest conflict changed persisted facts: before=%+v after=%+v", before, afterConflict)
	}
	var requests int
	var currentRevision int64
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM edge_automatic_publication_requests
		WHERE target_scope_id=$1`, identity.tenantScope).Scan(&requests); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT source_revision FROM edge_configuration_scopes
		WHERE scope_id=$1`, identity.tenantScope).Scan(&currentRevision); err != nil {
		t.Fatal(err)
	}
	if requests != 1 || currentRevision != sourceRevision {
		t.Fatalf("conflict state requests/current-revision=%d/%d want=1/%d", requests, currentRevision, sourceRevision)
	}
}

func TestSiteRuntimeV2EnqueueTxReadsRevisionAfterRealScopeLock(t *testing.T) {
	pool := openAutomaticDatabase(t)
	identity := seedAutomaticIntegrationIdentity(t, pool)
	insertPolicy(t, pool, identity, 1, edgeautopublish.ModeAutomatic)
	const initialRevision int64 = 41
	if _, err := pool.Exec(t.Context(), `INSERT INTO edge_configuration_scopes(scope_id,source_revision,updated_at)
		VALUES($1,$2,clock_timestamp())`, identity.tenantScope, initialRevision); err != nil {
		t.Fatal(err)
	}
	blocker, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Rollback(context.Background()) }()
	var blockerPID int32
	if err := blocker.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&blockerPID); err != nil {
		t.Fatal(err)
	}
	if _, err := blocker.Exec(t.Context(), `SELECT 1 FROM edge_configuration_scopes
		WHERE scope_id=$1 FOR UPDATE`, identity.tenantScope); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	input := siteRuntimeV2EnqueueInput(identity, uuid.New(), "runtime-v2-final-locked-revision")
	go func() {
		done <- pgx.BeginFunc(context.Background(), pool, func(tx pgx.Tx) error {
			_, err := edgeautopublish.EnqueueTx(context.Background(), tx, input)
			return err
		})
	}()
	waitErr := waitForAutomaticSiteRuntimeV2Blocker(t.Context(), pool, blockerPID)
	if _, err := blocker.Exec(t.Context(), `UPDATE edge_configuration_scopes SET source_revision=$2
		WHERE scope_id=$1`, identity.tenantScope, initialRevision+1); err != nil {
		t.Fatal(err)
	}
	if err := blocker.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	enqueueErr := <-done
	if waitErr != nil {
		t.Fatal(waitErr)
	}
	if enqueueErr != nil {
		t.Fatal(enqueueErr)
	}
	var storedRevision int64
	if err := pool.QueryRow(t.Context(), `SELECT source_revision FROM edge_automatic_publication_requests
		WHERE source_request_id=$1`, input.SourceRequestID).Scan(&storedRevision); err != nil {
		t.Fatal(err)
	}
	if storedRevision != initialRevision+1 {
		t.Fatalf("EnqueueTx stored revision=%d, final locked revision=%d", storedRevision, initialRevision+1)
	}
}

func siteRuntimeV2EnqueueInput(
	identity automaticIntegrationIdentity,
	resourceID uuid.UUID,
	requestID string,
) edgeautopublish.EnqueueInput {
	return edgeautopublish.EnqueueInput{
		Actor: edgeautopublish.Actor{
			UserID: identity.tenantUser, ScopeID: identity.tenantScope, ScopeKind: edgeautopublish.ScopeKindTenant,
		},
		TargetScopeID: identity.tenantScope, SourceKind: edgeautopublish.SourceSite,
		SourceResourceID: resourceID, Operation: "site.update", Reason: edgeautopublish.ReasonResourceMutation,
		Permission: edgeautopublish.PermissionSitesManage, SourceRequestID: requestID,
	}
}

type siteRuntimeV2AutomaticRequestState struct {
	sourceRevision int64
	digest         [sha256.Size]byte
	stateFacts     int
}

func siteRuntimeV2Enqueue(
	t *testing.T,
	pool *pgxpool.Pool,
	input edgeautopublish.EnqueueInput,
) edgeautopublish.EnqueueResult {
	t.Helper()
	var result edgeautopublish.EnqueueResult
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		var err error
		result, err = edgeautopublish.EnqueueTx(t.Context(), tx, input)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return result
}

func siteRuntimeV2ReadAutomaticRequest(
	t *testing.T,
	pool *pgxpool.Pool,
	requestID uuid.UUID,
) siteRuntimeV2AutomaticRequestState {
	t.Helper()
	var result siteRuntimeV2AutomaticRequestState
	var digest []byte
	if err := pool.QueryRow(t.Context(), `SELECT request_row.source_revision,request_row.request_digest,
		(SELECT count(*) FROM edge_automatic_publication_request_state_facts state
		 WHERE state.request_id=request_row.id)
		FROM edge_automatic_publication_requests request_row WHERE request_row.id=$1`, requestID).
		Scan(&result.sourceRevision, &digest, &result.stateFacts); err != nil {
		t.Fatal(err)
	}
	if len(digest) != sha256.Size {
		t.Fatalf("persisted request digest has %d bytes", len(digest))
	}
	copy(result.digest[:], digest)
	return result
}

func siteRuntimeV2ExpectedEnqueueDigest(
	t *testing.T,
	pool *pgxpool.Pool,
	input edgeautopublish.EnqueueInput,
	sourceRevision int64,
) [sha256.Size]byte {
	t.Helper()
	var policy struct {
		revision      int64
		nodeIDs       []uuid.UUID
		activationMS  int64
		observationMS int64
		successes     uint32
		maxAttempts   uint32
		deadline      int64
	}
	if err := pool.QueryRow(t.Context(), `SELECT revision,node_ids,activation_timeout_ms,observation_window_ms,
		required_consecutive_successes,max_attempts,deadline_window_seconds
		FROM edge_automatic_publication_policy_facts WHERE target_scope_id=$1
		ORDER BY revision DESC LIMIT 1`, input.TargetScopeID).Scan(&policy.revision, &policy.nodeIDs,
		&policy.activationMS, &policy.observationMS, &policy.successes, &policy.maxAttempts, &policy.deadline); err != nil {
		t.Fatal(err)
	}
	sort.Slice(policy.nodeIDs, func(i, j int) bool { return bytes.Compare(policy.nodeIDs[i][:], policy.nodeIDs[j][:]) < 0 })
	nodes := make([]string, len(policy.nodeIDs))
	for index, nodeID := range policy.nodeIDs {
		nodes[index] = nodeID.String()
	}
	resourceID := input.SourceResourceID.String()
	payload := struct {
		TargetScopeID    string   `json:"target_scope_id"`
		ActorScopeID     string   `json:"actor_scope_id"`
		ActorUserID      string   `json:"actor_user_id"`
		ActorScopeKind   string   `json:"actor_scope_kind"`
		SourceKind       string   `json:"source_kind"`
		SourceResourceID *string  `json:"source_resource_id,omitempty"`
		SourceRevision   int64    `json:"source_revision"`
		Operation        string   `json:"operation"`
		Reason           string   `json:"reason"`
		Permission       string   `json:"permission"`
		SourceRequestID  string   `json:"source_request_id"`
		PolicyRevision   int64    `json:"policy_revision"`
		NodeIDs          []string `json:"node_ids"`
		ActivationMS     int64    `json:"activation_timeout_ms"`
		ObservationMS    int64    `json:"observation_window_ms"`
		Successes        uint32   `json:"required_consecutive_successes"`
		MaxAttempts      uint32   `json:"max_attempts"`
		DeadlineSeconds  int64    `json:"deadline_window_seconds"`
	}{
		TargetScopeID: input.TargetScopeID.String(), ActorScopeID: input.Actor.ScopeID.String(),
		ActorUserID: input.Actor.UserID.String(), ActorScopeKind: input.Actor.ScopeKind,
		SourceKind: input.SourceKind, SourceResourceID: &resourceID, SourceRevision: sourceRevision,
		Operation: input.Operation, Reason: input.Reason, Permission: input.Permission,
		SourceRequestID: input.SourceRequestID, PolicyRevision: policy.revision, NodeIDs: nodes,
		ActivationMS: policy.activationMS, ObservationMS: policy.observationMS,
		Successes: policy.successes, MaxAttempts: policy.maxAttempts, DeadlineSeconds: policy.deadline,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(encoded)
}

func waitForAutomaticSiteRuntimeV2Blocker(
	ctx context.Context,
	pool *pgxpool.Pool,
	blockerPID int32,
) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for ctx.Err() == nil {
		var blocked bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(
			SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))
		)`, blockerPID).Scan(&blocked); err != nil {
			return err
		}
		if blocked {
			return nil
		}
		runtime.Gosched()
	}
	return fmt.Errorf("site mutation did not block on the scope row: %w", ctx.Err())
}
