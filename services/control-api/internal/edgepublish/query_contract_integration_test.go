//go:build integration

package edgepublish

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgestatus"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type staticTargetResolver struct {
	snapshot TargetSnapshot
	err      error
	calls    atomic.Int64
}

func (resolver *staticTargetResolver) ResolveTarget(
	context.Context,
	pgx.Tx,
	uuid.UUID,
	TargetSnapshotReference,
) (TargetSnapshot, error) {
	resolver.calls.Add(1)
	return resolver.snapshot, resolver.err
}

type noopAuditAppender struct{}

func (noopAuditAppender) Append(context.Context, pgx.Tx, audit.Event) error { return nil }

func TestPublicationQueryPaginationTenantIsolationAndRBAC(t *testing.T) {
	fixture := newPublishFixture(t)
	fixture.createSite(t, "publication-query.example", 80, false)
	nodes := []uuid.UUID{fixture.nodeID, uuid.New(), uuid.New()}
	seedPublishNode(t, fixture.pool, fixture.scopeID, fixture.userID, nodes[1])
	seedPublishNode(t, fixture.pool, fixture.scopeID, fixture.userID, nodes[2])

	created := make([]PublishResult, 0, len(nodes))
	for index, nodeID := range nodes {
		if index > 0 {
			fixture.createStream(t, "publication-query-"+string(rune('a'+index)), uint16(9100+index), "198.51.100.40", uint16(9200+index))
		}
		result, err := fixture.service.Publish(context.Background(), fixture.publishRequest("publication-query-"+string(rune('a'+index)), nodeID))
		if err != nil {
			t.Fatal(err)
		}
		created = append(created, result)
	}

	actor := fixture.publishActor()
	first, err := fixture.service.ListPublications(context.Background(), actor, fixture.scopeID, PublicationPageRequest{Limit: 2})
	if err != nil || len(first.Items) != 2 || first.NextCursor == "" ||
		first.CurrentSourceRevision != created[len(created)-1].SourceRevision {
		t.Fatalf("first publication page = %+v, %v", first, err)
	}
	second, err := fixture.service.ListPublications(context.Background(), actor, fixture.scopeID, PublicationPageRequest{
		Limit: 2, Cursor: first.NextCursor,
	})
	if err != nil || len(second.Items) != 1 || second.NextCursor != "" ||
		second.CurrentSourceRevision != first.CurrentSourceRevision {
		t.Fatalf("second publication page = %+v, %v", second, err)
	}
	seen := map[uuid.UUID]bool{}
	for _, item := range append(first.Items, second.Items...) {
		if seen[item.PublicationID] || item.ConfigurationScopeID != fixture.scopeID || item.Replayed {
			t.Fatalf("invalid publication page item = %+v", item)
		}
		seen[item.PublicationID] = true
	}
	if len(seen) != len(created) {
		t.Fatalf("publication page IDs = %v", seen)
	}
	got, err := fixture.service.GetPublication(context.Background(), actor, fixture.scopeID, created[1].PublicationID)
	want := created[1]
	if err != nil || got.PublicationID != want.PublicationID || got.ConfigurationScopeID != want.ConfigurationScopeID ||
		got.SourceRevision != want.SourceRevision || got.ConfigVersionID != want.ConfigVersionID || got.RolloutID != want.RolloutID ||
		got.CanonicalSnapshotSHA256 != want.CanonicalSnapshotSHA256 || got.ArtifactSHA256 != want.ArtifactSHA256 ||
		got.TargetKind != want.TargetKind || got.TargetSnapshot != nil || got.TargetSnapshotSHA256 != want.TargetSnapshotSHA256 ||
		got.NodeCount != want.NodeCount || !got.CreatedAt.Equal(want.CreatedAt) || got.Replayed {
		t.Fatalf("get publication = %+v, %v", got, err)
	}

	otherScope := seedEmptyTenantScope(t, fixture.pool)
	empty, err := fixture.service.ListPublications(context.Background(), actor, otherScope, PublicationPageRequest{})
	if err != nil || len(empty.Items) != 0 || empty.CurrentSourceRevision != 1 {
		t.Fatalf("cross-tenant publication list = %+v, %v", empty, err)
	}
	if _, err := fixture.service.GetPublication(context.Background(), actor, otherScope, created[0].PublicationID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant publication get = %v", err)
	}
	denied := seedUnprivilegedPlatformActor(t, fixture.pool, fixture.platformScopeID)
	if _, err := fixture.service.ListPublications(context.Background(), denied, fixture.scopeID, PublicationPageRequest{}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("unprivileged publication list = %v", err)
	}
	if _, err := fixture.service.ListPublications(context.Background(), actor, fixture.scopeID, PublicationPageRequest{Cursor: "invalid"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid publication cursor = %v", err)
	}
}

func TestPublishResolverSnapshotAndRejectsIneligibleTargets(t *testing.T) {
	t.Run("immutable resolver snapshot", func(t *testing.T) {
		fixture := newPublishFixture(t)
		fixture.createSite(t, "resolver-target.example", 80, false)
		secondNode := uuid.New()
		seedPublishNode(t, fixture.pool, fixture.scopeID, fixture.userID, secondNode)
		fixture.ensureV2Node(secondNode)
		reference := TargetSnapshotReference{ID: uuid.New(), Revision: 7, SHA256: sha256.Sum256([]byte("resolver-snapshot-7"))}
		resolver := &staticTargetResolver{snapshot: TargetSnapshot{Reference: reference, NodeIDs: []uuid.UUID{secondNode, fixture.nodeID}}}
		service := fixture.newServiceWithResolver(t, resolver, &testEntitlementAuthorizer{decision: validTestEntitlementDecision()}, nil)
		request := fixture.publishRequest("resolver-target", fixture.nodeID)
		request.NodeIDs = nil
		request.TargetSnapshot = &reference
		result, err := service.Publish(context.Background(), request)
		if err != nil || result.TargetKind != TargetKindResolver || result.TargetSnapshot == nil ||
			*result.TargetSnapshot != reference || result.NodeCount != 2 || resolver.calls.Load() != 1 {
			t.Fatalf("resolver publication = %+v calls=%d, %v", result, resolver.calls.Load(), err)
		}
	})

	for _, test := range []struct {
		name   string
		target func(*testing.T, *publishFixture) uuid.UUID
	}{
		{name: "unknown node", target: func(_ *testing.T, _ *publishFixture) uuid.UUID { return uuid.New() }},
		{name: "cross tenant node", target: func(t *testing.T, fixture *publishFixture) uuid.UUID {
			return seedOtherTenantNode(t, fixture.pool)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPublishFixture(t)
			fixture.createSite(t, strings.ReplaceAll(test.name, " ", "-")+".example", 80, false)
			authorizer := &testEntitlementAuthorizer{decision: validTestEntitlementDecision()}
			service := fixture.newServiceWithResolver(t, nil, authorizer, nil)
			if _, err := service.Publish(context.Background(), fixture.publishRequest("ineligible-"+strings.ReplaceAll(test.name, " ", "-"), test.target(t, fixture))); !errors.Is(err, ErrTargetIneligible) {
				t.Fatalf("ineligible target error = %v", err)
			}
			if authorizer.calls.Load() != 0 {
				t.Fatalf("entitlement evaluated before target rejection: calls=%d", authorizer.calls.Load())
			}
		})
	}

	t.Run("duplicate resolver nodes", func(t *testing.T) {
		fixture := newPublishFixture(t)
		fixture.createSite(t, "resolver-duplicate.example", 80, false)
		reference := TargetSnapshotReference{ID: uuid.New(), Revision: 1, SHA256: sha256.Sum256([]byte("resolver-duplicate"))}
		resolver := &staticTargetResolver{snapshot: TargetSnapshot{Reference: reference, NodeIDs: []uuid.UUID{fixture.nodeID, fixture.nodeID}}}
		service := fixture.newServiceWithResolver(t, resolver, &testEntitlementAuthorizer{decision: validTestEntitlementDecision()}, nil)
		request := fixture.publishRequest("resolver-duplicate", fixture.nodeID)
		request.NodeIDs, request.TargetSnapshot = nil, &reference
		if _, err := service.Publish(context.Background(), request); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("duplicate resolver nodes = %v", err)
		}
	})
}

func TestPublicationContractDatabaseGuardsAndFailClosedDown(t *testing.T) {
	t.Run("missing audit rolls back entire publication", func(t *testing.T) {
		fixture := newPublishFixture(t)
		fixture.createSite(t, "missing-audit.example", 80, false)
		service := fixture.newServiceWithResolver(t, nil, &testEntitlementAuthorizer{decision: validTestEntitlementDecision()}, noopAuditAppender{})
		if _, err := service.Publish(context.Background(), fixture.publishRequest("missing-audit", fixture.nodeID)); err == nil {
			t.Fatal("publication without a success audit committed")
		}
		assertPublishState(t, fixture.pool, 0, 0, 0, 0, 0)
	})

	t.Run("missing rollout audit rolls back cancellation", func(t *testing.T) {
		fixture := newPublishFixture(t)
		fixture.createSite(t, "missing-rollout-audit.example", 80, false)
		published, err := fixture.service.Publish(context.Background(), fixture.publishRequest("missing-rollout-audit", fixture.nodeID))
		if err != nil {
			t.Fatal(err)
		}
		iamService, sessionActor := fixture.newIAMService(t)
		writeAuthorizer := iamService.writeAuth.(iamWriteAuthorizer)
		store, err := edgedeployment.NewIAMStoreWithClockAndAuditor(
			fixture.pool, func() time.Time { return publishTestClock.Add(time.Second) }, noopAuditAppender{},
			writeAuthorizer.authorizer,
		)
		if err != nil {
			t.Fatal(err)
		}
		actor, err := edgedeployment.NewSessionActor(
			sessionActor.UserID, sessionActor.ScopeID, edgedeployment.ScopeKindPlatform,
			sessionActor.SessionID, sessionActor.rawSession(),
		)
		if err != nil {
			t.Fatal(err)
		}
		rollout, err := store.GetRollout(context.Background(), actor, fixture.scopeID, published.RolloutID)
		if err != nil {
			t.Fatal(err)
		}
		_, err = store.CancelRollout(context.Background(), edgedeployment.RolloutCommandRequest{
			Actor: actor, ConfigurationScopeID: fixture.scopeID, RolloutID: published.RolloutID,
			ExpectedRevision: rollout.Revision, IdempotencyKey: "missing-rollout-audit",
			RequestID: uuid.NewString(),
		})
		if err == nil {
			t.Fatal("rollout cancellation without a success audit committed")
		}
		var persistedStatus, deploymentState, outboxStatus string
		var revision, requests int
		if err := fixture.pool.QueryRow(context.Background(), `
			SELECT rollout.status,rollout.revision,deployment.state,outbox.status,
			       (SELECT count(*) FROM edge_rollout_write_requests)
			FROM rollouts rollout
			JOIN node_deployments deployment ON deployment.rollout_id=rollout.id
			JOIN edge_command_outbox outbox
			  ON outbox.deployment_id=deployment.id AND outbox.deployment_attempt=deployment.attempt
			WHERE rollout.id=$1`, published.RolloutID).Scan(
			&persistedStatus, &revision, &deploymentState, &outboxStatus, &requests); err != nil {
			t.Fatal(err)
		}
		if persistedStatus != "queued" || revision != 1 || deploymentState != "queued" || outboxStatus != "pending" || requests != 0 {
			t.Fatalf("cancellation audit rollback status=%s revision=%d deployment=%s outbox=%s requests=%d",
				persistedStatus, revision, deploymentState, outboxStatus, requests)
		}
	})

	fixture := newPublishFixture(t)
	fixture.createSite(t, "database-guard.example", 80, false)
	published, err := fixture.service.Publish(context.Background(), fixture.publishRequest("database-guard", fixture.nodeID))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(context.Background(), `
		UPDATE rollouts SET status='completed',revision=revision+1,updated_at=updated_at+interval '1 second'
		WHERE id=$1`, published.RolloutID); err == nil {
		t.Fatal("direct rollout success forgery was accepted")
	}
	if _, err := fixture.pool.Exec(context.Background(), `
		UPDATE node_deployments SET state='healthy',updated_at=updated_at+interval '1 second'
		WHERE rollout_id=$1`, published.RolloutID); err == nil {
		t.Fatal("direct deployment success forgery was accepted")
	}
	if _, err := fixture.pool.Exec(context.Background(), `TRUNCATE edge_rollout_write_requests`); err == nil {
		t.Fatal("edge rollout write request truncation was accepted")
	}
	assertPublishMigration046DownFails(t, fixture.pool)
}

func TestEntitlementDenialPreservesActiveEdgeState(t *testing.T) {
	fixture := newPublishFixture(t)
	fixture.createSite(t, "active-entitlement.example", 80, false)
	published, err := fixture.service.Publish(context.Background(), fixture.publishRequest("active-entitlement", fixture.nodeID))
	if err != nil {
		t.Fatal(err)
	}
	activatePublishedDeployment(t, fixture.pool, published.RolloutID)

	fixture.createStream(t, "denied-entitlement-revision", 9300, "198.51.100.50", 9301)
	denied := &testEntitlementAuthorizer{decision: EntitlementDecision{
		LocallyVerified: true, Status: EntitlementStatusValid, LeaseSerial: 1, EvaluatedAt: publishTestClock,
	}}
	service := fixture.newServiceWithResolver(t, nil, denied, nil)
	if _, err := service.Publish(context.Background(), fixture.publishRequest("denied-entitlement", fixture.nodeID)); !errors.Is(err, ErrEntitlementDenied) {
		t.Fatalf("denied publication = %v", err)
	}
	var currentConfig uuid.UUID
	var deploymentState string
	if err := fixture.pool.QueryRow(context.Background(), `
		SELECT state.current_config_version_id,deployment.state
		FROM node_config_state state
		JOIN node_deployments deployment ON deployment.node_id=state.node_id
		WHERE state.node_id=$1 AND deployment.rollout_id=$2`, fixture.nodeID, published.RolloutID).Scan(
		&currentConfig, &deploymentState); err != nil {
		t.Fatal(err)
	}
	if currentConfig != published.ConfigVersionID || deploymentState != "healthy" {
		t.Fatalf("active edge changed after entitlement denial: config=%s state=%s", currentConfig, deploymentState)
	}
	assertPublishState(t, fixture.pool, 1, 1, 1, 1, 1)
}

func (fixture *publishFixture) publishActor() Actor {
	return Actor{UserID: fixture.platformUserID, ScopeID: fixture.platformScopeID, ScopeKind: ScopeKindPlatform}
}

func (fixture *publishFixture) newServiceWithResolver(
	t *testing.T,
	resolver TargetResolver,
	authorizer EntitlementAuthorizer,
	auditor AuditAppender,
) *Service {
	t.Helper()
	store, err := edgedeployment.NewStoreWithClock(fixture.pool, func() time.Time { return publishTestClock })
	if err != nil {
		t.Fatal(err)
	}
	config := DefaultConfig()
	config.Clock = func() time.Time { return publishTestClock }
	config.TargetResolver, config.EntitlementAuthorizer, config.Auditor = resolver, authorizer, auditor
	service, err := newServiceWithWriteAuthorizer(fixture.pool, store, fixture.signer, config, fixtureWriteAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func seedEmptyTenantScope(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	tenantID, scopeID := uuid.New(), uuid.New()
	if _, err := pool.Exec(context.Background(), `
		WITH tenant AS (
			INSERT INTO tenants (id,display_name) VALUES ($1,'Other publication tenant')
		)
		INSERT INTO access_scopes (id,kind,tenant_id) VALUES ($2,'tenant',$1)`, tenantID, scopeID); err != nil {
		t.Fatal(err)
	}
	return scopeID
}

func seedOtherTenantNode(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	scopeID := seedEmptyTenantScope(t, pool)
	userID, nodeID := uuid.New(), uuid.New()
	username := "other-node-" + strings.ReplaceAll(userID.String(), "-", "")[:12]
	if _, err := pool.Exec(context.Background(), `
		WITH actor AS (
			INSERT INTO users (id,username,display_name,password_hash)
			VALUES ($1,$2,'Other node owner','not-used')
		)
		INSERT INTO memberships (scope_id,user_id) VALUES ($3,$1)`, userID, username, scopeID); err != nil {
		t.Fatal(err)
	}
	insertPublishNode(t, pool, scopeID, userID, nodeID, "other-tenant-node")
	return nodeID
}

func seedUnprivilegedPlatformActor(t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID) Actor {
	t.Helper()
	userID := uuid.New()
	username := "publication-reader-" + strings.ReplaceAll(userID.String(), "-", "")[:12]
	if _, err := pool.Exec(context.Background(), `
		WITH actor AS (
			INSERT INTO users (id,username,display_name,password_hash)
			VALUES ($1,$2,'Unprivileged publication reader','not-used')
		)
		INSERT INTO memberships (scope_id,user_id) VALUES ($3,$1)`, userID, username, scopeID); err != nil {
		t.Fatal(err)
	}
	return Actor{UserID: userID, ScopeID: scopeID, ScopeKind: ScopeKindPlatform}
}

func activatePublishedDeployment(t *testing.T, pool *pgxpool.Pool, rolloutID uuid.UUID) {
	t.Helper()
	var deploymentID, nodeID, configID uuid.UUID
	var commandBytes []byte
	if err := pool.QueryRow(context.Background(), `
		SELECT id,node_id,config_version_id,command_bytes
		FROM node_deployments WHERE rollout_id=$1`, rolloutID).Scan(
		&deploymentID, &nodeID, &configID, &commandBytes); err != nil {
		t.Fatal(err)
	}
	command := new(agentv1.DeploymentCommand)
	if err := proto.Unmarshal(commandBytes, command); err != nil || command.Event == nil || command.Event.OccurredTime == nil {
		t.Fatalf("decode publication command: %v", err)
	}
	validator, err := edgestatus.NewValidator(edgestatus.DefaultValidatorConfig())
	if err != nil {
		t.Fatal(err)
	}
	store, err := edgestatus.NewStoreWithClock(pool, func() time.Time { return publishTestClock.Add(time.Minute) })
	if err != nil {
		t.Fatal(err)
	}
	causationID := command.Event.EventId
	states := []agentv1.NodeDeploymentState{
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY,
	}
	for index, state := range states {
		status := &agentv1.DeploymentStatus{
			Event: &commonv1.EventMetadata{
				EventId: uuid.NewString(), RequestId: command.Event.RequestId,
				OccurredTime: timestamppb.New(command.Event.OccurredTime.AsTime().Add(time.Duration(index+1) * time.Second)),
				CausationId:  &causationID, Traceparent: command.Event.Traceparent,
				CorrelationId: command.Event.CorrelationId, TaskId: command.Event.TaskId,
			},
			DeploymentId: deploymentID.String(), Attempt: 1, ConfigVersionId: configID.String(),
			State: state, TransitionSequence: uint64(index + 1),
		}
		payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(status)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := validator.Decode(edgestatus.DefaultSubjectPrefix+"."+nodeID.String(), payload)
		if err != nil {
			t.Fatal(err)
		}
		result, err := store.Project(context.Background(), envelope)
		if err != nil || result.Outcome != edgestatus.OutcomeAdvanced {
			t.Fatalf("activate state %s = %+v, %v", state, result, err)
		}
	}
}
