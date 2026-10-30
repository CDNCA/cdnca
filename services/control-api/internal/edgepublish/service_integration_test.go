//go:build integration

package edgepublish

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"
	_ "unsafe"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish/capabilitytest"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
)

//go:linkname migratePublishVersionIsolatedFS github.com/cdnca/cdnca/services/control-api/internal/database.migrateFS
func migratePublishVersionIsolatedFS(context.Context, *pgxpool.Pool, string, fs.FS) error

type publishFixture struct {
	pool            *pgxpool.Pool
	service         *Service
	signer          *testSigner
	tenantID        uuid.UUID
	scopeID         uuid.UUID
	userID          uuid.UUID
	platformScopeID uuid.UUID
	platformUserID  uuid.UUID
	subscriptionID  uuid.UUID
	nodeID          uuid.UUID
	// t registers publication targets on first use (ensureV2Node).
	t testing.TB
	// nodeKeys are the artifact private keys of the nodes registered here.
	nodeKeys map[uuid.UUID][]byte
}

type fixtureSite struct {
	ID       uuid.UUID
	Domain   string
	Revision int64
}

type fixtureSiteResult struct {
	Site fixtureSite
}

type fixtureOrigin struct {
	Host    string
	Port    int
	Weight  int
	Enabled bool
}

type fixtureOriginPool struct {
	Origins          []fixtureOrigin
	BalanceMethod    string
	FailoverTries    int
	ConnectTimeoutMS int
	ReadTimeoutMS    int
}

type fixtureStream struct {
	ID                      uuid.UUID
	Revision                int64
	Protocol                string
	ListenAddress           string
	ListenPort              uint16
	UpstreamAddress         string
	UpstreamPort            uint16
	ConnectTimeoutMS        int
	ResponseTimeoutMS       int
	MaxConnectionsPerClient int
	ProxyProtocolV1         bool
	Enabled                 bool
}

type fixtureStreamResult struct {
	Forward fixtureStream
}

type automaticCoordinatorStub struct {
	prepared    PreparedAutomaticPublication
	prepareErr  error
	recordErr   error
	prepareCall atomic.Int64
	recordCall  atomic.Int64
	record      func(context.Context, pgx.Tx, AutomaticClaimReference, PublishResult, time.Time) error
}

func (coordinator *automaticCoordinatorStub) PrepareAutomaticPublication(
	_ context.Context,
	_ pgx.Tx,
	_ AutomaticClaimReference,
) (PreparedAutomaticPublication, error) {
	coordinator.prepareCall.Add(1)
	return coordinator.prepared, coordinator.prepareErr
}

func (coordinator *automaticCoordinatorStub) RecordAutomaticPublication(
	ctx context.Context,
	tx pgx.Tx,
	reference AutomaticClaimReference,
	result PublishResult,
	databaseNow time.Time,
) error {
	coordinator.recordCall.Add(1)
	if coordinator.record != nil {
		if err := coordinator.record(ctx, tx, reference, result, databaseNow); err != nil {
			return err
		}
	}
	return coordinator.recordErr
}

type evaluatedAtAuthorizer struct {
	request EntitlementRequest
}

func (authorizer *evaluatedAtAuthorizer) AuthorizePublication(
	_ context.Context,
	_ pgx.Tx,
	request EntitlementRequest,
) (EntitlementDecision, error) {
	authorizer.request = request
	return EntitlementDecision{
		Allowed: true, LocallyVerified: true, Status: EntitlementStatusValid,
		LeaseSerial: 1, EvaluatedAt: request.EvaluatedAt,
	}, nil
}

type failingAuditAppender struct{}

func (failingAuditAppender) Append(context.Context, pgx.Tx, audit.Event) error {
	return errors.New("forced audit failure")
}

func newPublishFixture(t *testing.T) *publishFixture {
	t.Helper()
	pool := openPublishTestDatabase(t, true)
	tenantID, scopeID, userID, platformScopeID, platformUserID := seedPublishIdentity(t, pool)
	subscriptionID := seedPublishPackage(t, pool, scopeID, userID, platformScopeID, platformUserID)
	installPublishEntitlement(t, pool)
	nodeID := uuid.New()
	seedPublishNode(t, pool, scopeID, userID, nodeID)
	deploymentStore, err := edgedeployment.NewStoreWithClock(pool, func() time.Time { return publishTestClock })
	if err != nil {
		t.Fatal(err)
	}
	signer := newTestSigner(t, "edge-publish-artifact-key")
	config := DefaultConfig()
	config.Clock = func() time.Time { return publishTestClock }
	config.EntitlementAuthorizer = &testEntitlementAuthorizer{decision: validTestEntitlementDecision()}
	publisher, err := newServiceWithWriteAuthorizer(pool, deploymentStore, signer, config, fixtureWriteAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	fixture := &publishFixture{
		t: t, nodeKeys: map[uuid.UUID][]byte{},
		pool: pool, service: publisher, signer: signer,
		tenantID: tenantID,
		scopeID:  scopeID, userID: userID, platformScopeID: platformScopeID,
		platformUserID: platformUserID, nodeID: nodeID,
		subscriptionID: subscriptionID,
	}
	return fixture
}

func TestAutomaticPublicationUsesOneTransactionAndDatabaseClock(t *testing.T) {
	fixture := newPublishFixture(t)
	databaseNow := publishTestClock.Add(17 * time.Second)
	reference := AutomaticClaimReference{RequestID: uuid.New(), LeaseToken: uuid.New(), StateSequence: 2}
	request := fixture.publishRequest("automatic-atomic", fixture.nodeID)
	request.Actor = Actor{UserID: fixture.userID, ScopeID: fixture.scopeID, ScopeKind: ScopeKindTenant}
	request.Deadline = databaseNow.Add(time.Hour)
	coordinator := &automaticCoordinatorStub{prepared: PreparedAutomaticPublication{
		Request: request, DatabaseNow: databaseNow,
	}}
	coordinator.record = func(ctx context.Context, tx pgx.Tx, gotReference AutomaticClaimReference,
		result PublishResult, gotNow time.Time,
	) error {
		if gotReference != reference || !gotNow.Equal(databaseNow) || !result.CreatedAt.Equal(databaseNow) {
			t.Fatalf("record reference/clock/result=%+v/%s/%+v", gotReference, gotNow, result)
		}
		var persisted time.Time
		if err := tx.QueryRow(ctx, `SELECT created_at FROM edge_config_publications WHERE id=$1`,
			result.PublicationID).Scan(&persisted); err != nil {
			return err
		}
		if !persisted.Equal(databaseNow) {
			t.Fatalf("persisted created_at=%s want=%s", persisted, databaseNow)
		}
		return nil
	}
	authorizer := &evaluatedAtAuthorizer{}
	config := fixture.config(authorizer, nil)
	config.Clock = func() time.Time { panic("automatic publication used application clock") }
	service, err := NewAutomaticService(
		fixture.pool, fixture.deploymentStore(t), fixture.signer, config, coordinator,
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.PublishAutomatic(t.Context(), reference)
	if err != nil {
		t.Fatal(err)
	}
	if !result.CreatedAt.Equal(databaseNow) || authorizer.request.EvaluatedAt != databaseNow ||
		coordinator.prepareCall.Load() != 1 || coordinator.recordCall.Load() != 1 {
		t.Fatalf("result/request/calls=%+v/%+v/%d/%d", result, authorizer.request,
			coordinator.prepareCall.Load(), coordinator.recordCall.Load())
	}
	assertPublishState(t, fixture.pool, 1, 1, 1, 1, 1)
}

func TestAutomaticPublicationRecordFailureRollsBackPublication(t *testing.T) {
	fixture := newPublishFixture(t)
	databaseNow := publishTestClock.Add(23 * time.Second)
	request := fixture.publishRequest("automatic-record-failure", fixture.nodeID)
	request.Actor = Actor{UserID: fixture.userID, ScopeID: fixture.scopeID, ScopeKind: ScopeKindTenant}
	request.Deadline = databaseNow.Add(time.Hour)
	coordinator := &automaticCoordinatorStub{
		prepared:  PreparedAutomaticPublication{Request: request, DatabaseNow: databaseNow},
		recordErr: errors.New("forced automatic record failure"),
	}
	config := fixture.config(&evaluatedAtAuthorizer{}, nil)
	config.Clock = func() time.Time { panic("automatic publication used application clock") }
	service, err := NewAutomaticService(
		fixture.pool, fixture.deploymentStore(t), fixture.signer, config, coordinator,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.PublishAutomatic(t.Context(), AutomaticClaimReference{
		RequestID: uuid.New(), LeaseToken: uuid.New(), StateSequence: 2,
	}); err == nil {
		t.Fatal("PublishAutomatic succeeded despite Record failure")
	}
	assertPublishState(t, fixture.pool, 0, 0, 0, 0, 0)
}

func TestAutomaticPublicationEntitlementDenialCommitsOnlyDenialAudit(t *testing.T) {
	fixture := newPublishFixture(t)
	databaseNow := publishTestClock.Add(29 * time.Second)
	request := fixture.publishRequest("automatic-entitlement-denied", fixture.nodeID)
	request.Actor = Actor{UserID: fixture.userID, ScopeID: fixture.scopeID, ScopeKind: ScopeKindTenant}
	request.Deadline = databaseNow.Add(time.Hour)
	coordinator := &automaticCoordinatorStub{prepared: PreparedAutomaticPublication{
		Request: request, DatabaseNow: databaseNow,
	}}
	config := fixture.config(&testEntitlementAuthorizer{decision: EntitlementDecision{
		EvaluatedAt: databaseNow,
	}}, nil)
	config.Clock = func() time.Time { panic("automatic publication used application clock") }
	service, err := NewAutomaticService(
		fixture.pool, fixture.deploymentStore(t), fixture.signer, config, coordinator,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.PublishAutomatic(t.Context(), AutomaticClaimReference{
		RequestID: uuid.New(), LeaseToken: uuid.New(), StateSequence: 2,
	}); !errors.Is(err, ErrEntitlementDenied) {
		t.Fatalf("PublishAutomatic entitlement error=%v", err)
	}
	if coordinator.recordCall.Load() != 0 {
		t.Fatalf("Record calls=%d", coordinator.recordCall.Load())
	}
	var denials int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events
		WHERE action='edge_publication.entitlement_check' AND result='denied'
		  AND resource_id=$1 AND request_id=$2`, fixture.scopeID.String(), request.RequestID).Scan(&denials); err != nil {
		t.Fatal(err)
	}
	if denials != 1 {
		t.Fatalf("entitlement denial audits=%d", denials)
	}
	assertPublishState(t, fixture.pool, 0, 0, 0, 0, 0)
}

func TestAutomaticAndIAMServiceEntryPointsRemainIsolated(t *testing.T) {
	fixture := newPublishFixture(t)
	request := fixture.publishRequest("automatic-public-denied", fixture.nodeID)
	coordinator := &automaticCoordinatorStub{prepared: PreparedAutomaticPublication{
		Request: request, DatabaseNow: publishTestClock,
	}}
	automatic, err := NewAutomaticService(
		fixture.pool, fixture.deploymentStore(t), fixture.signer, fixture.config(nil, nil), coordinator,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := automatic.Publish(t.Context(), request); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("automatic service public Publish error=%v", err)
	}
	rollback := fixture.rollbackRequest("automatic-rollback-denied", uuid.New(), fixture.nodeID)
	if _, err := automatic.Rollback(t.Context(), rollback); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("automatic service public Rollback error=%v", err)
	}
	iamService, _ := fixture.newIAMService(t)
	if _, err := iamService.PublishAutomatic(t.Context(), AutomaticClaimReference{
		RequestID: uuid.New(), LeaseToken: uuid.New(), StateSequence: 2,
	}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("IAM service automatic Publish error=%v", err)
	}
	var typedNil *automaticCoordinatorStub
	if _, err := NewAutomaticService(
		fixture.pool, fixture.deploymentStore(t), fixture.signer, fixture.config(nil, nil), typedNil,
	); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("typed-nil coordinator error=%v", err)
	}
	assertPublishState(t, fixture.pool, 0, 0, 0, 0, 0)
}

func TestPublishCompilesSignsAndPersistsOneAtomicChain(t *testing.T) {
	fixture := newPublishFixture(t)
	createdSite := fixture.createSite(t, "origin.example", 80, false)
	createdStream := fixture.createStream(t, "tcp-primary", 8443, "198.51.100.20", 9443)
	request := fixture.publishRequest("publish-primary", fixture.nodeID)
	if _, err := fixture.service.Publish(nil, request); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil context publication = %v", err)
	}
	assertPublishState(t, fixture.pool, 0, 0, 0, 0, 0)

	result, err := fixture.service.Publish(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	expectedConfigID := uuid.NewSHA1(fixture.scopeID, []byte(request.IdempotencyKey))
	if result.Replayed || result.ConfigVersionID != expectedConfigID || result.SourceRevision < 1 || result.NodeCount != 1 {
		t.Fatalf("publish result = %+v", result)
	}
	if result.PublicationID != uuid.NewSHA1(expectedConfigID, []byte("publication")) {
		t.Fatalf("publication ID = %s", result.PublicationID)
	}

	// The node receives the site runtime document, sealed to its artifact key.
	release := receivedV2Release(t, fixture, result, fixture.nodeID, fixture.nodeKeys[fixture.nodeID])
	bundle := release.Bundle
	snapshotBytes := bundle.Files["site-runtime.v2.json"]
	if sha256.Sum256(snapshotBytes) != result.CanonicalSnapshotSHA256 {
		t.Fatal("stored snapshot digest differs from publication")
	}
	document := decodeReceivedV2Document(t, bundle)
	if document.Streams == nil || len(document.Streams.StreamsV2) != 1 ||
		document.Streams.StreamsV2[0].MaxConnectionsPerClient != createdStream.Forward.MaxConnectionsPerClient ||
		document.Streams.StreamsV2[0].Listener.Port != 8443 || document.Streams.StreamsV2[0].Endpoint.Address != "198.51.100.20" ||
		document.Streams.StreamsV2[0].Endpoint.Port != 9443 {
		t.Fatalf("published stream = %+v", document.Streams)
	}
	if len(document.Sites) != 1 || document.Sites[0].ID != createdSite.Site.ID.String() ||
		!slices.Contains(document.Sites[0].Domains, createdSite.Site.Domain) {
		t.Fatalf("published sites = %+v", document.Sites)
	}
	// The site object carries the telemetry identity (tenant, site, billing).
	if fixture.tenantID == fixture.scopeID {
		t.Fatal("test fixture must keep tenant and access scope identities distinct")
	}
	if release.Root.ConfigVersionID != result.ConfigVersionID.String() || len(release.Sites) != 1 ||
		release.Sites[0].TenantID != fixture.tenantID.String() || release.Sites[0].SiteID != createdSite.Site.ID.String() ||
		release.Sites[0].Telemetry == nil {
		t.Fatalf("telemetry identity = %+v", release.Sites)
	}

	var commandBytes, outboxPayload []byte
	if err := fixture.pool.QueryRow(context.Background(), `
		SELECT deployment.command_bytes,outbox.payload
		FROM node_deployments deployment
		JOIN edge_command_outbox outbox
		  ON outbox.deployment_id=deployment.id AND outbox.deployment_attempt=deployment.attempt
		WHERE deployment.rollout_id=$1`, result.RolloutID).Scan(&commandBytes, &outboxPayload); err != nil {
		t.Fatal(err)
	}
	command := new(agentv1.DeploymentCommand)
	if err := proto.Unmarshal(commandBytes, command); err != nil {
		t.Fatal(err)
	}
	if command.ConfigVersionId != result.ConfigVersionID.String() || !bytes.Equal(commandBytes, outboxPayload) {
		t.Fatalf("deployment command config=%q outbox_equal=%t", command.ConfigVersionId, bytes.Equal(commandBytes, outboxPayload))
	}
	assertPublishState(t, fixture.pool, 1, 1, 1, 1, 1)

	changedFields := createdStream.Forward
	updatedStream := fixture.updateStream(t, changedFields, "198.51.100.21")
	if updatedStream.Forward.Revision <= createdStream.Forward.Revision {
		t.Fatalf("update stream = %+v", updatedStream)
	}
	// One publication signs its site object root and each node's key
	// envelope; a replay or refused request signs nothing more.
	perPublication := fixture.signer.calls.Load()
	replayRequest := request
	replayRequest.RequestID = uuid.NewString()
	replayRequest.CorrelationID = uuid.NewString()
	replayRequest.Traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	replayTaskID := "publication-replay"
	replayRequest.TaskID = &replayTaskID
	replay, err := fixture.service.Publish(context.Background(), replayRequest)
	if err != nil || !replay.Replayed || replay.ConfigVersionID != result.ConfigVersionID || replay.SourceRevision != result.SourceRevision {
		t.Fatalf("publication replay = %+v, %v", replay, err)
	}
	if fixture.signer.calls.Load() != perPublication {
		t.Fatalf("sign calls after replay = %d, want %d", fixture.signer.calls.Load(), perPublication)
	}
	assertPublishState(t, fixture.pool, 1, 1, 1, 1, 1)
	conflict := request
	conflict.Deadline = conflict.Deadline.Add(time.Minute)
	if _, err := fixture.service.Publish(context.Background(), conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed idempotent request error = %v", err)
	}
	if fixture.signer.calls.Load() != perPublication {
		t.Fatalf("sign calls after idempotency conflict = %d, want %d", fixture.signer.calls.Load(), perPublication)
	}

	secondNode := uuid.New()
	seedPublishNode(t, fixture.pool, fixture.scopeID, fixture.userID, secondNode)
	duplicateRequestID := fixture.publishRequest("publish-duplicate-request-id", secondNode)
	duplicateRequestID.RequestID = request.RequestID
	if _, err := fixture.service.Publish(context.Background(), duplicateRequestID); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("duplicate request ID error = %v, want idempotency conflict", err)
	}
	if fixture.signer.calls.Load() != perPublication {
		t.Fatalf("sign calls after duplicate request ID = %d, want %d", fixture.signer.calls.Load(), perPublication)
	}
	assertPublishState(t, fixture.pool, 1, 1, 1, 1, 1)
	secondRequest := fixture.publishRequest("publish-secondary", secondNode)
	second, err := fixture.service.Publish(context.Background(), secondRequest)
	if err != nil {
		t.Fatal(err)
	}
	if second.ConfigVersionID != uuid.NewSHA1(fixture.scopeID, []byte(secondRequest.IdempotencyKey)) || second.ConfigVersionID == result.ConfigVersionID {
		t.Fatalf("second deterministic config ID = %s", second.ConfigVersionID)
	}
	if uuid.NewSHA1(uuid.New(), []byte(request.IdempotencyKey)) == result.ConfigVersionID {
		t.Fatal("changing scope did not change deterministic config ID")
	}
	if fixture.signer.calls.Load() != 2*perPublication {
		t.Fatalf("sign calls after distinct publish = %d, want %d", fixture.signer.calls.Load(), 2*perPublication)
	}
}

func TestPublishPlatformNodeClaimsOneTenantConfigurationScope(t *testing.T) {
	fixture := newPublishFixture(t)
	platformNodeID := uuid.New()
	seedPublishNode(t, fixture.pool, fixture.platformScopeID, fixture.platformUserID, platformNodeID)
	fixture.nodeID = platformNodeID
	fixture.createSite(t, "platform-node-binding.example", 80, false)

	first, err := fixture.service.Publish(context.Background(), fixture.publishRequest("platform-node-binding-first", platformNodeID))
	if err != nil {
		t.Fatal(err)
	}
	var nodeScopeID, configurationScopeID uuid.UUID
	if err := fixture.pool.QueryRow(context.Background(), `
		SELECT node.scope_id,state.configuration_scope_id
		FROM nodes node
		JOIN node_config_state state ON state.node_id=node.id
		WHERE node.id=$1`, platformNodeID).Scan(&nodeScopeID, &configurationScopeID); err != nil {
		t.Fatal(err)
	}
	if nodeScopeID != fixture.platformScopeID || configurationScopeID != fixture.scopeID {
		t.Fatalf("platform node scope=%s configuration scope=%s", nodeScopeID, configurationScopeID)
	}

	activatePublishedDeployment(t, fixture.pool, first.RolloutID)
	fixture.createSite(t, "platform-node-binding-second.example", 8080, false)
	second, err := fixture.service.Publish(context.Background(), fixture.publishRequest("platform-node-binding-second", platformNodeID))
	if err != nil || second.ConfigVersionID == first.ConfigVersionID {
		t.Fatalf("same-tenant platform node republish=%+v, %v", second, err)
	}
	activatePublishedDeployment(t, fixture.pool, second.RolloutID)

	otherScopeID := seedEmptyTenantScope(t, fixture.pool)
	crossTenant := fixture.publishRequest("platform-node-binding-cross-tenant", platformNodeID)
	crossTenant.ConfigurationScopeID = otherScopeID
	crossTenant.ExpectedSourceRevision = 1
	if _, err := fixture.service.Publish(context.Background(), crossTenant); !errors.Is(err, ErrTargetIneligible) {
		t.Fatalf("cross-tenant platform node publication=%v", err)
	}
	if err := fixture.pool.QueryRow(context.Background(), `
		SELECT scope_id FROM nodes WHERE id=$1`, platformNodeID).Scan(&nodeScopeID); err != nil {
		t.Fatal(err)
	}
	if err := fixture.pool.QueryRow(context.Background(), `
		SELECT configuration_scope_id FROM node_config_state WHERE node_id=$1`, platformNodeID).Scan(&configurationScopeID); err != nil {
		t.Fatal(err)
	}
	if nodeScopeID != fixture.platformScopeID || configurationScopeID != fixture.scopeID {
		t.Fatalf("cross-tenant attempt changed node scope=%s configuration scope=%s", nodeScopeID, configurationScopeID)
	}
}

func TestDeniedPlatformNodePublicationDoesNotClaimConfigurationScope(t *testing.T) {
	fixture := newPublishFixture(t)
	platformNodeID := uuid.New()
	seedPublishNode(t, fixture.pool, fixture.platformScopeID, fixture.platformUserID, platformNodeID)
	fixture.createSite(t, "platform-node-denied.example", 80, false)
	decision := validTestEntitlementDecision()
	decision.InGrace = true
	service := fixture.newService(t, &testEntitlementAuthorizer{decision: decision}, nil)
	if _, err := service.Publish(context.Background(), fixture.publishRequest("platform-node-denied", platformNodeID)); !errors.Is(err, ErrEntitlementDenied) {
		t.Fatalf("denied platform node publication=%v", err)
	}
	var states int
	if err := fixture.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM node_config_state WHERE node_id=$1`, platformNodeID).Scan(&states); err != nil {
		t.Fatal(err)
	}
	if states != 0 {
		t.Fatalf("denied publication claimed %d platform node states", states)
	}
}

func TestPublishCarriesCachePolicyAcrossListenersAndRollbackArtifact(t *testing.T) {
	fixture := newPublishFixture(t)
	created := fixture.createSiteWithPorts(t, "cache-policy.example", []string{"80", "8080"})
	cacheStore, err := cachecontrol.NewStore(fixture.pool, func() time.Time { return publishTestClock })
	if err != nil {
		t.Fatal(err)
	}
	cacheActor := cachecontrol.Actor{
		UserID: fixture.userID, ScopeID: fixture.scopeID, ActorScopeID: fixture.scopeID,
	}
	policy, err := cacheStore.PublishPolicy(context.Background(), cacheActor, cachecontrol.PublishPolicyRequest{
		SiteID: created.Site.ID, ExpectedRevision: 0,
		Document: cachecontrol.PolicyDocument{
			SchemaVersion: cachecontrol.PolicySchemaV2,
			Mode:          cachecontrol.PolicyOverride,
			Rules: []cachecontrol.Rule{{
				Order: 1, Extensions: []string{".css"}, PathPrefix: "/assets/",
				StatusCodes: []int{200, 304}, Action: cachecontrol.RuleActionCache,
				TTLSeconds: 300, BrowserTTLSeconds: 120,
			}, {
				Order: 2, PathPrefix: "/private/", Action: cachecontrol.RuleActionNoCache,
			}},
			QueryMode: cachecontrol.QueryInclude, QueryNames: []string{"lang", "version"},
			VaryHeaders: []string{"accept-encoding"}, DiskQuotaBytes: 128 << 20,
		},
		IdempotencyKey: "cache-policy-first", RequestID: "cache-policy-first-request",
	})
	if err != nil || policy.Policy.Revision != 1 {
		t.Fatalf("publish cache policy = %+v, %v", policy, err)
	}

	first, err := fixture.service.Publish(context.Background(), fixture.publishRequest("cache-bundle-first", fixture.nodeID))
	if err != nil {
		t.Fatal(err)
	}
	var originalWire []byte
	if err := fixture.pool.QueryRow(context.Background(), `
		SELECT wire_bytes FROM configuration_artifacts WHERE config_version_id=$1`, first.ConfigVersionID).Scan(&originalWire); err != nil {
		t.Fatal(err)
	}
	// The site carries its cache policy once; the node derives the per-listener
	// cache identity (siteruntimev2 compiler_cache.go).
	document := decodeReceivedV2Document(t, receivedV2Bundle(t, fixture, first, fixture.nodeID, fixture.nodeKeys[fixture.nodeID]))
	if len(document.Sites) != 1 || len(document.Sites[0].Listeners) != 2 || document.Sites[0].Cache == nil {
		t.Fatalf("published cached site = %+v", document.Sites)
	}
	cache := document.Sites[0].Cache
	if cache.TenantID != fixture.tenantID.String() || cache.Domain != "cache-policy.example" ||
		cache.Policy.SchemaVersion != edgeconfig.CachePolicyDocumentSchemaV2 || cache.Policy.Revision != 1 ||
		cache.Policy.Mode != edgeconfig.CacheOverride || len(cache.Policy.Rules) != 2 ||
		cache.Policy.Rules[0].Action != edgeconfig.CacheRuleActionCache || cache.Policy.Rules[0].BrowserTTLSeconds != 120 ||
		cache.Policy.Rules[1].Action != edgeconfig.CacheRuleActionNoCache || len(cache.Policy.QueryNames) != 2 ||
		cache.Policy.DiskQuotaBytes != 128<<20 {
		t.Fatalf("published cache binding = %+v", cache)
	}
	finishPublishDeployment(t, fixture, first, &first.ConfigVersionID, nil)

	if _, err := cacheStore.PublishPolicy(context.Background(), cacheActor, cachecontrol.PublishPolicyRequest{
		SiteID: created.Site.ID, ExpectedRevision: 1,
		Document: cachecontrol.PolicyDocument{
			SchemaVersion: cachecontrol.PolicySchemaV2, Mode: cachecontrol.PolicyDisabled, QueryMode: cachecontrol.QueryIgnore,
		},
		IdempotencyKey: "cache-policy-second", RequestID: "cache-policy-second-request",
	}); err != nil {
		t.Fatal(err)
	}
	second, err := fixture.service.Publish(context.Background(), fixture.publishRequest("cache-bundle-second", fixture.nodeID))
	if err != nil {
		t.Fatal(err)
	}
	finishPublishDeployment(t, fixture, second, &second.ConfigVersionID, &first.ConfigVersionID)
	rolledBack, err := fixture.service.Rollback(context.Background(), fixture.rollbackRequest("cache-bundle-rollback", first.PublicationID, fixture.nodeID))
	if err != nil || rolledBack.ConfigVersionID != first.ConfigVersionID {
		t.Fatalf("rollback cache bundle = %+v, %v", rolledBack, err)
	}
	var storedWire []byte
	if err := fixture.pool.QueryRow(context.Background(), `
		SELECT wire_bytes FROM configuration_artifacts WHERE config_version_id=$1`, first.ConfigVersionID).Scan(&storedWire); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(storedWire, originalWire) {
		t.Fatal("stored cache artifact changed after later publish and rollback")
	}
}

func TestPublishIAMSessionAuthorizationReplayMetadataAndRevocation(t *testing.T) {
	fixture := newPublishFixture(t)
	fixture.createSite(t, "iam-session.example", 80, false)
	service, actor := fixture.newIAMService(t)
	request := fixture.publishRequest("publish-iam-session", fixture.nodeID)
	request.Actor = actor
	request.Traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	taskID := "edgepublish-iam-smoke"
	request.TaskID = &taskID

	legacy, err := NewService(fixture.pool, fixture.deploymentStore(t), fixture.signer, fixture.config(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Publish(context.Background(), request); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("legacy constructor publish error = %v, want permission denied", err)
	}
	assertPublishState(t, fixture.pool, 0, 0, 0, 0, 0)

	created, err := service.Publish(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	replayedRequest := request
	replayedRequest.RequestID = uuid.NewString()
	replayedRequest.CorrelationID = uuid.NewString()
	replayed, err := service.Publish(context.Background(), replayedRequest)
	if err != nil || !replayed.Replayed || replayed.PublicationID != created.PublicationID {
		t.Fatalf("replay = %+v, %v", replayed, err)
	}
	assertPublishState(t, fixture.pool, 1, 1, 1, 1, 1)

	var payload map[string]any
	if err := fixture.pool.QueryRow(context.Background(), `SELECT payload FROM audit_events
		WHERE action='edge_publication.publish' AND resource_id=$1`, created.PublicationID.String()).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		"authentication_scope_id": actor.ScopeID.String(),
		"session_id":              actor.SessionID.String(),
		"correlation_id":          request.CorrelationID,
		"traceparent":             request.Traceparent,
		"task_id":                 taskID,
	} {
		if payload[key] != want {
			t.Fatalf("audit payload %s = %#v, want %q", key, payload[key], want)
		}
	}

	if err := pgx.BeginFunc(context.Background(), fixture.pool, func(tx pgx.Tx) error {
		if err := iamlock.AcquireExclusive(context.Background(), tx); err != nil {
			return err
		}
		if _, err := iamlock.AcquireScopes(context.Background(), tx, []uuid.UUID{actor.ScopeID}); err != nil {
			return err
		}
		_, err := tx.Exec(context.Background(), `UPDATE auth_sessions
			SET revoked_at=$2,revocation_reason='edgepublish_test'
			WHERE id=$1`, actor.SessionID, time.Now().UTC())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	denied := fixture.publishRequest("publish-after-session-revocation", fixture.nodeID)
	denied.Actor = actor
	if _, err := service.Publish(context.Background(), denied); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("revoked session publish error = %v, want authentication required", err)
	}
	assertPublishState(t, fixture.pool, 1, 1, 1, 1, 1)
}

func TestPublishConcurrentReplayHasOneWinner(t *testing.T) {
	fixture := newPublishFixture(t)
	fixture.createSite(t, "concurrent.example", 80, false)
	request := fixture.publishRequest("publish-concurrent", fixture.nodeID)
	results := make([]PublishResult, 2)
	errs := make([]error, 2)
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index := range results {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			results[index], errs[index] = fixture.service.Publish(context.Background(), request)
		}(index)
	}
	close(start)
	wait.Wait()
	if errs[0] != nil || errs[1] != nil || results[0].ConfigVersionID != results[1].ConfigVersionID || results[0].Replayed == results[1].Replayed {
		t.Fatalf("concurrent results=%+v errors=%v", results, errs)
	}
	// One publication to one node signs its site object root and the node's
	// key envelope; the losing replay signs nothing.
	if fixture.signer.calls.Load() != 2 {
		t.Fatalf("concurrent sign calls = %d, want 2 (one publication)", fixture.signer.calls.Load())
	}
	assertPublishState(t, fixture.pool, 1, 1, 1, 1, 1)
}

func TestManualPublishAndRollbackReplayAfterDeadline(t *testing.T) {
	fixture := newPublishFixture(t)
	clock := publishTestClock
	store, err := edgedeployment.NewStoreWithClock(fixture.pool, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	config := fixture.config(nil, nil)
	config.Clock = func() time.Time { return clock }
	service, err := newServiceWithWriteAuthorizer(
		fixture.pool, store, fixture.signer, config, fixtureWriteAuthorizer{},
	)
	if err != nil {
		t.Fatal(err)
	}

	fixture.createSite(t, "expired-replay.example", 80, false)
	firstRequest := fixture.publishRequest("publish-expired-replay-first", fixture.nodeID)
	first, err := service.Publish(t.Context(), firstRequest)
	if err != nil {
		t.Fatal(err)
	}
	finishPublishDeployment(t, fixture, first, &first.ConfigVersionID, nil)
	fixture.createStream(t, "expired-replay-second", 9443, "198.51.100.70", 9444)
	secondRequest := fixture.publishRequest("publish-expired-replay-second", fixture.nodeID)
	second, err := service.Publish(t.Context(), secondRequest)
	if err != nil {
		t.Fatal(err)
	}
	finishPublishDeployment(t, fixture, second, &second.ConfigVersionID, &first.ConfigVersionID)
	rollbackRequest := fixture.rollbackRequest("rollback-expired-replay", first.PublicationID, fixture.nodeID)
	rollback, err := service.Rollback(t.Context(), rollbackRequest)
	if err != nil {
		t.Fatal(err)
	}

	clock = firstRequest.Deadline
	publishReplayRequest := firstRequest
	publishReplayRequest.RequestID = uuid.NewString()
	publishReplayRequest.CorrelationID = uuid.NewString()
	publishReplay, err := service.Publish(t.Context(), publishReplayRequest)
	if err != nil || !publishReplay.Replayed || publishReplay.PublicationID != first.PublicationID ||
		publishReplay.RolloutID != first.RolloutID {
		t.Fatalf("expired publish replay=%+v error=%v", publishReplay, err)
	}
	publishConflict := publishReplayRequest
	publishConflict.MaxAttempts++
	if _, err := service.Publish(t.Context(), publishConflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("expired publish conflict error=%v", err)
	}
	freshExpiredPublish := fixture.publishRequest("publish-expired-new", fixture.nodeID)
	freshExpiredPublish.Deadline = clock
	if _, err := service.Publish(t.Context(), freshExpiredPublish); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("new expired publish error=%v", err)
	}

	rollbackReplayRequest := rollbackRequest
	rollbackReplay, err := service.Rollback(t.Context(), rollbackReplayRequest)
	if err != nil || !rollbackReplay.Replayed || rollbackReplay.RolloutID != rollback.RolloutID {
		t.Fatalf("expired rollback replay=%+v error=%v", rollbackReplay, err)
	}
	rollbackConflict := rollbackReplayRequest
	rollbackConflict.MaxAttempts++
	if _, err := service.Rollback(t.Context(), rollbackConflict); !errors.Is(err, edgedeployment.ErrIdempotencyConflict) {
		t.Fatalf("expired rollback conflict error=%v", err)
	}
	freshExpiredRollback := rollbackRequest
	freshExpiredRollback.IdempotencyKey = "rollback-expired-new"
	freshExpiredRollback.RequestID = uuid.NewString()
	freshExpiredRollback.CorrelationID = uuid.NewString()
	if _, err := service.Rollback(t.Context(), freshExpiredRollback); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("new expired rollback error=%v", err)
	}

	assertPublishState(t, fixture.pool, 2, 3, 3, 3, 2)
	var publishAudits, rollbackAudits int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM audit_events WHERE action='edge_publication.publish'),
		(SELECT count(*) FROM audit_events WHERE action='edge_publication.rollback')`).Scan(
		&publishAudits, &rollbackAudits); err != nil {
		t.Fatal(err)
	}
	if publishAudits != 2 || rollbackAudits != 1 {
		t.Fatalf("expired replay audits publish=%d rollback=%d", publishAudits, rollbackAudits)
	}
}

func TestPublishSourceRevisionCASAndConcurrentSingleWinner(t *testing.T) {
	fixture := newPublishFixture(t)
	fixture.createSite(t, "cas.example", 80, false)
	stale := fixture.publishRequest("publish-stale", fixture.nodeID)
	stale.ExpectedSourceRevision--
	if _, err := fixture.service.Publish(context.Background(), stale); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale source revision error = %v", err)
	}
	assertPublishState(t, fixture.pool, 0, 0, 0, 0, 0)

	secondNode := uuid.New()
	seedPublishNode(t, fixture.pool, fixture.scopeID, fixture.userID, secondNode)
	first := fixture.publishRequest("publish-cas-a", fixture.nodeID)
	second := fixture.publishRequest("publish-cas-b", secondNode)
	results := make([]PublishResult, 2)
	errs := make([]error, 2)
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index, request := range []PublishRequest{first, second} {
		wait.Add(1)
		go func(index int, request PublishRequest) {
			defer wait.Done()
			<-start
			results[index], errs[index] = fixture.service.Publish(context.Background(), request)
		}(index, request)
	}
	close(start)
	wait.Wait()
	succeeded, conflicted := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrRevisionConflict):
			conflicted++
		default:
			t.Fatalf("unexpected concurrent publish error: %v", err)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("concurrent outcomes success=%d conflict=%d results=%+v", succeeded, conflicted, results)
	}
	assertPublishState(t, fixture.pool, 1, 1, 1, 1, 1)
}

func TestPublishEntitlementTargetAndAuditFailuresRollBack(t *testing.T) {
	t.Run("inconsistent grace entitlement", func(t *testing.T) {
		fixture := newPublishFixture(t)
		fixture.createSite(t, "grace.example", 80, false)
		decision := validTestEntitlementDecision()
		decision.InGrace = true // InGrace with status "valid" is not a coherent decision.
		service := fixture.newService(t, &testEntitlementAuthorizer{decision: decision}, nil)
		if _, err := service.Publish(context.Background(), fixture.publishRequest("publish-grace", fixture.nodeID)); !errors.Is(err, ErrEntitlementDenied) {
			t.Fatalf("grace entitlement error = %v", err)
		}
		assertPublishState(t, fixture.pool, 0, 0, 0, 0, 0)
		var deniedAudits int
		if err := fixture.pool.QueryRow(context.Background(), `
			SELECT count(*) FROM audit_events
			WHERE action='edge_publication.entitlement_check' AND result='denied'`).Scan(&deniedAudits); err != nil {
			t.Fatal(err)
		}
		if deniedAudits != 1 {
			t.Fatalf("entitlement denied audits = %d", deniedAudits)
		}
	})

	t.Run("disabled target", func(t *testing.T) {
		fixture := newPublishFixture(t)
		fixture.createSite(t, "disabled-node.example", 80, false)
		if _, err := fixture.pool.Exec(context.Background(), `UPDATE nodes SET admin_state='disabled' WHERE id=$1`, fixture.nodeID); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.service.Publish(context.Background(), fixture.publishRequest("publish-disabled", fixture.nodeID)); !errors.Is(err, ErrTargetIneligible) {
			t.Fatalf("disabled target error = %v", err)
		}
		assertPublishState(t, fixture.pool, 0, 0, 0, 0, 0)
	})

	t.Run("audit append", func(t *testing.T) {
		fixture := newPublishFixture(t)
		fixture.createSite(t, "audit-failure.example", 80, false)
		service := fixture.newService(t, &testEntitlementAuthorizer{decision: validTestEntitlementDecision()}, failingAuditAppender{})
		if _, err := service.Publish(context.Background(), fixture.publishRequest("publish-audit-failure", fixture.nodeID)); err == nil {
			t.Fatal("audit failure accepted publication")
		}
		assertPublishState(t, fixture.pool, 0, 0, 0, 0, 0)
	})
}

func TestSourceRevisionTracksOriginFactsAndSiteCascade(t *testing.T) {
	fixture := newPublishFixture(t)
	created := fixture.createSite(t, "revision.example", 80, false)
	revision := readSourceRevision(t, fixture.pool, fixture.scopeID)

	if _, err := fixture.pool.Exec(context.Background(), `
		UPDATE site_origin_pools SET connect_timeout_ms=connect_timeout_ms+1 WHERE site_id=$1`, created.Site.ID); err != nil {
		t.Fatal(err)
	}
	revision = requireRevisionAdvance(t, fixture.pool, fixture.scopeID, revision, "origin pool update")

	if _, err := fixture.pool.Exec(context.Background(), `
		INSERT INTO site_origins (site_id,position,host,port,weight,enabled)
		VALUES ($1,2,'203.0.113.11',8081,2,true)`, created.Site.ID); err != nil {
		t.Fatal(err)
	}
	revision = requireRevisionAdvance(t, fixture.pool, fixture.scopeID, revision, "origin insert")

	if _, err := fixture.pool.Exec(context.Background(), `
		UPDATE site_origins SET weight=3 WHERE site_id=$1 AND position=2`, created.Site.ID); err != nil {
		t.Fatal(err)
	}
	revision = requireRevisionAdvance(t, fixture.pool, fixture.scopeID, revision, "origin update")

	if _, err := fixture.pool.Exec(context.Background(), `
		DELETE FROM site_origins WHERE site_id=$1 AND position=2`, created.Site.ID); err != nil {
		t.Fatal(err)
	}
	revision = requireRevisionAdvance(t, fixture.pool, fixture.scopeID, revision, "origin delete")

	if _, err := fixture.pool.Exec(context.Background(), `DELETE FROM sites WHERE id=$1`, created.Site.ID); err != nil {
		t.Fatal(err)
	}
	requireRevisionAdvance(t, fixture.pool, fixture.scopeID, revision, "site cascade delete")
	var pools, origins int
	if err := fixture.pool.QueryRow(context.Background(), `SELECT
		(SELECT count(*) FROM site_origin_pools WHERE site_id=$1),
		(SELECT count(*) FROM site_origins WHERE site_id=$1)`, created.Site.ID).Scan(&pools, &origins); err != nil {
		t.Fatal(err)
	}
	if pools != 0 || origins != 0 {
		t.Fatalf("site cascade left pools=%d origins=%d", pools, origins)
	}
}

func TestConcurrentOriginReplacementPublishesOnlyConsistentSnapshots(t *testing.T) {
	fixture := newPublishFixture(t)
	created := fixture.createSite(t, "snapshot.example", 80, false)
	poolA := fixtureOriginPool{
		Origins: []fixtureOrigin{
			{Host: "203.0.113.41", Port: 8041, Weight: 1, Enabled: true},
			{Host: "203.0.113.42", Port: 8042, Weight: 2, Enabled: true},
		},
		BalanceMethod: "round_robin", FailoverTries: 2, ConnectTimeoutMS: 3000, ReadTimeoutMS: 30000,
	}
	poolB := fixtureOriginPool{
		Origins: []fixtureOrigin{
			{Host: "203.0.113.51", Port: 8051, Weight: 3, Enabled: true},
			{Host: "203.0.113.52", Port: 8052, Weight: 4, Enabled: true},
		},
		BalanceMethod: "round_robin", FailoverTries: 2, ConnectTimeoutMS: 3000, ReadTimeoutMS: 30000,
	}
	current := fixture.replaceOriginPool(t, created.Site.ID, created.Site.Revision, poolA)

	for iteration := 0; iteration < 8; iteration++ {
		before := poolA
		target := poolB
		if iteration%2 == 1 {
			before, target = poolB, poolA
		}
		nodeID := uuid.New()
		seedPublishNode(t, fixture.pool, fixture.scopeID, fixture.userID, nodeID)
		publishRequest := fixture.publishRequest("publish-origin-race-"+strconv.Itoa(iteration), nodeID)
		start := make(chan struct{})
		var published PublishResult
		var updated fixtureSiteResult
		var publishErr, updateErr error
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			published, publishErr = fixture.service.Publish(context.Background(), publishRequest)
		}()
		go func() {
			defer wait.Done()
			<-start
			updated, updateErr = fixture.replaceOriginPoolResult(created.Site.ID, current.Site.Revision, target)
		}()
		close(start)
		wait.Wait()
		if updateErr != nil {
			t.Fatalf("iteration %d update=%v", iteration, updateErr)
		}
		current = updated
		if errors.Is(publishErr, ErrRevisionConflict) {
			continue
		}
		if publishErr != nil {
			t.Fatalf("iteration %d publish=%v", iteration, publishErr)
		}
		var snapshotBytes []byte
		if err := fixture.pool.QueryRow(context.Background(), `SELECT canonical_snapshot FROM config_versions WHERE id=$1`, published.ConfigVersionID).Scan(&snapshotBytes); err != nil {
			t.Fatal(err)
		}
		var snapshot siteRuntimeV2Document
		if err := json.Unmarshal(snapshotBytes, &snapshot); err != nil {
			t.Fatal(err)
		}
		if len(snapshot.Sites) != 1 || len(snapshot.Sites[0].OriginPools) == 0 ||
			(!sameRuntimeOrigins(snapshot.Sites[0].OriginPools[0].Origins, before.Origins) &&
				!sameRuntimeOrigins(snapshot.Sites[0].OriginPools[0].Origins, target.Origins)) {
			t.Fatalf("iteration %d published mixed origins: %+v", iteration, snapshot.Sites)
		}
	}
}

func TestPublishFailureLeavesNoPartialChain(t *testing.T) {
	t.Run("missing tenant scope", func(t *testing.T) {
		fixture := newPublishFixture(t)
		request := fixture.publishRequest("publish-missing-tenant-scope", fixture.nodeID)
		request.ConfigurationScopeID = uuid.New()
		if _, err := fixture.service.Publish(context.Background(), request); err == nil {
			t.Fatal("missing tenant scope accepted publication")
		}
		assertPublishState(t, fixture.pool, 0, 0, 0, 0, 0)
	})

	t.Run("platform scope without tenant", func(t *testing.T) {
		fixture := newPublishFixture(t)
		request := fixture.publishRequest("publish-platform-scope", fixture.nodeID)
		request.ConfigurationScopeID = fixture.platformScopeID
		if _, err := fixture.service.Publish(context.Background(), request); err == nil {
			t.Fatal("platform scope accepted tenant publication")
		}
		assertPublishState(t, fixture.pool, 0, 0, 0, 0, 0)
	})

	t.Run("tenant scope without tenant ID", func(t *testing.T) {
		fixture := newPublishFixture(t)
		fixture.createSite(t, "missing-tenant-id.example", 80, false)
		// The corruption is unreachable through the CHECK and the 067/079
		// classification guards (the tenant owner role carries those grants).
		if _, err := fixture.pool.Exec(context.Background(), `ALTER TABLE access_scopes DROP CONSTRAINT access_scopes_check`); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.pool.Exec(context.Background(), `ALTER TABLE access_scopes
			DISABLE TRIGGER access_scopes_protect_announcement_classification_067,
			DISABLE TRIGGER access_scopes_protect_package_commerce_classification_079`); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.pool.Exec(context.Background(), `UPDATE access_scopes SET tenant_id=NULL WHERE id=$1`, fixture.scopeID); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.service.Publish(context.Background(), fixture.publishRequest("publish-missing-tenant-id", fixture.nodeID)); err == nil {
			t.Fatal("tenant scope without tenant ID accepted publication")
		}
		assertPublishState(t, fixture.pool, 0, 0, 0, 0, 0)
	})

	t.Run("no active resources", func(t *testing.T) {
		fixture := newPublishFixture(t)
		// An empty scope publishes the health-only withdrawal sold package
		// stops rely on (TestSiteRuntimeV2PublishesEmptyWithdrawalAndL4OnlyScope).
		if _, err := fixture.service.Publish(context.Background(), fixture.publishRequest("publish-empty", fixture.nodeID)); err != nil {
			t.Fatalf("empty withdrawal publish error = %v", err)
		}
		assertPublishState(t, fixture.pool, 1, 1, 1, 1, 1)
	})

	t.Run("TLS material unavailable", func(t *testing.T) {
		fixture := newPublishFixture(t)
		fixture.createSite(t, "tls.example", 80, true)
		if _, err := fixture.service.Publish(context.Background(), fixture.publishRequest("publish-tls", fixture.nodeID)); !errors.Is(err, ErrTLSMaterialUnavailable) {
			t.Fatalf("TLS publish error = %v", err)
		}
		assertPublishState(t, fixture.pool, 0, 0, 0, 0, 0)
	})

	t.Run("HTTP and L4 port conflict", func(t *testing.T) {
		fixture := newPublishFixture(t)
		fixture.createStream(t, "conflicting-stream", 8080, "198.51.100.30", 9000)
		fixture.createSite(t, "port-conflict.example", 8080, false)
		// The site runtime's shared stream fragment refuses the conflicting socket.
		if _, err := fixture.service.Publish(context.Background(), fixture.publishRequest("publish-port-conflict", fixture.nodeID)); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("port conflict error = %v", err)
		}
		assertPublishState(t, fixture.pool, 0, 0, 0, 0, 0)
	})

	t.Run("publication insert failure", func(t *testing.T) {
		fixture := newPublishFixture(t)
		fixture.createSite(t, "late-failure.example", 80, false)
		if _, err := fixture.pool.Exec(context.Background(), `
			CREATE FUNCTION fail_edge_publication_insert() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN RAISE EXCEPTION 'forced publication failure'; END;
			$$;
			CREATE TRIGGER edge_publication_forced_failure
			BEFORE INSERT ON edge_config_publications
			FOR EACH ROW EXECUTE FUNCTION fail_edge_publication_insert()`); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.service.Publish(context.Background(), fixture.publishRequest("publish-late-failure", fixture.nodeID)); !errors.Is(err, ErrPersistence) {
			t.Fatalf("late publication error = %v", err)
		}
		assertPublishState(t, fixture.pool, 0, 0, 0, 0, 0)
	})

	t.Run("signing failure", func(t *testing.T) {
		fixture := newPublishFixture(t)
		fixture.createSite(t, "signing-failure.example", 80, false)
		fixture.signer.fail.Store(true)
		if _, err := fixture.service.Publish(context.Background(), fixture.publishRequest("publish-signing-failure", fixture.nodeID)); !errors.Is(err, ErrSigningFailed) {
			t.Fatalf("signing failure error = %v", err)
		}
		assertPublishState(t, fixture.pool, 0, 0, 0, 0, 0)
	})

	t.Run("active deployment rejects second publish", func(t *testing.T) {
		fixture := newPublishFixture(t)
		fixture.createSite(t, "active-deployment.example", 80, false)
		if _, err := fixture.service.Publish(context.Background(), fixture.publishRequest("publish-active-first", fixture.nodeID)); err != nil {
			t.Fatal(err)
		}
		fixture.createStream(t, "active-second-revision", 9000, "198.51.100.31", 9001)
		secondRequest := fixture.publishRequest("publish-active-second", fixture.nodeID)
		secondConfigID := uuid.NewSHA1(fixture.scopeID, []byte(secondRequest.IdempotencyKey))
		if _, err := fixture.service.Publish(context.Background(), secondRequest); !errors.Is(err, edgedeployment.ErrNodeDeploymentActive) {
			t.Fatalf("second active publish error = %v", err)
		}
		var secondConfigs int
		if err := fixture.pool.QueryRow(context.Background(), `SELECT count(*) FROM config_versions WHERE id=$1`, secondConfigID).Scan(&secondConfigs); err != nil {
			t.Fatal(err)
		}
		if secondConfigs != 0 {
			t.Fatalf("failed second publish left config %s", secondConfigID)
		}
		assertPublishState(t, fixture.pool, 1, 1, 1, 1, 1)
	})
}

func TestRollbackCreatesOnlyDirectPreviousDeployment(t *testing.T) {
	t.Run("success and idempotent replay", func(t *testing.T) {
		fixture := newPublishFixture(t)
		fixture.createSite(t, "rollback.example", 80, false)
		first, err := fixture.service.Publish(context.Background(), fixture.publishRequest("rollback-first", fixture.nodeID))
		if err != nil {
			t.Fatal(err)
		}
		finishPublishDeployment(t, fixture, first, &first.ConfigVersionID, nil)

		fixture.createStream(t, "rollback-second", 9443, "198.51.100.40", 9444)
		second, err := fixture.service.Publish(context.Background(), fixture.publishRequest("rollback-second", fixture.nodeID))
		if err != nil {
			t.Fatal(err)
		}
		finishPublishDeployment(t, fixture, second, &second.ConfigVersionID, &first.ConfigVersionID)

		request := fixture.rollbackRequest("rollback-direct-previous", first.PublicationID, fixture.nodeID)
		result, err := fixture.service.Rollback(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		if result.Replayed || result.ConfigVersionID != first.ConfigVersionID || result.PublicationID != first.PublicationID ||
			result.NodeCount != 1 || result.TargetKind != TargetKindExplicit {
			t.Fatalf("rollback result = %+v", result)
		}

		var action string
		var commandBytes []byte
		var artifactBindings int
		if err := fixture.pool.QueryRow(context.Background(), `
			SELECT rollout.action,deployment.command_bytes,
			       (SELECT count(*) FROM node_deployment_artifacts artifact
			        WHERE artifact.deployment_id=deployment.id AND artifact.deployment_attempt=deployment.attempt)
			FROM rollouts rollout
			JOIN node_deployments deployment ON deployment.rollout_id=rollout.id
			WHERE rollout.id=$1 AND deployment.node_id=$2`, result.RolloutID, fixture.nodeID).Scan(
			&action, &commandBytes, &artifactBindings); err != nil {
			t.Fatal(err)
		}
		command := new(agentv1.DeploymentCommand)
		if err := proto.Unmarshal(commandBytes, command); err != nil {
			t.Fatal(err)
		}
		if action != "rollback" || command.Action != agentv1.DeploymentAction_DEPLOYMENT_ACTION_ROLLBACK ||
			command.ConfigVersionId != first.ConfigVersionID.String() || command.PreviousConfigVersionId == nil ||
			*command.PreviousConfigVersionId != second.ConfigVersionID.String() ||
			len(command.Artifacts) != 0 || artifactBindings != 0 {
			t.Fatalf("rollback command=%+v action=%q artifact_bindings=%d", command, action, artifactBindings)
		}

		var auditCount int
		var auditPayload map[string]any
		if err := fixture.pool.QueryRow(context.Background(), `
			SELECT payload
			FROM audit_events
			WHERE action='edge_publication.rollback' AND resource_id=$1`, first.PublicationID.String()).Scan(&auditPayload); err != nil {
			t.Fatal(err)
		}
		if err := fixture.pool.QueryRow(context.Background(), `
			SELECT count(*) FROM audit_events
			WHERE action='edge_publication.rollback' AND resource_id=$1`, first.PublicationID.String()).Scan(&auditCount); err != nil {
			t.Fatal(err)
		}
		if auditCount != 1 || auditPayload["operation"] != "rollback" || auditPayload["reason"] != "operator_requested" ||
			auditPayload["config_version_id"] != first.ConfigVersionID.String() {
			t.Fatalf("rollback audit count=%d payload=%v", auditCount, auditPayload)
		}
		replay, err := fixture.service.Rollback(context.Background(), request)
		if err != nil || !replay.Replayed || replay.RolloutID != result.RolloutID {
			t.Fatalf("rollback replay = %+v, %v", replay, err)
		}
		if err := fixture.pool.QueryRow(context.Background(), `
			SELECT count(*) FROM audit_events
			WHERE action='edge_publication.rollback' AND resource_id=$1`, first.PublicationID.String()).Scan(&auditCount); err != nil {
			t.Fatal(err)
		}
		if auditCount != 1 {
			t.Fatalf("rollback replay audit count=%d, want 1", auditCount)
		}
		assertPublishState(t, fixture.pool, 2, 3, 3, 3, 2)
	})

	t.Run("unknown publication leaves no facts", func(t *testing.T) {
		fixture := newPublishFixture(t)
		request := fixture.rollbackRequest("rollback-unknown", uuid.New(), fixture.nodeID)
		if _, err := fixture.service.Rollback(context.Background(), request); !errors.Is(err, ErrNotFound) {
			t.Fatalf("unknown publication rollback error=%v", err)
		}
		assertPublishState(t, fixture.pool, 0, 0, 0, 0, 0)
	})

	t.Run("non previous version leaves no rollout", func(t *testing.T) {
		fixture := newPublishFixture(t)
		fixture.createSite(t, "rollback-not-previous.example", 80, false)
		first, err := fixture.service.Publish(context.Background(), fixture.publishRequest("rollback-not-previous-first", fixture.nodeID))
		if err != nil {
			t.Fatal(err)
		}
		finishPublishDeployment(t, fixture, first, &first.ConfigVersionID, nil)
		request := fixture.rollbackRequest("rollback-not-previous", first.PublicationID, fixture.nodeID)
		if _, err := fixture.service.Rollback(context.Background(), request); !errors.Is(err, edgedeployment.ErrRollbackStateConflict) {
			t.Fatalf("non-previous rollback error=%v", err)
		}
		assertPublishState(t, fixture.pool, 1, 1, 1, 1, 1)
	})

	t.Run("active deployment leaves no partial rollback", func(t *testing.T) {
		fixture := newPublishFixture(t)
		fixture.createSite(t, "rollback-active.example", 80, false)
		first, err := fixture.service.Publish(context.Background(), fixture.publishRequest("rollback-active-first", fixture.nodeID))
		if err != nil {
			t.Fatal(err)
		}
		finishPublishDeployment(t, fixture, first, &first.ConfigVersionID, nil)
		fixture.createStream(t, "rollback-active-second", 9553, "198.51.100.41", 9554)
		second, err := fixture.service.Publish(context.Background(), fixture.publishRequest("rollback-active-second", fixture.nodeID))
		if err != nil {
			t.Fatal(err)
		}
		setNodeConfigState(t, fixture, &second.ConfigVersionID, &first.ConfigVersionID)
		request := fixture.rollbackRequest("rollback-while-active", first.PublicationID, fixture.nodeID)
		if _, err := fixture.service.Rollback(context.Background(), request); !errors.Is(err, edgedeployment.ErrNodeDeploymentActive) {
			t.Fatalf("active deployment rollback error=%v", err)
		}
		assertPublishState(t, fixture.pool, 2, 2, 2, 2, 2)
	})

	t.Run("reconciliation leaves no partial rollback", func(t *testing.T) {
		fixture := newPublishFixture(t)
		fixture.createSite(t, "rollback-reconcile.example", 80, false)
		first, err := fixture.service.Publish(context.Background(), fixture.publishRequest("rollback-reconcile-first", fixture.nodeID))
		if err != nil {
			t.Fatal(err)
		}
		finishPublishDeployment(t, fixture, first, &first.ConfigVersionID, nil)
		fixture.createStream(t, "rollback-reconcile-second", 9663, "198.51.100.42", 9664)
		second, err := fixture.service.Publish(context.Background(), fixture.publishRequest("rollback-reconcile-second", fixture.nodeID))
		if err != nil {
			t.Fatal(err)
		}
		finishPublishDeployment(t, fixture, second, &second.ConfigVersionID, &first.ConfigVersionID)
		var deploymentID uuid.UUID
		if err := fixture.pool.QueryRow(context.Background(), `SELECT id FROM node_deployments WHERE rollout_id=$1`, second.RolloutID).Scan(&deploymentID); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.pool.Exec(context.Background(), `
			UPDATE node_config_state
			SET reconciliation_required=true,reconciliation_reason='rollback_failed',
			    reconciliation_deployment_id=$2,reconciliation_deployment_attempt=1,
			    reconciliation_requested_at=$3,revision=revision+1,updated_at=$3
			WHERE node_id=$1`, fixture.nodeID, deploymentID, publishTestClock); err != nil {
			t.Fatal(err)
		}
		request := fixture.rollbackRequest("rollback-reconciliation", first.PublicationID, fixture.nodeID)
		if _, err := fixture.service.Rollback(context.Background(), request); !errors.Is(err, edgedeployment.ErrNodeReconciliationRequired) {
			t.Fatalf("reconciliation rollback error=%v", err)
		}
		assertPublishState(t, fixture.pool, 2, 2, 2, 2, 2)
	})
}

func TestEdgePublicationMigrationRoundTrip(t *testing.T) {
	pool := openPublishTestDatabase(t, false)
	if err := migratePublishVersionIsolated(context.Background(), pool, "up", 46); err != nil {
		t.Fatal(err)
	}
	assertPublicationMigrationApplied(t, pool)
	migratePublishDownToVersion(t, pool, 45)
	assertMigrationState(t, pool, 45, true)
	if err := migratePublishVersionIsolated(context.Background(), pool, "up", 46); err != nil {
		t.Fatal(err)
	}
	assertMigrationState(t, pool, 46, true)
	migratePublishDownToVersion(t, pool, 20)
	assertMigrationState(t, pool, 20, false)
	if err := migratePublishVersionIsolated(context.Background(), pool, "up", 46); err != nil {
		t.Fatal(err)
	}
	assertPublicationMigrationApplied(t, pool)
}

func (fixture *publishFixture) createSite(t *testing.T, domain string, port int, https bool) fixtureSiteResult {
	t.Helper()
	httpsPorts := []string{}
	if https {
		httpsPorts = []string{"443"}
	}
	return fixture.createSiteWithPortSets(t, domain, []string{strconv.Itoa(port)}, httpsPorts, https)
}

func (fixture *publishFixture) createSiteWithPorts(t *testing.T, domain string, ports []string) fixtureSiteResult {
	t.Helper()
	return fixture.createSiteWithPortSets(t, domain, ports, []string{}, false)
}

func (fixture *publishFixture) createSiteWithPortSets(t *testing.T, domain string, httpPorts, httpsPorts []string, https bool) fixtureSiteResult {
	t.Helper()
	result, err := fixture.createSiteResult(domain, httpPorts, httpsPorts, https)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func (fixture *publishFixture) createSiteResult(domain string, httpPorts, httpsPorts []string, https bool) (fixtureSiteResult, error) {
	item := fixtureSite{ID: uuid.New(), Domain: domain, Revision: 1}
	err := pgx.BeginFunc(context.Background(), fixture.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(context.Background(), `
			WITH allocated AS (
				INSERT INTO site_display_id_sequences(scope_id,next_value,updated_at)
				VALUES($2,2,$10)
				ON CONFLICT(scope_id) DO UPDATE SET
					next_value=site_display_id_sequences.next_value+1,
					updated_at=EXCLUDED.updated_at
				RETURNING next_value-1 AS display_id
			)
			INSERT INTO sites (
				id,display_id,scope_id,owner_user_id,domain,http_ports,https_ports,origins,origin_hosts,
				https_enabled,enabled,status,created_by_user_id,updated_by_user_id,
				created_at,updated_at
			) SELECT $1,allocated.display_id,$2,$3,$4,$5,$6,$7,$8,$9,true,'active',$3,$3,$10,$10
			FROM allocated`,
			item.ID, fixture.scopeID, fixture.userID, domain, httpPorts, httpsPorts,
			[]string{"203.0.113.10:8080"}, []string{"203.0.113.10"}, https, publishTestClock); err != nil {
			return err
		}
		if _, err := tx.Exec(context.Background(), `
			INSERT INTO site_origin_pools (
				site_id,balance_method,failover_tries,connect_timeout_ms,read_timeout_ms,updated_at
			) VALUES ($1,'round_robin',1,3000,30000,$2)`, item.ID, publishTestClock); err != nil {
			return err
		}
		if _, err := tx.Exec(context.Background(), `
			INSERT INTO site_origins (site_id,position,host,port,weight,enabled)
			VALUES ($1,1,'203.0.113.10',8080,1,true)`, item.ID); err != nil {
			return err
		}
		// Only a site on a valid package is published (fix-nopkgpub): the
		// fixture's sites are on its subscription, as a tenant's would be.
		if fixture.subscriptionID == uuid.Nil {
			return nil
		}
		return bindFixtureSitePackage(context.Background(), tx, fixture.scopeID, fixture.userID, fixture.subscriptionID, item.ID)
	})
	return fixtureSiteResult{Site: item}, err
}

// bindFixtureSitePackage puts siteID on subscriptionID, with the owner
// projection sites_package_subscription_owner_113_fk requires.
func bindFixtureSitePackage(ctx context.Context, tx pgx.Tx, scopeID, userID, subscriptionID, siteID uuid.UUID) error {
	if _, err := tx.Exec(ctx, `INSERT INTO package_monitor_subscription_owners(subscription_id,state_revision,tenant_scope_id,
		owner_user_id,source_kind,created_at) VALUES($1,1,$2,$3,'subscription_state',clock_timestamp())
		ON CONFLICT DO NOTHING`, subscriptionID, scopeID, userID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE sites SET package_subscription_id=$2,
		package_id=(SELECT product_id FROM package_subscriptions WHERE id=$2) WHERE id=$1`, siteID, subscriptionID)
	return err
}

// unbindSitePackage takes siteID off its package (has → has not), as an
// edit that drops the binding would.
func (fixture *publishFixture) unbindSitePackage(t *testing.T, siteID uuid.UUID) {
	t.Helper()
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE sites SET package_subscription_id=NULL,package_id=NULL,
		revision=revision+1 WHERE id=$1`, siteID); err != nil {
		t.Fatal(err)
	}
}

// createStream inserts a v2 L4 forward the way l4forward.Store writes one
// (row + latest publish intent); a stream belongs to no website (492).
func (fixture *publishFixture) createStream(t *testing.T, name string, port uint16, upstream string, upstreamPort uint16) fixtureStreamResult {
	t.Helper()
	item := fixtureStream{
		ID: uuid.New(), Revision: 1, Protocol: "tcp", ListenAddress: "*", ListenPort: port,
		UpstreamAddress: upstream, UpstreamPort: upstreamPort, ConnectTimeoutMS: 3000,
		ResponseTimeoutMS: 30000, MaxConnectionsPerClient: 37, ProxyProtocolV1: true, Enabled: true,
	}
	err := pgx.BeginFunc(context.Background(), fixture.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(context.Background(), `
			INSERT INTO l4_forwards (
				id,scope_id,owner_user_id,name,protocol,listen_address,listen_port,
				upstream_address,upstream_port,connect_timeout_ms,response_timeout_ms,
				package_subscription_id,max_connections_per_client,proxy_protocol_v1,enabled,
				created_by_user_id,updated_by_user_id,created_at,updated_at
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::inet,$9,$10,$11,$12,$13,$14,$15,$3,$3,$16,$16)`,
			item.ID, fixture.scopeID, fixture.userID, name, item.Protocol, item.ListenAddress, item.ListenPort,
			item.UpstreamAddress, item.UpstreamPort, item.ConnectTimeoutMS, item.ResponseTimeoutMS,
			fixture.subscriptionID, item.MaxConnectionsPerClient, item.ProxyProtocolV1, item.Enabled, publishTestClock); err != nil {
			return err
		}
		return fixture.appendStreamIntent(tx, item, "create")
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixtureStreamResult{Forward: item}
}

func (fixture *publishFixture) updateStream(t *testing.T, current fixtureStream, upstream string) fixtureStreamResult {
	t.Helper()
	item := current
	item.UpstreamAddress = upstream
	err := pgx.BeginFunc(context.Background(), fixture.pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(context.Background(), `
			UPDATE l4_forwards SET
				upstream_address=$2::inet,revision=revision+1,updated_by_user_id=$3,updated_at=$4
			WHERE id=$1 AND revision=$5 AND deleted_at IS NULL
			RETURNING revision`, item.ID, item.UpstreamAddress, fixture.userID, publishTestClock, current.Revision).Scan(&item.Revision); err != nil {
			return err
		}
		return fixture.appendStreamIntent(tx, item, "update")
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixtureStreamResult{Forward: item}
}

// appendStreamIntent records item's v2 runtime as its latest publish intent.
func (fixture *publishFixture) appendStreamIntent(tx pgx.Tx, item fixtureStream, operation string) error {
	scope, stream := fixture.scopeID.String(), item.ID.String()
	runtime, err := json.Marshal(edgeconfig.L4StreamRuntimeV2{
		SchemaVersion: "cdnca.edge.l4/v2", TenantID: scope, StreamID: stream, Revision: item.Revision,
		Listener: edgeconfig.L4ListenerV2{Protocol: item.Protocol, Address: item.ListenAddress, Port: int(item.ListenPort)},
		Endpoint: edgeconfig.L4EndpointV2{Address: item.UpstreamAddress, Port: int(item.UpstreamPort)},
		Geo: edgeconfig.L4GeoPolicyV2{TenantID: scope, StreamID: stream, Revision: item.Revision,
			UnknownRegionAction: "allow", TrustedProxyCIDRs: []string{}, BlockedRegions: []string{}, RegionCIDRs: []edgeconfig.L4RegionCIDRsV2{}},
		ConnectTimeoutMS: item.ConnectTimeoutMS, ResponseTimeoutMS: item.ResponseTimeoutMS,
		MaxConnectionsPerClient: item.MaxConnectionsPerClient, DrainTimeoutMS: 30000,
		ProxyProtocolOutbound: item.ProxyProtocolV1,
	})
	if err != nil {
		return err
	}
	tag, err := tx.Exec(context.Background(), `
		INSERT INTO l4_publish_intents (
			id,scope_id,stream_id,version,operation,desired_state,resource_revision,
			configuration_source_revision,runtime_spec,created_by_user_id,created_at
		) SELECT $1,$2,$3,
			COALESCE((SELECT max(version) FROM l4_publish_intents WHERE scope_id=$2),0)+1,
			$4,'enabled',$5,scope.source_revision,$6::jsonb,$7,$8
		FROM edge_configuration_scopes scope WHERE scope.scope_id=$2`,
		uuid.New(), fixture.scopeID, item.ID, operation, item.Revision, runtime, fixture.userID, publishTestClock)
	if err == nil && tag.RowsAffected() != 1 {
		err = fmt.Errorf("stream %s publish intent rows=%d", item.ID, tag.RowsAffected())
	}
	return err
}

func (fixture *publishFixture) replaceOriginPool(t *testing.T, siteID uuid.UUID, expectedRevision int64, pool fixtureOriginPool) fixtureSiteResult {
	t.Helper()
	result, err := fixture.replaceOriginPoolResult(siteID, expectedRevision, pool)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func (fixture *publishFixture) replaceOriginPoolResult(siteID uuid.UUID, expectedRevision int64, pool fixtureOriginPool) (fixtureSiteResult, error) {
	var result fixtureSiteResult
	err := pgx.BeginFunc(context.Background(), fixture.pool, func(tx pgx.Tx) error {
		command, err := tx.Exec(context.Background(), `
			UPDATE site_origin_pools SET
				balance_method=$2,failover_tries=$3,connect_timeout_ms=$4,read_timeout_ms=$5,updated_at=$6
			WHERE site_id=$1`, siteID, pool.BalanceMethod, pool.FailoverTries,
			pool.ConnectTimeoutMS, pool.ReadTimeoutMS, publishTestClock)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return fmt.Errorf("site origin pool %s not found", siteID)
		}
		if _, err := tx.Exec(context.Background(), `DELETE FROM site_origins WHERE site_id=$1`, siteID); err != nil {
			return err
		}
		origins := make([]string, len(pool.Origins))
		hosts := make([]string, len(pool.Origins))
		for index, origin := range pool.Origins {
			if _, err := tx.Exec(context.Background(), `
				INSERT INTO site_origins (site_id,position,host,port,weight,enabled)
				VALUES ($1,$2,$3,$4,$5,$6)`, siteID, index+1, origin.Host, origin.Port, origin.Weight, origin.Enabled); err != nil {
				return err
			}
			hosts[index] = origin.Host
			origins[index] = fmt.Sprintf("%s:%d", origin.Host, origin.Port)
		}
		return tx.QueryRow(context.Background(), `
			UPDATE sites SET
				origins=$2,origin_hosts=$3,revision=revision+1,updated_by_user_id=$4,updated_at=$5
			WHERE id=$1 AND revision=$6 AND deleted_at IS NULL
			RETURNING id,domain,revision`,
			siteID, origins, hosts, fixture.userID, publishTestClock, expectedRevision).Scan(
			&result.Site.ID, &result.Site.Domain, &result.Site.Revision)
	})
	return result, err
}

// publishRequest publishes the site runtime (v2) to nodeID, which gets a
// real 1.0.35 identity on first use unless the test registered it already.
func (fixture *publishFixture) publishRequest(key string, nodeID uuid.UUID) PublishRequest {
	fixture.ensureV2Node(nodeID)
	return PublishRequest{
		Actor:                Actor{UserID: fixture.platformUserID, ScopeID: fixture.platformScopeID, ScopeKind: ScopeKindPlatform},
		ConfigurationScopeID: fixture.scopeID, ExpectedSourceRevision: fixture.sourceRevision(),
		NodeIDs: []uuid.UUID{nodeID}, MaxAttempts: 3,
		HealthCheck: edgedeployment.HealthCheckPolicy{
			ActivationTimeout: time.Minute, ObservationWindow: 5 * time.Second, RequiredConsecutiveSuccesses: 2,
		},
		Deadline: publishTestClock.Add(time.Hour), IdempotencyKey: key,
		RequestID: uuid.NewString(), CorrelationID: uuid.NewString(),
	}
}

func (fixture *publishFixture) rollbackRequest(key string, publicationID, nodeID uuid.UUID) RollbackRequest {
	return RollbackRequest{
		Actor:                fixture.publishRequest("unused", nodeID).Actor,
		ConfigurationScopeID: fixture.scopeID, PublicationID: publicationID, NodeIDs: []uuid.UUID{nodeID}, MaxAttempts: 3,
		HealthCheck: edgedeployment.HealthCheckPolicy{
			ActivationTimeout: time.Minute, ObservationWindow: 5 * time.Second, RequiredConsecutiveSuccesses: 2,
		},
		Deadline: publishTestClock.Add(time.Hour), IdempotencyKey: key,
		RequestID: uuid.NewString(), CorrelationID: uuid.NewString(),
	}
}

func finishPublishDeployment(
	t *testing.T,
	fixture *publishFixture,
	publication PublishResult,
	current, previous *uuid.UUID,
) {
	t.Helper()
	var deploymentID uuid.UUID
	var attempt int
	var transitionSequence int64
	if err := fixture.pool.QueryRow(t.Context(), `
		SELECT deployment.id,deployment.attempt,COALESCE(max(event.transition_sequence),0)
		FROM node_deployments deployment
		LEFT JOIN deployment_status_events event
		  ON event.deployment_id=deployment.id AND event.attempt=deployment.attempt
		WHERE deployment.rollout_id=$1 AND deployment.node_id=$2
		GROUP BY deployment.id,deployment.attempt`, publication.RolloutID, fixture.nodeID).Scan(
		&deploymentID, &attempt, &transitionSequence); err != nil {
		t.Fatal(err)
	}
	for index, state := range []string{"delivered", "staged", "prechecked", "activated", "healthy"} {
		transitionSequence++
		at := publishTestClock.Add(time.Duration(index+1) * time.Second)
		payload := []byte("edge-publish-test-status-" + state)
		digest := sha256.Sum256(payload)
		if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(t.Context(), `INSERT INTO deployment_status_events(
				id,deployment_id,event_id,attempt,transition_sequence,state,payload,payload_sha256,occurred_at,received_at)
				VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9)`, uuid.New(), deploymentID, uuid.New(), attempt,
				transitionSequence, state, payload, digest[:], at); err != nil {
				return err
			}
			_, err := tx.Exec(t.Context(), `UPDATE node_deployments SET state=$2,updated_at=$3
				WHERE id=$1 AND attempt=$4`, deploymentID, state, at, attempt)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	setNodeConfigState(t, fixture, current, previous)
}

func setNodeConfigState(t *testing.T, fixture *publishFixture, current, previous *uuid.UUID) {
	t.Helper()
	if _, err := fixture.pool.Exec(context.Background(), `
		UPDATE node_config_state
		SET configuration_scope_id=$2,current_config_version_id=$3,previous_config_version_id=$4,
		    revision=revision+1,updated_at=$5
		WHERE node_id=$1`, fixture.nodeID, fixture.scopeID, current, previous, publishTestClock); err != nil {
		t.Fatal(err)
	}
}

func (fixture *publishFixture) sourceRevision() int64 {
	var revision int64
	if err := fixture.pool.QueryRow(context.Background(), `
		SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1`, fixture.scopeID).Scan(&revision); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 1
		}
		panic(err)
	}
	return revision
}

func (fixture *publishFixture) newService(
	t *testing.T,
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
	config.EntitlementAuthorizer = authorizer
	config.Auditor = auditor
	service, err := newServiceWithWriteAuthorizer(fixture.pool, store, fixture.signer, config, fixtureWriteAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func (fixture *publishFixture) deploymentStore(t *testing.T) *edgedeployment.Store {
	t.Helper()
	store, err := edgedeployment.NewStoreWithClock(fixture.pool, func() time.Time { return publishTestClock })
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func (fixture *publishFixture) config(authorizer EntitlementAuthorizer, auditor AuditAppender) Config {
	config := DefaultConfig()
	config.Clock = func() time.Time { return publishTestClock }
	if authorizer == nil {
		authorizer = &testEntitlementAuthorizer{decision: validTestEntitlementDecision()}
	}
	config.EntitlementAuthorizer = authorizer
	config.Auditor = auditor
	return config
}

func (fixture *publishFixture) newIAMService(t *testing.T) (*Service, Actor) {
	t.Helper()
	tokens, err := identity.NewTokenManager("edgepublish-iam-test-access-token-secret", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := sessioncredential.NewVerifier(tokens, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x61}, 32), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := uuid.New()
	now := time.Now().UTC().Truncate(time.Microsecond)
	refreshDigest := sha256.Sum256(sessionID[:])
	if _, err := fixture.pool.Exec(context.Background(), `INSERT INTO auth_sessions(
		id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
	) VALUES($1,$2,$3,$4,$5,$6,$7)`, sessionID, uuid.New(), fixture.platformUserID,
		fixture.platformScopeID, refreshDigest[:], now.Add(-time.Minute), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	rawToken, _, err := tokens.Mint(fixture.platformUserID, fixture.platformScopeID, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	actor, err := NewSessionActor(fixture.platformUserID, fixture.platformScopeID, ScopeKindPlatform, sessionID, rawToken)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewIAMService(fixture.pool, fixture.deploymentStore(t), fixture.signer, fixture.config(nil, nil), authorizer)
	if err != nil {
		t.Fatal(err)
	}
	return service, actor
}

func seedPublishNode(t *testing.T, pool *pgxpool.Pool, scopeID, userID, nodeID uuid.UUID) []byte {
	t.Helper()
	createdAt := publishNodeCreatedAt
	insertPublishNode(t, pool, scopeID, userID, nodeID,
		"publish-node-"+strings.ReplaceAll(nodeID.String(), "-", "")[:12])
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := privateKey.PublicKey().Bytes()
	publicKeyDigest := sha256.Sum256(publicKey)
	keyID := "x25519:" + hex.EncodeToString(publicKeyDigest[:])
	tokenID, authorizationID, requestID := uuid.New(), uuid.New(), uuid.New()
	now := createdAt
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(t.Context(), `INSERT INTO node_enrollment_tokens(
		id,node_id,purpose,token_hash,created_by_user_id,created_at,expires_at,consumed_at,consume_request_id,consume_request_digest
	) VALUES($1,$2,'initial_enrollment',$3,$4,$5,$6,$5,$7,$8)`, tokenID, nodeID, publishTestDigest(), userID,
		now, publishTestClock.Add(time.Hour), requestID.String(), publishTestDigest()); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO node_enrollment_authorizations(
		id,token_id,node_id,purpose,request_id,request_digest,authorized_at
	) VALUES($1,$2,$3,'initial_enrollment',$4,$5,$6)`, authorizationID, tokenID, nodeID,
		requestID.String(), publishTestDigest(), now); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO node_identity_authorizations(
		id,token_id,node_id,purpose,request_id,request_digest,token_hash,csr_der,csr_sha256,
		machine_fingerprint_sha256,protocol_min_major,protocol_min_minor,protocol_max_major,protocol_max_minor,
		selected_protocol_major,selected_protocol_minor,capabilities_snapshot,capabilities_sha256,
		gateway_workload_identity,gateway_instance_id,artifact_key_id,artifact_public_key,status,authorized_at,expires_at
	) VALUES($1,$2,$3,'initial_enrollment',$4,$5,$6,$7,$8,$9,1,0,1,0,1,0,$10,$11,
		'spiffe://cdnca.test/gateway','edgepublish-test',$12,$13,'authorized',$14,$15)`,
		authorizationID, tokenID, nodeID, requestID, publishTestDigest(), publishTestDigest(), []byte{0x30},
		publishTestDigest(), publishTestDigest(), []byte{0x01}, publishTestDigest(), keyID, publicKey, now, publishTestClock.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO node_artifact_encryption_keys(
		id,node_id,authorization_id,public_key,public_key_sha256,status,created_at,activated_at
	) VALUES($1,$2,$3,$4,$5,'active',$6,$6)`, keyID, nodeID, authorizationID, publicKey, publicKeyDigest[:], now); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `UPDATE node_identity_state SET active_artifact_key_id=$2,
		authorization_revision=authorization_revision+1,updated_at=GREATEST(updated_at,$3) WHERE node_id=$1`, nodeID, keyID, createdAt); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	return privateKey.Bytes()
}

// ensureV2Node gives nodeID a real 1.0.35 publication identity (issued
// certificate, active artifact key, declared capabilities) unless it has an
// issued certificate already: a second real registration of one node fails.
// It returns the node's artifact private key when this fixture registered it.
func (fixture *publishFixture) ensureV2Node(nodeID uuid.UUID) []byte {
	t := fixture.t
	t.Helper()
	if fixture.nodeKeys == nil {
		return nil
	}
	if key, ok := fixture.nodeKeys[nodeID]; ok {
		return key
	}
	// A node a test registered itself, or one that is missing or not active
	// (refusal tests), is left as it is.
	var eligible bool
	if err := fixture.pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM nodes WHERE id=$1 AND admin_state='active')
		AND NOT EXISTS(SELECT 1 FROM node_certificates WHERE node_id=$1)`, nodeID).Scan(&eligible); err != nil {
		t.Fatal(err)
	}
	if !eligible {
		return nil
	}
	key := capabilitytest.SeedNodePublicationIdentityForTest(t.(*testing.T), fixture.pool, fixture.scopeID, fixture.userID,
		nodeID, &agentv1.AgentCapabilities{
			AgentVersion: "1.0.35", BuildId: "publish-fixture", OperatingSystem: "linux", Architecture: "amd64",
			Features: v2DefaultNodeFeatures(),
		}, publishTestClock.Add(-10*time.Minute), true).ArtifactPrivateKey
	fixture.nodeKeys[nodeID] = key
	return key
}

func publishTestDigest() []byte {
	digest := sha256.Sum256([]byte(uuid.NewString()))
	return digest[:]
}

func assertPublishState(t *testing.T, pool *pgxpool.Pool, configs, rollouts, deployments, outbox, publications int) {
	t.Helper()
	var actualConfigs, actualRollouts, actualDeployments, actualOutbox, actualPublications int
	if err := pool.QueryRow(context.Background(), `SELECT
		(SELECT count(*) FROM config_versions),
		(SELECT count(*) FROM rollouts),
		(SELECT count(*) FROM node_deployments),
		(SELECT count(*) FROM edge_command_outbox),
		(SELECT count(*) FROM edge_config_publications)`).Scan(
		&actualConfigs, &actualRollouts, &actualDeployments, &actualOutbox, &actualPublications); err != nil {
		t.Fatal(err)
	}
	if actualConfigs != configs || actualRollouts != rollouts || actualDeployments != deployments || actualOutbox != outbox || actualPublications != publications {
		t.Fatalf("state configs=%d rollouts=%d deployments=%d outbox=%d publications=%d", actualConfigs, actualRollouts, actualDeployments, actualOutbox, actualPublications)
	}
}

func assertMigrationState(t *testing.T, pool *pgxpool.Pool, version int64, publicationTable bool) {
	t.Helper()
	var actualVersion int64
	var tableExists bool
	if err := pool.QueryRow(context.Background(), `SELECT COALESCE(max(version),0) FROM schema_migrations`).Scan(&actualVersion); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT to_regclass('edge_config_publications') IS NOT NULL`).Scan(&tableExists); err != nil {
		t.Fatal(err)
	}
	if actualVersion != version || tableExists != publicationTable {
		t.Fatalf("migration version=%d publication_table=%t", actualVersion, tableExists)
	}
}

func assertPublicationMigrationApplied(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var migrationApplied, tableExists bool
	if err := pool.QueryRow(context.Background(), `SELECT EXISTS (
		SELECT 1 FROM schema_migrations WHERE version = 21)`).Scan(&migrationApplied); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT to_regclass('edge_config_publications') IS NOT NULL`).Scan(&tableExists); err != nil {
		t.Fatal(err)
	}
	if !migrationApplied || !tableExists {
		t.Fatalf("publication migration applied=%t publication_table=%t", migrationApplied, tableExists)
	}
}

func migratePublishDownToVersion(t *testing.T, pool *pgxpool.Pool, target int64) {
	t.Helper()
	var current int64
	if err := pool.QueryRow(context.Background(), `SELECT COALESCE(max(version),0) FROM schema_migrations`).Scan(&current); err != nil {
		t.Fatal(err)
	}
	if current < target {
		t.Fatalf("cannot migrate down from version %d to %d", current, target)
	}
	for current > target {
		if err := migratePublishVersionIsolated(context.Background(), pool, "down", current); err != nil {
			t.Fatalf("migrate down from version %d: %v", current, err)
		}
		var next int64
		if err := pool.QueryRow(context.Background(), `SELECT COALESCE(max(version),0) FROM schema_migrations`).Scan(&next); err != nil {
			t.Fatal(err)
		}
		if next >= current {
			t.Fatalf("migration down did not advance: before=%d after=%d", current, next)
		}
		current = next
	}
	if current != target {
		t.Fatalf("migration version = %d, want %d", current, target)
	}
}

func migratePublishVersionIsolated(ctx context.Context, pool *pgxpool.Pool, direction string, target int64) error {
	files := make(fstest.MapFS, int(target)*2)
	for version := int64(1); version <= target; version++ {
		for _, migrationDirection := range []string{"up", "down"} {
			pattern := fmt.Sprintf("%03d_*.%s.sql", version, migrationDirection)
			matches, err := fs.Glob(controlmigrations.FS, pattern)
			if err != nil || len(matches) != 1 {
				return fmt.Errorf("resolve migration %03d %s: matches=%v err=%v", version, migrationDirection, matches, err)
			}
			content, err := fs.ReadFile(controlmigrations.FS, matches[0])
			if err != nil {
				return fmt.Errorf("read migration %q: %w", matches[0], err)
			}
			files[matches[0]] = &fstest.MapFile{Data: content}
		}
	}
	return migratePublishVersionIsolatedFS(ctx, pool, direction, files)
}

func assertPublishMigration046DownFails(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	script, err := fs.ReadFile(controlmigrations.FS, "046_edge_publication_contract.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if err := pgx.BeginFunc(context.Background(), pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), string(script))
		return err
	}); err == nil {
		t.Fatal("migration 046 rolled back over publication facts")
	}
	var publicationFacts int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM edge_config_publications WHERE contract_version=1`).Scan(&publicationFacts); err != nil {
		t.Fatal(err)
	}
	if publicationFacts == 0 {
		t.Fatal("migration 046 down failure did not preserve publication facts")
	}
}

func readSourceRevision(t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID) int64 {
	t.Helper()
	var revision int64
	if err := pool.QueryRow(context.Background(), `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1`, scopeID).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	return revision
}

func requireRevisionAdvance(t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID, previous int64, operation string) int64 {
	t.Helper()
	current := readSourceRevision(t, pool, scopeID)
	if current <= previous {
		t.Fatalf("%s revision=%d, want > %d", operation, current, previous)
	}
	return current
}

func sameRuntimeOrigins(published []siteRuntimeV2Origin, expected []fixtureOrigin) bool {
	if len(published) != len(expected) {
		return false
	}
	for index := range published {
		if published[index].Host != expected[index].Host || published[index].Port != int64(expected[index].Port) ||
			published[index].Weight != int64(expected[index].Weight) {
			return false
		}
	}
	return true
}

// openPublishTestDatabase returns an empty schema, or with migrate a schema at
// the release head (a clone of TEST_DATABASE_TEMPLATE when it is set).
func openPublishTestDatabase(t *testing.T, migrate bool) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	if migrate {
		if pool := databasetest.ClonedMigratedPool(t, nil); pool != nil {
			return pool
		}
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.Ping(ctx); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	schema := "edge_publish_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^edge_publish_test_[a-f0-9]{32}$`).MatchString(schema) {
		t.Fatalf("unsafe schema name %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop edge publish schema: %v", err)
		}
		admin.Close()
	})
	if migrate {
		if err := database.Migrate(ctx, pool, "up"); err != nil {
			t.Fatal(err)
		}
	}
	return pool
}
