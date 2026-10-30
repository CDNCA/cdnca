//go:build integration

package certificatepublish

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgestatus"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestPublicationLifecyclePartialRecoveryRBACAndUnpublish(t *testing.T) {
	pool := openPublicationIntegrationDatabase(t)
	certificates, err := certificateasset.NewStoreWithDependencies(
		pool, integrationCertificateEnveloper{}, audit.New(pool), func() time.Time { return publicationIntegrationNow },
	)
	if err != nil {
		t.Fatal(err)
	}
	tenant := seedPublicationTenant(t, pool)
	certificatePEM, privateKeyPEM := issuePublicationCertificate(t, tenant.domain)
	imported, err := certificates.Import(t.Context(), tenant.certificateActor, certificateasset.ImportRequest{
		TenantScopeID: tenant.scopeID, Name: "publication lifecycle certificate", Source: certificateasset.SourceUploaded,
		CertificatePEM: certificatePEM, PrivateKeyPEM: privateKeyPEM,
		IdempotencyKey: "certificate-publication-lifecycle-import", RequestID: uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := certificates.Activate(t.Context(), tenant.certificateActor, certificateasset.ActivateRequest{
		TenantScopeID: tenant.scopeID, AssetID: imported.Asset.ID, VersionID: imported.Version.ID,
		ExpectedRevision: imported.Asset.Revision, IdempotencyKey: "certificate-publication-lifecycle-activate",
		RequestID: uuid.NewString(),
	}); err != nil {
		t.Fatal(err)
	}
	bound, err := certificates.Bind(t.Context(), tenant.certificateActor, certificateasset.BindRequest{
		TenantScopeID: tenant.scopeID, SiteID: tenant.siteID, AssetID: imported.Asset.ID,
		VersionID: imported.Version.ID, ExpectedRevision: 0,
		IdempotencyKey: "certificate-publication-lifecycle-bind", RequestID: uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}

	actor, deploymentStore := seedPublicationDeploymentActor(t, pool)
	statusStore, err := edgestatus.NewStoreWithClock(pool, func() time.Time { return publicationIntegrationNow })
	if err != nil {
		t.Fatal(err)
	}
	nodes := []publicationNode{
		seedPublicationNode(t, pool, tenant.scopeID, tenant.userID),
		seedPublicationNode(t, pool, tenant.scopeID, tenant.userID),
	}
	signer := &integrationPublicationSigner{}
	_, signer.private, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	producer, err := NewProducer(signer)
	if err != nil {
		t.Fatal(err)
	}
	publisherStore, err := edgedeployment.NewCertificatePublisherStore(deploymentStore, NewActorRevalidator())
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewPublicationService(pool, certificates, publisherStore, producer, DefaultPublicationConfig())
	if err != nil {
		t.Fatal(err)
	}
	base := publicationIntegrationRequest(t, pool, actor, tenant, nodes, bound, "certificate-publication-lifecycle-initial")
	created, err := service.Publish(t.Context(), base)
	if err != nil {
		t.Fatal(err)
	}
	// One audit event per new publication rollout; a replay writes none.
	if replay, err := service.Publish(t.Context(), base); err != nil || !replay.Replayed {
		t.Fatalf("publish replay=%+v error=%v", replay, err)
	}
	assertPublicationLifecycleAuditCount(t, pool, tenant.scopeID, auditPublicationPublish, 1)
	var publishPayload struct {
		SiteIDs         []string `json:"site_ids"`
		NodeIDs         []string `json:"node_ids"`
		BindingRevision int64    `json:"binding_revision"`
		RolloutID       string   `json:"result_rollout_id"`
	}
	var publishActor uuid.UUID
	var publishPayloadRaw []byte
	if err := pool.QueryRow(t.Context(), `SELECT actor_user_id,payload FROM audit_events WHERE scope_id=$1 AND action=$2`,
		tenant.scopeID, auditPublicationPublish).Scan(&publishActor, &publishPayloadRaw); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(publishPayloadRaw, &publishPayload); err != nil || publishActor != actor.UserID ||
		len(publishPayload.SiteIDs) != 1 || len(publishPayload.NodeIDs) != 2 ||
		publishPayload.BindingRevision != bound.Revision || publishPayload.RolloutID != created.Rollout.ID.String() {
		t.Fatalf("publish audit actor=%s payload=%+v error=%v", publishActor, publishPayload, err)
	}
	projectPublicationSuccess(t, statusStore, created.Rollout.Deployments[0])
	projectPublicationFailure(t, statusStore, created.Rollout.Deployments[1])

	recoverRequest := RecoverPartialRequest{
		PublicationRequest: base,
		SourceRolloutID:    created.Rollout.ID, ExpectedSourceRevision: created.Rollout.Revision,
	}
	recoverRequest.NodeIDs = []uuid.UUID{created.Rollout.Deployments[1].NodeID}
	recoverRequest.IdempotencyKey = "certificate-publication-lifecycle-recover"
	recoverRequest.RequestID = uuid.NewString()
	recoverRequest.CorrelationID = uuid.NewString()

	invalidNodes := recoverRequest
	invalidNodes.NodeIDs = []uuid.UUID{created.Rollout.Deployments[0].NodeID}
	invalidNodes.IdempotencyKey = "certificate-publication-lifecycle-wrong-nodes"
	invalidNodes.RequestID = uuid.NewString()
	invalidNodes.CorrelationID = uuid.NewString()
	before := publicationLifecycleCounts(t, pool, tenant.scopeID)
	if _, err := service.RecoverPartial(t.Context(), invalidNodes); !errors.Is(err, edgedeployment.ErrInvalidInput) {
		t.Fatalf("wrong recovery nodes error=%v", err)
	}
	assertPublicationLifecycleCounts(t, pool, tenant.scopeID, before)

	roleID := revokePublicationDeploymentRole(t, pool, actor)
	// The publisher store revalidates the actor itself (ActorRevalidator):
	// without certificates.manage it is no longer an authorized publisher.
	if _, err := service.RecoverPartial(t.Context(), recoverRequest); !errors.Is(err, edgedeployment.ErrUnauthenticated) {
		t.Fatalf("revoked recovery error=%v", err)
	}
	assertPublicationLifecycleCounts(t, pool, tenant.scopeID, before)
	restorePublicationDeploymentRole(t, pool, actor, roleID)

	recovered, err := service.RecoverPartial(t.Context(), recoverRequest)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Replayed || recovered.SourceRolloutID != created.Rollout.ID ||
		recovered.SourceRevision != created.Rollout.Revision+1 || len(recovered.Rollout.Deployments) != 1 ||
		recovered.Rollout.Deployments[0].NodeID != created.Rollout.Deployments[1].NodeID {
		t.Fatalf("recovery=%+v", recovered)
	}
	assertPublicationLifecycleAudit(t, pool, tenant.scopeID, actor, recovered,
		"certificate.publication.recover", "partial_failure_recovery", []uuid.UUID{tenant.siteID})
	replayedRecovery, err := service.RecoverPartial(t.Context(), recoverRequest)
	if err != nil || !replayedRecovery.Replayed || replayedRecovery.Rollout.ID != recovered.Rollout.ID {
		t.Fatalf("recovery replay=%+v error=%v", replayedRecovery, err)
	}
	assertPublicationLifecycleAuditCount(t, pool, tenant.scopeID, "certificate.publication.recover", 1)

	staleRecovery := recoverRequest
	staleRecovery.IdempotencyKey = "certificate-publication-lifecycle-stale-recover"
	staleRecovery.RequestID = uuid.NewString()
	staleRecovery.CorrelationID = uuid.NewString()
	beforeStale := publicationLifecycleCounts(t, pool, tenant.scopeID)
	if _, err := service.RecoverPartial(t.Context(), staleRecovery); !errors.Is(err, edgedeployment.ErrRevisionConflict) {
		t.Fatalf("stale recovery error=%v", err)
	}
	assertPublicationLifecycleCounts(t, pool, tenant.scopeID, beforeStale)
	projectPublicationSuccess(t, statusStore, recovered.Rollout.Deployments[0])

	unbound, err := certificates.Unbind(t.Context(), tenant.certificateActor, certificateasset.UnbindRequest{
		TenantScopeID: tenant.scopeID, SiteID: tenant.siteID, ExpectedRevision: bound.Revision,
		IdempotencyKey: "certificate-publication-lifecycle-unbind", RequestID: uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	replayedRecoveryAfterUnbind, err := service.RecoverPartial(t.Context(), recoverRequest)
	if err != nil || !replayedRecoveryAfterUnbind.Replayed || replayedRecoveryAfterUnbind.Rollout.ID != recovered.Rollout.ID {
		t.Fatalf("recovery replay after unbind=%+v error=%v", replayedRecoveryAfterUnbind, err)
	}
	replayedPublishAfterUnbind, err := service.Publish(t.Context(), base)
	if err != nil || !replayedPublishAfterUnbind.Replayed || replayedPublishAfterUnbind.Rollout.ID != created.Rollout.ID {
		t.Fatalf("publish replay after unbind=%+v error=%v", replayedPublishAfterUnbind, err)
	}
	unpublishBase := base
	unpublishBase.SiteIDs = nil
	unpublishBase.IdempotencyKey = "certificate-publication-lifecycle-unpublish"
	unpublishBase.RequestID = uuid.NewString()
	unpublishBase.CorrelationID = uuid.NewString()
	unpublishRequest := UnpublishRequest{
		PublicationRequest: unpublishBase, SourceRolloutID: created.Rollout.ID,
		ExpectedSourceRevision: recovered.SourceRevision, RemovedSiteIDs: []uuid.UUID{tenant.siteID},
	}
	blockedNodeID := nodes[0].id
	if bytes.Compare(nodes[1].id[:], blockedNodeID[:]) < 0 {
		blockedNodeID = nodes[1].id
	}
	blocker, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Rollback(context.Background()) }()
	var lockedNode uuid.UUID
	if err := blocker.QueryRow(t.Context(), `SELECT id FROM nodes WHERE id=$1 FOR UPDATE`, blockedNodeID).Scan(&lockedNode); err != nil {
		t.Fatal(err)
	}
	type unpublishOutcome struct {
		result LifecycleResult
		err    error
	}
	unpublishDone := make(chan unpublishOutcome, 1)
	go func() {
		result, publishErr := service.Unpublish(context.Background(), unpublishRequest)
		unpublishDone <- unpublishOutcome{result: result, err: publishErr}
	}()
	waitForPublicationLockWaiters(t, pool, 1)
	type bindOutcome struct {
		binding certificateasset.Binding
		err     error
	}
	bindDone := make(chan bindOutcome, 1)
	go func() {
		binding, bindErr := certificates.Bind(context.Background(), tenant.certificateActor, certificateasset.BindRequest{
			TenantScopeID: tenant.scopeID, SiteID: tenant.siteID, AssetID: imported.Asset.ID,
			VersionID: imported.Version.ID, ExpectedRevision: unbound.Revision,
			IdempotencyKey: "certificate-publication-lifecycle-racing-rebind", RequestID: uuid.NewString(),
		})
		bindDone <- bindOutcome{binding: binding, err: bindErr}
	}()
	waitForPublicationLockWaiters(t, pool, 2)
	if err := blocker.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	unpublishedOutcome := <-unpublishDone
	if unpublishedOutcome.err != nil {
		t.Fatal(unpublishedOutcome.err)
	}
	unpublished := unpublishedOutcome.result
	reboundOutcome := <-bindDone
	if reboundOutcome.err != nil {
		t.Fatal(reboundOutcome.err)
	}
	rebound := reboundOutcome.binding
	replayedPublishAfterRebind, err := service.Publish(t.Context(), base)
	if err != nil || !replayedPublishAfterRebind.Replayed || replayedPublishAfterRebind.Rollout.ID != created.Rollout.ID {
		t.Fatalf("publish replay after rebind=%+v error=%v", replayedPublishAfterRebind, err)
	}
	if unpublished.Replayed || unpublished.SourceRevision != recovered.SourceRevision+1 ||
		len(unpublished.Rollout.Deployments) != len(nodes) {
		t.Fatalf("unpublish=%+v", unpublished)
	}
	assertRemovalArtifacts(t, pool, unpublished.Rollout, nodes)
	assertPublicationLifecycleAudit(t, pool, tenant.scopeID, actor, unpublished,
		"certificate.publication.unpublish", "binding_removed", []uuid.UUID{tenant.siteID})

	changedPublish := base
	changedPublish.SiteIDs = []uuid.UUID{uuid.New()}
	if _, err := service.Publish(t.Context(), changedPublish); !errors.Is(err, edgedeployment.ErrIdempotencyConflict) {
		t.Fatalf("changed publish site replay error=%v", err)
	}
	for name, mutate := range map[string]func(*RecoverPartialRequest){
		"source":   func(value *RecoverPartialRequest) { value.SourceRolloutID = uuid.New() },
		"revision": func(value *RecoverPartialRequest) { value.ExpectedSourceRevision++ },
		"site":     func(value *RecoverPartialRequest) { value.SiteIDs = []uuid.UUID{uuid.New()} },
	} {
		changed := recoverRequest
		mutate(&changed)
		if _, err := service.RecoverPartial(t.Context(), changed); !errors.Is(err, edgedeployment.ErrIdempotencyConflict) {
			t.Fatalf("changed recovery %s replay error=%v", name, err)
		}
	}
	for name, mutate := range map[string]func(*UnpublishRequest){
		"source":   func(value *UnpublishRequest) { value.SourceRolloutID = uuid.New() },
		"revision": func(value *UnpublishRequest) { value.ExpectedSourceRevision++ },
		"removed":  func(value *UnpublishRequest) { value.RemovedSiteIDs = []uuid.UUID{uuid.New()} },
	} {
		changed := unpublishRequest
		mutate(&changed)
		if _, err := service.Unpublish(t.Context(), changed); !errors.Is(err, edgedeployment.ErrIdempotencyConflict) {
			t.Fatalf("changed unpublish %s replay error=%v", name, err)
		}
	}

	replayedUnpublish, err := service.Unpublish(t.Context(), unpublishRequest)
	if err != nil || !replayedUnpublish.Replayed || replayedUnpublish.Rollout.ID != unpublished.Rollout.ID {
		t.Fatalf("unpublish replay after rebind=%+v error=%v", replayedUnpublish, err)
	}
	if _, err := certificates.Unbind(t.Context(), tenant.certificateActor, certificateasset.UnbindRequest{
		TenantScopeID: tenant.scopeID, SiteID: tenant.siteID, ExpectedRevision: rebound.Revision,
		IdempotencyKey: "certificate-publication-lifecycle-final-unbind", RequestID: uuid.NewString(),
	}); err != nil {
		t.Fatal(err)
	}
	seedPublicationCertificateRevocation(t, pool, tenant, imported.Asset.ID, imported.Version.ID, "replay independence")
	assertMutableStateReplays := func(state string, replayService *PublicationService) {
		t.Helper()
		for name, replay := range map[string]func() (uuid.UUID, bool, error){
			"publish": func() (uuid.UUID, bool, error) {
				value, replayErr := replayService.Publish(t.Context(), base)
				return value.Rollout.ID, value.Replayed, replayErr
			},
			"recover": func() (uuid.UUID, bool, error) {
				value, replayErr := replayService.RecoverPartial(t.Context(), recoverRequest)
				return value.Rollout.ID, value.Replayed, replayErr
			},
			"unpublish": func() (uuid.UUID, bool, error) {
				value, replayErr := replayService.Unpublish(t.Context(), unpublishRequest)
				return value.Rollout.ID, value.Replayed, replayErr
			},
		} {
			rolloutID, replayed, replayErr := replay()
			if replayErr != nil || !replayed || rolloutID == uuid.Nil {
				t.Fatalf("%s replay after %s id=%s replayed=%t error=%v", name, state, rolloutID, replayed, replayErr)
			}
		}
	}
	assertMutableStateReplays("revoke", service)
	expiredCertificates, err := certificateasset.NewStoreWithDependencies(
		pool, integrationCertificateEnveloper{}, audit.New(pool), func() time.Time {
			return publicationIntegrationNow.Add(48 * time.Hour)
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	expiredService, err := NewPublicationService(
		pool, expiredCertificates, publisherStore, producer, DefaultPublicationConfig(),
	)
	if err != nil {
		t.Fatal(err)
	}
	assertMutableStateReplays("expiry", expiredService)
	assertPublicationLifecycleAuditCount(t, pool, tenant.scopeID, "certificate.publication.unpublish", 1)
}

type publicationLifecycleCount struct {
	configs, rollouts, deployments, outbox, audits int
}

func publicationLifecycleCounts(t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID) publicationLifecycleCount {
	t.Helper()
	var result publicationLifecycleCount
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM config_versions WHERE configuration_scope_id=$1),
		(SELECT count(*) FROM rollouts WHERE configuration_scope_id=$1),
		(SELECT count(*) FROM node_deployments deployment JOIN rollouts rollout ON rollout.id=deployment.rollout_id WHERE rollout.configuration_scope_id=$1),
		(SELECT count(*) FROM edge_command_outbox outbox JOIN node_deployments deployment ON deployment.id=outbox.deployment_id WHERE deployment.rollout_id IN (SELECT id FROM rollouts WHERE configuration_scope_id=$1)),
		(SELECT count(*) FROM audit_events WHERE scope_id=$1 AND action LIKE 'certificate.publication.%')`, scopeID).Scan(
		&result.configs, &result.rollouts, &result.deployments, &result.outbox, &result.audits,
	); err != nil {
		t.Fatal(err)
	}
	return result
}

func assertPublicationLifecycleCounts(t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID, want publicationLifecycleCount) {
	t.Helper()
	if got := publicationLifecycleCounts(t, pool, scopeID); got != want {
		t.Fatalf("publication lifecycle counts=%+v want=%+v", got, want)
	}
}

func waitForPublicationLockWaiters(t *testing.T, pool *pgxpool.Pool, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var count int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM pg_stat_activity
			WHERE datname=current_database() AND pid<>pg_backend_pid() AND wait_event_type='Lock'`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d PostgreSQL lock waiters", want)
}

func revokePublicationDeploymentRole(t *testing.T, pool *pgxpool.Pool, actor edgedeployment.Actor) uuid.UUID {
	t.Helper()
	var roleID uuid.UUID
	if err := pool.QueryRow(t.Context(), `DELETE FROM role_assignments
		WHERE scope_id=$1 AND user_id=$2 RETURNING role_id`, actor.ScopeID, actor.UserID).Scan(&roleID); err != nil {
		t.Fatal(err)
	}
	return roleID
}

func restorePublicationDeploymentRole(t *testing.T, pool *pgxpool.Pool, actor edgedeployment.Actor, roleID uuid.UUID) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`,
		actor.ScopeID, actor.UserID, roleID); err != nil {
		t.Fatal(err)
	}
}

func assertPublicationLifecycleAudit(
	t *testing.T,
	pool *pgxpool.Pool,
	targetScopeID uuid.UUID,
	actor edgedeployment.Actor,
	result LifecycleResult,
	action, reason string,
	siteIDs []uuid.UUID,
) {
	t.Helper()
	var actorUserID uuid.UUID
	var payload []byte
	if err := pool.QueryRow(t.Context(), `SELECT actor_user_id,payload FROM audit_events
		WHERE scope_id=$1 AND action=$2 AND resource_id=$3`, targetScopeID, action, result.Rollout.ID.String()).Scan(
		&actorUserID, &payload,
	); err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		ActorScopeID          string   `json:"actor_scope_id"`
		TargetScopeID         string   `json:"target_scope_id"`
		Operation             string   `json:"operation"`
		Reason                string   `json:"reason"`
		SourceRolloutID       string   `json:"source_rollout_id"`
		SourceRevision        int64    `json:"source_revision"`
		ResultRolloutID       string   `json:"result_rollout_id"`
		ResultRolloutRevision int64    `json:"result_rollout_revision"`
		NodeIDs               []string `json:"node_ids"`
		SiteIDs               []string `json:"site_ids"`
	}
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if actorUserID != actor.UserID || decoded.ActorScopeID != actor.ScopeID.String() ||
		decoded.TargetScopeID != targetScopeID.String() || decoded.Operation != action || decoded.Reason != reason ||
		decoded.SourceRolloutID != result.SourceRolloutID.String() || decoded.SourceRevision != result.SourceRevision ||
		decoded.ResultRolloutID != result.Rollout.ID.String() || decoded.ResultRolloutRevision != result.Rollout.Revision ||
		len(decoded.NodeIDs) != len(result.Rollout.Deployments) || len(decoded.SiteIDs) != len(siteIDs) {
		t.Fatalf("lifecycle audit=%+v actor=%s", decoded, actorUserID)
	}
}

func assertPublicationLifecycleAuditCount(t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID, action string, want int) {
	t.Helper()
	var got int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE scope_id=$1 AND action=$2`, scopeID, action).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("%s audit count=%d want=%d", action, got, want)
	}
}

func assertRemovalArtifacts(t *testing.T, pool *pgxpool.Pool, rollout edgedeployment.Rollout, nodes []publicationNode) {
	t.Helper()
	nodesByID := make(map[uuid.UUID]publicationNode, len(nodes))
	for _, node := range nodes {
		nodesByID[node.id] = node
	}
	for _, deployment := range rollout.Deployments {
		descriptor := deployment.Command.Artifacts[0]
		var wire []byte
		if err := pool.QueryRow(t.Context(), `SELECT wire_bytes FROM configuration_artifacts
			WHERE config_version_id=$1 AND id=$2`, rollout.ConfigVersionID, uuid.MustParse(descriptor.ArtifactId)).Scan(&wire); err != nil {
			t.Fatal(err)
		}
		metadata := artifactMetadata{
			EventID: deployment.Command.Event.EventId, DeploymentID: deployment.Command.DeploymentId,
			Attempt: deployment.Command.Attempt, ConfigVersionID: deployment.Command.ConfigVersionId,
			ArtifactID: descriptor.ArtifactId, RecipientKeyID: descriptor.GetRecipientKeyId(),
			Kind: descriptor.Kind, SizeBytes: descriptor.SizeBytes, SigningKeyID: descriptor.SigningKeyId,
			SignatureAlgorithm: descriptor.SignatureAlgorithm, Compression: descriptor.Compression,
			MediaType: descriptor.MediaType, EncryptionAlgorithm: descriptor.EncryptionAlgorithm,
		}
		info, aad := frozenConsumerContext(t, metadata)
		plaintext := decryptFrozenArtifact(t, nodesByID[deployment.NodeID].privateKey, wire, info, aad)
		if !bytes.Contains(plaintext, []byte(`"certificates":[]`)) ||
			!bytes.Contains(plaintext, []byte(`"bindings":[]`)) {
			clearBytes(plaintext)
			t.Fatalf("non-empty removal artifact: %s", plaintext)
		}
		clearBytes(plaintext)
	}
}

func projectPublicationSuccess(t *testing.T, store *edgestatus.Store, deployment edgedeployment.Deployment) {
	t.Helper()
	states := []agentv1.NodeDeploymentState{
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY,
	}
	for index, state := range states {
		causationID := deployment.Command.Event.EventId
		status := &agentv1.DeploymentStatus{
			Event: &commonv1.EventMetadata{
				EventId: uuid.NewString(), RequestId: deployment.Command.Event.RequestId,
				OccurredTime: timestamppb.New(publicationIntegrationNow), CausationId: &causationID,
				CorrelationId: deployment.Command.Event.CorrelationId,
			},
			DeploymentId: deployment.ID.String(), Attempt: 1,
			ConfigVersionId: deployment.Command.ConfigVersionId,
			State:           state, TransitionSequence: uint64(index + 1),
		}
		payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(status)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(payload)
		result, err := store.Project(t.Context(), edgestatus.Envelope{
			NodeID: deployment.NodeID, DeploymentID: deployment.ID,
			ConfigID: uuid.MustParse(status.ConfigVersionId), EventID: uuid.MustParse(status.Event.EventId),
			RequestID: uuid.MustParse(status.Event.RequestId), Status: status, Payload: payload, Digest: digest,
		})
		if err != nil || result.Outcome != edgestatus.OutcomeAdvanced {
			t.Fatalf("project publication success state=%s result=%+v error=%v", state, result, err)
		}
	}
}
