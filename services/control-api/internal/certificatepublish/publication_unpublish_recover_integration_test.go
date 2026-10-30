//go:build integration

package certificatepublish

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgestatus"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Recovering a partially failed unpublication sends the failed nodes the
// removal again (removed_sites), never the sites that remain: they were not
// part of the command. Two sites share a certificate; one is unbound and
// unpublished, one node fails the removal.
func TestRecoverPartialOfUnpublishSendsTheRemovalAgain(t *testing.T) {
	pool := openPublicationIntegrationDatabase(t)
	certificates, err := certificateasset.NewStoreWithDependencies(
		pool, integrationCertificateEnveloper{}, audit.New(pool), func() time.Time { return publicationIntegrationNow },
	)
	if err != nil {
		t.Fatal(err)
	}
	tenant := seedPublicationTenant(t, pool)
	secondSite := seedPublicationSite(t, pool, tenant, "second.publication.example.test")
	certificatePEM, privateKeyPEM := issuePublicationCertificate(t, tenant.domain, "second.publication.example.test")
	imported, err := certificates.Import(t.Context(), tenant.certificateActor, certificateasset.ImportRequest{
		TenantScopeID: tenant.scopeID, Name: "unpublish recovery certificate", Source: certificateasset.SourceUploaded,
		CertificatePEM: certificatePEM, PrivateKeyPEM: privateKeyPEM,
		IdempotencyKey: "unpublish-recover-import", RequestID: uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := certificates.Activate(t.Context(), tenant.certificateActor, certificateasset.ActivateRequest{
		TenantScopeID: tenant.scopeID, AssetID: imported.Asset.ID, VersionID: imported.Version.ID,
		ExpectedRevision: imported.Asset.Revision, IdempotencyKey: "unpublish-recover-activate", RequestID: uuid.NewString(),
	}); err != nil {
		t.Fatal(err)
	}
	bindings := map[uuid.UUID]certificateasset.Binding{}
	for _, siteID := range []uuid.UUID{tenant.siteID, secondSite} {
		bound, err := certificates.Bind(t.Context(), tenant.certificateActor, certificateasset.BindRequest{
			TenantScopeID: tenant.scopeID, SiteID: siteID, AssetID: imported.Asset.ID, VersionID: imported.Version.ID,
			IdempotencyKey: "unpublish-recover-bind-" + siteID.String(), RequestID: uuid.NewString(),
		})
		if err != nil {
			t.Fatal(err)
		}
		bindings[siteID] = bound
	}
	if bindings[tenant.siteID].Revision != bindings[secondSite].Revision {
		t.Fatalf("binding revisions differ: %d %d", bindings[tenant.siteID].Revision, bindings[secondSite].Revision)
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
	service := newRecoverPublicationService(t, pool, certificates, deploymentStore)
	base := publicationIntegrationRequest(t, pool, actor, tenant, nodes, bindings[tenant.siteID], "unpublish-recover-publish")
	base.SiteIDs = []uuid.UUID{tenant.siteID, secondSite}
	published, err := service.Publish(t.Context(), base)
	if err != nil {
		t.Fatal(err)
	}
	for _, deployment := range published.Rollout.Deployments {
		projectPublicationSuccess(t, statusStore, deployment)
	}
	// The worker settles a bind intent with this rollout: the outcome is the
	// system's audit event, the requester in its payload.
	intents, err := certificateasset.NewPublicationIntentStore(pool, certificateasset.DefaultPublicationIntentStoreConfig())
	if err != nil {
		t.Fatal(err)
	}
	lease, found, err := intents.ClaimPublicationIntent(t.Context(), "audit-worker")
	if err != nil || !found {
		t.Fatalf("claim publication intent found=%t error=%v", found, err)
	}
	if err := intents.CompletePublicationIntent(t.Context(), lease, certificateasset.PublicationResult{
		Outcome: certificateasset.PublicationAck, PublicationID: uuid.New(), PublicationRevision: published.Rollout.Revision,
		ConfigVersionID: published.Rollout.ConfigVersionID, RolloutID: published.Rollout.ID, RolloutRevision: published.Rollout.Revision,
	}); err != nil {
		t.Fatal(err)
	}
	var outcomeActor *uuid.UUID
	var outcomeResult string
	var outcomePayload []byte
	if err := pool.QueryRow(t.Context(), `SELECT actor_user_id,result,payload FROM audit_events
		WHERE scope_id=$1 AND action=$2 AND resource_id=$3`, tenant.scopeID, certificateasset.AuditPublicationComplete,
		lease.SiteID.String()).Scan(&outcomeActor, &outcomeResult, &outcomePayload); err != nil {
		t.Fatal(err)
	}
	var outcome map[string]any
	if err := json.Unmarshal(outcomePayload, &outcome); err != nil || outcomeActor != nil || outcomeResult != "success" ||
		outcome["rollout_id"] != published.Rollout.ID.String() || outcome["requested_by_user_id"] != tenant.userID.String() {
		t.Fatalf("publication outcome audit actor=%v result=%s payload=%v error=%v", outcomeActor, outcomeResult, outcome, err)
	}

	unbound, err := certificates.Unbind(t.Context(), tenant.certificateActor, certificateasset.UnbindRequest{
		TenantScopeID: tenant.scopeID, SiteID: secondSite, ExpectedRevision: bindings[secondSite].Revision,
		IdempotencyKey: "unpublish-recover-unbind", RequestID: uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	unpublishBase := base
	unpublishBase.SiteIDs = nil
	unpublishBase.IdempotencyKey = "unpublish-recover-unpublish"
	unpublishBase.RequestID, unpublishBase.CorrelationID = uuid.NewString(), uuid.NewString()
	unpublished, err := service.Unpublish(t.Context(), UnpublishRequest{
		PublicationRequest: unpublishBase, SourceRolloutID: published.Rollout.ID,
		ExpectedSourceRevision: published.Rollout.Revision, RemovedSiteIDs: []uuid.UUID{secondSite},
	})
	if err != nil {
		t.Fatal(err)
	}
	projectPublicationSuccess(t, statusStore, unpublished.Rollout.Deployments[0])
	projectPublicationFailure(t, statusStore, unpublished.Rollout.Deployments[1])
	failedNode := unpublished.Rollout.Deployments[1].NodeID

	recoverBase := unpublishBase
	recoverBase.SiteIDs = []uuid.UUID{secondSite}
	recoverBase.NodeIDs = []uuid.UUID{failedNode}
	recoverBase.IdempotencyKey = "unpublish-recover-recover"
	recoverBase.RequestID, recoverBase.CorrelationID = uuid.NewString(), uuid.NewString()
	recoverRequest := RecoverPartialRequest{
		PublicationRequest: recoverBase, SourceRolloutID: unpublished.Rollout.ID,
		ExpectedSourceRevision: unpublished.Rollout.Revision,
	}
	// The remaining site is not what the unpublication sent.
	wrongSites := recoverRequest
	wrongSites.SiteIDs = []uuid.UUID{tenant.siteID}
	wrongSites.IdempotencyKey = "unpublish-recover-wrong-sites"
	if _, err := service.RecoverPartial(t.Context(), wrongSites); !errors.Is(err, edgedeployment.ErrInvalidInput) {
		t.Fatalf("recovering an unpublication with the remaining site: %v", err)
	}
	recovered, err := service.RecoverPartial(t.Context(), recoverRequest)
	if err != nil {
		t.Fatal(err)
	}
	if len(recovered.Rollout.Deployments) != 1 || recovered.Rollout.Deployments[0].NodeID != failedNode {
		t.Fatalf("recovery = %+v, want only the failed node", recovered)
	}
	assertRemovalArtifacts(t, pool, recovered.Rollout, nodes)
	removed := decryptRemovedSites(t, pool, recovered.Rollout, nodes)
	if len(removed) != 1 || removed[0].SiteID != secondSite.String() || removed[0].BindingRevision != unbound.Revision ||
		removed[0].TenantID != tenant.tenantID.String() {
		t.Fatalf("recovery removed_sites = %+v, want site %s at revision %d", removed, secondSite, unbound.Revision)
	}
	assertPublicationLifecycleAudit(t, pool, tenant.scopeID, actor, recovered,
		certificatePublicationRecoverAction, partialFailureRecoveryReason, []uuid.UUID{secondSite})

	// A recovery is itself recoverable: its snapshot keeps the removal.
	projectPublicationFailure(t, statusStore, recovered.Rollout.Deployments[0])
	again := recoverRequest
	again.SourceRolloutID, again.ExpectedSourceRevision = recovered.Rollout.ID, recovered.Rollout.Revision
	again.IdempotencyKey = "unpublish-recover-again"
	// Its snapshot still parses (removal kept); with no healthy node it is
	// not a partial failure.
	if _, err := service.RecoverPartial(t.Context(), again); !errors.Is(err, edgedeployment.ErrInvalidInput) {
		t.Fatalf("recovery of a recovery with no healthy node: %v", err)
	}
}

func newRecoverPublicationService(
	t *testing.T,
	pool *pgxpool.Pool,
	certificates *certificateasset.Store,
	deploymentStore *edgedeployment.Store,
) *PublicationService {
	t.Helper()
	signer := &integrationPublicationSigner{}
	var err error
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
	return service
}

type removedSiteWire struct {
	TenantID        string `json:"tenant_id"`
	SiteID          string `json:"site_id"`
	BindingRevision int64  `json:"binding_revision"`
}

// decryptRemovedSites returns the activation removed_sites every deployment
// of rollout carries (they must agree).
func decryptRemovedSites(t *testing.T, pool *pgxpool.Pool, rollout edgedeployment.Rollout, nodes []publicationNode) []removedSiteWire {
	t.Helper()
	nodesByID := make(map[uuid.UUID]publicationNode, len(nodes))
	for _, node := range nodes {
		nodesByID[node.id] = node
	}
	var result []removedSiteWire
	for index, deployment := range rollout.Deployments {
		descriptor := deployment.Command.Artifacts[0]
		var wire []byte
		if err := pool.QueryRow(t.Context(), `SELECT wire_bytes FROM configuration_artifacts
			WHERE config_version_id=$1 AND id=$2`, rollout.ConfigVersionID, uuid.MustParse(descriptor.ArtifactId)).Scan(&wire); err != nil {
			t.Fatal(err)
		}
		info, aad := frozenConsumerContext(t, artifactMetadata{
			EventID: deployment.Command.Event.EventId, DeploymentID: deployment.Command.DeploymentId,
			Attempt: deployment.Command.Attempt, ConfigVersionID: deployment.Command.ConfigVersionId,
			ArtifactID: descriptor.ArtifactId, RecipientKeyID: descriptor.GetRecipientKeyId(),
			Kind: descriptor.Kind, SizeBytes: descriptor.SizeBytes, SigningKeyID: descriptor.SigningKeyId,
			SignatureAlgorithm: descriptor.SignatureAlgorithm, Compression: descriptor.Compression,
			MediaType: descriptor.MediaType, EncryptionAlgorithm: descriptor.EncryptionAlgorithm,
		})
		plaintext := decryptFrozenArtifact(t, nodesByID[deployment.NodeID].privateKey, wire, info, aad)
		var artifact struct {
			Activation struct {
				RemovedSites []removedSiteWire `json:"removed_sites"`
			} `json:"activation"`
		}
		err := json.NewDecoder(bytes.NewReader(plaintext)).Decode(&artifact)
		clearBytes(plaintext)
		if err != nil {
			t.Fatal(err)
		}
		if index == 0 {
			result = artifact.Activation.RemovedSites
		} else if len(result) != len(artifact.Activation.RemovedSites) {
			t.Fatalf("deployments disagree on removed_sites")
		}
	}
	return result
}

func seedPublicationSite(t *testing.T, pool *pgxpool.Pool, tenant publicationTenant, domain string) uuid.UUID {
	t.Helper()
	siteID := uuid.New()
	// One transaction: a site requires its origin pool at commit.
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO sites(id,display_id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id)
		 VALUES($1,(SELECT COALESCE(max(display_id),0)+1 FROM sites WHERE scope_id=$2),$2,$3,$4,ARRAY['origin.example.test:443'],ARRAY['origin.example.test'],$3,$3)`,
			[]any{siteID, tenant.scopeID, tenant.userID, domain}},
		{`INSERT INTO site_origin_pools(site_id) VALUES($1)`, []any{siteID}},
		{`INSERT INTO site_origins(site_id,position,host,port) VALUES($1,1,'origin.example.test',443)`, []any{siteID}},
	} {
		if _, err := tx.Exec(t.Context(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	return siteID
}
