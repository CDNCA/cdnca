//go:build integration

package certificatepublish

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/cdnca/cdnca/services/control-api/internal/edgestatus"
	"github.com/google/uuid"
)

// demo-fill 11-01 (73, site B): the first publication of a binding failed
// permanently, so no node holds the certificate. The unbind's intent then
// found no succeeded publication: ErrNotFound → publication_unavailable,
// retried 10 times to permanent_failed "edge deployment not found", and the
// rebind waited behind it. Now the unbind completes as a no-op (succeeded,
// no rollout, noop_reason never_published, success audit) and the rebind is
// claimed next. A publication some node activated before failing is a real
// source: its unbind removes it.
func TestUnpublishOfNeverPublishedCertificateCompletesWithoutRollout(t *testing.T) {
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
		TenantScopeID: tenant.scopeID, Name: "never published certificate", Source: certificateasset.SourceUploaded,
		CertificatePEM: certificatePEM, PrivateKeyPEM: privateKeyPEM,
		IdempotencyKey: "noop-import", RequestID: uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := certificates.Activate(t.Context(), tenant.certificateActor, certificateasset.ActivateRequest{
		TenantScopeID: tenant.scopeID, AssetID: imported.Asset.ID, VersionID: imported.Version.ID,
		ExpectedRevision: imported.Asset.Revision, IdempotencyKey: "noop-activate", RequestID: uuid.NewString(),
	}); err != nil {
		t.Fatal(err)
	}
	deploymentActor, deploymentStore := seedPublicationDeploymentActor(t, pool)
	service := newRecoverPublicationService(t, pool, certificates, deploymentStore)
	intents, err := certificateasset.NewPublicationIntentStore(pool, certificateasset.DefaultPublicationIntentStoreConfig())
	if err != nil {
		t.Fatal(err)
	}
	claim := func(want int64, operation string) certificateasset.PublicationIntentLease {
		t.Helper()
		lease, found, err := intents.ClaimPublicationIntent(t.Context(), "noop-worker")
		if err != nil || !found || lease.BindingRevision != want || lease.Operation != operation {
			t.Fatalf("claim = %+v found=%t err=%v, want %s revision %d", lease, found, err, operation, want)
		}
		return lease
	}
	resolve := func(revision int64) (certificateUnpublishSource, error) {
		return service.ResolveCertificateUnpublishSource(t.Context(), certificateasset.CertificatePublicationCommandV1{
			TenantScopeID: tenant.scopeID, SiteID: tenant.siteID, BindingRevision: revision,
		})
	}

	bound, err := certificates.Bind(t.Context(), tenant.certificateActor, certificateasset.BindRequest{
		TenantScopeID: tenant.scopeID, SiteID: tenant.siteID, AssetID: imported.Asset.ID, VersionID: imported.Version.ID,
		IdempotencyKey: "noop-bind", RequestID: uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	publishLease := claim(bound.Revision, "publish")
	if err := intents.PermanentlyFailPublicationIntent(t.Context(), publishLease, "publication_terminal_failed"); err != nil {
		t.Fatal(err)
	}
	unbound, err := certificates.Unbind(t.Context(), tenant.certificateActor, certificateasset.UnbindRequest{
		TenantScopeID: tenant.scopeID, SiteID: tenant.siteID, ExpectedRevision: bound.Revision,
		IdempotencyKey: "noop-unbind", RequestID: uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	// The real resolver: nothing reached a node.
	if _, err := resolve(unbound.Revision); !errors.Is(err, errCertificateNeverPublished) {
		t.Fatalf("unpublish source after a failed publication = %v, want never published", err)
	}
	unbindLease := claim(unbound.Revision, "unpublish")
	result := certificateasset.PublicationResult{
		Outcome: certificateasset.PublicationAck, NoopReason: certificateasset.PublicationNoopNeverPublished,
	}
	if err := intents.CompletePublicationIntent(t.Context(), unbindLease, result); err != nil {
		t.Fatal(err)
	}
	var state, noopReason string
	var rolloutID *uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT state,noop_reason,rollout_id FROM certificate_publication_intent_state_facts
		WHERE tenant_scope_id=$1 AND site_id=$2 AND binding_revision=$3 ORDER BY sequence DESC LIMIT 1`,
		tenant.scopeID, tenant.siteID, unbound.Revision).Scan(&state, &noopReason, &rolloutID); err != nil {
		t.Fatal(err)
	}
	if state != "succeeded" || noopReason != certificateasset.PublicationNoopNeverPublished || rolloutID != nil {
		t.Fatalf("unbind settled state=%s noop=%s rollout=%v", state, noopReason, rolloutID)
	}
	var auditResult string
	var payload []byte
	if err := pool.QueryRow(t.Context(), `SELECT result,payload FROM audit_events
		WHERE scope_id=$1 AND action=$2 AND resource_id=$3 AND payload->>'operation'='unpublish'`,
		tenant.scopeID, certificateasset.AuditPublicationComplete, tenant.siteID.String()).Scan(&auditResult, &payload); err != nil {
		t.Fatal(err)
	}
	var audited map[string]any
	if err := json.Unmarshal(payload, &audited); err != nil || auditResult != "success" ||
		audited["noop_reason"] != certificateasset.PublicationNoopNeverPublished || audited["rollout_id"] != nil {
		t.Fatalf("unbind audit result=%s payload=%v err=%v", auditResult, audited, err)
	}
	statuses, err := certificateasset.NewPublicationStatusStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	detail, err := statuses.Get(t.Context(), tenant.certificateActor, tenant.scopeID, tenant.siteID, unbound.Revision)
	if err != nil || detail.Current.State != "succeeded" || detail.Current.NoopReason != certificateasset.PublicationNoopNeverPublished ||
		detail.Current.RolloutID != nil {
		t.Fatalf("unbind status = %+v, %v", detail.Current, err)
	}
	// The rebind is claimed next, not stuck behind the unbind; nothing to
	// remove after a no-op unbind either.
	rebound, err := certificates.Bind(t.Context(), tenant.certificateActor, certificateasset.BindRequest{
		TenantScopeID: tenant.scopeID, SiteID: tenant.siteID, AssetID: imported.Asset.ID, VersionID: imported.Version.ID,
		ExpectedRevision: unbound.Revision, IdempotencyKey: "noop-rebind", RequestID: uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	rebindLease := claim(rebound.Revision, "publish")
	noopForPublish := intents.CompletePublicationIntent(t.Context(), rebindLease, result)
	if !errors.Is(noopForPublish, certificateasset.ErrInvalidInput) {
		t.Fatalf("a publication completed as a no-op: %v", noopForPublish)
	}

	// The rebind's publication reaches one node and fails on the other: the
	// certificate is on a node, so the next unbind is not a no-op.
	actor := deploymentActor
	statusStore, err := edgestatus.NewStoreWithClock(pool, func() time.Time { return publicationIntegrationNow })
	if err != nil {
		t.Fatal(err)
	}
	nodes := []publicationNode{
		seedPublicationNode(t, pool, tenant.scopeID, tenant.userID),
		seedPublicationNode(t, pool, tenant.scopeID, tenant.userID),
	}
	request := publicationIntegrationRequest(t, pool, actor, tenant, nodes, rebound, "")
	request.IdempotencyKey = certificatePublicationRolloutKey(tenant.scopeID, tenant.siteID, rebound.Revision)
	published, err := service.Publish(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	projectPublicationSuccess(t, statusStore, published.Rollout.Deployments[0])
	projectPublicationFailure(t, statusStore, published.Rollout.Deployments[1])
	if err := intents.PermanentlyFailPublicationIntent(t.Context(), rebindLease, "publication_terminal_failed"); err != nil {
		t.Fatal(err)
	}
	secondUnbind, err := certificates.Unbind(t.Context(), tenant.certificateActor, certificateasset.UnbindRequest{
		TenantScopeID: tenant.scopeID, SiteID: tenant.siteID, ExpectedRevision: rebound.Revision,
		IdempotencyKey: "noop-unbind-2", RequestID: uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	source, err := resolve(secondUnbind.Revision)
	if err != nil || source.RolloutID != published.Rollout.ID || source.Revision != published.Rollout.Revision ||
		len(source.NodeIDs) != 2 {
		t.Fatalf("unpublish source after a partial publication = %+v, %v; want rollout %s", source, err, published.Rollout.ID)
	}
}
