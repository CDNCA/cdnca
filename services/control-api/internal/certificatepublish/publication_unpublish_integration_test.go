//go:build integration

package certificatepublish

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/google/uuid"
)

// An unpublication tells the nodes which site was removed, by its tenant and
// the binding revision of its unbind (the node refuses older bindings).
func TestUnpublishRemovalNamesTenantAndUnbindRevision(t *testing.T) {
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
		TenantScopeID: tenant.scopeID, Name: "unpublish certificate", Source: certificateasset.SourceUploaded,
		CertificatePEM: certificatePEM, PrivateKeyPEM: privateKeyPEM,
		IdempotencyKey: "certificate-unpublish-import", RequestID: uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := certificates.Activate(t.Context(), tenant.certificateActor, certificateasset.ActivateRequest{
		TenantScopeID: tenant.scopeID, AssetID: imported.Asset.ID, VersionID: imported.Version.ID,
		ExpectedRevision: imported.Asset.Revision, IdempotencyKey: "certificate-unpublish-activate", RequestID: uuid.NewString(),
	}); err != nil {
		t.Fatal(err)
	}
	bound, err := certificates.Bind(t.Context(), tenant.certificateActor, certificateasset.BindRequest{
		TenantScopeID: tenant.scopeID, SiteID: tenant.siteID, AssetID: imported.Asset.ID,
		VersionID: imported.Version.ID, IdempotencyKey: "certificate-unpublish-bind", RequestID: uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockUnboundLifecycleSites(t.Context(), tx, tenant.scopeID, []uuid.UUID{tenant.siteID}); err != certificateasset.ErrInvalidTransition {
		t.Fatalf("a bound site was removable: %v", err)
	}
	_ = tx.Rollback(t.Context())

	unbound, err := certificates.Unbind(t.Context(), tenant.certificateActor, certificateasset.UnbindRequest{
		TenantScopeID: tenant.scopeID, SiteID: tenant.siteID, ExpectedRevision: bound.Revision,
		IdempotencyKey: "certificate-unpublish-unbind", RequestID: uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	tx, err = pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	removed, err := lockUnboundLifecycleSites(t.Context(), tx, tenant.scopeID, []uuid.UUID{tenant.siteID})
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || removed[0].TenantID != tenant.tenantID || removed[0].SiteID != tenant.siteID ||
		removed[0].BindingRevision != unbound.Revision || unbound.Revision <= bound.Revision {
		t.Fatalf("removed = %+v, want tenant %s site %s revision %d (bound at %d)", removed, tenant.tenantID, tenant.siteID, unbound.Revision, bound.Revision)
	}
}
